use idiom::SwitchIdiomRecovery;
use interval::SwitchIntervalRecovery;
use recovered::{RecoveredSwitch, SwitchCaseEnumerator};
use resolver::SwitchResolver;

use crate::analysis::function::recovery::{
    FunctionRecovery, FunctionRecoveryExtension, StructuredFunctionContext,
};
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::engine::AnalysisContext;
use crate::il::common::{IlArtefact, IlError};
use crate::il::ecode::ECodeIr;
use crate::ir::{FlowKind, FunctionId, SwitchId, SwitchProperties};
use crate::project::Project;
use crate::types::Revision;

mod idiom;
mod interval;
mod recovered;
mod resolver;

pub(crate) const SWITCH_RECOVERY_ANALYSER: &str = "switch-recovery";

#[derive(Debug, Clone, Copy)]
pub struct SwitchRecoveryConfig {
    max_cases: u32,
    max_element_size: u32,
    max_trace_depth: u32,
    max_trace_steps: usize,
}

impl Default for SwitchRecoveryConfig {
    fn default() -> Self {
        Self {
            max_cases: 4096,
            max_element_size: 8,
            max_trace_depth: 256,
            max_trace_steps: 1 << 20,
        }
    }
}

impl SwitchRecoveryConfig {
    pub fn max_cases(&self) -> u32 {
        self.max_cases
    }

    pub fn set_max_cases(&mut self, max_cases: u32) {
        self.max_cases = max_cases;
    }

    pub fn with_max_cases(mut self, max_cases: u32) -> Self {
        self.set_max_cases(max_cases);
        self
    }

    pub fn max_element_size(&self) -> u32 {
        self.max_element_size
    }

    pub fn set_max_element_size(&mut self, max_element_size: u32) {
        self.max_element_size = max_element_size;
    }

    pub fn with_max_element_size(mut self, max_element_size: u32) -> Self {
        self.set_max_element_size(max_element_size);
        self
    }

    pub fn max_trace_depth(&self) -> u32 {
        self.max_trace_depth
    }

    pub fn set_max_trace_depth(&mut self, max_trace_depth: u32) {
        self.max_trace_depth = max_trace_depth;
    }

    pub fn with_max_trace_depth(mut self, max_trace_depth: u32) -> Self {
        self.set_max_trace_depth(max_trace_depth);
        self
    }

    pub fn max_trace_steps(&self) -> usize {
        self.max_trace_steps
    }

    pub fn set_max_trace_steps(&mut self, max_trace_steps: usize) {
        self.max_trace_steps = max_trace_steps;
    }

    pub fn with_max_trace_steps(mut self, max_trace_steps: usize) -> Self {
        self.set_max_trace_steps(max_trace_steps);
        self
    }
}

#[derive(Default)]
pub struct SwitchRecovery {
    config: SwitchRecoveryConfig,
}

impl SwitchRecovery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with(config: SwitchRecoveryConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &SwitchRecoveryConfig {
        &self.config
    }
}

impl AnalysisPass<StructuredFunctionContext> for SwitchRecovery {
    fn analyse_with(
        &mut self,
        context: &mut AnalysisContext<'_, '_>,
        state: &mut StructuredFunctionContext,
    ) -> Result<(), AnalysisError> {
        let project = &context.project;
        let mut resolved = Vec::new();
        {
            let arch = project.arch();
            let (function, insns) = state.function_and_resolver(arch);
            let mut branches = function
                .indirect_branches()
                .filter(|(_, branch)| !function.has_pending_switch(*branch))
                .peekable();
            if branches.peek().is_none() {
                return Ok(());
            }

            let segments = project.segments();
            let mut idiom_recovery = SwitchIdiomRecovery::new(self.config);
            let mut resolver = SwitchResolver::new(arch, segments, insns);
            let mut unresolved = Vec::new();
            let mut retry = Vec::new();

            for (block_id, site) in branches {
                let Some(block) = function.block(block_id) else {
                    continue;
                };
                let predecessors = block.predecessors();

                let mut outcome = None;
                let mut ambiguous = false;

                let sources = predecessors
                    .iter()
                    .map(Some)
                    .chain(predecessors.is_empty().then_some(None));
                for source in sources {
                    let Some(candidate) =
                        idiom_recovery.recover(function, source, block_id, site, &mut resolver)
                    else {
                        continue;
                    };
                    outcome = match outcome.take() {
                        None => Some(candidate),
                        Some(existing) => match existing.reconcile(candidate) {
                            Some(recovered) => Some(recovered),
                            None => {
                                ambiguous = true;
                                break;
                            }
                        },
                    };
                }

                match (ambiguous, outcome) {
                    (false, Some(recovered)) => {
                        tracing::debug!(
                            "recovered switch at {} with {} cases (confidence {})",
                            site,
                            recovered.cases().len(),
                            recovered.confidence(),
                        );
                        if !recovered.is_guarded() {
                            retry.push((block_id, site));
                        }
                        resolved.push((block_id, site, recovered));
                    }
                    _ => unresolved.push((block_id, site)),
                }
            }

            if !unresolved.is_empty() || !retry.is_empty() {
                let ssa = project
                    .speculative_il::<ECodeIr>(function, Revision::default())
                    .map_err(|e| AnalysisError::pass_failed(SWITCH_RECOVERY_ANALYSER, e))?
                    .ok_or_else(|| {
                        AnalysisError::pass_failed(
                            SWITCH_RECOVERY_ANALYSER,
                            IlError::missing_artefact(FunctionId::INVALID, ECodeIr::FORM),
                        )
                    })?;
                let mut interval_recovery = SwitchIntervalRecovery::new(&ssa, self.config);

                for (block_id, site) in unresolved {
                    let block = function.block(block_id).expect("switch block must exist");
                    if let Some(recovered) =
                        interval_recovery.recover(site, block.context(), &mut resolver)
                    {
                        tracing::debug!(
                            "recovered switch at {} with {} cases (confidence {})",
                            site,
                            recovered.cases().len(),
                            recovered.confidence(),
                        );
                        resolved.push((block_id, site, recovered));
                    }
                }

                for (block_id, site) in retry {
                    let block = function.block(block_id).expect("switch block must exist");
                    let Some(recovered) =
                        interval_recovery.recover(site, block.context(), &mut resolver)
                    else {
                        continue;
                    };
                    if let Some((_, _, existing)) = resolved
                        .iter_mut()
                        .find(|(_, existing, _)| *existing == site)
                        && existing.should_replace_with(&recovered)
                    {
                        *existing = recovered;
                    }
                }
            }
        }

        for (block, site, recovered) in resolved {
            if let Some(existing) = project.switch_at(site)
                && (existing.is_override()
                    || (existing
                        .properties()
                        .contains(SwitchProperties::GUARD_FOUND)
                        && !recovered.is_guarded()))
            {
                continue;
            }

            let recovered = recovered
                .with_fallback_default(state.function().sibling_successor_from_incoming(block));
            for case in recovered.cases() {
                state.context_mut().add_local_target_with_context(
                    site,
                    case.target().clone(),
                    FlowKind::SwitchBranch,
                );
            }

            let switch = recovered.into_switch(SwitchId::INVALID, FunctionId::INVALID, site);
            state.function_mut().add_pending_switch(switch);
        }

        Ok(())
    }
}

#[fugue_core::extension]
impl FunctionRecoveryExtension {
    const NAME: &str = "switch";

    fn configure(_: &Project, recovery: &mut FunctionRecovery) -> Result<(), AnalysisError> {
        if recovery.config().switch_analysis() {
            recovery.add_post_structuring_pass(SWITCH_RECOVERY_ANALYSER, SwitchRecovery::new());
        }

        Ok(())
    }
}
