use crate::analysis::control::Cancelled;
use crate::analysis::function::recovery::{FunctionRecoveryState, InsnResolver};
use crate::analysis::switch::SwitchRecoveryConfig;
use crate::analysis::switch::slice::SwitchSliceEvaluator;
use crate::analysis::switch::syntactic::SwitchSyntacticRecoveryContext;
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::il::common::IlError;
use crate::il::ecode::ssa::ECodeToSsa;
use crate::il::pcode::PCodeError;
use crate::ir::{FlowKind, FunctionId, SwitchEvidence, SwitchId};
use crate::project::Project;

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

impl AnalysisPass<FunctionRecoveryState> for SwitchRecovery {
    fn analyse_with(
        &mut self,
        project: &mut Project,
        state: &mut FunctionRecoveryState,
    ) -> Result<(), AnalysisError> {
        let mut resolved = Vec::new();
        {
            let arch = project.arch();
            let segments = project.segments();
            let mut resolver = InsnResolver::new(project);
            let mut syntactic = SwitchSyntacticRecoveryContext::new(self.config, arch, segments);
            let function = state.function();
            let mut branches = function.indirect_branches().peekable();
            if branches.peek().is_none() {
                return Ok(());
            }
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
                    let Some(candidate) = syntactic.recover(function, source, block_id, site)
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
                        resolved.push((site, recovered));
                    }
                    _ => unresolved.push((block_id, site)),
                }
            }

            if !unresolved.is_empty() || !retry.is_empty() {
                let ssa = ECodeToSsa
                    .build_incomplete_function(
                        project.language(),
                        function,
                        project.segments(),
                        0,
                        state.cancellation(),
                    )
                    .map_err(|error| match error {
                        PCodeError::Common(IlError::Cancelled) => {
                            AnalysisError::Cancelled(Cancelled)
                        }
                        error => AnalysisError::pass_failed("switch-recovery", error),
                    })?;
                let evaluator = SwitchSliceEvaluator::new(&ssa, arch, segments, self.config);

                for (block_id, site) in unresolved {
                    let block = function.block(block_id).expect("switch block must exist");
                    if let Some(recovered) = evaluator.recover(site, block.context(), &mut resolver)
                    {
                        tracing::debug!(
                            "recovered switch at {} with {} cases (confidence {})",
                            site,
                            recovered.cases().len(),
                            recovered.confidence(),
                        );
                        resolved.push((site, recovered));
                    }
                }

                for (block_id, site) in retry {
                    let block = function.block(block_id).expect("switch block must exist");
                    let Some(recovered) = evaluator.recover(site, block.context(), &mut resolver)
                    else {
                        continue;
                    };
                    if let Some((_, existing)) =
                        resolved.iter_mut().find(|(existing, _)| *existing == site)
                        && existing.should_replace_with(&recovered)
                    {
                        *existing = recovered;
                    }
                }
            }
        }

        for (site, recovered) in resolved {
            if let Some(existing) = project.switches().get_by_branch(site)
                && (existing.is_override()
                    || existing.is_assisted()
                    || (existing.evidence().contains(SwitchEvidence::GUARD_FOUND)
                        && !recovered.is_guarded()))
            {
                continue;
            }

            for case in recovered.cases() {
                state.context_mut().add_local_target_with_context(
                    site,
                    case.target().clone(),
                    FlowKind::SwitchBranch,
                );
            }

            let switch = recovered.into_switch(SwitchId::default(), FunctionId::INVALID, site);
            state.function_mut().add_pending_switch(switch);
        }

        Ok(())
    }
}
