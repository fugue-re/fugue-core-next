use crate::analysis::control::Cancelled;
use crate::analysis::function::recovery::{
    FunctionRecovery, FunctionRecoveryExtension, FunctionRecoveryState,
};
use crate::analysis::switch::SwitchRecoveryConfig;
use crate::analysis::switch::idiom::SwitchIdiomRecovery;
use crate::analysis::switch::interval::SwitchIntervalRecovery;
use crate::analysis::switch::resolver::SwitchTargetResolver;
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::engine::ProjectView;
use crate::il::common::{IlArtefact, IlError, IlGenerationError};
use crate::il::ecode::ECodeIr;
use crate::ir::{FlowKind, FunctionId, SwitchId, SwitchProperties};
use crate::project::Project;
use crate::types::Revision;

pub(crate) const SWITCH_RECOVERY_ANALYSER: &str = "switch-recovery";

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
        project: &ProjectView<'_>,
        state: &mut FunctionRecoveryState,
    ) -> Result<(), AnalysisError> {
        let mut resolved = Vec::new();
        {
            let cancellation = state.cancellation().clone();
            let arch = project.arch();
            let (function, resolver) = state.function_and_resolver(arch);
            let mut branches = function
                .indirect_branches()
                .filter(|(_, branch)| !function.has_pending_switch(*branch))
                .peekable();
            if branches.peek().is_none() {
                return Ok(());
            }

            let segments = project.segments();
            let mut idiom_recovery = SwitchIdiomRecovery::new(self.config);
            let mut target_resolver =
                SwitchTargetResolver::new(arch, segments, function.entry().space());
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
                    let Some(candidate) = idiom_recovery.recover(
                        resolver,
                        function,
                        source,
                        block_id,
                        site,
                        &mut target_resolver,
                    ) else {
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
                    .speculative_il::<ECodeIr>(function, Revision::default(), &cancellation)
                    .map_err(|error| match error {
                        IlGenerationError::Il(IlError::Cancelled) => {
                            AnalysisError::Cancelled(Cancelled)
                        }
                        error => AnalysisError::pass_failed(SWITCH_RECOVERY_ANALYSER, error),
                    })?
                    .ok_or_else(|| {
                        AnalysisError::pass_failed(
                            SWITCH_RECOVERY_ANALYSER,
                            IlError::missing_artefact(FunctionId::INVALID, ECodeIr::FORM),
                        )
                    })?;
                let mut interval_recovery = SwitchIntervalRecovery::new(&ssa, self.config);

                for (block_id, site) in unresolved {
                    let block = function.block(block_id).expect("switch block must exist");
                    if let Some(recovered) = interval_recovery.recover(
                        site,
                        block.context(),
                        resolver,
                        &mut target_resolver,
                    ) {
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
                    let Some(recovered) = interval_recovery.recover(
                        site,
                        block.context(),
                        resolver,
                        &mut target_resolver,
                    ) else {
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

    fn apply(_project: &Project, recovery: &mut FunctionRecovery) -> Result<(), AnalysisError> {
        if recovery.config().switch_analysis() {
            recovery
                .add_builder_post_structuring_pass(SWITCH_RECOVERY_ANALYSER, SwitchRecovery::new());
        }

        Ok(())
    }
}
