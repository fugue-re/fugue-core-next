use crate::analysis::control::Cancelled;
use crate::analysis::function::recovery::{PartialFunctionWithContext, Translator};
use crate::analysis::switch::slice::SwitchSliceEvaluator;
use crate::analysis::switch::{RecoveredSwitch, SwitchRecoveryConfig};
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::il::common::IlError;
use crate::il::ecode::ssa::ECodeToSsa;
use crate::il::pcode::PCodeError;
use crate::ir::{FlowKind, FunctionId, SwitchEvidence, SwitchId};
use crate::project::Project;
use crate::storage::segments::SegmentReader;

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

impl AnalysisPass<PartialFunctionWithContext> for SwitchRecovery {
    fn analyse_with(
        &mut self,
        project: &mut Project,
        state: &mut PartialFunctionWithContext,
    ) -> Result<(), AnalysisError> {
        let mut resolved = Vec::new();
        {
            let arch = project.arch();
            let segments = project.segments();
            let mut translator = Translator::new(project);
            let mut reader = SegmentReader::new(segments);
            let function = state.function();
            let mut branches = function.indirect_branches().peekable();
            if branches.peek().is_none() {
                return Ok(());
            }
            let mut operations = Vec::new();
            let mut unresolved = Vec::new();
            let mut retry = Vec::new();

            for (block_index, site) in branches {
                let Some(block) = function.blocks().get(block_index) else {
                    continue;
                };
                let predecessors = block.predecessors();

                let mut outcome = None;
                let mut ambiguous = false;

                let sources = predecessors
                    .iter()
                    .copied()
                    .map(Some)
                    .chain(predecessors.is_empty().then_some(None));
                for source in sources {
                    operations.clear();
                    if let Some(predecessor) = source
                        && function
                            .append_block_pcode(
                                predecessor,
                                &mut reader,
                                &mut translator,
                                &mut operations,
                            )
                            .is_err()
                    {
                        continue;
                    }
                    if function
                        .append_block_pcode(
                            block_index,
                            &mut reader,
                            &mut translator,
                            &mut operations,
                        )
                        .is_err()
                    {
                        continue;
                    }

                    let Some(candidate) = RecoveredSwitch::from_syntactic(
                        self.config,
                        arch,
                        segments,
                        site,
                        &operations,
                        translator.context(),
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
                            retry.push((block_index, site));
                        }
                        resolved.push((site, recovered));
                    }
                    _ => unresolved.push((block_index, site)),
                }
            }

            if !unresolved.is_empty() || !retry.is_empty() {
                match ECodeToSsa
                    .build_partial_function_tolerant(
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
                    }) {
                    Ok(local) => {
                        if let Some(ssa) = local.ir() {
                            let evaluator =
                                SwitchSliceEvaluator::new(ssa, arch, segments, self.config);

                            for (block_index, site) in unresolved {
                                let block = &function.blocks()[block_index];
                                if local.omits(block.address()) {
                                    continue;
                                }
                                if let Some(recovered) =
                                    evaluator.recover(site, block.context(), &mut translator)
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

                            for (block_index, site) in retry {
                                let block = &function.blocks()[block_index];
                                if local.omits(block.address()) {
                                    continue;
                                }
                                let Some(recovered) =
                                    evaluator.recover(site, block.context(), &mut translator)
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
                    Err(error @ AnalysisError::Cancelled(_)) => return Err(error),
                    Err(error) => {
                        tracing::debug!(
                            "skipping semantic switch recovery for function at {}: {error}",
                            function.entry(),
                        );
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
