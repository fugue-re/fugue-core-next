use fugue_bv::BitVec;
use fugue_bytes::Endian;
use rustc_hash::FxHashMap;

use evaluator::ThunkTargetEvaluator;

use crate::analysis::function::recovery::{
    FunctionRecovery, FunctionRecoveryExtension, StructuredFunctionContext,
};
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::engine::AnalysisContext;
use crate::il::common::{IlArtefact, IlError, RegisterId};
use crate::il::ecode::analysis::ECodeBlockArgInputs;
use crate::il::ecode::{ECodeIr, ECodeOpcode};
use crate::ir::{Address, AddressWithContext, FunctionId};
use crate::lifter::TrackedContext;
use crate::project::Project;
use crate::storage::SegmentMappingCache;

mod evaluator;

pub(crate) const THUNK_TARGET_RECOVERY_ANALYSER: &str = "thunk-target-recovery";

#[derive(Debug, Clone, Copy)]
pub struct ThunkTargetRecoveryConfig {
    max_trace_steps: usize,
}

impl Default for ThunkTargetRecoveryConfig {
    fn default() -> Self {
        Self {
            max_trace_steps: 4096,
        }
    }
}

impl ThunkTargetRecoveryConfig {
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
pub struct ThunkTargetRecovery {
    config: ThunkTargetRecoveryConfig,
}

impl ThunkTargetRecovery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with(config: ThunkTargetRecoveryConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &ThunkTargetRecoveryConfig {
        &self.config
    }
}

impl AnalysisPass<StructuredFunctionContext> for ThunkTargetRecovery {
    fn analyse_with(
        &mut self,
        context: &mut AnalysisContext<'_, '_>,
        state: &mut StructuredFunctionContext,
    ) -> Result<(), AnalysisError> {
        let project = &context.project;
        let arch = project.arch();
        let segments = project.segments();
        let function = state.function();

        let [block] = function.blocks() else {
            return Ok(());
        };
        let Some(&id) = block.insn_ids().last() else {
            return Ok(());
        };
        let Some(site) = function
            .insn(id)
            .filter(|insn| {
                insn.is_branch()
                    && insn.is_indirect()
                    && !insn.is_call()
                    && !insn.is_return()
                    && !insn
                        .iter_targets()
                        .any(|(target, _, _)| target.is_indirect())
            })
            .map(|insn| insn.address())
        else {
            return Ok(());
        };

        let entry = function.entry();
        let mut mapping_cache = SegmentMappingCache::new();
        let seeds = mapping_cache
            .view_containing(segments, entry)
            .and_then(|view| view.tracked_set_at(entry).cloned())
            .map(|tracked| {
                tracked
                    .iter()
                    .map(|tracked| {
                        let location = tracked.location();
                        (RegisterId::new(location.offset()), *tracked)
                    })
                    .collect::<FxHashMap<RegisterId, TrackedContext>>()
            })
            .unwrap_or_default();

        let ssa = project
            .lifted_for_incomplete::<ECodeIr>(function)
            .map_err(|e| AnalysisError::pass_failed(THUNK_TARGET_RECOVERY_ANALYSER, e))?
            .ok_or_else(|| {
                AnalysisError::pass_failed(
                    THUNK_TARGET_RECOVERY_ANALYSER,
                    IlError::missing_artefact(FunctionId::INVALID, ECodeIr::FORM),
                )
            })?;

        let Some(target) = ssa
            .ops_for_source(site)
            .find(|(_, operation)| operation.opcode() == ECodeOpcode::BranchIndirect)
            .and_then(|(_, operation)| ssa.op_operands_for(operation).first().copied())
        else {
            return Ok(());
        };

        let block_arg_inputs = ssa.analyse::<ECodeBlockArgInputs>();

        let mut evaluator =
            ThunkTargetEvaluator::new(&ssa, &block_arg_inputs, &seeds, entry.space(), self.config);
        let mut buffer = Vec::new();

        let Some(value) = evaluator.evaluate(target, |address, size| {
            buffer.resize(size, 0);
            mapping_cache
                .read_bytes_exact(segments, address, &mut buffer)
                .ok()?;
            Some(match arch.endian() {
                Endian::Big => BitVec::from_be_bytes(&buffer),
                Endian::Little => BitVec::from_le_bytes(&buffer),
            })
        }) else {
            return Ok(());
        };

        let Some((canonical, context)) = value
            .to_u64()
            .and_then(|value| arch.canonicalise_address(value))
        else {
            return Ok(());
        };

        let target = Address::new(site.space(), canonical);
        if !mapping_cache
            .mapping_properties(segments, target)
            .is_some_and(|properties| properties.is_executable())
        {
            return Ok(());
        }

        tracing::debug!("resolved thunk target of {site} to {target}");
        state
            .function_mut()
            .insn_mut(id)
            .expect("the thunk branch exists")
            .set_indirect_target(AddressWithContext::new(target, context));

        Ok(())
    }
}

#[fugue_core::extension]
impl FunctionRecoveryExtension {
    const NAME: &str = "thunk-target";

    fn configure(_: &Project, recovery: &mut FunctionRecovery) -> Result<(), AnalysisError> {
        recovery.add_post_structuring_pass(THUNK_TARGET_RECOVERY_ANALYSER, ThunkTargetRecovery::new());
        Ok(())
    }
}
