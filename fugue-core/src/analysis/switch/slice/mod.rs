use rustc_hash::FxHashMap;

use crate::analysis::function::recovery::Translator;
use crate::analysis::switch::{RecoveredSwitch, SwitchRecoveryConfig};
use crate::arch::Arch;
use crate::il::common::{IlBlockId, IlDominance, IlValueId};
use crate::il::ecode::ssa::{ECodeSsaIr, ECodeSsaOpcode, StridedIntervals};
use crate::ir::Address;
use crate::lifter::ContextSet;
use crate::storage::SegmentStorage;

mod evaluate;
mod guard;
mod layout;
mod recover;

pub(crate) struct SwitchSliceEvaluator<'a> {
    ssa: &'a ECodeSsaIr,
    arch: &'a Arch,
    segments: &'a SegmentStorage,
    config: SwitchRecoveryConfig,
    intervals: StridedIntervals,
    dominance: IlDominance,
    operation_blocks: Vec<Option<IlBlockId>>,
    block_argument_sources: FxHashMap<IlValueId, Vec<IlValueId>>,
}

impl<'a> SwitchSliceEvaluator<'a> {
    pub(crate) fn new(
        ssa: &'a ECodeSsaIr,
        arch: &'a Arch,
        segments: &'a SegmentStorage,
        config: SwitchRecoveryConfig,
    ) -> Self {
        let mut operation_blocks = vec![None; ssa.operations().len()];
        for (block_index, block) in ssa.graph().blocks().iter().enumerate() {
            let block_id =
                IlBlockId::try_from_index(block_index).expect("block count fits the id space");
            operation_blocks[block.operations().start()..block.operations().end()]
                .fill(Some(block_id));
        }

        Self {
            ssa,
            arch,
            segments,
            config,
            intervals: StridedIntervals::build(ssa),
            dominance: ssa.dominance(),
            operation_blocks,
            block_argument_sources: ssa.block_argument_sources(),
        }
    }

    pub(crate) fn recover(
        &self,
        branch: Address,
        context: &ContextSet,
        translator: &mut Translator,
    ) -> Option<RecoveredSwitch> {
        let target = self
            .ssa
            .operations_for_source(branch)
            .find(|(_, operation)| operation.opcode() == ECodeSsaOpcode::BranchIndirect)
            .and_then(|(_, operation)| self.ssa.operation_operands(operation).first().copied())?;
        context.apply(branch, translator.context_mut());
        if let Some(layout) = self.table_layout(target) {
            return self.recover_loaded(branch, target, layout, context, translator);
        }
        if let Some(layout) = self.inline_table_layout(target) {
            return self.recover_inline(branch, layout, context, translator);
        }
        tracing::trace!("switch slice at {branch}: no idiom");
        None
    }

    fn common_block_argument_source(&self, value: IlValueId) -> Option<IlValueId> {
        let sources = self.block_argument_sources.get(&value)?;
        let first = *sources.first()?;
        sources
            .iter()
            .all(|&source| source == first)
            .then_some(first)
    }

    fn underlying_value(&self, value: IlValueId) -> IlValueId {
        let mut current = value;
        for _ in 0..self.ssa.values().len() {
            let Some(operation) = self.ssa.defining_operation(current) else {
                return current;
            };
            match operation.opcode() {
                ECodeSsaOpcode::Copy
                | ECodeSsaOpcode::ZeroExtend
                | ECodeSsaOpcode::SignExtend
                | ECodeSsaOpcode::Truncate => {
                    let Some(&inner) = self.ssa.operation_operands(operation).first() else {
                        return current;
                    };
                    current = inner;
                }
                _ => return current,
            }
        }
        current
    }

    fn canonical(&self, value: IlValueId) -> IlValueId {
        let mut current = self.underlying_value(value);
        for _ in 0..self.config.max_trace_depth() {
            let Some(source) = self.common_block_argument_source(current) else {
                break;
            };
            let next = self.underlying_value(source);
            if next == current {
                break;
            }
            current = next;
        }
        current
    }

    fn block_of_source(&self, address: Address) -> Option<IlBlockId> {
        let (operation, _) = self.ssa.operations_for_source(address).next()?;
        self.operation_blocks.get(operation).copied().flatten()
    }
}
