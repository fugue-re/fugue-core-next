use rustc_hash::FxHashMap;

use crate::analysis::function::recovery::InsnResolver;
use crate::analysis::switch::{RecoveredSwitch, SwitchRecoveryConfig, SwitchTargetResolver};
use crate::analysis::value::StridedInterval;
use crate::arch::Arch;
use crate::il::common::{IlArtefact, IlBlockId, IlDominance, IlValueId};
use crate::il::ecode::ssa::{
    ECodeSsaBlockArgumentInputs, ECodeSsaIr, ECodeSsaOpcode, ECodeSsaStridedIntervals,
};
use crate::ir::{
    Address, AddressTable, SwitchCase, SwitchCaseLabel, SwitchEvidence, SwitchModel,
    SwitchProperties,
};
use crate::lifter::ContextSet;
use crate::storage::SegmentStorage;

mod context;
mod guard;
mod layout;

use context::SwitchTargetEvaluatorContext;
use guard::SwitchGuard;
use layout::{SwitchInlineTableLayout, SwitchTableLayout};

pub(crate) struct SwitchSliceEvaluator<'a> {
    ssa: &'a ECodeSsaIr,
    blocks_by_source: FxHashMap<Address, IlBlockId>,
    arch: &'a Arch,
    segments: &'a SegmentStorage,
    config: SwitchRecoveryConfig,
    intervals: ECodeSsaStridedIntervals,
    dominance: IlDominance,
    operation_blocks: Vec<Option<IlBlockId>>,
    block_argument_inputs: ECodeSsaBlockArgumentInputs,
}

struct IndexDomain {
    interval: StridedInterval,
    guard: Option<SwitchGuard>,
}

impl<'a> SwitchSliceEvaluator<'a> {
    pub(crate) fn new(
        ssa: &'a ECodeSsaIr,
        arch: &'a Arch,
        segments: &'a SegmentStorage,
        config: SwitchRecoveryConfig,
    ) -> Self {
        let mut blocks_by_source = FxHashMap::default();
        for (index, &source) in ssa.graph().block_sources().iter().enumerate() {
            let block = IlBlockId::try_from_index(index).expect("block count fits the id space");
            blocks_by_source.entry(source).or_insert(block);
        }
        let mut operation_blocks = vec![None; ssa.operations().len()];
        for (block_index, block) in ssa.graph().blocks().iter().enumerate() {
            let block_id =
                IlBlockId::try_from_index(block_index).expect("block count fits the id space");
            operation_blocks[block.operations().start()..block.operations().end()]
                .fill(Some(block_id));
        }

        Self {
            ssa,
            blocks_by_source,
            arch,
            segments,
            config,
            intervals: ssa.analyse::<ECodeSsaStridedIntervals>(),
            dominance: ssa.analyse::<IlDominance>(),
            operation_blocks,
            block_argument_inputs: ssa.analyse::<ECodeSsaBlockArgumentInputs>(),
        }
    }

    pub(crate) fn recover(
        &self,
        branch: Address,
        context: &ContextSet,
        resolver: &mut InsnResolver,
    ) -> Option<RecoveredSwitch> {
        let target = self
            .ssa
            .operations_for_source(branch)
            .find(|(_, operation)| operation.opcode() == ECodeSsaOpcode::BranchIndirect)
            .and_then(|(_, operation)| self.ssa.operation_operands(operation).first().copied())?;
        context.apply(branch, resolver.context_mut());
        if let Some(layout) = self.table_layout(target) {
            return self.recover_loaded(branch, target, layout, context, resolver);
        }
        if let Some(layout) = self.inline_table_layout(target) {
            return self.recover_inline(branch, layout, context, resolver);
        }
        tracing::trace!("switch slice at {branch}: no idiom");
        None
    }

    fn recover_loaded(
        &self,
        branch: Address,
        target: IlValueId,
        layout: SwitchTableLayout,
        context: &ContextSet,
        insn_resolver: &mut InsnResolver,
    ) -> Option<RecoveredSwitch> {
        let index = layout.index();
        let IndexDomain { interval, guard } = self.index_domain(index, branch)?;
        let guarded = guard.is_some();
        let limit = interval
            .count()
            .map_or(self.config.max_cases() as usize, |count| {
                count.min(self.config.max_cases() as usize)
            });
        let space = branch.space();
        let mut target_resolver = SwitchTargetResolver::new(self.arch, self.segments, space);
        let mut evaluator = SwitchTargetEvaluatorContext::new(self, space);
        let mut cases = Vec::new();
        let label_offset = self.label_offset(index);

        for value in interval.iter().take(limit) {
            let Some(target_value) = evaluator.evaluate(target, index, &value) else {
                break;
            };
            let Some(destination) =
                target_resolver.resolve_value(&target_value, insn_resolver.context())
            else {
                break;
            };
            let mut case = SwitchCase::new(destination);
            if let Some(raw) = value.to_u64() {
                case.add_label(SwitchCaseLabel::new(raw.wrapping_add(label_offset as u64)));
            }
            cases.push(case);
        }

        if cases.is_empty() {
            tracing::trace!("switch slice at {branch}: slice not closed");
            return None;
        }

        let truncated = interval.count().is_some_and(|count| cases.len() < count);
        let table_address = Address::new(space, layout.address());
        let table = AddressTable::new(table_address, layout.element_size())
            .with_element_count(cases.len() as u32);
        let evidence = SwitchEvidence::from_recovery(guarded)
            | target_resolver.evidence_for_table(table_address, &cases);
        let properties = SwitchProperties::from_recovery(truncated);
        let recovered =
            RecoveredSwitch::new(SwitchModel::Absolute(table), cases, evidence, properties);
        Some(
            match self.resolve_default_branch_target(guard.as_ref(), branch, context, insn_resolver)
            {
                Some(default) => recovered.with_default(default),
                None => recovered,
            },
        )
    }

    fn recover_inline(
        &self,
        branch: Address,
        layout: SwitchInlineTableLayout,
        context: &ContextSet,
        insn_resolver: &mut InsnResolver,
    ) -> Option<RecoveredSwitch> {
        let IndexDomain { interval, guard } = self.index_domain(layout.index(), branch)?;
        let guarded = guard.is_some();
        let limit = interval
            .count()
            .map_or(self.config.max_cases() as usize, |count| {
                count.min(self.config.max_cases() as usize)
            });
        let space = branch.space();
        let table_address = Address::new(space, layout.address());
        let mut table = AddressTable::new(table_address, layout.stride());
        let mut target_resolver = SwitchTargetResolver::new(self.arch, self.segments, space);
        let mut cases = Vec::new();
        let label_offset = self.label_offset(layout.index());

        for value in interval.iter().take(limit) {
            let entry = u32::try_from(value.to_u64()?).ok()?;
            let address = table.entry_address(entry);
            let Some(destination) = target_resolver.resolve_branch_target(
                address,
                Some(layout.stride() as usize),
                context,
                insn_resolver,
            ) else {
                break;
            };
            let mut case = SwitchCase::new(destination);
            case.add_label(SwitchCaseLabel::new(
                u64::from(entry).wrapping_add(label_offset as u64),
            ));
            cases.push(case);
        }

        if cases.is_empty() {
            tracing::trace!("switch slice at {branch}: inline table is not closed");
            return None;
        }

        table.set_element_count(cases.len() as u32);
        let truncated = interval.count().is_some_and(|count| cases.len() < count);
        let evidence = SwitchEvidence::from_recovery(guarded)
            | SwitchEvidence::CONTIGUOUS_ENTRIES
            | target_resolver.evidence_for_targets(&cases);
        let properties = SwitchProperties::from_recovery(truncated);
        let recovered = RecoveredSwitch::new(
            SwitchModel::InlineBranchTable(table),
            cases,
            evidence,
            properties,
        );
        Some(
            match self.resolve_default_branch_target(guard.as_ref(), branch, context, insn_resolver)
            {
                Some(default) => recovered.with_default(default),
                None => recovered,
            },
        )
    }

    fn index_domain(&self, index: IlValueId, branch: Address) -> Option<IndexDomain> {
        let width = self.ssa.value_width(index)?;
        let mut interval = self
            .intervals
            .get(index)
            .filter(|interval| !interval.is_empty())
            .cloned()
            .unwrap_or_else(|| StridedInterval::full(width));
        let guard = self.guard_for_index(index, branch);
        if let Some(guard) = &guard {
            interval = interval.meet(guard.interval());
        }
        Some(IndexDomain { interval, guard })
    }

    fn label_offset(&self, index: IlValueId) -> i64 {
        let Some(operation) = self.ssa.defining_operation(index) else {
            return 0;
        };
        let Some(constant) = self
            .ssa
            .operation_operands(operation)
            .iter()
            .find_map(|&operand| self.ssa.constant_value(operand))
            .and_then(|constant| constant.to_u64())
        else {
            return 0;
        };
        match operation.opcode() {
            ECodeSsaOpcode::Sub => constant as i64,
            ECodeSsaOpcode::Add => (constant as i64).wrapping_neg(),
            _ => 0,
        }
    }

    fn common_block_argument_input(&self, value: IlValueId) -> Option<IlValueId> {
        let inputs = self.block_argument_inputs.get(value)?;
        let first = *inputs.first()?;
        inputs.iter().all(|&input| input == first).then_some(first)
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

    fn canonical_value(&self, value: IlValueId) -> IlValueId {
        let mut current = self.underlying_value(value);
        for _ in 0..self.config.max_trace_depth() {
            let Some(input) = self.common_block_argument_input(current) else {
                break;
            };
            let next = self.underlying_value(input);
            if next == current {
                break;
            }
            current = next;
        }
        current
    }

    fn block_for_source(&self, address: Address) -> Option<IlBlockId> {
        if let Some(&block) = self.blocks_by_source.get(&address) {
            return Some(block);
        }
        let (operation, _) = self.ssa.operations_for_source(address).next()?;
        self.operation_blocks.get(operation).copied().flatten()
    }
}
