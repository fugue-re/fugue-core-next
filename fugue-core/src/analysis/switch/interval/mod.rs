use fugue_bv::BitVec;
use rustc_hash::FxHashMap;

use crate::analysis::function::recovery::InsnResolver;
use crate::analysis::switch::{RecoveredSwitch, SwitchRecoveryConfig, SwitchTargetResolver};
use crate::analysis::value::StridedInterval;
use crate::il::common::{IlArtefact, IlBlockId, IlDominance, IlValueId};
use crate::il::ecode::ssa::{
    ECodeSsaBlockArgumentInputs, ECodeSsaIr, ECodeSsaOpcode, ECodeSsaStridedIntervals,
};
use crate::ir::{
    Address, AddressTable, AddressWithContext, SwitchCase, SwitchCaseLabel, SwitchModel,
    SwitchProperties,
};
use crate::lifter::ContextSet;

mod evaluator;
mod guard;
mod layout;

use evaluator::SwitchTargetEvaluator;
use guard::SwitchGuard;
use layout::{SwitchInlineTableLayout, SwitchTableLayout};

pub(crate) struct SwitchIntervalContext<'analysis> {
    ssa: &'analysis ECodeSsaIr,
    blocks_by_source: FxHashMap<Address, IlBlockId>,
    config: SwitchRecoveryConfig,
    intervals: ECodeSsaStridedIntervals,
    dominance: IlDominance,
    block_argument_inputs: ECodeSsaBlockArgumentInputs,
    cases: Vec<SwitchCase>,
}

struct SwitchCaseEnumeration {
    interval: StridedInterval,
    guard: Option<SwitchGuard>,
    label_offset: i64,
    limit: usize,
}

impl SwitchCaseEnumeration {
    fn populate_cases(
        &self,
        cases: &mut Vec<SwitchCase>,
        mut resolve: impl FnMut(&BitVec) -> Option<AddressWithContext>,
    ) {
        cases.clear();
        for value in self.interval.iter().take(self.limit) {
            let Some(destination) = resolve(&value) else {
                break;
            };
            let mut case = SwitchCase::new(destination);
            if let Some(raw) = value.to_u64() {
                case.add_label(SwitchCaseLabel::new(
                    raw.wrapping_add(self.label_offset as u64),
                ));
            }
            cases.push(case);
        }
    }

    fn guard(&self) -> Option<&SwitchGuard> {
        self.guard.as_ref()
    }

    fn properties(&self, case_count: usize) -> SwitchProperties {
        let truncated = self
            .interval
            .count()
            .is_some_and(|count| case_count < count);
        SwitchProperties::from_recovery(self.guard.is_some(), truncated)
    }
}

impl<'analysis> SwitchIntervalContext<'analysis> {
    pub(crate) fn new(ssa: &'analysis ECodeSsaIr, config: SwitchRecoveryConfig) -> Self {
        let mut blocks_by_source = FxHashMap::default();
        for (block, source) in ssa.graph().blocks_with_sources() {
            blocks_by_source.entry(source).or_insert(block);
        }
        Self {
            ssa,
            blocks_by_source,
            config,
            intervals: ssa.analyse::<ECodeSsaStridedIntervals>(),
            dominance: ssa.analyse::<IlDominance>(),
            block_argument_inputs: ssa.analyse::<ECodeSsaBlockArgumentInputs>(),
            cases: Vec::new(),
        }
    }

    pub(crate) fn recover(
        &mut self,
        branch: Address,
        context: &ContextSet,
        insn_resolver: &mut InsnResolver,
        target_resolver: &mut SwitchTargetResolver<'_>,
    ) -> Option<RecoveredSwitch> {
        let target = self
            .ssa
            .operations_for_source(branch)
            .find(|(_, operation)| operation.opcode() == ECodeSsaOpcode::BranchIndirect)
            .and_then(|(_, operation)| self.ssa.operation_operands(operation).first().copied())?;
        context.apply(branch, insn_resolver.context_mut());
        if let Some(layout) = self.table_layout(target) {
            return self.recover_loaded(
                branch,
                target,
                layout,
                context,
                insn_resolver,
                target_resolver,
            );
        }
        if let Some(layout) = self.inline_table_layout(target) {
            return self.recover_inline(branch, layout, context, insn_resolver, target_resolver);
        }
        tracing::trace!("switch interval recovery at {branch}: no idiom");
        None
    }

    fn recover_loaded(
        &mut self,
        branch: Address,
        target: IlValueId,
        layout: SwitchTableLayout,
        context: &ContextSet,
        insn_resolver: &mut InsnResolver,
        target_resolver: &mut SwitchTargetResolver<'_>,
    ) -> Option<RecoveredSwitch> {
        let index = layout.index();
        let enumeration = self.case_enumeration(index, branch)?;
        let space = branch.space();
        target_resolver.set_space(space);
        let mut cases = std::mem::take(&mut self.cases);
        let mut evaluator = SwitchTargetEvaluator::new(self, space);
        enumeration.populate_cases(&mut cases, |value| {
            let target = evaluator.evaluate(target, index, value, |address, size| {
                target_resolver.read_bitvec(address, size)
            })?;
            target_resolver.resolve_value(&target, insn_resolver.context())
        });

        if cases.is_empty() {
            self.cases = cases;
            tracing::trace!("switch interval recovery at {branch}: evaluation not closed");
            return None;
        }

        let table_address = Address::new(space, layout.address());
        let table = AddressTable::new(table_address, layout.element_size())
            .with_element_count(cases.len() as u32);
        let properties = enumeration.properties(cases.len())
            | target_resolver.properties_for_table(table_address, &cases);
        let recovered = RecoveredSwitch::new(SwitchModel::Absolute(table), cases, properties);
        Some(self.finalise_recovery(
            branch,
            context,
            insn_resolver,
            target_resolver,
            &enumeration,
            recovered,
        ))
    }

    fn recover_inline(
        &mut self,
        branch: Address,
        layout: SwitchInlineTableLayout,
        context: &ContextSet,
        insn_resolver: &mut InsnResolver,
        target_resolver: &mut SwitchTargetResolver<'_>,
    ) -> Option<RecoveredSwitch> {
        let enumeration = self.case_enumeration(layout.index(), branch)?;
        let space = branch.space();
        let table_address = Address::new(space, layout.address());
        let mut table = AddressTable::new(table_address, layout.stride());
        target_resolver.set_space(space);
        let mut cases = std::mem::take(&mut self.cases);
        enumeration.populate_cases(&mut cases, |value| {
            let entry = u32::try_from(value.to_u64()?).ok()?;
            let address = table.entry_address(entry);
            target_resolver.resolve_branch_target(
                address,
                Some(layout.stride() as usize),
                context,
                insn_resolver,
            )
        });

        if cases.is_empty() {
            self.cases = cases;
            tracing::trace!("switch interval recovery at {branch}: inline table is not closed");
            return None;
        }

        table.set_element_count(cases.len() as u32);
        let properties =
            enumeration.properties(cases.len()) | target_resolver.properties_for_targets(&cases);
        let recovered =
            RecoveredSwitch::new(SwitchModel::InlineBranchTable(table), cases, properties);
        Some(self.finalise_recovery(
            branch,
            context,
            insn_resolver,
            target_resolver,
            &enumeration,
            recovered,
        ))
    }

    fn case_enumeration(&self, index: IlValueId, branch: Address) -> Option<SwitchCaseEnumeration> {
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
        let maximum = self.config.max_cases() as usize;
        let limit = interval.count().map_or(maximum, |count| count.min(maximum));
        Some(SwitchCaseEnumeration {
            interval,
            guard,
            label_offset: self.label_offset(index),
            limit,
        })
    }

    fn finalise_recovery(
        &self,
        branch: Address,
        context: &ContextSet,
        insn_resolver: &mut InsnResolver,
        target_resolver: &mut SwitchTargetResolver<'_>,
        enumeration: &SwitchCaseEnumeration,
        recovered: RecoveredSwitch,
    ) -> RecoveredSwitch {
        match self.resolve_default_branch_target(
            enumeration.guard(),
            branch,
            context,
            insn_resolver,
            target_resolver,
        ) {
            Some(default) => recovered.with_fallback_default(Some(default)),
            None => recovered,
        }
    }

    fn label_offset(&self, index: IlValueId) -> i64 {
        let Some(operation) = self.ssa.defining_operation(index) else {
            return 0;
        };
        let operands = self.ssa.operation_operands(operation);
        match operation.opcode() {
            ECodeSsaOpcode::Sub => operands
                .get(1)
                .and_then(|&operand| self.ssa.constant_value(operand))
                .and_then(|constant| constant.to_u64())
                .map_or(0, |constant| constant as i64),
            ECodeSsaOpcode::Add => operands
                .iter()
                .find_map(|&operand| self.ssa.constant_value(operand))
                .and_then(|constant| constant.to_u64())
                .map_or(0, |constant| (constant as i64).wrapping_neg()),
            _ => 0,
        }
    }

    fn common_block_argument_input(&self, value: IlValueId) -> Option<IlValueId> {
        let inputs = self.block_argument_inputs.inputs_for(value)?;
        let first = *inputs.first()?;
        inputs.iter().all(|&input| input == first).then_some(first)
    }

    fn canonical_value(&self, value: IlValueId) -> IlValueId {
        let mut current = self.ssa.underlying_value(value);
        for _ in 0..self.config.max_trace_depth() {
            let Some(input) = self.common_block_argument_input(current) else {
                break;
            };
            let next = self.ssa.underlying_value(input);
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
        self.ssa.block_for_operation(operation)
    }
}
