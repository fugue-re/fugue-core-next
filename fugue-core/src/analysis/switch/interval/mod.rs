use std::mem;

use rustc_hash::FxHashMap;

use crate::analysis::switch::{
    RecoveredSwitch, SwitchCaseEnumerator, SwitchRecoveryConfig, SwitchResolver,
};
use crate::analysis::value::StridedInterval;
use crate::il::common::{IlArtefact, IlBlockId, IlDominance, IlValueId};
use crate::il::ecode::{ECodeBlockArgInputs, ECodeIr, ECodeOpcode, ECodeStridedIntervals};
use crate::ir::{Address, AddressTable, SwitchCase, SwitchModel};
use crate::lifter::ContextSet;

mod evaluator;
mod guard;
mod layout;

use evaluator::SwitchTargetEvaluator;
use guard::{SwitchGuard, SwitchGuardAnalysis};
use layout::{SwitchLayoutAnalysis, SwitchTableLayout};

pub(crate) struct SwitchIntervalRecovery<'analysis> {
    ssa: &'analysis ECodeIr,
    blocks_by_source: FxHashMap<Address, IlBlockId>,
    config: SwitchRecoveryConfig,
    intervals: ECodeStridedIntervals,
    dominance: IlDominance,
    block_arg_inputs: ECodeBlockArgInputs,
    cases: Vec<SwitchCase>,
}

impl<'analysis> SwitchIntervalRecovery<'analysis> {
    pub(crate) fn new(ssa: &'analysis ECodeIr, config: SwitchRecoveryConfig) -> Self {
        let mut blocks_by_source = FxHashMap::default();
        for (block, source) in ssa.graph().blocks_with_sources() {
            blocks_by_source.entry(source).or_insert(block);
        }
        Self {
            ssa,
            blocks_by_source,
            config,
            intervals: ssa.analyse::<ECodeStridedIntervals>(),
            dominance: ssa.analyse::<IlDominance>(),
            block_arg_inputs: ssa.analyse::<ECodeBlockArgInputs>(),
            cases: Vec::new(),
        }
    }

    pub(crate) fn recover(
        &mut self,
        branch: Address,
        context: &ContextSet,
        resolver: &mut SwitchResolver<'_, '_>,
    ) -> Option<RecoveredSwitch> {
        let target = self
            .ssa
            .ops_for_source(branch)
            .find(|(_, operation)| operation.opcode() == ECodeOpcode::BranchIndirect)
            .and_then(|(_, operation)| self.ssa.op_operands_for(operation).first().copied())?;
        resolver.apply_context(branch, context);
        let layout = SwitchLayoutAnalysis::new(self.ssa, &self.block_arg_inputs, self.config)
            .discover(target)?;
        self.resolve_layout(branch, context, layout, resolver)
    }

    fn resolve_layout(
        &mut self,
        branch: Address,
        context: &ContextSet,
        layout: SwitchTableLayout,
        resolver: &mut SwitchResolver<'_, '_>,
    ) -> Option<RecoveredSwitch> {
        let (interval, guard, label_offset) = self.case_enumeration(layout.index(), branch)?;
        let expected_count = interval.count().and_then(|count| u64::try_from(count).ok());
        let mut cases = mem::take(&mut self.cases);
        let mut evaluator = SwitchTargetEvaluator::new(self, branch.space());
        let case_enumerator = SwitchCaseEnumerator::new(self.config.max_cases());
        let properties = case_enumerator.enumerate(
            &mut cases,
            interval.iter(),
            expected_count,
            guard.is_some(),
            label_offset,
            |value| match &layout {
                SwitchTableLayout::Loaded { index, target, .. } => {
                    let target = evaluator.evaluate(*target, *index, value, |address, size| {
                        resolver.read_bitvec(address, size)
                    })?;
                    resolver.resolve_value(branch, &target)
                }
                SwitchTableLayout::Inline {
                    address, stride, ..
                } => {
                    let entry = u32::try_from(value.to_u64()?).ok()?;
                    let address = Address::new(branch.space(), *address);
                    let table = AddressTable::new(address, *stride);
                    resolver.resolve_branch_target(
                        table.entry_address(entry),
                        Some(table.element_size() as usize),
                        context,
                    )
                }
            },
        );
        let Some(mut properties) = properties else {
            self.cases = cases;
            tracing::trace!(
                "switch interval recovery at {branch}: target enumeration is not closed"
            );
            return None;
        };

        let model = match layout {
            SwitchTableLayout::Loaded {
                address,
                element_size,
                ..
            } => {
                let address = Address::new(branch.space(), address);
                let table =
                    AddressTable::new(address, element_size).with_element_count(cases.len() as u32);
                properties |= resolver.properties_for_table(address, &cases);
                SwitchModel::Absolute(table)
            }
            SwitchTableLayout::Inline {
                address, stride, ..
            } => {
                let address = Address::new(branch.space(), address);
                let table =
                    AddressTable::new(address, stride).with_element_count(cases.len() as u32);
                properties |= resolver.properties_for_targets(&cases);
                SwitchModel::InlineBranchTable(table)
            }
        };
        let guard_analysis = SwitchGuardAnalysis::new(
            self.ssa,
            &self.blocks_by_source,
            self.config,
            &self.dominance,
            &self.block_arg_inputs,
        );
        let default =
            guard_analysis.resolve_default_branch_target(guard.as_ref(), branch, context, resolver);
        Some(RecoveredSwitch::new(model, cases, properties).with_fallback_default(default))
    }

    fn case_enumeration(
        &self,
        index: IlValueId,
        branch: Address,
    ) -> Option<(StridedInterval, Option<SwitchGuard>, i64)> {
        let width = self.ssa.value_width(index)?;
        let mut interval = self
            .intervals
            .interval_for(index)
            .filter(|interval| !interval.is_empty())
            .cloned()
            .unwrap_or_else(|| StridedInterval::full(width));
        let guard = SwitchGuardAnalysis::new(
            self.ssa,
            &self.blocks_by_source,
            self.config,
            &self.dominance,
            &self.block_arg_inputs,
        )
        .guard_for_index(index, branch);
        if let Some(guard) = &guard {
            interval = interval.meet(guard.interval());
        }
        Some((interval, guard, self.label_offset(index)))
    }

    fn label_offset(&self, index: IlValueId) -> i64 {
        let Some(operation) = self.ssa.defining_op(index) else {
            return 0;
        };
        let operands = self.ssa.op_operands_for(operation);
        match operation.opcode() {
            ECodeOpcode::Sub => operands
                .get(1)
                .and_then(|&operand| self.ssa.constant_value(operand))
                .and_then(|constant| constant.to_u64())
                .map_or(0, |constant| constant as i64),
            ECodeOpcode::Add => operands
                .iter()
                .find_map(|&operand| self.ssa.constant_value(operand))
                .and_then(|constant| constant.to_u64())
                .map_or(0, |constant| (constant as i64).wrapping_neg()),
            _ => 0,
        }
    }
}
