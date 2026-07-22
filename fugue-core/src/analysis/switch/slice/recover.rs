use fugue_bv::BitVec;

use super::SwitchSliceEvaluator;
use super::evaluate::SwitchTargetEvaluatorContext;
use super::guard::SwitchGuard;
use super::layout::{SwitchInlineTableLayout, SwitchTableLayout};
use crate::analysis::function::recovery::Translator;
use crate::analysis::switch::{RecoveredSwitch, SwitchTargetResolver};
use crate::analysis::value::StridedInterval;
use crate::il::common::IlValueId;
use crate::il::ecode::ssa::ECodeSsaOpcode;
use crate::ir::{Address, AddressTable, SwitchCase, SwitchCaseLabel, SwitchEvidence, SwitchModel};
use crate::lifter::ContextSet;

struct IndexDomain {
    interval: StridedInterval,
    guard: Option<SwitchGuard>,
}

impl SwitchSliceEvaluator<'_> {
    pub(crate) fn recover_loaded(
        &self,
        branch: Address,
        target: IlValueId,
        layout: SwitchTableLayout,
        context: &ContextSet,
        translator: &mut Translator,
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
        let mut resolver = SwitchTargetResolver::new(self.arch, self.segments, space);
        let mut evaluator = SwitchTargetEvaluatorContext::new(self, space);
        let mut cases = Vec::new();
        let label_offset = self.label_offset(index);

        for value in interval.iter().take(limit) {
            let Some(target_value) = evaluator.evaluate(target, index, &value) else {
                break;
            };
            let Some(destination) = resolver.resolve(&target_value, translator.context()) else {
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
        let evidence = SwitchEvidence::from_recovery(guarded, truncated)
            | resolver.table_evidence(table_address, &cases);
        let recovered = RecoveredSwitch::new(SwitchModel::Absolute(table), cases, evidence);
        Some(
            match guard
                .as_ref()
                .and_then(|guard| self.resolve_guard_default_target(guard, context, translator))
            {
                Some(default) => recovered.with_default(default),
                None => recovered,
            },
        )
    }

    pub(crate) fn recover_inline(
        &self,
        branch: Address,
        layout: SwitchInlineTableLayout,
        context: &ContextSet,
        translator: &mut Translator,
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
        let mut resolver = SwitchTargetResolver::new(self.arch, self.segments, space);
        let mut cases = Vec::new();
        let label_offset = self.label_offset(layout.index());

        for value in interval.iter().take(limit) {
            let entry = u32::try_from(value.to_u64()?).ok()?;
            let address = table.entry_address(entry);
            let Some(destination) = resolver.resolve_direct_branch(
                address,
                Some(layout.stride() as usize),
                context,
                translator,
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
        let evidence = SwitchEvidence::from_recovery(guarded, truncated)
            | SwitchEvidence::CONTIGUOUS_ENTRIES
            | resolver.target_alignment_evidence(&cases);
        let recovered =
            RecoveredSwitch::new(SwitchModel::InlineBranchTable(table), cases, evidence);
        Some(
            match guard
                .as_ref()
                .and_then(|guard| self.resolve_guard_default_target(guard, context, translator))
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
            .interval(index)
            .filter(|interval| !interval.is_empty())
            .cloned()
            .unwrap_or_else(|| StridedInterval::full(width));
        let guard = self.find_guard(index, branch);
        if let Some(bound) = guard.as_ref().and_then(|guard| guard.upper_bound(width)) {
            interval = interval.meet(&StridedInterval::range(
                BitVec::zero(width),
                bound,
                BitVec::one(width),
            ));
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
}
