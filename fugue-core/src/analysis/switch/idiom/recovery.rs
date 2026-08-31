use std::mem;

use fugue_bv::BitVec;

use super::SwitchIdiomMatcher;
use crate::analysis::switch::{RecoveredSwitch, SwitchRecoveryConfig, SwitchTargetResolver};
use crate::ir::{
    Address, AddressTable, IncompleteCodeBlockId, IncompleteFunction, SwitchCase, SwitchCaseLabel,
    SwitchModel, SwitchProperties,
};
use crate::lifter::{InsnResolver, LiftingContext, RawPCodeOp};

pub(crate) struct SwitchIdiomRecovery {
    cases: Vec<SwitchCase>,
    config: SwitchRecoveryConfig,
    operations: Vec<RawPCodeOp>,
}

impl SwitchIdiomRecovery {
    pub(crate) fn new(config: SwitchRecoveryConfig) -> Self {
        Self {
            cases: Vec::new(),
            config,
            operations: Vec::new(),
        }
    }

    pub(crate) fn recover(
        &mut self,
        insn_resolver: &mut InsnResolver,
        function: &IncompleteFunction,
        predecessor: Option<IncompleteCodeBlockId>,
        block: IncompleteCodeBlockId,
        branch: Address,
        target_resolver: &mut SwitchTargetResolver<'_>,
    ) -> Option<RecoveredSwitch> {
        self.operations.clear();
        if let Some(predecessor) = predecessor {
            self.lift_block(insn_resolver, function, predecessor, target_resolver)?;
        }
        self.lift_block(insn_resolver, function, block, target_resolver)?;
        self.recover_operations(branch, insn_resolver.context(), target_resolver)
    }

    fn lift_block(
        &mut self,
        insn_resolver: &mut InsnResolver,
        function: &IncompleteFunction,
        block: IncompleteCodeBlockId,
        target_resolver: &mut SwitchTargetResolver<'_>,
    ) -> Option<()> {
        let block = function.block(block)?;
        block
            .context()
            .apply(block.address(), insn_resolver.context_mut());

        let view = target_resolver.contiguous_view_from(block.address())?;
        let bytes = view.as_contiguous()?.get(..block.size())?;
        let output_start = self.operations.len();

        for &insn_id in block.insn_ids() {
            let insn = function.insn(insn_id)?;
            let offset = usize::from(insn.address() - block.address());
            if insn_resolver
                .lift_into(insn.address(), bytes.get(offset..)?, &mut self.operations)
                .is_err()
            {
                self.operations.truncate(output_start);
                return None;
            }
        }

        Some(())
    }

    fn recover_operations(
        &mut self,
        branch: Address,
        context: &LiftingContext,
        target_resolver: &mut SwitchTargetResolver<'_>,
    ) -> Option<RecoveredSwitch> {
        let idiom = SwitchIdiomMatcher::new(&self.operations, self.config.max_trace_depth())?
            .match_idiom()?;
        let element_size = idiom.element_size();
        if element_size == 0 || element_size > self.config.max_element_size() {
            return None;
        }

        let space = branch.space();
        let mut table = AddressTable::new(Address::new(space, idiom.table()), element_size)
            .with_shift(idiom.shift());
        target_resolver.set_space(space);
        let cap = u64::from(self.config.max_cases());
        let limit = idiom
            .bound()
            .and_then(BitVec::to_u64)
            .map_or(cap, |bound| bound.saturating_add(1).min(cap));

        self.cases.clear();
        for index in 0..limit {
            let raw = match target_resolver
                .read_bitvec(table.entry_address(index as u32), element_size as usize)
            {
                Some(raw) => raw,
                None => break,
            };
            let value = if table.shift() == 0 {
                raw
            } else {
                let bits = element_size * 8 + u32::from(table.shift());
                raw.unsigned_cast(bits) << BitVec::from_u64(u64::from(table.shift()), bits)
            };
            let target_value = match idiom.base() {
                Some(base) => {
                    let offset = if base.is_signed() {
                        value.signed_cast(u64::BITS)
                    } else {
                        value.unsigned_cast(u64::BITS)
                    };
                    BitVec::from_u64(base.address().offset(), u64::BITS) + offset
                }
                None => value.unsigned_cast(u64::BITS),
            };
            let Some(target) = target_resolver.resolve_value(&target_value, context) else {
                break;
            };

            let mut case = SwitchCase::new(target);
            case.add_label(SwitchCaseLabel::new(
                (index as i64).wrapping_add(idiom.label_offset()) as u64,
            ));
            self.cases.push(case);
        }

        if self.cases.is_empty() {
            return None;
        }

        table.set_element_count(self.cases.len() as u32);
        let guarded = idiom.bound().is_some();
        let truncated = idiom
            .bound()
            .and_then(BitVec::to_u64)
            .is_some_and(|bound| (self.cases.len() as u64) <= bound);
        let table_start = Address::new(space, idiom.table());
        let properties = SwitchProperties::from_recovery(guarded, truncated)
            | SwitchProperties::CONTIGUOUS_ENTRIES
            | target_resolver.properties_for_table(table_start, &self.cases);
        let model = match idiom.base() {
            Some(base) => SwitchModel::OffsetRelative {
                table,
                base: base.address(),
                signed: base.is_signed(),
            },
            None => SwitchModel::Absolute(table),
        };

        Some(RecoveredSwitch::new(
            model,
            mem::take(&mut self.cases),
            properties,
        ))
    }
}
