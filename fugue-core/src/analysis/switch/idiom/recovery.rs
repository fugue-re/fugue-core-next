use std::mem;

use fugue_bv::BitVec;

use super::{SwitchIdiomMatch, SwitchIdiomMatcher};
use crate::analysis::switch::{
    RecoveredSwitch, SwitchCaseEnumerator, SwitchRecoveryConfig, SwitchResolver,
};
use crate::ir::{
    Address, AddressTable, IncompleteCodeBlockId, IncompleteFunction, SwitchCase, SwitchModel,
    SwitchProperties,
};
use crate::lifter::RawPCodeOp;

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
        function: &IncompleteFunction,
        predecessor: Option<IncompleteCodeBlockId>,
        block: IncompleteCodeBlockId,
        branch: Address,
        resolver: &mut SwitchResolver<'_, '_>,
    ) -> Option<RecoveredSwitch> {
        self.operations.clear();
        if let Some(predecessor) = predecessor {
            resolver.lift_block(function, predecessor, &mut self.operations)?;
        }
        resolver.lift_block(function, block, &mut self.operations)?;
        let matched = SwitchIdiomMatcher::new(&self.operations, self.config.max_trace_depth())?
            .match_idiom()?;
        self.resolve_match(branch, matched, resolver)
    }

    fn resolve_match(
        &mut self,
        branch: Address,
        matched: SwitchIdiomMatch,
        resolver: &mut SwitchResolver<'_, '_>,
    ) -> Option<RecoveredSwitch> {
        let element_size = matched.element_size();
        if element_size == 0 || element_size > self.config.max_element_size() {
            return None;
        }

        let mut table =
            AddressTable::new(Address::new(branch.space(), matched.table()), element_size)
                .with_shift(matched.shift());
        let expected_count = matched
            .bound()
            .and_then(BitVec::to_u64)
            .map(|bound| bound.saturating_add(1));
        let values =
            (0..expected_count.unwrap_or(u64::MAX)).map(|index| BitVec::from_u64(index, u64::BITS));
        let enumeration = SwitchCaseEnumerator::new(self.config.max_cases());
        let properties = enumeration.enumerate(
            &mut self.cases,
            values,
            expected_count,
            matched.bound().is_some(),
            matched.label_offset(),
            |value| {
                let index = u32::try_from(value.to_u64()?).ok()?;
                let raw =
                    resolver.read_bitvec(table.entry_address(index), element_size as usize)?;
                let value = if table.shift() == 0 {
                    raw
                } else {
                    let bits = element_size * 8 + u32::from(table.shift());
                    raw.unsigned_cast(bits) << BitVec::from_u64(u64::from(table.shift()), bits)
                };
                let target = match matched.base() {
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
                resolver.resolve_value(branch, &target)
            },
        )?;

        table.set_element_count(self.cases.len() as u32);
        let table_address = table.address();
        let properties = properties
            | SwitchProperties::CONTIGUOUS_ENTRIES
            | resolver.properties_for_table(table_address, &self.cases);
        let model = match matched.base() {
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
