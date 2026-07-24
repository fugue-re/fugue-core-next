use fugue_bv::BitVec;

use super::SwitchIdiomMatcher;
use crate::analysis::function::recovery::InsnResolver;
use crate::analysis::switch::{RecoveredSwitch, SwitchRecoveryConfig, SwitchTargetResolver};
use crate::arch::Arch;
use crate::ir::{
    Address, AddressTable, IncompleteCodeBlockId, IncompleteFunction, SwitchCase, SwitchCaseLabel,
    SwitchModel, SwitchProperties,
};
use crate::lifter::{LiftingContext, RawPCodeOp};
use crate::storage::SegmentStorage;
use crate::storage::segments::SegmentMappingCache;

pub(crate) struct SwitchIdiomRecovery<'a> {
    config: SwitchRecoveryConfig,
    arch: &'a Arch,
    segments: &'a SegmentStorage,
    mapping_cache: SegmentMappingCache<'a>,
    operations: Vec<RawPCodeOp>,
}

impl<'a> SwitchIdiomRecovery<'a> {
    pub(crate) fn new(
        config: SwitchRecoveryConfig,
        arch: &'a Arch,
        segments: &'a SegmentStorage,
    ) -> Self {
        Self {
            config,
            arch,
            segments,
            mapping_cache: SegmentMappingCache::new(segments),
            operations: Vec::new(),
        }
    }

    pub(crate) fn recover(
        &mut self,
        resolver: &mut InsnResolver,
        function: &IncompleteFunction,
        predecessor: Option<IncompleteCodeBlockId>,
        block: IncompleteCodeBlockId,
        branch: Address,
    ) -> Option<RecoveredSwitch> {
        self.operations.clear();
        if let Some(predecessor) = predecessor {
            resolver
                .lift_block(
                    function,
                    predecessor,
                    &mut self.mapping_cache,
                    &mut self.operations,
                )
                .ok()?;
        }
        resolver
            .lift_block(
                function,
                block,
                &mut self.mapping_cache,
                &mut self.operations,
            )
            .ok()?;
        self.recover_operations(branch, resolver.context())
    }

    fn recover_operations(
        &mut self,
        branch: Address,
        context: &LiftingContext,
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
        let mut resolver = SwitchTargetResolver::new(self.arch, self.segments, space);
        let cap = u64::from(self.config.max_cases());
        let limit = idiom
            .bound()
            .and_then(BitVec::to_u64)
            .map_or(cap, |bound| bound.saturating_add(1).min(cap));

        let mut cases = Vec::new();
        for index in 0..limit {
            let raw = match self.mapping_cache.read_bitvec(
                table.entry_address(index as u32),
                element_size as usize,
                self.arch.endian(),
            ) {
                Ok(raw) => raw,
                Err(_) => break,
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
            let Some(target) = resolver.resolve_value(&target_value, context) else {
                break;
            };

            let mut case = SwitchCase::new(target);
            case.add_label(SwitchCaseLabel::new(
                (index as i64).wrapping_add(idiom.label_offset()) as u64,
            ));
            cases.push(case);
        }

        if cases.is_empty() {
            return None;
        }

        table.set_element_count(cases.len() as u32);
        let guarded = idiom.bound().is_some();
        let truncated = idiom
            .bound()
            .and_then(BitVec::to_u64)
            .is_some_and(|bound| (cases.len() as u64) <= bound);
        let table_start = Address::new(space, idiom.table());
        let properties = SwitchProperties::from_recovery(guarded, truncated)
            | SwitchProperties::CONTIGUOUS_ENTRIES
            | resolver.properties_for_table(table_start, &cases);
        let model = match idiom.base() {
            Some(base) => SwitchModel::OffsetRelative {
                table,
                base: base.address(),
                signed: base.is_signed(),
            },
            None => SwitchModel::Absolute(table),
        };

        Some(RecoveredSwitch::new(model, cases, properties))
    }
}
