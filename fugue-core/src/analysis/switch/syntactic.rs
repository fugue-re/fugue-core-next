use fugue_bv::BitVec;
use fugue_bytes::Endian;

use crate::analysis::switch::idiom::SwitchIdiomMatcher;
use crate::analysis::switch::{RecoveredSwitch, SwitchRecoveryConfig, SwitchTargetResolver};
use crate::arch::Arch;
use crate::ir::{Address, AddressTable, SwitchCase, SwitchCaseLabel, SwitchEvidence, SwitchModel};
use crate::lifter::{LiftingContext, PCodeOp};
use crate::storage::SegmentStorage;
use crate::storage::segments::SegmentReader;

impl RecoveredSwitch {
    pub(crate) fn from_syntactic(
        config: SwitchRecoveryConfig,
        arch: &Arch,
        segments: &SegmentStorage,
        branch: Address,
        operations: &[PCodeOp],
        context: &LiftingContext,
    ) -> Option<Self> {
        let idiom = SwitchIdiomMatcher::new(operations, config.max_trace_depth())?.match_idiom()?;
        let element_size = idiom.element_size();
        if element_size == 0 || element_size > config.max_element_size() {
            return None;
        }

        let space = branch.space();
        let mut table = AddressTable::new(Address::new(space, idiom.table()), element_size)
            .with_shift(idiom.shift());
        let mut resolver = SwitchTargetResolver::new(arch, segments, space);
        let mut entries = SegmentReader::new(segments);
        let cap = u64::from(config.max_cases());
        let limit = idiom
            .bound()
            .and_then(BitVec::to_u64)
            .map_or(cap, |bound| bound.saturating_add(1).min(cap));

        let mut cases = Vec::new();
        let mut buffer = vec![0u8; element_size as usize];

        for index in 0..limit {
            if entries
                .read_bytes_exact(table.entry_address(index as u32), &mut buffer)
                .is_err()
            {
                break;
            }

            let raw = match arch.endian() {
                Endian::Big => BitVec::from_be_bytes(&buffer),
                Endian::Little => BitVec::from_le_bytes(&buffer),
            };
            let value = if table.shift() == 0 {
                raw
            } else {
                let bits = buffer.len() as u32 * 8 + u32::from(table.shift());
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
            let Some(target) = resolver.resolve(&target_value, context) else {
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
        let evidence = SwitchEvidence::from_recovery(guarded, truncated)
            | SwitchEvidence::CONTIGUOUS_ENTRIES
            | resolver.table_evidence(table_start, &cases);
        let model = match idiom.base() {
            Some(base) => SwitchModel::OffsetRelative {
                table,
                base: base.address(),
                signed: base.is_signed(),
            },
            None => SwitchModel::Absolute(table),
        };

        Some(Self::new(model, cases, evidence))
    }
}
