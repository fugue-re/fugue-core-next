use fugue_bv::BitVec;
use fugue_bytes::Endian;

use crate::analysis::function::recovery::FunctionRecoveryError;
use crate::analysis::switch::idiom::SwitchIdiomMatcher;
use crate::analysis::switch::{RecoveredSwitch, SwitchRecoveryConfig, SwitchTargetResolver};
use crate::arch::Arch;
use crate::ir::{
    Address, AddressTable, IncompleteCodeBlockId, IncompleteFunction, SwitchCase, SwitchCaseLabel,
    SwitchEvidence, SwitchModel, SwitchProperties,
};
use crate::lifter::{Lifter, LifterError, LiftingContext, PCodeOp};
use crate::storage::SegmentStorage;
use crate::storage::segments::SegmentMappingCache;

pub(crate) struct SwitchSyntacticRecoveryContext<'a> {
    config: SwitchRecoveryConfig,
    arch: &'a Arch,
    segments: &'a SegmentStorage,
    lifter: Lifter,
    mapping_cache: SegmentMappingCache<'a>,
    operations: Vec<PCodeOp>,
    instruction_operations: Vec<PCodeOp>,
}

impl<'a> SwitchSyntacticRecoveryContext<'a> {
    pub(crate) fn new(
        config: SwitchRecoveryConfig,
        arch: &'a Arch,
        segments: &'a SegmentStorage,
    ) -> Self {
        Self {
            config,
            arch,
            segments,
            lifter: arch.lifter(),
            mapping_cache: SegmentMappingCache::new(segments),
            operations: Vec::new(),
            instruction_operations: Vec::new(),
        }
    }

    pub(crate) fn recover(
        &mut self,
        function: &IncompleteFunction,
        predecessor: Option<IncompleteCodeBlockId>,
        block: IncompleteCodeBlockId,
        branch: Address,
    ) -> Option<RecoveredSwitch> {
        self.operations.clear();
        if let Some(predecessor) = predecessor {
            self.lift_block(function, predecessor).ok()?;
        }
        self.lift_block(function, block).ok()?;
        RecoveredSwitch::from_syntactic(
            self.config,
            self.arch,
            self.segments,
            branch,
            &self.operations,
            self.lifter.context(),
        )
    }

    fn lift_block(
        &mut self,
        function: &IncompleteFunction,
        block: IncompleteCodeBlockId,
    ) -> Result<(), FunctionRecoveryError> {
        let block = function
            .block(block)
            .ok_or_else(|| FunctionRecoveryError::invalid_block_id(block))?;
        let start = block.address();

        let Some(view) = self.mapping_cache.view_containing(start) else {
            return Err(LifterError::invalid_instruction(start).into());
        };
        let Some(window) = view.bytes_from(start) else {
            return Err(LifterError::invalid_instruction(start).into());
        };
        let Some(bytes) = window.as_contiguous() else {
            return Err(LifterError::invalid_instruction(start).into());
        };

        block.context().apply(start, self.lifter.context_mut());

        let operation_start = self.operations.len();
        for &insn_id in block.insns() {
            let insn = function
                .insn(insn_id)
                .expect("block instruction must exist");

            let Some(offset) = insn.address().checked_offset_from(start) else {
                self.operations.truncate(operation_start);
                return Err(LifterError::invalid_instruction(insn.address()).into());
            };
            let Some(view) = bytes.get(offset as usize..) else {
                self.operations.truncate(operation_start);
                return Err(LifterError::invalid_instruction(insn.address()).into());
            };

            self.instruction_operations.clear();
            if let Err(error) = self
                .lifter
                .lift(insn.address(), view, &mut self.instruction_operations)
                .map_err(FunctionRecoveryError::from)
            {
                self.operations.truncate(operation_start);
                return Err(error);
            }
            self.operations.append(&mut self.instruction_operations);
        }

        Ok(())
    }
}

impl RecoveredSwitch {
    fn from_syntactic(
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
        let mut mapping_cache = SegmentMappingCache::new(segments);
        let cap = u64::from(config.max_cases());
        let limit = idiom
            .bound()
            .and_then(BitVec::to_u64)
            .map_or(cap, |bound| bound.saturating_add(1).min(cap));

        let mut cases = Vec::new();
        let mut buffer = vec![0u8; element_size as usize];

        for index in 0..limit {
            if mapping_cache
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
        let evidence = SwitchEvidence::from_recovery(guarded)
            | SwitchEvidence::CONTIGUOUS_ENTRIES
            | resolver.evidence_for_table(table_start, &cases);
        let properties = SwitchProperties::from_recovery(truncated);
        let model = match idiom.base() {
            Some(base) => SwitchModel::OffsetRelative {
                table,
                base: base.address(),
                signed: base.is_signed(),
            },
            None => SwitchModel::Absolute(table),
        };

        Some(Self::new(model, cases, evidence, properties))
    }
}
