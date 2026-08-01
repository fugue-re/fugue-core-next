use super::FunctionRecoveryError;
use crate::arch::Arch;
use crate::ir::{Address, IncompleteCodeBlockId, IncompleteFunction, Insn};
use crate::lifter::{Disassembler, Lifter, LiftingContext, Op, RawPCodeOp};
use crate::storage::{SegmentMappingCache, SegmentStorage};

pub struct InsnResolver {
    disassembler: Disassembler,
    lifter: Lifter,
    mapping_cache: SegmentMappingCache,
    operations: Vec<RawPCodeOp>,
}

impl InsnResolver {
    pub fn new(arch: &Arch) -> Self {
        let disassembler = arch.disassembler();
        let lifter = arch.lifter();

        Self {
            disassembler,
            lifter,
            mapping_cache: SegmentMappingCache::new(),
            operations: Vec::new(),
        }
    }

    pub fn resolve(
        &mut self,
        address: Address,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Insn, FunctionRecoveryError> {
        let bytes = bytes.as_ref();
        self.operations.clear();
        let mut insn = self
            .disassembler
            .disassemble(address, bytes, self.lifter.context_mut())?;

        if insn.needs_flow_resolution() || insn.is_empty() {
            self.resolve_flow(&mut insn, bytes)?;
        }

        Ok(insn)
    }

    fn resolve_flow(
        &mut self,
        insn: &mut Insn,
        bytes: impl AsRef<[u8]>,
    ) -> Result<(), FunctionRecoveryError> {
        let length = self
            .lifter
            .lift(insn.address(), bytes.as_ref(), &mut self.operations)?;
        insn.resolve_flow(self.lifter.language(), length, &self.operations)?;
        Ok(())
    }

    pub fn lift_block(
        &mut self,
        function: &IncompleteFunction,
        block: IncompleteCodeBlockId,
        segments: &SegmentStorage,
        mapping_cache: &mut SegmentMappingCache,
        operations: &mut Vec<RawPCodeOp>,
    ) -> Result<(), FunctionRecoveryError> {
        let block = function
            .block(block)
            .ok_or_else(|| FunctionRecoveryError::invalid_block_id(block))?;
        block
            .context()
            .apply(block.address(), self.lifter.context_mut());

        let operation_start = operations.len();
        for &insn_id in block.insns() {
            let insn = function
                .insn(insn_id)
                .expect("block instruction must exist");

            let view = match mapping_cache.contiguous_view_from(segments, insn.address()) {
                Ok(view) => view,
                Err(error) => {
                    operations.truncate(operation_start);
                    return Err(error.into());
                }
            };
            let bytes = view
                .as_contiguous()
                .expect("contiguous mapping view must contain bytes");

            self.operations.clear();
            if let Err(error) = self
                .lifter
                .lift(insn.address(), bytes, &mut self.operations)
                .map_err(FunctionRecoveryError::from)
            {
                operations.truncate(operation_start);
                return Err(error);
            }
            operations.append(&mut self.operations);
        }

        Ok(())
    }

    fn resolve_indirect_target_pointer(&self, insn: &Insn) -> Option<Address> {
        let language = self.lifter.language();
        let (position, target) =
            self.operations
                .iter()
                .enumerate()
                .find_map(|(index, operation)| {
                    if !matches!(operation.op(), Op::IBranch | Op::ICall) {
                        return None;
                    }
                    operation.inputs().first().map(|target| (index, *target))
                })?;

        if language.in_default_space(&target) {
            return Some(Address::new(insn.address().space(), target.offset()));
        }

        let definition = self.operations[..position]
            .iter()
            .rev()
            .find(|operation| operation.output() == Some(&target))?;

        if !matches!(definition.op(), Op::Copy) {
            return None;
        }

        definition
            .inputs()
            .first()
            .filter(|source| language.in_default_space(source))
            .map(|source| Address::new(insn.address().space(), source.offset()))
    }

    pub fn resolve_indirect_target(
        &mut self,
        segments: &SegmentStorage,
        insn: &Insn,
    ) -> Option<Address> {
        let pointer = self.resolve_indirect_target_pointer(insn)?;
        let size = self.lifter.language().address_size();
        let mut buffer = [0u8; size_of::<u64>()];
        let bytes = buffer.get_mut(..size)?;

        self.mapping_cache
            .read_bytes_exact(segments, pointer, bytes)
            .ok()?;

        let offset = if self.lifter.language().is_big_endian() {
            bytes
                .iter()
                .fold(0u64, |value, &byte| (value << 8) | u64::from(byte))
        } else {
            bytes
                .iter()
                .rev()
                .fold(0u64, |value, &byte| (value << 8) | u64::from(byte))
        };

        Some(Address::new(pointer.space(), offset))
    }

    pub fn operations(&self) -> &[RawPCodeOp] {
        &self.operations
    }

    pub fn context(&self) -> &LiftingContext {
        self.lifter.context()
    }

    pub fn context_mut(&mut self) -> &mut LiftingContext {
        self.lifter.context_mut()
    }
}
