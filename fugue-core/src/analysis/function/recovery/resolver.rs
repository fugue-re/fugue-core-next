use super::FunctionRecoveryError;
use crate::ir::{Address, IncompleteCodeBlockId, IncompleteFunction, Insn};
use crate::lifter::{Disassembler, Lifter, LifterError, LiftingContext, RawPCodeOp};
use crate::project::Project;
use crate::storage::segments::SegmentMappingCache;

pub struct InsnResolver {
    disassembler: Disassembler,
    lifter: Lifter,
    operations: Vec<RawPCodeOp>,
}

impl InsnResolver {
    pub fn new(project: &Project) -> Self {
        let disassembler = project.arch().disassembler();
        let lifter = project.arch().lifter();

        Self {
            disassembler,
            lifter,
            operations: Vec::new(),
        }
    }

    pub fn resolve(
        &mut self,
        address: Address,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Insn, FunctionRecoveryError> {
        let bytes = bytes.as_ref();
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
        self.operations.clear();
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
        mapping_cache: &mut SegmentMappingCache<'_>,
        operations: &mut Vec<RawPCodeOp>,
    ) -> Result<(), FunctionRecoveryError> {
        let block = function
            .block(block)
            .ok_or_else(|| FunctionRecoveryError::invalid_block_id(block))?;
        let start = block.address();
        let bytes = mapping_cache
            .contiguous_bytes_from(start)
            .map_err(|_| LifterError::invalid_instruction(start))?;

        block.context().apply(start, self.lifter.context_mut());

        let operation_start = operations.len();
        for &insn_id in block.insns() {
            let insn = function
                .insn(insn_id)
                .expect("block instruction must exist");

            let Some(offset) = insn.address().checked_offset_from(start) else {
                operations.truncate(operation_start);
                return Err(LifterError::invalid_instruction(insn.address()).into());
            };
            let Some(view) = bytes.get(offset as usize..) else {
                operations.truncate(operation_start);
                return Err(LifterError::invalid_instruction(insn.address()).into());
            };

            self.operations.clear();
            if let Err(error) = self
                .lifter
                .lift(insn.address(), view, &mut self.operations)
                .map_err(FunctionRecoveryError::from)
            {
                operations.truncate(operation_start);
                return Err(error);
            }
            operations.append(&mut self.operations);
        }

        Ok(())
    }

    pub fn context(&self) -> &LiftingContext {
        self.lifter.context()
    }

    pub fn context_mut(&mut self) -> &mut LiftingContext {
        self.lifter.context_mut()
    }
}
