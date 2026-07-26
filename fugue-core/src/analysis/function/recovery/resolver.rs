use super::FunctionRecoveryError;
use crate::ir::{Address, IncompleteCodeBlockId, IncompleteFunction, Insn};
use crate::lifter::{Disassembler, Lifter, LiftingContext, RawPCodeOp};
use crate::project::Project;
use crate::storage::{SegmentMappingCache, SegmentStorage};

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

            let view = match mapping_cache.contiguous_bytes_from(segments, insn.address()) {
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

    pub fn context(&self) -> &LiftingContext {
        self.lifter.context()
    }

    pub fn context_mut(&mut self) -> &mut LiftingContext {
        self.lifter.context_mut()
    }
}
