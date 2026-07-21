use super::FunctionRecoveryError;
use crate::ir::{Address, Insn};
use crate::lifter::{Disassembler, Lifter, LiftingContext, PCodeOp};
use crate::project::Project;

pub struct Translator {
    disassembler: Disassembler,
    lifter: Lifter,
    operations: Vec<PCodeOp>,
}

impl Translator {
    pub fn new(project: &Project) -> Self {
        let disassembler = project.arch().disassembler();
        let lifter = project.arch().lifter();

        Self {
            disassembler,
            lifter,
            operations: Vec::new(),
        }
    }

    pub fn disassemble(
        &mut self,
        address: Address,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Insn, FunctionRecoveryError> {
        let bytes = bytes.as_ref();
        let insn = self
            .disassembler
            .disassemble(address, bytes, self.lifter.context_mut())?;

        if !insn.needs_flow_resolution() && !insn.is_empty() {
            return Ok(insn);
        }

        self.lift(address, bytes)
    }

    pub fn lift(
        &mut self,
        address: Address,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Insn, FunctionRecoveryError> {
        self.lifter
            .resolve_insn_flow_into(address, bytes.as_ref(), &mut self.operations)
            .map_err(FunctionRecoveryError::from)
    }

    pub fn lift_into(
        &mut self,
        address: Address,
        bytes: impl AsRef<[u8]>,
        output: &mut Vec<PCodeOp>,
    ) -> Result<usize, FunctionRecoveryError> {
        self.lifter
            .lift_into(address, bytes.as_ref(), output)
            .map_err(FunctionRecoveryError::from)
    }

    pub fn context(&self) -> &LiftingContext {
        self.lifter.context()
    }

    pub fn context_mut(&mut self) -> &mut LiftingContext {
        self.lifter.context_mut()
    }
}
