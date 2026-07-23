use super::FunctionRecoveryError;
use crate::ir::{Address, Insn};
use crate::lifter::{Disassembler, Lifter, LiftingContext, PCodeOp};
use crate::project::Project;

pub struct InsnResolver {
    disassembler: Disassembler,
    lifter: Lifter,
    operations: Vec<PCodeOp>,
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

    pub fn context(&self) -> &LiftingContext {
        self.lifter.context()
    }

    pub fn context_mut(&mut self) -> &mut LiftingContext {
        self.lifter.context_mut()
    }
}
