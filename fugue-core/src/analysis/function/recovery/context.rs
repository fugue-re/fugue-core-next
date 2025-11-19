use crate::entities::Insn;
use crate::lifter::{
    Disassembler, DisassemblerError, DisassemblerImpl, Lifter, LifterError, LifterImpl,
    LiftingContext,
};

use crate::types::Address;

pub struct Translator {
    disassembler: Disassembler,
    lifter: Lifter,
}

impl Translator {
    pub fn new(project: &Project) -> Self {
        let disassembler = project.arch().disassembler();
        let lifter = project.arch().lifter();

        Self {
            disassembler,
            lifter,
        }
    }

    pub fn disassemble_insn(
        &mut self,
        address: Address,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Insn, DisassemblerError> {
        let bytes = bytes.as_ref();
        let insn = self
            .disassembler
            .disassemble_insn(address, bytes, self.lifter.context_mut())
            .map_err(DisassemblerError::disassembler)?;

        if !insn.needs_lifting() && insn.len() != 0 {
            return Ok(insn);
        }

        Ok(self.lifter.lift_insn(address, bytes)?)
    }

    pub fn lift_insn(
        &mut self,
        address: Address,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Insn, LifterError> {
        self.lifter.lift_insn(address, bytes.as_ref())
    }

    pub fn context(&self) -> &LiftingContext {
        self.lifter.context()
    }

    pub fn context_mut(&mut self) -> &mut LiftingContext {
        self.lifter.context_mut()
    }
}

impl DisassemblerImpl for Translator {
    fn disassemble_insn(
        &mut self,
        address: Address,
        bytes: &[u8],
        context: &mut LiftingContext,
    ) -> Result<Insn, DisassemblerError> {
        self.disassembler.disassemble_insn(address, bytes, context)
    }
}

impl LifterImpl for Translator {
    fn lift_insn(&mut self, address: Address, bytes: &[u8]) -> Result<Insn, LifterError> {
        self.lifter.lift_insn(address, bytes)
    }
}
