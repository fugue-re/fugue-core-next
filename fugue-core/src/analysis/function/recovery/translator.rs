use super::FunctionRecoveryError;
use crate::ir::{Address, Insn};
use crate::lifter::{Disassembler, Lifter, LiftingContext};
use crate::project::Project;
use crate::storage::ProjectStorageProvider;

pub struct Translator {
    disassembler: Disassembler,
    lifter: Lifter,
}

impl Translator {
    pub fn new<P>(project: &Project<P>) -> Self
    where
        P: ProjectStorageProvider,
    {
        let disassembler = project.arch().disassembler();
        let lifter = project.arch().lifter();

        Self {
            disassembler,
            lifter,
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

        if !insn.needs_lifting() && !insn.is_empty() {
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
            .lift(address, bytes.as_ref())
            .map_err(FunctionRecoveryError::from)
    }

    pub fn context(&self) -> &LiftingContext {
        self.lifter.context()
    }

    pub fn context_mut(&mut self) -> &mut LiftingContext {
        self.lifter.context_mut()
    }
}
