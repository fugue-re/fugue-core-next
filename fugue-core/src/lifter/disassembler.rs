use std::fmt::{Debug, Display};

use thiserror::Error;

use crate::ir::{Address, Insn};
use crate::lifter::LiftingContext;

#[derive(Debug, Error)]
pub enum DisassemblerError {
    #[error(transparent)]
    Disassembler(anyhow::Error),
    #[error("invalid instruction at {0}")]
    InvalidInstruction(Address),
}

impl DisassemblerError {
    pub fn invalid_instruction(address: Address) -> Self {
        Self::InvalidInstruction(address)
    }

    pub fn disassembler<E>(error: E) -> Self
    where
        E: std::error::Error + Debug + Display + Send + Sync + 'static,
    {
        Self::Disassembler(anyhow::Error::new(error))
    }

    pub fn disassembler_with<M>(msg: M) -> Self
    where
        M: Debug + Display + Send + Sync + 'static,
    {
        Self::Disassembler(anyhow::Error::msg(msg))
    }
}

pub trait DisassemblerImpl {
    fn disassemble_insn(
        &mut self,
        address: Address,
        bytes: &[u8],
        context: &mut LiftingContext,
    ) -> Result<Insn, DisassemblerError>;
}

pub struct Disassembler(Box<dyn DisassemblerImpl>);

impl Disassembler {
    pub fn new(disassembler: impl DisassemblerImpl + 'static) -> Self {
        Self(Box::new(disassembler))
    }

    fn disassemble_insn(
        &mut self,
        address: Address,
        bytes: &[u8],
        context: &mut LiftingContext,
    ) -> Result<Insn, DisassemblerError> {
        self.0.disassemble_insn(address, bytes, context)
    }
}
