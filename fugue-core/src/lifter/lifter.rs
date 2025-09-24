use std::fmt::{Debug, Display};

use thiserror::Error;

pub use fugue_lifter::{Lifter, LifterBuilder, LifterBuilderError};

use crate::ir::{Address, Insn};

#[derive(Debug, Error)]
pub enum LifterError {
    #[error("invalid instruction at {0}")]
    InvalidInstruction(Address),
    #[error(transparent)]
    Lifter(anyhow::Error),
}

impl LifterError {
    pub fn invalid_instruction(address: Address) -> Self {
        Self::InvalidInstruction(address)
    }

    pub fn disassembler<E>(error: E) -> Self
    where
        E: std::error::Error + Debug + Display + Send + Sync + 'static,
    {
        Self::Lifter(anyhow::Error::new(error))
    }

    pub fn disassembler_with<M>(msg: M) -> Self
    where
        M: Debug + Display + Send + Sync + 'static,
    {
        Self::Lifter(anyhow::Error::msg(msg))
    }
}

pub trait LifterImpl {
    fn lift_insn(&mut self, address: Address, bytes: &[u8]) -> Result<Insn, LifterError>;
}

impl LifterImpl for Lifter {
    fn lift_insn(&mut self, address: Address, bytes: &[u8]) -> Result<Insn, LifterError> {
        let mut operations = Vec::new();
        let Some(length) = self.lift(address.into(), bytes, &mut operations) else {
            return Err(LifterError::InvalidInstruction(address));
        };

        Ok(Insn::from_lifted(
            self.language(),
            address,
            length,
            operations,
        ))
    }
}
