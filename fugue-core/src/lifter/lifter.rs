use std::fmt::{Debug, Display};

use fugue_lifter::runtime::context::ContextBitRange;
use fugue_lifter::runtime::language::Language;
use fugue_lifter::runtime::pcode::{LiftingContext, Varnode};

use thiserror::Error;

use crate::il::pcode::PCodeOp;
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

#[derive(Clone)]
pub struct Lifter(fugue_lifter::Lifter);

impl Lifter {
    pub fn new(language: &'static Language, context: LiftingContext) -> Self {
        Self(fugue_lifter::Lifter::new(language, context))
    }

    pub fn language(&self) -> &'static Language {
        self.0.language()
    }

    pub fn context(&self) -> &LiftingContext {
        self.0.context()
    }

    pub fn context_mut(&mut self) -> &mut LiftingContext {
        self.0.context_mut()
    }

    pub fn address_alignment(&self) -> usize {
        self.0.address_alignment()
    }

    pub fn address_bits(&self) -> u32 {
        self.0.address_bits()
    }

    pub fn address_size(&self) -> usize {
        self.0.address_size()
    }

    pub fn address_upper_bound(&self) -> u64 {
        self.0.address_upper_bound()
    }

    pub fn constant_space(&self) -> u8 {
        self.0.constant_space()
    }

    pub fn default_space(&self) -> u8 {
        self.0.default_space()
    }

    pub fn register_space(&self) -> u8 {
        self.0.register_space()
    }

    pub fn register_space_size(&self) -> usize {
        self.0.register_space_size()
    }

    pub fn unique_mask(&self) -> u64 {
        self.0.unique_mask()
    }

    pub fn unique_space(&self) -> u8 {
        self.0.unique_space()
    }

    pub fn unique_space_size(&self) -> usize {
        self.0.unique_space_size()
    }

    pub fn space_name(&self, space: u8) -> Option<&'static str> {
        self.0.space_name(space)
    }

    pub fn space_by_name(&self, name: impl AsRef<str>) -> Option<u8> {
        self.0.space_by_name(name)
    }

    pub fn space_word_size(&self, space: u8) -> Option<usize> {
        self.0.space_word_size(space)
    }

    pub fn space_upper_bound(&self, space: u8) -> Option<u64> {
        self.0.space_upper_bound(space)
    }

    pub fn wrap_offset(&self, space: u8, offset: u64) -> Option<u64> {
        self.0.wrap_offset(space, offset)
    }

    pub fn context_variable_by_name(&self, name: impl AsRef<str>) -> Option<ContextBitRange> {
        self.0.context_variable_by_name(name)
    }

    pub fn register_by_name(&self, name: impl AsRef<str>) -> Option<Varnode> {
        self.0.register_by_name(name)
    }

    pub fn register_name(&self, vnd: &Varnode) -> Option<&'static str> {
        self.0.register_name(vnd)
    }

    pub fn user_op_by_name(&self, name: impl AsRef<str>) -> Option<u16> {
        self.0.user_op_by_name(name)
    }

    pub fn user_op_by_id(&self, id: u16) -> Option<&'static str> {
        self.0.user_op_by_id(id)
    }

    pub fn disassemble(
        &mut self,
        address: impl Into<Address>,
        bytes: &[u8],
        output: &mut String,
    ) -> Option<usize> {
        let address = address.into();
        self.0.disassemble(address.into(), bytes, output)
    }

    pub fn lift(&mut self, address: impl Into<Address>, bytes: &[u8]) -> Result<Insn, LifterError> {
        let address = address.into();
        let mut operations = Vec::new();

        let length = self.lift_into(address, bytes, &mut operations)?;

        Ok(Insn::from_lifted(
            self.language(),
            address,
            length,
            operations,
        ))
    }

    pub fn lift_into(
        &mut self,
        addr: impl Into<Address>,
        bytes: &[u8],
        output: &mut Vec<PCodeOp>,
    ) -> Result<usize, LifterError> {
        let address = addr.into();
        let Some(length) = self.0.lift(address.into(), bytes, output) else {
            return Err(LifterError::InvalidInstruction(address));
        };

        Ok(length)
    }
}
