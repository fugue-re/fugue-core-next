use std::fmt::{Debug, Display};

use arrayvec::ArrayVec;
use bincode::{Decode, Encode};

pub use fugue_lifter::{
    aarch64, arm, x86, x86_64, ContextBitRange, Language, LanguageId, LanguageVariant, Lifter,
    LifterBuilder, LifterBuilderError, LiftingContext, Op, PCodeOp, Varnode,
};

use thiserror::Error;

use crate::entities::Insn;
use crate::types::Address;

#[derive(Debug, Error)]
pub enum LifterError {
    #[error("invalid instruction at {0}")]
    InvalidInstruction(Address),
}

#[derive(Debug, Error)]
pub enum DisassemblerError {
    #[error(transparent)]
    Disassembler(anyhow::Error),
    #[error("invalid instruction at {0}")]
    InvalidInstruction(Address),
}

impl From<LifterError> for DisassemblerError {
    fn from(value: LifterError) -> Self {
        match value {
            LifterError::InvalidInstruction(address) => Self::InvalidInstruction(address),
        }
    }
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
        M: Display + Debug + Send + Sync + 'static,
    {
        Self::Disassembler(anyhow::Error::msg(msg))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Decode, Encode)]
pub struct ContextUpdate {
    bits: ContextBitRange,
    value: u32,
}

impl ContextUpdate {
    pub fn new(bits: ContextBitRange, value: u32) -> Self {
        Self { bits, value }
    }

    pub fn bits(&self) -> &ContextBitRange {
        &self.bits
    }

    pub fn value(&self) -> u32 {
        self.value
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ContextSet(ArrayVec<ContextUpdate, 2>);

impl Encode for ContextSet {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.0.len().encode(encoder)?;
        for update in self.0.iter() {
            update.encode(encoder)?;
        }
        Ok(())
    }
}

impl<C> Decode<C> for ContextSet {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let len = usize::decode(decoder)?;
        let mut context = ArrayVec::new();
        for _ in 0..len {
            context.push(ContextUpdate::decode(decoder)?);
        }
        Ok(Self(context))
    }
}

impl From<ContextUpdate> for ContextSet {
    fn from(value: ContextUpdate) -> Self {
        Self(ArrayVec::from_iter([value]))
    }
}

impl ContextSet {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub fn single(bits: ContextBitRange, value: u32) -> Self {
        ContextUpdate::new(bits, value).into()
    }

    #[inline]
    pub fn push(&mut self, value: ContextUpdate) {
        self.0.push(value);
    }

    #[inline]
    pub fn merge(&mut self, other: Self) {
        if other.is_empty() {
            return;
        }

        if self.is_empty() {
            *self = other;
            return;
        }

        for update in other.0 {
            if !self.0.iter().any(|existing| existing.bits == update.bits) {
                self.0.push(update);
            }
        }
    }

    #[inline]
    pub fn apply(&self, address: Address, context: &mut LiftingContext) {
        for ContextUpdate { bits, value } in self.0.iter() {
            tracing::trace!("setting context bits {bits:?} to {value} at {address}");
            context.set_variable_by_bits(bits, address.into(), *value);
        }
    }

    #[inline]
    pub fn apply_range(&self, from: Address, to: Option<Address>, context: &mut LiftingContext) {
        for ContextUpdate { bits, value } in self.0.iter() {
            tracing::trace!("setting context bits {bits:?} to {value} from {from} to {to:?}");
            context.set_variable_region_by_bits(bits, from.into(), to.map(Address::into), *value);
        }
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

pub trait LifterExt {
    fn lift_insn(&mut self, address: Address, bytes: &[u8]) -> Result<Insn, LifterError>;
}

impl LifterExt for Lifter {
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

pub struct HybridLifter {
    disassembler: Disassembler,
    lifter: Lifter,
}

impl HybridLifter {
    pub fn new(disassembler: Disassembler, lifter: Lifter) -> Self {
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
