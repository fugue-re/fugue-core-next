use arrayvec::ArrayVec;
use bincode::{Decode, Encode};

pub use fugue_lifter::{ContextBitRange, Language, LanguageId, LanguageVariant, LiftingContext};

use crate::ir::Address;

pub mod disassembler;
pub use disassembler::{Disassembler, DisassemblerError};

pub mod lifter;
pub use lifter::{Lifter, LifterError};

pub mod traits;

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
