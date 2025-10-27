use arrayvec::ArrayVec;
use bincode::{BorrowDecode, Decode, Encode};

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

impl<'de, C> BorrowDecode<'de, C> for ContextSet {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let len = usize::borrow_decode(decoder)?;
        let mut context = ArrayVec::new();
        for _ in 0..len {
            context.push(ContextUpdate::borrow_decode(decoder)?);
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub enum ContextHintKind {
    Code(u8),
    Data,
}

impl ContextHintKind {
    pub fn code() -> Self {
        ContextHintKind::Code(0)
    }

    pub fn code_with_bitness(bits: u8) -> Self {
        ContextHintKind::Code(bits)
    }

    pub fn data() -> Self {
        ContextHintKind::Data
    }

    pub fn is_code(&self) -> bool {
        matches!(self, ContextHintKind::Code(_))
    }

    pub fn is_data(&self) -> bool {
        matches!(self, ContextHintKind::Data)
    }

    pub fn has_bitness(&self) -> bool {
        matches!(self, ContextHintKind::Code(bits) if *bits != 0)
    }

    pub fn bitness(&self) -> Option<u32> {
        match self {
            ContextHintKind::Code(bits) if *bits != 0 => Some(*bits as u32),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct ContextHint {
    kind: ContextHintKind,
    context: Option<ContextSet>,
}

impl ContextHint {
    pub fn new(kind: ContextHintKind) -> Self {
        Self::new_with(kind, None)
    }

    pub fn new_with(kind: ContextHintKind, context: impl Into<Option<ContextSet>>) -> Self {
        Self {
            kind,
            context: context.into(),
        }
    }

    pub fn code() -> Self {
        Self::new(ContextHintKind::code())
    }

    pub fn code_with_bitness(bits: u8) -> Self {
        Self::new(ContextHintKind::code_with_bitness(bits))
    }

    pub fn data() -> Self {
        Self::new(ContextHintKind::data())
    }

    pub fn kind(&self) -> &ContextHintKind {
        &self.kind
    }

    pub fn context(&self) -> Option<&ContextSet> {
        self.context.as_ref()
    }

    pub fn with_context(mut self, context: ContextSet) -> Self {
        self.context = Some(context);
        self
    }
}
