use std::fmt::{self, Display};
use std::num::NonZeroU8;
use std::path::PathBuf;

pub use fugue_lifter::runtime::context::{TrackedContext, TrackedSet};
use fugue_lifter::runtime::dynamic::LanguageLoadError;
use fugue_lifter::runtime::language::LanguageParseError;
pub use fugue_lifter::runtime::operand;
pub use fugue_lifter::{
    ContextBitRange, Language, LanguageId, LiftingContext, Op, PCodeOp as RawPCodeOp, Varnode,
};
use fugue_sleigh_language::LanguageError as SleighLanguageError;
use thiserror::Error;

use crate::ir::Address;
use crate::types::EstimateSize;

mod disassembler;
pub use disassembler::{Disassembler, DisassemblerError};

mod dynamic;
pub use dynamic::{
    LanguageLoader, LanguageSource, resolve_language, resolve_language_id,
    resolve_language_id_with, resolve_language_with,
};

mod lift;
pub use lift::{Lifter, LifterError};

mod resolver;
pub(crate) use resolver::InsnResolver;
pub use resolver::InsnResolverError;

pub(crate) mod traits;

pub const MAX_CONTEXT_UPDATES: usize = 2;

#[derive(Debug, Error)]
pub enum LanguageError {
    #[error("ambiguous language provider for `{0}`")]
    AmbiguousProvider(String),
    #[error("ambiguous `.sla` `{}`: multiple variants match and none is `default`", path.display())]
    AmbiguousSla { path: PathBuf },
    #[error(transparent)]
    Database(#[from] SleighLanguageError),
    #[error("environment variable `{0}` is not set")]
    Environment(&'static str),
    #[error(transparent)]
    Load(#[from] LanguageLoadError),
    #[error(transparent)]
    Parse(#[from] LanguageParseError),
    #[error("unsupported architecture")]
    Unsupported,
    #[error("unsupported file extension for `{}`", path.display())]
    UnsupportedExtension { path: PathBuf },
}

impl LanguageError {
    pub fn ambiguous_sla(path: impl Into<PathBuf>) -> Self {
        Self::AmbiguousSla { path: path.into() }
    }

    pub fn unsupported_extension(path: impl Into<PathBuf>) -> Self {
        Self::UnsupportedExtension { path: path.into() }
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(PartialEq, Eq, PartialOrd, Ord, Hash))]
pub struct ContextUpdate {
    start: u8,
    #[rkyv(niche)]
    end: NonZeroU8,
    value: u32,
}

impl Display for ContextUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = self.bits();
        let start = bits.start_bit();
        let end = bits.end_bit();
        let value = self.value();
        write!(f, "[{start}:{end}]={value}")
    }
}

impl ContextUpdate {
    #[inline]
    pub fn new(bits: ContextBitRange, value: u32) -> Self {
        let start = u8::try_from(bits.word() * 32 + bits.start_bit())
            .expect("context bit position exceeds 255");
        let end = NonZeroU8::new(bits.end_bit() as u8 + 1).expect("context bit range is non-empty");
        Self { start, end, value }
    }

    pub fn bits(&self) -> ContextBitRange {
        let start = usize::from(self.start);
        let end = (start & !31) | usize::from(self.end.get() - 1);
        ContextBitRange::new(start, end)
    }

    pub fn value(&self) -> u32 {
        self.value
    }
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ContextSet([Option<ContextUpdate>; MAX_CONTEXT_UPDATES]);

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, rkyv::Portable, rkyv::bytecheck::CheckBytes)]
#[bytecheck(crate = rkyv::bytecheck)]
#[repr(transparent)]
pub struct ArchivedContextSet(rkyv::vec::ArchivedVec<ArchivedContextUpdate>);

impl rkyv::Archive for ContextSet {
    type Archived = ArchivedContextSet;
    type Resolver = rkyv::vec::VecResolver;

    fn resolve(&self, resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        rkyv::munge::munge!(let ArchivedContextSet(updates) = out);
        rkyv::vec::ArchivedVec::resolve_from_len(self.iter().count(), resolver, updates);
    }
}

impl<S> rkyv::Serialize<S> for ContextSet
where
    S: rkyv::rancor::Fallible + rkyv::ser::Allocator + rkyv::ser::Writer + ?Sized,
{
    fn serialize(&self, serialiser: &mut S) -> Result<Self::Resolver, S::Error> {
        rkyv::vec::ArchivedVec::serialize_from_unknown_length_iter(
            &mut self.iter().cloned(),
            serialiser,
        )
    }
}

impl<D> rkyv::Deserialize<ContextSet, D> for ArchivedContextSet
where
    D: rkyv::rancor::Fallible + ?Sized,
{
    fn deserialize(&self, deserialiser: &mut D) -> Result<ContextSet, D::Error> {
        assert!(
            self.0.len() <= MAX_CONTEXT_UPDATES,
            "context update limit exceeded"
        );
        let mut context = ContextSet::new();
        for (slot, update) in context.0.iter_mut().zip(self.0.iter()) {
            *slot = Some(update.deserialize(deserialiser)?);
        }
        Ok(context)
    }
}

impl fmt::Debug for ContextSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl EstimateSize for ContextSet {
    fn estimate_size(&self) -> usize {
        size_of::<Self>()
    }
}

impl Display for ContextSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("{")?;
        let mut updates = self.iter();
        if let Some(first) = updates.next() {
            first.fmt(f)?;
            for update in updates {
                write!(f, ", {update}")?;
            }
        }
        f.write_str("}")
    }
}

impl From<ContextUpdate> for ContextSet {
    #[inline]
    fn from(value: ContextUpdate) -> Self {
        Self::from_iter([value])
    }
}

impl FromIterator<(ContextBitRange, u32)> for ContextSet {
    fn from_iter<T: IntoIterator<Item = (ContextBitRange, u32)>>(iter: T) -> Self {
        Self::from_iter(
            iter.into_iter()
                .map(|(bits, value)| ContextUpdate::new(bits, value)),
        )
    }
}

impl FromIterator<ContextUpdate> for ContextSet {
    fn from_iter<T: IntoIterator<Item = ContextUpdate>>(iter: T) -> Self {
        let mut context = Self::new();
        for (slot, update) in context.0.iter_mut().zip(iter) {
            *slot = Some(update);
        }
        context
    }
}

impl ContextSet {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn single(bits: ContextBitRange, value: u32) -> Self {
        ContextUpdate::new(bits, value).into()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0[0].is_none()
    }

    #[inline]
    pub fn insert(&mut self, value: ContextUpdate) {
        let slot = self
            .0
            .iter_mut()
            .find(|slot| {
                slot.as_ref()
                    .is_none_or(|update| update.start == value.start && update.end == value.end)
            })
            .expect("context update limit exceeded");
        *slot = Some(value);
    }

    #[inline]
    pub fn merge(&mut self, other: &Self) {
        if self.is_empty() {
            self.clone_from(other);
            return;
        }

        for update in other.iter() {
            self.insert(update.clone());
        }
    }

    #[inline]
    pub fn apply(&self, address: Address, context: &mut LiftingContext) {
        for update in self.iter() {
            let bits = update.bits();
            let value = update.value();
            tracing::trace!("setting context bits {bits:?} to {value} at {address}");
            context.set_variable_by_bits(&bits, address.offset(), value);
        }
    }

    #[inline]
    pub fn apply_range(&self, from: Address, to: Option<Address>, context: &mut LiftingContext) {
        for update in self.iter() {
            let bits = update.bits();
            let value = update.value();
            tracing::trace!("setting context bits {bits:?} to {value} from {from} to {to:?}");
            context.set_variable_region_by_bits(
                &bits,
                from.offset(),
                to.map(|a| a.offset()),
                value,
            );
        }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &ContextUpdate> + '_ {
        self.0.iter().flatten()
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum ContextHintKind {
    Code(u8),
    Data,
}

impl Display for ContextHintKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContextHintKind::Code(bits) => {
                if *bits != 0 {
                    write!(f, "code ({bits}-bit)")
                } else {
                    f.write_str("code")
                }
            }
            ContextHintKind::Data => f.write_str("data"),
        }
    }
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

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct ContextHint {
    kind: ContextHintKind,
    context: Option<ContextSet>,
}

impl Display for ContextHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)?;

        let mut updates = self.context.iter().flat_map(ContextSet::iter);
        if let Some(first) = updates.next() {
            write!(f, " with context: {first}")?;
            for update in updates {
                write!(f, ", {update}")?;
            }
        }

        Ok(())
    }
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

    pub fn is_code(&self) -> bool {
        self.kind.is_code()
    }

    pub fn is_data(&self) -> bool {
        self.kind.is_data()
    }

    pub fn context(&self) -> Option<&ContextSet> {
        self.context.as_ref()
    }

    pub fn with_context(mut self, context: ContextSet) -> Self {
        self.set_context(context);
        self
    }

    pub fn set_context(&mut self, context: ContextSet) {
        self.context = Some(context);
    }
}
