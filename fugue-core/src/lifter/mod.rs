use std::fmt::Display;
use std::path::PathBuf;

use arrayvec::ArrayVec;
use fugue_lifter::runtime::dynamic::LanguageLoadError;
use fugue_lifter::runtime::language::LanguageParseError;
pub use fugue_lifter::runtime::operand;
pub use fugue_lifter::{ContextBitRange, Language, LanguageId, LiftingContext};
use fugue_sleigh_language::LanguageError as SleighLanguageError;
use rkyv::rancor::Fallible;
use rkyv::{Archive, Place, Serialize};
use thiserror::Error;

use crate::ir::Address;

pub mod disassembler;
pub use disassembler::{Disassembler, DisassemblerError};

pub mod dynamic;
pub use dynamic::{
    LanguageLoader, resolve_language, resolve_language_id, resolve_language_id_with,
    resolve_language_with,
};

pub mod lifter;
pub use lifter::{Lifter, LifterError};

pub mod traits;

pub const MAX_CONTEXT_UPDATES: usize = 2;

#[derive(Debug, Error)]
pub enum LanguageError {
    #[error("ambiguous `.sla` `{}`: multiple variants match and none is `default`", path.display())]
    AmbiguousSla { path: PathBuf },
    #[error(transparent)]
    Database(#[from] SleighLanguageError),
    #[error("environment variable `{0}` is not set")]
    Environment(&'static str),
    #[error("ambiguous language provider for `{0}`")]
    AmbiguousProvider(String),
    #[error(transparent)]
    Load(#[from] LanguageLoadError),
    #[error(transparent)]
    Parse(#[from] LanguageParseError),
    #[error("unsupported file extension for `{}`", path.display())]
    UnsupportedExtension { path: PathBuf },
    #[error("unsupported architecture")]
    Unsupported,
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
    bits: ContextBitRange,
    value: u32,
}

impl Display for ContextUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let start = self.bits.start_bit();
        let end = self.bits.end_bit();
        let value = self.value;
        write!(f, "[{start}:{end}]={value}")
    }
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
pub struct ContextSet(ArrayVec<ContextUpdate, MAX_CONTEXT_UPDATES>);

impl Display for ContextSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("{")?;
        if let Some((first, rest)) = self.0.split_first() {
            first.fmt(f)?;
            for update in rest.iter() {
                write!(f, ", {update}")?;
            }
        }
        f.write_str("}")?;
        Ok(())
    }
}

type ContextSetInner = ArrayVec<ContextUpdate, MAX_CONTEXT_UPDATES>;

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ArchivedContextSet(rkyv::Archived<ContextSetInner>);

unsafe impl rkyv::Portable for ArchivedContextSet {}
unsafe impl rkyv::traits::NoUndef for ArchivedContextSet {}

unsafe impl<C: rkyv::rancor::Fallible + ?Sized> rkyv::bytecheck::CheckBytes<C>
    for ArchivedContextSet
where
    rkyv::Archived<ContextSetInner>: rkyv::bytecheck::CheckBytes<C>,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe { <rkyv::Archived<ContextSetInner>>::check_bytes(value.cast(), context) }
    }
}

impl Archive for ContextSet {
    type Archived = ArchivedContextSet;
    type Resolver = <ContextSetInner as Archive>::Resolver;

    fn resolve(&self, resolver: Self::Resolver, out: Place<Self::Archived>) {
        let out_inner = unsafe { out.cast_unchecked::<rkyv::Archived<ContextSetInner>>() };
        self.0.resolve(resolver, out_inner);
    }
}

impl<S: Fallible + ?Sized + rkyv::ser::Allocator + rkyv::ser::Writer> Serialize<S> for ContextSet {
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<D: Fallible + ?Sized> rkyv::Deserialize<ContextSet, D> for ArchivedContextSet {
    fn deserialize(&self, deserializer: &mut D) -> Result<ContextSet, D::Error> {
        let inner = rkyv::Deserialize::<ContextSetInner, D>::deserialize(&self.0, deserializer)?;
        Ok(ContextSet(inner))
    }
}

impl From<ContextUpdate> for ContextSet {
    fn from(value: ContextUpdate) -> Self {
        Self(ArrayVec::from_iter([value]))
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
        Self(ArrayVec::from_iter(
            iter.into_iter().take(MAX_CONTEXT_UPDATES),
        ))
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
        for update in self.0.iter_mut() {
            if update.bits == value.bits {
                *update = value;
                return;
            }
        }
        self.0.push(value);
    }

    #[inline]
    pub fn merge(&mut self, other: &Self) {
        if other.is_empty() {
            return;
        }

        if self.is_empty() {
            self.clone_from(other);
            return;
        }

        for update in other.0.iter() {
            self.push(update.to_owned());
        }
    }

    #[inline]
    pub fn apply(&self, address: Address, context: &mut LiftingContext) {
        for ContextUpdate { bits, value } in self.0.iter() {
            tracing::trace!("setting context bits {bits:?} to {value} at {address}");
            context.set_variable_by_bits(bits, address.offset(), *value);
        }
    }

    #[inline]
    pub fn apply_range(&self, from: Address, to: Option<Address>, context: &mut LiftingContext) {
        for ContextUpdate { bits, value } in self.0.iter() {
            tracing::trace!("setting context bits {bits:?} to {value} from {from} to {to:?}");
            context.set_variable_region_by_bits(
                bits,
                from.offset(),
                to.map(|a| a.offset()),
                *value,
            );
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
pub enum ContextHintKind {
    Code(u8),
    Data,
}

impl Display for ContextHintKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ContextHintKind::Code(bits) => {
                if *bits != 0 {
                    write!(f, "code ({bits}-bit)")
                } else {
                    f.write_str("code")
                }
            }
            ContextHintKind::Data => f.write_str("data"),
        }?;

        if let Some((first, rest)) = &self
            .context
            .as_ref()
            .and_then(|context| context.0.split_first())
        {
            write!(f, " with context: {first}")?;
            for update in rest.iter() {
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
        self.context = Some(context);
        self
    }
}
