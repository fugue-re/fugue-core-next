use std::cmp::Ordering;
use std::fmt::{Debug, Formatter, LowerHex, Result as FmtResult, UpperHex};
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

use bytes::{BufMut, BytesMut};
use rkyv::bytecheck::CheckBytes;
use rkyv::primitive::ArchivedU64;
use rkyv::rancor::{Fallible, Source};
use rkyv::ser::{Allocator, Writer};
use rkyv::traits::NoUndef;
use rkyv::{Archive, Archived, Deserialize, Place, Portable, Serialize};
use tinyset::SetU64;

pub mod address;
pub use address::{
    Address, AddressRange, AddressRangeExt, AddressRangeSet, AddressWithContext, RawAddress,
    RawAddressMap, RawAddressRangeSet, ToRawAddress,
};

pub mod block;
pub use block::{CodeBlock, CodeBlockId, CodeBlockProperties, CodeBlockTable};

pub mod call_graph;
pub use call_graph::{CallGraphEdgeKey, CallGraphIndex};

pub mod cfg;
pub use cfg::{FlowKind, FlowTarget};
pub use fugue_bytes::Endian;

pub mod function;
pub use function::{Function, FunctionId, FunctionProperties, FunctionTable};

pub mod insn;
pub use insn::{Insn, InsnId, InsnList, InsnProperties, InsnTarget, InsnTargetKind};

pub mod module;
pub use module::{Module, ModuleId};

pub mod location;
pub use location::Location;

pub mod reference;
pub use reference::{
    Reference, ReferenceClass, ReferenceFlags, ReferenceIndex, ReferenceKey, ReferenceKind,
    ReferenceOrigin, ReferenceTarget,
};

pub mod segment;
pub use segment::{ExternFunctionTemplate, ExternSegment, SegmentProperties};

pub mod symbol;
pub use symbol::{
    LazySymbol, Symbol, SymbolEntry, SymbolId, SymbolIndex, SymbolMap, SymbolProperties, SymbolRef,
    SymbolTable, SymbolTableSelector, TransientSymbolTable,
};

pub struct Id<T> {
    id: u32,
    generation: u32,
    _marker: PhantomData<T>,
}

impl<T> Default for Id<T> {
    fn default() -> Self {
        Self::INVALID
    }
}

impl<T> Debug for Id<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_tuple("Id")
            .field(&self.id)
            .field(&self.generation)
            .finish()
    }
}

impl<T> LowerHex for Id<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        <u64 as LowerHex>::fmt(&self.key(), f)
    }
}

impl<T> UpperHex for Id<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        <u64 as UpperHex>::fmt(&self.key(), f)
    }
}

impl<T> Clone for Id<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Id<T> {}

impl<T> PartialEq for Id<T> {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}

impl<T> Eq for Id<T> {}

impl<T> PartialOrd for Id<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Id<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

impl<T> Hash for Id<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.generation.hash(state);
    }
}

impl<T> Id<T> {
    pub const INVALID: Self = Self::with_generation(u32::MAX, u32::MAX);

    pub(crate) const fn new(id: u32) -> Self {
        Self::with_generation(id, 0)
    }

    pub(crate) const fn with_generation(id: u32, generation: u32) -> Self {
        Self {
            id,
            generation,
            _marker: PhantomData,
        }
    }

    pub(crate) const fn from_index(index: usize) -> Self {
        assert!(index < u32::MAX as usize, "invalid index");
        Self::new(index as u32)
    }

    pub(crate) const fn index(&self) -> usize {
        assert!(self.id < u32::MAX, "invalid index");
        self.id as usize
    }

    pub(crate) const fn generation(&self) -> u32 {
        self.generation
    }

    pub(crate) const fn next_generation(&self) -> Self {
        assert!(self.generation < u32::MAX - 1, "invalid generation");
        Self::with_generation(self.id, self.generation + 1)
    }

    #[inline(always)]
    pub const fn is_valid(&self) -> bool {
        !self.is_invalid()
    }

    #[inline(always)]
    pub const fn is_invalid(&self) -> bool {
        self.id == Self::INVALID.id
    }

    #[inline(always)]
    pub(crate) fn decode_as_key(buf: &[u8]) -> Option<Self> {
        if buf.len() == 8 {
            Some(Self::from_key(u64::from_be_bytes(buf.try_into().unwrap())))
        } else {
            None
        }
    }

    #[inline(always)]
    pub(crate) fn encode_as_key(&self, buf: &mut BytesMut) {
        buf.put_u64(self.key());
    }

    #[inline(always)]
    const fn key(&self) -> u64 {
        ((self.generation as u64) << 32) | self.id as u64
    }

    #[inline(always)]
    const fn from_key(key: u64) -> Self {
        Self::with_generation(key as u32, (key >> 32) as u32)
    }
}

#[repr(transparent)]
pub struct IdSet<T> {
    set: SetU64,
    _marker: PhantomData<T>,
}

impl<T> Debug for IdSet<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl<T> Default for IdSet<T> {
    fn default() -> Self {
        IdSet::new()
    }
}

impl<T> Clone for IdSet<T> {
    fn clone(&self) -> Self {
        IdSet {
            set: self.set.clone(),
            _marker: PhantomData,
        }
    }
}

impl<T> PartialEq for IdSet<T> {
    fn eq(&self, other: &Self) -> bool {
        self.set == other.set
    }
}

impl<T> Eq for IdSet<T> {}

impl<T> IdSet<T> {
    pub const fn new() -> Self {
        IdSet {
            set: SetU64::new(),
            _marker: PhantomData,
        }
    }

    pub fn insert(&mut self, id: Id<T>) -> bool {
        self.set.insert(id.key())
    }

    pub fn contains(&self, id: Id<T>) -> bool {
        self.set.contains(id.key())
    }

    pub fn remove(&mut self, id: Id<T>) -> bool {
        self.set.remove(id.key())
    }

    pub fn iter(&self) -> impl Iterator<Item = Id<T>> + '_ {
        self.set.iter().map(Id::from_key)
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

#[repr(transparent)]
pub struct ArchivedId(ArchivedU64);

unsafe impl Portable for ArchivedId {}
unsafe impl NoUndef for ArchivedId {}

unsafe impl<C: Fallible + ?Sized> CheckBytes<C> for ArchivedId
where
    ArchivedU64: CheckBytes<C>,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe { ArchivedU64::check_bytes(value.cast(), context) }
    }
}

impl<T> Archive for Id<T> {
    type Archived = ArchivedId;
    type Resolver = ();

    fn resolve(&self, _: Self::Resolver, out: Place<Self::Archived>) {
        out.write(ArchivedId(ArchivedU64::from_native(self.key())));
    }
}

impl<S: Fallible + ?Sized, T> Serialize<S> for Id<T> {
    fn serialize(&self, _: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

impl<D: Fallible + ?Sized, T> Deserialize<Id<T>, D> for ArchivedId {
    fn deserialize(&self, _: &mut D) -> Result<Id<T>, D::Error> {
        Ok(Id::from_key(self.0.to_native()))
    }
}

#[repr(transparent)]
pub struct ArchivedIdSet(Archived<SetU64>);

unsafe impl Portable for ArchivedIdSet {}
unsafe impl NoUndef for ArchivedIdSet {}

unsafe impl<C: Fallible + ?Sized> CheckBytes<C> for ArchivedIdSet
where
    Archived<SetU64>: CheckBytes<C>,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe { <Archived<SetU64>>::check_bytes(value.cast(), context) }
    }
}

impl<T> Archive for IdSet<T> {
    type Archived = ArchivedIdSet;
    type Resolver = <SetU64 as Archive>::Resolver;

    fn resolve(&self, resolver: Self::Resolver, out: Place<Self::Archived>) {
        let out_inner = unsafe { out.cast_unchecked::<Archived<SetU64>>() };
        self.set.resolve(resolver, out_inner);
    }
}

impl<S: Fallible + Writer + Allocator + ?Sized, T> Serialize<S> for IdSet<T> {
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        self.set.serialize(serializer)
    }
}

impl<D: Fallible + ?Sized, T> Deserialize<IdSet<T>, D> for ArchivedIdSet
where
    D::Error: Source,
{
    fn deserialize(&self, deserializer: &mut D) -> Result<IdSet<T>, D::Error> {
        let set = Deserialize::<SetU64, D>::deserialize(&self.0, deserializer)?;
        Ok(IdSet {
            set,
            _marker: PhantomData,
        })
    }
}
