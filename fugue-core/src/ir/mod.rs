use std::fmt::{Debug, LowerHex, UpperHex};
use std::hash::Hash;

use bytes::{BufMut, BytesMut};
use rkyv::rancor::Fallible;
use rkyv::{Archive, Place, Serialize};

pub mod address;
pub use address::{
    Address, AddressWithContext, RawAddress, RawAddressMap, RawAddressRangeSet, ToRawAddress,
};

pub mod block;
pub use block::{CodeBlock, CodeBlockId, CodeBlockProperties, IndexedCodeBlockTable};

pub mod cfg;
pub use cfg::{FlowKind, FlowTarget};
pub use fugue_bytes::Endian;

pub mod function;
pub use function::{Function, FunctionId, FunctionProperties, IndexedFunctionTable};

pub mod insn;
pub use insn::{Insn, InsnId, InsnList, InsnProperties, InsnTarget, InsnTargetKind};

pub mod module;
pub use module::{Module, ModuleId};

pub mod location;
pub use location::Location;

pub mod segment;
pub use segment::{ExternFunctionTemplate, ExternSegment, SegmentProperties};

pub mod symbol;
pub use symbol::{
    IndexedSymbolTable, LazySymbol, Symbol, SymbolEntry, SymbolId, SymbolIndex, SymbolMap,
    SymbolProperties, SymbolTableSelector,
};

pub mod traits;

pub struct Id<T> {
    id: u32,
    _marker: std::marker::PhantomData<T>,
}

impl<T> Default for Id<T> {
    fn default() -> Self {
        Self::INVALID
    }
}

impl<T> Debug for Id<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <u32 as Debug>::fmt(&self.id, f)
    }
}

impl<T> LowerHex for Id<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <u32 as LowerHex>::fmt(&self.id, f)
    }
}

impl<T> UpperHex for Id<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <u32 as UpperHex>::fmt(&self.id, f)
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
        self.id == other.id
    }
}

impl<T> Eq for Id<T> {}

impl<T> PartialOrd for Id<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Id<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl<T> Hash for Id<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl<T> Id<T> {
    pub const INVALID: Self = Self::new(u32::MAX);

    pub(crate) const fn new(id: u32) -> Self {
        Id {
            id,
            _marker: std::marker::PhantomData,
        }
    }

    pub(crate) const fn from_index(index: usize) -> Self {
        assert!(index < u32::MAX as usize, "invalid index");
        Id {
            id: index as u32,
            _marker: std::marker::PhantomData,
        }
    }

    pub(crate) const fn index(&self) -> usize {
        assert!(self.id < u32::MAX, "invalid index");
        self.id as usize
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
        if buf.len() == 4 {
            Some(Id {
                id: u32::from_be_bytes(buf.try_into().unwrap()),
                _marker: std::marker::PhantomData,
            })
        } else {
            None
        }
    }

    #[inline(always)]
    pub(crate) fn encode_as_key(&self, buf: &mut BytesMut) {
        buf.put_u32(self.id);
    }
}

#[repr(transparent)]
pub struct IdSet<T> {
    set: tinyset::SetU32,
    _marker: std::marker::PhantomData<T>,
}

impl<T> Debug for IdSet<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
            _marker: std::marker::PhantomData,
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
            set: tinyset::SetU32::new(),
            _marker: std::marker::PhantomData,
        }
    }

    pub fn insert(&mut self, id: Id<T>) -> bool {
        self.set.insert(id.id)
    }

    pub fn contains(&self, id: Id<T>) -> bool {
        self.set.contains(id.id)
    }

    pub fn remove(&mut self, id: Id<T>) -> bool {
        self.set.remove(id.id)
    }

    pub fn iter(&self) -> impl Iterator<Item = Id<T>> + '_ {
        self.set.iter().map(|id| Id {
            id,
            _marker: std::marker::PhantomData,
        })
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

#[repr(transparent)]
pub struct ArchivedId(rkyv::primitive::ArchivedU32);

unsafe impl rkyv::Portable for ArchivedId {}
unsafe impl rkyv::traits::NoUndef for ArchivedId {}

unsafe impl<C: rkyv::rancor::Fallible + ?Sized> rkyv::bytecheck::CheckBytes<C> for ArchivedId
where
    rkyv::primitive::ArchivedU32: rkyv::bytecheck::CheckBytes<C>,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe { rkyv::primitive::ArchivedU32::check_bytes(value.cast(), context) }
    }
}

impl<T> Archive for Id<T> {
    type Archived = ArchivedId;
    type Resolver = ();

    fn resolve(&self, _: Self::Resolver, out: Place<Self::Archived>) {
        out.write(ArchivedId(rkyv::primitive::ArchivedU32::from_native(
            self.id,
        )));
    }
}

impl<S: Fallible + ?Sized, T> Serialize<S> for Id<T> {
    fn serialize(&self, _: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

impl<D: Fallible + ?Sized, T> rkyv::Deserialize<Id<T>, D> for ArchivedId {
    fn deserialize(&self, _: &mut D) -> Result<Id<T>, D::Error> {
        Ok(Id {
            id: self.0.to_native(),
            _marker: std::marker::PhantomData,
        })
    }
}

#[repr(transparent)]
pub struct ArchivedIdSet(rkyv::Archived<tinyset::SetU32>);

unsafe impl rkyv::Portable for ArchivedIdSet {}
unsafe impl rkyv::traits::NoUndef for ArchivedIdSet {}

unsafe impl<C: rkyv::rancor::Fallible + ?Sized> rkyv::bytecheck::CheckBytes<C> for ArchivedIdSet
where
    rkyv::Archived<tinyset::SetU32>: rkyv::bytecheck::CheckBytes<C>,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe { <rkyv::Archived<tinyset::SetU32>>::check_bytes(value.cast(), context) }
    }
}

impl<T> Archive for IdSet<T> {
    type Archived = ArchivedIdSet;
    type Resolver = <tinyset::SetU32 as Archive>::Resolver;

    fn resolve(&self, resolver: Self::Resolver, out: Place<Self::Archived>) {
        let out_inner = unsafe { out.cast_unchecked::<rkyv::Archived<tinyset::SetU32>>() };
        self.set.resolve(resolver, out_inner);
    }
}

impl<S: Fallible + rkyv::ser::Writer + rkyv::ser::Allocator + ?Sized, T> Serialize<S> for IdSet<T> {
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        self.set.serialize(serializer)
    }
}

impl<D: Fallible + ?Sized, T> rkyv::Deserialize<IdSet<T>, D> for ArchivedIdSet
where
    D::Error: rkyv::rancor::Source,
{
    fn deserialize(&self, deserializer: &mut D) -> Result<IdSet<T>, D::Error> {
        let set = rkyv::Deserialize::<tinyset::SetU32, D>::deserialize(&self.0, deserializer)?;
        Ok(IdSet {
            set,
            _marker: std::marker::PhantomData,
        })
    }
}
