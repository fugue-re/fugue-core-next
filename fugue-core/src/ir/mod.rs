use std::cmp::Ordering;
use std::fmt::{self, Debug, Formatter, LowerHex, UpperHex};
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::mem::size_of;

pub use fugue_bytes::Endian;
use tinyset::SetU64;

use crate::storage::entities::schema::ENTITY_INDEX_HEADER_ID;
use crate::storage::entities::{Entity, EntityId, EntityKeyCodec};
use crate::types::Revision;

pub(crate) mod address;
pub use address::{
    Address, AddressRange, AddressRangeExt, AddressRangeSet, AddressTable, AddressWithContext,
    RawAddress, RawAddressMap, RawAddressRangeSet, ToRawAddress,
};

pub(crate) mod block;
pub use block::{
    CodeBlock, CodeBlockId, CodeBlockProperties, CodeBlockRef, CodeBlockTable, IncompleteCodeBlock,
    IncompleteCodeBlockId,
};
pub(crate) use block::{CodeBlockIdsByStart, NormalisedCodeBlockRecord, PreparedCodeBlockRecord};

pub(crate) mod call_graph;
pub(crate) use call_graph::CallGraphStaging;
pub use call_graph::{CallGraphEdgeKey, CallGraphIndex};

pub(crate) mod cfg;
pub use cfg::{FlowKind, FlowTarget};

pub(crate) mod function;
pub use function::{
    Function, FunctionId, FunctionMut, FunctionProperties, FunctionRef, FunctionTable,
    FunctionTableError, IncompleteFunction, IncompleteFunctionError, InsnEntry, StackChangePoint,
};
pub(crate) use function::{
    FunctionTableStaging, NormalisedFunctionRecord, StagedFunctionChangeRecord,
};

pub(crate) mod insn;
pub use insn::{Insn, InsnError, InsnId, InsnProperties, InsnTarget, InsnTargetKind};

pub(crate) mod location;
pub use location::Location;

pub(crate) mod problem;
pub use problem::{
    Problem, ProblemClass, ProblemId, ProblemKey, ProblemKind, ProblemRef, ProblemScope,
    ProblemTable, ProblemTableError,
};

pub(crate) mod persistent;

pub(crate) mod reference;
pub(crate) use reference::PreparedReferenceIndexRecord;
pub use reference::{
    Reference, ReferenceIndex, ReferenceKey, ReferenceKind, ReferenceOrigin, ReferenceProperties,
    ReferenceTarget,
};

pub(crate) mod segment;
pub use segment::{ExternFunctionTemplate, ExternSegment, ExternSegmentError, SegmentProperties};

pub(crate) mod switch;
pub use switch::{
    Switch, SwitchCase, SwitchCaseLabel, SwitchId, SwitchModel, SwitchProperties, SwitchRef,
    SwitchTable, SwitchTableError,
};

pub(crate) mod symbol;
pub(crate) use symbol::SymbolIndexState;
pub use symbol::{
    LazySymbol, Symbol, SymbolEntry, SymbolId, SymbolIndex, SymbolInsertion, SymbolMap,
    SymbolProperties, SymbolRef, SymbolTable, SymbolTableSelector, TransientSymbolTable,
    existing_symbol, symbol,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct IndexMetadata {
    revision: Revision,
}

impl IndexMetadata {
    fn new(revision: Revision) -> Self {
        Self { revision }
    }

    fn revision(&self) -> Revision {
        self.revision
    }
}

impl Entity for IndexMetadata {
    const ID: EntityId = ENTITY_INDEX_HEADER_ID;
}

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
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Id")
            .field(&self.id)
            .field(&self.generation)
            .finish()
    }
}

impl<T> LowerHex for Id<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        <u64 as LowerHex>::fmt(&self.key(), f)
    }
}

impl<T> UpperHex for Id<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
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
    const fn key(&self) -> u64 {
        ((self.generation as u64) << 32) | self.id as u64
    }

    #[inline(always)]
    const fn from_key(key: u64) -> Self {
        Self::with_generation(key as u32, (key >> 32) as u32)
    }
}

impl<T> EntityKeyCodec for Id<T> {
    #[inline(always)]
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let (value, rest) = input.split_at_checked(size_of::<u64>())?;
        *input = rest;
        Some(Self::from_key(u64::from_be_bytes(value.try_into().ok()?)))
    }

    #[inline(always)]
    fn encode(&self, output: &mut impl Extend<u8>) {
        output.extend(self.key().to_be_bytes());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdAllocator<T> {
    free_ids: Vec<Id<T>>,
    next_index: usize,
}

impl<T> Default for IdAllocator<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> IdAllocator<T> {
    pub(crate) fn new() -> Self {
        Self {
            free_ids: Vec::new(),
            next_index: 0,
        }
    }

    pub(crate) fn next_id(&self) -> Id<T> {
        self.free_ids
            .last()
            .copied()
            .unwrap_or_else(|| Id::from_index(self.next_index))
    }

    pub(crate) fn pending_id(&self, offset: usize) -> Id<T> {
        if offset < self.free_ids.len() {
            self.free_ids[self.free_ids.len() - offset - 1]
        } else {
            Id::from_index(self.next_index + offset - self.free_ids.len())
        }
    }

    pub(crate) fn allocate(&mut self) -> Id<T> {
        match self.free_ids.pop() {
            Some(id) => id,
            None => {
                let id = Id::from_index(self.next_index);
                self.next_index += 1;
                id
            }
        }
    }

    pub(crate) fn try_allocate<R, E>(
        &mut self,
        f: impl FnOnce(Id<T>) -> Result<R, E>,
    ) -> Result<(Id<T>, R), E> {
        let id = self.next_id();
        let value = f(id)?;
        let allocated = self.allocate();
        debug_assert_eq!(allocated, id);
        Ok((id, value))
    }

    pub(crate) fn release(&mut self, id: Id<T>) {
        self.free_ids.push(id.next_generation());
    }

    pub(crate) fn mark_allocated(&mut self, id: Id<T>) {
        self.next_index = self.next_index.max(id.index() + 1);
        self.free_ids
            .retain(|free_id| free_id.index() != id.index());
    }

    pub(crate) fn free_count(&self) -> usize {
        self.free_ids.len()
    }
}

#[repr(transparent)]
pub struct IdSet<T> {
    set: SetU64,
    _marker: PhantomData<T>,
}

impl<T> Debug for IdSet<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
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
pub struct ArchivedId(rkyv::primitive::ArchivedU64);

unsafe impl rkyv::Portable for ArchivedId {}
unsafe impl rkyv::traits::NoUndef for ArchivedId {}

unsafe impl<C: rkyv::rancor::Fallible + ?Sized> rkyv::bytecheck::CheckBytes<C> for ArchivedId
where
    rkyv::primitive::ArchivedU64: rkyv::bytecheck::CheckBytes<C>,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe { rkyv::primitive::ArchivedU64::check_bytes(value.cast(), context) }
    }
}

impl<T> rkyv::Archive for Id<T> {
    type Archived = ArchivedId;
    type Resolver = ();

    fn resolve(&self, _: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        out.write(ArchivedId(rkyv::primitive::ArchivedU64::from_native(
            self.key(),
        )));
    }
}

impl<S: rkyv::rancor::Fallible + ?Sized, T> rkyv::Serialize<S> for Id<T> {
    fn serialize(&self, _: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

impl<D: rkyv::rancor::Fallible + ?Sized, T> rkyv::Deserialize<Id<T>, D> for ArchivedId {
    fn deserialize(&self, _: &mut D) -> Result<Id<T>, D::Error> {
        Ok(Id::from_key(self.0.to_native()))
    }
}

#[repr(transparent)]
pub struct ArchivedIdSet(rkyv::Archived<SetU64>);

unsafe impl rkyv::Portable for ArchivedIdSet {}
unsafe impl rkyv::traits::NoUndef for ArchivedIdSet {}

unsafe impl<C: rkyv::rancor::Fallible + ?Sized> rkyv::bytecheck::CheckBytes<C> for ArchivedIdSet
where
    rkyv::Archived<SetU64>: rkyv::bytecheck::CheckBytes<C>,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe { <rkyv::Archived<SetU64>>::check_bytes(value.cast(), context) }
    }
}

impl<T> rkyv::Archive for IdSet<T> {
    type Archived = ArchivedIdSet;
    type Resolver = <SetU64 as rkyv::Archive>::Resolver;

    fn resolve(&self, resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        let out_inner = unsafe { out.cast_unchecked::<rkyv::Archived<SetU64>>() };
        self.set.resolve(resolver, out_inner);
    }
}

impl<S: rkyv::rancor::Fallible + rkyv::ser::Writer + rkyv::ser::Allocator + ?Sized, T>
    rkyv::Serialize<S> for IdSet<T>
{
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        self.set.serialize(serializer)
    }
}

impl<D: rkyv::rancor::Fallible + ?Sized, T> rkyv::Deserialize<IdSet<T>, D> for ArchivedIdSet
where
    D::Error: rkyv::rancor::Source,
{
    fn deserialize(&self, deserializer: &mut D) -> Result<IdSet<T>, D::Error> {
        let set = rkyv::Deserialize::<SetU64, D>::deserialize(&self.0, deserializer)?;
        Ok(IdSet {
            set,
            _marker: PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    struct Marker;

    #[test]
    fn id_allocator_does_not_commit_failed_allocation() {
        let mut allocator = IdAllocator::<Marker>::new();
        let result = allocator.try_allocate(|_| Err::<(), _>("failure"));

        assert_eq!(result, Err("failure"));
        assert_eq!(allocator.next_id().index(), 0);
    }
}
