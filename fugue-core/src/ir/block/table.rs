use std::collections::BTreeMap;
use std::sync::Arc;

use iset::{Entry, IntervalMap};
use smallvec::SmallVec;
use thiserror::Error;

use crate::ir::{Address, CodeBlock, Id, IdSet, RawAddress};
use crate::lifter::ContextSet;
use crate::storage::entities::schema::ENTITY_CODE_BLOCK_TABLE_ID;
use crate::storage::entities::{
    Entity, EntityCache, EntityId, EntityMut, EntityRef, ProjectEntity, Ref, RefMut,
    WriteBackWorker,
};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::{EntityStorage, EntityStorageError};

const CODE_BLOCK_TABLE_VERSION: u32 = 1;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct CodeBlockTableHeader {
    version: u32,
}

impl Entity for CodeBlockTableHeader {
    const ID: EntityId = ENTITY_CODE_BLOCK_TABLE_ID;
}

struct CodeBlockIndex {
    bounds: BTreeMap<AddressSpaceId, IntervalMap<RawAddress, IdSet<CodeBlock>>>,
    free_ids: Vec<Id<CodeBlock>>,
    count: usize,
}

pub struct PersistentCodeBlockTable {
    index: CodeBlockIndex,
    entries: EntityCache<Id<CodeBlock>, CodeBlock>,
}

pub struct TransientCodeBlockTable {
    index: CodeBlockIndex,
    entries: Vec<Option<CodeBlock>>,
}

pub enum CodeBlockTable {
    Persistent(PersistentCodeBlockTable),
    Transient(TransientCodeBlockTable),
}

#[derive(Debug, Error)]
pub enum CodeBlockTableError {
    #[error("code block to insert has a different address than that used for insertion")]
    AddressMismatch,
    #[error(transparent)]
    Other(anyhow::Error),
    #[error(transparent)]
    Storage(#[from] EntityStorageError),
}

impl CodeBlockTableError {
    pub fn other<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Other(anyhow::Error::new(error))
    }

    pub fn other_with<M>(msg: M) -> Self
    where
        M: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    {
        Self::Other(anyhow::Error::msg(msg))
    }
}

pub type CodeBlockRef<'a> = Ref<'a, CodeBlock>;
pub type CodeBlockMut<'a> = RefMut<'a, Id<CodeBlock>, CodeBlock>;

type PersistentRef<'a> = EntityRef<'a, CodeBlock>;
type PersistentMut<'a> = EntityMut<'a, Id<CodeBlock>, CodeBlock>;

pub struct CodeBlockIter<'a> {
    inner: Box<dyn Iterator<Item = CodeBlockRef<'a>> + 'a>,
}

impl<'a> CodeBlockIter<'a> {
    pub fn new(iter: impl Iterator<Item = CodeBlockRef<'a>> + 'a) -> Self {
        Self {
            inner: Box::new(iter),
        }
    }
}

impl<'a> Iterator for CodeBlockIter<'a> {
    type Item = CodeBlockRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

pub struct CodeBlockIterMut<'a> {
    inner: Box<dyn Iterator<Item = CodeBlockMut<'a>> + 'a>,
}

impl<'a> CodeBlockIterMut<'a> {
    pub fn new(iter: impl Iterator<Item = CodeBlockMut<'a>> + 'a) -> Self {
        Self {
            inner: Box::new(iter),
        }
    }
}

impl<'a> Iterator for CodeBlockIterMut<'a> {
    type Item = CodeBlockMut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

type PersistentIter<'a> = Box<dyn Iterator<Item = PersistentRef<'a>> + 'a>;
type PersistentIterMut<'a> = Box<dyn Iterator<Item = PersistentMut<'a>> + 'a>;

impl PersistentCodeBlockTable {
    pub fn new(entities: EntityStorage, cache_bytes: usize) -> Result<Self, EntityStorageError> {
        Self::from_entries(EntityCache::new(entities, cache_bytes)?)
    }

    pub fn new_with(
        entities: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Self::from_entries(EntityCache::with_worker(entities, worker, cache_bytes))
    }

    fn from_entries(
        entries: EntityCache<Id<CodeBlock>, CodeBlock>,
    ) -> Result<Self, EntityStorageError> {
        let mut bounds = BTreeMap::<AddressSpaceId, IntervalMap<RawAddress, IdSet<CodeBlock>>>::new();
        let mut free_ids = Vec::new();
        let mut count = 0;
        let mut expected = 0u32;

        for entry in entries.try_iter()? {
            let (id, block) = entry?;

            let range = block.start().address()..block.next_address().address();
            bounds
                .entry(block.space())
                .or_default()
                .entry(range)
                .or_default()
                .insert(id);

            let index = id.index() as u32;
            while expected < index {
                free_ids.push(Id::new(expected));
                expected += 1;
            }
            expected = index + 1;
            count += 1;
        }

        Ok(Self {
            index: CodeBlockIndex {
                bounds,
                free_ids,
                count,
            },
            entries,
        })
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        self.entries.flush()
    }

    pub fn insert<F>(&mut self, addr: Address, f: F) -> Result<Id<CodeBlock>, CodeBlockTableError>
    where
        F: FnOnce(Id<CodeBlock>, Address) -> Result<CodeBlock, CodeBlockTableError>,
    {
        let reuse_id = self.index.free_ids.last().copied();
        let id = reuse_id.unwrap_or_else(|| Id::from_index(self.index.count));

        let block = f(id, addr)?;

        if block.start() != addr {
            return Err(CodeBlockTableError::AddressMismatch);
        }

        let range = block.start().address()..block.next_address().address();
        self.index
            .bounds
            .entry(addr.space())
            .or_default()
            .entry(range)
            .or_default()
            .insert(id);

        if reuse_id.is_some() {
            self.index.free_ids.pop();
        }

        self.entries.put(id, block);
        self.index.count += 1;

        Ok(id)
    }

    pub fn get_by_id(&self, id: Id<CodeBlock>) -> Option<PersistentRef<'_>> {
        self.try_get_by_id(id).unwrap_or_else(|e| e.into_fatal())
    }

    pub fn try_get_by_id(
        &self,
        id: Id<CodeBlock>,
    ) -> Result<Option<PersistentRef<'_>>, EntityStorageError> {
        self.entries.try_get(&id)
    }

    pub fn modify_by_id<R>(
        &mut self,
        id: Id<CodeBlock>,
        f: impl FnOnce(&mut CodeBlock) -> R,
    ) -> Option<R> {
        self.try_modify_by_id(id, f)
            .unwrap_or_else(|e| e.into_fatal())
    }

    pub fn try_modify_by_id<R>(
        &mut self,
        id: Id<CodeBlock>,
        f: impl FnOnce(&mut CodeBlock) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        self.entries.try_modify(&id, f)
    }

    pub fn get_by_id_mut(
        &mut self,
        id: Id<CodeBlock>,
    ) -> Option<EntityMut<'_, Id<CodeBlock>, CodeBlock>> {
        self.entries.get_mut(&id)
    }

    pub fn try_get_by_id_mut(
        &mut self,
        id: Id<CodeBlock>,
    ) -> Result<Option<EntityMut<'_, Id<CodeBlock>, CodeBlock>>, EntityStorageError> {
        self.entries.try_get_mut(&id)
    }

    pub fn remove_by_id(&mut self, id: Id<CodeBlock>) -> bool {
        self.try_remove_by_id(id).unwrap_or_else(|e| e.into_fatal())
    }

    pub fn try_remove_by_id(&mut self, id: Id<CodeBlock>) -> Result<bool, EntityStorageError> {
        let Some(block) = self.entries.try_get(&id)? else {
            return Ok(false);
        };

        let space = block.space();
        let range = block.start().address()..block.next_address().address();
        drop(block);

        if let Some(Entry::Occupied(mut entry)) =
            self.index.bounds.get_mut(&space).map(|m| m.entry(range))
        {
            let id_set = entry.get_mut();
            id_set.remove(id);

            if id_set.is_empty() {
                entry.remove();
            }
        }

        self.entries.try_remove(&id)?;
        self.index.free_ids.push(id);
        self.index.count -= 1;

        Ok(true)
    }

    pub fn remove_by_address(&mut self, addr: Address) -> usize {
        self.try_remove_by_address(addr)
            .unwrap_or_else(|e| e.into_fatal())
    }

    pub fn try_remove_by_address(&mut self, addr: Address) -> Result<usize, EntityStorageError> {
        let space = addr.space();
        let raw = addr.address();

        let Some(bounds) = self.index.bounds.get_mut(&space) else {
            return Ok(0);
        };

        let ranges = bounds
            .intervals_overlap(raw)
            .filter(|iv| iv.start == raw)
            .collect::<SmallVec<[_; 2]>>();

        let mut removed = 0;

        for range in ranges {
            let Some(id_set) = bounds.remove(range) else {
                continue;
            };

            for id in id_set.iter() {
                self.entries.try_remove(&id)?;
                self.index.free_ids.push(id);
                self.index.count -= 1;
                removed += 1;
            }
        }

        Ok(removed)
    }

    pub fn remove_by_address_and_context(&mut self, addr: Address, context: &ContextSet) -> usize {
        self.try_remove_by_address_and_context(addr, context)
            .unwrap_or_else(|e| e.into_fatal())
    }

    pub fn try_remove_by_address_and_context(
        &mut self,
        addr: Address,
        context: &ContextSet,
    ) -> Result<usize, EntityStorageError> {
        let space = addr.space();
        let raw = addr.address();

        let Some(bounds) = self.index.bounds.get_mut(&space) else {
            return Ok(0);
        };

        let ranges = bounds
            .intervals_overlap(raw)
            .filter(|iv| iv.start == raw)
            .collect::<SmallVec<[_; 2]>>();

        let mut removed = 0;

        for range in ranges {
            let Entry::Occupied(mut entry) = bounds.entry(range) else {
                continue;
            };

            let mut matching = SmallVec::<[Id<CodeBlock>; 2]>::new();
            for id in entry.get().iter() {
                let Some(block) = self.entries.try_get(&id)? else {
                    continue;
                };
                if block.context() == context {
                    matching.push(id);
                }
            }

            for &id in &matching {
                entry.get_mut().remove(id);
            }

            if entry.get().is_empty() {
                entry.remove();
            }

            for id in matching {
                self.entries.try_remove(&id)?;
                self.index.free_ids.push(id);
                self.index.count -= 1;
                removed += 1;
            }
        }

        Ok(removed)
    }

    pub fn get_by_address(&self, maddr: Address) -> PersistentIter<'_> {
        let space = maddr.space();
        let raw = maddr.address();

        let Some(bounds) = self.index.bounds.get(&space) else {
            return Box::new(std::iter::empty());
        };

        Box::new(bounds.values(raw..=raw).flat_map(move |id_set| {
            id_set.iter().filter_map(move |id| {
                let block = self.entries.get(&id)?;
                (block.start() == maddr).then_some(block)
            })
        }))
    }

    pub fn get_by_address_and_context<'a>(
        &'a self,
        maddr: Address,
        context: &'a ContextSet,
    ) -> PersistentIter<'a> {
        let space = maddr.space();
        let raw = maddr.address();

        let Some(bounds) = self.index.bounds.get(&space) else {
            return Box::new(std::iter::empty());
        };

        Box::new(bounds.values(raw..=raw).flat_map(move |id_set| {
            id_set.iter().filter_map(move |id| {
                let block = self.entries.get(&id)?;
                (block.start() == maddr && block.context() == context).then_some(block)
            })
        }))
    }

    pub fn contains(&self, addr: Address) -> bool {
        let space = addr.space();
        let raw = addr.address();

        self.index
            .bounds
            .get(&space)
            .is_some_and(|bounds| bounds.has_overlap(raw..=raw))
    }

    pub fn overlaps(&self, addr: Address) -> PersistentIter<'_> {
        let space = addr.space();
        let raw = addr.address();

        let Some(bounds) = self.index.bounds.get(&space) else {
            return Box::new(std::iter::empty());
        };

        Box::new(
            bounds
                .values(raw..=raw)
                .flat_map(move |id_set| id_set.iter().filter_map(move |id| self.entries.get(&id))),
        )
    }

    pub fn get_by_address_mut(&mut self, maddr: Address) -> PersistentIterMut<'_> {
        let space = maddr.space();
        let raw = maddr.address();

        let ids = self
            .index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.overlap(raw))
            .filter(move |(range, _)| range.start == raw)
            .flat_map(|(_, id_set)| id_set.iter());

        Box::new(self.entries.get_disjoint_mut(ids))
    }

    pub fn get_by_address_and_context_mut<'a>(
        &'a mut self,
        maddr: Address,
        context: &'a ContextSet,
    ) -> PersistentIterMut<'a> {
        let space = maddr.space();
        let raw = maddr.address();

        let ids = self
            .index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.overlap(raw))
            .filter(move |(range, _)| range.start == raw)
            .flat_map(|(_, id_set)| id_set.iter());

        Box::new(
            self.entries
                .get_disjoint_mut(ids)
                .filter(move |block| block.context() == context),
        )
    }

    pub fn overlaps_mut(&mut self, addr: Address) -> PersistentIterMut<'_> {
        let space = addr.space();
        let raw = addr.address();

        let ids = self
            .index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(raw..=raw))
            .flat_map(|id_set| id_set.iter());

        Box::new(self.entries.get_disjoint_mut(ids))
    }

    pub fn iter(&self) -> PersistentIter<'_> {
        Box::new(self.entries.iter())
    }

    pub fn iter_mut(&mut self) -> PersistentIterMut<'_> {
        Box::new(self.entries.iter_mut())
    }

    pub fn is_empty(&self) -> bool {
        self.index.count == 0
    }

    pub fn len(&self) -> usize {
        self.index.count
    }
}

impl Default for TransientCodeBlockTable {
    fn default() -> Self {
        Self::new()
    }
}

impl TransientCodeBlockTable {
    pub fn new() -> Self {
        Self {
            index: CodeBlockIndex {
                bounds: BTreeMap::new(),
                free_ids: Vec::new(),
                count: 0,
            },
            entries: Vec::new(),
        }
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        Ok(())
    }

    fn get_raw(&self, id: Id<CodeBlock>) -> Option<&CodeBlock> {
        self.entries.get(id.index())?.as_ref()
    }

    pub fn insert<F>(&mut self, addr: Address, f: F) -> Result<Id<CodeBlock>, CodeBlockTableError>
    where
        F: FnOnce(Id<CodeBlock>, Address) -> Result<CodeBlock, CodeBlockTableError>,
    {
        let reuse_id = self.index.free_ids.last().copied();
        let id = reuse_id.unwrap_or_else(|| Id::from_index(self.index.count));

        let block = f(id, addr)?;

        if block.start() != addr {
            return Err(CodeBlockTableError::AddressMismatch);
        }

        let range = block.start().address()..block.next_address().address();
        self.index
            .bounds
            .entry(addr.space())
            .or_default()
            .entry(range)
            .or_default()
            .insert(id);

        if reuse_id.is_some() {
            self.index.free_ids.pop();
        }

        let index = id.index();
        if index >= self.entries.len() {
            self.entries.resize_with(index + 1, || None);
        }
        self.entries[index] = Some(block);
        self.index.count += 1;

        Ok(id)
    }

    pub fn get_by_id(&self, id: Id<CodeBlock>) -> Option<&CodeBlock> {
        self.get_raw(id)
    }

    pub fn modify_by_id<R>(
        &mut self,
        id: Id<CodeBlock>,
        f: impl FnOnce(&mut CodeBlock) -> R,
    ) -> Option<R> {
        self.get_by_id_mut(id).map(f)
    }

    pub fn get_by_id_mut(&mut self, id: Id<CodeBlock>) -> Option<&mut CodeBlock> {
        self.entries.get_mut(id.index())?.as_mut()
    }

    pub fn remove_by_id(&mut self, id: Id<CodeBlock>) -> bool {
        let Some(block) = self.get_raw(id) else {
            return false;
        };

        let space = block.space();
        let range = block.start().address()..block.next_address().address();

        if let Some(Entry::Occupied(mut entry)) =
            self.index.bounds.get_mut(&space).map(|m| m.entry(range))
        {
            let id_set = entry.get_mut();
            id_set.remove(id);

            if id_set.is_empty() {
                entry.remove();
            }
        }

        self.entries[id.index()] = None;
        self.index.free_ids.push(id);
        self.index.count -= 1;

        true
    }

    pub fn remove_by_address(&mut self, addr: Address) -> usize {
        let space = addr.space();
        let raw = addr.address();

        let Some(bounds) = self.index.bounds.get_mut(&space) else {
            return 0;
        };

        let ranges = bounds
            .intervals_overlap(raw)
            .filter(|iv| iv.start == raw)
            .collect::<SmallVec<[_; 2]>>();

        let mut removed = 0;

        for range in ranges {
            let Some(id_set) = bounds.remove(range) else {
                continue;
            };

            for id in id_set.iter() {
                self.entries[id.index()] = None;
                self.index.free_ids.push(id);
                self.index.count -= 1;
                removed += 1;
            }
        }

        removed
    }

    pub fn remove_by_address_and_context(&mut self, addr: Address, context: &ContextSet) -> usize {
        let space = addr.space();
        let raw = addr.address();

        let Some(bounds) = self.index.bounds.get_mut(&space) else {
            return 0;
        };

        let ranges = bounds
            .intervals_overlap(raw)
            .filter(|iv| iv.start == raw)
            .collect::<SmallVec<[_; 2]>>();

        let mut matching = SmallVec::<[Id<CodeBlock>; 2]>::new();

        for range in ranges {
            let Entry::Occupied(mut entry) = bounds.entry(range) else {
                continue;
            };

            let mut local = SmallVec::<[Id<CodeBlock>; 2]>::new();
            for id in entry.get().iter() {
                let Some(block) = self.entries.get(id.index()).and_then(Option::as_ref) else {
                    continue;
                };
                if block.context() == context {
                    local.push(id);
                }
            }

            for &id in &local {
                entry.get_mut().remove(id);
            }

            if entry.get().is_empty() {
                entry.remove();
            }

            matching.extend(local);
        }

        let removed = matching.len();

        for id in matching {
            self.entries[id.index()] = None;
            self.index.free_ids.push(id);
            self.index.count -= 1;
        }

        removed
    }

    pub fn get_by_address(&self, maddr: Address) -> impl Iterator<Item = &CodeBlock> + '_ {
        let space = maddr.space();
        let raw = maddr.address();

        self.index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(raw..=raw))
            .flat_map(move |id_set| {
                id_set.iter().filter_map(move |id| {
                    let block = self.get_raw(id)?;
                    (block.start() == maddr).then_some(block)
                })
            })
    }

    pub fn get_by_address_and_context<'a>(
        &'a self,
        maddr: Address,
        context: &'a ContextSet,
    ) -> impl Iterator<Item = &'a CodeBlock> + 'a {
        let space = maddr.space();
        let raw = maddr.address();

        self.index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(raw..=raw))
            .flat_map(move |id_set| {
                id_set.iter().filter_map(move |id| {
                    let block = self.get_raw(id)?;
                    (block.start() == maddr && block.context() == context).then_some(block)
                })
            })
    }

    pub fn contains(&self, addr: Address) -> bool {
        let space = addr.space();
        let raw = addr.address();

        self.index
            .bounds
            .get(&space)
            .is_some_and(|bounds| bounds.has_overlap(raw..=raw))
    }

    pub fn overlaps(&self, addr: Address) -> impl Iterator<Item = &CodeBlock> + '_ {
        let space = addr.space();
        let raw = addr.address();

        self.index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(raw..=raw))
            .flat_map(move |id_set| id_set.iter().filter_map(move |id| self.get_raw(id)))
    }

    pub fn get_by_address_mut(
        &mut self,
        maddr: Address,
    ) -> impl Iterator<Item = &mut CodeBlock> + '_ {
        let space = maddr.space();
        let raw = maddr.address();

        let blocks_ptr = self.entries.as_mut_ptr();
        self.index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(raw..=raw))
            .flat_map(move |id_set| {
                id_set.iter().filter_map(move |id| {
                    // SAFETY:
                    //
                    // We are guaranteed not to have multiple instances of an
                    // Id<CodeBlock> within the sets iterated over, so the
                    // produced references never alias.
                    //
                    // The indices are guaranteed to be valid as they were
                    // obtained from the IdSet<CodeBlock> which only contains
                    // valid indices.
                    //
                    let block = unsafe { &mut *blocks_ptr.add(id.index()) }.as_mut()?;
                    (block.start() == maddr).then_some(block)
                })
            })
    }

    pub fn get_by_address_and_context_mut<'a>(
        &'a mut self,
        maddr: Address,
        context: &'a ContextSet,
    ) -> impl Iterator<Item = &'a mut CodeBlock> + 'a {
        let space = maddr.space();
        let raw = maddr.address();

        let blocks_ptr = self.entries.as_mut_ptr();
        self.index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(raw..=raw))
            .flat_map(move |id_set| {
                id_set.iter().filter_map(move |id| {
                    // SAFETY: see `get_by_address_mut` for justification.
                    let block = unsafe { &mut *blocks_ptr.add(id.index()) }.as_mut()?;
                    (block.start() == maddr && block.context() == context).then_some(block)
                })
            })
    }

    pub fn overlaps_mut(&mut self, addr: Address) -> impl Iterator<Item = &mut CodeBlock> + '_ {
        let space = addr.space();
        let raw = addr.address();

        let blocks_ptr = self.entries.as_mut_ptr();
        self.index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(raw..=raw))
            .flat_map(move |id_set| {
                id_set.iter().filter_map(move |id| {
                    // SAFETY: see `get_by_address_mut` for justification.
                    unsafe { &mut *blocks_ptr.add(id.index()) }.as_mut()
                })
            })
    }

    pub fn iter(&self) -> impl Iterator<Item = &CodeBlock> + '_ {
        self.entries.iter().filter_map(Option::as_ref)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut CodeBlock> + '_ {
        self.entries.iter_mut().filter_map(Option::as_mut)
    }

    pub fn is_empty(&self) -> bool {
        self.index.count == 0
    }

    pub fn len(&self) -> usize {
        self.index.count
    }
}

impl CodeBlockTable {
    pub fn new(entities: EntityStorage, cache_bytes: usize) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentCodeBlockTable::new(
            entities,
            cache_bytes,
        )?))
    }

    pub fn new_with(
        entities: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentCodeBlockTable::new_with(
            entities,
            worker,
            cache_bytes,
        )?))
    }

    pub fn new_transient() -> Self {
        Self::Transient(TransientCodeBlockTable::new())
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(p) => p.flush(),
            Self::Transient(t) => t.flush(),
        }
    }

    pub fn insert<F>(&mut self, addr: Address, f: F) -> Result<Id<CodeBlock>, CodeBlockTableError>
    where
        F: FnOnce(Id<CodeBlock>, Address) -> Result<CodeBlock, CodeBlockTableError>,
    {
        match self {
            Self::Persistent(p) => p.insert(addr, f),
            Self::Transient(t) => t.insert(addr, f),
        }
    }

    pub fn get_by_id(&self, id: Id<CodeBlock>) -> Option<CodeBlockRef<'_>> {
        match self {
            Self::Persistent(p) => p.get_by_id(id).map(Ref::Shared),
            Self::Transient(t) => t.get_by_id(id).map(Ref::Borrowed),
        }
    }

    pub fn try_get_by_id(
        &self,
        id: Id<CodeBlock>,
    ) -> Result<Option<CodeBlockRef<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_by_id(id)?.map(Ref::Shared)),
            Self::Transient(t) => Ok(t.get_by_id(id).map(Ref::Borrowed)),
        }
    }

    pub fn modify_by_id<R>(
        &mut self,
        id: Id<CodeBlock>,
        f: impl FnOnce(&mut CodeBlock) -> R,
    ) -> Option<R> {
        match self {
            Self::Persistent(p) => p.modify_by_id(id, f),
            Self::Transient(t) => t.modify_by_id(id, f),
        }
    }

    pub fn try_modify_by_id<R>(
        &mut self,
        id: Id<CodeBlock>,
        f: impl FnOnce(&mut CodeBlock) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_modify_by_id(id, f),
            Self::Transient(t) => Ok(t.modify_by_id(id, f)),
        }
    }

    pub fn get_by_id_mut(&mut self, id: Id<CodeBlock>) -> Option<CodeBlockMut<'_>> {
        match self {
            Self::Persistent(p) => p.get_by_id_mut(id).map(RefMut::Guard),
            Self::Transient(t) => t.get_by_id_mut(id).map(RefMut::Borrowed),
        }
    }

    pub fn try_get_by_id_mut(
        &mut self,
        id: Id<CodeBlock>,
    ) -> Result<Option<CodeBlockMut<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_by_id_mut(id)?.map(RefMut::Guard)),
            Self::Transient(t) => Ok(t.get_by_id_mut(id).map(RefMut::Borrowed)),
        }
    }

    pub fn remove_by_id(&mut self, id: Id<CodeBlock>) -> bool {
        match self {
            Self::Persistent(p) => p.remove_by_id(id),
            Self::Transient(t) => t.remove_by_id(id),
        }
    }

    pub fn try_remove_by_id(&mut self, id: Id<CodeBlock>) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_remove_by_id(id),
            Self::Transient(t) => Ok(t.remove_by_id(id)),
        }
    }

    pub fn remove_by_address(&mut self, addr: Address) -> usize {
        match self {
            Self::Persistent(p) => p.remove_by_address(addr),
            Self::Transient(t) => t.remove_by_address(addr),
        }
    }

    pub fn try_remove_by_address(&mut self, addr: Address) -> Result<usize, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_remove_by_address(addr),
            Self::Transient(t) => Ok(t.remove_by_address(addr)),
        }
    }

    pub fn remove_by_address_and_context(&mut self, addr: Address, context: &ContextSet) -> usize {
        match self {
            Self::Persistent(p) => p.remove_by_address_and_context(addr, context),
            Self::Transient(t) => t.remove_by_address_and_context(addr, context),
        }
    }

    pub fn try_remove_by_address_and_context(
        &mut self,
        addr: Address,
        context: &ContextSet,
    ) -> Result<usize, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_remove_by_address_and_context(addr, context),
            Self::Transient(t) => Ok(t.remove_by_address_and_context(addr, context)),
        }
    }

    pub fn get_by_address(&self, maddr: Address) -> CodeBlockIter<'_> {
        match self {
            Self::Persistent(p) => CodeBlockIter::new(p.get_by_address(maddr).map(Ref::Shared)),
            Self::Transient(t) => CodeBlockIter::new(t.get_by_address(maddr).map(Ref::Borrowed)),
        }
    }

    pub fn get_by_address_and_context<'a>(
        &'a self,
        maddr: Address,
        context: &'a ContextSet,
    ) -> CodeBlockIter<'a> {
        match self {
            Self::Persistent(p) => CodeBlockIter::new(
                p.get_by_address_and_context(maddr, context)
                    .map(Ref::Shared),
            ),
            Self::Transient(t) => CodeBlockIter::new(
                t.get_by_address_and_context(maddr, context)
                    .map(Ref::Borrowed),
            ),
        }
    }

    pub fn contains(&self, addr: Address) -> bool {
        match self {
            Self::Persistent(p) => p.contains(addr),
            Self::Transient(t) => t.contains(addr),
        }
    }

    pub fn overlaps(&self, addr: Address) -> CodeBlockIter<'_> {
        match self {
            Self::Persistent(p) => CodeBlockIter::new(p.overlaps(addr).map(Ref::Shared)),
            Self::Transient(t) => CodeBlockIter::new(t.overlaps(addr).map(Ref::Borrowed)),
        }
    }

    pub fn get_by_address_mut(&mut self, maddr: Address) -> CodeBlockIterMut<'_> {
        match self {
            Self::Persistent(p) => {
                CodeBlockIterMut::new(p.get_by_address_mut(maddr).map(RefMut::Guard))
            }
            Self::Transient(t) => {
                CodeBlockIterMut::new(t.get_by_address_mut(maddr).map(RefMut::Borrowed))
            }
        }
    }

    pub fn get_by_address_and_context_mut<'a>(
        &'a mut self,
        maddr: Address,
        context: &'a ContextSet,
    ) -> CodeBlockIterMut<'a> {
        match self {
            Self::Persistent(p) => CodeBlockIterMut::new(
                p.get_by_address_and_context_mut(maddr, context)
                    .map(RefMut::Guard),
            ),
            Self::Transient(t) => CodeBlockIterMut::new(
                t.get_by_address_and_context_mut(maddr, context)
                    .map(RefMut::Borrowed),
            ),
        }
    }

    pub fn overlaps_mut(&mut self, addr: Address) -> CodeBlockIterMut<'_> {
        match self {
            Self::Persistent(p) => CodeBlockIterMut::new(p.overlaps_mut(addr).map(RefMut::Guard)),
            Self::Transient(t) => {
                CodeBlockIterMut::new(t.overlaps_mut(addr).map(RefMut::Borrowed))
            }
        }
    }

    pub fn iter(&self) -> CodeBlockIter<'_> {
        match self {
            Self::Persistent(p) => CodeBlockIter::new(p.iter().map(Ref::Shared)),
            Self::Transient(t) => CodeBlockIter::new(t.iter().map(Ref::Borrowed)),
        }
    }

    pub fn iter_mut(&mut self) -> CodeBlockIterMut<'_> {
        match self {
            Self::Persistent(p) => CodeBlockIterMut::new(p.iter_mut().map(RefMut::Guard)),
            Self::Transient(t) => CodeBlockIterMut::new(t.iter_mut().map(RefMut::Borrowed)),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Persistent(p) => p.is_empty(),
            Self::Transient(t) => t.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Persistent(p) => p.len(),
            Self::Transient(t) => t.len(),
        }
    }
}

impl PersistableProjectEntity for CodeBlockTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(_) => storage.insert(
                &ProjectEntity::CodeBlockTable,
                &CodeBlockTableHeader {
                    version: CODE_BLOCK_TABLE_VERSION,
                },
            ),
            Self::Transient(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ir::InsnList;
    use crate::storage::entities::InMemoryEntityStorage;

    fn table() -> CodeBlockTable {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        CodeBlockTable::new(storage, 64 * 1024).unwrap()
    }

    fn free_ids(table: &CodeBlockTable) -> &[Id<CodeBlock>] {
        match table {
            CodeBlockTable::Persistent(p) => &p.index.free_ids,
            CodeBlockTable::Transient(t) => &t.index.free_ids,
        }
    }

    #[test]
    fn test_basic_operations() {
        let mut table = table();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        let addr = Address::from(0x1000);
        let blk_id = table
            .insert(addr, |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
            })
            .unwrap();
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);

        let blk = table.get_by_id(blk_id).unwrap();
        assert_eq!(blk.start(), addr);
        assert_eq!(blk.len(), 0x10);
        drop(blk);

        assert!(table.remove_by_id(blk_id));
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_overlapped() {
        let mut table = table();

        let addr1 = Address::from(0x1000);
        let addr2 = Address::from(0x1000); // overlaps with addr1
        let addr3 = Address::from(0x1005);

        let blk_id1 = table
            .insert(addr1, |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
            })
            .unwrap();
        let blk_id2 = table
            .insert(addr2, |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x8, InsnList::new()).unwrap())
            })
            .unwrap();
        let blk_id3 = table
            .insert(addr3, |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x6, InsnList::new()).unwrap())
            })
            .unwrap();

        let overlaps = table.overlaps(Address::from(0x1007)).collect::<Vec<_>>();
        assert_eq!(overlaps.len(), 3); // all three blocks overlap at 0x1007
        assert!(overlaps.iter().any(|blk| blk.id() == blk_id1));
        assert!(overlaps.iter().any(|blk| blk.id() == blk_id2));
        assert!(overlaps.iter().any(|blk| blk.id() == blk_id3));

        let removed_count = table.remove_by_address(Address::from(0x1000));
        assert_eq!(removed_count, 2);

        let remaining_blk = table.get_by_id(blk_id3).unwrap();
        assert_eq!(remaining_blk.start(), addr3);
    }

    #[test]
    fn test_index_rebuild_on_open() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());

        {
            let mut table = CodeBlockTable::new(storage.clone(), 64 * 1024).unwrap();
            for base in 1..=3u64 {
                table
                    .insert(Address::from(base * 0x1000), |id, start| {
                        Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
                    })
                    .unwrap();
            }
        }

        let table = CodeBlockTable::new(storage, 64 * 1024).unwrap();
        assert_eq!(table.len(), 3);
        assert!(table.contains(Address::from(0x1000)));
        assert!(table.overlaps(Address::from(0x2000)).next().is_some());
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn test_free_id_reuse_sqlite() {
        use crate::storage::TRANSIENT;
        use crate::storage::entities::SqliteEntityStorage;

        let storage = EntityStorage::new(SqliteEntityStorage::<TRANSIENT>::new().unwrap());
        let mut table = CodeBlockTable::new(storage, 64 * 1024).unwrap();

        let mut ids = Vec::new();
        for base in 1..=3u64 {
            ids.push(
                table
                    .insert(Address::from(base * 0x1000), |id, start| {
                        Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
                    })
                    .unwrap(),
            );
        }

        assert!(table.remove_by_id(ids[1]));
        assert_eq!(free_ids(&table), [ids[1]]);

        let reused = table
            .insert(Address::from(0x4000), |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
            })
            .unwrap();
        assert_eq!(reused, ids[1]);
        assert!(free_ids(&table).is_empty());

        let fresh = table
            .insert(Address::from(0x5000), |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
            })
            .unwrap();
        assert_eq!(fresh.index(), 3);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn test_free_id_rebuild_on_reopen_sqlite() {
        use tempfile::TempDir;

        use crate::storage::PERSISTENT;
        use crate::storage::entities::SqliteEntityStorage;

        let dir = TempDir::new().unwrap();

        {
            let storage =
                EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
            let worker = WriteBackWorker::new(storage.clone()).unwrap();
            let mut table = CodeBlockTable::new_with(storage, worker, 64 * 1024).unwrap();

            let mut ids = Vec::new();
            for base in 1..=5u64 {
                ids.push(
                    table
                        .insert(Address::from(base * 0x1000), |id, start| {
                            Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
                        })
                        .unwrap(),
                );
            }

            assert!(table.remove_by_id(ids[1]));
            assert!(table.remove_by_id(ids[3]));

            table.flush().unwrap();
        }

        let storage =
            EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        let mut table = CodeBlockTable::new_with(storage, worker, 64 * 1024).unwrap();

        assert_eq!(table.len(), 3);

        let first = table
            .insert(Address::from(0x6000), |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
            })
            .unwrap();
        let second = table
            .insert(Address::from(0x7000), |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
            })
            .unwrap();
        let third = table
            .insert(Address::from(0x8000), |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
            })
            .unwrap();

        assert_eq!([first.index(), second.index(), third.index()], [3, 1, 5]);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn test_get_by_id_mut_persists_sqlite() {
        use tempfile::TempDir;

        use crate::storage::PERSISTENT;
        use crate::storage::entities::SqliteEntityStorage;

        let dir = TempDir::new().unwrap();
        let addr = Address::from(0x1000);
        let successor = Id::<CodeBlock>::new(7);

        {
            let storage =
                EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
            let worker = WriteBackWorker::new(storage.clone()).unwrap();
            let mut table = CodeBlockTable::new_with(storage, worker, 64 * 1024).unwrap();

            let bid = table
                .insert(addr, |id, start| {
                    Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
                })
                .unwrap();

            {
                let mut block = table.get_by_id_mut(bid).expect("block exists");
                block.add_successor(successor);
            }

            table.flush().unwrap();
        }

        let storage =
            EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        let table = CodeBlockTable::new_with(storage, worker, 64 * 1024).unwrap();

        let block = table.get_by_address(addr).next().expect("block exists");
        assert!(block.successors().contains(successor));
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn test_iter_mut_persists() {
        use tempfile::TempDir;

        use crate::storage::PERSISTENT;
        use crate::storage::entities::SqliteEntityStorage;

        let dir = TempDir::new().unwrap();
        let successor = Id::<CodeBlock>::new(99);

        {
            let storage =
                EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
            let worker = WriteBackWorker::new(storage.clone()).unwrap();
            let mut table = CodeBlockTable::new_with(storage, worker, 64 * 1024).unwrap();

            for base in 1..=3u64 {
                table
                    .insert(Address::from(base * 0x1000), |id, start| {
                        Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
                    })
                    .unwrap();
            }

            for mut block in table.iter_mut() {
                block.add_successor(successor);
            }

            table.flush().unwrap();
        }

        let storage =
            EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        let table = CodeBlockTable::new_with(storage, worker, 64 * 1024).unwrap();

        assert_eq!(table.len(), 3);
        for block in table.iter() {
            assert!(block.successors().contains(successor));
        }
    }

    #[test]
    fn test_transient_basic_operations() {
        let mut table = CodeBlockTable::new_transient();
        assert!(table.is_empty());

        let addr = Address::from(0x1000);
        let blk_id = table
            .insert(addr, |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
            })
            .unwrap();
        assert_eq!(table.len(), 1);

        let blk = table.get_by_id(blk_id).unwrap();
        assert_eq!(blk.start(), addr);
        drop(blk);

        assert!(table.contains(addr));
        assert_eq!(table.overlaps(Address::from(0x1005)).count(), 1);

        assert!(table.remove_by_id(blk_id));
        assert!(table.is_empty());
    }

    #[test]
    fn test_transient_iter_mut_mutate() {
        let mut table = CodeBlockTable::new_transient();
        let successor = Id::<CodeBlock>::new(42);

        let ids = (1..=3u64)
            .map(|base| {
                table
                    .insert(Address::from(base * 0x1000), |id, start| {
                        Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
                    })
                    .unwrap()
            })
            .collect::<Vec<_>>();

        for mut block in table.iter_mut() {
            block.add_successor(successor);
        }

        for id in ids {
            let block = table.get_by_id(id).unwrap();
            assert!(block.successors().contains(successor));
        }
    }
}
