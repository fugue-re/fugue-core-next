use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::Arc;

use iset::{Entry, IntervalMap};
use smallvec::SmallVec;

use super::{CodeBlockIndex, CodeBlockTableAllocation, CodeBlockTableError};
use crate::ir::{Address, CodeBlock, Id, IdAllocator, IdSet, RawAddress};
use crate::lifter::ContextSet;
use crate::storage::entities::{CachedMut, CachedRef, EntityCache, WriteBackWorker};
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::{EntityStorage, EntityStorageError};

type Ref<'a> = CachedRef<'a, CodeBlock>;
type RefMut<'a> = CachedMut<'a, CodeBlock>;
type Iter<'a> = Box<dyn Iterator<Item = Ref<'a>> + 'a>;
type IterMut<'a> = Box<dyn Iterator<Item = RefMut<'a>> + 'a>;

pub struct CodeBlockTable {
    index: CodeBlockIndex,
    entries: EntityCache<Id<CodeBlock>, CodeBlock>,
}

impl CodeBlockTable {
    pub(crate) fn new(
        entities: EntityStorage,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Self::from_entries(EntityCache::new(entities, cache_bytes)?)
    }

    pub(crate) fn with_worker(
        entities: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Self::from_entries(EntityCache::with_worker(entities, worker, cache_bytes))
    }

    fn from_entries(
        entries: EntityCache<Id<CodeBlock>, CodeBlock>,
    ) -> Result<Self, EntityStorageError> {
        let mut bounds =
            BTreeMap::<AddressSpaceId, IntervalMap<RawAddress, IdSet<CodeBlock>>>::new();
        let mut live = 0;
        let mut allocator = IdAllocator::new();

        for entry in entries.try_iter_range(Bound::Unbounded)? {
            let (id, block) = entry?;

            let range = block.start().raw_address()..=block.last_address().raw_address();
            bounds
                .entry(block.space())
                .or_default()
                .entry(range)
                .or_default()
                .insert(id);

            live += 1;
            allocator.mark_allocated(id);
        }

        Ok(Self {
            index: CodeBlockIndex {
                allocator,
                bounds,
                live,
            },
            entries,
        })
    }

    pub(crate) fn flush(&self) -> Result<(), EntityStorageError> {
        self.entries.flush()
    }

    pub(crate) fn allocation_checkpoint(&self, max_pops: usize) -> CodeBlockTableAllocation {
        self.index.allocator.checkpoint(max_pops)
    }

    pub(crate) fn restore_allocation(&mut self, allocation: CodeBlockTableAllocation) {
        self.index.allocator.restore(allocation);
    }

    pub(crate) fn restore_entry(&mut self, block: CodeBlock) -> Result<(), EntityStorageError> {
        let id = block.id();
        if self.entries.try_get(&id)?.is_some() {
            self.clear_entry(id)?;
        }

        let space = block.space();
        let range = block.start().raw_address()..=block.last_address().raw_address();
        self.entries.try_put(id, block)?;
        self.index
            .bounds
            .entry(space)
            .or_default()
            .entry(range)
            .or_default()
            .insert(id);
        self.index.allocator.mark_allocated(id);
        self.index.live += 1;
        Ok(())
    }

    pub(crate) fn clear_entry(&mut self, id: Id<CodeBlock>) -> Result<bool, EntityStorageError> {
        let Some(block) = self.entries.try_get(&id)? else {
            return Ok(false);
        };

        let space = block.space();
        let range = block.start().raw_address()..=block.last_address().raw_address();
        drop(block);

        self.entries.try_remove(&id)?;

        if let Some(Entry::Occupied(mut entry)) =
            self.index.bounds.get_mut(&space).map(|m| m.entry(range))
        {
            let id_set = entry.get_mut();
            id_set.remove(id);

            if id_set.is_empty() {
                entry.remove();
            }
        }

        self.index.live -= 1;
        Ok(true)
    }

    pub(crate) fn insert<F>(
        &mut self,
        addr: Address,
        f: F,
    ) -> Result<Id<CodeBlock>, CodeBlockTableError>
    where
        F: FnOnce(Id<CodeBlock>, Address) -> Result<CodeBlock, CodeBlockTableError>,
    {
        let entries = &self.entries;
        let (id, (space, range)) = self.index.allocator.try_allocate(|id| {
            let block = f(id, addr)?;
            if block.start() != addr {
                return Err(CodeBlockTableError::AddressMismatch);
            }
            let space = block.space();
            let range = block.start().raw_address()..=block.last_address().raw_address();
            entries.try_put(id, block)?;
            Ok((space, range))
        })?;

        self.index
            .bounds
            .entry(space)
            .or_default()
            .entry(range)
            .or_default()
            .insert(id);

        self.index.live += 1;

        Ok(id)
    }

    pub(crate) fn try_get_by_id(
        &self,
        id: Id<CodeBlock>,
    ) -> Result<Option<Ref<'_>>, EntityStorageError> {
        self.entries.try_get(&id)
    }

    pub(crate) fn try_modify_by_id<R>(
        &mut self,
        id: Id<CodeBlock>,
        f: impl FnOnce(&mut CodeBlock) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        self.entries.try_modify(&id, f)
    }

    pub(crate) fn try_get_by_id_mut(
        &mut self,
        id: Id<CodeBlock>,
    ) -> Result<Option<RefMut<'_>>, EntityStorageError> {
        self.entries.try_get_mut(&id)
    }

    pub(crate) fn try_remove_by_id(
        &mut self,
        id: Id<CodeBlock>,
    ) -> Result<bool, EntityStorageError> {
        let Some(block) = self.entries.try_get(&id)? else {
            return Ok(false);
        };

        let space = block.space();
        let range = block.start().raw_address()..=block.last_address().raw_address();
        drop(block);

        self.entries.try_remove(&id)?;

        if let Some(Entry::Occupied(mut entry)) =
            self.index.bounds.get_mut(&space).map(|m| m.entry(range))
        {
            let id_set = entry.get_mut();
            id_set.remove(id);

            if id_set.is_empty() {
                entry.remove();
            }
        }

        self.index.allocator.release(id);
        self.index.live -= 1;

        Ok(true)
    }

    pub(crate) fn try_remove_by_address(
        &mut self,
        addr: Address,
    ) -> Result<usize, EntityStorageError> {
        let space = addr.space();
        let raw = addr.raw_address();

        let Some(bounds) = self.index.bounds.get(&space) else {
            return Ok(0);
        };

        let ranges = bounds
            .intervals_overlap(raw)
            .filter(|iv| *iv.start() == raw)
            .collect::<SmallVec<[_; 2]>>();

        let mut removed = 0;

        for range in ranges {
            let ids = {
                let Some(bounds) = self.index.bounds.get_mut(&space) else {
                    break;
                };
                let Entry::Occupied(entry) = bounds.entry(range.clone()) else {
                    continue;
                };
                entry.get().iter().collect::<SmallVec<[_; 2]>>()
            };

            for id in ids {
                self.entries.try_remove(&id)?;

                if let Some(Entry::Occupied(mut entry)) = self
                    .index
                    .bounds
                    .get_mut(&space)
                    .map(|bounds| bounds.entry(range.clone()))
                {
                    entry.get_mut().remove(id);
                    if entry.get().is_empty() {
                        entry.remove();
                    }
                }

                self.index.allocator.release(id);
                self.index.live -= 1;
                removed += 1;
            }
        }

        Ok(removed)
    }

    pub(crate) fn try_remove_by_address_and_context(
        &mut self,
        addr: Address,
        context: &ContextSet,
    ) -> Result<usize, EntityStorageError> {
        let space = addr.space();
        let raw = addr.raw_address();

        let Some(bounds) = self.index.bounds.get(&space) else {
            return Ok(0);
        };

        let ranges = bounds
            .intervals_overlap(raw)
            .filter(|iv| *iv.start() == raw)
            .collect::<SmallVec<[_; 2]>>();

        let mut removed = 0;

        for range in ranges {
            let ids = {
                let Some(bounds) = self.index.bounds.get_mut(&space) else {
                    break;
                };
                let Entry::Occupied(entry) = bounds.entry(range.clone()) else {
                    continue;
                };
                entry.get().iter().collect::<SmallVec<[_; 2]>>()
            };

            let mut matching = SmallVec::<[Id<CodeBlock>; 2]>::new();
            for id in ids {
                let Some(block) = self.entries.try_get(&id)? else {
                    continue;
                };
                if block.context() == context {
                    matching.push(id);
                }
            }

            for id in matching {
                self.entries.try_remove(&id)?;

                if let Some(Entry::Occupied(mut entry)) = self
                    .index
                    .bounds
                    .get_mut(&space)
                    .map(|bounds| bounds.entry(range.clone()))
                {
                    entry.get_mut().remove(id);
                    if entry.get().is_empty() {
                        entry.remove();
                    }
                }

                self.index.allocator.release(id);
                self.index.live -= 1;
                removed += 1;
            }
        }

        Ok(removed)
    }

    pub(crate) fn get_by_address(&self, maddr: Address) -> Iter<'_> {
        let space = maddr.space();
        let raw = maddr.raw_address();

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

    pub(crate) fn get_by_address_and_context<'a>(
        &'a self,
        maddr: Address,
        context: &'a ContextSet,
    ) -> Iter<'a> {
        let space = maddr.space();
        let raw = maddr.raw_address();

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

    pub(crate) fn contains(&self, addr: Address) -> bool {
        let space = addr.space();
        let raw = addr.raw_address();

        self.index
            .bounds
            .get(&space)
            .is_some_and(|bounds| bounds.has_overlap(raw..=raw))
    }

    pub(crate) fn overlaps(&self, addr: Address) -> Iter<'_> {
        let space = addr.space();
        let raw = addr.raw_address();

        let Some(bounds) = self.index.bounds.get(&space) else {
            return Box::new(std::iter::empty());
        };

        Box::new(
            bounds
                .values(raw..=raw)
                .flat_map(move |id_set| id_set.iter().filter_map(move |id| self.entries.get(&id))),
        )
    }

    pub(crate) fn get_by_address_mut(&mut self, maddr: Address) -> IterMut<'_> {
        let space = maddr.space();
        let raw = maddr.raw_address();

        let ids = self
            .index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.overlap(raw))
            .filter(move |(range, _)| *range.start() == raw)
            .flat_map(|(_, id_set)| id_set.iter());

        Box::new(self.entries.iter_disjoint_mut(ids))
    }

    pub(crate) fn get_by_address_and_context_mut<'a>(
        &'a mut self,
        maddr: Address,
        context: &'a ContextSet,
    ) -> IterMut<'a> {
        let space = maddr.space();
        let raw = maddr.raw_address();

        let ids = self
            .index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.overlap(raw))
            .filter(move |(range, _)| *range.start() == raw)
            .flat_map(|(_, id_set)| id_set.iter());

        Box::new(
            self.entries
                .iter_disjoint_mut(ids)
                .filter(move |block| block.context() == context),
        )
    }

    pub(crate) fn overlaps_mut(&mut self, addr: Address) -> IterMut<'_> {
        let space = addr.space();
        let raw = addr.raw_address();

        let ids = self
            .index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(raw..=raw))
            .flat_map(|id_set| id_set.iter());

        Box::new(self.entries.iter_disjoint_mut(ids))
    }

    pub(crate) fn iter(&self) -> Iter<'_> {
        Box::new(self.entries.iter())
    }

    pub(crate) fn iter_mut(&mut self) -> IterMut<'_> {
        Box::new(self.entries.iter_mut())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.index.live == 0
    }

    pub(crate) fn len(&self) -> usize {
        self.index.live
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod test {
    use super::*;
    use crate::ir::InsnList;
    use crate::storage::TRANSIENT;
    use crate::storage::entities::SqliteEntityStorage;

    #[test]
    fn test_free_id_reuse_sqlite() {
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
        assert_eq!(table.index.allocator.free_len(), 1);
        assert_eq!(table.index.allocator.next_id(), ids[1].next_generation());

        let reused = table
            .insert(Address::from(0x4000), |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
            })
            .unwrap();
        assert_eq!(reused.index(), ids[1].index());
        assert_eq!(reused.generation(), ids[1].generation() + 1);
        assert!(table.try_get_by_id(ids[1]).unwrap().is_none());
        assert_eq!(table.index.allocator.free_len(), 0);

        let fresh = table
            .insert(Address::from(0x5000), |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
            })
            .unwrap();
        assert_eq!(fresh.index(), 3);
    }
}
