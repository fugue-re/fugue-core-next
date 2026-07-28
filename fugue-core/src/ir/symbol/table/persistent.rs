use std::collections::BTreeMap;
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;

use smallvec::SmallVec;

use super::SymbolInsertion;
use crate::ir::symbol::{
    Symbol, SymbolEntry, SymbolId, SymbolIndex, SymbolMap, SymbolProperties, SymbolTableSelector,
};
use crate::ir::{Address, IdAllocation, IdAllocator};
use crate::storage::entities::{CachedRef, EntityCache, WriteBackWorker};
use crate::storage::{EntityStorage, EntityStorageError};

type Ref<'a> = CachedRef<'a, SymbolEntry>;

pub(super) type Allocation = IdAllocation<Symbol>;

struct SymbolTableIndex {
    allocator: IdAllocator<Symbol>,
    names: SymbolMap<SmallVec<[SymbolId; 2]>>,
    addresses: BTreeMap<Address, SmallVec<[SymbolId; 2]>>,
    indices: BTreeMap<SymbolIndex, SymbolId>,
    live: usize,
}

impl SymbolTableIndex {
    fn link(&mut self, id: SymbolId, entry: &SymbolEntry) {
        self.names.entry(entry.symbol()).or_default().push(id);
        self.addresses.entry(entry.address()).or_default().push(id);
        for &symbol_index in entry.indices() {
            self.indices.insert(symbol_index, id);
        }
    }

    fn unlink(&mut self, id: SymbolId, entry: &SymbolEntry) {
        use std::collections::btree_map::Entry as AddrsEntry;
        use std::collections::hash_map::Entry as NamesEntry;

        if let NamesEntry::Occupied(mut ids) = self.names.entry(entry.symbol()) {
            ids.get_mut().retain(|oid| *oid != id);
            if ids.get().is_empty() {
                ids.remove();
            }
        }

        if let AddrsEntry::Occupied(mut ids) = self.addresses.entry(entry.address()) {
            ids.get_mut().retain(|oid| *oid != id);
            if ids.get().is_empty() {
                ids.remove();
            }
        }

        for symbol_index in entry.indices() {
            self.indices.remove(symbol_index);
        }
    }

    fn release(&mut self, id: SymbolId) {
        self.allocator.release(id);
        self.live -= 1;
    }
}

pub struct SymbolTable {
    index: SymbolTableIndex,
    entries: EntityCache<SymbolId, SymbolEntry>,
}

impl SymbolTable {
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
        entries: EntityCache<SymbolId, SymbolEntry>,
    ) -> Result<Self, EntityStorageError> {
        let mut index = SymbolTableIndex {
            allocator: IdAllocator::new(),
            names: SymbolMap::default(),
            addresses: BTreeMap::new(),
            indices: BTreeMap::new(),
            live: 0,
        };

        for entry in entries.try_iter_range(Bound::Unbounded)? {
            let (id, entry) = entry?;
            index.link(id, entry.as_ref());
            index.allocator.mark_allocated(id);
            index.live += 1;
        }

        Ok(Self { index, entries })
    }

    pub(crate) fn flush(&self) -> Result<(), EntityStorageError> {
        self.entries.flush()
    }

    pub(super) fn allocation_checkpoint(&self, max_pops: usize) -> Allocation {
        self.index.allocator.checkpoint(max_pops)
    }

    pub(super) fn restore_allocation(&mut self, allocation: Allocation) {
        self.index.allocator.restore(allocation);
    }

    pub(super) fn restore_entry(
        &mut self,
        id: SymbolId,
        entry: SymbolEntry,
    ) -> Result<(), EntityStorageError> {
        self.clear_entry(id)?;

        let entry = Arc::new(entry);
        self.entries.try_put(id, Arc::clone(&entry))?;
        self.index.link(id, &entry);
        self.index.allocator.mark_allocated(id);
        self.index.live += 1;
        Ok(())
    }

    pub(super) fn clear_entry(&mut self, id: SymbolId) -> Result<bool, EntityStorageError> {
        let Some(entry) = self.entries.try_get(&id)? else {
            return Ok(false);
        };
        let entry = entry.as_ref().clone();

        self.entries.try_remove(&id)?;
        self.index.unlink(id, &entry);
        self.index.live -= 1;
        Ok(true)
    }

    pub(super) fn get_ids_replaced_by_insert(
        &self,
        index: SymbolIndex,
        entry: &SymbolEntry,
    ) -> Result<SmallVec<[SymbolId; 2]>, EntityStorageError> {
        let mut replaced = SmallVec::new();
        if let Some(id) = self.index.indices.get(&index).copied() {
            replaced.push(id);
        }

        if let Some(id) = self.referent_of(entry)? {
            replaced.push(id);
        }

        Ok(replaced)
    }

    pub(super) fn get_ids_by_symbol(
        &self,
        symbol: impl AsRef<str>,
    ) -> Option<&SmallVec<[SymbolId; 2]>> {
        Symbol::from_existing(symbol.as_ref()).and_then(|symbol| self.index.names.get(&symbol))
    }

    pub(super) fn get_ids_by_address(&self, address: Address) -> Option<&SmallVec<[SymbolId; 2]>> {
        self.index.addresses.get(&address)
    }

    pub(super) fn get_id_by_index(&self, index: SymbolIndex) -> Option<SymbolId> {
        self.index.indices.get(&index).copied()
    }

    fn referent_of(&self, entry: &SymbolEntry) -> Result<Option<SymbolId>, EntityStorageError> {
        let Some(ids) = self.index.addresses.get(&entry.address()) else {
            return Ok(None);
        };

        for &id in ids {
            if let Some(existing) = self.entries.try_get(&id)?
                && existing.as_ref().has_same_referent(entry)
            {
                return Ok(Some(id));
            }
        }

        Ok(None)
    }

    fn insert_or_update(
        &mut self,
        index: SymbolIndex,
        entry: SymbolEntry,
    ) -> Result<SymbolInsertion, EntityStorageError> {
        if let Some(id) = self.referent_of(&entry)? {
            let Some(existing) = self.entries.try_get(&id)? else {
                return Ok(SymbolInsertion::new(id, false));
            };
            let mut updated = existing.as_ref().clone();
            drop(existing);

            updated.add_index(index);
            updated.update_visibility(entry.properties());
            self.entries.try_put(id, updated)?;

            return Ok(SymbolInsertion::new(id, false));
        }

        let entry = Arc::new(entry);
        let entries = &self.entries;
        let (id, ()) = self
            .index
            .allocator
            .try_allocate(|id| entries.try_put(id, Arc::clone(&entry)).map(|_| ()))?;
        self.index.link(id, &entry);
        self.index.live += 1;

        Ok(SymbolInsertion::new(id, true))
    }

    pub(crate) fn insert(
        &mut self,
        index: SymbolIndex,
        address: Address,
        symbol: Symbol,
        properties: SymbolProperties,
    ) -> Result<SymbolInsertion, EntityStorageError> {
        let symbol_entry = SymbolEntry::new(address, symbol, properties).with_index(index);

        let Some(existing_id) = self.index.indices.get(&index).copied() else {
            let insertion = self.insert_or_update(index, symbol_entry)?;
            self.index.indices.insert(index, insertion.id());
            return Ok(insertion);
        };

        let Some(existing) = self.entries.try_get(&existing_id)? else {
            let insertion = self.insert_or_update(index, symbol_entry)?;
            self.index.indices.insert(index, insertion.id());
            return Ok(insertion);
        };

        if *existing.as_ref() == symbol_entry {
            return Ok(SymbolInsertion::new(existing_id, false));
        }

        if existing.as_ref().indices().len() > 1 {
            let mut updated = existing.as_ref().clone();
            drop(existing);

            updated.remove_index(index);
            self.entries.try_put(existing_id, updated)?;

            let insertion = self.insert_or_update(index, symbol_entry)?;
            self.index.indices.insert(index, insertion.id());
            return Ok(insertion);
        }

        drop(existing);
        self.remove_by_id(existing_id)?;
        self.insert(index, address, symbol, properties)
    }

    pub(crate) fn try_modify_by_id<R>(
        &mut self,
        id: SymbolId,
        f: impl FnOnce(&mut SymbolEntry) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        let Some(existing) = self.entries.try_get(&id)? else {
            return Ok(None);
        };

        let mut updated = existing.as_ref().clone();
        drop(existing);

        let result = f(&mut updated);
        self.entries.try_put(id, updated)?;

        Ok(Some(result))
    }

    pub(crate) fn get(
        &self,
        symbol: impl AsRef<str>,
    ) -> Option<impl Iterator<Item = (SymbolId, Ref<'_>)> + '_> {
        let symbol = Symbol::from_existing(symbol.as_ref())?;
        let ids = self.index.names.get(&symbol)?;
        Some(self.entries_for(ids))
    }

    pub(crate) fn try_get_first(
        &self,
        symbol: impl AsRef<str>,
    ) -> Result<Option<(SymbolId, Ref<'_>)>, EntityStorageError> {
        let Some(symbol) = Symbol::from_existing(symbol.as_ref()) else {
            return Ok(None);
        };
        let Some(id) = self
            .index
            .names
            .get(&symbol)
            .and_then(|ids| ids.first())
            .copied()
        else {
            return Ok(None);
        };
        Ok(self.try_get_by_id(id)?.map(|entry| (id, entry)))
    }

    pub(crate) fn try_get_by_id(
        &self,
        id: SymbolId,
    ) -> Result<Option<Ref<'_>>, EntityStorageError> {
        self.entries.try_get(&id)
    }

    pub(crate) fn try_get_by_index(
        &self,
        index: SymbolIndex,
    ) -> Result<Option<(SymbolId, Ref<'_>)>, EntityStorageError> {
        let Some(id) = self.index.indices.get(&index).copied() else {
            return Ok(None);
        };
        Ok(self.entries.try_get(&id)?.map(|entry| (id, entry)))
    }

    pub(crate) fn get_by_address(
        &self,
        address: Address,
    ) -> impl Iterator<Item = (SymbolId, Ref<'_>)> + '_ {
        let ids = self
            .index
            .addresses
            .get(&address)
            .map(|ids| ids.as_slice())
            .unwrap_or_default();
        self.entries_for(ids)
    }

    pub(crate) fn try_get_first_by_address(
        &self,
        address: Address,
    ) -> Result<Option<(SymbolId, Ref<'_>)>, EntityStorageError> {
        let Some(id) = self
            .index
            .addresses
            .get(&address)
            .and_then(|ids| ids.first())
            .copied()
        else {
            return Ok(None);
        };
        Ok(self.try_get_by_id(id)?.map(|entry| (id, entry)))
    }

    pub(crate) fn contains(&self, symbol: impl AsRef<str>) -> bool {
        Symbol::from_existing(symbol.as_ref())
            .is_some_and(|symbol| self.index.names.contains_key(&symbol))
    }

    pub(crate) fn contains_index(&self, index: SymbolIndex) -> bool {
        self.index.indices.contains_key(&index)
    }

    pub(crate) fn contains_address(&self, address: Address) -> bool {
        self.index.addresses.contains_key(&address)
    }

    fn entries_for<'a>(
        &'a self,
        ids: &'a [SymbolId],
    ) -> impl Iterator<Item = (SymbolId, Ref<'a>)> + 'a {
        ids.iter()
            .copied()
            .filter_map(move |id| self.entries.get(&id).map(|entry| (id, entry)))
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (SymbolId, Ref<'_>)> + '_ {
        self.index
            .addresses
            .values()
            .flat_map(move |ids| self.entries_for(ids))
    }

    pub(crate) fn iter_by_selector(
        &self,
        selector: SymbolTableSelector,
    ) -> impl Iterator<Item = (SymbolId, Ref<'_>)> + '_ {
        self.index
            .indices
            .iter()
            .filter(move |(index, _)| index.selector() == selector)
            .filter_map(move |(_, &id)| self.entries.get(&id).map(|entry| (id, entry)))
    }

    pub(crate) fn iter_by_address(&self) -> impl Iterator<Item = (SymbolId, Ref<'_>)> + '_ {
        self.index
            .addresses
            .values()
            .flat_map(move |ids| self.entries_for(ids))
    }

    pub(crate) fn range_by_address<R>(
        &self,
        range: R,
    ) -> impl Iterator<Item = (SymbolId, Ref<'_>)> + '_
    where
        R: RangeBounds<Address>,
    {
        self.index
            .addresses
            .range(range)
            .flat_map(move |(_, ids)| self.entries_for(ids))
    }

    pub(crate) fn iter_by_index(
        &self,
    ) -> impl Iterator<Item = (SymbolIndex, SymbolId, Ref<'_>)> + '_ {
        self.index
            .indices
            .iter()
            .filter_map(move |(&index, &id)| self.entries.get(&id).map(|entry| (index, id, entry)))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn len(&self) -> usize {
        self.index.live
    }

    pub(crate) fn remove(&mut self, symbol: impl AsRef<str>) -> Result<usize, EntityStorageError> {
        let Some(ids) = Symbol::from_existing(symbol.as_ref())
            .and_then(|symbol| self.index.names.remove(&symbol))
        else {
            return Ok(0);
        };

        let count = ids.len();
        for id in ids {
            self.remove_by_id(id)?;
        }

        Ok(count)
    }

    pub(crate) fn remove_by_address(
        &mut self,
        address: Address,
    ) -> Result<usize, EntityStorageError> {
        let Some(ids) = self.index.addresses.remove(&address) else {
            return Ok(0);
        };

        let count = ids.len();
        for id in ids {
            self.remove_by_id(id)?;
        }

        Ok(count)
    }

    pub(crate) fn remove_by_id(&mut self, id: SymbolId) -> Result<bool, EntityStorageError> {
        let Some(entry) = self.entries.try_get(&id)? else {
            return Ok(false);
        };
        let entry = entry.as_ref().clone();

        self.entries.try_remove(&id)?;
        self.index.unlink(id, &entry);
        self.index.release(id);

        Ok(true)
    }

    pub(crate) fn remove_by_index(
        &mut self,
        index: SymbolIndex,
    ) -> Result<bool, EntityStorageError> {
        let Some(id) = self.index.indices.get(&index).copied() else {
            return Ok(false);
        };

        self.remove_by_id(id)
    }
}
