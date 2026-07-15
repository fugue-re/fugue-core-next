use std::collections::BTreeMap;
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;

use smallvec::SmallVec;

use super::super::{SymbolEntry, SymbolIndex, SymbolMap, SymbolProperties, SymbolTableSelector};
use crate::ir::{Address, Id, symbol::Symbol};
use crate::storage::entities::{CachedRef, EntityCache, WriteBackWorker};
use crate::storage::{EntityStorage, EntityStorageError};

type Ref<'a> = CachedRef<'a, SymbolEntry>;

pub(super) struct Allocation {
    free_ids_len: usize,
    free_ids_tail: Vec<Id<Symbol>>,
    next_index: usize,
}

impl Allocation {
    fn new(free_ids: &[Id<Symbol>], next_index: usize, max_pops: usize) -> Self {
        let tail_start = free_ids.len().saturating_sub(max_pops);
        Self {
            free_ids_len: free_ids.len(),
            free_ids_tail: free_ids[tail_start..].to_vec(),
            next_index,
        }
    }
}

struct SymbolTableIndex {
    names: SymbolMap<SmallVec<[Id<Symbol>; 2]>>,
    addresses: BTreeMap<Address, SmallVec<[Id<Symbol>; 2]>>,
    indices: BTreeMap<SymbolIndex, Id<Symbol>>,
    free_ids: Vec<Id<Symbol>>,
    next_index: usize,
    live: usize,
}

impl SymbolTableIndex {
    fn link(&mut self, id: Id<Symbol>, entry: &SymbolEntry) {
        self.names.entry(entry.symbol()).or_default().push(id);
        self.addresses.entry(entry.address()).or_default().push(id);
        for &symbol_index in entry.indices() {
            self.indices.insert(symbol_index, id);
        }
    }

    fn unlink(&mut self, id: Id<Symbol>, entry: &SymbolEntry) {
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

    fn allocate(&mut self) -> Id<Symbol> {
        let id = match self.free_ids.pop() {
            Some(free_id) => free_id,
            None => {
                let id = Id::from_index(self.next_index);
                self.next_index += 1;
                id
            }
        };
        self.live += 1;
        id
    }

    fn release(&mut self, id: Id<Symbol>) {
        self.free_ids.push(id.next_generation());
        self.live -= 1;
    }
}

pub struct SymbolTable {
    index: SymbolTableIndex,
    entries: EntityCache<Id<Symbol>, SymbolEntry>,
}

impl SymbolTable {
    pub(crate) fn new(
        entities: EntityStorage,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Self::from_entries(EntityCache::new(entities, cache_bytes)?)
    }

    pub(crate) fn new_with(
        entities: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Self::from_entries(EntityCache::with_worker(entities, worker, cache_bytes))
    }

    fn from_entries(
        entries: EntityCache<Id<Symbol>, SymbolEntry>,
    ) -> Result<Self, EntityStorageError> {
        let mut index = SymbolTableIndex {
            names: SymbolMap::default(),
            addresses: BTreeMap::new(),
            indices: BTreeMap::new(),
            free_ids: Vec::new(),
            next_index: 0,
            live: 0,
        };

        for entry in entries.try_scan_range(Bound::Unbounded)? {
            let (id, entry) = entry?;
            index.link(id, entry.as_ref());
            index.next_index = index.next_index.max(id.index() + 1);
            index.live += 1;
        }

        Ok(Self { index, entries })
    }

    pub(crate) fn flush(&self) -> Result<(), EntityStorageError> {
        self.entries.flush()
    }

    pub(super) fn allocation_checkpoint(&self, max_pops: usize) -> Allocation {
        Allocation::new(&self.index.free_ids, self.index.next_index, max_pops)
    }

    pub(super) fn restore_allocation(&mut self, allocation: Allocation) {
        let tail_start = allocation.free_ids_len - allocation.free_ids_tail.len();
        self.index.free_ids.truncate(tail_start);
        self.index.free_ids.extend(allocation.free_ids_tail);
        self.index.next_index = allocation.next_index;
    }

    pub(super) fn restore_entry(
        &mut self,
        id: Id<Symbol>,
        entry: SymbolEntry,
    ) -> Result<(), EntityStorageError> {
        self.clear_entry(id)?;

        self.index.link(id, &entry);
        self.index.next_index = self.index.next_index.max(id.index() + 1);
        self.index
            .free_ids
            .retain(|free_id| free_id.index() != id.index());
        self.index.live += 1;
        self.entries.try_put(id, entry).map(|_| ())
    }

    pub(super) fn clear_entry(&mut self, id: Id<Symbol>) -> Result<bool, EntityStorageError> {
        let Some(entry) = self.entries.try_get(&id)? else {
            return Ok(false);
        };
        let entry = entry.as_ref().clone();

        self.index.unlink(id, &entry);
        self.index.live -= 1;
        self.entries.try_remove(&id)?;
        Ok(true)
    }

    pub(super) fn touched_by_insert(
        &self,
        index: SymbolIndex,
        entry: &SymbolEntry,
    ) -> Result<Vec<Id<Symbol>>, EntityStorageError> {
        let mut touched = Vec::new();
        if let Some(id) = self.index.indices.get(&index).copied() {
            touched.push(id);
        }

        if let Some(id) = self.referent_of(entry)? {
            touched.push(id);
        }

        Ok(touched)
    }

    pub(super) fn ids_by_symbol(&self, symbol: impl AsRef<str>) -> Vec<Id<Symbol>> {
        Symbol::from_existing(symbol.as_ref())
            .and_then(|symbol| self.index.names.get(&symbol))
            .map(|ids| ids.to_vec())
            .unwrap_or_default()
    }

    pub(super) fn ids_by_address(&self, address: Address) -> Vec<Id<Symbol>> {
        self.index
            .addresses
            .get(&address)
            .map(|ids| ids.to_vec())
            .unwrap_or_default()
    }

    pub(super) fn id_by_index(&self, index: SymbolIndex) -> Option<Id<Symbol>> {
        self.index.indices.get(&index).copied()
    }

    fn referent_of(&self, entry: &SymbolEntry) -> Result<Option<Id<Symbol>>, EntityStorageError> {
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
    ) -> Result<(bool, Id<Symbol>), EntityStorageError> {
        if let Some(id) = self.referent_of(&entry)? {
            let Some(existing) = self.entries.try_get(&id)? else {
                return Ok((false, id));
            };
            let mut updated = existing.as_ref().clone();
            drop(existing);

            updated.add_index(index);
            updated.update_visibility(entry.properties());
            self.entries.try_put(id, updated)?;

            return Ok((false, id));
        }

        let id = self.index.allocate();
        self.index.link(id, &entry);
        self.entries.try_put(id, entry)?;

        Ok((true, id))
    }

    pub(crate) fn insert(
        &mut self,
        index: SymbolIndex,
        address: Address,
        symbol: Symbol,
        properties: SymbolProperties,
    ) -> Result<(bool, Id<Symbol>), EntityStorageError> {
        let symbol_entry = SymbolEntry::new(address, symbol, properties).with_index(index);

        let Some(existing_id) = self.index.indices.get(&index).copied() else {
            let (is_new, id) = self.insert_or_update(index, symbol_entry)?;
            self.index.indices.insert(index, id);
            return Ok((is_new, id));
        };

        let Some(existing) = self.entries.try_get(&existing_id)? else {
            let (is_new, id) = self.insert_or_update(index, symbol_entry)?;
            self.index.indices.insert(index, id);
            return Ok((is_new, id));
        };

        if *existing.as_ref() == symbol_entry {
            return Ok((false, existing_id));
        }

        if existing.as_ref().indices().len() > 1 {
            let mut updated = existing.as_ref().clone();
            drop(existing);

            updated.remove_index(index);
            self.entries.try_put(existing_id, updated)?;

            let (is_new, id) = self.insert_or_update(index, symbol_entry)?;
            self.index.indices.insert(index, id);
            return Ok((is_new, id));
        }

        drop(existing);
        self.remove_by_id(existing_id)?;
        self.insert(index, address, symbol, properties)
    }

    pub(crate) fn get(
        &self,
        symbol: impl AsRef<str>,
    ) -> Option<impl Iterator<Item = (Id<Symbol>, Ref<'_>)> + '_> {
        let symbol = Symbol::from_existing(symbol.as_ref())?;
        let ids = self.index.names.get(&symbol)?;
        Some(self.entries_for(ids))
    }

    pub(crate) fn get_by_id(&self, id: Id<Symbol>) -> Option<Ref<'_>> {
        self.entries.get(&id)
    }

    pub(crate) fn get_by_index(&self, index: SymbolIndex) -> Option<(Id<Symbol>, Ref<'_>)> {
        let id = self.index.indices.get(&index).copied()?;
        self.entries.get(&id).map(|entry| (id, entry))
    }

    pub(crate) fn get_by_address(
        &self,
        address: Address,
    ) -> impl Iterator<Item = (Id<Symbol>, Ref<'_>)> + '_ {
        let ids = self
            .index
            .addresses
            .get(&address)
            .map(|ids| ids.as_slice())
            .unwrap_or_default();
        self.entries_for(ids)
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
        ids: &'a [Id<Symbol>],
    ) -> impl Iterator<Item = (Id<Symbol>, Ref<'a>)> + 'a {
        ids.iter()
            .copied()
            .filter_map(move |id| self.entries.get(&id).map(|entry| (id, entry)))
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (Id<Symbol>, Ref<'_>)> + '_ {
        self.index
            .addresses
            .values()
            .flat_map(move |ids| self.entries_for(ids))
    }

    pub(crate) fn iter_by_selector(
        &self,
        selector: SymbolTableSelector,
    ) -> impl Iterator<Item = (Id<Symbol>, Ref<'_>)> + '_ {
        self.index
            .indices
            .iter()
            .filter(move |(index, _)| index.selector() == selector)
            .filter_map(move |(_, &id)| self.entries.get(&id).map(|entry| (id, entry)))
    }

    pub(crate) fn iter_by_address(&self) -> impl Iterator<Item = (Id<Symbol>, Ref<'_>)> + '_ {
        self.index
            .addresses
            .values()
            .flat_map(move |ids| self.entries_for(ids))
    }

    pub(crate) fn range_by_address<R>(
        &self,
        range: R,
    ) -> impl Iterator<Item = (Id<Symbol>, Ref<'_>)> + '_
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
    ) -> impl Iterator<Item = (SymbolIndex, Id<Symbol>, Ref<'_>)> + '_ {
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
            self.remove_unlinked(id, move |index, entry| {
                use std::collections::btree_map::Entry as AddrsEntry;

                if let AddrsEntry::Occupied(mut ids) = index.addresses.entry(entry.address()) {
                    ids.get_mut().retain(|oid| *oid != id);
                    if ids.get().is_empty() {
                        ids.remove();
                    }
                }
            })?;
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
            self.remove_unlinked(id, move |index, entry| {
                use std::collections::hash_map::Entry as NamesEntry;

                if let NamesEntry::Occupied(mut ids) = index.names.entry(entry.symbol()) {
                    ids.get_mut().retain(|oid| *oid != id);
                    if ids.get().is_empty() {
                        ids.remove();
                    }
                }
            })?;
        }

        Ok(count)
    }

    fn remove_unlinked(
        &mut self,
        id: Id<Symbol>,
        unlink_rest: impl FnOnce(&mut SymbolTableIndex, &SymbolEntry),
    ) -> Result<(), EntityStorageError> {
        if let Some(entry) = self.entries.try_get(&id)? {
            let entry = entry.as_ref().clone();
            unlink_rest(&mut self.index, &entry);
            for symbol_index in entry.indices() {
                self.index.indices.remove(symbol_index);
            }
        }

        self.entries.try_remove(&id)?;
        self.index.release(id);
        Ok(())
    }

    pub(crate) fn remove_by_id(&mut self, id: Id<Symbol>) -> Result<bool, EntityStorageError> {
        let Some(entry) = self.entries.try_get(&id)? else {
            return Ok(false);
        };
        let entry = entry.as_ref().clone();

        self.index.unlink(id, &entry);
        self.entries.try_remove(&id)?;
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
