use std::ops::{Bound, RangeBounds};
use std::str;
use std::sync::Arc;

use bytes::Bytes;
use smallvec::SmallVec;

use super::transient::SymbolTable as TransientSymbolTable;
use super::{SymbolIndexState, SymbolInsertion};
use crate::ir::Address;
use crate::ir::persistent::{PersistentIdAllocator, PersistentTable, append_insert, append_remove};
use crate::ir::symbol::{
    Symbol, SymbolEntry, SymbolId, SymbolIndex, SymbolProperties, SymbolTableSelector, symbol,
};
use crate::storage::entities::schema::{
    ENTITY_KEY_SYMBOL_ADDRESS_ID, ENTITY_KEY_SYMBOL_LOADER_ID, ENTITY_KEY_SYMBOL_NAME_ID,
    ENTITY_SYMBOL_ADDRESS_INDEX_ID, ENTITY_SYMBOL_LOADER_INDEX_ID, ENTITY_SYMBOL_NAME_INDEX_ID,
};
use crate::storage::entities::{
    CachedRef, Entity, EntityCache, EntityId, EntityKey, EntityKeyId, EntityStorage,
    EntityStorageError, EntityWrite, EntityWriteBatch, WriteBackWorker, schema,
};

const INDEX_REBUILD_BATCH: usize = 512;

type Ref<'a> = CachedRef<'a, SymbolEntry>;

struct PreparedSymbolInsertion {
    encoded_len: usize,
    entry: SymbolEntry,
    id: SymbolId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SymbolNameKey {
    name: Symbol,
    id: SymbolId,
}

impl SymbolNameKey {
    fn first(name: Symbol) -> Self {
        Self {
            name,
            id: SymbolId::with_generation(0, 0),
        }
    }
}

impl EntityKey for SymbolNameKey {
    const ID: EntityKeyId = ENTITY_KEY_SYMBOL_NAME_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        let (length, rest) = buf.split_at_checked(size_of::<u32>())?;
        let length = u32::from_be_bytes(length.try_into().ok()?) as usize;
        if rest.len() != length + size_of::<u64>() {
            return None;
        }
        Some(Self {
            name: symbol(str::from_utf8(&rest[..length]).ok()?),
            id: SymbolId::decode_as_key(&rest[length..])?,
        })
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        let name = self.name.as_bytes();
        let length = u32::try_from(name.len()).expect("symbol name fits persistent index key");
        output.extend(length.to_be_bytes());
        output.extend(name.iter().copied());
        self.id.encode(output);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SymbolAddressKey {
    address: Address,
    id: SymbolId,
}

impl SymbolAddressKey {
    fn first(address: Address) -> Self {
        Self {
            address,
            id: SymbolId::with_generation(0, 0),
        }
    }
}

impl EntityKey for SymbolAddressKey {
    const ID: EntityKeyId = ENTITY_KEY_SYMBOL_ADDRESS_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != Address::ENCODED_SIZE + size_of::<u64>() {
            return None;
        }
        Some(Self {
            address: Address::decode(&buf[..Address::ENCODED_SIZE])?,
            id: SymbolId::decode_as_key(&buf[Address::ENCODED_SIZE..])?,
        })
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        self.address.encode(output);
        self.id.encode(output);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SymbolLoaderKey {
    selector: u8,
    index: u64,
}

impl SymbolLoaderKey {
    fn new(index: SymbolIndex) -> Self {
        Self {
            selector: index.selector().index() as u8,
            index: index.index() as u64,
        }
    }

    fn first(selector: SymbolTableSelector) -> Self {
        Self {
            selector: selector.index() as u8,
            index: 0,
        }
    }

    fn symbol_index(self) -> SymbolIndex {
        SymbolIndex::new(
            SymbolTableSelector::new(usize::from(self.selector)),
            self.index as usize,
        )
    }
}

impl EntityKey for SymbolLoaderKey {
    const ID: EntityKeyId = ENTITY_KEY_SYMBOL_LOADER_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        let (&selector, index) = buf.split_first()?;
        Some(Self {
            selector,
            index: u64::from_be_bytes(index.try_into().ok()?),
        })
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        output.extend([self.selector]);
        output.extend(self.index.to_be_bytes());
    }
}

#[derive(Debug, Clone, Copy, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct SymbolNameRecord;

impl Entity for SymbolNameRecord {
    const ID: EntityId = ENTITY_SYMBOL_NAME_INDEX_ID;
}

#[derive(Debug, Clone, Copy, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct SymbolAddressRecord;

impl Entity for SymbolAddressRecord {
    const ID: EntityId = ENTITY_SYMBOL_ADDRESS_INDEX_ID;
}

#[derive(Debug, Clone, Copy, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct SymbolLoaderRecord {
    id: SymbolId,
}

impl Entity for SymbolLoaderRecord {
    const ID: EntityId = ENTITY_SYMBOL_LOADER_INDEX_ID;
}

pub struct SymbolTable {
    allocator: PersistentIdAllocator<Symbol>,
    entries: EntityCache<SymbolId, SymbolEntry>,
    storage: EntityStorage,
}

impl SymbolTable {
    pub(crate) fn new(
        storage: EntityStorage,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        let entries = EntityCache::new(storage.clone(), cache_bytes)?;
        Self::from_entries(storage, entries)
    }

    pub(crate) fn with_worker(
        storage: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        let entries = EntityCache::with_worker(storage.clone(), worker, cache_bytes);
        Self::from_entries(storage, entries)
    }

    fn from_entries(
        storage: EntityStorage,
        entries: EntityCache<SymbolId, SymbolEntry>,
    ) -> Result<Self, EntityStorageError> {
        let allocator =
            match PersistentIdAllocator::load(storage.clone(), PersistentTable::Symbols)? {
                Some(allocator) => allocator,
                None => Self::rebuild_indexes(&storage, &entries)?,
            };
        Ok(Self {
            allocator,
            entries,
            storage,
        })
    }

    fn rebuild_indexes(
        storage: &EntityStorage,
        entries: &EntityCache<SymbolId, SymbolEntry>,
    ) -> Result<PersistentIdAllocator<Symbol>, EntityStorageError> {
        let mut live = 0usize;
        let mut next_index = 0usize;
        let mut writes = EntityWriteBatch::with_capacity(INDEX_REBUILD_BATCH);
        for entry in entries.try_iter()? {
            let (id, entry) = entry?;
            Self::append_links(&mut writes, id, &entry)?;
            live += 1;
            next_index = next_index.max(id.index() + 1);
            if writes.len() >= INDEX_REBUILD_BATCH {
                storage.apply_batch(&writes)?;
                writes.clear();
            }
        }
        storage.apply_batch(&writes)?;
        PersistentIdAllocator::initialise(
            storage.clone(),
            PersistentTable::Symbols,
            next_index,
            live,
        )
    }

    fn append_links(
        writes: &mut EntityWriteBatch,
        id: SymbolId,
        entry: &SymbolEntry,
    ) -> Result<(), EntityStorageError> {
        append_insert(
            writes,
            &SymbolNameKey {
                name: entry.symbol(),
                id,
            },
            &SymbolNameRecord,
        )?;
        append_insert(
            writes,
            &SymbolAddressKey {
                address: entry.address(),
                id,
            },
            &SymbolAddressRecord,
        )?;
        for &index in entry.indices() {
            append_insert(
                writes,
                &SymbolLoaderKey::new(index),
                &SymbolLoaderRecord { id },
            )?;
        }
        Ok(())
    }

    pub(super) fn initialise(
        &mut self,
        symbols: TransientSymbolTable,
    ) -> Result<(), EntityStorageError> {
        let mut symbols = symbols.into_entries();
        loop {
            let mut prepared = Vec::with_capacity(INDEX_REBUILD_BATCH);
            let mut reservations = Vec::with_capacity(INDEX_REBUILD_BATCH);
            let mut writes = EntityWriteBatch::with_capacity(INDEX_REBUILD_BATCH * 4);

            for offset in 0..INDEX_REBUILD_BATCH {
                let Some(entry) = symbols.next() else {
                    break;
                };
                let id = self.preview_id(offset);
                let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(&entry)
                    .map_err(EntityStorageError::encode)?;
                let encoded_len = encoded.len();
                writes.push(EntityWrite::insert_archive(
                    schema::make_key::<SymbolId, SymbolEntry>(&id),
                    encoded,
                ));
                Self::append_links(&mut writes, id, &entry)?;
                reservations.push(id);
                prepared.push(PreparedSymbolInsertion {
                    encoded_len,
                    entry,
                    id,
                });
            }

            if prepared.is_empty() {
                return Ok(());
            }

            self.allocator
                .append_transition(&reservations, &[], prepared.len(), 0, &mut writes)?;
            self.storage.apply_batch(&writes)?;
            for insertion in prepared {
                self.entries
                    .publish_put(insertion.id, insertion.entry, insertion.encoded_len);
            }
            self.allocator
                .publish_transition(&reservations, reservations.len(), 0);
        }
    }

    fn append_unlinks(writes: &mut EntityWriteBatch, id: SymbolId, entry: &SymbolIndexState) {
        append_remove::<_, SymbolNameRecord>(
            writes,
            &SymbolNameKey {
                name: entry.symbol(),
                id,
            },
        );
        append_remove::<_, SymbolAddressRecord>(
            writes,
            &SymbolAddressKey {
                address: entry.address(),
                id,
            },
        );
        for &index in entry.indices() {
            append_remove::<_, SymbolLoaderRecord>(writes, &SymbolLoaderKey::new(index));
        }
    }

    pub(crate) fn append_mutation_writes(
        &self,
        id: SymbolId,
        entry: Option<&SymbolEntry>,
        previous: Option<&SymbolIndexState>,
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        if let Some(previous) = previous {
            Self::append_unlinks(writes, id, previous);
        }
        if let Some(entry) = entry {
            Self::append_links(writes, id, entry)?;
        }
        Ok(())
    }

    pub(crate) fn append_allocator_writes(
        &self,
        reservations: &[SymbolId],
        releases: &[SymbolId],
        added: usize,
        removed: usize,
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        self.allocator
            .append_transition(reservations, releases, added, removed, writes)
    }

    pub(crate) fn publish_transition(
        &mut self,
        reservations: &[SymbolId],
        added: usize,
        removed: usize,
    ) {
        self.allocator
            .publish_transition(reservations, added, removed);
    }

    pub(crate) fn flush(&self) -> Result<(), EntityStorageError> {
        self.entries.flush()
    }

    pub(super) fn preview_id(&self, offset: usize) -> SymbolId {
        self.allocator
            .preview_id(offset)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub(super) fn publish_upsert(&self, id: SymbolId, entry: SymbolEntry, encoded_len: usize) {
        self.entries.publish_put(id, entry, encoded_len);
    }

    pub(super) fn publish_remove(&self, id: SymbolId) {
        self.entries.publish_remove(&id);
    }

    pub(super) fn get_id_by_index(&self, index: SymbolIndex) -> Option<SymbolId> {
        self.storage
            .get::<SymbolLoaderKey, SymbolLoaderRecord>(&SymbolLoaderKey::new(index))
            .unwrap_or_else(|error| error.into_fatal())
            .map(|record| record.id)
    }

    fn ids_by_address(
        &self,
        address: Address,
    ) -> Result<SmallVec<[SymbolId; 2]>, EntityStorageError> {
        let first = SymbolAddressKey::first(address);
        self.storage
            .iter_range::<SymbolAddressKey, SymbolAddressRecord>(Bound::Included(&first))?
            .map_while(|entry| match entry {
                Ok((key, _)) if key.address == address => Some(Ok(key.id)),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }

    fn ids_by_name(&self, name: Symbol) -> Result<Vec<SymbolId>, EntityStorageError> {
        let first = SymbolNameKey::first(name);
        self.storage
            .iter_range::<SymbolNameKey, SymbolNameRecord>(Bound::Included(&first))?
            .map_while(|entry| match entry {
                Ok((key, _)) if key.name == name => Some(Ok(key.id)),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }

    fn referent_of(&self, entry: &SymbolEntry) -> Result<Option<SymbolId>, EntityStorageError> {
        for id in self.ids_by_address(entry.address())? {
            if self
                .entries
                .try_get(&id)?
                .is_some_and(|existing| existing.has_same_referent(entry))
            {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    fn replace_entry(
        &mut self,
        id: SymbolId,
        entry: SymbolEntry,
        previous: Option<&SymbolEntry>,
        is_new: bool,
    ) -> Result<(), EntityStorageError> {
        let encoded =
            rkyv::to_bytes::<rkyv::rancor::Error>(&entry).map_err(EntityStorageError::encode)?;
        let encoded_len = encoded.len();
        let mut writes = EntityWriteBatch::new();
        writes.push(EntityWrite::insert_archive(
            schema::make_key::<SymbolId, SymbolEntry>(&id),
            encoded,
        ));
        let previous_state = previous.map(SymbolIndexState::new);
        self.append_mutation_writes(id, Some(&entry), previous_state.as_ref(), &mut writes)?;
        let added = if is_new { 1 } else { 0 };
        let reservations = is_new
            .then_some(id)
            .into_iter()
            .collect::<SmallVec<[_; 1]>>();
        self.allocator
            .append_transition(&reservations, &[], added, 0, &mut writes)?;
        self.entries.flush()?;
        self.storage.apply_batch(&writes)?;
        self.entries.publish_put(id, entry, encoded_len);
        self.allocator.publish_transition(&reservations, added, 0);
        Ok(())
    }

    fn insert_or_update(
        &mut self,
        index: SymbolIndex,
        mut entry: SymbolEntry,
    ) -> Result<SymbolInsertion, EntityStorageError> {
        if let Some(id) = self.referent_of(&entry)? {
            let Some(existing) = self.entries.try_get(&id)? else {
                return Ok(SymbolInsertion::new(id, false));
            };
            let previous = existing.as_ref().clone();
            drop(existing);
            let properties = entry.properties();
            entry = previous.clone();
            entry.add_index(index);
            entry.update_visibility(properties);
            self.replace_entry(id, entry, Some(&previous), false)?;
            return Ok(SymbolInsertion::new(id, false));
        }

        let id = self.preview_id(0);
        self.replace_entry(id, entry, None, true)?;
        Ok(SymbolInsertion::new(id, true))
    }

    pub(crate) fn insert(
        &mut self,
        index: SymbolIndex,
        address: Address,
        name: Symbol,
        properties: SymbolProperties,
    ) -> Result<SymbolInsertion, EntityStorageError> {
        let entry = SymbolEntry::new(address, name, properties).with_index(index);
        let Some(existing_id) = self.get_id_by_index(index) else {
            return self.insert_or_update(index, entry);
        };
        let Some(existing) = self.entries.try_get(&existing_id)? else {
            return self.insert_or_update(index, entry);
        };
        if *existing == entry {
            return Ok(SymbolInsertion::new(existing_id, false));
        }
        let previous = existing.as_ref().clone();
        drop(existing);
        if previous.indices().len() > 1 {
            let mut updated = previous.clone();
            updated.remove_index(index);
            self.replace_entry(existing_id, updated, Some(&previous), false)?;
            return self.insert_or_update(index, entry);
        }
        self.remove_by_id(existing_id)?;
        self.insert_or_update(index, entry)
    }

    pub(crate) fn try_modify_by_id<R>(
        &mut self,
        id: SymbolId,
        f: impl FnOnce(&mut SymbolEntry) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        let Some(existing) = self.entries.try_get(&id)? else {
            return Ok(None);
        };
        let previous = existing.as_ref().clone();
        let mut updated = previous.clone();
        drop(existing);
        let result = f(&mut updated);
        self.replace_entry(id, updated, Some(&previous), false)?;
        Ok(Some(result))
    }

    pub(crate) fn get(
        &self,
        name: impl AsRef<str>,
    ) -> Option<impl Iterator<Item = (SymbolId, Ref<'_>)> + '_> {
        let name = Symbol::from_existing(name.as_ref())?;
        let ids = self
            .ids_by_name(name)
            .unwrap_or_else(|error| error.into_fatal());
        Some(
            ids.into_iter()
                .filter_map(move |id| self.entries.get(&id).map(|entry| (id, entry))),
        )
    }

    pub(crate) fn try_get_first(
        &self,
        name: impl AsRef<str>,
    ) -> Result<Option<(SymbolId, Ref<'_>)>, EntityStorageError> {
        let Some(name) = Symbol::from_existing(name.as_ref()) else {
            return Ok(None);
        };
        let Some(id) = self.ids_by_name(name)?.into_iter().next() else {
            return Ok(None);
        };
        Ok(self.entries.try_get(&id)?.map(|entry| (id, entry)))
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
        let Some(id) = self.get_id_by_index(index) else {
            return Ok(None);
        };
        Ok(self.entries.try_get(&id)?.map(|entry| (id, entry)))
    }

    pub(crate) fn get_by_address(
        &self,
        address: Address,
    ) -> impl Iterator<Item = (SymbolId, Ref<'_>)> + '_ {
        let ids = self
            .ids_by_address(address)
            .unwrap_or_else(|error| error.into_fatal());
        ids.into_iter()
            .filter_map(move |id| self.entries.get(&id).map(|entry| (id, entry)))
    }

    pub(crate) fn try_get_first_by_address(
        &self,
        address: Address,
    ) -> Result<Option<(SymbolId, Ref<'_>)>, EntityStorageError> {
        let Some(id) = self.ids_by_address(address)?.into_iter().next() else {
            return Ok(None);
        };
        Ok(self.entries.try_get(&id)?.map(|entry| (id, entry)))
    }

    pub(crate) fn contains(&self, name: impl AsRef<str>) -> bool {
        Symbol::from_existing(name.as_ref()).is_some_and(|name| {
            !self
                .ids_by_name(name)
                .unwrap_or_else(|error| error.into_fatal())
                .is_empty()
        })
    }

    pub(crate) fn contains_index(&self, index: SymbolIndex) -> bool {
        self.get_id_by_index(index).is_some()
    }

    pub(crate) fn contains_address(&self, address: Address) -> bool {
        !self
            .ids_by_address(address)
            .unwrap_or_else(|error| error.into_fatal())
            .is_empty()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (SymbolId, Ref<'_>)> + '_ {
        self.iter_by_address()
    }

    pub(crate) fn iter_by_selector(
        &self,
        selector: SymbolTableSelector,
    ) -> impl Iterator<Item = (SymbolId, Ref<'_>)> + '_ {
        let first = SymbolLoaderKey::first(selector);
        self.storage
            .iter_range::<SymbolLoaderKey, SymbolLoaderRecord>(Bound::Included(&first))
            .unwrap_or_else(|error| error.into_fatal())
            .map_while(move |entry| {
                let (key, record) = entry.unwrap_or_else(|error| error.into_fatal());
                (key.selector == selector.index() as u8).then_some(record.id)
            })
            .filter_map(move |id| self.entries.get(&id).map(|entry| (id, entry)))
    }

    pub(crate) fn iter_by_address(&self) -> impl Iterator<Item = (SymbolId, Ref<'_>)> + '_ {
        self.storage
            .iter::<SymbolAddressKey, SymbolAddressRecord>()
            .unwrap_or_else(|error| error.into_fatal())
            .filter_map(move |entry| {
                let (key, _) = entry.unwrap_or_else(|error| error.into_fatal());
                self.entries.get(&key.id).map(|entry| (key.id, entry))
            })
    }

    pub(crate) fn range_by_address<R>(
        &self,
        range: R,
    ) -> impl Iterator<Item = (SymbolId, Ref<'_>)> + '_
    where
        R: RangeBounds<Address>,
    {
        let lower = match range.start_bound() {
            Bound::Included(address) => Bound::Included(*address),
            Bound::Excluded(address) => Bound::Excluded(*address),
            Bound::Unbounded => Bound::Unbounded,
        };
        let upper = match range.end_bound() {
            Bound::Included(address) => Bound::Included(*address),
            Bound::Excluded(address) => Bound::Excluded(*address),
            Bound::Unbounded => Bound::Unbounded,
        };
        let start = match lower {
            Bound::Included(address) | Bound::Excluded(address) => {
                Bound::Included(SymbolAddressKey::first(address))
            }
            Bound::Unbounded => Bound::Unbounded,
        };
        self.storage
            .iter_range::<SymbolAddressKey, SymbolAddressRecord>(start.as_ref())
            .unwrap_or_else(|error| error.into_fatal())
            .map_while(move |entry| {
                let (key, _) = entry.unwrap_or_else(|error| error.into_fatal());
                match upper {
                    Bound::Included(end) if key.address > end => None,
                    Bound::Excluded(end) if key.address >= end => None,
                    _ => Some(key),
                }
            })
            .filter(move |key| match lower {
                Bound::Included(start) => key.address >= start,
                Bound::Excluded(start) => key.address > start,
                Bound::Unbounded => true,
            })
            .filter_map(move |key| self.entries.get(&key.id).map(|entry| (key.id, entry)))
    }

    pub(crate) fn iter_by_index(
        &self,
    ) -> impl Iterator<Item = (SymbolIndex, SymbolId, Ref<'_>)> + '_ {
        self.storage
            .iter::<SymbolLoaderKey, SymbolLoaderRecord>()
            .unwrap_or_else(|error| error.into_fatal())
            .filter_map(move |entry| {
                let (key, record) = entry.unwrap_or_else(|error| error.into_fatal());
                self.entries
                    .get(&record.id)
                    .map(|entry| (key.symbol_index(), record.id, entry))
            })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.allocator.len() == 0
    }

    pub(crate) fn len(&self) -> usize {
        self.allocator.len()
    }

    pub(crate) fn remove(&mut self, name: impl AsRef<str>) -> Result<usize, EntityStorageError> {
        let Some(name) = Symbol::from_existing(name.as_ref()) else {
            return Ok(0);
        };
        let ids = self.ids_by_name(name)?;
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
        let ids = self.ids_by_address(address)?;
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
        let previous = SymbolIndexState::new(&entry);
        drop(entry);
        let mut writes = EntityWriteBatch::new();
        append_remove::<_, SymbolEntry>(&mut writes, &id);
        self.append_mutation_writes(id, None, Some(&previous), &mut writes)?;
        self.allocator
            .append_transition(&[], &[id], 0, 1, &mut writes)?;
        self.entries.flush()?;
        self.storage.apply_batch(&writes)?;
        self.entries.publish_remove(&id);
        self.allocator.publish_transition(&[], 0, 1);
        Ok(true)
    }

    pub(crate) fn remove_by_index(
        &mut self,
        index: SymbolIndex,
    ) -> Result<bool, EntityStorageError> {
        let Some(id) = self.get_id_by_index(index) else {
            return Ok(false);
        };
        self.remove_by_id(id)
    }
}
