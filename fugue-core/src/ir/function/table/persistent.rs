use std::collections::BTreeSet;
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;

use bytes::Bytes;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use super::{FunctionTableError, PreparedFunctionEntry};
use crate::ir::persistent::{PersistentIdAllocator, PersistentTable, append_insert, append_remove};
use crate::ir::{Address, CodeBlockId, Function, FunctionId, Id, RawAddress};
use crate::storage::entities::schema::{
    ENTITY_FUNCTION_ENTRY_INDEX_ID, ENTITY_FUNCTION_OWNER_INDEX_ID, ENTITY_KEY_FUNCTION_OWNER_ID,
};
use crate::storage::entities::{
    CachedMut, CachedRef, Entity, EntityCache, EntityId, EntityKey, EntityKeyId, EntityStorage,
    EntityStorageError, EntityWrite, EntityWriteBatch, WriteBackWorker, schema,
};
use crate::storage::segments::space::AddressSpaceId;

const INDEX_REBUILD_BATCH: usize = 512;

type Ref<'a> = CachedRef<'a, Function>;
type RefMut<'a> = CachedMut<'a, Function>;

#[derive(Debug, Clone, Copy, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct FunctionEntryRecord {
    id: FunctionId,
}

impl Entity for FunctionEntryRecord {
    const ID: EntityId = ENTITY_FUNCTION_ENTRY_INDEX_ID;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FunctionOwnerKey {
    block: CodeBlockId,
    function: FunctionId,
}

impl FunctionOwnerKey {
    fn first(block: CodeBlockId) -> Self {
        Self {
            block,
            function: FunctionId::with_generation(0, 0),
        }
    }
}

impl EntityKey for FunctionOwnerKey {
    const ID: EntityKeyId = ENTITY_KEY_FUNCTION_OWNER_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        const ID_SIZE: usize = size_of::<u64>();
        if buf.len() != ID_SIZE * 2 {
            return None;
        }
        Some(Self {
            block: CodeBlockId::decode_as_key(&buf[..ID_SIZE])?,
            function: FunctionId::decode_as_key(&buf[ID_SIZE..])?,
        })
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        self.block.encode(output);
        self.function.encode(output);
    }
}

#[derive(Debug, Clone, Copy, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct FunctionOwnerRecord;

impl Entity for FunctionOwnerRecord {
    const ID: EntityId = ENTITY_FUNCTION_OWNER_INDEX_ID;
}

pub struct FunctionTable {
    allocator: PersistentIdAllocator<Function>,
    entries: EntityCache<Id<Function>, Function>,
    storage: EntityStorage,
}

impl FunctionTable {
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
        entries: EntityCache<Id<Function>, Function>,
    ) -> Result<Self, EntityStorageError> {
        let allocator =
            match PersistentIdAllocator::load(storage.clone(), PersistentTable::Functions)? {
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
        entries: &EntityCache<Id<Function>, Function>,
    ) -> Result<PersistentIdAllocator<Function>, EntityStorageError> {
        let mut live = 0usize;
        let mut next_index = 0usize;
        let mut writes = EntityWriteBatch::with_capacity(INDEX_REBUILD_BATCH);

        for entry in entries.try_iter()? {
            let (id, function) = entry?;
            append_insert(&mut writes, &function.entry(), &FunctionEntryRecord { id })?;
            for (_, block) in function.blocks() {
                append_insert(
                    &mut writes,
                    &FunctionOwnerKey {
                        block,
                        function: id,
                    },
                    &FunctionOwnerRecord,
                )?;
            }
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
            PersistentTable::Functions,
            next_index,
            live,
        )
    }

    pub(crate) fn flush(&self) -> Result<(), EntityStorageError> {
        self.entries.flush()
    }

    pub(super) fn preview_id(&self, offset: usize) -> FunctionId {
        self.allocator
            .preview_id(offset)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub(super) fn append_stage_writes(
        &self,
        entries: &[PreparedFunctionEntry],
        reservations: &[FunctionId],
        cancelled: &BTreeSet<FunctionId>,
        owners: &FxHashMap<CodeBlockId, SmallVec<[FunctionId; 2]>>,
        original_owners: &FxHashMap<CodeBlockId, SmallVec<[FunctionId; 2]>>,
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        let mut added = 0usize;
        let mut removed = 0usize;
        for entry in entries {
            if let Some(previous) = entry.previous
                && (entry.function.is_none()
                    || entry
                        .function
                        .as_ref()
                        .is_some_and(|function| function.entry() != previous))
            {
                append_remove::<_, FunctionEntryRecord>(writes, &previous);
            }
            match &entry.function {
                Some(function) => {
                    append_insert(
                        writes,
                        &function.entry(),
                        &FunctionEntryRecord { id: entry.id },
                    )?;
                    if entry.previous.is_none() {
                        added += 1;
                    }
                }
                None => removed += 1,
            }
        }

        for (&block, final_owners) in owners {
            let previous = original_owners
                .get(&block)
                .map_or(&[] as &[FunctionId], SmallVec::as_slice);
            for owner in previous
                .iter()
                .filter(|owner| !final_owners.contains(owner))
            {
                append_remove::<_, FunctionOwnerRecord>(
                    writes,
                    &FunctionOwnerKey {
                        block,
                        function: *owner,
                    },
                );
            }
            for owner in final_owners
                .iter()
                .filter(|owner| !previous.contains(owner))
            {
                append_insert(
                    writes,
                    &FunctionOwnerKey {
                        block,
                        function: *owner,
                    },
                    &FunctionOwnerRecord,
                )?;
            }
        }

        let releases = cancelled
            .iter()
            .copied()
            .chain(entries.iter().filter_map(|entry| {
                (entry.function.is_none() && entry.previous.is_some()).then_some(entry.id)
            }))
            .collect::<SmallVec<[_; 8]>>();
        self.allocator
            .append_transition(reservations, &releases, added, removed, writes)
    }

    pub(super) fn publish_transition(
        &mut self,
        reservations: &[FunctionId],
        added: usize,
        removed: usize,
    ) {
        self.allocator
            .publish_transition(reservations, added, removed);
    }

    pub(super) fn publish_upsert(&self, function: Function, encoded_len: usize) {
        self.entries
            .publish_put(function.id(), function, encoded_len);
    }

    pub(super) fn publish_remove(&self, id: FunctionId) {
        self.entries.publish_remove(&id);
    }

    pub(crate) fn insert_with<R, F>(
        &mut self,
        address: Address,
        f: F,
    ) -> Result<(FunctionId, R), FunctionTableError>
    where
        F: FnOnce(Id<Function>, Address) -> Result<(Function, R), FunctionTableError>,
    {
        let previous = self.try_get_by_address(address)?;
        let id = previous
            .as_ref()
            .map_or_else(|| self.preview_id(0), |function| function.id());
        let (function, value) = f(id, address)?;
        if function.entry() != address {
            return Err(FunctionTableError::AddressMismatch);
        }

        let previous_blocks = previous
            .as_ref()
            .map(|function| {
                function
                    .blocks()
                    .map(|(_, block)| block)
                    .collect::<SmallVec<[_; 8]>>()
            })
            .unwrap_or_default();
        let blocks = function
            .blocks()
            .map(|(_, block)| block)
            .collect::<SmallVec<[_; 8]>>();
        let encoded =
            rkyv::to_bytes::<rkyv::rancor::Error>(&function).map_err(EntityStorageError::encode)?;
        let encoded_len = encoded.len();
        let mut writes = EntityWriteBatch::new();
        writes.push(EntityWrite::insert_archive(
            schema::make_key::<FunctionId, Function>(&id),
            encoded,
        ));
        append_insert(&mut writes, &address, &FunctionEntryRecord { id })?;
        for block in previous_blocks
            .iter()
            .filter(|block| !blocks.contains(block))
        {
            append_remove::<_, FunctionOwnerRecord>(
                &mut writes,
                &FunctionOwnerKey {
                    block: *block,
                    function: id,
                },
            );
        }
        for block in blocks
            .iter()
            .filter(|block| !previous_blocks.contains(block))
        {
            append_insert(
                &mut writes,
                &FunctionOwnerKey {
                    block: *block,
                    function: id,
                },
                &FunctionOwnerRecord,
            )?;
        }
        let is_new = previous.is_none();
        let added = if is_new { 1 } else { 0 };
        let reservations = is_new
            .then_some(id)
            .into_iter()
            .collect::<SmallVec<[_; 1]>>();
        self.allocator
            .append_transition(&reservations, &[], added, 0, &mut writes)?;
        self.entries.flush()?;
        self.storage.apply_batch(&writes)?;
        self.entries.publish_put(id, function, encoded_len);
        self.allocator.publish_transition(&reservations, added, 0);
        Ok((id, value))
    }

    pub(crate) fn try_get_by_id(
        &self,
        id: Id<Function>,
    ) -> Result<Option<Ref<'_>>, EntityStorageError> {
        self.entries.try_get(&id)
    }

    pub(crate) fn try_get_by_address(
        &self,
        address: Address,
    ) -> Result<Option<Ref<'_>>, EntityStorageError> {
        let Some(record) = self.storage.get::<Address, FunctionEntryRecord>(&address)? else {
            return Ok(None);
        };
        self.entries.try_get(&record.id)
    }

    pub(crate) fn try_modify_by_id<R>(
        &mut self,
        id: Id<Function>,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        self.entries.try_modify(&id, f)
    }

    pub(crate) fn try_modify_by_address<R>(
        &mut self,
        address: Address,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        let Some(record) = self.storage.get::<Address, FunctionEntryRecord>(&address)? else {
            return Ok(None);
        };
        self.entries.try_modify(&record.id, f)
    }

    pub(crate) fn try_get_by_id_mut(
        &mut self,
        id: Id<Function>,
    ) -> Result<Option<RefMut<'_>>, EntityStorageError> {
        self.entries.try_get_mut(&id)
    }

    pub(crate) fn try_get_by_address_mut(
        &mut self,
        address: Address,
    ) -> Result<Option<RefMut<'_>>, EntityStorageError> {
        let Some(record) = self.storage.get::<Address, FunctionEntryRecord>(&address)? else {
            return Ok(None);
        };
        self.entries.try_get_mut(&record.id)
    }

    pub(crate) fn try_remove_by_id(
        &mut self,
        id: Id<Function>,
    ) -> Result<bool, EntityStorageError> {
        let Some(function) = self.entries.try_get(&id)? else {
            return Ok(false);
        };
        let address = function.entry();
        let blocks = function
            .blocks()
            .map(|(_, block)| block)
            .collect::<SmallVec<[_; 8]>>();
        drop(function);

        let mut writes = EntityWriteBatch::new();
        append_remove::<_, Function>(&mut writes, &id);
        append_remove::<_, FunctionEntryRecord>(&mut writes, &address);
        for block in blocks {
            append_remove::<_, FunctionOwnerRecord>(
                &mut writes,
                &FunctionOwnerKey {
                    block,
                    function: id,
                },
            );
        }
        self.allocator
            .append_transition(&[], &[id], 0, 1, &mut writes)?;
        self.entries.flush()?;
        self.storage.apply_batch(&writes)?;
        self.entries.publish_remove(&id);
        self.allocator.publish_transition(&[], 0, 1);
        Ok(true)
    }

    pub(crate) fn try_remove_by_address(
        &mut self,
        address: Address,
    ) -> Result<bool, EntityStorageError> {
        let Some(record) = self.storage.get::<Address, FunctionEntryRecord>(&address)? else {
            return Ok(false);
        };
        self.try_remove_by_id(record.id)
    }

    pub(crate) fn contains(&self, address: Address) -> bool {
        self.storage
            .contains::<Address, FunctionEntryRecord>(&address)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub(crate) fn addresses(&self) -> impl Iterator<Item = Address> + '_ {
        self.storage
            .iter::<Address, FunctionEntryRecord>()
            .unwrap_or_else(|error| error.into_fatal())
            .map(|entry| entry.unwrap_or_else(|error| error.into_fatal()).0)
    }

    pub(crate) fn addresses_in_range<R>(
        &self,
        space: AddressSpaceId,
        range: R,
    ) -> impl Iterator<Item = Address> + '_
    where
        R: RangeBounds<RawAddress>,
    {
        let (start, end) = Address::bounds_in_space(space, &range);
        self.storage
            .iter_range::<Address, FunctionEntryRecord>(start.as_ref())
            .unwrap_or_else(|error| error.into_fatal())
            .map(|entry| entry.unwrap_or_else(|error| error.into_fatal()).0)
            .take_while(move |address| match end {
                Bound::Included(end) => *address <= end,
                Bound::Excluded(end) => *address < end,
                Bound::Unbounded => true,
            })
    }

    pub(super) fn block_owners(&self, block: CodeBlockId) -> SmallVec<[FunctionId; 2]> {
        self.storage
            .iter_range::<FunctionOwnerKey, FunctionOwnerRecord>(Bound::Included(
                &FunctionOwnerKey::first(block),
            ))
            .unwrap_or_else(|error| error.into_fatal())
            .map_while(|entry| {
                let (key, _) = entry.unwrap_or_else(|error| error.into_fatal());
                (key.block == block).then_some(key.function)
            })
            .collect()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = Ref<'_>> + '_ {
        self.try_iter()
            .unwrap_or_else(|error| error.into_fatal())
            .map(|entry| entry.unwrap_or_else(|error| error.into_fatal()))
    }

    pub(crate) fn try_iter(
        &self,
    ) -> Result<impl Iterator<Item = Result<Ref<'_>, EntityStorageError>>, EntityStorageError> {
        Ok(self
            .entries
            .try_iter()?
            .map(|entry| entry.map(|(_, function)| function)))
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = RefMut<'_>> + '_ {
        self.entries.iter_mut()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.allocator.len() == 0
    }

    pub(crate) fn len(&self) -> usize {
        self.allocator.len()
    }
}
