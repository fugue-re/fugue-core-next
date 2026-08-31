use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::Arc;

use smallvec::SmallVec;

use super::{CodeBlockIds, CodeBlockIdsByAddress};
use crate::ir::persistent::{PersistentIdAllocator, PersistentTable};
use crate::ir::{Address, AddressRange, CodeBlock, Id, PreparedCodeBlockRecord, RawAddress};
use crate::lifter::ContextSet;
use crate::storage::entities::schema::{
    ENTITY_CODE_BLOCK_SIZE_BUCKET_INDEX_ID, ENTITY_CODE_BLOCK_SIZE_BUCKETS_INDEX_ID,
    ENTITY_CODE_BLOCK_START_INDEX_ID, ENTITY_KEY_CODE_BLOCK_SIZE_BUCKET_ID,
    ENTITY_KEY_CODE_BLOCK_SIZE_BUCKETS_ID, ENTITY_KEY_CODE_BLOCK_START_ID,
};
use crate::storage::entities::{
    CachedRef, Entity, EntityCache, EntityId, EntityKey, EntityKeyCodec, EntityKeyId,
    EntityStorage, EntityStorageError, EntityWriteBatch, WriteBackWorker,
};
use crate::storage::segments::space::AddressSpaceId;

const INDEX_REBUILD_BATCH: usize = 512;

type Ref<'a> = CachedRef<'a, CodeBlock>;
type Iter<'a> = Box<dyn Iterator<Item = Ref<'a>> + 'a>;

pub struct CodeBlockTable {
    allocator: PersistentIdAllocator<CodeBlock>,
    entries: EntityCache<Id<CodeBlock>, CodeBlock>,
    storage: EntityStorage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CodeBlockStartKey {
    space: AddressSpaceId,
    start: RawAddress,
    id: Id<CodeBlock>,
}

impl CodeBlockStartKey {
    fn first(space: AddressSpaceId, start: RawAddress) -> Self {
        Self {
            space,
            start,
            id: Id::with_generation(0, 0),
        }
    }
}

impl EntityKeyCodec for CodeBlockStartKey {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        Some(Self {
            space: AddressSpaceId::decode(input)?,
            start: RawAddress::decode(input)?,
            id: Id::decode(input)?,
        })
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        self.space.encode(output);
        self.start.encode(output);
        self.id.encode(output);
    }
}

impl EntityKey for CodeBlockStartKey {
    const ID: EntityKeyId = ENTITY_KEY_CODE_BLOCK_START_ID;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CodeBlockSizeBucketKey {
    space: AddressSpaceId,
    bucket: u8,
    start: RawAddress,
    id: Id<CodeBlock>,
}

impl CodeBlockSizeBucketKey {
    fn first(space: AddressSpaceId, bucket: u8, start: RawAddress) -> Self {
        Self {
            space,
            bucket,
            start,
            id: Id::with_generation(0, 0),
        }
    }
}

impl EntityKeyCodec for CodeBlockSizeBucketKey {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let space = AddressSpaceId::decode(input)?;
        let (&bucket, rest) = input.split_first()?;
        *input = rest;
        Some(Self {
            space,
            bucket,
            start: RawAddress::decode(input)?,
            id: Id::decode(input)?,
        })
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        self.space.encode(output);
        output.extend([self.bucket]);
        self.start.encode(output);
        self.id.encode(output);
    }
}

impl EntityKey for CodeBlockSizeBucketKey {
    const ID: EntityKeyId = ENTITY_KEY_CODE_BLOCK_SIZE_BUCKET_ID;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
struct CodeBlockSizeBucketsKey(AddressSpaceId);

impl EntityKeyCodec for CodeBlockSizeBucketsKey {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        AddressSpaceId::decode(input).map(Self)
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        self.0.encode(output);
    }
}

impl EntityKey for CodeBlockSizeBucketsKey {
    const ID: EntityKeyId = ENTITY_KEY_CODE_BLOCK_SIZE_BUCKETS_ID;
}

#[derive(Debug, Clone, Copy, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct CodeBlockStartRecord;

impl Entity for CodeBlockStartRecord {
    const ID: EntityId = ENTITY_CODE_BLOCK_START_INDEX_ID;
}

#[derive(Debug, Clone, Copy, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct CodeBlockSizeBucketRecord {
    end: RawAddress,
}

impl Entity for CodeBlockSizeBucketRecord {
    const ID: EntityId = ENTITY_CODE_BLOCK_SIZE_BUCKET_INDEX_ID;
}

#[derive(Debug, Clone, Copy, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct CodeBlockSizeBucketsRecord {
    bucket_bits: u64,
    full_width: bool,
}

impl CodeBlockSizeBucketsRecord {
    fn contains(self, bucket: u8) -> bool {
        if bucket == 64 {
            self.full_width
        } else {
            self.bucket_bits & (1u64 << bucket) != 0
        }
    }

    fn is_empty(self) -> bool {
        self.bucket_bits == 0 && !self.full_width
    }

    fn insert(&mut self, bucket: u8) {
        if bucket == 64 {
            self.full_width = true;
        } else {
            self.bucket_bits |= 1u64 << bucket;
        }
    }

    fn remove(&mut self, bucket: u8) {
        if bucket == 64 {
            self.full_width = false;
        } else {
            self.bucket_bits &= !(1u64 << bucket);
        }
    }

    fn buckets(self) -> impl Iterator<Item = u8> {
        (0..=64).filter(move |&bucket| self.contains(bucket))
    }
}

impl Entity for CodeBlockSizeBucketsRecord {
    const ID: EntityId = ENTITY_CODE_BLOCK_SIZE_BUCKETS_INDEX_ID;
}

#[derive(Default)]
struct CodeBlockSizeBucketChange {
    inserted: bool,
    removed: BTreeSet<Id<CodeBlock>>,
}

impl CodeBlockTable {
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
        entries: EntityCache<Id<CodeBlock>, CodeBlock>,
    ) -> Result<Self, EntityStorageError> {
        let allocator =
            match PersistentIdAllocator::load(storage.clone(), PersistentTable::CodeBlocks)? {
                Some(allocator) => allocator,
                None => Self::rebuild_indexes(&storage, &entries)?,
            };
        Ok(Self {
            allocator,
            entries,
            storage,
        })
    }

    pub(crate) fn pending_id(&self, offset: usize) -> Id<CodeBlock> {
        self.allocator
            .pending_id(offset)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub(crate) fn try_get_by_id(
        &self,
        id: Id<CodeBlock>,
    ) -> Result<Option<Ref<'_>>, EntityStorageError> {
        self.entries.try_get(&id)
    }

    pub(crate) fn contains(&self, address: Address) -> bool {
        !self
            .overlap_ids(address)
            .unwrap_or_else(|error| error.into_fatal())
            .is_empty()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = Ref<'_>> + '_ {
        self.entries
            .try_iter()
            .unwrap_or_else(|error| error.into_fatal())
            .map(|entry| entry.unwrap_or_else(|error| error.into_fatal()).1)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.allocator.len() == 0
    }

    pub(crate) fn len(&self) -> usize {
        self.allocator.len()
    }

    fn ids_starting_at(&self, address: Address) -> Result<CodeBlockIds, EntityStorageError> {
        let start = CodeBlockStartKey::first(address.space(), address.raw_address());
        self.storage
            .iter_range::<CodeBlockStartKey, CodeBlockStartRecord>(Bound::Included(&start))?
            .map_while(|entry| match entry {
                Ok((key, _))
                    if key.space == address.space() && key.start == address.raw_address() =>
                {
                    Some(Ok(key.id))
                }
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }

    pub(crate) fn try_get_ids_by_address(
        &self,
        addresses: &[Address],
    ) -> Result<CodeBlockIdsByAddress, EntityStorageError> {
        let mut ids_by_address = CodeBlockIdsByAddress::with_capacity(addresses.len());
        for addresses in addresses.chunk_by(|left, right| left.space() == right.space()) {
            let space = addresses[0].space();
            let first = CodeBlockStartKey::first(space, addresses[0].raw_address());
            let mut records = self
                .storage
                .iter_range::<CodeBlockStartKey, CodeBlockStartRecord>(Bound::Included(&first))?;
            let mut current = records.next().transpose()?;

            for &address in addresses {
                let mut ids = SmallVec::new();
                while current.as_ref().is_some_and(|(key, _)| {
                    key.space == space && key.start <= address.raw_address()
                }) {
                    let (key, _) = current.take().expect("current record must exist");
                    if key.start == address.raw_address() {
                        ids.push(key.id);
                    }
                    current = records.next().transpose()?;
                }
                ids_by_address.push(address, ids);
            }
        }
        Ok(ids_by_address)
    }

    pub(crate) fn get_by_address(&self, address: Address) -> Iter<'_> {
        let ids = self
            .ids_starting_at(address)
            .unwrap_or_else(|error| error.into_fatal());
        Box::new(ids.into_iter().filter_map(move |id| self.entries.get(&id)))
    }

    pub(crate) fn get_by_address_and_context<'a>(
        &'a self,
        address: Address,
        context: &'a ContextSet,
    ) -> Iter<'a> {
        Box::new(
            self.get_by_address(address)
                .filter(move |block| block.context() == context),
        )
    }

    pub(crate) fn overlaps_address(&self, address: Address) -> Iter<'_> {
        let ids = self
            .overlap_ids(address)
            .unwrap_or_else(|error| error.into_fatal());
        Box::new(ids.into_iter().filter_map(move |id| self.entries.get(&id)))
    }

    pub(crate) fn overlaps(&self, range: &AddressRange) -> Iter<'_> {
        let mut ids = self
            .overlap_ids(range.start_address())
            .unwrap_or_else(|error| error.into_fatal());
        let start = CodeBlockStartKey::first(range.space(), range.start());
        let iter = self
            .storage
            .iter_range::<CodeBlockStartKey, CodeBlockStartRecord>(Bound::Excluded(&start))
            .unwrap_or_else(|error| error.into_fatal());
        for entry in iter {
            let (key, _) = entry.unwrap_or_else(|error| error.into_fatal());
            if key.space != range.space() || key.start > range.end() {
                break;
            }
            if key.start > range.start() {
                ids.push(key.id);
            }
        }
        Box::new(ids.into_iter().filter_map(move |id| self.entries.get(&id)))
    }

    pub(crate) fn flush(&self) -> Result<(), EntityStorageError> {
        self.entries.flush()
    }

    pub(crate) fn publish_upsert(&self, block: CodeBlock, encoded_size: usize) {
        self.entries.publish_insert(block.id(), block, encoded_size);
    }

    pub(crate) fn publish_remove(&self, id: Id<CodeBlock>) {
        self.entries.publish_remove(&id);
    }

    pub(crate) fn find_by_range_and_context(
        &self,
        range: AddressRange,
        context: &ContextSet,
        mut predicate: impl FnMut(&CodeBlock) -> bool,
    ) -> Option<Ref<'_>> {
        self.get_by_address(range.start_address()).find(|block| {
            block.address_range() == range && block.context() == context && predicate(block)
        })
    }

    fn overlap_ids(
        &self,
        address: Address,
    ) -> Result<SmallVec<[Id<CodeBlock>; 8]>, EntityStorageError> {
        let Some(buckets) = self
            .storage
            .get::<CodeBlockSizeBucketsKey, CodeBlockSizeBucketsRecord>(
                &CodeBlockSizeBucketsKey(address.space()),
            )?
        else {
            return Ok(SmallVec::new());
        };
        let raw = address.raw_address();
        let mut ids = SmallVec::new();
        for bucket in buckets.buckets() {
            let start = CodeBlockSizeBucketKey::first(
                address.space(),
                bucket,
                Self::bucket_window_start(raw, bucket),
            );
            for entry in self
                .storage
                .iter_range::<CodeBlockSizeBucketKey, CodeBlockSizeBucketRecord>(Bound::Included(
                    &start,
                ))?
            {
                let (key, record) = entry?;
                if key.space != address.space() || key.bucket != bucket || key.start > raw {
                    break;
                }
                if record.end >= raw {
                    ids.push(key.id);
                }
            }
        }
        Ok(ids)
    }

    fn rebuild_indexes(
        storage: &EntityStorage,
        entries: &EntityCache<Id<CodeBlock>, CodeBlock>,
    ) -> Result<PersistentIdAllocator<CodeBlock>, EntityStorageError> {
        let mut buckets = BTreeMap::<AddressSpaceId, CodeBlockSizeBucketsRecord>::new();
        let mut live = 0usize;
        let mut next_index = 0usize;
        let mut writes = EntityWriteBatch::with_capacity(INDEX_REBUILD_BATCH);
        for entry in entries.try_iter()? {
            let (id, block) = entry?;
            let range = block.address_range();
            let bucket = Self::size_bucket(range);
            Self::append_range_insert(&mut writes, id, range, bucket)?;
            buckets.entry(range.space()).or_default().insert(bucket);
            live += 1;
            next_index = next_index.max(id.index() + 1);
            if writes.len() >= INDEX_REBUILD_BATCH {
                storage.apply_batch(&writes)?;
                writes.clear();
            }
        }
        for (space, record) in buckets {
            writes.insert_entity(&CodeBlockSizeBucketsKey(space), &record)?;
        }
        storage.apply_batch(&writes)?;
        PersistentIdAllocator::initialise(
            storage.clone(),
            PersistentTable::CodeBlocks,
            next_index,
            live,
        )
    }

    fn size_bucket(range: AddressRange) -> u8 {
        let size = u128::from(range.end().offset()) - u128::from(range.start().offset()) + 1;
        (u128::BITS - (size - 1).leading_zeros()) as u8
    }

    fn bucket_window_start(address: RawAddress, bucket: u8) -> RawAddress {
        let width = if bucket == 64 {
            u64::MAX
        } else {
            (1u64 << bucket) - 1
        };
        RawAddress::from(address.offset().saturating_sub(width))
    }

    fn append_range_insert(
        writes: &mut EntityWriteBatch,
        id: Id<CodeBlock>,
        range: AddressRange,
        bucket: u8,
    ) -> Result<(), EntityStorageError> {
        writes.insert_entity(
            &CodeBlockStartKey {
                space: range.space(),
                start: range.start(),
                id,
            },
            &CodeBlockStartRecord,
        )?;
        writes.insert_entity(
            &CodeBlockSizeBucketKey {
                space: range.space(),
                bucket,
                start: range.start(),
                id,
            },
            &CodeBlockSizeBucketRecord { end: range.end() },
        )
    }

    fn append_range_remove(writes: &mut EntityWriteBatch, id: Id<CodeBlock>, range: AddressRange) {
        writes.remove_entity::<_, CodeBlockStartRecord>(&CodeBlockStartKey {
            space: range.space(),
            start: range.start(),
            id,
        });
        writes.remove_entity::<_, CodeBlockSizeBucketRecord>(&CodeBlockSizeBucketKey {
            space: range.space(),
            bucket: Self::size_bucket(range),
            start: range.start(),
            id,
        });
    }

    pub(crate) fn append_prepared_writes(
        &self,
        entries: &[PreparedCodeBlockRecord],
        reservations: &[Id<CodeBlock>],
        cancelled: &BTreeSet<Id<CodeBlock>>,
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        let mut bucket_changes = BTreeMap::<(AddressSpaceId, u8), CodeBlockSizeBucketChange>::new();
        let mut added = 0usize;
        let mut removed = 0usize;
        let mut releases = cancelled.iter().copied().collect::<SmallVec<[_; 8]>>();
        for entry in entries {
            if let Some(previous) = entry.previous {
                Self::append_range_remove(writes, entry.id, previous);
                bucket_changes
                    .entry((previous.space(), Self::size_bucket(previous)))
                    .or_default()
                    .removed
                    .insert(entry.id);
            }
            match entry.block.as_ref() {
                Some(block) => {
                    let range = block.address_range();
                    let bucket = Self::size_bucket(range);
                    Self::append_range_insert(writes, entry.id, range, bucket)?;
                    bucket_changes
                        .entry((range.space(), bucket))
                        .or_default()
                        .inserted = true;
                    if entry.previous.is_none() {
                        added += 1;
                    }
                }
                None => {
                    removed += 1;
                    releases.push(entry.id);
                }
            }
        }
        self.append_size_bucket_changes(bucket_changes, writes)?;
        self.allocator
            .append_transition(reservations, &releases, added, removed, writes)
    }

    fn append_size_bucket_changes(
        &self,
        changes: BTreeMap<(AddressSpaceId, u8), CodeBlockSizeBucketChange>,
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        let mut records = BTreeMap::<AddressSpaceId, CodeBlockSizeBucketsRecord>::new();
        for ((space, bucket), change) in changes {
            let occupied =
                change.inserted || self.size_bucket_has_other(space, bucket, &change.removed)?;
            let record = match records.entry(space) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    let record = self
                        .storage
                        .get::<CodeBlockSizeBucketsKey, CodeBlockSizeBucketsRecord>(
                            &CodeBlockSizeBucketsKey(space),
                        )?
                        .unwrap_or_default();
                    entry.insert(record)
                }
            };
            if occupied {
                record.insert(bucket);
            } else {
                record.remove(bucket);
            }
        }
        for (space, record) in records {
            if record.is_empty() {
                writes.remove_entity::<_, CodeBlockSizeBucketsRecord>(&CodeBlockSizeBucketsKey(
                    space,
                ));
            } else {
                writes.insert_entity(&CodeBlockSizeBucketsKey(space), &record)?;
            }
        }
        Ok(())
    }

    fn size_bucket_has_other(
        &self,
        space: AddressSpaceId,
        bucket: u8,
        removed: &BTreeSet<Id<CodeBlock>>,
    ) -> Result<bool, EntityStorageError> {
        for entry in self
            .storage
            .iter_range::<CodeBlockSizeBucketKey, CodeBlockSizeBucketRecord>(Bound::Included(
                &CodeBlockSizeBucketKey::first(space, bucket, RawAddress::from(0u64)),
            ))?
        {
            let (key, _) = entry?;
            if key.space != space || key.bucket != bucket {
                break;
            }
            if !removed.contains(&key.id) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn publish_transition(
        &mut self,
        reservations: &[Id<CodeBlock>],
        added: usize,
        removed: usize,
    ) {
        self.allocator
            .publish_transition(reservations, added, removed);
    }
}
