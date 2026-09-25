use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::num::NonZeroU16;
use std::ops::Bound;
use std::sync::Arc;

use smallvec::SmallVec;

use super::{CodeBlockIds, CodeBlockIdsByAddress};
use crate::ir::persistent::{PersistentIdAllocator, PersistentIndexRebuilder, PersistentTable};
use crate::ir::{Address, AddressRange, CodeBlock, Id, IdSet, PreparedCodeBlockRecord, RawAddress};
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

type Ref<'a> = CachedRef<'a, CodeBlock>;
type Iter<'a> = Box<dyn Iterator<Item = Ref<'a>> + 'a>;

pub struct CodeBlockTable {
    allocator: PersistentIdAllocator<CodeBlock>,
    entries: EntityCache<Id<CodeBlock>, CodeBlock>,
    storage: EntityStorage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
struct CodeBlockSizeBucket(u8);

impl CodeBlockSizeBucket {
    const MAX: Self = Self(u16::BITS as u8);

    fn new(range: AddressRange) -> Self {
        let size = u16::try_from(range.size())
            .ok()
            .and_then(NonZeroU16::new)
            .expect("code block size must fit in u16");
        Self(
            (u16::BITS - (size.get() - 1).leading_zeros())
                .try_into()
                .expect("code block size bucket must fit in u8"),
        )
    }

    fn overlap_search_start(self, address: RawAddress) -> RawAddress {
        let width = (1u32 << self.0) - 1;
        address.checked_sub(width).unwrap_or_else(RawAddress::zero)
    }

    fn all() -> impl Iterator<Item = Self> {
        (0..=Self::MAX.0).map(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CodeBlockStartKey {
    address: Address,
    id: Id<CodeBlock>,
}

impl CodeBlockStartKey {
    fn new(address: Address, id: Id<CodeBlock>) -> Self {
        Self { address, id }
    }
}

impl EntityKeyCodec for CodeBlockStartKey {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let space = AddressSpaceId::decode(input)?;
        let address = Address::new(space, RawAddress::decode(input)?);
        Some(Self::new(address, Id::decode(input)?))
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        self.address.space().encode(output);
        self.address.raw_address().encode(output);
        self.id.encode(output);
    }
}

impl EntityKey for CodeBlockStartKey {
    const ID: EntityKeyId = ENTITY_KEY_CODE_BLOCK_START_ID;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CodeBlockSizeBucketKey {
    address: Address,
    id: Id<CodeBlock>,
    bucket: CodeBlockSizeBucket,
}

impl CodeBlockSizeBucketKey {
    fn new(address: Address, id: Id<CodeBlock>, bucket: CodeBlockSizeBucket) -> Self {
        Self {
            address,
            id,
            bucket,
        }
    }
}

impl EntityKeyCodec for CodeBlockSizeBucketKey {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let space = AddressSpaceId::decode(input)?;
        let (&bucket, rest) = input.split_first()?;
        *input = rest;
        let address = Address::new(space, RawAddress::decode(input)?);
        let id = Id::decode(input)?;
        Some(Self::new(address, id, CodeBlockSizeBucket(bucket)))
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        self.address.space().encode(output);
        output.extend([self.bucket.0]);
        self.address.raw_address().encode(output);
        self.id.encode(output);
    }
}

impl EntityKey for CodeBlockSizeBucketKey {
    const ID: EntityKeyId = ENTITY_KEY_CODE_BLOCK_SIZE_BUCKET_ID;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
struct CodeBlockSizeBucketsKey(AddressSpaceId);

impl CodeBlockSizeBucketsKey {
    fn new(space: AddressSpaceId) -> Self {
        Self(space)
    }
}

impl EntityKeyCodec for CodeBlockSizeBucketsKey {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        AddressSpaceId::decode(input).map(Self::new)
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
    bucket_bits: u32,
}

impl CodeBlockSizeBucketsRecord {
    fn contains(self, bucket: CodeBlockSizeBucket) -> bool {
        self.bucket_bits & (1u32 << bucket.0) != 0
    }

    fn is_empty(self) -> bool {
        self.bucket_bits == 0
    }

    fn insert(&mut self, bucket: CodeBlockSizeBucket) {
        self.bucket_bits |= 1u32 << bucket.0;
    }

    fn remove(&mut self, bucket: CodeBlockSizeBucket) {
        self.bucket_bits &= !(1u32 << bucket.0);
    }

    fn buckets(self) -> impl Iterator<Item = CodeBlockSizeBucket> {
        CodeBlockSizeBucket::all().filter(move |&bucket| self.contains(bucket))
    }
}

impl Entity for CodeBlockSizeBucketsRecord {
    const ID: EntityId = ENTITY_CODE_BLOCK_SIZE_BUCKETS_INDEX_ID;
}

#[derive(Default)]
struct CodeBlockSizeBucketChange {
    inserted: bool,
    removed: IdSet<CodeBlock>,
}

fn append_range_insert(
    writes: &mut EntityWriteBatch,
    id: Id<CodeBlock>,
    range: AddressRange,
    bucket: CodeBlockSizeBucket,
) -> Result<(), EntityStorageError> {
    writes.insert_entity(
        &CodeBlockStartKey::new(range.start_address(), id),
        &CodeBlockStartRecord,
    )?;
    writes.insert_entity(
        &CodeBlockSizeBucketKey::new(range.start_address(), id, bucket),
        &CodeBlockSizeBucketRecord { end: range.end() },
    )
}

fn append_range_remove(writes: &mut EntityWriteBatch, id: Id<CodeBlock>, range: AddressRange) {
    writes.remove_entity::<_, CodeBlockStartRecord>(&CodeBlockStartKey::new(
        range.start_address(),
        id,
    ));
    writes.remove_entity::<_, CodeBlockSizeBucketRecord>(&CodeBlockSizeBucketKey::new(
        range.start_address(),
        id,
        CodeBlockSizeBucket::new(range),
    ));
}

fn rebuild_indexes(
    storage: &EntityStorage,
    entries: &EntityCache<Id<CodeBlock>, CodeBlock>,
) -> Result<PersistentIdAllocator<CodeBlock>, EntityStorageError> {
    let mut buckets = BTreeMap::<AddressSpaceId, CodeBlockSizeBucketsRecord>::new();
    let mut rebuilder = PersistentIndexRebuilder::new(storage, PersistentTable::CodeBlocks);
    for entry in entries.try_iter()? {
        let (id, block) = entry?;
        let range = block.address_range();
        let bucket = CodeBlockSizeBucket::new(range);
        rebuilder.append(id, |writes| append_range_insert(writes, id, range, bucket))?;
        buckets.entry(range.space()).or_default().insert(bucket);
    }
    rebuilder.finish(|writes| {
        for (space, record) in buckets {
            writes.insert_entity(&CodeBlockSizeBucketsKey::new(space), &record)?;
        }
        Ok(())
    })
}

impl CodeBlockTable {
    pub(crate) fn new(
        storage: EntityStorage,
        cache_bytes: usize,
        worker: Arc<WriteBackWorker>,
    ) -> Result<Self, EntityStorageError> {
        let entries = EntityCache::new(storage.clone(), cache_bytes, worker);
        Self::new_with(storage, entries)
    }

    fn new_with(
        storage: EntityStorage,
        entries: EntityCache<Id<CodeBlock>, CodeBlock>,
    ) -> Result<Self, EntityStorageError> {
        let allocator =
            match PersistentIdAllocator::load(storage.clone(), PersistentTable::CodeBlocks)? {
                Some(allocator) => allocator,
                None => rebuild_indexes(&storage, &entries)?,
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
        let start = CodeBlockStartKey::new(address, Id::with_generation(0, 0));
        self.storage
            .iter_range::<CodeBlockStartKey, CodeBlockStartRecord>(Bound::Included(&start))?
            .map_while(|entry| match entry {
                Ok((key, _)) if key.address == address => Some(Ok(key.id)),
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
            let first = CodeBlockStartKey::new(addresses[0], Id::with_generation(0, 0));
            let mut records = self
                .storage
                .iter_range::<CodeBlockStartKey, CodeBlockStartRecord>(Bound::Included(&first))?;
            let mut current = records.next().transpose()?;

            for &address in addresses {
                let mut ids = SmallVec::new();
                while current
                    .as_ref()
                    .is_some_and(|(key, _)| key.address.space() == space && key.address <= address)
                {
                    let (key, _) = current.take().expect("current record must exist");
                    if key.address == address {
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
        let start = CodeBlockStartKey::new(range.start_address(), Id::with_generation(0, 0));
        let iter = self
            .storage
            .iter_range::<CodeBlockStartKey, CodeBlockStartRecord>(Bound::Excluded(&start))
            .unwrap_or_else(|error| error.into_fatal());
        for entry in iter {
            let (key, _) = entry.unwrap_or_else(|error| error.into_fatal());
            if key.address.space() != range.space() || key.address > range.end_address() {
                break;
            }
            if key.address > range.start_address() {
                ids.push(key.id);
            }
        }
        Box::new(ids.into_iter().filter_map(move |id| self.entries.get(&id)))
    }

    pub(crate) fn flush(&self) -> Result<(), EntityStorageError> {
        self.entries.flush()
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
                &CodeBlockSizeBucketsKey::new(address.space()),
            )?
        else {
            return Ok(SmallVec::new());
        };
        let raw = address.raw_address();
        let mut ids = SmallVec::new();
        for bucket in buckets.buckets() {
            let start = CodeBlockSizeBucketKey::new(
                Address::new(address.space(), bucket.overlap_search_start(raw)),
                Id::with_generation(0, 0),
                bucket,
            );
            for entry in self
                .storage
                .iter_range::<CodeBlockSizeBucketKey, CodeBlockSizeBucketRecord>(Bound::Included(
                    &start,
                ))?
            {
                let (key, record) = entry?;
                if key.address.space() != address.space()
                    || key.bucket != bucket
                    || key.address > address
                {
                    break;
                }
                if record.end >= raw {
                    ids.push(key.id);
                }
            }
        }
        Ok(ids)
    }

    pub(crate) fn append_prepared_writes(
        &self,
        entries: &[PreparedCodeBlockRecord],
        reservations: &[Id<CodeBlock>],
        cancelled: &IdSet<CodeBlock>,
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        let mut bucket_changes =
            BTreeMap::<(AddressSpaceId, CodeBlockSizeBucket), CodeBlockSizeBucketChange>::new();
        let mut added = 0usize;
        let mut removed = 0usize;
        let mut releases = cancelled.iter().collect::<SmallVec<[_; 8]>>();
        for entry in entries {
            if let Some(previous) = entry.previous {
                append_range_remove(writes, entry.id, previous);
                bucket_changes
                    .entry((previous.space(), CodeBlockSizeBucket::new(previous)))
                    .or_default()
                    .removed
                    .insert(entry.id);
            }
            match entry.block.as_ref() {
                Some(block) => {
                    let range = block.address_range();
                    let bucket = CodeBlockSizeBucket::new(range);
                    append_range_insert(writes, entry.id, range, bucket)?;
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
        releases.sort_unstable();
        self.append_bucket_writes(bucket_changes, writes)?;
        self.allocator
            .append_transition(reservations, &releases, added, removed, writes)
    }

    fn append_bucket_writes(
        &self,
        changes: BTreeMap<(AddressSpaceId, CodeBlockSizeBucket), CodeBlockSizeBucketChange>,
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        let mut records = BTreeMap::<AddressSpaceId, CodeBlockSizeBucketsRecord>::new();
        for ((space, bucket), change) in changes {
            let occupied = change.inserted
                || self.bucket_has_remaining_block(space, bucket, &change.removed)?;
            let record = match records.entry(space) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    let record = self
                        .storage
                        .get::<CodeBlockSizeBucketsKey, CodeBlockSizeBucketsRecord>(
                            &CodeBlockSizeBucketsKey::new(space),
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
                writes.remove_entity::<_, CodeBlockSizeBucketsRecord>(
                    &CodeBlockSizeBucketsKey::new(space),
                );
            } else {
                writes.insert_entity(&CodeBlockSizeBucketsKey::new(space), &record)?;
            }
        }
        Ok(())
    }

    fn bucket_has_remaining_block(
        &self,
        space: AddressSpaceId,
        bucket: CodeBlockSizeBucket,
        removed: &IdSet<CodeBlock>,
    ) -> Result<bool, EntityStorageError> {
        for entry in self
            .storage
            .iter_range::<CodeBlockSizeBucketKey, CodeBlockSizeBucketRecord>(Bound::Included(
                &CodeBlockSizeBucketKey::new(
                    Address::new(space, RawAddress::zero()),
                    Id::with_generation(0, 0),
                    bucket,
                ),
            ))?
        {
            let (key, _) = entry?;
            if key.address.space() != space || key.bucket != bucket {
                break;
            }
            if !removed.contains(key.id) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn publish_upsert(&self, block: CodeBlock, encoded_size: usize) {
        self.entries.publish_insert(block.id(), block, encoded_size);
    }

    pub(crate) fn publish_remove(&self, id: Id<CodeBlock>) {
        self.entries.publish_remove(&id);
    }

    pub(crate) fn publish_allocations(
        &mut self,
        reservations: &[Id<CodeBlock>],
        added: usize,
        removed: usize,
    ) {
        self.allocator
            .publish_transition(reservations, added, removed);
    }
}
