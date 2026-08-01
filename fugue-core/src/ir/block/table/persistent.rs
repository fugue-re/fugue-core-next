use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::Arc;

use bytes::Bytes;
use smallvec::SmallVec;

use super::{
    CodeBlockIds, CodeBlockIdsByStart, CodeBlockTableError, PersistentCodeBlockTable,
};
use crate::ir::persistent::{PersistentIdAllocator, PersistentTable, append_insert, append_remove};
use crate::ir::{Address, AddressRange, CodeBlock, Id, PreparedBlockMutation, RawAddress};
use crate::lifter::ContextSet;
use crate::storage::entities::schema::{
    ENTITY_BLOCK_CLASSES_INDEX_ID, ENTITY_BLOCK_LENGTH_INDEX_ID, ENTITY_BLOCK_START_INDEX_ID,
    ENTITY_KEY_BLOCK_CLASSES_ID, ENTITY_KEY_BLOCK_LENGTH_ID, ENTITY_KEY_BLOCK_START_ID,
};
use crate::storage::entities::{
    CachedMut, CachedRef, Entity, EntityCache, EntityId, EntityKey, EntityKeyId, EntityStorage,
    EntityStorageError, EntityWrite, EntityWriteBatch, WriteBackWorker, schema,
};
use crate::storage::segments::space::AddressSpaceId;

const INDEX_REBUILD_BATCH: usize = 512;

type Ref<'a> = CachedRef<'a, CodeBlock>;
type RefMut<'a> = CachedMut<'a, CodeBlock>;
type Iter<'a> = Box<dyn Iterator<Item = Ref<'a>> + 'a>;
type IterMut<'a> = Box<dyn Iterator<Item = RefMut<'a>> + 'a>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct BlockStartKey {
    space: AddressSpaceId,
    start: RawAddress,
    id: Id<CodeBlock>,
}

impl BlockStartKey {
    fn first(space: AddressSpaceId, start: RawAddress) -> Self {
        Self {
            space,
            start,
            id: Id::with_generation(0, 0),
        }
    }
}

impl EntityKey for BlockStartKey {
    const ID: EntityKeyId = ENTITY_KEY_BLOCK_START_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        const SPACE_SIZE: usize = size_of::<AddressSpaceId>();
        const ADDRESS_SIZE: usize = size_of::<RawAddress>();
        if buf.len() != SPACE_SIZE + ADDRESS_SIZE + size_of::<u64>() {
            return None;
        }
        Some(Self {
            space: AddressSpaceId::from(u16::from_be_bytes(buf[..SPACE_SIZE].try_into().ok()?)),
            start: RawAddress::from(u64::from_be_bytes(
                buf[SPACE_SIZE..SPACE_SIZE + ADDRESS_SIZE].try_into().ok()?,
            )),
            id: Id::decode_as_key(&buf[SPACE_SIZE + ADDRESS_SIZE..])?,
        })
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        output.extend((self.space.index() as u16).to_be_bytes());
        output.extend(self.start.offset().to_be_bytes());
        self.id.encode(output);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct BlockLengthKey {
    space: AddressSpaceId,
    class: u8,
    start: RawAddress,
    id: Id<CodeBlock>,
}

impl BlockLengthKey {
    fn first(space: AddressSpaceId, class: u8, start: RawAddress) -> Self {
        Self {
            space,
            class,
            start,
            id: Id::with_generation(0, 0),
        }
    }
}

impl EntityKey for BlockLengthKey {
    const ID: EntityKeyId = ENTITY_KEY_BLOCK_LENGTH_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        const SPACE_SIZE: usize = size_of::<AddressSpaceId>();
        const ADDRESS_SIZE: usize = size_of::<RawAddress>();
        if buf.len() != SPACE_SIZE + 1 + ADDRESS_SIZE + size_of::<u64>() {
            return None;
        }
        Some(Self {
            space: AddressSpaceId::from(u16::from_be_bytes(buf[..SPACE_SIZE].try_into().ok()?)),
            class: buf[SPACE_SIZE],
            start: RawAddress::from(u64::from_be_bytes(
                buf[SPACE_SIZE + 1..SPACE_SIZE + 1 + ADDRESS_SIZE]
                    .try_into()
                    .ok()?,
            )),
            id: Id::decode_as_key(&buf[SPACE_SIZE + 1 + ADDRESS_SIZE..])?,
        })
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        output.extend((self.space.index() as u16).to_be_bytes());
        output.extend([self.class]);
        output.extend(self.start.offset().to_be_bytes());
        self.id.encode(output);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
struct BlockClassesKey(AddressSpaceId);

impl EntityKey for BlockClassesKey {
    const ID: EntityKeyId = ENTITY_KEY_BLOCK_CLASSES_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        Some(Self(AddressSpaceId::from(u16::from_be_bytes(
            buf.try_into().ok()?,
        ))))
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        output.extend((self.0.index() as u16).to_be_bytes());
    }
}

#[derive(Debug, Clone, Copy, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct BlockRangeRecord {
    end: RawAddress,
}

impl Entity for BlockRangeRecord {
    const ID: EntityId = ENTITY_BLOCK_START_INDEX_ID;
}

#[derive(Debug, Clone, Copy, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct BlockLengthRecord {
    end: RawAddress,
}

impl Entity for BlockLengthRecord {
    const ID: EntityId = ENTITY_BLOCK_LENGTH_INDEX_ID;
}

#[derive(Debug, Clone, Copy, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct BlockClassesRecord {
    classes: u64,
    widest: bool,
}

impl BlockClassesRecord {
    fn contains(self, class: u8) -> bool {
        if class == 64 {
            self.widest
        } else {
            self.classes & (1u64 << class) != 0
        }
    }

    fn insert(&mut self, class: u8) {
        if class == 64 {
            self.widest = true;
        } else {
            self.classes |= 1u64 << class;
        }
    }

    fn remove(&mut self, class: u8) {
        if class == 64 {
            self.widest = false;
        } else {
            self.classes &= !(1u64 << class);
        }
    }

    fn classes(self) -> impl Iterator<Item = u8> {
        (0..=64).filter(move |&class| self.contains(class))
    }

    fn is_empty(self) -> bool {
        self.classes == 0 && !self.widest
    }
}

impl Entity for BlockClassesRecord {
    const ID: EntityId = ENTITY_BLOCK_CLASSES_INDEX_ID;
}

impl PersistentCodeBlockTable {
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

    fn rebuild_indexes(
        storage: &EntityStorage,
        entries: &EntityCache<Id<CodeBlock>, CodeBlock>,
    ) -> Result<PersistentIdAllocator<CodeBlock>, EntityStorageError> {
        let mut classes = BTreeMap::<AddressSpaceId, BlockClassesRecord>::new();
        let mut live = 0usize;
        let mut next_index = 0usize;
        let mut writes = EntityWriteBatch::with_capacity(INDEX_REBUILD_BATCH);
        for entry in entries.try_iter()? {
            let (id, block) = entry?;
            let range = block.address_range();
            let class = Self::length_class(range);
            Self::append_range_insert(&mut writes, id, range, class)?;
            classes.entry(range.space()).or_default().insert(class);
            live += 1;
            next_index = next_index.max(id.index() + 1);
            if writes.len() >= INDEX_REBUILD_BATCH {
                storage.apply_batch(&writes)?;
                writes.clear();
            }
        }
        for (space, record) in classes {
            append_insert(&mut writes, &BlockClassesKey(space), &record)?;
        }
        storage.apply_batch(&writes)?;
        PersistentIdAllocator::initialise(
            storage.clone(),
            PersistentTable::CodeBlocks,
            next_index,
            live,
        )
    }

    fn length_class(range: AddressRange) -> u8 {
        let length = u128::from(range.end().offset()) - u128::from(range.start().offset()) + 1;
        (u128::BITS - (length - 1).leading_zeros()) as u8
    }

    fn class_window_start(address: RawAddress, class: u8) -> RawAddress {
        let width = if class == 64 {
            u64::MAX
        } else {
            (1u64 << class) - 1
        };
        RawAddress::from(address.offset().saturating_sub(width))
    }

    fn append_range_insert(
        writes: &mut EntityWriteBatch,
        id: Id<CodeBlock>,
        range: AddressRange,
        class: u8,
    ) -> Result<(), EntityStorageError> {
        append_insert(
            writes,
            &BlockStartKey {
                space: range.space(),
                start: range.start(),
                id,
            },
            &BlockRangeRecord { end: range.end() },
        )?;
        append_insert(
            writes,
            &BlockLengthKey {
                space: range.space(),
                class,
                start: range.start(),
                id,
            },
            &BlockLengthRecord { end: range.end() },
        )
    }

    fn append_range_remove(writes: &mut EntityWriteBatch, id: Id<CodeBlock>, range: AddressRange) {
        append_remove::<_, BlockRangeRecord>(
            writes,
            &BlockStartKey {
                space: range.space(),
                start: range.start(),
                id,
            },
        );
        append_remove::<_, BlockLengthRecord>(
            writes,
            &BlockLengthKey {
                space: range.space(),
                class: Self::length_class(range),
                start: range.start(),
                id,
            },
        );
    }

    pub(crate) fn flush(&self) -> Result<(), EntityStorageError> {
        self.entries.flush()
    }

    pub(crate) fn append_stage_writes(
        &self,
        entries: &[PreparedBlockMutation],
        reservations: &[Id<CodeBlock>],
        cancelled: &BTreeSet<Id<CodeBlock>>,
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        let mut class_changes = BTreeMap::<(AddressSpaceId, u8), ClassChange>::new();
        let mut added = 0usize;
        let mut removed = 0usize;
        let mut releases = cancelled.iter().copied().collect::<SmallVec<[_; 8]>>();
        for entry in entries {
            if let Some(previous) = entry.previous() {
                Self::append_range_remove(writes, entry.id(), previous);
                class_changes
                    .entry((previous.space(), Self::length_class(previous)))
                    .or_default()
                    .removed
                    .insert(entry.id());
            }
            match entry.block() {
                Some(block) => {
                    let range = block.address_range();
                    let class = Self::length_class(range);
                    Self::append_range_insert(writes, entry.id(), range, class)?;
                    class_changes
                        .entry((range.space(), class))
                        .or_default()
                        .inserted = true;
                    if entry.previous().is_none() {
                        added += 1;
                    }
                }
                None => {
                    removed += 1;
                    releases.push(entry.id());
                }
            }
        }
        self.append_class_changes(class_changes, writes)?;
        self.allocator
            .append_transition(reservations, &releases, added, removed, writes)
    }

    fn append_class_changes(
        &self,
        changes: BTreeMap<(AddressSpaceId, u8), ClassChange>,
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        let mut records = BTreeMap::<AddressSpaceId, BlockClassesRecord>::new();
        for ((space, class), change) in changes {
            let occupied =
                change.inserted || self.class_has_other(space, class, &change.removed)?;
            let record = match records.entry(space) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    let record = self
                        .storage
                        .get::<BlockClassesKey, BlockClassesRecord>(&BlockClassesKey(space))?
                        .unwrap_or_default();
                    entry.insert(record)
                }
            };
            if occupied {
                record.insert(class);
            } else {
                record.remove(class);
            }
        }
        for (space, record) in records {
            if record.is_empty() {
                append_remove::<_, BlockClassesRecord>(writes, &BlockClassesKey(space));
            } else {
                append_insert(writes, &BlockClassesKey(space), &record)?;
            }
        }
        Ok(())
    }

    fn class_has_other(
        &self,
        space: AddressSpaceId,
        class: u8,
        removed: &BTreeSet<Id<CodeBlock>>,
    ) -> Result<bool, EntityStorageError> {
        for entry in self
            .storage
            .iter_range::<BlockLengthKey, BlockLengthRecord>(Bound::Included(
                &BlockLengthKey::first(space, class, RawAddress::from(0u64)),
            ))?
        {
            let (key, _) = entry?;
            if key.space != space || key.class != class {
                break;
            }
            if !removed.contains(&key.id) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn publish_transition(
        &mut self,
        reservations: &[Id<CodeBlock>],
        added: usize,
        removed: usize,
    ) {
        self.allocator
            .publish_transition(reservations, added, removed);
    }

    pub(super) fn publish_upsert(&self, block: CodeBlock, encoded_len: usize) {
        self.entries.publish_put(block.id(), block, encoded_len);
    }

    pub(super) fn publish_remove(&self, id: Id<CodeBlock>) {
        self.entries.publish_remove(&id);
    }

    pub(crate) fn insert<F>(
        &mut self,
        address: Address,
        f: F,
    ) -> Result<Id<CodeBlock>, CodeBlockTableError>
    where
        F: FnOnce(Id<CodeBlock>, Address) -> Result<CodeBlock, CodeBlockTableError>,
    {
        let id = self
            .allocator
            .preview_id(0)
            .unwrap_or_else(|error| error.into_fatal());
        let block = f(id, address)?;
        if block.start() != address {
            return Err(CodeBlockTableError::AddressMismatch);
        }
        let range = block.address_range();
        let class = Self::length_class(range);
        let encoded =
            rkyv::to_bytes::<rkyv::rancor::Error>(&block).map_err(EntityStorageError::encode)?;
        let encoded_len = encoded.len();
        let mut writes = EntityWriteBatch::new();
        writes.push(EntityWrite::insert_archive(
            schema::make_key::<Id<CodeBlock>, CodeBlock>(&id),
            encoded,
        ));
        Self::append_range_insert(&mut writes, id, range, class)?;
        let mut record = self
            .storage
            .get::<BlockClassesKey, BlockClassesRecord>(&BlockClassesKey(range.space()))?
            .unwrap_or_default();
        record.insert(class);
        append_insert(&mut writes, &BlockClassesKey(range.space()), &record)?;
        self.allocator
            .append_transition(&[id], &[], 1, 0, &mut writes)?;
        self.entries.flush()?;
        self.storage.apply_batch(&writes)?;
        self.entries.publish_put(id, block, encoded_len);
        self.allocator.publish_transition(&[id], 1, 0);
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
        let range = block.address_range();
        drop(block);
        let class = Self::length_class(range);
        let mut writes = EntityWriteBatch::new();
        append_remove::<_, CodeBlock>(&mut writes, &id);
        Self::append_range_remove(&mut writes, id, range);
        let change = ClassChange {
            inserted: false,
            removed: BTreeSet::from([id]),
        };
        self.append_class_changes(
            BTreeMap::from([((range.space(), class), change)]),
            &mut writes,
        )?;
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
    ) -> Result<usize, EntityStorageError> {
        let ids = self.ids_starting_at(address)?;
        let count = ids.len();
        for id in ids {
            self.try_remove_by_id(id)?;
        }
        Ok(count)
    }

    pub(crate) fn try_remove_by_address_and_context(
        &mut self,
        address: Address,
        context: &ContextSet,
    ) -> Result<usize, EntityStorageError> {
        let mut matching = SmallVec::<[Id<CodeBlock>; 2]>::new();
        for id in self.ids_starting_at(address)? {
            if self
                .entries
                .try_get(&id)?
                .is_some_and(|block| block.context() == context)
            {
                matching.push(id);
            }
        }
        let count = matching.len();
        for id in matching {
            self.try_remove_by_id(id)?;
        }
        Ok(count)
    }

    fn ids_starting_at(&self, address: Address) -> Result<CodeBlockIds, EntityStorageError> {
        let start = BlockStartKey::first(address.space(), address.raw_address());
        self.storage
            .iter_range::<BlockStartKey, BlockRangeRecord>(Bound::Included(&start))?
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

    pub(super) fn ids_at_starts(
        &self,
        starts: &[Address],
    ) -> Result<CodeBlockIdsByStart, EntityStorageError> {
        let mut locations = Vec::with_capacity(starts.len());
        for starts in starts.chunk_by(|left, right| left.space() == right.space()) {
            let space = starts[0].space();
            let first = BlockStartKey::first(space, starts[0].raw_address());
            let mut records = self
                .storage
                .iter_range::<BlockStartKey, BlockRangeRecord>(Bound::Included(&first))?;
            let mut current = records.next().transpose()?;

            for &address in starts {
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
                locations.push((address, ids));
            }
        }
        Ok(locations)
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

    pub(super) fn find_by_range_and_context(
        &self,
        range: AddressRange,
        context: &ContextSet,
        mut predicate: impl FnMut(&CodeBlock) -> bool,
    ) -> Option<Ref<'_>> {
        self.get_by_address(range.start_address()).find(|block| {
            block.address_range() == range && block.context() == context && predicate(block)
        })
    }

    pub(crate) fn contains(&self, address: Address) -> bool {
        !self
            .overlap_ids(address)
            .unwrap_or_else(|error| error.into_fatal())
            .is_empty()
    }

    fn overlap_ids(
        &self,
        address: Address,
    ) -> Result<SmallVec<[Id<CodeBlock>; 8]>, EntityStorageError> {
        let Some(classes) = self
            .storage
            .get::<BlockClassesKey, BlockClassesRecord>(&BlockClassesKey(address.space()))?
        else {
            return Ok(SmallVec::new());
        };
        let raw = address.raw_address();
        let mut ids = SmallVec::new();
        for class in classes.classes() {
            let start =
                BlockLengthKey::first(address.space(), class, Self::class_window_start(raw, class));
            for entry in self
                .storage
                .iter_range::<BlockLengthKey, BlockLengthRecord>(Bound::Included(&start))?
            {
                let (key, record) = entry?;
                if key.space != address.space() || key.class != class || key.start > raw {
                    break;
                }
                if record.end >= raw {
                    ids.push(key.id);
                }
            }
        }
        Ok(ids)
    }

    pub(crate) fn overlaps(&self, address: Address) -> Iter<'_> {
        let ids = self
            .overlap_ids(address)
            .unwrap_or_else(|error| error.into_fatal());
        Box::new(ids.into_iter().filter_map(move |id| self.entries.get(&id)))
    }

    pub(crate) fn overlaps_range(&self, range: &AddressRange) -> Iter<'_> {
        let mut ids = self
            .overlap_ids(range.start_address())
            .unwrap_or_else(|error| error.into_fatal());
        let start = BlockStartKey::first(range.space(), range.start());
        let iter = self
            .storage
            .iter_range::<BlockStartKey, BlockRangeRecord>(Bound::Excluded(&start))
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

    pub(crate) fn get_by_address_mut(&mut self, address: Address) -> IterMut<'_> {
        let ids = self
            .ids_starting_at(address)
            .unwrap_or_else(|error| error.into_fatal());
        Box::new(self.entries.iter_disjoint_mut(ids))
    }

    pub(crate) fn get_by_address_and_context_mut<'a>(
        &'a mut self,
        address: Address,
        context: &'a ContextSet,
    ) -> IterMut<'a> {
        let ids = self
            .ids_starting_at(address)
            .unwrap_or_else(|error| error.into_fatal())
            .into_iter()
            .filter(|id| {
                self.entries
                    .get(id)
                    .is_some_and(|block| block.context() == context)
            })
            .collect::<SmallVec<[_; 2]>>();
        Box::new(self.entries.iter_disjoint_mut(ids))
    }

    pub(crate) fn overlaps_mut(&mut self, address: Address) -> IterMut<'_> {
        let ids = self
            .overlap_ids(address)
            .unwrap_or_else(|error| error.into_fatal());
        Box::new(self.entries.iter_disjoint_mut(ids))
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = Ref<'_>> + '_ {
        self.entries
            .try_iter()
            .unwrap_or_else(|error| error.into_fatal())
            .map(|entry| entry.unwrap_or_else(|error| error.into_fatal()).1)
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

#[derive(Default)]
struct ClassChange {
    inserted: bool,
    removed: BTreeSet<Id<CodeBlock>>,
}
