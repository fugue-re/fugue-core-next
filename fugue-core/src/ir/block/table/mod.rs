use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use iset::IntervalMap;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::ir::{
    Address, AddressRange, AddressRangeSet, CodeBlock, CodeBlockId, Id, IdAllocator, IdSet,
    RawAddress,
};
use crate::lifter::ContextSet;
use crate::storage::entities::schema::ENTITY_CODE_BLOCK_TABLE_ID;
use crate::storage::entities::{Entity, EntityId, EntityRef, ProjectEntity, WriteBackWorker};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::{EntityStorage, EntityStorageError};

pub(crate) const ATTRIBUTE_CODE_BLOCK_CACHE_SIZE: &str = "storage.entities.code_block.cache_size";
pub(crate) const DEFAULT_CODE_BLOCK_CACHE_BYTES: usize = 8 * 1024 * 1024;

mod persistent;
use persistent::CodeBlockTable as PersistentCodeBlockTable;

mod transient;
use transient::CodeBlockTable as TransientCodeBlockTable;

const CODE_BLOCK_TABLE_VERSION: u32 = 1;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct CodeBlockTableHeader {
    format_version: u32,
}

impl Entity for CodeBlockTableHeader {
    const ID: EntityId = ENTITY_CODE_BLOCK_TABLE_ID;
}

struct CodeBlockIndex {
    allocator: IdAllocator<CodeBlock>,
    bounds: BTreeMap<AddressSpaceId, IntervalMap<RawAddress, IdSet<CodeBlock>>>,
    live: usize,
}

pub(crate) struct PreparedCodeBlockRecord {
    block: Option<CodeBlock>,
    encoded_size: usize,
    id: Id<CodeBlock>,
    previous: Option<AddressRange>,
}

impl PreparedCodeBlockRecord {
    pub(crate) fn new(
        id: Id<CodeBlock>,
        block: Option<CodeBlock>,
        previous: Option<AddressRange>,
        encoded_size: usize,
    ) -> Self {
        Self {
            block,
            encoded_size,
            id,
            previous,
        }
    }

    pub(crate) fn is_addition(&self) -> bool {
        self.block.is_some() && self.previous.is_none()
    }

    pub(crate) fn is_removal(&self) -> bool {
        self.block.is_none() && self.previous.is_some()
    }

    pub(crate) fn into_block(self) -> Option<CodeBlock> {
        self.block
    }
}

pub enum CodeBlockTable {
    Persistent(PersistentCodeBlockTable),
    Transient(TransientCodeBlockTable),
}

pub type CodeBlockRef<'a> = EntityRef<'a, CodeBlock>;
pub(crate) type CodeBlockIds = SmallVec<[Id<CodeBlock>; 2]>;

#[derive(Default)]
pub(crate) struct CodeBlockIdsByStart {
    additional: FxHashMap<Address, CodeBlockIds>,
    first: FxHashMap<Address, CodeBlockId>,
}

impl CodeBlockIdsByStart {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            additional: FxHashMap::default(),
            first: FxHashMap::with_capacity_and_hasher(capacity, Default::default()),
        }
    }

    pub(in crate::ir) fn contains(&self, address: Address) -> bool {
        self.first.contains_key(&address)
    }

    fn push(&mut self, address: Address, ids: CodeBlockIds) {
        for id in ids {
            self.insert(address, id);
        }
    }

    pub(in crate::ir) fn append(&mut self, locations: Self) {
        for (address, id) in locations.first {
            self.insert(address, id);
        }
        for (address, ids) in locations.additional {
            for id in ids {
                self.insert(address, id);
            }
        }
    }

    pub(in crate::ir) fn ids(&self, address: Address) -> impl Iterator<Item = CodeBlockId> + '_ {
        self.first
            .get(&address)
            .copied()
            .into_iter()
            .chain(self.additional.get(&address).into_iter().flatten().copied())
    }

    pub(in crate::ir) fn insert(&mut self, address: Address, id: CodeBlockId) {
        match self.first.entry(address) {
            Entry::Vacant(entry) => {
                entry.insert(id);
            }
            Entry::Occupied(_) => self.additional.entry(address).or_default().push(id),
        }
    }

    pub(in crate::ir) fn remove(&mut self, address: Address, id: CodeBlockId) {
        if self.first.get(&address).copied() == Some(id) {
            let replacement = self
                .additional
                .get_mut(&address)
                .and_then(|ids| (!ids.is_empty()).then(|| ids.remove(0)));
            if self
                .additional
                .get(&address)
                .is_some_and(SmallVec::is_empty)
            {
                self.additional.remove(&address);
            }
            match replacement {
                Some(replacement) => {
                    self.first.insert(address, replacement);
                }
                None => {
                    self.first.remove(&address);
                }
            }
            return;
        }

        let remove = self.additional.get_mut(&address).is_some_and(|ids| {
            ids.retain(|candidate| *candidate != id);
            ids.is_empty()
        });
        if remove {
            self.additional.remove(&address);
        }
    }

    pub(in crate::ir) fn reserve(&mut self, additional: usize) {
        self.first.reserve(additional);
    }
}

impl CodeBlockTable {
    pub fn new(entities: EntityStorage, cache_bytes: usize) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentCodeBlockTable::new(
            entities,
            cache_bytes,
        )?))
    }

    pub fn with_worker(
        entities: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentCodeBlockTable::with_worker(
            entities,
            worker,
            cache_bytes,
        )?))
    }

    pub fn new_transient() -> Self {
        Self::Transient(TransientCodeBlockTable::new())
    }

    pub fn contains(&self, addr: Address) -> bool {
        match self {
            Self::Persistent(table) => table.contains(addr),
            Self::Transient(table) => table.contains(addr),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Persistent(table) => table.is_empty(),
            Self::Transient(table) => table.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Persistent(table) => table.len(),
            Self::Transient(table) => table.len(),
        }
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(table) => table.flush(),
            Self::Transient(_) => Ok(()),
        }
    }

    pub(crate) fn pending_id(&self, offset: usize) -> Id<CodeBlock> {
        match self {
            Self::Persistent(table) => table.pending_id(offset),
            Self::Transient(table) => table.pending_id(offset),
        }
    }

    pub(crate) fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent(_))
    }

    pub(crate) fn publish_prepared(
        &mut self,
        reservations: &[Id<CodeBlock>],
        cancelled: &BTreeSet<Id<CodeBlock>>,
        added: usize,
        removed: usize,
    ) {
        match self {
            Self::Persistent(table) => table.publish_transition(reservations, added, removed),
            Self::Transient(table) => {
                table.publish_reservations(reservations);
                for &id in cancelled {
                    table.publish_release(id);
                }
            }
        }
    }

    pub(crate) fn publish_upsert(&mut self, block: CodeBlock, encoded_size: usize) {
        match self {
            Self::Persistent(table) => table.publish_upsert(block, encoded_size),
            Self::Transient(table) => table.publish_upsert(block),
        }
    }

    pub(crate) fn publish_new_batch(&mut self, blocks: impl IntoIterator<Item = CodeBlock>) {
        if let Self::Transient(table) = self {
            table.publish_batch(blocks);
        }
    }

    pub(crate) fn publish_remove(&mut self, id: Id<CodeBlock>, previous: AddressRange) {
        match self {
            Self::Persistent(table) => table.publish_remove(id),
            Self::Transient(table) => table.publish_remove(id, previous),
        }
    }

    pub(crate) fn publish_record(&mut self, record: PreparedCodeBlockRecord) {
        let PreparedCodeBlockRecord {
            block,
            encoded_size,
            id,
            previous,
        } = record;
        match block {
            Some(block) => self.publish_upsert(block, encoded_size),
            None => self.publish_remove(
                id,
                previous.expect("prepared block removal has a previous range"),
            ),
        }
    }

    pub fn get_by_id(&self, id: Id<CodeBlock>) -> Option<CodeBlockRef<'_>> {
        self.try_get_by_id(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_id(
        &self,
        id: Id<CodeBlock>,
    ) -> Result<Option<CodeBlockRef<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(table) => Ok(table.try_get_by_id(id)?.map(EntityRef::cached)),
            Self::Transient(table) => Ok(table.get_by_id(id).map(EntityRef::borrowed)),
        }
    }

    pub fn coverage(&self, blocks: impl IntoIterator<Item = Id<CodeBlock>>) -> AddressRangeSet {
        let mut covered = AddressRangeSet::new();
        self.coverage_into(blocks, &mut covered);
        covered
    }

    pub fn coverage_into(
        &self,
        blocks: impl IntoIterator<Item = Id<CodeBlock>>,
        covered: &mut AddressRangeSet,
    ) {
        for id in blocks {
            if let Some(block) = self.get_by_id(id) {
                block.coverage_into(covered);
            }
        }
    }

    pub fn get_by_address(
        &self,
        address: Address,
    ) -> Box<dyn Iterator<Item = CodeBlockRef<'_>> + '_> {
        match self {
            Self::Persistent(table) => {
                Box::new(table.get_by_address(address).map(EntityRef::cached))
            }
            Self::Transient(table) => {
                Box::new(table.get_by_address(address).map(EntityRef::borrowed))
            }
        }
    }

    pub fn get_by_address_and_context<'a>(
        &'a self,
        address: Address,
        context: &'a ContextSet,
    ) -> Box<dyn Iterator<Item = CodeBlockRef<'a>> + 'a> {
        match self {
            Self::Persistent(table) => Box::new(
                table
                    .get_by_address_and_context(address, context)
                    .map(EntityRef::cached),
            ),
            Self::Transient(table) => Box::new(
                table
                    .get_by_address_and_context(address, context)
                    .map(EntityRef::borrowed),
            ),
        }
    }

    pub(crate) fn find_by_range_and_context(
        &self,
        range: AddressRange,
        context: &ContextSet,
        predicate: impl FnMut(&CodeBlock) -> bool,
    ) -> Option<CodeBlockRef<'_>> {
        match self {
            Self::Persistent(table) => table
                .find_by_range_and_context(range, context, predicate)
                .map(EntityRef::cached),
            Self::Transient(table) => table
                .find_by_range_and_context(range, context, predicate)
                .map(EntityRef::borrowed),
        }
    }

    pub(crate) fn try_ids_at_starts(
        &self,
        starts: &[Address],
    ) -> Result<CodeBlockIdsByStart, EntityStorageError> {
        match self {
            Self::Persistent(table) => table.ids_at_starts(starts),
            Self::Transient(table) => Ok(table.ids_at_starts(starts)),
        }
    }

    pub fn overlaps_address(
        &self,
        addr: Address,
    ) -> Box<dyn Iterator<Item = CodeBlockRef<'_>> + '_> {
        match self {
            Self::Persistent(table) => {
                Box::new(table.overlaps_address(addr).map(EntityRef::cached))
            }
            Self::Transient(table) => {
                Box::new(table.overlaps_address(addr).map(EntityRef::borrowed))
            }
        }
    }

    pub fn overlaps<'a>(
        &'a self,
        range: &'a AddressRange,
    ) -> Box<dyn Iterator<Item = CodeBlockRef<'a>> + 'a> {
        match self {
            Self::Persistent(table) => Box::new(table.overlaps(range).map(EntityRef::cached)),
            Self::Transient(table) => Box::new(table.overlaps(range).map(EntityRef::borrowed)),
        }
    }

    pub fn iter(&self) -> Box<dyn Iterator<Item = CodeBlockRef<'_>> + '_> {
        match self {
            Self::Persistent(table) => Box::new(table.iter().map(EntityRef::cached)),
            Self::Transient(table) => Box::new(table.iter().map(EntityRef::borrowed)),
        }
    }
}

impl PersistableProjectEntity for CodeBlockTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(_) => storage.insert(
                &ProjectEntity::CodeBlockTable,
                &CodeBlockTableHeader {
                    format_version: CODE_BLOCK_TABLE_VERSION,
                },
            ),
            Self::Transient(_) => Ok(()),
        }
    }
}
