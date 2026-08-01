use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use iset::IntervalMap;
use smallvec::SmallVec;
use thiserror::Error;

use crate::ir::{
    Address, AddressRange, AddressRangeSet, CodeBlock, Id, IdAllocator, IdSet, RawAddress,
};
use crate::ir::persistent::PersistentIdAllocator;
use crate::lifter::ContextSet;
use crate::storage::entities::schema::ENTITY_CODE_BLOCK_TABLE_ID;
use crate::storage::entities::{
    Entity, EntityCache, EntityId, EntityMut, EntityRef, ProjectEntity, WriteBackWorker,
};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::{EntityStorage, EntityStorageError};

mod persistent;
mod transient;

use transient::CodeBlockTable as TransientCodeBlockTable;

const CODE_BLOCK_TABLE_VERSION: u32 = 1;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct CodeBlockTableHeader {
    version: u32,
}

impl Entity for CodeBlockTableHeader {
    const ID: EntityId = ENTITY_CODE_BLOCK_TABLE_ID;
}

struct CodeBlockIndex {
    allocator: IdAllocator<CodeBlock>,
    bounds: BTreeMap<AddressSpaceId, IntervalMap<RawAddress, IdSet<CodeBlock>>>,
    live: usize,
}

pub(crate) struct PreparedBlockMutation {
    block: Option<CodeBlock>,
    encoded_len: usize,
    id: Id<CodeBlock>,
    previous: Option<AddressRange>,
}

impl PreparedBlockMutation {
    pub(crate) fn new(
        id: Id<CodeBlock>,
        block: Option<CodeBlock>,
        previous: Option<AddressRange>,
        encoded_len: usize,
    ) -> Self {
        Self {
            block,
            encoded_len,
            id,
            previous,
        }
    }

    pub(crate) fn block(&self) -> Option<&CodeBlock> {
        self.block.as_ref()
    }

    pub(crate) fn id(&self) -> Id<CodeBlock> {
        self.id
    }

    pub(crate) fn previous(&self) -> Option<AddressRange> {
        self.previous
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Id<CodeBlock>,
        Option<CodeBlock>,
        Option<AddressRange>,
        usize,
    ) {
        (self.id, self.block, self.previous, self.encoded_len)
    }
}

pub struct PersistentCodeBlockTable {
    allocator: PersistentIdAllocator<CodeBlock>,
    entries: EntityCache<Id<CodeBlock>, CodeBlock>,
    storage: EntityStorage,
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
        E: Error + Send + Sync + 'static,
    {
        Self::Other(anyhow::Error::new(error))
    }

    pub fn other_with<M>(msg: M) -> Self
    where
        M: fmt::Debug + fmt::Display + Send + Sync + 'static,
    {
        Self::Other(anyhow::Error::msg(msg))
    }
}

pub type CodeBlockRef<'a> = EntityRef<'a, CodeBlock>;
pub type CodeBlockMut<'a> = EntityMut<'a, CodeBlock>;
pub(crate) type CodeBlockIds = SmallVec<[Id<CodeBlock>; 2]>;
pub(crate) type CodeBlockIdsByStart = Vec<(Address, CodeBlockIds)>;

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

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(p) => p.flush(),
            Self::Transient(t) => t.flush(),
        }
    }

    pub(crate) fn preview_id(&self, offset: usize) -> Id<CodeBlock> {
        match self {
            Self::Persistent(table) => table
                .allocator
                .preview_id(offset)
                .unwrap_or_else(|error| error.into_fatal()),
            Self::Transient(t) => t.preview_id(offset),
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

    pub(crate) fn publish_upsert(&mut self, block: CodeBlock, encoded_len: usize) {
        match self {
            Self::Persistent(p) => p.publish_upsert(block, encoded_len),
            Self::Transient(t) => t.publish_upsert(block),
        }
    }

    pub(crate) fn publish_new_batch(&mut self, blocks: impl IntoIterator<Item = CodeBlock>) {
        if let Self::Transient(table) = self {
            table.publish_batch(blocks);
        }
    }

    pub(crate) fn publish_remove(&mut self, id: Id<CodeBlock>, previous: AddressRange) {
        match self {
            Self::Persistent(p) => p.publish_remove(id),
            Self::Transient(t) => t.publish_remove(id, previous),
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
        self.try_get_by_id(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_id(
        &self,
        id: Id<CodeBlock>,
    ) -> Result<Option<CodeBlockRef<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_by_id(id)?.map(EntityRef::cached)),
            Self::Transient(t) => Ok(t.get_by_id(id).map(EntityRef::borrowed)),
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

    pub fn modify_by_id<R>(
        &mut self,
        id: Id<CodeBlock>,
        f: impl FnOnce(&mut CodeBlock) -> R,
    ) -> Option<R> {
        self.try_modify_by_id(id, f)
            .unwrap_or_else(|error| error.into_fatal())
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
        self.try_get_by_id_mut(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_id_mut(
        &mut self,
        id: Id<CodeBlock>,
    ) -> Result<Option<CodeBlockMut<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_by_id_mut(id)?.map(EntityMut::cached)),
            Self::Transient(t) => Ok(t.get_by_id_mut(id).map(EntityMut::borrowed)),
        }
    }

    pub fn remove_by_id(&mut self, id: Id<CodeBlock>) -> bool {
        self.try_remove_by_id(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove_by_id(&mut self, id: Id<CodeBlock>) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_remove_by_id(id),
            Self::Transient(t) => Ok(t.remove_by_id(id)),
        }
    }

    pub fn remove_by_address(&mut self, addr: Address) -> usize {
        self.try_remove_by_address(addr)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove_by_address(&mut self, addr: Address) -> Result<usize, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_remove_by_address(addr),
            Self::Transient(t) => Ok(t.remove_by_address(addr)),
        }
    }

    pub fn remove_by_address_and_context(&mut self, addr: Address, context: &ContextSet) -> usize {
        self.try_remove_by_address_and_context(addr, context)
            .unwrap_or_else(|error| error.into_fatal())
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

    pub fn get_by_address(
        &self,
        maddr: Address,
    ) -> Box<dyn Iterator<Item = CodeBlockRef<'_>> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.get_by_address(maddr).map(EntityRef::cached)),
            Self::Transient(t) => Box::new(t.get_by_address(maddr).map(EntityRef::borrowed)),
        }
    }

    pub fn get_by_address_and_context<'a>(
        &'a self,
        maddr: Address,
        context: &'a ContextSet,
    ) -> Box<dyn Iterator<Item = CodeBlockRef<'a>> + 'a> {
        match self {
            Self::Persistent(p) => Box::new(
                p.get_by_address_and_context(maddr, context)
                    .map(EntityRef::cached),
            ),
            Self::Transient(t) => Box::new(
                t.get_by_address_and_context(maddr, context)
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

    pub fn contains(&self, addr: Address) -> bool {
        match self {
            Self::Persistent(p) => p.contains(addr),
            Self::Transient(t) => t.contains(addr),
        }
    }

    pub fn overlaps(&self, addr: Address) -> Box<dyn Iterator<Item = CodeBlockRef<'_>> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.overlaps(addr).map(EntityRef::cached)),
            Self::Transient(t) => Box::new(t.overlaps(addr).map(EntityRef::borrowed)),
        }
    }

    pub fn overlaps_range<'a>(
        &'a self,
        range: &'a AddressRange,
    ) -> Box<dyn Iterator<Item = CodeBlockRef<'a>> + 'a> {
        match self {
            Self::Persistent(p) => Box::new(p.overlaps_range(range).map(EntityRef::cached)),
            Self::Transient(t) => Box::new(t.overlaps_range(range).map(EntityRef::borrowed)),
        }
    }

    pub fn get_by_address_mut(
        &mut self,
        maddr: Address,
    ) -> Box<dyn Iterator<Item = CodeBlockMut<'_>> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.get_by_address_mut(maddr).map(EntityMut::cached)),
            Self::Transient(t) => Box::new(t.get_by_address_mut(maddr).map(EntityMut::borrowed)),
        }
    }

    pub fn get_by_address_and_context_mut<'a>(
        &'a mut self,
        maddr: Address,
        context: &'a ContextSet,
    ) -> Box<dyn Iterator<Item = CodeBlockMut<'a>> + 'a> {
        match self {
            Self::Persistent(p) => Box::new(
                p.get_by_address_and_context_mut(maddr, context)
                    .map(EntityMut::cached),
            ),
            Self::Transient(t) => Box::new(
                t.get_by_address_and_context_mut(maddr, context)
                    .map(EntityMut::borrowed),
            ),
        }
    }

    pub fn overlaps_mut(
        &mut self,
        addr: Address,
    ) -> Box<dyn Iterator<Item = CodeBlockMut<'_>> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.overlaps_mut(addr).map(EntityMut::cached)),
            Self::Transient(t) => Box::new(t.overlaps_mut(addr).map(EntityMut::borrowed)),
        }
    }

    pub fn iter(&self) -> Box<dyn Iterator<Item = CodeBlockRef<'_>> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.iter().map(EntityRef::cached)),
            Self::Transient(t) => Box::new(t.iter().map(EntityRef::borrowed)),
        }
    }

    pub fn iter_mut(&mut self) -> Box<dyn Iterator<Item = CodeBlockMut<'_>> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.iter_mut().map(EntityMut::cached)),
            Self::Transient(t) => Box::new(t.iter_mut().map(EntityMut::borrowed)),
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
    use std::collections::BTreeSet;

    #[cfg(feature = "sqlite")]
    use tempfile::TempDir;

    use super::*;
    use crate::ir::InsnList;
    #[cfg(feature = "sqlite")]
    use crate::storage::PERSISTENT;
    use crate::storage::entities::InMemoryEntityStorage;
    #[cfg(feature = "sqlite")]
    use crate::storage::entities::SqliteEntityStorage;

    fn table() -> CodeBlockTable {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        CodeBlockTable::new(storage, 64 * 1024).unwrap()
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
    fn test_reused_slot_invalidates_removed_id() {
        let mut table = table();

        let first = table
            .insert(Address::from(0x1000), |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
            })
            .unwrap();

        assert!(table.remove_by_id(first));
        assert!(table.get_by_id(first).is_none());

        let second = table
            .insert(Address::from(0x2000), |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
            })
            .unwrap();

        assert_eq!(first.index(), second.index());
        assert_eq!(first.generation() + 1, second.generation());
        assert!(table.get_by_id(first).is_none());
        assert_eq!(
            table.get_by_id(second).unwrap().start(),
            Address::from(0x2000)
        );
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

        let exact = table
            .find_by_range_and_context(
                AddressRange::from_size(addr2, 0x8).expect("valid block range"),
                &ContextSet::default(),
                |_| true,
            )
            .expect("block with exact range exists");
        assert_eq!(exact.id(), blk_id2);

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
    fn test_free_id_reuse_after_reopen_sqlite() {
        let dir = TempDir::new().unwrap();

        {
            let storage =
                EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
            let worker = WriteBackWorker::new(storage.clone()).unwrap();
            let mut table = CodeBlockTable::with_worker(storage, worker, 64 * 1024).unwrap();

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
        let mut table = CodeBlockTable::with_worker(storage, worker, 64 * 1024).unwrap();

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

        assert_eq!(
            [
                (first.index(), first.generation()),
                (second.index(), second.generation()),
                (third.index(), third.generation()),
            ],
            [(1, 1), (3, 1), (5, 0)]
        );
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn test_get_by_id_mut_persists_sqlite() {
        let dir = TempDir::new().unwrap();
        let addr = Address::from(0x1000);

        {
            let storage =
                EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
            let worker = WriteBackWorker::new(storage.clone()).unwrap();
            let mut table = CodeBlockTable::with_worker(storage, worker, 64 * 1024).unwrap();

            let bid = table
                .insert(addr, |id, start| {
                    Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
                })
                .unwrap();

            {
                let mut block = table.get_by_id_mut(bid).expect("block exists");
                block.mark_call();
            }

            table.flush().unwrap();
        }

        let storage =
            EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        let table = CodeBlockTable::with_worker(storage, worker, 64 * 1024).unwrap();

        let block = table.get_by_address(addr).next().expect("block exists");
        assert!(block.is_call());
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn test_iter_mut_persists() {
        let dir = TempDir::new().unwrap();

        {
            let storage =
                EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
            let worker = WriteBackWorker::new(storage.clone()).unwrap();
            let mut table = CodeBlockTable::with_worker(storage, worker, 64 * 1024).unwrap();

            for base in 1..=3u64 {
                table
                    .insert(Address::from(base * 0x1000), |id, start| {
                        Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
                    })
                    .unwrap();
            }

            for mut block in table.iter_mut() {
                block.mark_unresolved();
            }

            table.flush().unwrap();
        }

        let storage =
            EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        let table = CodeBlockTable::with_worker(storage, worker, 64 * 1024).unwrap();

        assert_eq!(table.len(), 3);
        for block in table.iter() {
            assert!(block.has_unresolved());
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
    fn transient_block_batches_merge_exact_and_overlapping_ranges() {
        let mut table = CodeBlockTable::new_transient();
        let ids = (0..5)
            .map(|offset| table.preview_id(offset))
            .collect::<Vec<_>>();
        table.publish_prepared(&ids, &BTreeSet::new(), 0, 0);

        let block = |id, address, len| {
            CodeBlock::try_new(id, Address::from(address), len, InsnList::new())
                .expect("valid block")
        };
        table.publish_new_batch([
            block(ids[0], 0x1000, 0x10),
            block(ids[1], 0x2000, 0x10),
        ]);
        table.publish_new_batch([
            block(ids[2], 0x1000, 0x10),
            block(ids[3], 0x1008, 0x10),
            block(ids[4], 0x3000, 0x10),
        ]);

        let overlaps = table
            .overlaps(Address::from(0x1008))
            .map(|block| block.id())
            .collect::<BTreeSet<_>>();
        assert_eq!(overlaps, BTreeSet::from([ids[0], ids[2], ids[3]]));
        assert_eq!(table.len(), ids.len());
        assert!(table.contains(Address::from(0x2000)));
        assert!(table.contains(Address::from(0x3000)));
    }

    #[test]
    fn test_transient_iter_mut_mutate() {
        let mut table = CodeBlockTable::new_transient();

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
            block.mark_call();
        }

        for id in ids {
            let block = table.get_by_id(id).unwrap();
            assert!(block.is_call());
        }
    }
}
