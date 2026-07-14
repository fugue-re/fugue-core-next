use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt::{Debug as FmtDebug, Display};
use std::sync::Arc;

use anyhow::Error as AnyhowError;
use iset::IntervalMap;
use thiserror::Error;

use crate::ir::{
    Address, AddressRangeSet, CodeBlock, Id, IdSet, RawAddress, Reference, ReferenceKey,
    ReferenceKind, ReferenceOrigin,
};
use crate::lifter::ContextSet;
use crate::storage::entities::schema::ENTITY_CODE_BLOCK_TABLE_ID;
use crate::storage::entities::{
    Entity, EntityId, EntityMut, EntityRef, ProjectEntity, WriteBackWorker,
};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::{EntityStorage, EntityStorageError};

mod persistent;
mod transient;

pub use persistent::CodeBlockTable as PersistentCodeBlockTable;
pub use transient::CodeBlockTable as TransientCodeBlockTable;

const CODE_BLOCK_TABLE_VERSION: u32 = 1;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct CodeBlockTableHeader {
    version: u32,
}

impl Entity for CodeBlockTableHeader {
    const ID: EntityId = ENTITY_CODE_BLOCK_TABLE_ID;
}

struct CodeBlockIndex {
    bounds: BTreeMap<AddressSpaceId, IntervalMap<RawAddress, IdSet<CodeBlock>>>,
    free_ids: Vec<Id<CodeBlock>>,
    live_entries: usize,
    next_index: usize,
}

pub(crate) struct CodeBlockTableAllocation {
    free_ids_len: usize,
    free_ids: Vec<Id<CodeBlock>>,
    next_index: usize,
}

impl CodeBlockTableAllocation {
    fn new(free_ids: &[Id<CodeBlock>], next_index: usize, max_pops: usize) -> Self {
        let tail_start = free_ids.len().saturating_sub(max_pops);
        Self {
            free_ids_len: free_ids.len(),
            free_ids: free_ids[tail_start..].to_vec(),
            next_index,
        }
    }
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
    Other(AnyhowError),
    #[error(transparent)]
    Storage(#[from] EntityStorageError),
}

impl CodeBlockTableError {
    pub fn other<E>(error: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::Other(AnyhowError::new(error))
    }

    pub fn other_with<M>(msg: M) -> Self
    where
        M: FmtDebug + Display + Send + Sync + 'static,
    {
        Self::Other(AnyhowError::msg(msg))
    }
}

pub type CodeBlockRef<'a> = EntityRef<'a, CodeBlock>;
pub type CodeBlockMut<'a> = EntityMut<'a, CodeBlock>;

pub struct CodeBlockIter<'a> {
    inner: Box<dyn Iterator<Item = CodeBlockRef<'a>> + 'a>,
}

impl<'a> CodeBlockIter<'a> {
    pub fn new(iter: impl Iterator<Item = CodeBlockRef<'a>> + 'a) -> Self {
        Self {
            inner: Box::new(iter),
        }
    }
}

impl<'a> Iterator for CodeBlockIter<'a> {
    type Item = CodeBlockRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

pub struct CodeBlockIterMut<'a> {
    inner: Box<dyn Iterator<Item = CodeBlockMut<'a>> + 'a>,
}

impl<'a> CodeBlockIterMut<'a> {
    pub fn new(iter: impl Iterator<Item = CodeBlockMut<'a>> + 'a) -> Self {
        Self {
            inner: Box::new(iter),
        }
    }
}

impl<'a> Iterator for CodeBlockIterMut<'a> {
    type Item = CodeBlockMut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl CodeBlockTable {
    pub fn new(entities: EntityStorage, cache_bytes: usize) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentCodeBlockTable::new(
            entities,
            cache_bytes,
        )?))
    }

    pub fn new_with(
        entities: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentCodeBlockTable::new_with(
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

    pub(crate) fn allocation_checkpoint(&self, max_pops: usize) -> CodeBlockTableAllocation {
        match self {
            Self::Persistent(p) => p.allocation_checkpoint(max_pops),
            Self::Transient(t) => t.allocation_checkpoint(max_pops),
        }
    }

    pub(crate) fn restore_allocation(&mut self, allocation: CodeBlockTableAllocation) {
        match self {
            Self::Persistent(p) => p.restore_allocation(allocation),
            Self::Transient(t) => t.restore_allocation(allocation),
        }
    }

    pub(crate) fn restore_entry(&mut self, block: CodeBlock) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(p) => p.restore_entry(block),
            Self::Transient(t) => {
                t.restore_entry(block);
                Ok(())
            }
        }
    }

    pub(crate) fn clear_entry(&mut self, id: Id<CodeBlock>) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.clear_entry(id),
            Self::Transient(t) => Ok(t.clear_entry(id)),
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
        match self {
            Self::Persistent(p) => p.get_by_id(id).map(EntityRef::cached),
            Self::Transient(t) => t.get_by_id(id).map(EntityRef::borrowed),
        }
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

    pub fn references(&self, blocks: impl IntoIterator<Item = Id<CodeBlock>>) -> Vec<Reference> {
        let mut coalesced = BTreeMap::<ReferenceKey, ReferenceKind>::new();
        for id in blocks {
            if let Some(block) = self.get_by_id(id) {
                for insn in block.instructions().iter() {
                    for reference in insn.flow_references().chain(insn.data_references()) {
                        let key = ReferenceKey::new(reference.from(), reference.target());
                        coalesced
                            .entry(key)
                            .and_modify(|kind| *kind = kind.merged(reference.kind()))
                            .or_insert_with(|| reference.kind());
                    }
                }
            }
        }

        coalesced
            .into_iter()
            .map(|(key, kind)| {
                Reference::new(key.from(), key.target(), kind).with_origin(ReferenceOrigin::Derived)
            })
            .collect()
    }

    pub fn modify_by_id<R>(
        &mut self,
        id: Id<CodeBlock>,
        f: impl FnOnce(&mut CodeBlock) -> R,
    ) -> Option<R> {
        match self {
            Self::Persistent(p) => p.modify_by_id(id, f),
            Self::Transient(t) => t.modify_by_id(id, f),
        }
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
        match self {
            Self::Persistent(p) => p.get_by_id_mut(id).map(EntityMut::cached),
            Self::Transient(t) => t.get_by_id_mut(id).map(EntityMut::borrowed),
        }
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
        match self {
            Self::Persistent(p) => p.remove_by_id(id),
            Self::Transient(t) => t.remove_by_id(id),
        }
    }

    pub fn try_remove_by_id(&mut self, id: Id<CodeBlock>) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_remove_by_id(id),
            Self::Transient(t) => Ok(t.remove_by_id(id)),
        }
    }

    pub fn remove_by_address(&mut self, addr: Address) -> usize {
        match self {
            Self::Persistent(p) => p.remove_by_address(addr),
            Self::Transient(t) => t.remove_by_address(addr),
        }
    }

    pub fn try_remove_by_address(&mut self, addr: Address) -> Result<usize, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_remove_by_address(addr),
            Self::Transient(t) => Ok(t.remove_by_address(addr)),
        }
    }

    pub fn remove_by_address_and_context(&mut self, addr: Address, context: &ContextSet) -> usize {
        match self {
            Self::Persistent(p) => p.remove_by_address_and_context(addr, context),
            Self::Transient(t) => t.remove_by_address_and_context(addr, context),
        }
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

    pub fn get_by_address(&self, maddr: Address) -> CodeBlockIter<'_> {
        match self {
            Self::Persistent(p) => {
                CodeBlockIter::new(p.get_by_address(maddr).map(EntityRef::cached))
            }
            Self::Transient(t) => {
                CodeBlockIter::new(t.get_by_address(maddr).map(EntityRef::borrowed))
            }
        }
    }

    pub fn get_by_address_and_context<'a>(
        &'a self,
        maddr: Address,
        context: &'a ContextSet,
    ) -> CodeBlockIter<'a> {
        match self {
            Self::Persistent(p) => CodeBlockIter::new(
                p.get_by_address_and_context(maddr, context)
                    .map(EntityRef::cached),
            ),
            Self::Transient(t) => CodeBlockIter::new(
                t.get_by_address_and_context(maddr, context)
                    .map(EntityRef::borrowed),
            ),
        }
    }

    pub fn contains(&self, addr: Address) -> bool {
        match self {
            Self::Persistent(p) => p.contains(addr),
            Self::Transient(t) => t.contains(addr),
        }
    }

    pub fn overlaps(&self, addr: Address) -> CodeBlockIter<'_> {
        match self {
            Self::Persistent(p) => CodeBlockIter::new(p.overlaps(addr).map(EntityRef::cached)),
            Self::Transient(t) => CodeBlockIter::new(t.overlaps(addr).map(EntityRef::borrowed)),
        }
    }

    pub fn get_by_address_mut(&mut self, maddr: Address) -> CodeBlockIterMut<'_> {
        match self {
            Self::Persistent(p) => {
                CodeBlockIterMut::new(p.get_by_address_mut(maddr).map(EntityMut::cached))
            }
            Self::Transient(t) => {
                CodeBlockIterMut::new(t.get_by_address_mut(maddr).map(EntityMut::borrowed))
            }
        }
    }

    pub fn get_by_address_and_context_mut<'a>(
        &'a mut self,
        maddr: Address,
        context: &'a ContextSet,
    ) -> CodeBlockIterMut<'a> {
        match self {
            Self::Persistent(p) => CodeBlockIterMut::new(
                p.get_by_address_and_context_mut(maddr, context)
                    .map(EntityMut::cached),
            ),
            Self::Transient(t) => CodeBlockIterMut::new(
                t.get_by_address_and_context_mut(maddr, context)
                    .map(EntityMut::borrowed),
            ),
        }
    }

    pub fn overlaps_mut(&mut self, addr: Address) -> CodeBlockIterMut<'_> {
        match self {
            Self::Persistent(p) => {
                CodeBlockIterMut::new(p.overlaps_mut(addr).map(EntityMut::cached))
            }
            Self::Transient(t) => {
                CodeBlockIterMut::new(t.overlaps_mut(addr).map(EntityMut::borrowed))
            }
        }
    }

    pub fn iter(&self) -> CodeBlockIter<'_> {
        match self {
            Self::Persistent(p) => CodeBlockIter::new(p.iter().map(EntityRef::cached)),
            Self::Transient(t) => CodeBlockIter::new(t.iter().map(EntityRef::borrowed)),
        }
    }

    pub fn iter_mut(&mut self) -> CodeBlockIterMut<'_> {
        match self {
            Self::Persistent(p) => CodeBlockIterMut::new(p.iter_mut().map(EntityMut::cached)),
            Self::Transient(t) => CodeBlockIterMut::new(t.iter_mut().map(EntityMut::borrowed)),
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
    fn test_free_id_rebuild_on_reopen_sqlite() {
        let dir = TempDir::new().unwrap();

        {
            let storage =
                EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
            let worker = WriteBackWorker::new(storage.clone()).unwrap();
            let mut table = CodeBlockTable::new_with(storage, worker, 64 * 1024).unwrap();

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
        let mut table = CodeBlockTable::new_with(storage, worker, 64 * 1024).unwrap();

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

        assert_eq!([first.index(), second.index(), third.index()], [5, 6, 7]);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn test_get_by_id_mut_persists_sqlite() {
        let dir = TempDir::new().unwrap();
        let addr = Address::from(0x1000);
        let successor = Id::<CodeBlock>::new(7);

        {
            let storage =
                EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
            let worker = WriteBackWorker::new(storage.clone()).unwrap();
            let mut table = CodeBlockTable::new_with(storage, worker, 64 * 1024).unwrap();

            let bid = table
                .insert(addr, |id, start| {
                    Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
                })
                .unwrap();

            {
                let mut block = table.get_by_id_mut(bid).expect("block exists");
                block.add_successor(successor);
            }

            table.flush().unwrap();
        }

        let storage =
            EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        let table = CodeBlockTable::new_with(storage, worker, 64 * 1024).unwrap();

        let block = table.get_by_address(addr).next().expect("block exists");
        assert!(block.successors().contains(successor));
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn test_iter_mut_persists() {
        let dir = TempDir::new().unwrap();
        let successor = Id::<CodeBlock>::new(99);

        {
            let storage =
                EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
            let worker = WriteBackWorker::new(storage.clone()).unwrap();
            let mut table = CodeBlockTable::new_with(storage, worker, 64 * 1024).unwrap();

            for base in 1..=3u64 {
                table
                    .insert(Address::from(base * 0x1000), |id, start| {
                        Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
                    })
                    .unwrap();
            }

            for mut block in table.iter_mut() {
                block.add_successor(successor);
            }

            table.flush().unwrap();
        }

        let storage =
            EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        let table = CodeBlockTable::new_with(storage, worker, 64 * 1024).unwrap();

        assert_eq!(table.len(), 3);
        for block in table.iter() {
            assert!(block.successors().contains(successor));
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
    fn test_transient_iter_mut_mutate() {
        let mut table = CodeBlockTable::new_transient();
        let successor = Id::<CodeBlock>::new(42);

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
            block.add_successor(successor);
        }

        for id in ids {
            let block = table.get_by_id(id).unwrap();
            assert!(block.successors().contains(successor));
        }
    }
}
