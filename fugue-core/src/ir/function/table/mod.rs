use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt::{Debug as FmtDebug, Display};
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;

use thiserror::Error;

use crate::ir::block::CodeBlockTableAllocation;
use crate::ir::{
    Address, AddressRange, CodeBlock, CodeBlockTable, Function, FunctionId, Id, IdAllocation,
    IdAllocator, RawAddress,
};
use crate::storage::entities::schema::ENTITY_FUNCTION_TABLE_ID;
use crate::storage::entities::{
    Entity, EntityId, EntityMut, EntityRef, ProjectEntity, WriteBackWorker,
};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::{EntityStorage, EntityStorageError};
use crate::types::common::cursor_bound;

mod persistent;
mod transient;

use persistent::FunctionTable as PersistentFunctionTable;
use transient::FunctionTable as TransientFunctionTable;

pub type FunctionRef<'a> = EntityRef<'a, Function>;
pub type FunctionMut<'a> = EntityMut<'a, Function>;

const FUNCTION_TABLE_VERSION: u32 = 1;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct FunctionTableHeader {
    version: u32,
}

impl Entity for FunctionTableHeader {
    const ID: EntityId = ENTITY_FUNCTION_TABLE_ID;
}

struct FunctionIndex {
    allocator: IdAllocator<Function>,
    addresses: BTreeMap<Address, Id<Function>>,
}

type FunctionTableAllocation = IdAllocation<Function>;

pub enum FunctionTable {
    Persistent(PersistentFunctionTable),
    Transient(TransientFunctionTable),
}

pub(crate) struct FunctionTableRevert {
    entry: Address,
    function_allocation: FunctionTableAllocation,
    block_allocation: CodeBlockTableAllocation,
    previous_function: Option<Function>,
    previous_blocks: Vec<CodeBlock>,
}

#[derive(Debug, Error)]
pub enum FunctionTableError {
    #[error("function to insert has a different address than that used for insertion")]
    AddressMismatch,
    #[error(transparent)]
    Other(anyhow::Error),
    #[error(transparent)]
    Storage(#[from] EntityStorageError),
}

impl FunctionTableError {
    pub fn other<E>(error: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::Other(anyhow::Error::new(error))
    }

    pub fn other_with<M>(msg: M) -> Self
    where
        M: FmtDebug + Display + Send + Sync + 'static,
    {
        Self::Other(anyhow::Error::msg(msg))
    }
}

impl FunctionTableRevert {
    pub(crate) fn capture(
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
        entry: Address,
        new_block_count: usize,
    ) -> Self {
        let previous_function = functions
            .get_by_address(entry)
            .map(|function| function.as_ref().clone());
        let previous_blocks = previous_function
            .as_ref()
            .map(|function| {
                function
                    .blocks()
                    .filter_map(|(_, id)| blocks.get_by_id(id).map(|block| block.as_ref().clone()))
                    .collect()
            })
            .unwrap_or_default();

        Self {
            entry,
            function_allocation: functions.allocation_checkpoint(1),
            block_allocation: blocks.allocation_checkpoint(new_block_count),
            previous_function,
            previous_blocks,
        }
    }

    pub(crate) fn entry(&self) -> Address {
        self.entry
    }

    pub(crate) fn restore(
        self,
        functions: &mut FunctionTable,
        blocks: &mut CodeBlockTable,
    ) -> Result<(), EntityStorageError> {
        let current_blocks = functions
            .get_by_address(self.entry)
            .map(|function| function.blocks().map(|(_, id)| id).collect::<Vec<_>>())
            .unwrap_or_default();
        let current_function = functions
            .get_by_address(self.entry)
            .map(|function| function.id());

        if let Some(id) = current_function {
            functions.clear_entry(id)?;
        }

        for block in current_blocks {
            blocks.clear_entry(block)?;
        }

        for block in self.previous_blocks {
            blocks.restore_entry(block)?;
        }

        if let Some(function) = self.previous_function {
            functions.restore_entry(function)?;
        }

        functions.restore_allocation(self.function_allocation);
        blocks.restore_allocation(self.block_allocation);

        Ok(())
    }
}

impl FunctionTable {
    pub fn new(entities: EntityStorage, cache_bytes: usize) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentFunctionTable::new(
            entities,
            cache_bytes,
        )?))
    }

    pub fn with_worker(
        entities: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentFunctionTable::with_worker(
            entities,
            worker,
            cache_bytes,
        )?))
    }

    pub fn new_transient() -> Self {
        Self::Transient(TransientFunctionTable::new())
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(p) => p.flush(),
            Self::Transient(t) => t.flush(),
        }
    }

    fn allocation_checkpoint(&self, max_pops: usize) -> FunctionTableAllocation {
        match self {
            Self::Persistent(p) => p.allocation_checkpoint(max_pops),
            Self::Transient(t) => t.allocation_checkpoint(max_pops),
        }
    }

    fn restore_allocation(&mut self, allocation: FunctionTableAllocation) {
        match self {
            Self::Persistent(p) => p.restore_allocation(allocation),
            Self::Transient(t) => t.restore_allocation(allocation),
        }
    }

    fn restore_entry(&mut self, function: Function) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(p) => p.restore_entry(function),
            Self::Transient(t) => {
                t.restore_entry(function);
                Ok(())
            }
        }
    }

    fn clear_entry(&mut self, id: Id<Function>) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.clear_entry(id),
            Self::Transient(t) => Ok(t.clear_entry(id)),
        }
    }

    pub fn insert<F>(&mut self, addr: Address, f: F) -> Result<Id<Function>, FunctionTableError>
    where
        F: FnOnce(Id<Function>, Address) -> Result<Function, FunctionTableError>,
    {
        match self {
            Self::Persistent(p) => p.insert(addr, f),
            Self::Transient(t) => t.insert(addr, f),
        }
    }

    pub fn get_by_id(&self, id: Id<Function>) -> Option<FunctionRef<'_>> {
        self.try_get_by_id(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_id(
        &self,
        id: Id<Function>,
    ) -> Result<Option<FunctionRef<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_by_id(id)?.map(EntityRef::cached)),
            Self::Transient(t) => Ok(t.get_by_id(id).map(EntityRef::borrowed)),
        }
    }

    pub fn get_by_address(&self, addr: Address) -> Option<FunctionRef<'_>> {
        self.try_get_by_address(addr)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_address(
        &self,
        addr: Address,
    ) -> Result<Option<FunctionRef<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_by_address(addr)?.map(EntityRef::cached)),
            Self::Transient(t) => Ok(t.get_by_address(addr).map(EntityRef::borrowed)),
        }
    }

    pub fn get_by_id_mut(&mut self, id: Id<Function>) -> Option<FunctionMut<'_>> {
        self.try_get_by_id_mut(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_id_mut(
        &mut self,
        id: Id<Function>,
    ) -> Result<Option<FunctionMut<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_by_id_mut(id)?.map(EntityMut::cached)),
            Self::Transient(t) => Ok(t.get_by_id_mut(id).map(EntityMut::borrowed)),
        }
    }

    pub fn get_by_address_mut(&mut self, addr: Address) -> Option<FunctionMut<'_>> {
        self.try_get_by_address_mut(addr)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_address_mut(
        &mut self,
        addr: Address,
    ) -> Result<Option<FunctionMut<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_by_address_mut(addr)?.map(EntityMut::cached)),
            Self::Transient(t) => Ok(t.get_by_address_mut(addr).map(EntityMut::borrowed)),
        }
    }

    pub fn modify_by_id<R>(
        &mut self,
        id: Id<Function>,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Option<R> {
        self.try_modify_by_id(id, f)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_modify_by_id<R>(
        &mut self,
        id: Id<Function>,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_modify_by_id(id, f),
            Self::Transient(t) => Ok(t.modify_by_id(id, f)),
        }
    }

    pub fn modify_by_address<R>(
        &mut self,
        addr: Address,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Option<R> {
        self.try_modify_by_address(addr, f)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_modify_by_address<R>(
        &mut self,
        addr: Address,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_modify_by_address(addr, f),
            Self::Transient(t) => Ok(t.modify_by_address(addr, f)),
        }
    }

    pub fn remove_by_id(&mut self, id: Id<Function>) -> bool {
        self.try_remove_by_id(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove_by_id(&mut self, id: Id<Function>) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_remove_by_id(id),
            Self::Transient(t) => Ok(t.remove_by_id(id)),
        }
    }

    pub fn remove_by_address(&mut self, addr: Address) -> bool {
        self.try_remove_by_address(addr)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove_by_address(&mut self, addr: Address) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_remove_by_address(addr),
            Self::Transient(t) => Ok(t.remove_by_address(addr)),
        }
    }

    pub fn addresses(&self) -> Box<dyn Iterator<Item = Address> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.addresses()),
            Self::Transient(t) => Box::new(t.addresses()),
        }
    }

    pub fn addresses_in_range<R>(
        &self,
        space: AddressSpaceId,
        range: R,
    ) -> Box<dyn Iterator<Item = Address> + '_>
    where
        R: RangeBounds<RawAddress>,
    {
        match self {
            Self::Persistent(p) => Box::new(p.addresses_in_range(space, range)),
            Self::Transient(t) => Box::new(t.addresses_in_range(space, range)),
        }
    }

    pub fn addresses_in_space_after(
        &self,
        space: AddressSpaceId,
        after: Option<RawAddress>,
    ) -> Box<dyn Iterator<Item = Address> + '_> {
        let start = cursor_bound(after);
        self.addresses_in_range(space, (start, Bound::Unbounded))
    }

    pub fn overlaps<'a>(
        &'a self,
        blocks: &'a CodeBlockTable,
        range: &'a AddressRange,
    ) -> impl Iterator<Item = Id<Function>> + 'a {
        self.iter()
            .filter(|function| {
                function.blocks().any(|(_, block)| {
                    blocks
                        .get_by_id(block)
                        .is_some_and(|block| block.address_range().intersects(range))
                })
            })
            .map(|function| function.id())
    }

    pub(crate) fn function_containing(
        &self,
        blocks: &CodeBlockTable,
        address: Address,
    ) -> Option<FunctionId> {
        let block = blocks.block_containing(address)?;
        self.iter()
            .find(|function| {
                function
                    .blocks()
                    .any(|(_, block_id)| block_id == block.id())
            })
            .map(|function| function.id())
    }

    pub fn iter(&self) -> Box<dyn Iterator<Item = FunctionRef<'_>> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.iter().map(EntityRef::cached)),
            Self::Transient(t) => Box::new(t.iter().map(EntityRef::borrowed)),
        }
    }

    pub fn iter_mut(&mut self) -> Box<dyn Iterator<Item = FunctionMut<'_>> + '_> {
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

impl PersistableProjectEntity for FunctionTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(_) => storage.insert(
                &ProjectEntity::FunctionTable,
                &FunctionTableHeader {
                    version: FUNCTION_TABLE_VERSION,
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
    #[cfg(feature = "sqlite")]
    use crate::storage::PERSISTENT;
    use crate::storage::entities::InMemoryEntityStorage;
    #[cfg(feature = "sqlite")]
    use crate::storage::entities::SqliteEntityStorage;

    fn table() -> FunctionTable {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        FunctionTable::new(storage, 64 * 1024).unwrap()
    }

    #[test]
    fn test_basic_operations() {
        let mut table = table();

        let addr = Address::from(0x1000);
        let func_id = table
            .insert(addr, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();

        assert_eq!(table.len(), 1);

        let func = table.get_by_address(addr).unwrap();
        assert_eq!(func.id(), func_id);
        drop(func);

        assert!(table.remove_by_id(func_id));
        assert_eq!(table.len(), 0);

        assert!(table.get_by_address(addr).is_none());
    }

    #[test]
    fn test_removal_operations() {
        let mut table = table();

        let addr1 = Address::from(0x1000);
        let addr2 = Address::from(0x2000);
        let addr3 = Address::from(0x3000);

        let func_id1 = table
            .insert(addr1, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();

        let func_id2 = table
            .insert(addr2, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();

        assert_eq!(table.len(), 2);

        assert!(table.remove_by_address(addr1));
        assert_eq!(table.len(), 1);

        assert!(table.get_by_address(addr1).is_none());
        assert!(table.get_by_address(addr2).is_some());

        let func_id3 = table
            .insert(addr3, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();

        assert_eq!(table.len(), 2);

        assert_eq!(func_id1.index(), func_id3.index());
        assert_eq!(func_id1.generation() + 1, func_id3.generation());
        assert!(table.get_by_id(func_id1).is_none());
        assert_eq!(table.get_by_id(func_id3).unwrap().entry(), addr3);

        let func_id4 = table
            .insert(addr1, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();

        assert_eq!(table.len(), 3);
        assert_ne!(func_id4.index(), func_id1.index());

        assert!(table.remove_by_id(func_id2));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn test_index_rebuild_on_open() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());

        {
            let mut table = FunctionTable::new(storage.clone(), 64 * 1024).unwrap();
            table
                .insert(Address::from(0x1000), |id, entry| {
                    Ok(Function::new(id, entry))
                })
                .unwrap();
            table
                .insert(Address::from(0x2000), |id, entry| {
                    Ok(Function::new(id, entry))
                })
                .unwrap();
        }

        let table = FunctionTable::new(storage, 64 * 1024).unwrap();
        assert_eq!(table.len(), 2);
        assert!(table.get_by_address(Address::from(0x1000)).is_some());
        assert!(table.get_by_address(Address::from(0x2000)).is_some());
    }

    #[test]
    fn test_worker_round_trip() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());

        {
            let worker = WriteBackWorker::new(storage.clone()).unwrap();
            let mut table = FunctionTable::with_worker(storage.clone(), worker, 64 * 1024).unwrap();
            table
                .insert(Address::from(0x1000), |id, entry| {
                    Ok(Function::new(id, entry))
                })
                .unwrap();
            table
                .insert(Address::from(0x2000), |id, entry| {
                    Ok(Function::new(id, entry))
                })
                .unwrap();
            table.flush().unwrap();
        }

        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        let table = FunctionTable::with_worker(storage, worker, 64 * 1024).unwrap();
        assert_eq!(table.len(), 2);
        assert!(table.get_by_address(Address::from(0x1000)).is_some());
        assert!(table.get_by_address(Address::from(0x2000)).is_some());
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn test_free_id_rebuild_on_reopen_sqlite() {
        let dir = TempDir::new().unwrap();

        {
            let storage =
                EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
            let worker = WriteBackWorker::new(storage.clone()).unwrap();
            let mut table = FunctionTable::with_worker(storage, worker, 64 * 1024).unwrap();

            for base in 1..=5u64 {
                table
                    .insert(Address::from(base * 0x1000), |id, entry| {
                        Ok(Function::new(id, entry))
                    })
                    .unwrap();
            }

            assert!(table.remove_by_address(Address::from(0x2000)));
            assert!(table.remove_by_address(Address::from(0x4000)));

            table.flush().unwrap();
        }

        let storage =
            EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        let mut table = FunctionTable::with_worker(storage, worker, 64 * 1024).unwrap();

        assert_eq!(table.len(), 3);

        let first = table
            .insert(Address::from(0x6000), |id, entry| {
                Ok(Function::new(id, entry))
            })
            .unwrap();
        let second = table
            .insert(Address::from(0x7000), |id, entry| {
                Ok(Function::new(id, entry))
            })
            .unwrap();
        let third = table
            .insert(Address::from(0x8000), |id, entry| {
                Ok(Function::new(id, entry))
            })
            .unwrap();

        assert_eq!([first.index(), second.index(), third.index()], [5, 6, 7]);
    }

    #[test]
    fn test_transient_basic_operations() {
        let mut table = FunctionTable::new_transient();

        let addr = Address::from(0x1000);
        let func_id = table
            .insert(addr, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();

        assert_eq!(table.len(), 1);

        let func = table.get_by_address(addr).unwrap();
        assert_eq!(func.id(), func_id);
        drop(func);

        assert!(table.remove_by_id(func_id));
        assert_eq!(table.len(), 0);
        assert!(table.get_by_address(addr).is_none());
    }

    #[test]
    fn stale_id_does_not_remove_reused_slot() {
        let mut table = FunctionTable::new_transient();
        let first_entry = Address::from(0x1000u64);
        let second_entry = Address::from(0x2000u64);
        let first = table
            .insert(first_entry, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();
        assert!(table.remove_by_id(first));

        let second = table
            .insert(second_entry, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();
        assert_eq!(first.index(), second.index());
        assert_ne!(first, second);
        assert!(!table.remove_by_id(first));
        assert_eq!(
            table.get_by_id(second).map(|function| function.entry()),
            Some(second_entry)
        );
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_transient_iter_mut_mutate_reload() {
        let mut table = FunctionTable::new_transient();

        let addrs = [0x1000u64, 0x2000, 0x3000].map(Address::from);
        let ids = addrs
            .iter()
            .map(|&addr| {
                table
                    .insert(addr, |id, entry| Ok(Function::new(id, entry)))
                    .unwrap()
            })
            .collect::<Vec<_>>();

        for mut function in table.iter_mut() {
            function.update_name("renamed");
        }

        for &id in &ids {
            let function = table.get_by_id(id).unwrap();
            assert_eq!(function.name().as_deref(), Some("renamed"));
        }
    }
}
