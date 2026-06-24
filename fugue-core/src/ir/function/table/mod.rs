use std::collections::BTreeMap;
use std::sync::Arc;

use thiserror::Error;

use crate::ir::{Address, Function, Id};
use crate::storage::entities::schema::ENTITY_FUNCTION_TABLE_ID;
use crate::storage::entities::{Entity, EntityId, ProjectEntity, Ref, RefMut, WriteBackWorker};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::{EntityStorage, EntityStorageError};

mod persistent;
mod transient;

pub use persistent::FunctionTable as PersistentFunctionTable;
pub use transient::FunctionTable as TransientFunctionTable;

pub type FunctionRef<'a> = Ref<'a, Function>;
pub type FunctionMut<'a> = RefMut<'a, Function>;

const FUNCTION_TABLE_VERSION: u32 = 1;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct FunctionTableHeader {
    version: u32,
}

impl Entity for FunctionTableHeader {
    const ID: EntityId = ENTITY_FUNCTION_TABLE_ID;
}

struct FunctionIndex {
    addresses: BTreeMap<Address, Id<Function>>,
    free_ids: Vec<Id<Function>>,
}

pub enum FunctionTable {
    Persistent(PersistentFunctionTable),
    Transient(TransientFunctionTable),
}

#[derive(Debug, Error)]
pub enum FunctionTableError {
    #[error("function to insert has a different address than that used for insertion")]
    AddressMismatch,
    #[error(transparent)]
    Custom(anyhow::Error),
    #[error(transparent)]
    Storage(#[from] EntityStorageError),
}

impl FunctionTableError {
    pub fn custom<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Custom(anyhow::Error::new(error))
    }

    pub fn custom_with<M>(msg: M) -> Self
    where
        M: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    {
        Self::Custom(anyhow::Error::msg(msg))
    }
}

impl FunctionTable {
    pub fn new(entities: EntityStorage, cache_bytes: usize) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentFunctionTable::new(
            entities,
            cache_bytes,
        )?))
    }

    pub fn new_with(
        entities: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentFunctionTable::new_with(
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
        match self {
            Self::Persistent(p) => p.get_by_id(id).map(Ref::Shared),
            Self::Transient(t) => t.get_by_id(id).map(Ref::Borrowed),
        }
    }

    pub fn try_get_by_id(
        &self,
        id: Id<Function>,
    ) -> Result<Option<FunctionRef<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_by_id(id)?.map(Ref::Shared)),
            Self::Transient(t) => Ok(t.get_by_id(id).map(Ref::Borrowed)),
        }
    }

    pub fn get_by_address(&self, addr: Address) -> Option<FunctionRef<'_>> {
        match self {
            Self::Persistent(p) => p.get_by_address(addr).map(Ref::Shared),
            Self::Transient(t) => t.get_by_address(addr).map(Ref::Borrowed),
        }
    }

    pub fn try_get_by_address(
        &self,
        addr: Address,
    ) -> Result<Option<FunctionRef<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_by_address(addr)?.map(Ref::Shared)),
            Self::Transient(t) => Ok(t.get_by_address(addr).map(Ref::Borrowed)),
        }
    }

    pub fn get_by_id_mut(&mut self, id: Id<Function>) -> Option<FunctionMut<'_>> {
        match self {
            Self::Persistent(p) => p.get_by_id_mut(id).map(RefMut::Guard),
            Self::Transient(t) => t.get_by_id_mut(id).map(RefMut::Borrowed),
        }
    }

    pub fn try_get_by_id_mut(
        &mut self,
        id: Id<Function>,
    ) -> Result<Option<FunctionMut<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_by_id_mut(id)?.map(RefMut::Guard)),
            Self::Transient(t) => Ok(t.get_by_id_mut(id).map(RefMut::Borrowed)),
        }
    }

    pub fn get_by_address_mut(&mut self, addr: Address) -> Option<FunctionMut<'_>> {
        match self {
            Self::Persistent(p) => p.get_by_address_mut(addr).map(RefMut::Guard),
            Self::Transient(t) => t.get_by_address_mut(addr).map(RefMut::Borrowed),
        }
    }

    pub fn try_get_by_address_mut(
        &mut self,
        addr: Address,
    ) -> Result<Option<FunctionMut<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_by_address_mut(addr)?.map(RefMut::Guard)),
            Self::Transient(t) => Ok(t.get_by_address_mut(addr).map(RefMut::Borrowed)),
        }
    }

    pub fn modify_by_id<R>(
        &mut self,
        id: Id<Function>,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Option<R> {
        match self {
            Self::Persistent(p) => p.modify_by_id(id, f),
            Self::Transient(t) => t.modify_by_id(id, f),
        }
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
        match self {
            Self::Persistent(p) => p.modify_by_address(addr, f),
            Self::Transient(t) => t.modify_by_address(addr, f),
        }
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
        match self {
            Self::Persistent(p) => p.remove_by_id(id),
            Self::Transient(t) => t.remove_by_id(id),
        }
    }

    pub fn try_remove_by_id(&mut self, id: Id<Function>) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_remove_by_id(id),
            Self::Transient(t) => Ok(t.remove_by_id(id)),
        }
    }

    pub fn remove_by_address(&mut self, addr: Address) -> bool {
        match self {
            Self::Persistent(p) => p.remove_by_address(addr),
            Self::Transient(t) => t.remove_by_address(addr),
        }
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

    pub fn iter(&self) -> Box<dyn Iterator<Item = FunctionRef<'_>> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.iter().map(Ref::Shared)),
            Self::Transient(t) => Box::new(t.iter().map(Ref::Borrowed)),
        }
    }

    pub fn iter_mut(&mut self) -> Box<dyn Iterator<Item = FunctionMut<'_>> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.iter_mut().map(RefMut::Guard)),
            Self::Transient(t) => Box::new(t.iter_mut().map(RefMut::Borrowed)),
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
    use super::*;
    use crate::storage::entities::InMemoryEntityStorage;

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

        assert_eq!(func_id1, func_id3);

        let func_id4 = table
            .insert(addr1, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();

        assert_eq!(table.len(), 3);
        assert_ne!(func_id4, func_id1);

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
            let mut table = FunctionTable::new_with(storage.clone(), worker, 64 * 1024).unwrap();
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
        let table = FunctionTable::new_with(storage, worker, 64 * 1024).unwrap();
        assert_eq!(table.len(), 2);
        assert!(table.get_by_address(Address::from(0x1000)).is_some());
        assert!(table.get_by_address(Address::from(0x2000)).is_some());
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn test_free_id_rebuild_on_reopen_sqlite() {
        use tempfile::TempDir;

        use crate::storage::PERSISTENT;
        use crate::storage::entities::SqliteEntityStorage;

        let dir = TempDir::new().unwrap();

        {
            let storage =
                EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
            let worker = WriteBackWorker::new(storage.clone()).unwrap();
            let mut table = FunctionTable::new_with(storage, worker, 64 * 1024).unwrap();

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
        let mut table = FunctionTable::new_with(storage, worker, 64 * 1024).unwrap();

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

        assert_eq!([first.index(), second.index(), third.index()], [3, 1, 5]);
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
