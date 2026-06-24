use std::collections::BTreeMap;
use std::sync::Arc;

use thiserror::Error;

use crate::ir::{Address, Function, Id};
use crate::storage::entities::schema::ENTITY_FUNCTION_TABLE_ID;
use crate::storage::entities::{
    Entity, EntityCache, EntityId, EntityMut, EntityRef, ProjectEntity, Ref, RefMut,
    WriteBackWorker,
};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::{EntityStorage, EntityStorageError};

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

pub struct PersistentFunctionTable {
    index: FunctionIndex,
    entries: EntityCache<Id<Function>, Function>,
}

pub struct TransientFunctionTable {
    index: FunctionIndex,
    entries: Vec<Option<Function>>,
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

impl PersistentFunctionTable {
    pub fn new(entities: EntityStorage, cache_bytes: usize) -> Result<Self, EntityStorageError> {
        Self::from_entries(EntityCache::new(entities, cache_bytes)?)
    }

    pub fn new_with(
        entities: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Self::from_entries(EntityCache::with_worker(entities, worker, cache_bytes))
    }

    fn from_entries(
        entries: EntityCache<Id<Function>, Function>,
    ) -> Result<Self, EntityStorageError> {
        let mut addresses = BTreeMap::new();
        let mut free_ids = Vec::new();
        let mut expected = 0u32;

        for entry in entries.try_iter()? {
            let (id, function) = entry?;
            addresses.insert(function.entry(), id);

            let index = id.index() as u32;
            while expected < index {
                free_ids.push(Id::new(expected));
                expected += 1;
            }
            expected = index + 1;
        }

        Ok(Self {
            index: FunctionIndex { addresses, free_ids },
            entries,
        })
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        self.entries.flush()
    }

    pub fn insert<F>(&mut self, addr: Address, f: F) -> Result<Id<Function>, FunctionTableError>
    where
        F: FnOnce(Id<Function>, Address) -> Result<Function, FunctionTableError>,
    {
        if let Some(&existing) = self.index.addresses.get(&addr) {
            let function = f(existing, addr)?;

            if function.entry() != addr {
                return Err(FunctionTableError::AddressMismatch);
            }

            self.entries.put(existing, function);

            return Ok(existing);
        }

        let reuse_id = self.index.free_ids.last().copied();
        let id = reuse_id.unwrap_or_else(|| Id::new(self.index.addresses.len() as u32));

        let function = f(id, addr)?;

        if function.entry() != addr {
            return Err(FunctionTableError::AddressMismatch);
        }

        self.index.addresses.insert(addr, id);

        if reuse_id.is_some() {
            self.index.free_ids.pop();
        }

        self.entries.put(id, function);

        Ok(id)
    }

    pub fn get_by_id(&self, id: Id<Function>) -> Option<EntityRef<'_, Function>> {
        self.try_get_by_id(id).unwrap_or_else(|e| e.into_fatal())
    }

    pub fn try_get_by_id(
        &self,
        id: Id<Function>,
    ) -> Result<Option<EntityRef<'_, Function>>, EntityStorageError> {
        self.entries.try_get(&id)
    }

    pub fn get_by_address(&self, addr: Address) -> Option<EntityRef<'_, Function>> {
        self.try_get_by_address(addr)
            .unwrap_or_else(|e| e.into_fatal())
    }

    pub fn try_get_by_address(
        &self,
        addr: Address,
    ) -> Result<Option<EntityRef<'_, Function>>, EntityStorageError> {
        let Some(&id) = self.index.addresses.get(&addr) else {
            return Ok(None);
        };

        self.entries.try_get(&id)
    }

    pub fn modify_by_id<R>(
        &mut self,
        id: Id<Function>,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Option<R> {
        self.try_modify_by_id(id, f)
            .unwrap_or_else(|e| e.into_fatal())
    }

    pub fn try_modify_by_id<R>(
        &mut self,
        id: Id<Function>,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        self.entries.try_modify(&id, f)
    }

    pub fn modify_by_address<R>(
        &mut self,
        addr: Address,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Option<R> {
        self.try_modify_by_address(addr, f)
            .unwrap_or_else(|e| e.into_fatal())
    }

    pub fn try_modify_by_address<R>(
        &mut self,
        addr: Address,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        let Some(&id) = self.index.addresses.get(&addr) else {
            return Ok(None);
        };

        self.entries.try_modify(&id, f)
    }

    pub fn get_by_id_mut(
        &mut self,
        id: Id<Function>,
    ) -> Option<EntityMut<'_, Function>> {
        self.entries.get_mut(&id)
    }

    pub fn try_get_by_id_mut(
        &mut self,
        id: Id<Function>,
    ) -> Result<Option<EntityMut<'_, Function>>, EntityStorageError> {
        self.entries.try_get_mut(&id)
    }

    pub fn get_by_address_mut(
        &mut self,
        addr: Address,
    ) -> Option<EntityMut<'_, Function>> {
        let id = *self.index.addresses.get(&addr)?;
        self.entries.get_mut(&id)
    }

    pub fn try_get_by_address_mut(
        &mut self,
        addr: Address,
    ) -> Result<Option<EntityMut<'_, Function>>, EntityStorageError> {
        let Some(&id) = self.index.addresses.get(&addr) else {
            return Ok(None);
        };

        self.entries.try_get_mut(&id)
    }

    pub fn remove_by_id(&mut self, id: Id<Function>) -> bool {
        self.try_remove_by_id(id).unwrap_or_else(|e| e.into_fatal())
    }

    pub fn try_remove_by_id(&mut self, id: Id<Function>) -> Result<bool, EntityStorageError> {
        let addr = match self.entries.try_get(&id)? {
            Some(function) => function.entry(),
            None => return Ok(false),
        };

        self.index.addresses.remove(&addr);
        self.index.free_ids.push(id);
        self.entries.try_remove(&id)?;

        Ok(true)
    }

    pub fn remove_by_address(&mut self, addr: Address) -> bool {
        self.try_remove_by_address(addr)
            .unwrap_or_else(|e| e.into_fatal())
    }

    pub fn try_remove_by_address(&mut self, addr: Address) -> Result<bool, EntityStorageError> {
        let Some(id) = self.index.addresses.remove(&addr) else {
            return Ok(false);
        };

        self.index.free_ids.push(id);
        self.entries.try_remove(&id)?;

        Ok(true)
    }

    pub fn addresses(&self) -> impl Iterator<Item = Address> + '_ {
        self.index.addresses.keys().copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = EntityRef<'_, Function>> + '_ {
        self.try_iter()
            .unwrap_or_else(|e| e.into_fatal())
            .map(|entry| entry.unwrap_or_else(|e| e.into_fatal()))
    }

    pub fn try_iter(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<EntityRef<'_, Function>, EntityStorageError>>,
        EntityStorageError,
    > {
        Ok(self
            .entries
            .try_iter()?
            .map(|entry| entry.map(|(_, function)| function)))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = EntityMut<'_, Function>> + '_ {
        self.entries.iter_mut()
    }

    pub fn is_empty(&self) -> bool {
        self.index.addresses.is_empty()
    }

    pub fn len(&self) -> usize {
        self.index.addresses.len()
    }
}

impl Default for TransientFunctionTable {
    fn default() -> Self {
        Self::new()
    }
}

impl TransientFunctionTable {
    pub fn new() -> Self {
        Self {
            index: FunctionIndex {
                addresses: BTreeMap::new(),
                free_ids: Vec::new(),
            },
            entries: Vec::new(),
        }
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        Ok(())
    }

    pub fn insert<F>(&mut self, addr: Address, f: F) -> Result<Id<Function>, FunctionTableError>
    where
        F: FnOnce(Id<Function>, Address) -> Result<Function, FunctionTableError>,
    {
        if let Some(&existing) = self.index.addresses.get(&addr) {
            let function = f(existing, addr)?;

            if function.entry() != addr {
                return Err(FunctionTableError::AddressMismatch);
            }

            self.entries[existing.index()] = Some(function);

            return Ok(existing);
        }

        let reuse_id = self.index.free_ids.last().copied();
        let id = reuse_id.unwrap_or_else(|| Id::new(self.index.addresses.len() as u32));

        let function = f(id, addr)?;

        if function.entry() != addr {
            return Err(FunctionTableError::AddressMismatch);
        }

        self.index.addresses.insert(addr, id);

        if reuse_id.is_some() {
            self.index.free_ids.pop();
        }

        let index = id.index();
        if index >= self.entries.len() {
            self.entries.resize_with(index + 1, || None);
        }
        self.entries[index] = Some(function);

        Ok(id)
    }

    pub fn get_by_id(&self, id: Id<Function>) -> Option<&Function> {
        self.entries.get(id.index())?.as_ref()
    }

    pub fn get_by_address(&self, addr: Address) -> Option<&Function> {
        let id = *self.index.addresses.get(&addr)?;
        self.get_by_id(id)
    }

    pub fn get_by_id_mut(&mut self, id: Id<Function>) -> Option<&mut Function> {
        self.entries.get_mut(id.index())?.as_mut()
    }

    pub fn get_by_address_mut(&mut self, addr: Address) -> Option<&mut Function> {
        let id = *self.index.addresses.get(&addr)?;
        self.get_by_id_mut(id)
    }

    pub fn modify_by_id<R>(
        &mut self,
        id: Id<Function>,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Option<R> {
        self.get_by_id_mut(id).map(f)
    }

    pub fn modify_by_address<R>(
        &mut self,
        addr: Address,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Option<R> {
        self.get_by_address_mut(addr).map(f)
    }

    pub fn remove_by_id(&mut self, id: Id<Function>) -> bool {
        let Some(function) = self.entries.get_mut(id.index()).and_then(Option::take) else {
            return false;
        };

        self.index.addresses.remove(&function.entry());
        self.index.free_ids.push(id);

        true
    }

    pub fn remove_by_address(&mut self, addr: Address) -> bool {
        let Some(id) = self.index.addresses.remove(&addr) else {
            return false;
        };

        if let Some(slot) = self.entries.get_mut(id.index()) {
            *slot = None;
        }
        self.index.free_ids.push(id);

        true
    }

    pub fn addresses(&self) -> impl Iterator<Item = Address> + '_ {
        self.index.addresses.keys().copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Function> + '_ {
        self.entries.iter().filter_map(Option::as_ref)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Function> + '_ {
        self.entries.iter_mut().filter_map(Option::as_mut)
    }

    pub fn is_empty(&self) -> bool {
        self.index.addresses.is_empty()
    }

    pub fn len(&self) -> usize {
        self.index.addresses.len()
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

    fn free_ids(table: &FunctionTable) -> &[Id<Function>] {
        match table {
            FunctionTable::Persistent(p) => &p.index.free_ids,
            FunctionTable::Transient(t) => &t.index.free_ids,
        }
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
        assert!(free_ids(&table).is_empty());

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
    fn test_free_id_reuse_sqlite() {
        use crate::storage::TRANSIENT;
        use crate::storage::entities::SqliteEntityStorage;

        let storage = EntityStorage::new(SqliteEntityStorage::<TRANSIENT>::new().unwrap());
        let mut table = FunctionTable::new(storage, 64 * 1024).unwrap();

        let id0 = table
            .insert(Address::from(0x1000), |id, entry| Ok(Function::new(id, entry)))
            .unwrap();
        let id1 = table
            .insert(Address::from(0x2000), |id, entry| Ok(Function::new(id, entry)))
            .unwrap();
        let id2 = table
            .insert(Address::from(0x3000), |id, entry| Ok(Function::new(id, entry)))
            .unwrap();

        assert_eq!([id0.index(), id1.index(), id2.index()], [0, 1, 2]);

        assert!(table.remove_by_address(Address::from(0x2000)));
        assert_eq!(free_ids(&table), [id1]);

        let reused = table
            .insert(Address::from(0x4000), |id, entry| Ok(Function::new(id, entry)))
            .unwrap();
        assert_eq!(reused, id1);
        assert!(free_ids(&table).is_empty());

        let fresh = table
            .insert(Address::from(0x5000), |id, entry| Ok(Function::new(id, entry)))
            .unwrap();
        assert_eq!(fresh.index(), 3);
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
            .insert(Address::from(0x6000), |id, entry| Ok(Function::new(id, entry)))
            .unwrap();
        let second = table
            .insert(Address::from(0x7000), |id, entry| Ok(Function::new(id, entry)))
            .unwrap();
        let third = table
            .insert(Address::from(0x8000), |id, entry| Ok(Function::new(id, entry)))
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
