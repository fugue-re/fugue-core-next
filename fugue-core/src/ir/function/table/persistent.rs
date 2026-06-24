use std::collections::BTreeMap;
use std::sync::Arc;

use super::{FunctionIndex, FunctionTableError};
use crate::ir::{Address, Function, Id};
use crate::storage::entities::{EntityCache, EntityMut, EntityRef, WriteBackWorker};
use crate::storage::{EntityStorage, EntityStorageError};

type Ref<'a> = EntityRef<'a, Function>;
type RefMut<'a> = EntityMut<'a, Function>;

pub struct FunctionTable {
    index: FunctionIndex,
    entries: EntityCache<Id<Function>, Function>,
}

impl FunctionTable {
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
            index: FunctionIndex {
                addresses,
                free_ids,
            },
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

    pub fn get_by_id(&self, id: Id<Function>) -> Option<Ref<'_>> {
        self.try_get_by_id(id).unwrap_or_else(|e| e.into_fatal())
    }

    pub fn try_get_by_id(&self, id: Id<Function>) -> Result<Option<Ref<'_>>, EntityStorageError> {
        self.entries.try_get(&id)
    }

    pub fn get_by_address(&self, addr: Address) -> Option<Ref<'_>> {
        self.try_get_by_address(addr)
            .unwrap_or_else(|e| e.into_fatal())
    }

    pub fn try_get_by_address(&self, addr: Address) -> Result<Option<Ref<'_>>, EntityStorageError> {
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

    pub fn get_by_id_mut(&mut self, id: Id<Function>) -> Option<RefMut<'_>> {
        self.entries.get_mut(&id)
    }

    pub fn try_get_by_id_mut(
        &mut self,
        id: Id<Function>,
    ) -> Result<Option<RefMut<'_>>, EntityStorageError> {
        self.entries.try_get_mut(&id)
    }

    pub fn get_by_address_mut(&mut self, addr: Address) -> Option<RefMut<'_>> {
        let id = *self.index.addresses.get(&addr)?;
        self.entries.get_mut(&id)
    }

    pub fn try_get_by_address_mut(
        &mut self,
        addr: Address,
    ) -> Result<Option<RefMut<'_>>, EntityStorageError> {
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

    pub fn iter(&self) -> impl Iterator<Item = Ref<'_>> + '_ {
        self.try_iter()
            .unwrap_or_else(|e| e.into_fatal())
            .map(|entry| entry.unwrap_or_else(|e| e.into_fatal()))
    }

    pub fn try_iter(
        &self,
    ) -> Result<impl Iterator<Item = Result<Ref<'_>, EntityStorageError>>, EntityStorageError> {
        Ok(self
            .entries
            .try_iter()?
            .map(|entry| entry.map(|(_, function)| function)))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = RefMut<'_>> + '_ {
        self.entries.iter_mut()
    }

    pub fn is_empty(&self) -> bool {
        self.index.addresses.is_empty()
    }

    pub fn len(&self) -> usize {
        self.index.addresses.len()
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod test {
    use super::*;

    #[test]
    fn test_free_id_reuse_sqlite() {
        use crate::storage::TRANSIENT;
        use crate::storage::entities::SqliteEntityStorage;

        let storage = EntityStorage::new(SqliteEntityStorage::<TRANSIENT>::new().unwrap());
        let mut table = FunctionTable::new(storage, 64 * 1024).unwrap();

        let id0 = table
            .insert(Address::from(0x1000), |id, entry| {
                Ok(Function::new(id, entry))
            })
            .unwrap();
        let id1 = table
            .insert(Address::from(0x2000), |id, entry| {
                Ok(Function::new(id, entry))
            })
            .unwrap();
        let id2 = table
            .insert(Address::from(0x3000), |id, entry| {
                Ok(Function::new(id, entry))
            })
            .unwrap();

        assert_eq!([id0.index(), id1.index(), id2.index()], [0, 1, 2]);

        assert!(table.remove_by_address(Address::from(0x2000)));
        assert_eq!(table.index.free_ids, [id1]);

        let reused = table
            .insert(Address::from(0x4000), |id, entry| {
                Ok(Function::new(id, entry))
            })
            .unwrap();
        assert_eq!(reused, id1);
        assert!(table.index.free_ids.is_empty());

        let fresh = table
            .insert(Address::from(0x5000), |id, entry| {
                Ok(Function::new(id, entry))
            })
            .unwrap();
        assert_eq!(fresh.index(), 3);
    }
}
