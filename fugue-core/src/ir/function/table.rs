use std::collections::BTreeMap;
use std::mem;

use thiserror::Error;

use crate::ir::{Address, Function, Id};
use crate::storage::entities::schema::ENTITY_FUNCTION_TABLE_ID;
use crate::storage::entities::{Entity, EntityId, ProjectEntity};
use crate::storage::project::{PersistableProjectEntity, ProjectEntityFromStorage};
use crate::storage::{EntityStorage, EntityStorageError};

// A simple function table that maps function addresses to their corresponding
// function IDs.
//
// This implementation is primarily suited to project storage implementations
// that are purely in-memory, i.e., so-called transient storage in our
// nomenclature.
//
// Within the project storage layer, this implementation retreives the entire
// table contents at once on project creation/load, and defers persisting
// changes until the project is explicitly persisted or the owning project is
// dropped.
//
#[derive(Debug, Clone, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FunctionTable {
    addresses: BTreeMap<Address, Id<Function>>,
    functions: Vec<Function>,
    free_ids: Vec<Id<Function>>,
}

impl FunctionTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            addresses: BTreeMap::new(),
            functions: Vec::with_capacity(capacity),
            free_ids: Vec::new(),
        }
    }
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

pub type FunctionRef<'a> = &'a Function;
pub type FunctionMut<'a> = &'a mut Function;

pub struct FunctionIter<'a> {
    inner: Box<dyn Iterator<Item = FunctionRef<'a>> + 'a>,
}

impl<'a> FunctionIter<'a> {
    pub fn new(iter: impl Iterator<Item = FunctionRef<'a>> + 'a) -> Self {
        Self {
            inner: Box::new(iter),
        }
    }
}

impl<'a> Iterator for FunctionIter<'a> {
    type Item = FunctionRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

pub struct FunctionIterMut<'a> {
    inner: Box<dyn Iterator<Item = FunctionMut<'a>> + 'a>,
}

impl<'a> FunctionIterMut<'a> {
    pub fn new(iter: impl Iterator<Item = FunctionMut<'a>> + 'a) -> Self {
        Self {
            inner: Box::new(iter),
        }
    }
}

impl<'a> Iterator for FunctionIterMut<'a> {
    type Item = FunctionMut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl FunctionTable {
    pub fn insert<F>(&mut self, addr: Address, f: F) -> Result<Id<Function>, FunctionTableError>
    where
        F: FnOnce(Id<Function>, Address) -> Result<Function, FunctionTableError>,
    {
        if let Some(existing) = self.get_by_address_mut(addr) {
            let nf = f(existing.id(), addr)?;

            if nf.entry() != addr {
                return Err(FunctionTableError::AddressMismatch);
            }

            *existing = nf;

            return Ok(existing.id());
        }

        let (reuse, id) = if let Some(free_id) = self.free_ids.last().copied() {
            (true, free_id)
        } else {
            (false, Id::new(self.functions.len() as u32))
        };

        let nf = f(id, addr)?;

        if nf.entry() != addr {
            return Err(FunctionTableError::AddressMismatch);
        }

        self.addresses.insert(addr, id);

        if reuse {
            self.free_ids.pop();
            self.functions[id.index()] = nf;
        } else {
            self.functions.push(nf);
        }

        Ok(id)
    }

    pub fn remove_by_id(&mut self, id: Id<Function>) -> bool {
        let Some(f) = self
            .functions
            .get_mut(id.index())
            .filter(|f| f.id().is_valid())
        else {
            return false;
        };

        self.addresses.remove(&f.entry());
        self.free_ids.push(id);

        mem::take(f); // remove the function; replace with default

        true
    }

    pub fn remove_by_address(&mut self, addr: Address) -> bool {
        let Some(id) = self.addresses.remove(&addr) else {
            return false;
        };

        let _ = mem::take(&mut self.functions[id.index()]);
        self.free_ids.push(id);

        true
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.functions.len() - self.free_ids.len()
    }

    pub fn get_by_id(&self, id: Id<Function>) -> Option<FunctionRef> {
        self.functions.get(id.index()).filter(|f| f.id().is_valid())
    }

    pub fn get_by_id_mut(&mut self, id: Id<Function>) -> Option<FunctionMut> {
        self.functions
            .get_mut(id.index())
            .filter(|f| f.id().is_valid())
    }

    pub fn get_by_address(&self, addr: Address) -> Option<FunctionRef> {
        self.addresses
            .get(&addr)
            .copied()
            .and_then(|id| self.get_by_id(id))
    }

    pub fn get_by_address_mut(&mut self, addr: Address) -> Option<FunctionMut> {
        self.addresses
            .get(&addr)
            .copied()
            .and_then(|id| self.get_by_id_mut(id))
    }

    pub fn addresses(&self) -> impl Iterator<Item = Address> + '_ {
        self.addresses.keys().copied()
    }

    pub fn iter(&self) -> FunctionIter<'_> {
        FunctionIter::new(self.functions.iter().filter(|f| f.id().is_valid()))
    }

    pub fn iter_mut(&mut self) -> FunctionIterMut<'_> {
        FunctionIterMut::new(self.functions.iter_mut().filter(|f| f.id().is_valid()))
    }
}

impl Entity for FunctionTable {
    const ID: EntityId = ENTITY_FUNCTION_TABLE_ID;
}

impl ProjectEntityFromStorage for FunctionTable {
    fn from_entity_storage(storage: &EntityStorage) -> Result<Option<Self>, EntityStorageError> {
        storage.get(&ProjectEntity::FunctionTable)
    }

    fn default_from_entity_storage(_storage: &EntityStorage) -> Result<Self, EntityStorageError> {
        Ok(Self::default())
    }
}

impl PersistableProjectEntity for FunctionTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        storage.insert(&ProjectEntity::FunctionTable, self)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_basic_operations() {
        let mut table = FunctionTable::new();

        let addr = Address::from(0x1000);
        let func_id = table
            .insert(addr, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();

        assert_eq!(table.len(), 1);

        let func = table.get_by_address(addr).unwrap();
        assert_eq!(func.id(), func_id);

        assert!(table.remove_by_id(func_id));
        assert_eq!(table.len(), 0);

        assert!(table.get_by_address(addr).is_none());
    }

    #[test]
    fn test_removal_operations() {
        let mut table = FunctionTable::new();

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

        // free list
        assert_eq!(func_id1, func_id3);
        assert!(table.free_ids.is_empty());

        let func_id4 = table
            .insert(addr1, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();

        assert_eq!(table.len(), 3);
        assert_ne!(func_id4, func_id1);

        assert!(table.remove_by_id(func_id2));
        assert_eq!(table.len(), 2);
    }
}
