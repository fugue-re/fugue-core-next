use std::collections::BTreeMap;
use std::mem;

use bincode::{Decode, Encode};
use thiserror::Error;

use crate::ir::traits::{
    FunctionIter, FunctionIterMut, FunctionMut, FunctionRef, FunctionTable as FunctionTableT,
};
use crate::ir::{Address, Function, Id};
use crate::storage::entities::schema::ENTITY_KEY_FUNCTION_ENTITY_ID;
use crate::storage::entities::{Entity, EntityKeyId, ProjectEntity};
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
#[derive(Debug, Clone, Default, Decode, Encode)]
pub struct IndexedFunctionTable {
    addresses: BTreeMap<Address, Id<Function>>,
    functions: Vec<Function>,
    free_ids: Vec<Id<Function>>,
}

impl IndexedFunctionTable {
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
pub enum IndexedFunctionTableError {
    #[error("function to insert has a different address than that used for insertion")]
    AddressMismatch,
    #[error(transparent)]
    Storage(#[from] EntityStorageError),
}

impl FunctionTableT for IndexedFunctionTable {
    type Error = IndexedFunctionTableError;

    type FunctionRef<'a> = FunctionRef<'a>;
    type FunctionMut<'a> = FunctionMut<'a>;

    type FunctionIter<'a> = FunctionIter<'a>;
    type FunctionIterMut<'a> = FunctionIterMut<'a>;

    fn insert<F, E>(&mut self, addr: Address, f: F) -> Result<Id<Function>, Self::Error>
    where
        F: Fn(Id<Function>, Address) -> Result<Function, Self::Error>,
        E: Into<Self::Error>,
    {
        if let Some(existing) = self.get_by_address_mut(addr) {
            let nf = f(existing.id(), addr)?;

            if nf.entry() != addr {
                return Err(IndexedFunctionTableError::AddressMismatch);
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
            return Err(IndexedFunctionTableError::AddressMismatch);
        }

        self.addresses.insert(addr, id);

        if reuse {
            self.free_ids.pop();
            self.functions[id.index() as usize] = nf;
        } else {
            self.functions.push(nf);
        }

        Ok(id)
    }

    fn remove_by_id(&mut self, id: Id<Function>) -> bool {
        let Some(f) = self
            .functions
            .get_mut(id.index() as usize)
            .filter(|f| f.id().is_valid())
        else {
            return false
        };

        self.addresses.remove(&f.entry());
        self.free_ids.push(id);

        mem::take(f); // remove the function; replace with default

        true
    }

    fn remove_by_address(&mut self, addr: Address) -> bool {
        let Some(id) = self.addresses.remove(&addr) else {
            return false
        };

        let _ = mem::take(&mut self.functions[id.index() as usize]);
        self.free_ids.push(id);

        true
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn len(&self) -> usize {
        self.functions.len() - self.free_ids.len()
    }

    fn get_by_id(&self, id: Id<Function>) -> Option<FunctionRef> {
        self.functions
            .get(id.index() as usize)
            .filter(|f| f.id().is_valid())
    }

    fn get_by_id_mut(&mut self, id: Id<Function>) -> Option<FunctionMut> {
        self.functions
            .get_mut(id.index() as usize)
            .filter(|f| f.id().is_valid())
    }

    fn get_by_address(&self, addr: Address) -> Option<FunctionRef> {
        self.addresses
            .get(&addr)
            .copied()
            .and_then(|id| self.get_by_id(id))
    }

    fn get_by_address_mut(&mut self, addr: Address) -> Option<FunctionMut> {
        self.addresses
            .get(&addr)
            .copied()
            .and_then(|id| self.get_by_id_mut(id))
    }

    fn iter<'a>(&'a self) -> FunctionIter<'a> {
        FunctionIter::new(self.functions.iter().filter(|f| f.id().is_valid()))
    }

    fn iter_mut<'a>(&'a mut self) -> FunctionIterMut<'a> {
        FunctionIterMut::new(self.functions.iter_mut().filter(|f| f.id().is_valid()))
    }
}

impl Entity for IndexedFunctionTable {
    const ID: EntityKeyId = ENTITY_KEY_FUNCTION_ENTITY_ID;
}

impl ProjectEntityFromStorage for IndexedFunctionTable {
    fn from_entity_storage(storage: &EntityStorage) -> Result<Option<Self>, EntityStorageError> {
        storage.get(&ProjectEntity::FunctionTable)
    }

    fn default_from_entity_storage(_storage: &EntityStorage) -> Result<Self, EntityStorageError> {
        Ok(Self::default())
    }
}

impl PersistableProjectEntity for IndexedFunctionTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        storage.insert(&ProjectEntity::FunctionTable, self)
    }
}
