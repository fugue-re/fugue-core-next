use std::collections::BTreeMap;

use bincode::{Decode, Encode};

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
    functions: Vec<Function>, // TODO: replace with Slab
}

impl IndexedFunctionTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            addresses: BTreeMap::new(),
            functions: Vec::with_capacity(capacity),
        }
    }
}

impl FunctionTableT for IndexedFunctionTable {
    type FunctionRef<'a> = FunctionRef<'a>;
    type FunctionMut<'a> = FunctionMut<'a>;

    type FunctionIter<'a> = FunctionIter<'a>;
    type FunctionIterMut<'a> = FunctionIterMut<'a>;

    fn insert(&mut self, func: Function) {
        let id = Id::new(self.functions.len() as u32);
        self.addresses.insert(func.address(), id);
        self.functions.push(func);
    }

    fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    fn len(&self) -> usize {
        self.functions.len()
    }

    fn get_by_id(&self, id: Id<Function>) -> Option<FunctionRef> {
        self.functions.get(id.index() as usize)
    }

    fn get_by_id_mut(&mut self, id: Id<Function>) -> Option<FunctionMut> {
        self.functions.get_mut(id.index() as usize)
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
        FunctionIter::new(self.functions.iter())
    }

    fn iter_mut<'a>(&'a mut self) -> FunctionIterMut<'a> {
        FunctionIterMut::new(self.functions.iter_mut())
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
