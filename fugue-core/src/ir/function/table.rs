use std::collections::BTreeMap;

use bincode::{Decode, Encode};

use crate::ir::traits::{
    FunctionIterator, FunctionIteratorMut, FunctionMut, FunctionRef,
    FunctionTable as FunctionTableT,
};
use crate::ir::{Address, Function, Id};
use crate::storage::entities::common::ENTITY_KEY_FUNCTION_ENTITY_ID;
use crate::storage::entities::{
    DefaultFromEntityStorage, Entity, EntityKeyId, PersistableEntity, ProjectEntity,
};
use crate::storage::{EntityStorage, EntityStorageError};

#[derive(Debug, Clone, Default, Decode, Encode)]
pub struct IndexedFunctionTable {
    addresses: BTreeMap<Address, Id<Function>>,
    functions: Vec<Function>,
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

    fn iter<'a>(&'a self) -> FunctionIterator<'a> {
        FunctionIterator::new(self.functions.iter())
    }

    fn iter_mut<'a>(&'a mut self) -> FunctionIteratorMut<'a> {
        FunctionIteratorMut::new(self.functions.iter_mut())
    }
}

impl Entity for IndexedFunctionTable {
    const ID: EntityKeyId = ENTITY_KEY_FUNCTION_ENTITY_ID;
}

impl DefaultFromEntityStorage for IndexedFunctionTable {
    fn default_from_entity_storage(_storage: &EntityStorage) -> Result<Self, EntityStorageError> {
        Ok(Self::default())
    }
}

impl PersistableEntity for IndexedFunctionTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        storage.insert(&ProjectEntity::FunctionTable, self)
    }
}

pub struct FunctionTable {
    inner: Box<dyn FunctionTableT>,
}

impl FunctionTable {
    pub fn new(inner: impl FunctionTableT + 'static) -> Self {
        Self {
            inner: Box::new(inner),
        }
    }

    pub fn insert(&mut self, func: Function) {
        self.inner.insert(func);
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn get_by_id(&self, id: Id<Function>) -> Option<FunctionRef> {
        self.inner.get_by_id(id)
    }

    pub fn get_by_id_mut(&mut self, id: Id<Function>) -> Option<FunctionMut> {
        self.inner.get_by_id_mut(id)
    }

    pub fn get_by_address(&self, addr: impl Into<Address>) -> Option<FunctionRef> {
        self.inner.get_by_address(addr.into())
    }

    pub fn get_by_address_mut(&mut self, addr: impl Into<Address>) -> Option<FunctionMut> {
        self.inner.get_by_address_mut(addr.into())
    }

    pub fn iter<'a>(&'a self) -> FunctionIterator<'a> {
        self.inner.iter()
    }

    pub fn iter_mut<'a>(&'a mut self) -> FunctionIteratorMut<'a> {
        self.inner.iter_mut()
    }
}

impl PersistableEntity for FunctionTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        self.inner.persist(storage)
    }
}
