use crate::ir::traits::{
    FunctionIterator, FunctionIteratorMut, FunctionMut, FunctionRef,
    FunctionTable as FunctionTableT,
};
use crate::ir::{Address, Function, Id};
use crate::storage::entities::PersistableEntity;
use crate::storage::{EntityStorage, EntityStorageError};

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
