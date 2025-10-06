use crate::ir::traits::{
    FunctionIterator, FunctionIteratorMut, FunctionMut, FunctionRef,
    FunctionTable as FunctionTableT,
};
use crate::ir::{Address, Function, Id};
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

    pub fn get(&self, id: Id<Function>) -> Option<FunctionRef> {
        self.inner.get(id)
    }

    pub fn get_mut(&mut self, id: Id<Function>) -> Option<FunctionMut> {
        self.inner.get_mut(id)
    }

    pub fn get_at(&self, addr: Address) -> Option<FunctionRef> {
        self.inner.get_at(addr)
    }

    pub fn get_mut_at(&mut self, addr: Address) -> Option<FunctionMut> {
        self.inner.get_mut_at(addr)
    }

    pub fn iter<'a>(&'a self) -> FunctionIterator<'a> {
        self.inner.iter()
    }

    pub fn iter_mut<'a>(&'a mut self) -> FunctionIteratorMut<'a> {
        self.inner.iter_mut()
    }

    pub fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        self.inner.persist(storage)
    }
}
