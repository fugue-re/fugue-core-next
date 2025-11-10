use crate::ir::{Address, Function, Id};
use crate::storage::entities::PersistableEntity;

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

pub trait FunctionTable: PersistableEntity {
    fn insert(&mut self, func: Function);

    fn is_empty(&self) -> bool;
    fn len(&self) -> usize;

    fn get_by_id(&self, id: Id<Function>) -> Option<FunctionRef>;
    fn get_by_id_mut(&mut self, id: Id<Function>) -> Option<FunctionMut>;

    fn get_by_address(&self, addr: Address) -> Option<FunctionRef>;
    fn get_by_address_mut(&mut self, addr: Address) -> Option<FunctionMut>;

    fn iter<'a>(&'a self) -> FunctionIter<'a>;
    fn iter_mut<'a>(&'a mut self) -> FunctionIterMut<'a>;
}
