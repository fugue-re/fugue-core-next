use std::ops::{Deref, DerefMut};

use crate::ir::{Address, Function, Id};
use crate::storage::project::FundamentalProjectEntity;

pub type FunctionRef<'a> = &'a Function; // EntityRef<'a, Function>;
pub type FunctionMut<'a> = &'a mut Function; // EntityMut<'a, Id<Function>, Function>;

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

pub trait AsFunctionRef<'a>: AsRef<Function> + Deref<Target = Function> {}
impl<'a> AsFunctionRef<'a> for FunctionRef<'a> {}

pub trait AsFunctionMut<'a>: AsMut<Function> + DerefMut<Target = Function> {}
impl<'a> AsFunctionMut<'a> for FunctionMut<'a> {}

// NOTE: since a function table interacts with the underlying entity storage, it's possible that
// operations on the function table may fail due to storage-related issues; within the context of
// the framework, these errors are essentially unrecoverable--what could be sensibly done if the
// underlying storage is non-functional? Therefore, we expect errors to be logged and a panic
// issued, an alternative would be to mask the errors by returning None/false values.
//
// It may be worth revisiting this decision in the future, but for now, this seems like the most
// pragmatic approach to allow a fluent API, since storage errors should not really occur in
// practice--they should be handled lower down the stack, e.g., by retries, etc.
//
pub trait FunctionTable: FundamentalProjectEntity {
    type Error: std::error::Error + Send + Sync + 'static;

    type FunctionRef<'a>: AsFunctionRef<'a>
    where
        Self: 'a;
    type FunctionMut<'a>: AsFunctionMut<'a>
    where
        Self: 'a;

    type FunctionIter<'a>: Iterator<Item = Self::FunctionRef<'a>> + 'a
    where
        Self: 'a;
    type FunctionIterMut<'a>: Iterator<Item = Self::FunctionMut<'a>> + 'a
    where
        Self: 'a;

    fn insert<F>(&mut self, addr: Address, f: F) -> Result<Id<Function>, Self::Error>
    where
        F: FnOnce(Id<Function>, Address) -> Result<Function, Self::Error>;

    fn remove_by_id(&mut self, id: Id<Function>) -> bool;
    fn remove_by_address(&mut self, addr: Address) -> bool;

    fn get_by_id<'a>(&'a self, id: Id<Function>) -> Option<Self::FunctionRef<'a>>;
    fn get_by_id_mut<'a>(&'a mut self, id: Id<Function>) -> Option<Self::FunctionMut<'a>>;

    fn get_by_address<'a>(&'a self, addr: Address) -> Option<Self::FunctionRef<'a>>;
    fn get_by_address_mut<'a>(&'a mut self, addr: Address) -> Option<Self::FunctionMut<'a>>;

    fn addresses<'a>(&'a self) -> impl Iterator<Item = Address> + 'a;

    fn iter<'a>(&'a self) -> Self::FunctionIter<'a>;
    fn iter_mut<'a>(&'a mut self) -> Self::FunctionIterMut<'a>;

    fn is_empty(&self) -> bool;
    fn len(&self) -> usize;
}
