use std::ops::{Deref, DerefMut};

use crate::ir::{Address, CodeBlock, Id};
use crate::lifter::ContextSet;
use crate::storage::project::FundamentalProjectEntity;

pub type CodeBlockRef<'a> = &'a CodeBlock;
pub type CodeBlockMut<'a> = &'a mut CodeBlock;

pub struct CodeBlockIter<'a> {
    inner: Box<dyn Iterator<Item = CodeBlockRef<'a>> + 'a>,
}

impl<'a> CodeBlockIter<'a> {
    pub fn new(iter: impl Iterator<Item = CodeBlockRef<'a>> + 'a) -> Self {
        Self {
            inner: Box::new(iter),
        }
    }
}

impl<'a> Iterator for CodeBlockIter<'a> {
    type Item = CodeBlockRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

pub struct CodeBlockIterMut<'a> {
    inner: Box<dyn Iterator<Item = CodeBlockMut<'a>> + 'a>,
}

impl<'a> CodeBlockIterMut<'a> {
    pub fn new(iter: impl Iterator<Item = CodeBlockMut<'a>> + 'a) -> Self {
        Self {
            inner: Box::new(iter),
        }
    }
}

impl<'a> Iterator for CodeBlockIterMut<'a> {
    type Item = CodeBlockMut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

pub trait AsCodeBlockRef<'a>: AsRef<CodeBlock> + Deref<Target = CodeBlock> {}
impl<'a> AsCodeBlockRef<'a> for CodeBlockRef<'a> {}

pub trait AsCodeBlockMut<'a>: AsMut<CodeBlock> + DerefMut<Target = CodeBlock> {}
impl<'a> AsCodeBlockMut<'a> for CodeBlockMut<'a> {}

pub trait CodeBlockTable: FundamentalProjectEntity {
    type Error: std::error::Error + 'static;

    type CodeBlockRef<'a>: AsCodeBlockRef<'a>
    where
        Self: 'a;
    type CodeBlockMut<'a>: AsCodeBlockMut<'a>
    where
        Self: 'a;

    type CodeBlockIter<'a>: Iterator<Item = Self::CodeBlockRef<'a>> + 'a
    where
        Self: 'a;
    type CodeBlockIterMut<'a>: Iterator<Item = Self::CodeBlockMut<'a>> + 'a
    where
        Self: 'a;

    fn insert<F>(&mut self, addr: Address, f: F) -> Result<Id<CodeBlock>, Self::Error>
    where
        F: Fn(Id<CodeBlock>, Address) -> Result<CodeBlock, Self::Error>;

    fn remove_by_id(&mut self, id: Id<CodeBlock>) -> bool;
    fn remove_by_address(&mut self, addr: Address) -> usize;
    fn remove_by_address_and_context(&mut self, addr: Address, context: &ContextSet) -> usize;

    fn get_by_id<'a>(&'a self, id: Id<CodeBlock>) -> Option<Self::CodeBlockRef<'a>>;
    fn get_by_id_mut<'a>(&'a mut self, id: Id<CodeBlock>) -> Option<CodeBlockMut<'a>>;

    fn get_by_address<'a>(&'a self, addr: Address) -> Self::CodeBlockIter<'a>;
    fn get_by_address_mut<'a>(&'a mut self, addr: Address) -> Self::CodeBlockIterMut<'a>;

    fn get_by_address_and_context<'a>(
        &'a self,
        addr: Address,
        context: &'a ContextSet,
    ) -> Self::CodeBlockIter<'a>;

    fn get_by_address_and_context_mut<'a>(
        &'a mut self,
        addr: Address,
        context: &'a ContextSet,
    ) -> Self::CodeBlockIterMut<'a>;

    fn get_first_by_address<'a>(&'a self, addr: Address) -> Option<Self::CodeBlockRef<'a>> {
        self.get_by_address(addr).next()
    }

    fn get_first_by_address_mut<'a>(&'a mut self, addr: Address) -> Option<Self::CodeBlockMut<'a>> {
        self.get_by_address_mut(addr).next()
    }

    fn get_first_by_address_and_context<'a>(
        &'a self,
        addr: Address,
        context: &'a ContextSet,
    ) -> Option<Self::CodeBlockRef<'a>> {
        self.get_by_address_and_context(addr, context).next()
    }

    fn overlaps<'a>(&'a self, addr: Address) -> Self::CodeBlockIter<'a>;
    fn overlaps_mut<'a>(&'a mut self, addr: Address) -> Self::CodeBlockIterMut<'a>;

    fn contains(&self, addr: Address) -> bool;

    fn iter<'a>(&'a self) -> Self::CodeBlockIter<'a>;
    fn iter_mut<'a>(&'a mut self) -> Self::CodeBlockIterMut<'a>;

    fn is_empty(&self) -> bool;
    fn len(&self) -> usize;
}
