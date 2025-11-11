use crate::ir::{Address, CodeBlock, Id};
use crate::lifter::ContextSet;
use crate::storage::project::PersistableProjectEntity;

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

pub trait CodeBlockTable: PersistableProjectEntity {
    fn insert(&mut self, func: CodeBlock);

    fn is_empty(&self) -> bool;
    fn len(&self) -> usize;

    fn get_by_id(&self, id: Id<CodeBlock>) -> Option<CodeBlockRef>;
    fn get_by_id_mut(&mut self, id: Id<CodeBlock>) -> Option<CodeBlockMut>;

    fn get_by_address(&self, addr: Address) -> CodeBlockIter<'_>;
    fn get_by_address_mut(&mut self, addr: Address) -> CodeBlockIterMut<'_>;

    fn get_by_address_and_context<'a>(
        &'a self,
        addr: Address,
        context: &'a ContextSet,
    ) -> CodeBlockIter<'a> {
        CodeBlockIter::new(
            self.get_by_address(addr)
                .filter(move |blk| blk.context() == context),
        )
    }

    fn get_by_address_and_context_mut<'a>(
        &'a mut self,
        addr: Address,
        context: &'a ContextSet,
    ) -> CodeBlockIterMut<'a> {
        CodeBlockIterMut::new(
            self.get_by_address_mut(addr)
                .filter(move |blk| blk.context() == context),
        )
    }

    fn get_first_by_address(&self, addr: Address) -> Option<CodeBlockRef> {
        self.get_by_address(addr).next()
    }

    fn get_first_by_address_mut(&mut self, addr: Address) -> Option<CodeBlockMut> {
        self.get_by_address_mut(addr).next()
    }

    fn overlaps<'a>(&'a self, addr: Address) -> CodeBlockIter<'a>;
    fn overlaps_mut<'a>(&'a mut self, addr: Address) -> CodeBlockIterMut<'a>;

    fn contains(&self, addr: Address) -> bool;

    fn iter<'a>(&'a self) -> CodeBlockIter<'a>;
    fn iter_mut<'a>(&'a mut self) -> CodeBlockIterMut<'a>;
}
