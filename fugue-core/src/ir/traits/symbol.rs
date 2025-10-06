use crate::ir::{Address, Symbol, SymbolEntry, SymbolProperties};
use crate::storage::{EntityStorage, EntityStorageError};

pub struct SymbolIterator<'a> {
    inner: Box<dyn Iterator<Item = SymbolEntry> + 'a>,
}

impl<'a> SymbolIterator<'a> {
    pub fn new(iter: impl Iterator<Item = SymbolEntry> + 'a) -> Self {
        Self {
            inner: Box::new(iter),
        }
    }
}

impl<'a> Iterator for SymbolIterator<'a> {
    type Item = SymbolEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

pub trait SymbolTable {
    fn insert(
        &mut self,
        index: usize,
        addr: Address,
        symbol: Option<Symbol>,
        props: SymbolProperties,
    );

    fn is_empty(&self) -> bool;
    fn len(&self) -> usize;

    fn get_at(&self, addr: Address) -> Option<SymbolEntry>;
    fn get_properties_at(&self, addr: Address) -> Option<SymbolProperties>;

    fn get(&self, sym: &str) -> Option<SymbolEntry>;
    fn get_address(&self, sym: &str) -> Option<Address>;
    fn get_properties(&self, sym: &str) -> Option<SymbolProperties>;

    fn get_by_index(&self, index: usize) -> Option<SymbolEntry>;
    fn get_address_by_index(&self, index: usize) -> Option<Address>;
    fn get_properties_by_index(&self, index: usize) -> Option<SymbolProperties>;

    fn contains_address(&self, addr: Address) -> bool;
    fn contains(&self, sym: &str) -> bool;

    fn iter<'a>(&'a self) -> SymbolIterator<'a>;

    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError>;
}
