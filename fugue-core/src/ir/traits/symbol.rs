use crate::ir::{Address, SymbolEntry, SymbolProperties};
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

pub trait SymbolTableImpl {
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

pub struct SymbolTable {
    inner: Box<dyn SymbolTableImpl>,
}

impl SymbolTable {
    pub fn new(inner: impl SymbolTableImpl + 'static) -> Self {
        Self {
            inner: Box::new(inner),
        }
    }

    pub fn insert(
        &mut self,
        index: usize,
        addr: impl Into<Address>,
        symbol: impl Into<Option<Symbol>>,
        props: SymbolProperties,
    ) {
        self.inner.insert(index, addr.into(), symbol.into(), props);
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn get_at(&self, addr: impl Into<Address>) -> Option<SymbolEntry> {
        self.inner.get_at(addr.into())
    }

    pub fn get_properties_at(&self, addr: impl Into<Address>) -> Option<SymbolProperties> {
        self.inner.get_properties_at(addr.into())
    }

    pub fn get_address(&self, sym: impl AsRef<str>) -> Option<Address> {
        self.inner.get_address(sym.as_ref())
    }

    pub fn get(&self, sym: impl AsRef<str>) -> Option<SymbolEntry> {
        self.inner.get(sym.as_ref())
    }

    pub fn get_properties(&self, sym: impl AsRef<str>) -> Option<SymbolProperties> {
        self.inner.get_properties(sym.as_ref())
    }

    pub fn get_by_index(&self, index: usize) -> Option<SymbolEntry> {
        self.inner.get_by_index(index)
    }

    pub fn get_address_by_index(&self, index: usize) -> Option<Address> {
        self.inner.get_address_by_index(index)
    }

    pub fn get_properties_by_index(&self, index: usize) -> Option<SymbolProperties> {
        self.inner.get_properties_by_index(index)
    }

    pub fn contains_address(&self, addr: impl Into<Address>) -> bool {
        self.inner.contains_address(addr.into())
    }

    pub fn contains(&self, sym: impl AsRef<str>) -> bool {
        self.inner.contains(sym.as_ref())
    }

    pub fn iter<'a>(&'a self) -> SymbolIterator<'a> {
        self.inner.iter()
    }
}
