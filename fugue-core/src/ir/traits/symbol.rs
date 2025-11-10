use crate::ir::{Address, Id, Symbol, SymbolEntry, SymbolIndex, SymbolProperties};
use crate::storage::entities::PersistableEntity;

pub struct SymbolEntryIter<'a> {
    inner: Box<dyn Iterator<Item = (Id<Symbol>, &'a SymbolEntry)> + 'a>,
}

impl<'a> SymbolEntryIter<'a> {
    pub fn new(iter: impl Iterator<Item = (Id<Symbol>, &'a SymbolEntry)> + 'a) -> Self {
        Self {
            inner: Box::new(iter),
        }
    }
}

impl<'a> Iterator for SymbolEntryIter<'a> {
    type Item = (Id<Symbol>, &'a SymbolEntry);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

pub struct SymbolEntryIterMut<'a> {
    inner: Box<dyn Iterator<Item = (Id<Symbol>, &'a mut SymbolEntry)> + 'a>,
}

impl<'a> SymbolEntryIterMut<'a> {
    pub fn new(iter: impl Iterator<Item = (Id<Symbol>, &'a mut SymbolEntry)> + 'a) -> Self {
        Self {
            inner: Box::new(iter),
        }
    }
}

impl<'a> Iterator for SymbolEntryIterMut<'a> {
    type Item = (Id<Symbol>, &'a mut SymbolEntry);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

pub struct SymbolIndexAndEntryIter<'a> {
    inner: Box<dyn Iterator<Item = (SymbolIndex, Id<Symbol>, &'a SymbolEntry)> + 'a>,
}

impl<'a> SymbolIndexAndEntryIter<'a> {
    pub fn new(
        iter: impl Iterator<Item = (SymbolIndex, Id<Symbol>, &'a SymbolEntry)> + 'a,
    ) -> Self {
        Self {
            inner: Box::new(iter),
        }
    }
}

impl<'a> Iterator for SymbolIndexAndEntryIter<'a> {
    type Item = (SymbolIndex, Id<Symbol>, &'a SymbolEntry);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

pub trait SymbolTable: PersistableEntity {
    fn get(&self, symbol: &str) -> Option<SymbolEntryIter<'_>>;
    fn get_mut(&mut self, symbol: &str) -> Option<SymbolEntryIterMut<'_>>;

    fn get_first(&self, symbol: &str) -> Option<(Id<Symbol>, &SymbolEntry)> {
        self.get(symbol).and_then(|mut iter| iter.next())
    }

    fn get_first_mut(&mut self, symbol: &str) -> Option<(Id<Symbol>, &mut SymbolEntry)> {
        self.get_mut(symbol).and_then(|mut iter| iter.next())
    }

    fn get_by_id(&self, id: Id<Symbol>) -> Option<&SymbolEntry>;
    fn get_by_id_mut(&mut self, id: Id<Symbol>) -> Option<&mut SymbolEntry>;

    fn get_by_index(&self, index: SymbolIndex) -> Option<(Id<Symbol>, &SymbolEntry)>;
    fn get_by_index_mut(&mut self, index: SymbolIndex) -> Option<(Id<Symbol>, &mut SymbolEntry)>;

    fn get_by_address(&self, address: Address) -> SymbolEntryIter<'_>;
    fn get_by_address_mut(&mut self, address: Address) -> SymbolEntryIterMut<'_>;

    fn get_first_by_address(&self, address: Address) -> Option<(Id<Symbol>, &SymbolEntry)> {
        self.get_by_address(address).next()
    }

    fn get_first_by_address_mut(
        &mut self,
        address: Address,
    ) -> Option<(Id<Symbol>, &mut SymbolEntry)> {
        self.get_by_address_mut(address).next()
    }

    fn contains(&self, symbol: &str) -> bool;
    fn contains_index(&self, index: SymbolIndex) -> bool;
    fn contains_address(&self, address: Address) -> bool;

    fn insert(
        &mut self,
        index: SymbolIndex,
        address: Address,
        symbol: Symbol,
        properties: SymbolProperties,
    ) -> (bool, Id<Symbol>);

    fn iter(&self) -> SymbolEntryIter<'_>;
    fn iter_by_selector(&self, selector: usize) -> SymbolEntryIter<'_>;
    fn iter_by_address(&self, address: Address) -> SymbolEntryIter<'_>;
    fn iter_by_index(&self) -> SymbolIndexAndEntryIter<'_>;

    fn is_empty(&self) -> bool;
    fn len(&self) -> usize;
}
