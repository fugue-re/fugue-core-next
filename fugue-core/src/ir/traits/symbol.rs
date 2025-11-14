use std::ops::{Deref, DerefMut};

use crate::storage::project::FundamentalProjectEntity;
use crate::{
    ir::{Address, Id, Symbol, SymbolEntry, SymbolIndex, SymbolProperties},
    storage::project::PersistableProjectEntity,
};

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

pub trait SymbolTable: PersistableProjectEntity {
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

pub trait AsSymbolEntryRef<'a>: AsRef<SymbolEntry> + Deref<Target = SymbolEntry> {}

impl<'a> AsSymbolEntryRef<'a> for &'a SymbolEntry {}

pub trait AsSymbolEntryMut<'a>: AsMut<SymbolEntry> + DerefMut<Target = SymbolEntry> {}

impl<'a> AsSymbolEntryMut<'a> for &'a mut SymbolEntry {}

pub type SymbolEntryItem<T> = (Id<Symbol>, T);
pub type SymbolIndexAndEntryItem<T> = (SymbolIndex, Id<Symbol>, T);

pub trait SymbolTable2: FundamentalProjectEntity {
    type SymbolEntryRef<'a>: AsSymbolEntryRef<'a>
    where
        Self: 'a;
    type SymbolEntryMut<'a>: AsSymbolEntryMut<'a>
    where
        Self: 'a;

    type SymbolEntryIter<'a>: Iterator<Item = (Id<Symbol>, Self::SymbolEntryRef<'a>)> + 'a
    where
        Self: 'a;
    type SymbolEntryIterMut<'a>: Iterator<Item = (Id<Symbol>, Self::SymbolEntryMut<'a>)> + 'a
    where
        Self: 'a;

    type SymbolIndexAndEntryIter<'a>: Iterator<Item = (SymbolIndex, Id<Symbol>, Self::SymbolEntryRef<'a>)>
        + 'a
    where
        Self: 'a;

    fn get<'a>(&'a self, symbol: &str) -> Option<Self::SymbolEntryIter<'a>>;
    fn get_mut<'a>(&'a mut self, symbol: &str) -> Option<Self::SymbolEntryIterMut<'a>>;

    fn get_first<'a>(&'a self, symbol: &str) -> Option<(Id<Symbol>, Self::SymbolEntryRef<'a>)> {
        self.get(symbol).and_then(|mut iter| iter.next())
    }

    fn get_first_mut<'a>(
        &'a mut self,
        symbol: &str,
    ) -> Option<(Id<Symbol>, Self::SymbolEntryMut<'a>)> {
        self.get_mut(symbol).and_then(|mut iter| iter.next())
    }

    fn get_by_id<'a>(&'a self, id: Id<Symbol>) -> Option<Self::SymbolEntryRef<'a>>;
    fn get_by_id_mut<'a>(&'a mut self, id: Id<Symbol>) -> Option<Self::SymbolEntryMut<'a>>;

    fn get_by_index<'a>(
        &'a self,
        index: SymbolIndex,
    ) -> Option<(Id<Symbol>, Self::SymbolEntryRef<'a>)>;
    fn get_by_index_mut<'a>(
        &'a mut self,
        index: SymbolIndex,
    ) -> Option<(Id<Symbol>, Self::SymbolEntryMut<'a>)>;

    fn get_by_address<'a>(&'a self, address: Address) -> Self::SymbolEntryIter<'a>;
    fn get_by_address_mut<'a>(&'a mut self, address: Address) -> Self::SymbolEntryIterMut<'a>;

    fn get_first_by_address<'a>(
        &'a self,
        address: Address,
    ) -> Option<(Id<Symbol>, Self::SymbolEntryRef<'a>)> {
        self.get_by_address(address).next()
    }

    fn get_first_by_address_mut<'a>(
        &'a mut self,
        address: Address,
    ) -> Option<(Id<Symbol>, Self::SymbolEntryMut<'a>)> {
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

    fn iter<'a>(&'a self) -> Self::SymbolEntryIter<'a>;
    fn iter_by_selector<'a>(&'a self, selector: usize) -> Self::SymbolEntryIter<'a>;
    fn iter_by_address<'a>(&'a self, address: Address) -> Self::SymbolEntryIter<'a>;
    fn iter_by_index<'a>(&'a self) -> Self::SymbolIndexAndEntryIter<'a>;

    fn is_empty(&self) -> bool;
    fn len(&self) -> usize;
}
