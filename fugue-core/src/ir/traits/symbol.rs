use std::fmt::Display;
use std::ops::{Deref, DerefMut};

use crate::ir::{Id, Address, Symbol, SymbolEntry, SymbolIndex, SymbolProperties};
use crate::storage::project::FundamentalProjectEntity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SymbolTableSelector(usize);

impl SymbolTableSelector {
    pub const fn new(selector: usize) -> Self {
        Self(selector)
    }

    pub const fn index(&self) -> usize {
        self.0
    }
}

impl Display for SymbolTableSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}", self.0)
    }
}

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

pub trait AsSymbolEntryRef<'a>: AsRef<SymbolEntry> + Deref<Target = SymbolEntry> {}

impl<'a> AsSymbolEntryRef<'a> for &'a SymbolEntry {}

pub trait AsSymbolEntryMut<'a>: AsMut<SymbolEntry> + DerefMut<Target = SymbolEntry> {}

impl<'a> AsSymbolEntryMut<'a> for &'a mut SymbolEntry {}

pub type SymbolEntryItem<T> = (Id<Symbol>, T);
pub type SymbolIndexAndEntryItem<T> = (SymbolIndex, Id<Symbol>, T);

pub trait SymbolTable: FundamentalProjectEntity {
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

    fn insert(
        &mut self,
        index: SymbolIndex,
        address: Address,
        symbol: Symbol,
        properties: SymbolProperties,
    ) -> (bool, Id<Symbol>);

    fn remove(&mut self, symbol: &str) -> usize;
    fn remove_by_address(&mut self, address: Address) -> usize;
    fn remove_by_id(&mut self, id: Id<Symbol>) -> bool;
    fn remove_by_index(&mut self, index: SymbolIndex) -> bool;

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

    fn iter<'a>(&'a self) -> Self::SymbolEntryIter<'a>;
    fn iter_by_selector<'a>(&'a self, selector: SymbolTableSelector) -> Self::SymbolEntryIter<'a>;
    fn iter_by_address<'a>(&'a self) -> Self::SymbolEntryIter<'a>;
    fn iter_by_index<'a>(&'a self) -> Self::SymbolIndexAndEntryIter<'a>;

    fn is_empty(&self) -> bool;
    fn len(&self) -> usize;
}
