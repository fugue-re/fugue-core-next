use std::ops::RangeInclusive;

use crate::ir::{Address, ExternFunctionTemplate, Symbol, SymbolEntry, SymbolProperties};

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
    fn add_symbol(
        &mut self,
        index: usize,
        addr: Address,
        symbol: Option<Symbol>,
        props: SymbolProperties,
    );

    fn address(&self) -> Address;

    fn last_address(&self) -> Address {
        if self.is_empty() {
            self.address()
        } else {
            self.address() + self.size() - 1usize
        }
    }

    fn bounds(&self) -> RangeInclusive<Address> {
        self.address()..=self.last_address()
    }

    fn alignment(&self) -> usize;
    fn size(&self) -> usize;

    fn is_empty(&self) -> bool;
    fn len(&self) -> usize;

    fn symbol_at(&self, addr: Address) -> Option<(Option<Symbol>, SymbolProperties)>;
    fn symbol_properties_at(&self, addr: Address) -> Option<SymbolProperties>;

    fn symbol_address(&self, sym: &str) -> Option<Address>;
    fn symbol_properties(&self, sym: &str) -> Option<SymbolProperties>;

    fn symbol_by_index(&self, index: usize) -> Option<Symbol>;
    fn symbol_address_by_index(&self, index: usize) -> Option<Address>;
    fn symbol_properties_by_index(&self, index: usize) -> Option<SymbolProperties>;
    fn symbol_with_properties_by_index(
        &self,
        index: usize,
    ) -> Option<(Option<Symbol>, SymbolProperties)>;

    fn contains_address(&self, addr: Address) -> bool;
    fn contains_symbol(&self, sym: &str) -> bool;

    fn iter<'a>(&'a self) -> SymbolIterator<'a>;
}

pub trait ExternSymbolTableImpl: SymbolTableImpl {
    fn template(&self) -> &ExternFunctionTemplate;
    fn aligned_template_size(&self) -> usize {
        let template_size = self.template().len();
        (template_size + self.alignment().wrapping_sub(1)) & !self.alignment().wrapping_sub(1)
    }
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

    pub fn add_symbol(
        &mut self,
        index: usize,
        addr: impl Into<Address>,
        symbol: impl Into<Option<Symbol>>,
        props: SymbolProperties,
    ) {
        self.inner
            .add_symbol(index, addr.into(), symbol.into(), props);
    }

    pub fn address(&self) -> Address {
        self.inner.address()
    }

    pub fn last_address(&self) -> Address {
        if self.is_empty() {
            self.address()
        } else {
            self.address() + self.size() - 1usize
        }
    }

    pub fn bounds(&self) -> RangeInclusive<Address> {
        self.inner.address()..=self.last_address()
    }

    pub fn alignment(&self) -> usize {
        self.inner.alignment()
    }

    pub fn size(&self) -> usize {
        self.inner.size()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn symbol_at(
        &self,
        addr: impl Into<Address>,
    ) -> Option<(Option<Symbol>, SymbolProperties)> {
        self.inner.symbol_at(addr.into())
    }

    pub fn symbol_properties_at(&self, addr: impl Into<Address>) -> Option<SymbolProperties> {
        self.inner.symbol_properties_at(addr.into())
    }

    pub fn symbol_address(&self, sym: impl AsRef<str>) -> Option<Address> {
        self.inner.symbol_address(sym.as_ref())
    }

    pub fn symbol_properties(&self, sym: impl AsRef<str>) -> Option<SymbolProperties> {
        self.inner.symbol_properties(sym.as_ref())
    }

    pub fn symbol_by_index(&self, index: usize) -> Option<Symbol> {
        self.inner.symbol_by_index(index)
    }

    pub fn symbol_address_by_index(&self, index: usize) -> Option<Address> {
        self.inner.symbol_address_by_index(index)
    }

    pub fn symbol_properties_by_index(&self, index: usize) -> Option<SymbolProperties> {
        self.inner.symbol_properties_by_index(index)
    }

    pub fn symbol_with_properties_by_index(
        &self,
        index: usize,
    ) -> Option<(Option<Symbol>, SymbolProperties)> {
        self.inner.symbol_with_properties_by_index(index)
    }

    pub fn contains_address(&self, addr: impl Into<Address>) -> bool {
        self.inner.contains_address(addr.into())
    }

    pub fn contains_symbol(&self, sym: impl AsRef<str>) -> bool {
        self.inner.contains_symbol(sym.as_ref())
    }

    pub fn iter<'a>(&'a self) -> SymbolIterator<'a> {
        self.inner.iter()
    }
}

pub struct ExternSymbolTable {
    inner: Box<dyn ExternSymbolTableImpl>,
}

impl ExternSymbolTable {
    pub fn new(inner: impl ExternSymbolTableImpl + 'static) -> Self {
        Self {
            inner: Box::new(inner),
        }
    }

    pub fn add_symbol(
        &mut self,
        index: usize,
        addr: impl Into<Address>,
        symbol: impl Into<Option<Symbol>>,
        props: SymbolProperties,
    ) {
        self.inner
            .add_symbol(index, addr.into(), symbol.into(), props);
    }

    pub fn address(&self) -> Address {
        self.inner.address()
    }

    pub fn last_address(&self) -> Address {
        self.inner.last_address()
    }

    pub fn bounds(&self) -> RangeInclusive<Address> {
        self.inner.bounds()
    }

    pub fn alignment(&self) -> usize {
        self.inner.alignment()
    }

    pub fn size(&self) -> usize {
        self.inner.size()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn symbol_at(
        &self,
        addr: impl Into<Address>,
    ) -> Option<(Option<Symbol>, SymbolProperties)> {
        self.inner.symbol_at(addr.into())
    }

    pub fn symbol_properties_at(&self, addr: impl Into<Address>) -> Option<SymbolProperties> {
        self.inner.symbol_properties_at(addr.into())
    }

    pub fn symbol_address(&self, sym: impl AsRef<str>) -> Option<Address> {
        self.inner.symbol_address(sym.as_ref())
    }

    pub fn symbol_properties(&self, sym: impl AsRef<str>) -> Option<SymbolProperties> {
        self.inner.symbol_properties(sym.as_ref())
    }

    pub fn symbol_by_index(&self, index: usize) -> Option<Symbol> {
        self.inner.symbol_by_index(index)
    }

    pub fn symbol_address_by_index(&self, index: usize) -> Option<Address> {
        self.inner.symbol_address_by_index(index)
    }

    pub fn symbol_properties_by_index(&self, index: usize) -> Option<SymbolProperties> {
        self.inner.symbol_properties_by_index(index)
    }

    pub fn symbol_with_properties_by_index(
        &self,
        index: usize,
    ) -> Option<(Option<Symbol>, SymbolProperties)> {
        self.inner.symbol_with_properties_by_index(index)
    }

    pub fn contains_address(&self, addr: impl Into<Address>) -> bool {
        self.inner.contains_address(addr.into())
    }

    pub fn contains_symbol(&self, sym: impl AsRef<str>) -> bool {
        self.inner.contains_symbol(sym.as_ref())
    }

    pub fn iter<'a>(&'a self) -> SymbolIterator<'a> {
        self.inner.iter()
    }

    pub fn template(&self) -> &ExternFunctionTemplate {
        self.inner.template()
    }

    pub fn aligned_template_size(&self) -> usize {
        self.inner.aligned_template_size()
    }
}
