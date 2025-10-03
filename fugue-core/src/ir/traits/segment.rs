use std::ops::RangeInclusive;

use crate::ir::{Address, ExternFunctionTemplate, Symbol, SymbolProperties};
use crate::ir::traits::symbol::SymbolTable;

pub struct ExternSegment {
    address: Address,
    alignment: usize,
    symbols: SymbolTable,
    template: ExternFunctionTemplate,
}

impl ExternSegment {
    pub fn add_extern(
        &mut self,
        index: usize,
        addr: impl Into<Address>,
        symbol: impl Into<Option<Symbol>>,
    ) {
        self.add_extern_with(index, addr, symbol, SymbolProperties::EXTERN)
    }

    pub fn add_extern_with(
        &mut self,
        index: usize,
        addr: impl Into<Address>,
        symbol: impl Into<Option<Symbol>>,
        props: SymbolProperties,
    ) {
        let addr = addr.into();
        let sym = symbol.into();

        let sym = sym.and_then(|sym| sym.is_empty().then(|| None).unwrap_or(Some(sym)));

        self.symbols
            .insert(index, addr, sym, props | SymbolProperties::EXTERN);
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn last_address(&self) -> Address {
        if self.symbols.is_empty() {
            self.address()
        } else {
            self.address() + self.size() - 1usize
        }
    }

    pub fn bounds(&self) -> RangeInclusive<Address> {
        self.address()..=self.last_address()
    }

    pub fn alignment(&self) -> usize {
        self.alignment
    }

    pub fn size(&self) -> usize {
        self.symbols.len() * self.aligned_template_size()
    }

    pub fn symbols(&self) -> &SymbolTable {
        &self.symbols
    }

    pub fn template(&self) -> &ExternFunctionTemplate {
        &self.template
    }

    pub fn aligned_template_size(&self) -> usize {
        let template_size = self.template.len();
        (template_size + self.alignment.wrapping_sub(1)) & !self.alignment.wrapping_sub(1)
    }
}
