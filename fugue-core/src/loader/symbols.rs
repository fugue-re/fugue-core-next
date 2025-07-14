use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::ops::RangeInclusive;

use bincode::{Decode, Encode};
use smallvec::SmallVec;

pub use ustr::{Ustr as Symbol, UstrMap as SymbolMap};

use crate::lifter::ContextSet;
use crate::storage::entities::common::{ENTITY_EXTERN_SYMBOLS_ID, ENTITY_LOCAL_SYMBOLS_ID};
use crate::storage::entities::{Entity, EntityId};
use crate::types::Address;

#[derive(Debug, Clone)]
pub struct ExternFunctionTemplate {
    bytes: SmallVec<[u8; 16]>,
    context: ContextSet,
}

impl<T> From<T> for ExternFunctionTemplate
where
    T: AsRef<[u8]>,
{
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl Encode for ExternFunctionTemplate {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.bytes.len().encode(encoder)?;
        for b in &self.bytes {
            b.encode(encoder)?;
        }
        self.context.encode(encoder)?;
        Ok(())
    }
}

impl<C> Decode<C> for ExternFunctionTemplate {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let bytes_len = usize::decode(decoder)?;
        let mut bytes = SmallVec::<[u8; 16]>::with_capacity(bytes_len);
        for _ in 0..bytes_len {
            let b = u8::decode(decoder)?;
            bytes.push(b);
        }
        let context = ContextSet::decode(decoder)?;
        Ok(Self { bytes, context })
    }
}

impl ExternFunctionTemplate {
    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        Self::new_with(bytes, ContextSet::default())
    }

    pub fn new_with(bytes: impl AsRef<[u8]>, context: ContextSet) -> Self {
        Self {
            bytes: SmallVec::from_slice(bytes.as_ref()),
            context,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn context(&self) -> &ContextSet {
        &self.context
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolEntry {
    address: Address,
    symbol: Option<Symbol>,
    properties: SymbolProperties,
}

impl Display for SymbolEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(sym) = &self.symbol {
            write!(f, "{sym} at {}; {}", self.address, self.properties)
        } else {
            write!(f, "<unnamed> at {}; {}", self.address, self.properties)
        }
    }
}

impl SymbolEntry {
    pub fn new(
        address: Address,
        symbol: impl Into<Option<Symbol>>,
        properties: SymbolProperties,
    ) -> Self {
        Self {
            address,
            symbol: symbol.into(),
            properties,
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn symbol(&self) -> Option<&Symbol> {
        self.symbol.as_ref()
    }

    pub fn properties(&self) -> SymbolProperties {
        self.properties
    }

    pub fn is_extern(&self) -> bool {
        self.properties.is_extern()
    }

    pub fn is_local(&self) -> bool {
        self.properties.is_local()
    }

    pub fn is_function(&self) -> bool {
        self.properties.is_function()
    }

    pub fn is_data(&self) -> bool {
        self.properties.is_data()
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SymbolProperties: u8 {
        const NONE     = 0b0000_0000;
        const EXTERN   = 0b0000_0001;
        const LOCAL    = 0b0000_0010;
        const FUNCTION = 0b0000_0100;
        const DATA     = 0b0000_1000;
    }
}

impl<C> Decode<C> for SymbolProperties {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let value = u8::decode(decoder)?;
        Ok(SymbolProperties::from_bits_truncate(value))
    }
}

impl Encode for SymbolProperties {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.bits().encode(encoder)
    }
}

impl Display for SymbolProperties {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names = self.iter_names();

        let Some((name, _)) = names.next() else {
            return f.write_str("NONE");
        };

        f.write_str(name)?;

        for (name, _) in names {
            write!(f, "|{}", name)?;
        }

        Ok(())
    }
}

impl SymbolProperties {
    pub fn new() -> Self {
        Self::NONE
    }

    pub fn is_extern(self) -> bool {
        self.contains(SymbolProperties::EXTERN)
    }

    pub fn is_local(self) -> bool {
        self.contains(SymbolProperties::LOCAL)
    }

    pub fn is_function(self) -> bool {
        self.contains(SymbolProperties::FUNCTION)
    }

    pub fn is_data(self) -> bool {
        self.contains(SymbolProperties::DATA)
    }
}

#[derive(Debug, Clone, Default)]
pub struct LocalSymbols {
    indices: BTreeMap<usize, Address>,
    sym_to_addr: SymbolMap<Address>,
    addr_to_sym: BTreeMap<Address, (Option<Symbol>, Cell<SymbolProperties>)>,
}

impl<C> Decode<C> for LocalSymbols {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        use bincode::serde::Compat;

        let indices = BTreeMap::<usize, Address>::decode(decoder)?;

        let sym_len = usize::decode(decoder)?;
        let sym_to_addr = (0..sym_len)
            .into_iter()
            .map(|_| {
                let Compat(sym) = Compat::<Symbol>::decode(decoder)?;
                let addr = Address::decode(decoder)?;
                Ok((sym, addr))
            })
            .collect::<Result<_, _>>()?;

        let addr_len = usize::decode(decoder)?;
        let addr_to_sym = (0..addr_len)
            .into_iter()
            .map(|_| {
                let addr = Address::decode(decoder)?;
                let Compat(sym) = Compat::<Option<Symbol>>::decode(decoder)?;
                let props = Cell::new(SymbolProperties::decode(decoder)?);
                Ok((addr, (sym, props)))
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            indices,
            sym_to_addr,
            addr_to_sym,
        })
    }
}

impl Encode for LocalSymbols {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        use bincode::serde::Compat;

        self.indices.encode(encoder)?;

        self.sym_to_addr.len().encode(encoder)?;
        for (&sym, &addr) in &self.sym_to_addr {
            sym.encode(encoder)?;
            addr.encode(encoder)?;
        }

        self.addr_to_sym.len().encode(encoder)?;
        for (&addr, (sym, props)) in &self.addr_to_sym {
            addr.encode(encoder)?;
            Compat(sym).encode(encoder)?;
            props.get().encode(encoder)?;
        }

        Ok(())
    }
}

impl Entity for LocalSymbols {
    const ID: EntityId = ENTITY_LOCAL_SYMBOLS_ID;
}

impl LocalSymbols {
    pub fn new() -> Self {
        Self {
            indices: BTreeMap::new(),
            sym_to_addr: SymbolMap::default(),
            addr_to_sym: BTreeMap::new(),
        }
    }

    pub fn add_symbol(
        &mut self,
        index: usize,
        addr: impl Into<Address>,
        symbol: impl Into<Option<Symbol>>,
    ) {
        Self::add_symbol_with(self, index, addr, symbol, SymbolProperties::LOCAL)
    }

    pub fn add_symbol_with(
        &mut self,
        index: usize,
        addr: impl Into<Address>,
        symbol: impl Into<Option<Symbol>>,
        props: SymbolProperties,
    ) {
        let addr = addr.into();
        let sym = symbol.into();

        let sym = sym.and_then(|sym| sym.is_empty().then(|| None).unwrap_or(Some(sym)));

        self.indices.insert(index, addr);

        self.addr_to_sym
            .insert(addr, (sym, Cell::new(props | SymbolProperties::LOCAL)));

        let Some(sym) = sym else {
            return;
        };

        self.sym_to_addr.insert(sym, addr);
    }

    pub fn symbol(&self, addr: impl Into<Address>) -> Option<(Option<Symbol>, SymbolProperties)> {
        self.addr_to_sym
            .get(&addr.into())
            .map(|(sym, props)| (*sym, props.get()))
    }

    pub fn symbol_properties(&self, addr: impl Into<Address>) -> Option<SymbolProperties> {
        self.addr_to_sym
            .get(&addr.into())
            .map(|(_, props)| props.get())
    }

    pub fn update_symbol_properties(
        &self,
        addr: impl Into<Address>,
        f: impl FnOnce(SymbolProperties) -> SymbolProperties,
    ) -> bool {
        let Some((_, curr_props)) = self.addr_to_sym.get(&addr.into()) else {
            return false;
        };

        curr_props.set(f(curr_props.get()));
        true
    }

    pub fn add_or_update_symbol_properties(
        &mut self,
        addr: impl Into<Address>,
        f: impl FnOnce(SymbolProperties) -> SymbolProperties,
    ) {
        let entry = self
            .addr_to_sym
            .entry(addr.into())
            .or_insert_with(|| (None, Cell::new(SymbolProperties::LOCAL)));

        entry.1.set(f(entry.1.get()));
    }

    pub fn address(&self, sym: impl AsRef<str>) -> Option<Address> {
        let sym = Symbol::from_existing(sym.as_ref())?;
        self.sym_to_addr.get(&sym).copied()
    }

    pub fn properties(&self, sym: impl AsRef<str>) -> Option<SymbolProperties> {
        let sym = Symbol::from_existing(sym.as_ref())?;
        self.sym_to_addr
            .get(&sym)
            .and_then(|addr| self.addr_to_sym.get(addr).map(|(_, props)| props.get()))
    }

    pub fn get_symbol(&self, index: usize) -> Option<Symbol> {
        self.indices
            .get(&index)
            .and_then(|&addr| self.addr_to_sym.get(&addr).and_then(|(sym, _)| *sym))
    }

    pub fn get_address(&self, index: usize) -> Option<Address> {
        self.indices.get(&index).copied()
    }

    pub fn get_properties(&self, index: usize) -> Option<SymbolProperties> {
        self.indices
            .get(&index)
            .and_then(|&addr| self.addr_to_sym.get(&addr).map(|(_, props)| props.get()))
    }

    pub fn get_symbol_with_properties(
        &self,
        index: usize,
    ) -> Option<(Option<Symbol>, SymbolProperties)> {
        self.indices.get(&index).and_then(|&addr| {
            self.addr_to_sym
                .get(&addr)
                .map(|(sym, props)| (*sym, props.get()))
        })
    }

    pub fn contains_address(&self, addr: impl Into<Address>) -> bool {
        self.addr_to_sym.contains_key(&addr.into())
    }

    pub fn contains_symbol(&self, sym: impl AsRef<str>) -> bool {
        let Some(sym) = Symbol::from_existing(sym.as_ref()) else {
            return false;
        };
        self.sym_to_addr.contains_key(&sym)
    }

    pub fn iter<'a>(&'a self) -> impl Iterator<Item = SymbolEntry> + 'a {
        self.addr_to_sym
            .iter()
            .map(|(&addr, (sym, props))| SymbolEntry {
                address: addr,
                symbol: *sym,
                properties: props.get(),
            })
    }

    pub fn next_index(&self) -> usize {
        self.indices.keys().max().map_or(0, |&max| max + 1)
    }

    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    pub fn len(&self) -> usize {
        self.indices.len()
    }
}

#[derive(Debug, Clone)]
pub struct ExternSymbols {
    base: Address,
    alignment: usize,
    indices: BTreeMap<usize, Address>,
    sym_to_addr: SymbolMap<Address>,
    addr_to_sym: BTreeMap<Address, (Option<Symbol>, Cell<SymbolProperties>)>,
    template: ExternFunctionTemplate,
}

impl<C> Decode<C> for ExternSymbols {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        use bincode::serde::Compat;

        let base = Address::decode(decoder)?;
        let alignment = usize::decode(decoder)?;
        let indices = BTreeMap::<usize, Address>::decode(decoder)?;

        let sym_len = usize::decode(decoder)?;
        let sym_to_addr = (0..sym_len)
            .into_iter()
            .map(|_| {
                let Compat(sym) = Compat::<Symbol>::decode(decoder)?;
                let addr = Address::decode(decoder)?;
                Ok((sym, addr))
            })
            .collect::<Result<_, _>>()?;

        let addr_len = usize::decode(decoder)?;
        let addr_to_sym = (0..addr_len)
            .into_iter()
            .map(|_| {
                let addr = Address::decode(decoder)?;
                let Compat(sym) = Compat::<Option<Symbol>>::decode(decoder)?;
                let props = Cell::new(SymbolProperties::decode(decoder)?);
                Ok((addr, (sym, props)))
            })
            .collect::<Result<_, _>>()?;

        let template = ExternFunctionTemplate::decode(decoder)?;

        Ok(Self {
            base,
            alignment,
            indices,
            sym_to_addr,
            addr_to_sym,
            template,
        })
    }
}

impl Encode for ExternSymbols {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        use bincode::serde::Compat;

        self.base.encode(encoder)?;
        self.alignment.encode(encoder)?;
        self.indices.encode(encoder)?;

        self.sym_to_addr.len().encode(encoder)?;
        for (&sym, &addr) in &self.sym_to_addr {
            sym.encode(encoder)?;
            addr.encode(encoder)?;
        }

        self.addr_to_sym.len().encode(encoder)?;
        for (&addr, (sym, props)) in &self.addr_to_sym {
            addr.encode(encoder)?;
            Compat(sym).encode(encoder)?;
            props.get().encode(encoder)?;
        }

        self.template.encode(encoder)?;

        Ok(())
    }
}

impl Entity for ExternSymbols {
    const ID: EntityId = ENTITY_EXTERN_SYMBOLS_ID;
}

impl ExternSymbols {
    pub fn new(
        base: impl Into<Address>,
        alignment: usize,
        template: ExternFunctionTemplate,
    ) -> Self {
        Self {
            base: base.into(),
            alignment,
            indices: BTreeMap::new(),
            sym_to_addr: SymbolMap::default(),
            addr_to_sym: BTreeMap::new(),
            template,
        }
    }

    pub fn add_symbol(
        &mut self,
        index: usize,
        addr: impl Into<Address>,
        symbol: impl Into<Option<Symbol>>,
    ) {
        Self::add_symbol_with(self, index, addr, symbol, SymbolProperties::EXTERN)
    }

    pub fn add_symbol_with(
        &mut self,
        index: usize,
        addr: impl Into<Address>,
        symbol: impl Into<Option<Symbol>>,
        props: SymbolProperties,
    ) {
        let addr = addr.into();
        let sym = symbol.into();

        let sym = sym.and_then(|sym| sym.is_empty().then(|| None).unwrap_or(Some(sym)));

        self.indices.insert(index, addr);

        self.addr_to_sym
            .insert(addr, (sym, Cell::new(props | SymbolProperties::EXTERN)));

        let Some(sym) = sym else {
            return;
        };

        self.sym_to_addr.insert(sym, addr);
    }

    pub fn base(&self) -> Address {
        self.base
    }

    pub fn alignment(&self) -> usize {
        self.alignment
    }

    pub fn last_address(&self) -> Address {
        if self.is_empty() {
            self.base()
        } else {
            self.base() + self.size() - 1usize
        }
    }

    pub fn bounds(&self) -> RangeInclusive<Address> {
        self.base()..=self.last_address()
    }

    pub fn symbol(&self, addr: impl Into<Address>) -> Option<(Option<Symbol>, SymbolProperties)> {
        self.addr_to_sym
            .get(&addr.into())
            .map(|(sym, props)| (*sym, props.get()))
    }

    pub fn symbol_properties(&self, addr: impl Into<Address>) -> Option<SymbolProperties> {
        self.addr_to_sym
            .get(&addr.into())
            .map(|(_, props)| props.get())
    }

    pub fn update_symbol_properties(
        &self,
        addr: impl Into<Address>,
        f: impl FnOnce(SymbolProperties) -> SymbolProperties,
    ) -> bool {
        let Some((_, curr_props)) = self.addr_to_sym.get(&addr.into()) else {
            return false;
        };

        curr_props.set(f(curr_props.get()));
        true
    }

    pub fn address(&self, sym: impl AsRef<str>) -> Option<Address> {
        let sym = Symbol::from_existing(sym.as_ref())?;
        self.sym_to_addr.get(&sym).copied()
    }

    pub fn properties(&self, sym: impl AsRef<str>) -> Option<SymbolProperties> {
        let sym = Symbol::from_existing(sym.as_ref())?;
        self.sym_to_addr
            .get(&sym)
            .and_then(|addr| self.addr_to_sym.get(addr).map(|(_, props)| props.get()))
    }

    pub fn get_symbol(&self, index: usize) -> Option<Symbol> {
        self.indices
            .get(&index)
            .and_then(|&addr| self.addr_to_sym.get(&addr).and_then(|(sym, _)| *sym))
    }

    pub fn get_address(&self, index: usize) -> Option<Address> {
        self.indices.get(&index).copied()
    }

    pub fn get_properties(&self, index: usize) -> Option<SymbolProperties> {
        self.indices
            .get(&index)
            .and_then(|&addr| self.addr_to_sym.get(&addr).map(|(_, props)| props.get()))
    }

    pub fn get_symbol_with_properties(
        &self,
        index: usize,
    ) -> Option<(Option<Symbol>, SymbolProperties)> {
        self.indices.get(&index).and_then(|&addr| {
            self.addr_to_sym
                .get(&addr)
                .map(|(sym, props)| (*sym, props.get()))
        })
    }

    pub fn contains_address(&self, addr: impl Into<Address>) -> bool {
        self.addr_to_sym.contains_key(&addr.into())
    }

    pub fn contains_symbol(&self, sym: impl AsRef<str>) -> bool {
        let Some(sym) = Symbol::from_existing(sym.as_ref()) else {
            return false;
        };
        self.sym_to_addr.contains_key(&sym)
    }

    pub fn iter<'a>(&'a self) -> impl Iterator<Item = SymbolEntry> + 'a {
        self.addr_to_sym
            .iter()
            .map(|(&addr, (sym, props))| SymbolEntry {
                address: addr,
                symbol: *sym,
                properties: props.get(),
            })
    }

    pub fn template(&self) -> &ExternFunctionTemplate {
        &self.template
    }

    pub fn aligned_template_size(&self) -> usize {
        let template_size = self.template.len();
        (template_size + self.alignment.wrapping_sub(1)) & !self.alignment().wrapping_sub(1)
    }

    pub fn size(&self) -> usize {
        self.indices.len() * self.aligned_template_size()
    }

    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    pub fn len(&self) -> usize {
        self.indices.len()
    }
}
