use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt::{Debug, Display};
use std::sync::LazyLock;

use bincode::{Decode, Encode};
use smallvec::SmallVec;

pub use ustr::{
    Ustr as Symbol, UstrMap as SymbolMap, existing_ustr as existing_symbol, ustr as symbol,
};

use crate::ir::traits::{
    SymbolEntryIter as BoxedSymbolEntryIter, SymbolEntryIterMut as BoxedSymbolEntryIterMut,
    SymbolIndexAndEntryIter as BoxedSymbolIndexAndEntryIter, SymbolTable as SymbolTableT,
    SymbolTable2,
};
use crate::ir::{Address, Id};
use crate::storage::entities::schema::ENTITY_SYMBOL_TABLE_ID;
use crate::storage::entities::{Entity, EntityId, ProjectEntity};
use crate::storage::project::{PersistableProjectEntity, ProjectEntityFromStorage};
use crate::storage::{EntityStorage, EntityStorageError};

pub type SymbolId = Id<Symbol>;
pub type LazySymbol = LazyLock<Symbol>;

#[macro_export]
macro_rules! lazy_symbol {
    ($value:literal) => {
        ::std::sync::LazyLock::new(|| ::fugue_core::ir::symbol::symbol($value))
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolEntry {
    address: Address,
    symbol: Symbol,
    properties: SymbolProperties,
}

impl AsRef<SymbolEntry> for SymbolEntry {
    fn as_ref(&self) -> &SymbolEntry {
        self
    }
}

impl AsMut<SymbolEntry> for SymbolEntry {
    fn as_mut(&mut self) -> &mut SymbolEntry {
        self
    }
}

impl Display for SymbolEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.symbol.is_empty() {
            write!(
                f,
                "{} at {}; {}",
                self.symbol, self.address, self.properties
            )
        } else {
            write!(f, "<unnamed> at {}; {}", self.address, self.properties)
        }
    }
}

impl Encode for SymbolEntry {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        use bincode::serde::Compat;

        self.address.encode(encoder)?;
        Compat(&self.symbol).encode(encoder)?;
        self.properties.encode(encoder)
    }
}

impl<C> Decode<C> for SymbolEntry {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        use bincode::serde::Compat;

        let address = Address::decode(decoder)?;
        let Compat(symbol) = Compat::<Symbol>::decode(decoder)?;
        let properties = SymbolProperties::decode(decoder)?;

        Ok(Self {
            address,
            symbol,
            properties,
        })
    }
}

impl SymbolEntry {
    pub fn new(address: Address, symbol: impl Into<Symbol>, properties: SymbolProperties) -> Self {
        Self {
            address,
            symbol: symbol.into(),
            properties,
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn symbol(&self) -> Symbol {
        self.symbol
    }

    pub fn properties(&self) -> SymbolProperties {
        self.properties
    }

    pub fn mark_as_extern(&mut self) {
        self.properties |= SymbolProperties::EXTERN;
        self.properties.remove(SymbolProperties::LOCAL);
    }

    pub fn mark_as_local(&mut self) {
        self.properties |= SymbolProperties::LOCAL;
        self.properties.remove(SymbolProperties::EXTERN);
    }

    pub fn mark_as_export(&mut self) {
        self.properties |= SymbolProperties::EXPORT | SymbolProperties::LOCAL;
        self.properties.remove(SymbolProperties::EXTERN);
    }

    pub fn mark_as_function(&mut self) {
        self.properties |= SymbolProperties::FUNCTION;
        self.properties.remove(SymbolProperties::DATA);
    }

    pub fn mark_as_data(&mut self) {
        self.properties |= SymbolProperties::DATA;
        self.properties.remove(SymbolProperties::FUNCTION);
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

    pub fn kind(&self) -> SymbolProperties {
        self.properties & SymbolProperties::KIND
    }

    pub fn visibility(&self) -> SymbolProperties {
        self.properties & SymbolProperties::VISIBILITY
    }

    pub fn update_kind(&mut self, properties: SymbolProperties) {
        let kind = properties & SymbolProperties::KIND;
        self.properties.remove(SymbolProperties::KIND);
        self.properties |= kind;
    }

    pub fn update_visibility(&mut self, properties: SymbolProperties) {
        let visibility = properties & SymbolProperties::VISIBILITY;
        self.properties.remove(SymbolProperties::VISIBILITY);
        self.properties |= visibility;
    }

    pub fn has_same_referent(&self, other: &SymbolEntry) -> bool {
        self.address == other.address && self.symbol == other.symbol && self.kind() == other.kind()
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SymbolProperties: u8 {
        const NONE     = 0b0000_0000;
        const EXTERN   = 0b0000_0001;
        const EXPORT   = 0b0000_0010;
        const LOCAL    = 0b0000_0100;
        const FUNCTION = 0b0000_1000;
        const DATA     = 0b0001_0000;

        // aliases
        const IMPORT = Self::EXTERN.bits();

        // groups
        const KIND       = Self::FUNCTION.bits() | Self::DATA.bits();
        const VISIBILITY = Self::EXTERN.bits() | Self::LOCAL.bits() | Self::EXPORT.bits();
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

    pub fn is_import(self) -> bool {
        self.is_extern()
    }

    pub fn is_export(self) -> bool {
        self.contains(SymbolProperties::EXPORT)
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

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
#[repr(transparent)]
pub struct SymbolIndex(usize);

impl Debug for SymbolIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymbolIndex")
            .field("selector", &self.selector())
            .field("index", &self.index())
            .finish()
    }
}

impl SymbolIndex {
    // Selector bits is the number of upper bits used to encode symbol index provenance;
    // for ELF we have two possibilities: the global symbol table, and the dynamic symbol
    // table.
    const SELECTOR_BITS: usize = 1;
    // Selector bits mask is the mask for the selector bits.
    const SELECTOR_MASK: usize = (1usize << Self::SELECTOR_BITS).wrapping_sub(1);
    // Selector bits shift is the number of bits to shift the selector bits to the upper bits.
    const SELECTOR_SHIFT: u32 = usize::BITS.wrapping_sub(Self::SELECTOR_BITS as u32);
    // Index mask is the upper bits used to determine the symbol index provenance.
    const INDEX_MASK: usize = !(Self::SELECTOR_MASK << Self::SELECTOR_SHIFT);

    pub fn new(selector: usize, index: usize) -> Self {
        assert_eq!(selector & !Self::SELECTOR_MASK, 0, "invalid selector bits");
        assert_eq!(index & !Self::INDEX_MASK, 0, "symbol index out of range");
        Self((selector << Self::SELECTOR_SHIFT) | index)
    }

    pub fn index(self) -> usize {
        self.0 & Self::INDEX_MASK
    }

    pub fn selector(self) -> usize {
        (self.0 >> Self::SELECTOR_SHIFT) & Self::SELECTOR_MASK
    }
}

#[derive(Debug, Clone, Default)]
pub struct IndexedSymbolTable {
    // all known symbols
    symbols: Vec<SymbolEntry>,
    // map from each original symbol table to its symbols
    indices: BTreeMap<SymbolIndex, Id<Symbol>>,
    // map of symbol names to known symbols
    names: SymbolMap<SmallVec<[Id<Symbol>; 2]>>,
    // map of addresses to known symbols
    addresses: BTreeMap<Address, SmallVec<[Id<Symbol>; 2]>>,
}

impl<C> Decode<C> for IndexedSymbolTable {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        use bincode::serde::Compat;

        let symbols = Vec::<SymbolEntry>::decode(decoder)?;
        let indices = BTreeMap::<SymbolIndex, Id<Symbol>>::decode(decoder)?;

        let names_len = usize::decode(decoder)?;
        let names = (0..names_len)
            .into_iter()
            .map(|_| {
                let Compat(sym) = Compat::<Symbol>::decode(decoder)?;
                let ids_len = usize::decode(decoder)?;
                let ids = (0..ids_len)
                    .into_iter()
                    .map(|_| Id::<Symbol>::decode(decoder))
                    .collect::<Result<SmallVec<[_; 2]>, _>>()?;
                Ok((sym, ids))
            })
            .collect::<Result<SymbolMap<SmallVec<[_; 2]>>, _>>()?;

        let addresses_len = usize::decode(decoder)?;
        let addresses = (0..addresses_len)
            .into_iter()
            .map(|_| {
                let addr = Address::decode(decoder)?;
                let ids_len = usize::decode(decoder)?;
                let ids = (0..ids_len)
                    .into_iter()
                    .map(|_| Id::<Symbol>::decode(decoder))
                    .collect::<Result<SmallVec<[_; 2]>, _>>()?;
                Ok((addr, ids))
            })
            .collect::<Result<BTreeMap<Address, SmallVec<[_; 2]>>, _>>()?;

        Ok(Self {
            symbols,
            indices,
            names,
            addresses,
        })
    }
}

impl Encode for IndexedSymbolTable {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        use bincode::serde::Compat;

        self.symbols.encode(encoder)?;
        self.indices.encode(encoder)?;

        self.names.len().encode(encoder)?;
        for (sym, ids) in &self.names {
            Compat(sym).encode(encoder)?;
            ids.len().encode(encoder)?;
            for id in ids {
                id.encode(encoder)?;
            }
        }

        self.addresses.len().encode(encoder)?;
        for (addr, ids) in &self.addresses {
            addr.encode(encoder)?;
            ids.len().encode(encoder)?;
            for id in ids {
                id.encode(encoder)?;
            }
        }

        Ok(())
    }
}

impl Entity for IndexedSymbolTable {
    const ID: EntityId = ENTITY_SYMBOL_TABLE_ID;
}

impl ProjectEntityFromStorage for IndexedSymbolTable {
    fn from_entity_storage(storage: &EntityStorage) -> Result<Option<Self>, EntityStorageError> {
        tracing::trace!("loading SymbolTable from entity storage");
        storage.get(&ProjectEntity::SymbolTable)
    }

    fn default_from_entity_storage(_storage: &EntityStorage) -> Result<Self, EntityStorageError> {
        tracing::trace!("creating default (empty) SymbolTable from entity storage");
        Ok(Self::default())
    }
}

impl PersistableProjectEntity for IndexedSymbolTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        tracing::trace!("persisting SymbolTable with {} entries", self.len());
        storage.insert(&ProjectEntity::SymbolTable, self)
    }
}

#[derive(Clone)]
pub struct SymbolEntryIter<'a> {
    ids: std::slice::Iter<'a, Id<Symbol>>,
    symbols: &'a [SymbolEntry],
}

impl<'a> SymbolEntryIter<'a> {
    pub(crate) fn new(ids: &'a [Id<Symbol>], symbols: &'a [SymbolEntry]) -> Self {
        Self {
            ids: ids.iter(),
            symbols,
        }
    }
}

impl<'a> Iterator for SymbolEntryIter<'a> {
    type Item = (Id<Symbol>, &'a SymbolEntry);

    fn next(&mut self) -> Option<Self::Item> {
        let id = self.ids.next()?;
        Some((*id, &self.symbols[id.index()]))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.ids.size_hint()
    }
}

impl<'a> ExactSizeIterator for SymbolEntryIter<'a> {}

pub struct SymbolEntryIterMut<'a> {
    ids: std::slice::Iter<'a, Id<Symbol>>,
    symbols: &'a mut [SymbolEntry],
}

impl<'a> SymbolEntryIterMut<'a> {
    pub(crate) fn new(ids: &'a [Id<Symbol>], symbols: &'a mut [SymbolEntry]) -> Self {
        Self {
            ids: ids.iter(),
            symbols,
        }
    }
}

impl<'a> Iterator for SymbolEntryIterMut<'a> {
    type Item = (Id<Symbol>, &'a mut SymbolEntry);

    fn next(&mut self) -> Option<Self::Item> {
        let id = self.ids.next()?;
        // SAFETY: we know that the ids will be unique and valid.
        unsafe {
            let symbols_ptr = self.symbols.as_mut_ptr();
            Some((*id, &mut *symbols_ptr.add(id.index())))
        }
    }
}

impl<'a> ExactSizeIterator for SymbolEntryIterMut<'a> {}

impl IndexedSymbolTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get<'a>(
        &'a self,
        symbol: impl AsRef<str>,
    ) -> Option<impl Iterator<Item = (Id<Symbol>, &'a SymbolEntry)> + 'a> {
        let symbol = Symbol::from_existing(symbol.as_ref())?;
        let ids = self.names.get(&symbol)?;
        Some(SymbolEntryIter::new(ids, &self.symbols))
    }

    pub fn get_mut<'a>(
        &'a mut self,
        symbol: impl AsRef<str>,
    ) -> Option<impl Iterator<Item = (Id<Symbol>, &'a mut SymbolEntry)> + 'a> {
        let symbol = Symbol::from_existing(symbol.as_ref())?;
        let ids = self.names.get(&symbol)?;
        Some(SymbolEntryIterMut::new(ids, &mut self.symbols))
    }

    pub fn get_first(&self, symbol: impl AsRef<str>) -> Option<(Id<Symbol>, &SymbolEntry)> {
        self.get(symbol).and_then(|mut iter| iter.next())
    }

    pub fn get_first_mut(
        &mut self,
        symbol: impl AsRef<str>,
    ) -> Option<(Id<Symbol>, &mut SymbolEntry)> {
        self.get_mut(symbol).and_then(|mut iter| iter.next())
    }

    pub fn get_by_id(&self, id: Id<Symbol>) -> Option<&SymbolEntry> {
        self.symbols.get(id.index())
    }

    pub fn get_by_id_mut(&mut self, id: Id<Symbol>) -> Option<&mut SymbolEntry> {
        self.symbols.get_mut(id.index())
    }

    pub fn get_by_index(&self, index: SymbolIndex) -> Option<(Id<Symbol>, &SymbolEntry)> {
        let id = self.indices.get(&index)?;
        self.get_by_id(*id).map(|sym_entry| (*id, sym_entry))
    }

    pub fn get_by_index_mut(
        &mut self,
        index: SymbolIndex,
    ) -> Option<(Id<Symbol>, &mut SymbolEntry)> {
        let id = self.indices.get(&index)?;
        self.symbols
            .get_mut(id.index())
            .map(|sym_entry| (*id, sym_entry))
    }

    pub fn get_by_address(
        &self,
        address: impl Into<Address>,
    ) -> impl Iterator<Item = (Id<Symbol>, &SymbolEntry)> {
        let address = address.into();
        let ids = self
            .addresses
            .get(&address)
            .map(|ids| ids.as_slice())
            .unwrap_or_default();
        SymbolEntryIter::new(ids, &self.symbols)
    }

    pub fn get_by_address_mut(
        &mut self,
        address: impl Into<Address>,
    ) -> impl Iterator<Item = (Id<Symbol>, &mut SymbolEntry)> {
        let address = address.into();
        let ids = self
            .addresses
            .get(&address)
            .map(|ids| ids.as_slice())
            .unwrap_or_default();
        SymbolEntryIterMut::new(ids, &mut self.symbols)
    }

    pub fn get_first_by_address(
        &self,
        address: impl Into<Address>,
    ) -> Option<(Id<Symbol>, &SymbolEntry)> {
        self.get_by_address(address).next()
    }

    pub fn get_first_by_address_mut(
        &mut self,
        address: impl Into<Address>,
    ) -> Option<(Id<Symbol>, &mut SymbolEntry)> {
        self.get_by_address_mut(address).next()
    }

    pub fn contains(&self, symbol: impl AsRef<str>) -> bool {
        let Some(symbol) = Symbol::from_existing(symbol.as_ref()) else {
            return false;
        };
        self.names.contains_key(&symbol)
    }

    pub fn contains_index(&self, index: SymbolIndex) -> bool {
        self.indices.contains_key(&index)
    }

    pub fn contains_address(&self, address: impl Into<Address>) -> bool {
        self.addresses.contains_key(&address.into())
    }

    pub fn insert_local(
        &mut self,
        index: SymbolIndex,
        address: impl Into<Address>,
        symbol: impl Into<Symbol>,
    ) -> (bool, Id<Symbol>) {
        self.insert_local_with(index, address, symbol, SymbolProperties::NONE)
    }

    pub fn insert_local_with(
        &mut self,
        index: SymbolIndex,
        address: impl Into<Address>,
        symbol: impl Into<Symbol>,
        properties: SymbolProperties,
    ) -> (bool, Id<Symbol>) {
        self.insert(index, address, symbol, properties | SymbolProperties::LOCAL)
    }

    pub fn insert_extern(
        &mut self,
        index: SymbolIndex,
        address: impl Into<Address>,
        symbol: impl Into<Symbol>,
    ) -> (bool, Id<Symbol>) {
        self.insert_extern_with(index, address, symbol, SymbolProperties::NONE)
    }

    pub fn insert_extern_with(
        &mut self,
        index: SymbolIndex,
        address: impl Into<Address>,
        symbol: impl Into<Symbol>,
        properties: SymbolProperties,
    ) -> (bool, Id<Symbol>) {
        self.insert(
            index,
            address,
            symbol,
            properties | SymbolProperties::EXTERN,
        )
    }

    pub fn insert(
        &mut self,
        index: SymbolIndex,
        address: impl Into<Address>,
        symbol: impl Into<Symbol>,
        properties: SymbolProperties,
    ) -> (bool, Id<Symbol>) {
        let address = address.into();
        let symbol = symbol.into();
        let symbol_entry = SymbolEntry::new(address, symbol, properties);

        match self.indices.entry(index) {
            Entry::Vacant(entry) => {
                let address = address.into();
                let symbol_id = if let Some(symbol_id) =
                    // inlines get_by_address to split the borrows
                    self.addresses.get(&address).and_then(|ids| {
                            SymbolEntryIter::new(ids, &self.symbols).find_map(|(id, entry)| {
                                entry.has_same_referent(&symbol_entry).then_some(id)
                            })
                        }) {
                    // NOTE: we update the properties with new visibility if the symbol already
                    // exists.
                    self.symbols[symbol_id.index()].update_visibility(properties);

                    symbol_id
                } else {
                    let symbol_id = Id::from_index(self.symbols.len());

                    self.symbols.push(symbol_entry);

                    // NOTE: due to how symbol identifiers are constructed, we know that
                    // the set of symbols will remain sorted.
                    self.names.entry(symbol).or_default().push(symbol_id);
                    self.addresses.entry(address).or_default().push(symbol_id);

                    symbol_id
                };

                entry.insert(symbol_id);

                (true, symbol_id)
            }
            Entry::Occupied(entry) => {
                let symbol_id = *entry.get();
                let existing = &self.symbols[symbol_id.index()];

                if existing == &symbol_entry {
                    return (false, symbol_id);
                }

                self.symbols[symbol_id.index()] = symbol_entry;
                (true, symbol_id)
            }
        }
    }

    // Iterator over all symbol entries in insertion order.
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = (Id<Symbol>, &'a SymbolEntry)> + 'a {
        self.symbols.iter().enumerate().map(|(i, entry)| {
            let id = Id::from_index(i);
            (id, entry)
        })
    }

    // Iterator over all symbol entries for a given selector.
    pub fn iter_by_selector<'a>(
        &'a self,
        selector: usize,
    ) -> impl Iterator<Item = (Id<Symbol>, &'a SymbolEntry)> + 'a {
        self.indices.iter().filter_map(move |(&index, &id)| {
            if index.selector() == selector {
                Some((id, &self.symbols[id.index()]))
            } else {
                None
            }
        })
    }

    // Iterator over all symbol entries in (ascending) order by address.
    pub fn iter_by_address<'a>(
        &'a self,
        address: impl Into<Address>,
    ) -> impl Iterator<Item = (Id<Symbol>, &'a SymbolEntry)> + 'a {
        let address = address.into();
        self.addresses
            .get(&address)
            .into_iter()
            .flat_map(move |ids| SymbolEntryIter::new(ids, &self.symbols))
    }

    // Iterator over all symbol entries by their original symbol table indices.
    pub fn iter_by_index<'a>(
        &'a self,
    ) -> impl Iterator<Item = (SymbolIndex, Id<Symbol>, &'a SymbolEntry)> + 'a {
        self.indices
            .iter()
            .map(move |(&index, &id)| (index, id, &self.symbols[id.index()]))
    }

    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    pub fn len(&self) -> usize {
        self.symbols.len()
    }
}

impl SymbolTableT for IndexedSymbolTable {
    fn get(&self, symbol: &str) -> Option<BoxedSymbolEntryIter> {
        Self::get(self, symbol).map(BoxedSymbolEntryIter::new)
    }

    fn get_mut(&mut self, symbol: &str) -> Option<BoxedSymbolEntryIterMut> {
        Self::get_mut(self, symbol).map(BoxedSymbolEntryIterMut::new)
    }

    fn get_first(&self, symbol: &str) -> Option<(Id<Symbol>, &SymbolEntry)> {
        Self::get_first(self, symbol)
    }

    fn get_first_mut(&mut self, symbol: &str) -> Option<(Id<Symbol>, &mut SymbolEntry)> {
        Self::get_first_mut(self, symbol)
    }

    fn get_by_id(&self, id: Id<Symbol>) -> Option<&SymbolEntry> {
        Self::get_by_id(self, id)
    }

    fn get_by_id_mut(&mut self, id: Id<Symbol>) -> Option<&mut SymbolEntry> {
        Self::get_by_id_mut(self, id)
    }

    fn get_by_index(&self, index: SymbolIndex) -> Option<(Id<Symbol>, &SymbolEntry)> {
        Self::get_by_index(self, index)
    }

    fn get_by_index_mut(&mut self, index: SymbolIndex) -> Option<(Id<Symbol>, &mut SymbolEntry)> {
        Self::get_by_index_mut(self, index)
    }

    fn get_by_address(&self, address: Address) -> BoxedSymbolEntryIter {
        BoxedSymbolEntryIter::new(Self::get_by_address(self, address))
    }

    fn get_by_address_mut(&mut self, address: Address) -> BoxedSymbolEntryIterMut {
        BoxedSymbolEntryIterMut::new(Self::get_by_address_mut(self, address))
    }

    fn get_first_by_address(&self, address: Address) -> Option<(Id<Symbol>, &SymbolEntry)> {
        Self::get_first_by_address(self, address)
    }

    fn get_first_by_address_mut(
        &mut self,
        address: Address,
    ) -> Option<(Id<Symbol>, &mut SymbolEntry)> {
        Self::get_first_by_address_mut(self, address)
    }

    fn contains(&self, symbol: &str) -> bool {
        Self::contains(self, symbol)
    }

    fn contains_index(&self, index: SymbolIndex) -> bool {
        Self::contains_index(self, index)
    }

    fn contains_address(&self, address: Address) -> bool {
        Self::contains_address(self, address)
    }

    fn insert(
        &mut self,
        index: SymbolIndex,
        address: Address,
        symbol: Symbol,
        properties: SymbolProperties,
    ) -> (bool, Id<Symbol>) {
        Self::insert(self, index, address, symbol, properties)
    }

    fn iter(&self) -> BoxedSymbolEntryIter {
        BoxedSymbolEntryIter::new(self.iter())
    }

    fn iter_by_selector(&self, selector: usize) -> BoxedSymbolEntryIter {
        BoxedSymbolEntryIter::new(self.iter_by_selector(selector))
    }

    fn iter_by_address(&self, address: Address) -> BoxedSymbolEntryIter {
        BoxedSymbolEntryIter::new(self.iter_by_address(address))
    }

    fn iter_by_index(&self) -> BoxedSymbolIndexAndEntryIter {
        BoxedSymbolIndexAndEntryIter::new(self.iter_by_index())
    }

    fn is_empty(&self) -> bool {
        Self::is_empty(self)
    }

    fn len(&self) -> usize {
        Self::len(self)
    }
}

impl SymbolTable2 for IndexedSymbolTable {
    type SymbolEntryRef<'a> = &'a SymbolEntry;
    type SymbolEntryMut<'a> = &'a mut SymbolEntry;

    type SymbolEntryIter<'a> = BoxedSymbolEntryIter<'a>;
    type SymbolEntryIterMut<'a> = BoxedSymbolEntryIterMut<'a>;
    type SymbolIndexAndEntryIter<'a> = BoxedSymbolIndexAndEntryIter<'a>;

    fn get<'a>(&'a self, symbol: &str) -> Option<Self::SymbolEntryIter<'a>> {
        Self::get(self, symbol).map(BoxedSymbolEntryIter::new)
    }

    fn get_mut<'a>(&'a mut self, symbol: &str) -> Option<Self::SymbolEntryIterMut<'a>> {
        Self::get_mut(self, symbol).map(BoxedSymbolEntryIterMut::new)
    }

    fn get_first(&self, symbol: &str) -> Option<(Id<Symbol>, Self::SymbolEntryRef<'_>)> {
        Self::get_first(self, symbol)
    }

    fn get_first_mut(
        &mut self,
        symbol: &str,
    ) -> Option<(Id<Symbol>, Self::SymbolEntryMut<'_>)> {
        Self::get_first_mut(self, symbol)
    }

    fn get_by_id(&self, id: Id<Symbol>) -> Option<Self::SymbolEntryRef<'_>> {
        Self::get_by_id(self, id)
    }

    fn get_by_id_mut(&mut self, id: Id<Symbol>) -> Option<Self::SymbolEntryMut<'_>> {
        Self::get_by_id_mut(self, id)
    }

    fn get_by_index(
        &self,
        index: SymbolIndex,
    ) -> Option<(Id<Symbol>, Self::SymbolEntryRef<'_>)> {
        Self::get_by_index(self, index)
    }

    fn get_by_index_mut(
        &mut self,
        index: SymbolIndex,
    ) -> Option<(Id<Symbol>, Self::SymbolEntryMut<'_>)> {
        Self::get_by_index_mut(self, index)
    }

    fn get_by_address(
        &self,
        address: Address,
    ) -> Self::SymbolEntryIter<'_> {
        BoxedSymbolEntryIter::new(Self::get_by_address(self, address))
    }

    fn get_by_address_mut(
        &mut self,
        address: Address,
    ) -> Self::SymbolEntryIterMut<'_> {
        BoxedSymbolEntryIterMut::new(Self::get_by_address_mut(self, address))
    }

    fn get_first_by_address(
        &self,
        address: Address,
    ) -> Option<(Id<Symbol>, Self::SymbolEntryRef<'_>)> {
        Self::get_first_by_address(self, address)
    }

    fn get_first_by_address_mut(
        &mut self,
        address: Address,
    ) -> Option<(Id<Symbol>, Self::SymbolEntryMut<'_>)> {
        Self::get_first_by_address_mut(self, address)
    }

    fn contains(&self, symbol: &str) -> bool {
        Self::contains(self, symbol)
    }

    fn contains_index(&self, index: SymbolIndex) -> bool {
        Self::contains_index(self, index)
    }

    fn contains_address(&self, address: Address) -> bool {
        Self::contains_address(self, address)
    }

    fn insert(
        &mut self,
        index: SymbolIndex,
        address: Address,
        symbol: Symbol,
        properties: SymbolProperties,
    ) -> (bool, Id<Symbol>) {
        Self::insert(self, index, address, symbol, properties)
    }

    fn iter(&self) -> Self::SymbolEntryIter<'_> {
        BoxedSymbolEntryIter::new(self.iter())
    }

    fn iter_by_selector(&self, selector: usize) -> Self::SymbolEntryIter<'_> {
        BoxedSymbolEntryIter::new(self.iter_by_selector(selector))
    }

    fn iter_by_address(&self, address: Address) -> Self::SymbolEntryIter<'_> {
        BoxedSymbolEntryIter::new(self.iter_by_address(address))
    }

    fn iter_by_index(&self) -> Self::SymbolIndexAndEntryIter<'_> {
        BoxedSymbolIndexAndEntryIter::new(self.iter_by_index())
    }

    fn is_empty(&self) -> bool {
        Self::is_empty(self)
    }

    fn len(&self) -> usize {
        Self::len(self)
    }
}

pub struct SymbolTable {
    inner: Box<dyn SymbolTableT>,
}

impl PersistableProjectEntity for SymbolTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        self.inner.persist(storage)
    }
}

impl SymbolTable {
    pub fn new(inner: impl SymbolTableT + 'static) -> Self {
        Self {
            inner: Box::new(inner),
        }
    }

    pub fn get(&self, symbol: impl AsRef<str>) -> Option<BoxedSymbolEntryIter<'_>> {
        self.inner.get(symbol.as_ref())
    }

    pub fn get_mut(&mut self, symbol: impl AsRef<str>) -> Option<BoxedSymbolEntryIterMut<'_>> {
        self.inner.get_mut(symbol.as_ref())
    }

    pub fn get_first(&self, symbol: impl AsRef<str>) -> Option<(Id<Symbol>, &SymbolEntry)> {
        self.inner.get_first(symbol.as_ref())
    }

    pub fn get_first_mut(
        &mut self,
        symbol: impl AsRef<str>,
    ) -> Option<(Id<Symbol>, &mut SymbolEntry)> {
        self.inner.get_first_mut(symbol.as_ref())
    }

    pub fn get_by_id(&self, id: Id<Symbol>) -> Option<&SymbolEntry> {
        self.inner.get_by_id(id)
    }

    pub fn get_by_id_mut(&mut self, id: Id<Symbol>) -> Option<&mut SymbolEntry> {
        self.inner.get_by_id_mut(id)
    }

    pub fn get_by_index(&self, index: SymbolIndex) -> Option<(Id<Symbol>, &SymbolEntry)> {
        self.inner.get_by_index(index)
    }

    pub fn get_by_index_mut(
        &mut self,
        index: SymbolIndex,
    ) -> Option<(Id<Symbol>, &mut SymbolEntry)> {
        self.inner.get_by_index_mut(index)
    }

    pub fn get_by_address(&self, address: impl Into<Address>) -> BoxedSymbolEntryIter<'_> {
        self.inner.get_by_address(address.into())
    }

    pub fn get_by_address_mut(
        &mut self,
        address: impl Into<Address>,
    ) -> BoxedSymbolEntryIterMut<'_> {
        self.inner.get_by_address_mut(address.into())
    }

    pub fn get_first_by_address(
        &self,
        address: impl Into<Address>,
    ) -> Option<(Id<Symbol>, &SymbolEntry)> {
        self.inner.get_first_by_address(address.into())
    }

    pub fn get_first_by_address_mut(
        &mut self,
        address: impl Into<Address>,
    ) -> Option<(Id<Symbol>, &mut SymbolEntry)> {
        self.inner.get_first_by_address_mut(address.into())
    }

    pub fn contains(&self, symbol: &str) -> bool {
        self.inner.contains(symbol)
    }

    pub fn contains_index(&self, index: SymbolIndex) -> bool {
        self.inner.contains_index(index)
    }

    pub fn contains_address(&self, address: impl Into<Address>) -> bool {
        self.inner.contains_address(address.into())
    }

    pub fn insert_local(
        &mut self,
        index: SymbolIndex,
        address: impl Into<Address>,
        symbol: impl Into<Symbol>,
    ) -> (bool, Id<Symbol>) {
        self.insert_local_with(index, address, symbol, SymbolProperties::NONE)
    }

    pub fn insert_local_with(
        &mut self,
        index: SymbolIndex,
        address: impl Into<Address>,
        symbol: impl Into<Symbol>,
        properties: SymbolProperties,
    ) -> (bool, Id<Symbol>) {
        self.insert(index, address, symbol, properties | SymbolProperties::LOCAL)
    }

    pub fn insert_extern(
        &mut self,
        index: SymbolIndex,
        address: impl Into<Address>,
        symbol: impl Into<Symbol>,
    ) -> (bool, Id<Symbol>) {
        self.insert_extern_with(index, address, symbol, SymbolProperties::NONE)
    }

    pub fn insert_extern_with(
        &mut self,
        index: SymbolIndex,
        address: impl Into<Address>,
        symbol: impl Into<Symbol>,
        properties: SymbolProperties,
    ) -> (bool, Id<Symbol>) {
        self.insert(
            index,
            address,
            symbol,
            properties | SymbolProperties::EXTERN,
        )
    }

    pub fn insert(
        &mut self,
        index: SymbolIndex,
        address: impl Into<Address>,
        symbol: impl Into<Symbol>,
        properties: SymbolProperties,
    ) -> (bool, Id<Symbol>) {
        self.inner
            .insert(index, address.into(), symbol.into(), properties)
    }

    pub fn iter(&self) -> BoxedSymbolEntryIter<'_> {
        self.inner.iter()
    }

    pub fn iter_by_selector(&self, selector: usize) -> BoxedSymbolEntryIter<'_> {
        self.inner.iter_by_selector(selector)
    }

    pub fn iter_by_address(&self, address: impl Into<Address>) -> BoxedSymbolEntryIter<'_> {
        self.inner.iter_by_address(address.into())
    }

    pub fn iter_by_index(&self) -> BoxedSymbolIndexAndEntryIter<'_> {
        self.inner.iter_by_index()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic(expected = "invalid selector bits")]
    fn test_symbol_index_invalid_selector() {
        let _ = SymbolIndex::new(2, 1);
    }

    #[test]
    #[should_panic(expected = "symbol index out of range")]
    fn test_symbol_index_invalid_index() {
        let _ = SymbolIndex::new(1, usize::MAX);
    }

    #[test]
    fn test_symbol_index_valid() {
        let index = SymbolIndex::new(1, 42);
        assert_eq!(index.index(), 42);
        assert_eq!(index.selector(), 1);
    }
}
