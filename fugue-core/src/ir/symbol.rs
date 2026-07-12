use std::collections::BTreeMap;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::mem;
use std::ops::RangeBounds;
use std::slice::Iter;
use std::sync::LazyLock;

use rkyv::bytecheck::CheckBytes;
use rkyv::rancor::Fallible;
use rkyv::traits::NoUndef;
use rkyv::{Archive, Deserialize, Place, Portable, Serialize};
use smallvec::SmallVec;
pub use ustr::{
    Ustr as Symbol, UstrMap as SymbolMap, existing_ustr as existing_symbol, ustr as symbol,
};

use crate::ir::{Address, Id};
use crate::storage::entities::schema::{ENTITY_SYMBOL_ID, ENTITY_SYMBOL_TABLE_ID};
use crate::storage::entities::{Entity, EntityId, ProjectEntity};
use crate::storage::project::{PersistableProjectEntity, ProjectEntityFromStorage};
use crate::storage::{EntityStorage, EntityStorageError};

pub type SymbolId = Id<Symbol>;
pub type LazySymbol = LazyLock<Symbol>;

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
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{:02x}", self.0)
    }
}

#[macro_export]
macro_rules! lazy_symbol {
    ($value:literal) => {
        ::std::sync::LazyLock::new(|| ::fugue_core::ir::symbol::symbol($value))
    };
}

#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct SymbolEntry<A = Address> {
    address: A,
    symbol: Symbol,
    properties: SymbolProperties,
    indices: SmallVec<[SymbolIndex; 2]>,
}

impl<A> AsRef<SymbolEntry<A>> for SymbolEntry<A> {
    fn as_ref(&self) -> &SymbolEntry<A> {
        self
    }
}

impl<A> AsMut<SymbolEntry<A>> for SymbolEntry<A> {
    fn as_mut(&mut self) -> &mut SymbolEntry<A> {
        self
    }
}

impl<A> Display for SymbolEntry<A>
where
    A: Display + Copy,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let address = self.address;
        let properties = self.properties;
        if !self.symbol.is_empty() {
            let symbol = self.symbol;
            write!(f, "{symbol} at {address}; {properties}")
        } else {
            write!(f, "<unnamed> at {address}; {properties}")
        }
    }
}

impl<A> SymbolEntry<A>
where
    A: Copy + Eq,
{
    pub fn new(
        address: impl Into<A>,
        symbol: impl Into<Symbol>,
        properties: SymbolProperties,
    ) -> Self {
        Self {
            address: address.into(),
            symbol: symbol.into(),
            properties,
            indices: SmallVec::new(),
        }
    }

    pub fn address(&self) -> A {
        self.address
    }

    pub fn symbol(&self) -> Symbol {
        self.symbol
    }

    pub fn properties(&self) -> SymbolProperties {
        self.properties
    }

    fn add_index(&mut self, index: SymbolIndex) {
        if !self.indices.contains(&index) {
            self.indices.push(index);
        }
    }

    fn with_index(mut self, index: SymbolIndex) -> Self {
        self.add_index(index);
        self
    }

    pub(crate) fn indices(&self) -> &[SymbolIndex] {
        &self.indices
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

    fn is_valid(&self) -> bool {
        self.properties != SymbolProperties::INVALID
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

    pub fn has_same_referent(&self, other: &SymbolEntry<A>) -> bool {
        self.address == other.address && self.symbol == other.symbol && self.kind() == other.kind()
    }
}

impl Entity for SymbolEntry {
    const ID: EntityId = ENTITY_SYMBOL_ID;
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

        // invalid (marker)
        const INVALID = 0b1111_1111;
    }
}

impl Default for SymbolProperties {
    fn default() -> Self {
        Self::INVALID
    }
}

#[repr(transparent)]
pub struct ArchivedSymbolProperties(u8);

unsafe impl Portable for ArchivedSymbolProperties {}
unsafe impl NoUndef for ArchivedSymbolProperties {}

unsafe impl<C: Fallible + ?Sized> CheckBytes<C> for ArchivedSymbolProperties
where
    u8: CheckBytes<C>,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe { u8::check_bytes(value.cast(), context) }
    }
}

impl Archive for SymbolProperties {
    type Archived = ArchivedSymbolProperties;
    type Resolver = ();

    fn resolve(&self, _resolver: Self::Resolver, out: Place<Self::Archived>) {
        out.write(ArchivedSymbolProperties(self.bits()));
    }
}

impl<S: Fallible + ?Sized> Serialize<S> for SymbolProperties {
    fn serialize(&self, _serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

impl<D: Fallible + ?Sized> Deserialize<SymbolProperties, D> for ArchivedSymbolProperties {
    fn deserialize(&self, _deserializer: &mut D) -> Result<SymbolProperties, D::Error> {
        Ok(SymbolProperties::from_bits_truncate(self.0))
    }
}

impl Display for SymbolProperties {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let mut names = self.iter_names();

        let Some((name, _)) = names.next() else {
            return f.write_str("NONE");
        };

        f.write_str(name)?;

        for (name, _) in names {
            write!(f, "|{name}")?;
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

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(transparent)]
pub struct SymbolIndex(u64);

impl Debug for SymbolIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("SymbolIndex")
            .field("selector", &self.selector())
            .field("index", &self.index())
            .finish()
    }
}

impl SymbolIndex {
    // Index mask is the upper bits used to determine the symbol index provenance.
    const INDEX_MASK: u64 = !(Self::SELECTOR_MASK << Self::SELECTOR_SHIFT);
    // Selector bits is the number of upper bits used to encode symbol index provenance;
    // for ELF we have two possibilities: the global symbol table, and the dynamic symbol
    // table.
    const SELECTOR_BITS: u32 = 8;
    // Selector bits mask is the mask for the selector bits.
    const SELECTOR_MASK: u64 = (1u64 << Self::SELECTOR_BITS).wrapping_sub(1);
    // Selector bits shift is the number of bits to shift the selector bits to the upper bits.
    const SELECTOR_SHIFT: u32 = u64::BITS.wrapping_sub(Self::SELECTOR_BITS);

    pub fn new(selector: SymbolTableSelector, index: usize) -> Self {
        let selector = selector.index() as u64;
        let index = index as u64;

        assert_eq!(selector & !Self::SELECTOR_MASK, 0, "invalid selector bits");
        assert_eq!(index & !Self::INDEX_MASK, 0, "symbol index out of range");

        Self((selector << Self::SELECTOR_SHIFT) | index)
    }

    pub fn index(self) -> usize {
        (self.0 & Self::INDEX_MASK)
            .try_into()
            .expect("symbol index out of range")
    }

    pub fn selector(self) -> SymbolTableSelector {
        SymbolTableSelector::new(
            ((self.0 >> Self::SELECTOR_SHIFT) & Self::SELECTOR_MASK)
                .try_into()
                .expect("selector out of range"),
        )
    }
}

const SYMBOL_TABLE_VERSION: u32 = 1;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct SymbolTableHeader {
    version: u32,
}

impl Entity for SymbolTableHeader {
    const ID: EntityId = ENTITY_SYMBOL_TABLE_ID;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SymbolTable<A = Address> {
    // all known symbols
    symbols: Vec<SymbolEntry<A>>,
    generations: Vec<u32>,
    // map from each original symbol table to its symbols
    indices: BTreeMap<SymbolIndex, Id<Symbol>>,
    // map of symbol names to known symbols
    names: SymbolMap<SmallVec<[Id<Symbol>; 2]>>,
    // map of addresses to known symbols
    addresses: BTreeMap<A, SmallVec<[Id<Symbol>; 2]>>,
    // indices of removed symbols that can be reused
    free_ids: Vec<Id<Symbol>>,
}

pub(crate) struct SymbolTableRevert<A = Address> {
    allocation: SymbolTableAllocation,
    entries: Vec<(Id<Symbol>, SymbolEntry<A>)>,
    touched: Vec<Id<Symbol>>,
}

struct SymbolTableAllocation {
    symbols_len: usize,
    generations_len: usize,
    free_ids_len: usize,
    free_ids_tail: Vec<Id<Symbol>>,
}

impl SymbolTableAllocation {
    fn new(
        free_ids: &[Id<Symbol>],
        symbols_len: usize,
        generations_len: usize,
        max_pops: usize,
    ) -> Self {
        let tail_start = free_ids.len().saturating_sub(max_pops);
        Self {
            symbols_len,
            generations_len,
            free_ids_len: free_ids.len(),
            free_ids_tail: free_ids[tail_start..].to_vec(),
        }
    }
}

impl<A> SymbolTableRevert<A>
where
    A: Copy + Default + Ord + Eq,
{
    fn new(
        table: &SymbolTable<A>,
        ids: impl IntoIterator<Item = Id<Symbol>>,
        max_pops: usize,
    ) -> Self {
        let mut touched = Vec::new();
        let mut entries = Vec::new();

        for id in ids {
            if touched.contains(&id) {
                continue;
            }

            if let Some(entry) = table.get_by_id(id) {
                entries.push((id, entry.clone()));
            }
            touched.push(id);
        }

        Self {
            allocation: table.allocation_checkpoint(max_pops),
            entries,
            touched,
        }
    }

    pub(crate) fn touch(&mut self, id: Id<Symbol>) {
        if !self.touched.contains(&id) {
            self.touched.push(id);
        }
    }

    pub(crate) fn restore(self, table: &mut SymbolTable<A>) {
        for id in self.touched {
            table.clear_entry(id);
        }

        table.restore_allocation(self.allocation);

        for (id, entry) in self.entries {
            table.restore_entry(id, entry);
        }
    }
}

impl SymbolTable {
    fn load_entry(&mut self, id: Id<Symbol>, entry: SymbolEntry) {
        let index = id.index();

        while self.symbols.len() < index {
            self.symbols.push(SymbolEntry::default());
            self.generations.push(0);
        }

        if self.symbols.len() == index {
            self.symbols.push(entry);
            self.generations.push(id.generation());
        } else {
            self.symbols[index] = entry;
            self.generations[index] = id.generation();
        }

        let entry = &self.symbols[index];
        if !entry.is_valid() {
            return;
        }

        self.names.entry(entry.symbol()).or_default().push(id);
        self.addresses.entry(entry.address()).or_default().push(id);

        for &symbol_index in entry.indices() {
            self.indices.insert(symbol_index, id);
        }
    }

    fn rebuild_free_ids(&mut self) {
        self.free_ids = self
            .symbols
            .iter()
            .enumerate()
            .filter(|(_, entry)| !entry.is_valid())
            .map(|(index, _)| Id::with_generation(index as u32, self.generations[index]))
            .collect();
    }

    fn write_entries<P, D>(&self, mut put: P, mut delete: D) -> Result<(), EntityStorageError>
    where
        P: FnMut(&Id<Symbol>, &SymbolEntry) -> Result<(), EntityStorageError>,
        D: FnMut(&Id<Symbol>) -> Result<(), EntityStorageError>,
    {
        for (index, entry) in self.symbols.iter().enumerate() {
            let generation = self.generations[index];
            for previous_generation in 0..generation {
                let previous = Id::<Symbol>::with_generation(index as u32, previous_generation);
                delete(&previous)?;
            }

            let id = Id::<Symbol>::with_generation(index as u32, generation);
            put(&id, entry)?;
        }

        Ok(())
    }
}

impl ProjectEntityFromStorage for SymbolTable {
    fn from_entity_storage(storage: &EntityStorage) -> Result<Option<Self>, EntityStorageError> {
        tracing::trace!("loading symbol table from entity storage");

        if !storage.contains::<ProjectEntity, SymbolTableHeader>(&ProjectEntity::SymbolTable)? {
            return Ok(None);
        }

        let mut table = SymbolTable::new();
        for entry in storage.iter::<Id<Symbol>, SymbolEntry>()? {
            let (id, entry) = entry?;
            table.load_entry(id, entry);
        }
        table.rebuild_free_ids();

        Ok(Some(table))
    }

    fn default_from_entity_storage(_storage: &EntityStorage) -> Result<Self, EntityStorageError> {
        tracing::trace!("creating default (empty) symbol table from entity storage");
        Ok(Self::default())
    }
}

impl PersistableProjectEntity for SymbolTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        tracing::trace!("persisting symbol table with {} entries", self.len());

        let header = SymbolTableHeader {
            version: SYMBOL_TABLE_VERSION,
        };

        if storage.is_transient() {
            storage.insert(&ProjectEntity::SymbolTable, &header)?;
            return self.write_entries(
                |id, entry| storage.insert(id, entry),
                |id| storage.remove::<Id<Symbol>, SymbolEntry>(id),
            );
        }

        let writer = storage.transactional_writer()?;
        writer.insert(&ProjectEntity::SymbolTable, &header)?;
        self.write_entries(
            |id, entry| writer.insert(id, entry),
            |id| writer.remove::<Id<Symbol>, SymbolEntry>(id),
        )?;
        writer.commit()
    }
}

#[derive(Clone)]
pub struct SymbolEntryIter<'a, A = Address> {
    ids: Iter<'a, Id<Symbol>>,
    symbols: &'a [SymbolEntry<A>],
}

impl<'a, A> SymbolEntryIter<'a, A> {
    pub(crate) fn new(ids: &'a [Id<Symbol>], symbols: &'a [SymbolEntry<A>]) -> Self {
        Self {
            ids: ids.iter(),
            symbols,
        }
    }
}

impl<'a, A> Iterator for SymbolEntryIter<'a, A> {
    type Item = (Id<Symbol>, &'a SymbolEntry<A>);

    fn next(&mut self) -> Option<Self::Item> {
        let id = self.ids.next()?;
        Some((*id, &self.symbols[id.index()]))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.ids.size_hint()
    }
}

impl<'a, A> ExactSizeIterator for SymbolEntryIter<'a, A> {}

pub struct SymbolEntryIterMut<'a, A = Address> {
    ids: Iter<'a, Id<Symbol>>,
    symbols: &'a mut [SymbolEntry<A>],
}

impl<'a, A> SymbolEntryIterMut<'a, A> {
    pub(crate) fn new(ids: &'a [Id<Symbol>], symbols: &'a mut [SymbolEntry<A>]) -> Self {
        Self {
            ids: ids.iter(),
            symbols,
        }
    }
}

impl<'a, A> Iterator for SymbolEntryIterMut<'a, A> {
    type Item = (Id<Symbol>, &'a mut SymbolEntry<A>);

    fn next(&mut self) -> Option<Self::Item> {
        let id = self.ids.next()?;
        // SAFETY: we know that the ids will be unique and valid.
        unsafe {
            let symbols_ptr = self.symbols.as_mut_ptr();
            Some((*id, &mut *symbols_ptr.add(id.index())))
        }
    }
}

impl<'a, A> ExactSizeIterator for SymbolEntryIterMut<'a, A> {}

impl<A> SymbolTable<A>
where
    A: Copy + Default + Ord + Eq,
{
    pub fn new() -> Self {
        Self::default()
    }

    fn allocation_checkpoint(&self, max_pops: usize) -> SymbolTableAllocation {
        SymbolTableAllocation::new(
            &self.free_ids,
            self.symbols.len(),
            self.generations.len(),
            max_pops,
        )
    }

    fn restore_allocation(&mut self, allocation: SymbolTableAllocation) {
        let tail_start = allocation.free_ids_len - allocation.free_ids_tail.len();
        self.free_ids.truncate(tail_start);
        self.free_ids.extend(allocation.free_ids_tail);
        self.symbols.truncate(allocation.symbols_len);
        self.generations.truncate(allocation.generations_len);
    }

    fn restore_entry(&mut self, id: Id<Symbol>, entry: SymbolEntry<A>) {
        self.clear_entry(id);

        let index = id.index();
        if index >= self.symbols.len() {
            self.symbols.resize_with(index + 1, SymbolEntry::default);
            self.generations.resize(index + 1, 0);
        }

        self.symbols[index] = entry;
        self.generations[index] = id.generation();

        let entry = &self.symbols[index];
        if entry.is_valid() {
            self.names.entry(entry.symbol()).or_default().push(id);
            self.addresses.entry(entry.address()).or_default().push(id);

            for &symbol_index in entry.indices() {
                self.indices.insert(symbol_index, id);
            }
        }

        self.free_ids
            .retain(|free_id| free_id.index() != id.index());
    }

    fn clear_entry(&mut self, id: Id<Symbol>) -> bool {
        use std::collections::btree_map::Entry as AddrsEntry;
        use std::collections::hash_map::Entry as NamesEntry;

        let index = id.index();
        if self.generations.get(index).copied() != Some(id.generation()) {
            return false;
        }

        let Some(symbol_entry) = self.symbols.get_mut(index).filter(|entry| entry.is_valid())
        else {
            return false;
        };

        if let NamesEntry::Occupied(mut entry) = self.names.entry(symbol_entry.symbol()) {
            let ids = entry.get_mut();
            ids.retain(|oid| *oid != id);

            if ids.is_empty() {
                entry.remove();
            }
        }

        if let AddrsEntry::Occupied(mut entry) = self.addresses.entry(symbol_entry.address()) {
            let ids = entry.get_mut();
            ids.retain(|oid| *oid != id);

            if ids.is_empty() {
                entry.remove();
            }
        }

        for index in symbol_entry.indices() {
            self.indices.remove(index);
        }

        mem::take(symbol_entry);
        true
    }

    pub(crate) fn insert_revert(
        &self,
        index: SymbolIndex,
        entry: &SymbolEntry<A>,
    ) -> SymbolTableRevert<A> {
        let mut touched = Vec::new();
        if let Some(id) = self.indices.get(&index).copied() {
            touched.push(id);
        }

        if let Some(id) = self.addresses.get(&entry.address()).and_then(|ids| {
            SymbolEntryIter::new(ids, &self.symbols)
                .find_map(|(id, existing)| existing.has_same_referent(entry).then_some(id))
        }) {
            touched.push(id);
        }

        SymbolTableRevert::new(self, touched, 1)
    }

    pub(crate) fn remove_symbol_revert(&self, symbol: impl AsRef<str>) -> SymbolTableRevert<A> {
        let ids = Symbol::from_existing(symbol.as_ref())
            .and_then(|symbol| self.names.get(&symbol))
            .into_iter()
            .flatten()
            .copied();

        SymbolTableRevert::new(self, ids, 0)
    }

    pub(crate) fn remove_address_revert(&self, address: A) -> SymbolTableRevert<A> {
        let ids = self.addresses.get(&address).into_iter().flatten().copied();

        SymbolTableRevert::new(self, ids, 0)
    }

    pub(crate) fn remove_id_revert(&self, id: Id<Symbol>) -> SymbolTableRevert<A> {
        SymbolTableRevert::new(self, [id], 0)
    }

    pub(crate) fn remove_index_revert(&self, index: SymbolIndex) -> SymbolTableRevert<A> {
        SymbolTableRevert::new(self, self.indices.get(&index).copied(), 0)
    }

    pub fn get<'a>(
        &'a self,
        symbol: impl AsRef<str>,
    ) -> Option<impl Iterator<Item = (Id<Symbol>, &'a SymbolEntry<A>)> + 'a> {
        let symbol = Symbol::from_existing(symbol.as_ref())?;
        let ids = self.names.get(&symbol)?;
        Some(SymbolEntryIter::new(ids, &self.symbols))
    }

    pub fn get_mut<'a>(
        &'a mut self,
        symbol: impl AsRef<str>,
    ) -> Option<impl Iterator<Item = (Id<Symbol>, &'a mut SymbolEntry<A>)> + 'a> {
        let symbol = Symbol::from_existing(symbol.as_ref())?;
        let ids = self.names.get(&symbol)?;
        Some(SymbolEntryIterMut::new(ids, &mut self.symbols))
    }

    pub fn get_first(&self, symbol: impl AsRef<str>) -> Option<(Id<Symbol>, &SymbolEntry<A>)> {
        self.get(symbol).and_then(|mut iter| iter.next())
    }

    pub fn get_first_mut(
        &mut self,
        symbol: impl AsRef<str>,
    ) -> Option<(Id<Symbol>, &mut SymbolEntry<A>)> {
        self.get_mut(symbol).and_then(|mut iter| iter.next())
    }

    pub fn get_by_id(&self, id: Id<Symbol>) -> Option<&SymbolEntry<A>> {
        let index = id.index();
        if self.generations.get(index).copied()? != id.generation() {
            return None;
        }

        self.symbols.get(index).filter(|entry| entry.is_valid())
    }

    pub fn get_by_id_mut(&mut self, id: Id<Symbol>) -> Option<&mut SymbolEntry<A>> {
        let index = id.index();
        if self.generations.get(index).copied()? != id.generation() {
            return None;
        }

        self.symbols.get_mut(index).filter(|entry| entry.is_valid())
    }

    pub fn get_by_index(&self, index: SymbolIndex) -> Option<(Id<Symbol>, &SymbolEntry<A>)> {
        let id = self.indices.get(&index)?;
        self.get_by_id(*id).map(|sym_entry| (*id, sym_entry))
    }

    pub fn get_by_index_mut(
        &mut self,
        index: SymbolIndex,
    ) -> Option<(Id<Symbol>, &mut SymbolEntry<A>)> {
        let id = self.indices.get(&index)?;
        self.symbols
            .get_mut(id.index())
            .map(|sym_entry| (*id, sym_entry))
    }

    pub fn get_by_address(
        &self,
        address: impl Into<A>,
    ) -> impl Iterator<Item = (Id<Symbol>, &SymbolEntry<A>)> {
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
        address: impl Into<A>,
    ) -> impl Iterator<Item = (Id<Symbol>, &mut SymbolEntry<A>)> {
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
        address: impl Into<A>,
    ) -> Option<(Id<Symbol>, &SymbolEntry<A>)> {
        self.get_by_address(address).next()
    }

    pub fn get_first_by_address_mut(
        &mut self,
        address: impl Into<A>,
    ) -> Option<(Id<Symbol>, &mut SymbolEntry<A>)> {
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

    pub fn contains_address(&self, address: impl Into<A>) -> bool {
        self.addresses.contains_key(&address.into())
    }

    pub fn insert_local(
        &mut self,
        index: SymbolIndex,
        address: impl Into<A>,
        symbol: impl Into<Symbol>,
    ) -> (bool, Id<Symbol>) {
        self.insert_local_with(index, address, symbol, SymbolProperties::NONE)
    }

    pub fn insert_local_with(
        &mut self,
        index: SymbolIndex,
        address: impl Into<A>,
        symbol: impl Into<Symbol>,
        properties: SymbolProperties,
    ) -> (bool, Id<Symbol>) {
        self.insert(index, address, symbol, properties | SymbolProperties::LOCAL)
    }

    pub fn insert_extern(
        &mut self,
        index: SymbolIndex,
        address: impl Into<A>,
        symbol: impl Into<Symbol>,
    ) -> (bool, Id<Symbol>) {
        self.insert_extern_with(index, address, symbol, SymbolProperties::NONE)
    }

    pub fn insert_extern_with(
        &mut self,
        index: SymbolIndex,
        address: impl Into<A>,
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

    fn insert_or_update(
        addresses: &mut BTreeMap<A, SmallVec<[Id<Symbol>; 2]>>,
        names: &mut SymbolMap<SmallVec<[Id<Symbol>; 2]>>,
        symbols: &mut Vec<SymbolEntry<A>>,
        generations: &mut Vec<u32>,
        free_ids: &mut Vec<Id<Symbol>>,
        index: SymbolIndex,
        entry: SymbolEntry<A>,
    ) -> (bool, Id<Symbol>) {
        let address = entry.address();
        let symbol = entry.symbol();

        if let Some(symbol_id) = addresses.get(&address).and_then(|ids| {
            // inlines get_by_address to split the borrows
            SymbolEntryIter::new(ids, &*symbols)
                .find_map(|(id, existing)| existing.has_same_referent(&entry).then_some(id))
        }) {
            // NOTE: we update the properties with new visibility if the symbol already
            // exists.
            let symbol = &mut symbols[symbol_id.index()];

            // NOTE: we resuse the entry for an equivalent symbol
            symbol.add_index(index);
            symbol.update_visibility(entry.properties());

            (false, symbol_id)
        } else {
            let symbol_id = if let Some(free_id) = free_ids.pop() {
                symbols[free_id.index()] = entry;
                generations[free_id.index()] = free_id.generation();
                free_id
            } else {
                let id = Id::from_index(symbols.len());
                symbols.push(entry);
                generations.push(id.generation());
                id
            };

            names.entry(symbol).or_default().push(symbol_id);
            addresses.entry(address).or_default().push(symbol_id);

            (true, symbol_id)
        }
    }

    pub fn insert(
        &mut self,
        index: SymbolIndex,
        address: impl Into<A>,
        symbol: impl Into<Symbol>,
        properties: SymbolProperties,
    ) -> (bool, Id<Symbol>) {
        use std::collections::btree_map::Entry;

        let address = address.into();
        let symbol = symbol.into();
        let symbol_entry = SymbolEntry::new(address, symbol, properties).with_index(index);

        match self.indices.entry(index) {
            Entry::Vacant(entry) => {
                let (is_new, symbol_id) = Self::insert_or_update(
                    &mut self.addresses,
                    &mut self.names,
                    &mut self.symbols,
                    &mut self.generations,
                    &mut self.free_ids,
                    index,
                    symbol_entry,
                );

                entry.insert(symbol_id);

                (is_new, symbol_id)
            }
            Entry::Occupied(mut entry) => {
                let symbol_id = *entry.get();
                let existing = &mut self.symbols[symbol_id.index()];

                if *existing == symbol_entry {
                    return (false, symbol_id);
                }

                // NOTE: if existing has multiple indices referring to it, then
                // we just remove this one, and create a new symbol entry.
                if existing.indices().len() > 1 {
                    // remove the index from existing
                    existing.indices.retain(|idx| *idx != index);

                    let (is_new, symbol_id) = Self::insert_or_update(
                        &mut self.addresses,
                        &mut self.names,
                        &mut self.symbols,
                        &mut self.generations,
                        &mut self.free_ids,
                        index,
                        symbol_entry,
                    );

                    entry.insert(symbol_id);

                    return (is_new, symbol_id);
                }

                // NOTE: we have a single referent, so it's easier to remove the current
                // entry and just insert
                self.remove_by_id(symbol_id);
                self.insert(index, address, symbol, properties)
            }
        }
    }

    // Iterator over all symbol entries in insertion order.
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = (Id<Symbol>, &'a SymbolEntry<A>)> + 'a {
        self.symbols
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.is_valid())
            .map(|(i, entry)| {
                let id = Id::with_generation(i as u32, self.generations[i]);
                (id, entry)
            })
    }

    // Iterator over all symbol entries for a given selector.
    pub fn iter_by_selector<'a>(
        &'a self,
        selector: SymbolTableSelector,
    ) -> impl Iterator<Item = (Id<Symbol>, &'a SymbolEntry<A>)> + 'a {
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
    ) -> impl Iterator<Item = (Id<Symbol>, &'a SymbolEntry<A>)> + 'a {
        self.addresses
            .values()
            .flat_map(move |ids| SymbolEntryIter::new(ids, &self.symbols))
    }

    pub fn range_by_address<'a, R>(
        &'a self,
        range: R,
    ) -> impl Iterator<Item = (Id<Symbol>, &'a SymbolEntry<A>)> + 'a
    where
        R: RangeBounds<A>,
    {
        self.addresses
            .range(range)
            .flat_map(move |(_, ids)| SymbolEntryIter::new(ids, &self.symbols))
    }

    // Iterator over all symbol entries by their original symbol table indices.
    pub fn iter_by_index<'a>(
        &'a self,
    ) -> impl Iterator<Item = (SymbolIndex, Id<Symbol>, &'a SymbolEntry<A>)> + 'a {
        self.indices
            .iter()
            .map(move |(&index, &id)| (index, id, &self.symbols[id.index()]))
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.symbols.len() - self.free_ids.len()
    }

    pub fn remove(&mut self, symbol: impl AsRef<str>) -> usize {
        use std::collections::btree_map::Entry;

        let Some(symbol) = Symbol::from_existing(symbol.as_ref()) else {
            return 0;
        };

        let Some(ids) = self.names.remove(&symbol) else {
            return 0;
        };

        let count = ids.len();

        for id in ids {
            let symbol_entry = mem::take(&mut self.symbols[id.index()]);

            // remove from addresses map
            if let Entry::Occupied(mut entry) = self.addresses.entry(symbol_entry.address()) {
                let ids = entry.get_mut();

                ids.retain(|oid| *oid != id);

                if ids.is_empty() {
                    entry.remove();
                }
            }

            for index in symbol_entry.indices() {
                self.indices.remove(index);
            }

            let next_id = id.next_generation();
            self.generations[id.index()] = next_id.generation();
            self.free_ids.push(next_id);
        }

        count
    }

    pub fn remove_by_address(&mut self, address: impl Into<A>) -> usize {
        use std::collections::hash_map::Entry;

        let address = address.into();

        let Some(ids) = self.addresses.remove(&address) else {
            return 0;
        };

        let count = ids.len();

        for id in ids {
            let symbol_entry = mem::take(&mut self.symbols[id.index()]);

            // remove from names map
            if let Entry::Occupied(mut entry) = self.names.entry(symbol_entry.symbol()) {
                let ids = entry.get_mut();

                ids.retain(|oid| *oid != id);

                if ids.is_empty() {
                    entry.remove();
                }
            }

            for index in symbol_entry.indices() {
                self.indices.remove(index);
            }

            let next_id = id.next_generation();
            self.generations[id.index()] = next_id.generation();
            self.free_ids.push(next_id);
        }

        count
    }

    pub fn remove_by_id(&mut self, id: Id<Symbol>) -> bool {
        use std::collections::btree_map::Entry as AddrsEntry;
        use std::collections::hash_map::Entry as NamesEntry;

        let index = id.index();
        if self.generations.get(index).copied() != Some(id.generation()) {
            return false;
        }

        let Some(symbol_entry) = self.symbols.get_mut(index).filter(|entry| entry.is_valid())
        else {
            return false;
        };

        // remove from names map
        if let NamesEntry::Occupied(mut entry) = self.names.entry(symbol_entry.symbol()) {
            let ids = entry.get_mut();

            ids.retain(|oid| *oid != id);

            if ids.is_empty() {
                entry.remove();
            }
        }

        // remove from addresses map
        if let AddrsEntry::Occupied(mut entry) = self.addresses.entry(symbol_entry.address()) {
            let ids = entry.get_mut();

            ids.retain(|oid| *oid != id);

            if ids.is_empty() {
                entry.remove();
            }
        }

        for index in symbol_entry.indices() {
            self.indices.remove(index);
        }

        // mark as removed
        mem::take(symbol_entry);
        let next_id = id.next_generation();
        self.generations[index] = next_id.generation();
        self.free_ids.push(next_id);

        true
    }

    pub fn remove_by_index(&mut self, index: SymbolIndex) -> bool {
        let Some(id) = self.indices.get(&index).copied() else {
            return false;
        };

        self.remove_by_id(id)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::storage::entities::InMemoryEntityStorage;

    #[test]
    #[should_panic(expected = "invalid selector bits")]
    fn test_symbol_index_invalid_selector() {
        let sel = SymbolTableSelector::new(0xffff);
        let _ = SymbolIndex::new(sel, 1);
    }

    #[test]
    #[should_panic(expected = "symbol index out of range")]
    fn test_symbol_index_invalid_index() {
        let sel = SymbolTableSelector::new(1);
        let _ = SymbolIndex::new(sel, usize::MAX);
    }

    #[test]
    fn test_symbol_index_valid() {
        let sel = SymbolTableSelector::new(1);
        let index = SymbolIndex::new(sel, 42);
        assert_eq!(index.index(), 42);
        assert_eq!(index.selector().index(), 1);
    }

    #[test]
    fn test_symbol_index_free_list() {
        let mut table = SymbolTable::new();
        let sel = SymbolTableSelector::new(0);

        let (inserted1, id1) = table.insert_local(
            SymbolIndex::new(sel, 1),
            Address::from(0x1000u32),
            "symbol1",
        );
        assert!(inserted1);

        let (inserted2, _id2) = table.insert_local(
            SymbolIndex::new(sel, 2),
            Address::from(0x2000u32),
            "symbol2",
        );
        assert!(inserted2);

        assert_eq!(table.len(), 2);

        let removed = table.remove_by_id(id1);
        assert!(removed);
        assert_eq!(table.len(), 1);

        let (inserted3, id3) = table.insert_local(
            SymbolIndex::new(sel, 3),
            Address::from(0x3000u32),
            "symbol3",
        );
        assert!(inserted3);
        assert_eq!(table.len(), 2);

        assert_eq!(id1.index(), id3.index());
        assert_eq!(id1.generation() + 1, id3.generation());
        assert!(table.get_by_id(id1).is_none());
        assert!(!table.remove_by_id(id1));
        assert_eq!(table.len(), 2);

        let (inserted4, id4) = table.insert_local(
            SymbolIndex::new(sel, 4),
            Address::from(0x3000u32),
            "symbol3",
        );
        assert!(!inserted4);
        assert_eq!(table.len(), 2);

        // check that the ID is the same as the existing one (same referent, different symbol index)
        assert_eq!(id3, id4);

        let (inserted5, _id5) = table.insert_local(
            SymbolIndex::new(sel, 5),
            Address::from(0x3000u32),
            "symbol4",
        );
        assert!(inserted5);

        // check that we inserted a new symbol referring to the same address as id3 and id4
        assert_eq!(table.len(), 3);

        let mut ntable = table.clone();

        // check we remove id3 and id4, which will have two indices associated with it, but one symbol
        assert_eq!(table.remove("symbol3"), 1);
        assert_eq!(table.len(), 2);

        // check we remove id3, id4, and id5, which will be two distinct symbols
        assert_eq!(ntable.remove_by_address(Address::from(0x3000u32)), 2);
        assert_eq!(ntable.len(), 1);

        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        table.persist(&storage).unwrap();
        let reloaded = SymbolTable::from_entity_storage(&storage).unwrap().unwrap();

        assert_eq!(table, reloaded);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn test_symbol_persist_reopen_sqlite() {
        use tempfile::TempDir;

        use crate::storage::PERSISTENT;
        use crate::storage::entities::SqliteEntityStorage;

        let sel = SymbolTableSelector::new(0);
        let dir = TempDir::new().unwrap();

        let mut table = SymbolTable::new();
        let (_, hole) =
            table.insert_local(SymbolIndex::new(sel, 1), Address::from(0x1000u32), "alpha");
        table.insert_local(SymbolIndex::new(sel, 2), Address::from(0x2000u32), "beta");
        table.insert_local(SymbolIndex::new(sel, 3), Address::from(0x3000u32), "gamma");
        assert!(table.remove_by_id(hole));

        {
            let storage =
                EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
            table.persist(&storage).unwrap();
        }

        let storage =
            EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
        let reloaded = SymbolTable::from_entity_storage(&storage).unwrap().unwrap();

        assert_eq!(table, reloaded);
        assert_eq!(reloaded.len(), 2);
        assert!(reloaded.get_first("beta").is_some());
        assert!(reloaded.get_first("alpha").is_none());
    }
}
