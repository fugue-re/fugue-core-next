use std::fmt::{self, Debug, Display, Formatter};
use std::sync::LazyLock;

use smallvec::SmallVec;
pub use ustr::{
    Ustr as Symbol, UstrMap as SymbolMap, UstrSet as SymbolSet, existing_ustr as existing_symbol,
    ustr as symbol,
};

use crate::ir::{Address, Id};
use crate::storage::entities::schema::ENTITY_SYMBOL_ID;
use crate::storage::entities::{Entity, EntityId};
use crate::types::common::archived_bitflags;

mod table;

pub(crate) use table::SymbolTableRevert;
pub use table::{SymbolInsertion, SymbolRef, SymbolTable, TransientSymbolTable};

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
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}", self.0)
    }
}

#[macro_export]
macro_rules! lazy_symbol {
    ($value:literal) => {
        ::std::sync::LazyLock::new(|| ::fugue_core::ir::symbol($value))
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
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
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

    pub fn set_properties(&mut self, properties: SymbolProperties) {
        self.properties = properties;
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

    fn remove_index(&mut self, index: SymbolIndex) {
        self.indices.retain(|existing| *existing != index);
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

    pub fn is_non_returning(&self) -> bool {
        self.properties.is_non_returning()
    }

    pub fn mark_non_returning(&mut self) {
        self.properties |= SymbolProperties::NON_RETURNING;
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
        const NONE          = 0b0000_0000;
        const EXTERN        = 0b0000_0001;
        const EXPORT        = 0b0000_0010;
        const LOCAL         = 0b0000_0100;
        const FUNCTION      = 0b0000_1000;
        const DATA          = 0b0001_0000;
        const NON_RETURNING = 0b0010_0000;

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

archived_bitflags!(SymbolProperties, ArchivedSymbolProperties, u8);

impl Display for SymbolProperties {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
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

    pub fn is_non_returning(self) -> bool {
        self.contains(SymbolProperties::NON_RETURNING)
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
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
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

#[cfg(test)]
mod test {
    use super::*;

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
}
