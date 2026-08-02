use std::collections::BTreeMap;
use std::mem;
use std::ops::RangeBounds;
use std::slice::Iter;

use smallvec::SmallVec;

use super::{SymbolIndexState, SymbolInsertion};
use crate::ir::symbol::{
    Symbol, SymbolEntry, SymbolId, SymbolIndex, SymbolMap, SymbolProperties, SymbolTableSelector,
};
use crate::ir::{Address, IdAllocator};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SymbolTable<A = Address> {
    allocator: IdAllocator<Symbol>,
    symbols: Vec<SymbolEntry<A>>,
    generations: Vec<u32>,
    indices: BTreeMap<SymbolIndex, SymbolId>,
    names: SymbolMap<SmallVec<[SymbolId; 2]>>,
    addresses: BTreeMap<A, SmallVec<[SymbolId; 2]>>,
}

#[derive(Clone)]
pub(super) struct SymbolEntryIter<'a, A = Address> {
    ids: Iter<'a, SymbolId>,
    symbols: &'a [SymbolEntry<A>],
}

impl<'a, A> SymbolEntryIter<'a, A> {
    pub(super) fn new(ids: &'a [SymbolId], symbols: &'a [SymbolEntry<A>]) -> Self {
        Self {
            ids: ids.iter(),
            symbols,
        }
    }
}

impl<'a, A> Iterator for SymbolEntryIter<'a, A> {
    type Item = (SymbolId, &'a SymbolEntry<A>);

    fn next(&mut self) -> Option<Self::Item> {
        let id = self.ids.next()?;
        Some((*id, &self.symbols[id.index()]))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.ids.size_hint()
    }
}

impl<'a, A> ExactSizeIterator for SymbolEntryIter<'a, A> {}

pub(super) struct SymbolEntryIterMut<'a, A = Address> {
    ids: Iter<'a, SymbolId>,
    symbols: &'a mut [SymbolEntry<A>],
}

impl<'a, A> SymbolEntryIterMut<'a, A> {
    pub(super) fn new(ids: &'a [SymbolId], symbols: &'a mut [SymbolEntry<A>]) -> Self {
        Self {
            ids: ids.iter(),
            symbols,
        }
    }
}

impl<'a, A> Iterator for SymbolEntryIterMut<'a, A> {
    type Item = (SymbolId, &'a mut SymbolEntry<A>);

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

    fn clear_entry(&mut self, id: SymbolId) -> bool {
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

    pub(super) fn pending_id(&self, offset: usize) -> SymbolId {
        self.allocator.pending_id(offset)
    }

    pub(super) fn publish_reservation(&mut self, id: SymbolId) {
        let allocated = self.allocator.allocate();
        debug_assert_eq!(allocated, id);
        if id.index() >= self.symbols.len() {
            self.symbols
                .resize_with(id.index() + 1, SymbolEntry::default);
            self.generations.resize(id.index() + 1, 0);
        }
        self.generations[id.index()] = id.generation();
    }

    pub(super) fn publish_release(&mut self, id: SymbolId) {
        self.generations[id.index()] = id.next_generation().generation();
        self.allocator.release(id);
    }

    pub(super) fn publish_upsert(
        &mut self,
        id: SymbolId,
        entry: SymbolEntry<A>,
        previous: Option<&SymbolIndexState>,
    ) {
        if previous.is_some() {
            self.clear_entry(id);
        }
        self.symbols[id.index()] = entry;
        self.generations[id.index()] = id.generation();
        let entry = &self.symbols[id.index()];
        self.names.entry(entry.symbol()).or_default().push(id);
        self.addresses.entry(entry.address()).or_default().push(id);
        for &index in entry.indices() {
            self.indices.insert(index, id);
        }
    }

    pub(super) fn publish_remove(&mut self, id: SymbolId, _previous: &SymbolIndexState) {
        let removed = self.clear_entry(id);
        debug_assert!(removed);
        self.generations[id.index()] = id.next_generation().generation();
        self.allocator.release(id);
    }

    pub(super) fn get_id_by_index(&self, index: SymbolIndex) -> Option<SymbolId> {
        self.indices.get(&index).copied()
    }

    pub fn get<'a>(
        &'a self,
        symbol: impl AsRef<str>,
    ) -> impl Iterator<Item = (SymbolId, &'a SymbolEntry<A>)> + 'a {
        let ids = Symbol::from_existing(symbol.as_ref())
            .and_then(|symbol| self.names.get(&symbol))
            .map_or(&[] as &[SymbolId], SmallVec::as_slice);
        SymbolEntryIter::new(ids, &self.symbols)
    }

    pub fn get_mut<'a>(
        &'a mut self,
        symbol: impl AsRef<str>,
    ) -> Option<impl Iterator<Item = (SymbolId, &'a mut SymbolEntry<A>)> + 'a> {
        let symbol = Symbol::from_existing(symbol.as_ref())?;
        let ids = self.names.get(&symbol)?;
        Some(SymbolEntryIterMut::new(ids, &mut self.symbols))
    }

    pub fn get_first(&self, symbol: impl AsRef<str>) -> Option<(SymbolId, &SymbolEntry<A>)> {
        self.get(symbol).next()
    }

    pub fn get_first_mut(
        &mut self,
        symbol: impl AsRef<str>,
    ) -> Option<(SymbolId, &mut SymbolEntry<A>)> {
        self.get_mut(symbol).and_then(|mut iter| iter.next())
    }

    pub fn get_by_id(&self, id: SymbolId) -> Option<&SymbolEntry<A>> {
        let index = id.index();
        if self.generations.get(index).copied()? != id.generation() {
            return None;
        }

        self.symbols.get(index).filter(|entry| entry.is_valid())
    }

    pub fn get_by_id_mut(&mut self, id: SymbolId) -> Option<&mut SymbolEntry<A>> {
        let index = id.index();
        if self.generations.get(index).copied()? != id.generation() {
            return None;
        }

        self.symbols.get_mut(index).filter(|entry| entry.is_valid())
    }

    pub fn get_by_index(&self, index: SymbolIndex) -> Option<(SymbolId, &SymbolEntry<A>)> {
        let id = self.indices.get(&index)?;
        self.get_by_id(*id).map(|sym_entry| (*id, sym_entry))
    }

    pub fn modify_by_id<R>(
        &mut self,
        id: SymbolId,
        f: impl FnOnce(&mut SymbolEntry<A>) -> R,
    ) -> Option<R> {
        self.get_by_id_mut(id).map(f)
    }

    pub fn get_by_index_mut(
        &mut self,
        index: SymbolIndex,
    ) -> Option<(SymbolId, &mut SymbolEntry<A>)> {
        let id = self.indices.get(&index)?;
        self.symbols
            .get_mut(id.index())
            .map(|sym_entry| (*id, sym_entry))
    }

    pub fn get_by_address(
        &self,
        address: impl Into<A>,
    ) -> impl Iterator<Item = (SymbolId, &SymbolEntry<A>)> {
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
    ) -> impl Iterator<Item = (SymbolId, &mut SymbolEntry<A>)> {
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
    ) -> Option<(SymbolId, &SymbolEntry<A>)> {
        self.get_by_address(address).next()
    }

    pub fn get_first_by_address_mut(
        &mut self,
        address: impl Into<A>,
    ) -> Option<(SymbolId, &mut SymbolEntry<A>)> {
        self.get_by_address_mut(address).next()
    }

    pub fn contains(&self, symbol: impl AsRef<str>) -> bool {
        let Some(symbol) = Symbol::from_existing(symbol.as_ref()) else {
            return false;
        };
        self.names.contains_key(&symbol)
    }

    pub fn contains_by_index(&self, index: SymbolIndex) -> bool {
        self.indices.contains_key(&index)
    }

    pub fn contains_by_address(&self, address: impl Into<A>) -> bool {
        self.addresses.contains_key(&address.into())
    }

    pub fn insert_local(
        &mut self,
        index: SymbolIndex,
        address: impl Into<A>,
        symbol: impl Into<Symbol>,
    ) -> SymbolInsertion {
        self.insert_local_with(index, address, symbol, SymbolProperties::NONE)
    }

    pub fn insert_local_with(
        &mut self,
        index: SymbolIndex,
        address: impl Into<A>,
        symbol: impl Into<Symbol>,
        properties: SymbolProperties,
    ) -> SymbolInsertion {
        self.insert(index, address, symbol, properties | SymbolProperties::LOCAL)
    }

    pub fn insert_extern(
        &mut self,
        index: SymbolIndex,
        address: impl Into<A>,
        symbol: impl Into<Symbol>,
    ) -> SymbolInsertion {
        self.insert_extern_with(index, address, symbol, SymbolProperties::NONE)
    }

    pub fn insert_extern_with(
        &mut self,
        index: SymbolIndex,
        address: impl Into<A>,
        symbol: impl Into<Symbol>,
        properties: SymbolProperties,
    ) -> SymbolInsertion {
        self.insert(
            index,
            address,
            symbol,
            properties | SymbolProperties::EXTERN,
        )
    }

    fn insert_or_update(
        addresses: &mut BTreeMap<A, SmallVec<[SymbolId; 2]>>,
        names: &mut SymbolMap<SmallVec<[SymbolId; 2]>>,
        symbols: &mut Vec<SymbolEntry<A>>,
        generations: &mut Vec<u32>,
        allocator: &mut IdAllocator<Symbol>,
        index: SymbolIndex,
        entry: SymbolEntry<A>,
    ) -> SymbolInsertion {
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

            SymbolInsertion::new(symbol_id, false)
        } else {
            let symbol_id = allocator.allocate();
            if symbol_id.index() < symbols.len() {
                symbols[symbol_id.index()] = entry;
                generations[symbol_id.index()] = symbol_id.generation();
            } else {
                symbols.push(entry);
                generations.push(symbol_id.generation());
            }

            names.entry(symbol).or_default().push(symbol_id);
            addresses.entry(address).or_default().push(symbol_id);

            SymbolInsertion::new(symbol_id, true)
        }
    }

    pub fn insert(
        &mut self,
        index: SymbolIndex,
        address: impl Into<A>,
        symbol: impl Into<Symbol>,
        properties: SymbolProperties,
    ) -> SymbolInsertion {
        use std::collections::btree_map::Entry;

        let address = address.into();
        let symbol = symbol.into();
        let symbol_entry = SymbolEntry::new(address, symbol, properties).with_index(index);

        match self.indices.entry(index) {
            Entry::Vacant(entry) => {
                let insertion = Self::insert_or_update(
                    &mut self.addresses,
                    &mut self.names,
                    &mut self.symbols,
                    &mut self.generations,
                    &mut self.allocator,
                    index,
                    symbol_entry,
                );

                entry.insert(insertion.id());

                insertion
            }
            Entry::Occupied(mut entry) => {
                let symbol_id = *entry.get();
                let existing = &mut self.symbols[symbol_id.index()];

                if *existing == symbol_entry {
                    return SymbolInsertion::new(symbol_id, false);
                }

                // NOTE: if existing has multiple indices referring to it, then
                // we just remove this one, and create a new symbol entry.
                if existing.indices().len() > 1 {
                    // remove the index from existing
                    existing.remove_index(index);

                    let insertion = Self::insert_or_update(
                        &mut self.addresses,
                        &mut self.names,
                        &mut self.symbols,
                        &mut self.generations,
                        &mut self.allocator,
                        index,
                        symbol_entry,
                    );

                    entry.insert(insertion.id());

                    return insertion;
                }

                // NOTE: we have a single referent, so it's easier to remove the current
                // entry and just insert
                self.remove_by_id(symbol_id);
                self.insert(index, address, symbol, properties)
            }
        }
    }

    // Iterator over all symbol entries in insertion order.
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = (SymbolId, &'a SymbolEntry<A>)> + 'a {
        self.symbols
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.is_valid())
            .map(|(i, entry)| {
                let id = SymbolId::with_generation(i as u32, self.generations[i]);
                (id, entry)
            })
    }

    pub(super) fn into_entries(self) -> impl Iterator<Item = SymbolEntry<A>> {
        self.symbols.into_iter().filter(SymbolEntry::is_valid)
    }

    // Iterator over all symbol entries for a given selector.
    pub fn iter_by_selector<'a>(
        &'a self,
        selector: SymbolTableSelector,
    ) -> impl Iterator<Item = (SymbolId, &'a SymbolEntry<A>)> + 'a {
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
    ) -> impl Iterator<Item = (SymbolId, &'a SymbolEntry<A>)> + 'a {
        self.addresses
            .values()
            .flat_map(move |ids| SymbolEntryIter::new(ids, &self.symbols))
    }

    pub fn range_by_address<'a, R>(
        &'a self,
        range: R,
    ) -> impl Iterator<Item = (SymbolId, &'a SymbolEntry<A>)> + 'a
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
    ) -> impl Iterator<Item = (SymbolIndex, SymbolId, &'a SymbolEntry<A>)> + 'a {
        self.indices
            .iter()
            .map(move |(&index, &id)| (index, id, &self.symbols[id.index()]))
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.symbols.len() - self.allocator.free_count()
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
            self.allocator.release(id);
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
            self.allocator.release(id);
        }

        count
    }

    pub fn remove_by_id(&mut self, id: SymbolId) -> bool {
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
        self.allocator.release(id);

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
    use crate::ir::symbol::SymbolTableSelector;

    #[test]
    fn symbol_index_free_list() {
        let mut table = SymbolTable::<Address>::new();
        let sel = SymbolTableSelector::new(0);

        let insertion = table.insert_local(
            SymbolIndex::new(sel, 1),
            Address::from(0x1000u32),
            "symbol1",
        );
        assert!(insertion.is_new());
        let id1 = insertion.id();

        let insertion = table.insert_local(
            SymbolIndex::new(sel, 2),
            Address::from(0x2000u32),
            "symbol2",
        );
        assert!(insertion.is_new());

        assert_eq!(table.len(), 2);

        let removed = table.remove_by_id(id1);
        assert!(removed);
        assert_eq!(table.len(), 1);

        let insertion = table.insert_local(
            SymbolIndex::new(sel, 3),
            Address::from(0x3000u32),
            "symbol3",
        );
        assert!(insertion.is_new());
        let id3 = insertion.id();
        assert_eq!(table.len(), 2);

        assert_eq!(id1.index(), id3.index());
        assert_eq!(id1.generation() + 1, id3.generation());
        assert!(table.get_by_id(id1).is_none());
        assert!(!table.remove_by_id(id1));
        assert_eq!(table.len(), 2);

        let insertion = table.insert_local(
            SymbolIndex::new(sel, 4),
            Address::from(0x3000u32),
            "symbol3",
        );
        assert!(!insertion.is_new());
        let id4 = insertion.id();
        assert_eq!(table.len(), 2);

        // check that the ID is the same as the existing one (same referent, different symbol index)
        assert_eq!(id3, id4);

        let insertion = table.insert_local(
            SymbolIndex::new(sel, 5),
            Address::from(0x3000u32),
            "symbol4",
        );
        assert!(insertion.is_new());

        // check that we inserted a new symbol referring to the same address as id3 and id4
        assert_eq!(table.len(), 3);

        let mut ntable = table.clone();

        // check we remove id3 and id4, which will have two indices associated with it, but one symbol
        assert_eq!(table.remove("symbol3"), 1);
        assert_eq!(table.len(), 2);

        // check we remove id3, id4, and id5, which will be two distinct symbols
        assert_eq!(ntable.remove_by_address(Address::from(0x3000u32)), 2);
        assert_eq!(ntable.len(), 1);
    }
}
