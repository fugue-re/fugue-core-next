use std::collections::BTreeMap;
use std::mem;
use std::ops::RangeBounds;
use std::slice::Iter;

use smallvec::SmallVec;

use super::super::{SymbolEntry, SymbolIndex, SymbolMap, SymbolProperties, SymbolTableSelector};
use crate::ir::symbol::Symbol;
use crate::ir::{Address, Id};

pub(super) struct Allocation {
    symbols_len: usize,
    generations_len: usize,
    free_ids_len: usize,
    free_ids_tail: Vec<Id<Symbol>>,
}

impl Allocation {
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

#[derive(Clone)]
pub(super) struct SymbolEntryIter<'a, A = Address> {
    ids: Iter<'a, Id<Symbol>>,
    symbols: &'a [SymbolEntry<A>],
}

impl<'a, A> SymbolEntryIter<'a, A> {
    pub(super) fn new(ids: &'a [Id<Symbol>], symbols: &'a [SymbolEntry<A>]) -> Self {
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

pub(super) struct SymbolEntryIterMut<'a, A = Address> {
    ids: Iter<'a, Id<Symbol>>,
    symbols: &'a mut [SymbolEntry<A>],
}

impl<'a, A> SymbolEntryIterMut<'a, A> {
    pub(super) fn new(ids: &'a [Id<Symbol>], symbols: &'a mut [SymbolEntry<A>]) -> Self {
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

    pub(super) fn allocation_checkpoint(&self, max_pops: usize) -> Allocation {
        Allocation::new(
            &self.free_ids,
            self.symbols.len(),
            self.generations.len(),
            max_pops,
        )
    }

    pub(super) fn restore_allocation(&mut self, allocation: Allocation) {
        let tail_start = allocation.free_ids_len - allocation.free_ids_tail.len();
        self.free_ids.truncate(tail_start);
        self.free_ids.extend(allocation.free_ids_tail);
        self.symbols.truncate(allocation.symbols_len);
        self.generations.truncate(allocation.generations_len);
    }

    pub(super) fn restore_entry(&mut self, id: Id<Symbol>, entry: SymbolEntry<A>) {
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

    pub(super) fn clear_entry(&mut self, id: Id<Symbol>) -> bool {
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

    pub(super) fn touched_by_insert(
        &self,
        index: SymbolIndex,
        entry: &SymbolEntry<A>,
    ) -> Vec<Id<Symbol>> {
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

        touched
    }

    pub(super) fn ids_by_symbol(&self, symbol: impl AsRef<str>) -> Vec<Id<Symbol>> {
        Symbol::from_existing(symbol.as_ref())
            .and_then(|symbol| self.names.get(&symbol))
            .map(|ids| ids.to_vec())
            .unwrap_or_default()
    }

    pub(super) fn ids_by_address(&self, address: A) -> Vec<Id<Symbol>> {
        self.addresses
            .get(&address)
            .map(|ids| ids.to_vec())
            .unwrap_or_default()
    }

    pub(super) fn id_by_index(&self, index: SymbolIndex) -> Option<Id<Symbol>> {
        self.indices.get(&index).copied()
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
                    existing.remove_index(index);

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
    use crate::ir::symbol::SymbolTableSelector;

    #[test]
    fn test_symbol_index_free_list() {
        let mut table = SymbolTable::<Address>::new();
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
    }
}
