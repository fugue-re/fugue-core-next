use std::collections::BTreeMap;
use std::ops::{Bound, RangeBounds};

use super::{FunctionIndex, FunctionTableAllocation, FunctionTableError};
use crate::ir::{Address, Function, Id, RawAddress};
use crate::storage::EntityStorageError;
use crate::storage::segments::space::AddressSpaceId;

fn address_start_bound(space: AddressSpaceId, bound: Bound<&RawAddress>) -> Bound<Address> {
    match bound {
        Bound::Included(address) => Bound::Included(Address::new(space, *address)),
        Bound::Excluded(address) => Bound::Excluded(Address::new(space, *address)),
        Bound::Unbounded => Bound::Included(Address::new(space, RawAddress::zero())),
    }
}

fn address_end_bound(space: AddressSpaceId, bound: Bound<&RawAddress>) -> Bound<Address> {
    match bound {
        Bound::Included(address) => Bound::Included(Address::new(space, *address)),
        Bound::Excluded(address) => Bound::Excluded(Address::new(space, *address)),
        Bound::Unbounded => Bound::Included(Address::new(space, RawAddress::MAX)),
    }
}

pub struct FunctionTable {
    index: FunctionIndex,
    entries: Vec<Option<Function>>,
}

impl Default for FunctionTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionTable {
    pub fn new() -> Self {
        Self {
            index: FunctionIndex {
                addresses: BTreeMap::new(),
                free_ids: Vec::new(),
                next_index: 0,
            },
            entries: Vec::new(),
        }
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        Ok(())
    }

    pub(super) fn allocation_checkpoint(&self, max_pops: usize) -> FunctionTableAllocation {
        FunctionTableAllocation::new(&self.index.free_ids, self.index.next_index, max_pops)
    }

    pub(super) fn restore_allocation(&mut self, allocation: FunctionTableAllocation) {
        let tail_start = allocation.free_ids_len - allocation.free_ids_tail.len();
        self.index.free_ids.truncate(tail_start);
        self.index.free_ids.extend(allocation.free_ids_tail);
        self.index.next_index = allocation.next_index;
    }

    pub(super) fn restore_entry(&mut self, function: Function) {
        let id = function.id();
        let index = id.index();
        if index >= self.entries.len() {
            self.entries.resize_with(index + 1, || None);
        }
        self.index.addresses.insert(function.entry(), id);
        self.index.next_index = self.index.next_index.max(index + 1);
        self.index
            .free_ids
            .retain(|free_id| free_id.index() != index);
        self.entries[index] = Some(function);
    }

    pub(super) fn clear_entry(&mut self, id: Id<Function>) -> bool {
        let Some(function) = self.get_by_id(id) else {
            return false;
        };
        let entry = function.entry();

        self.index.addresses.remove(&entry);
        self.entries[id.index()] = None;
        true
    }

    pub fn insert<F>(&mut self, addr: Address, f: F) -> Result<Id<Function>, FunctionTableError>
    where
        F: FnOnce(Id<Function>, Address) -> Result<Function, FunctionTableError>,
    {
        if let Some(&existing) = self.index.addresses.get(&addr) {
            let function = f(existing, addr)?;

            if function.entry() != addr {
                return Err(FunctionTableError::AddressMismatch);
            }

            self.entries[existing.index()] = Some(function);

            return Ok(existing);
        }

        let reuse_id = self.index.free_ids.last().copied();
        let id = reuse_id.unwrap_or_else(|| Id::from_index(self.index.next_index));

        let function = f(id, addr)?;

        if function.entry() != addr {
            return Err(FunctionTableError::AddressMismatch);
        }

        self.index.addresses.insert(addr, id);

        if reuse_id.is_some() {
            self.index.free_ids.pop();
        } else {
            self.index.next_index += 1;
        }

        let index = id.index();
        if index >= self.entries.len() {
            self.entries.resize_with(index + 1, || None);
        }
        self.entries[index] = Some(function);

        Ok(id)
    }

    pub fn get_by_id(&self, id: Id<Function>) -> Option<&Function> {
        self.entries
            .get(id.index())?
            .as_ref()
            .filter(|function| function.id() == id)
    }

    pub fn get_by_address(&self, addr: Address) -> Option<&Function> {
        let id = *self.index.addresses.get(&addr)?;
        self.get_by_id(id)
    }

    pub fn get_by_id_mut(&mut self, id: Id<Function>) -> Option<&mut Function> {
        self.entries
            .get_mut(id.index())?
            .as_mut()
            .filter(|function| function.id() == id)
    }

    pub fn get_by_address_mut(&mut self, addr: Address) -> Option<&mut Function> {
        let id = *self.index.addresses.get(&addr)?;
        self.get_by_id_mut(id)
    }

    pub fn modify_by_id<R>(
        &mut self,
        id: Id<Function>,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Option<R> {
        self.get_by_id_mut(id).map(f)
    }

    pub fn modify_by_address<R>(
        &mut self,
        addr: Address,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Option<R> {
        self.get_by_address_mut(addr).map(f)
    }

    pub fn remove_by_id(&mut self, id: Id<Function>) -> bool {
        let Some(function) = self.entries.get_mut(id.index()).and_then(Option::take) else {
            return false;
        };

        self.index.addresses.remove(&function.entry());
        self.index.free_ids.push(id.next_generation());

        true
    }

    pub fn remove_by_address(&mut self, addr: Address) -> bool {
        let Some(id) = self.index.addresses.remove(&addr) else {
            return false;
        };

        if let Some(slot) = self.entries.get_mut(id.index()) {
            *slot = None;
        }
        self.index.free_ids.push(id.next_generation());

        true
    }

    pub fn addresses(&self) -> impl Iterator<Item = Address> + '_ {
        self.index.addresses.keys().copied()
    }

    pub fn addresses_in_range<R>(
        &self,
        space: AddressSpaceId,
        range: R,
    ) -> impl Iterator<Item = Address> + '_
    where
        R: RangeBounds<RawAddress>,
    {
        let start = address_start_bound(space, range.start_bound());
        let end = address_end_bound(space, range.end_bound());
        self.index
            .addresses
            .range((start, end))
            .map(|(address, _)| *address)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Function> + '_ {
        self.entries.iter().filter_map(Option::as_ref)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Function> + '_ {
        self.entries.iter_mut().filter_map(Option::as_mut)
    }

    pub fn is_empty(&self) -> bool {
        self.index.addresses.is_empty()
    }

    pub fn len(&self) -> usize {
        self.index.addresses.len()
    }
}
