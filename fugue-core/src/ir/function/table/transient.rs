use std::collections::BTreeMap;
use std::ops::RangeBounds;

use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use super::{FunctionIndex, FunctionTableError};
use crate::ir::{Address, CodeBlockId, Function, FunctionId, Id, IdAllocator, IdSet, RawAddress};
use crate::storage::segments::space::AddressSpaceId;

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
            index: FunctionIndex::new(IdAllocator::new(), BTreeMap::new()),
            entries: Vec::new(),
        }
    }

    pub(crate) fn pending_id(&self, offset: usize) -> FunctionId {
        self.index.allocator.pending_id(offset)
    }

    pub fn get_by_id(&self, id: Id<Function>) -> Option<&Function> {
        self.entries
            .get(id.index())?
            .as_ref()
            .filter(|function| function.id() == id)
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

    pub fn contains(&self, addr: Address) -> bool {
        self.index.addresses.contains_key(&addr)
    }

    pub fn addresses(&self) -> impl Iterator<Item = Address> + '_ {
        self.index.addresses.keys().copied()
    }

    pub(crate) fn get_by_block_id(&self, block: CodeBlockId) -> IdSet<Function> {
        self.index.get_by_block_id(block)
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

    pub(crate) fn publish_reservations(&mut self, reservations: &[FunctionId]) {
        let mut required = self.entries.len();
        for &id in reservations {
            let allocated = self.index.allocator.allocate();
            debug_assert_eq!(allocated, id);
            required = required.max(id.index() + 1);
        }
        if required > self.entries.len() {
            self.entries.resize_with(required, || None);
        }
    }

    pub(crate) fn publish_release(&mut self, id: FunctionId) {
        self.index.allocator.release(id);
    }

    pub(crate) fn publish_upsert(&mut self, function: Function, previous_entry: Option<Address>) {
        if let Some(previous_entry) = previous_entry {
            self.index.addresses.remove(&previous_entry);
        }
        let id = function.id();
        let index = id.index();
        if index >= self.entries.len() {
            self.entries.resize_with(index + 1, || None);
        }
        self.index.addresses.insert(function.entry(), id);
        self.entries[index] = Some(function);
    }

    pub(crate) fn publish_remove(&mut self, id: FunctionId, entry: Address) {
        self.index.addresses.remove(&entry);
        self.entries[id.index()] = None;
        self.index.allocator.release(id);
    }

    pub(crate) fn publish_membership(&mut self, by_block: FxHashMap<CodeBlockId, IdSet<Function>>) {
        self.index.publish_membership(by_block);
    }

    pub(crate) fn insert_with<R, F>(
        &mut self,
        addr: Address,
        f: F,
    ) -> Result<(FunctionId, R), FunctionTableError>
    where
        F: FnOnce(Id<Function>, Address) -> Result<(Function, R), FunctionTableError>,
    {
        if let Some(&existing) = self.index.addresses.get(&addr) {
            let (function, value) = f(existing, addr)?;

            if function.entry() != addr {
                return Err(FunctionTableError::AddressMismatch);
            }

            let previous_blocks = self.entries[existing.index()].as_ref().map(|previous| {
                previous
                    .blocks()
                    .map(|(_, block)| block)
                    .collect::<SmallVec<[_; 8]>>()
            });
            let blocks = function
                .blocks()
                .map(|(_, block)| block)
                .collect::<SmallVec<[_; 8]>>();
            self.entries[existing.index()] = Some(function);
            self.index
                .remove_memberships(existing, previous_blocks.iter().flatten().copied());
            self.index.insert_memberships(existing, blocks);

            return Ok((existing, value));
        }

        let (id, (function, value)) = self.index.allocator.try_allocate(|id| {
            let (function, value) = f(id, addr)?;
            if function.entry() != addr {
                return Err(FunctionTableError::AddressMismatch);
            }
            Ok((function, value))
        })?;

        self.index.addresses.insert(addr, id);
        self.index.insert_membership(&function);

        let index = id.index();
        if index >= self.entries.len() {
            self.entries.resize_with(index + 1, || None);
        }
        self.entries[index] = Some(function);

        Ok((id, value))
    }

    pub fn get_by_address(&self, addr: Address) -> Option<&Function> {
        let id = *self.index.addresses.get(&addr)?;
        self.get_by_id(id)
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
        let Some(function) = self
            .entries
            .get_mut(id.index())
            .and_then(|slot| slot.take_if(|function| function.id() == id))
        else {
            return false;
        };

        self.index.addresses.remove(&function.entry());
        self.index.remove_membership(&function);
        self.index.allocator.release(id);

        true
    }

    pub fn remove_by_address(&mut self, addr: Address) -> bool {
        let Some(id) = self.index.addresses.remove(&addr) else {
            return false;
        };

        if let Some(function) = self.entries.get_mut(id.index()).and_then(Option::take) {
            self.index.remove_membership(&function);
        }
        self.index.allocator.release(id);

        true
    }

    pub fn addresses_in_range<R>(
        &self,
        space: AddressSpaceId,
        range: R,
    ) -> impl Iterator<Item = Address> + '_
    where
        R: RangeBounds<RawAddress>,
    {
        let (start, end) = Address::bounds_in_space(space, &range);
        self.index
            .addresses
            .range((start, end))
            .map(|(address, _)| *address)
    }
}
