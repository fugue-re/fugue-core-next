use super::{SwitchIndex, SwitchTableError};
use crate::ir::switch::{Switch, SwitchId};
use crate::ir::{Address, AddressRange, IdAllocator};

pub struct SwitchTable {
    allocator: IdAllocator<Switch>,
    index: SwitchIndex,
    entries: Vec<Option<Switch>>,
}

impl Default for SwitchTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SwitchTable {
    pub fn new() -> Self {
        Self {
            allocator: IdAllocator::new(),
            index: SwitchIndex::new(),
            entries: Vec::new(),
        }
    }

    pub(crate) fn pending_id(&self, offset: usize) -> SwitchId {
        self.allocator.pending_id(offset)
    }

    pub fn get_by_id(&self, id: SwitchId) -> Option<&Switch> {
        self.entries
            .get(id.index())?
            .as_ref()
            .filter(|switch| switch.id() == id)
    }

    pub fn get_by_branch(&self, branch: Address) -> Option<&Switch> {
        let id = self.index.id_by_branch(branch)?;
        self.get_by_id(id)
    }

    pub fn contains(&self, branch: Address) -> bool {
        self.index.contains(branch)
    }

    pub fn branches(&self) -> impl Iterator<Item = Address> + '_ {
        self.index.branches()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Switch> + '_ {
        self.entries.iter().filter_map(Option::as_ref)
    }

    pub fn entries_after(&self, after: Option<Address>) -> impl Iterator<Item = &Switch> + '_ {
        self.index
            .entries_after(after)
            .filter_map(|(_, id)| self.get_by_id(id))
    }

    pub fn overlaps(&self, range: &AddressRange) -> impl Iterator<Item = &Switch> + '_ {
        self.index
            .overlaps(range)
            .into_iter()
            .filter_map(|id| self.get_by_id(id))
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn insert<F>(&mut self, branch: Address, f: F) -> Result<SwitchId, SwitchTableError>
    where
        F: FnOnce(SwitchId, Address) -> Result<Switch, SwitchTableError>,
    {
        if let Some(existing) = self.index.id_by_branch(branch) {
            let switch = f(existing, branch)?;
            if switch.branch() != branch {
                return Err(SwitchTableError::AddressMismatch);
            }
            self.store(switch);
            return Ok(existing);
        }

        let (id, switch) = self.allocator.try_allocate(|id| {
            let switch = f(id, branch)?;
            if switch.branch() != branch {
                return Err(SwitchTableError::AddressMismatch);
            }
            Ok(switch)
        })?;

        self.store(switch);

        Ok(id)
    }

    pub fn modify_by_id<R>(&mut self, id: SwitchId, f: impl FnOnce(&mut Switch) -> R) -> Option<R> {
        let switch = self
            .entries
            .get_mut(id.index())?
            .as_mut()
            .filter(|switch| switch.id() == id)?;
        self.index
            .remove(switch.id(), switch.branch(), &switch.coverage());
        let result = f(switch);
        self.index.insert(switch);
        Some(result)
    }

    pub fn modify_by_branch<R>(
        &mut self,
        branch: Address,
        f: impl FnOnce(&mut Switch) -> R,
    ) -> Option<R> {
        let id = self.index.id_by_branch(branch)?;
        self.modify_by_id(id, f)
    }

    pub fn remove_by_id(&mut self, id: SwitchId) -> bool {
        let Some(switch) = self
            .entries
            .get_mut(id.index())
            .and_then(|entry| entry.take_if(|switch| switch.id() == id))
        else {
            return false;
        };
        self.index.remove(id, switch.branch(), &switch.coverage());
        self.allocator.release(id);
        true
    }

    pub fn remove_by_branch(&mut self, branch: Address) -> bool {
        let Some(id) = self.index.id_by_branch(branch) else {
            return false;
        };
        self.remove_by_id(id)
    }

    pub(crate) fn publish_reservation(&mut self, id: SwitchId) {
        let allocated = self.allocator.allocate();
        debug_assert_eq!(allocated, id);
    }

    pub(crate) fn publish_release(&mut self, id: SwitchId) {
        self.allocator.release(id);
    }

    pub(crate) fn publish_upsert(&mut self, switch: Switch) {
        self.store(switch);
    }

    pub(crate) fn publish_remove(&mut self, id: SwitchId) {
        if let Some(switch) = self.entries[id.index()].take() {
            self.index.remove(id, switch.branch(), &switch.coverage());
        }
        self.allocator.release(id);
    }

    fn store(&mut self, switch: Switch) {
        let slot = switch.id().index();
        if slot >= self.entries.len() {
            self.entries.resize_with(slot + 1, || None);
        }
        if let Some(previous) = self.entries[slot].take() {
            self.index
                .remove(previous.id(), previous.branch(), &previous.coverage());
        }
        self.index.insert(&switch);
        self.entries[slot] = Some(switch);
    }
}
