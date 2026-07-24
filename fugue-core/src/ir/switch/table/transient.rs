use super::{SwitchIndex, SwitchTableAllocation, SwitchTableError};
use crate::ir::switch::{Switch, SwitchId};
use crate::ir::{Address, FunctionId};
use crate::storage::EntityStorageError;

pub struct SwitchTable {
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
            index: SwitchIndex::new(),
            entries: Vec::new(),
        }
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        Ok(())
    }

    pub fn branches_of_function(&self, function: FunctionId) -> impl Iterator<Item = Address> + '_ {
        self.index.branches_of_function(function)
    }

    pub(crate) fn allocation_checkpoint(&self, max_pops: usize) -> SwitchTableAllocation {
        self.index.allocator.checkpoint(max_pops)
    }

    pub(crate) fn restore_allocation(&mut self, allocation: SwitchTableAllocation) {
        self.index.allocator.restore(allocation);
    }

    pub(crate) fn restore_entry(&mut self, switch: Switch) {
        let id = switch.id();
        self.clear_entry(id);

        self.index.insert(id, switch.function(), switch.branch());
        self.index.allocator.mark_allocated(id);

        let slot = id.index();
        if slot >= self.entries.len() {
            self.entries.resize_with(slot + 1, || None);
        }
        self.entries[slot] = Some(switch);
    }

    pub(crate) fn clear_entry(&mut self, id: SwitchId) -> bool {
        let Some(switch) = self
            .entries
            .get_mut(id.index())
            .and_then(|entry| entry.take_if(|switch| switch.id() == id))
        else {
            return false;
        };
        self.index.remove(switch.function(), switch.branch());
        true
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
            if let Some(previous) = self.entries[existing.index()].as_ref() {
                self.index.remove(previous.function(), branch);
            }
            self.index.insert(existing, switch.function(), branch);
            self.entries[existing.index()] = Some(switch);
            return Ok(existing);
        }

        let (id, switch) = self.index.allocator.try_allocate(|id| {
            let switch = f(id, branch)?;
            if switch.branch() != branch {
                return Err(SwitchTableError::AddressMismatch);
            }
            Ok(switch)
        })?;

        self.index.insert(id, switch.function(), branch);

        let slot = id.index();
        if slot >= self.entries.len() {
            self.entries.resize_with(slot + 1, || None);
        }
        self.entries[slot] = Some(switch);

        Ok(id)
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

    pub fn get_by_id_mut(&mut self, id: SwitchId) -> Option<&mut Switch> {
        self.entries
            .get_mut(id.index())?
            .as_mut()
            .filter(|switch| switch.id() == id)
    }

    pub fn modify_by_id<R>(&mut self, id: SwitchId, f: impl FnOnce(&mut Switch) -> R) -> Option<R> {
        let switch = self
            .entries
            .get_mut(id.index())?
            .as_mut()
            .filter(|switch| switch.id() == id)?;
        let previous_function = switch.function();
        let branch = switch.branch();
        let result = f(switch);
        let function = switch.function();

        if function != previous_function {
            self.index.remove(previous_function, branch);
            self.index.insert(id, function, branch);
        }

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
        self.index.remove(switch.function(), switch.branch());
        self.index.allocator.release(id);
        true
    }

    pub fn remove_by_branch(&mut self, branch: Address) -> bool {
        let Some(id) = self.index.id_by_branch(branch) else {
            return false;
        };
        self.remove_by_id(id)
    }

    pub fn branches(&self) -> impl Iterator<Item = Address> + '_ {
        self.index.branches()
    }

    pub fn entries_after(&self, after: Option<Address>) -> impl Iterator<Item = &Switch> + '_ {
        self.index
            .entries_after(after)
            .filter_map(|(_, id)| self.get_by_id(id))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Switch> + '_ {
        self.entries.iter().filter_map(Option::as_ref)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Switch> + '_ {
        self.entries.iter_mut().filter_map(Option::as_mut)
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }
}
