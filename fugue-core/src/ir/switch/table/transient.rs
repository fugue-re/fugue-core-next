use std::ops::Bound;

use super::{SwitchIndex, SwitchTableAllocation, SwitchTableError};
use crate::ir::switch::{Switch, SwitchId};
use crate::ir::{Address, FunctionId, Id};
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
        SwitchTableAllocation::new(&self.index.free_ids, self.index.next_index, max_pops)
    }

    pub(crate) fn restore_allocation(&mut self, allocation: SwitchTableAllocation) {
        let tail_start = allocation.free_ids_len - allocation.free_ids_tail.len();
        self.index.free_ids.truncate(tail_start);
        self.index.free_ids.extend(allocation.free_ids_tail);
        self.index.next_index = allocation.next_index;
    }

    pub(crate) fn restore_entry(&mut self, switch: Switch) {
        let id = switch.id();
        self.index.branches.insert(switch.branch(), id);
        self.index.link(switch.function(), switch.branch());
        self.index.next_index = self.index.next_index.max(id.index() + 1);
        self.index
            .free_ids
            .retain(|free_id| free_id.index() != id.index());

        let slot = id.index();
        if slot >= self.entries.len() {
            self.entries.resize_with(slot + 1, || None);
        }
        self.entries[slot] = Some(switch);
    }

    pub(crate) fn clear_entry(&mut self, id: SwitchId) -> bool {
        let Some(switch) = self.entries.get_mut(id.index()).and_then(Option::take) else {
            return false;
        };
        self.index.unlink(switch.function(), switch.branch());
        self.index.branches.remove(&switch.branch());
        true
    }

    pub fn insert<F>(&mut self, branch: Address, f: F) -> Result<SwitchId, SwitchTableError>
    where
        F: FnOnce(SwitchId, Address) -> Switch,
    {
        if let Some(&existing) = self.index.branches.get(&branch) {
            let switch = f(existing, branch);
            if switch.branch() != branch {
                return Err(SwitchTableError::AddressMismatch);
            }
            if let Some(previous) = self.entries[existing.index()].as_ref() {
                let previous_function = previous.function();
                self.index.unlink(previous_function, branch);
            }
            self.index.link(switch.function(), branch);
            self.entries[existing.index()] = Some(switch);
            return Ok(existing);
        }

        let reuse_id = self.index.free_ids.last().copied();
        let id = reuse_id.unwrap_or_else(|| Id::from_index(self.index.next_index));

        let switch = f(id, branch);
        if switch.branch() != branch {
            return Err(SwitchTableError::AddressMismatch);
        }

        self.index.branches.insert(branch, id);
        self.index.link(switch.function(), branch);
        if reuse_id.is_some() {
            self.index.free_ids.pop();
        } else {
            self.index.next_index += 1;
        }

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
        let id = *self.index.branches.get(&branch)?;
        self.get_by_id(id)
    }

    pub fn contains(&self, branch: Address) -> bool {
        self.index.branches.contains_key(&branch)
    }

    pub fn get_by_id_mut(&mut self, id: SwitchId) -> Option<&mut Switch> {
        self.entries
            .get_mut(id.index())?
            .as_mut()
            .filter(|switch| switch.id() == id)
    }

    pub fn modify_by_id<R>(&mut self, id: SwitchId, f: impl FnOnce(&mut Switch) -> R) -> Option<R> {
        self.get_by_id_mut(id).map(f)
    }

    pub fn modify_by_branch<R>(
        &mut self,
        branch: Address,
        f: impl FnOnce(&mut Switch) -> R,
    ) -> Option<R> {
        let id = *self.index.branches.get(&branch)?;
        self.modify_by_id(id, f)
    }

    pub fn remove_by_id(&mut self, id: SwitchId) -> bool {
        let Some(switch) = self.entries.get_mut(id.index()).and_then(Option::take) else {
            return false;
        };
        self.index.unlink(switch.function(), switch.branch());
        self.index.branches.remove(&switch.branch());
        self.index.free_ids.push(id.next_generation());
        true
    }

    pub fn remove_by_branch(&mut self, branch: Address) -> bool {
        let Some(id) = self.index.branches.remove(&branch) else {
            return false;
        };
        if let Some(switch) = self.entries.get_mut(id.index()).and_then(Option::take) {
            self.index.unlink(switch.function(), branch);
        }
        self.index.free_ids.push(id.next_generation());
        true
    }

    pub fn branches(&self) -> impl Iterator<Item = Address> + '_ {
        self.index.branches.keys().copied()
    }

    pub fn branches_after(&self, after: Option<Address>) -> impl Iterator<Item = Address> + '_ {
        let start = after.map_or(Bound::Unbounded, Bound::Excluded);
        self.index
            .branches
            .range((start, Bound::Unbounded))
            .map(|(address, _)| *address)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Switch> + '_ {
        self.entries.iter().filter_map(Option::as_ref)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Switch> + '_ {
        self.entries.iter_mut().filter_map(Option::as_mut)
    }

    pub fn is_empty(&self) -> bool {
        self.index.branches.is_empty()
    }

    pub fn len(&self) -> usize {
        self.index.branches.len()
    }
}
