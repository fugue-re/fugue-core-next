use std::ops::Bound;
use std::sync::Arc;

use super::{SwitchIndex, SwitchTableAllocation, SwitchTableError};
use crate::ir::switch::{Switch, SwitchId};
use crate::ir::{Address, FunctionId, Id};
use crate::storage::entities::{CachedMut, CachedRef, EntityCache, WriteBackWorker};
use crate::storage::{EntityStorage, EntityStorageError};

type Ref<'a> = CachedRef<'a, Switch>;
type RefMut<'a> = CachedMut<'a, Switch>;

pub struct SwitchTable {
    index: SwitchIndex,
    entries: EntityCache<SwitchId, Switch>,
}

impl SwitchTable {
    pub(crate) fn new(
        entities: EntityStorage,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Self::from_entries(EntityCache::new(entities, cache_bytes)?)
    }

    pub(crate) fn new_with(
        entities: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Self::from_entries(EntityCache::with_worker(entities, worker, cache_bytes))
    }

    fn from_entries(entries: EntityCache<SwitchId, Switch>) -> Result<Self, EntityStorageError> {
        let mut index = SwitchIndex::new();

        for entry in entries.try_scan_range(Bound::Unbounded)? {
            let (id, switch) = entry?;
            index.branches.insert(switch.branch(), id);
            index.link(switch.function(), switch.branch());
            index.next_index = index.next_index.max(id.index() + 1);
        }

        Ok(Self { index, entries })
    }

    pub(crate) fn branches_of_function(
        &self,
        function: FunctionId,
    ) -> impl Iterator<Item = Address> + '_ {
        self.index.branches_of_function(function)
    }

    pub(crate) fn flush(&self) -> Result<(), EntityStorageError> {
        self.entries.flush()
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

    pub(crate) fn restore_entry(&mut self, switch: Switch) -> Result<(), EntityStorageError> {
        let id = switch.id();
        self.index.branches.insert(switch.branch(), id);
        self.index.link(switch.function(), switch.branch());
        self.index.next_index = self.index.next_index.max(id.index() + 1);
        self.index
            .free_ids
            .retain(|free_id| free_id.index() != id.index());
        self.entries.try_put(id, switch).map(|_| ())
    }

    pub(crate) fn clear_entry(&mut self, id: SwitchId) -> Result<bool, EntityStorageError> {
        let Some(switch) = self.entries.try_get(&id)? else {
            return Ok(false);
        };
        let branch = switch.branch();
        let function = switch.function();
        drop(switch);

        self.index.branches.remove(&branch);
        self.index.unlink(function, branch);
        self.entries.try_remove(&id)?;
        Ok(true)
    }

    pub(crate) fn insert<F>(&mut self, branch: Address, f: F) -> Result<SwitchId, SwitchTableError>
    where
        F: FnOnce(SwitchId, Address) -> Switch,
    {
        if let Some(&existing) = self.index.branches.get(&branch) {
            let switch = f(existing, branch);
            if switch.branch() != branch {
                return Err(SwitchTableError::AddressMismatch);
            }
            if let Some(previous) = self.entries.try_get(&existing)? {
                let previous_function = previous.function();
                drop(previous);
                self.index.unlink(previous_function, branch);
            }
            self.index.link(switch.function(), branch);
            self.entries.put(existing, switch);
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

        self.entries.put(id, switch);

        Ok(id)
    }

    pub(crate) fn get_by_id(&self, id: SwitchId) -> Option<Ref<'_>> {
        self.try_get_by_id(id).unwrap_or_else(|e| e.into_fatal())
    }

    pub(crate) fn try_get_by_id(
        &self,
        id: SwitchId,
    ) -> Result<Option<Ref<'_>>, EntityStorageError> {
        self.entries.try_get(&id)
    }

    pub(crate) fn get_by_branch(&self, branch: Address) -> Option<Ref<'_>> {
        let id = *self.index.branches.get(&branch)?;
        self.get_by_id(id)
    }

    pub(crate) fn contains(&self, branch: Address) -> bool {
        self.index.branches.contains_key(&branch)
    }

    pub(crate) fn get_by_id_mut(&mut self, id: SwitchId) -> Option<RefMut<'_>> {
        self.entries.get_mut(&id)
    }

    pub(crate) fn modify_by_id<R>(
        &mut self,
        id: SwitchId,
        f: impl FnOnce(&mut Switch) -> R,
    ) -> Option<R> {
        self.try_modify_by_id(id, f)
            .unwrap_or_else(|e| e.into_fatal())
    }

    pub(crate) fn try_modify_by_id<R>(
        &mut self,
        id: SwitchId,
        f: impl FnOnce(&mut Switch) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        self.entries.try_modify(&id, f)
    }

    pub(crate) fn modify_by_branch<R>(
        &mut self,
        branch: Address,
        f: impl FnOnce(&mut Switch) -> R,
    ) -> Option<R> {
        let id = *self.index.branches.get(&branch)?;
        self.modify_by_id(id, f)
    }

    pub(crate) fn remove_by_id(&mut self, id: SwitchId) -> bool {
        self.try_remove_by_id(id).unwrap_or_else(|e| e.into_fatal())
    }

    pub(crate) fn try_remove_by_id(&mut self, id: SwitchId) -> Result<bool, EntityStorageError> {
        let (branch, function) = match self.entries.try_get(&id)? {
            Some(switch) => (switch.branch(), switch.function()),
            None => return Ok(false),
        };

        self.index.branches.remove(&branch);
        self.index.unlink(function, branch);
        self.index.free_ids.push(id.next_generation());
        self.entries.try_remove(&id)?;

        Ok(true)
    }

    pub(crate) fn remove_by_branch(&mut self, branch: Address) -> bool {
        let Some(id) = self.index.branches.remove(&branch) else {
            return false;
        };
        if let Some(function) = self
            .entries
            .try_get(&id)
            .unwrap_or_else(|e| e.into_fatal())
            .map(|switch| switch.function())
        {
            self.index.unlink(function, branch);
        }
        self.index.free_ids.push(id.next_generation());
        self.entries
            .try_remove(&id)
            .unwrap_or_else(|e| e.into_fatal());
        true
    }

    pub(crate) fn branches(&self) -> impl Iterator<Item = Address> + '_ {
        self.index.branches.keys().copied()
    }

    pub(crate) fn branches_after(
        &self,
        after: Option<Address>,
    ) -> impl Iterator<Item = Address> + '_ {
        let start = after.map_or(Bound::Unbounded, Bound::Excluded);
        self.index
            .branches
            .range((start, Bound::Unbounded))
            .map(|(address, _)| *address)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = Ref<'_>> + '_ {
        self.entries
            .try_iter()
            .unwrap_or_else(|e| e.into_fatal())
            .map(|entry| entry.unwrap_or_else(|e| e.into_fatal()).1)
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = RefMut<'_>> + '_ {
        self.entries.iter_mut()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.index.branches.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.index.branches.len()
    }
}
