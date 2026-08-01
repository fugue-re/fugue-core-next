use std::ops::Bound;
use std::sync::Arc;

use super::{SwitchIndex, SwitchTableError};
use crate::ir::switch::{Switch, SwitchId};
use crate::ir::{Address, FunctionId};
use crate::storage::entities::{CachedRef, EntityCache, WriteBackWorker};
use crate::storage::{EntityStorage, EntityStorageError};

type Ref<'a> = CachedRef<'a, Switch>;

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

    pub(crate) fn with_worker(
        entities: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Self::from_entries(EntityCache::with_worker(entities, worker, cache_bytes))
    }

    fn from_entries(entries: EntityCache<SwitchId, Switch>) -> Result<Self, EntityStorageError> {
        let mut index = SwitchIndex::new();

        for entry in entries.try_iter_range(Bound::Unbounded)? {
            let (id, switch) = entry?;
            index.insert(id, switch.function(), switch.branch());
            index.allocator.mark_allocated(id);
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

    pub(super) fn preview_id(&self, offset: usize) -> SwitchId {
        self.index.allocator.preview_id(offset)
    }

    pub(super) fn publish_reservation(&mut self, id: SwitchId) {
        let allocated = self.index.allocator.allocate();
        debug_assert_eq!(allocated, id);
    }

    pub(super) fn publish_release(&mut self, id: SwitchId) {
        self.index.allocator.release(id);
    }

    pub(super) fn publish_upsert(
        &mut self,
        switch: Switch,
        previous_function: Option<FunctionId>,
        encoded_len: usize,
    ) {
        let id = switch.id();
        let branch = switch.branch();
        let function = switch.function();
        self.entries.publish_put(id, switch, encoded_len);
        if let Some(previous_function) = previous_function {
            self.index.remove(previous_function, branch);
        }
        self.index.insert(id, function, branch);
    }

    pub(super) fn publish_remove(&mut self, id: SwitchId, function: FunctionId, branch: Address) {
        self.entries.publish_remove(&id);
        self.index.remove(function, branch);
        self.index.allocator.release(id);
    }

    pub(crate) fn insert<F>(&mut self, branch: Address, f: F) -> Result<SwitchId, SwitchTableError>
    where
        F: FnOnce(SwitchId, Address) -> Result<Switch, SwitchTableError>,
    {
        if let Some(existing) = self.index.id_by_branch(branch) {
            let switch = f(existing, branch)?;
            if switch.branch() != branch {
                return Err(SwitchTableError::AddressMismatch);
            }
            let previous_function = self
                .entries
                .try_get(&existing)?
                .map(|previous| previous.function());
            let function = switch.function();
            self.entries.try_put(existing, switch)?;
            if let Some(previous_function) = previous_function {
                self.index.remove(previous_function, branch);
            }
            self.index.insert(existing, function, branch);
            return Ok(existing);
        }

        let entries = &self.entries;
        let (id, function) = self.index.allocator.try_allocate(|id| {
            let switch = f(id, branch)?;
            if switch.branch() != branch {
                return Err(SwitchTableError::AddressMismatch);
            }
            let function = switch.function();
            entries.try_put(id, switch)?;
            Ok(function)
        })?;

        self.index.insert(id, function, branch);

        Ok(id)
    }

    pub(crate) fn try_get_by_id(
        &self,
        id: SwitchId,
    ) -> Result<Option<Ref<'_>>, EntityStorageError> {
        self.entries.try_get(&id)
    }

    pub(crate) fn try_get_by_branch(
        &self,
        branch: Address,
    ) -> Result<Option<Ref<'_>>, EntityStorageError> {
        let Some(id) = self.index.id_by_branch(branch) else {
            return Ok(None);
        };
        self.try_get_by_id(id)
    }

    pub(crate) fn contains(&self, branch: Address) -> bool {
        self.index.contains(branch)
    }

    pub(crate) fn try_modify_by_id<R>(
        &mut self,
        id: SwitchId,
        f: impl FnOnce(&mut Switch) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        let Some(previous) = self.entries.try_get(&id)? else {
            return Ok(None);
        };
        let previous_function = previous.function();
        let branch = previous.branch();
        let mut switch = previous.as_ref().clone();
        drop(previous);
        let result = f(&mut switch);
        let function = switch.function();

        self.entries.try_put(id, switch)?;
        self.index.remove(previous_function, branch);
        self.index.insert(id, function, branch);

        Ok(Some(result))
    }

    pub(crate) fn try_modify_by_branch<R>(
        &mut self,
        branch: Address,
        f: impl FnOnce(&mut Switch) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        let Some(id) = self.index.id_by_branch(branch) else {
            return Ok(None);
        };
        self.try_modify_by_id(id, f)
    }

    pub(crate) fn try_remove_by_id(&mut self, id: SwitchId) -> Result<bool, EntityStorageError> {
        let (branch, function) = match self.entries.try_get(&id)? {
            Some(switch) => (switch.branch(), switch.function()),
            None => return Ok(false),
        };

        self.entries.try_remove(&id)?;
        self.index.remove(function, branch);
        self.index.allocator.release(id);

        Ok(true)
    }

    pub(crate) fn try_remove_by_branch(
        &mut self,
        branch: Address,
    ) -> Result<bool, EntityStorageError> {
        let Some(id) = self.index.id_by_branch(branch) else {
            return Ok(false);
        };
        self.try_remove_by_id(id)
    }

    pub(crate) fn branches(&self) -> impl Iterator<Item = Address> + '_ {
        self.index.branches()
    }

    pub(crate) fn entries_after(
        &self,
        after: Option<Address>,
    ) -> impl Iterator<Item = Ref<'_>> + '_ {
        self.index
            .entries_after(after)
            .filter_map(|(_, id)| self.entries.get(&id))
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = Ref<'_>> + '_ {
        self.entries
            .try_iter()
            .unwrap_or_else(|e| e.into_fatal())
            .map(|entry| entry.unwrap_or_else(|e| e.into_fatal()).1)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.index.len()
    }
}
