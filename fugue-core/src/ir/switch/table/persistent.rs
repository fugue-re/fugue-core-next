use std::ops::Bound;
use std::sync::Arc;

use super::{SwitchIndex, SwitchTableError};
use crate::ir::persistent::{PersistentIdAllocator, PersistentIndexRebuilder, PersistentTable};
use crate::ir::switch::{Switch, SwitchId};
use crate::ir::{Address, FunctionId};
use crate::storage::entities::{
    CachedRef, Entity, EntityCache, EntityWrite, EntityWriteBatch, WriteBackWorker,
};
use crate::storage::{EntityStorage, EntityStorageError};

type Ref<'a> = CachedRef<'a, Switch>;

pub struct SwitchTable {
    allocator: PersistentIdAllocator<Switch>,
    index: SwitchIndex,
    entries: EntityCache<SwitchId, Switch>,
    storage: EntityStorage,
}

impl SwitchTable {
    pub(crate) fn new(
        storage: EntityStorage,
        cache_bytes: usize,
        worker: Arc<WriteBackWorker>,
    ) -> Result<Self, EntityStorageError> {
        let entries = EntityCache::new(storage.clone(), cache_bytes, worker);
        Self::new_with(storage, entries)
    }

    fn new_with(
        storage: EntityStorage,
        entries: EntityCache<SwitchId, Switch>,
    ) -> Result<Self, EntityStorageError> {
        let allocator = PersistentIdAllocator::load(storage.clone(), PersistentTable::Switches)?;
        let mut rebuilder = allocator
            .is_none()
            .then(|| PersistentIndexRebuilder::new(&storage, PersistentTable::Switches));
        let mut index = SwitchIndex::new();

        for entry in entries.try_iter_range(Bound::Unbounded)? {
            let (id, switch) = entry?;
            index.insert(id, switch.function(), switch.branch());
            if let Some(rebuilder) = &mut rebuilder {
                rebuilder.append(id, |_| Ok(()))?;
            }
        }

        let allocator = match allocator {
            Some(allocator) => allocator,
            None => rebuilder
                .expect("missing switch allocator requires index rebuild")
                .finish(|_| Ok(()))?,
        };
        Ok(Self {
            allocator,
            index,
            entries,
            storage,
        })
    }

    pub(crate) fn branches_for_function(
        &self,
        function: FunctionId,
    ) -> impl Iterator<Item = Address> + '_ {
        self.index.branches_for_function(function)
    }

    pub(crate) fn flush(&self) -> Result<(), EntityStorageError> {
        self.entries.flush()
    }

    pub(crate) fn pending_id(&self, offset: usize) -> SwitchId {
        self.allocator
            .pending_id(offset)
            .unwrap_or_else(|error| error.into_fatal())
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

    pub(crate) fn branches(&self) -> impl Iterator<Item = Address> + '_ {
        self.index.branches()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = Ref<'_>> + '_ {
        self.entries
            .try_iter()
            .unwrap_or_else(|e| e.into_fatal())
            .map(|entry| entry.unwrap_or_else(|e| e.into_fatal()).1)
    }

    pub(crate) fn entries_after(
        &self,
        after: Option<Address>,
    ) -> impl Iterator<Item = Ref<'_>> + '_ {
        self.index
            .entries_after(after)
            .filter_map(|(_, id)| self.entries.get(&id))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.index.len()
    }

    pub(crate) fn append_allocation_writes(
        &self,
        reservations: &[SwitchId],
        releases: &[SwitchId],
        added: usize,
        removed: usize,
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        self.allocator
            .append_transition(reservations, releases, added, removed, writes)
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
            self.entries.try_insert(existing, switch)?;
            if let Some(previous_function) = previous_function {
                self.index.remove(previous_function, branch);
            }
            self.index.insert(existing, function, branch);
            return Ok(existing);
        }

        let id = self.pending_id(0);
        let switch = f(id, branch)?;
        if switch.branch() != branch {
            return Err(SwitchTableError::AddressMismatch);
        }
        let function = switch.function();
        let encoded =
            rkyv::to_bytes::<rkyv::rancor::Error>(&switch).map_err(EntityStorageError::encode)?;
        let encoded_size = encoded.len();
        let reservations = [id];
        let releases = [];
        let mut writes = EntityWriteBatch::new();
        writes.push(EntityWrite::insert_archived(
            Switch::ID.key_for(&id),
            encoded,
        ));
        self.allocator.append_transition(
            &reservations,
            &releases,
            reservations.len(),
            releases.len(),
            &mut writes,
        )?;
        self.entries.flush()?;
        self.storage.write_batch(&writes)?;
        self.entries.publish_insert(id, switch, encoded_size);
        self.allocator
            .publish_transition(&reservations, reservations.len(), releases.len());
        self.index.insert(id, function, branch);

        Ok(id)
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

        self.entries.try_insert(id, switch)?;
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

        let mut writes = EntityWriteBatch::new();
        writes.push(EntityWrite::remove(Switch::ID.key_for(&id)));
        self.allocator
            .append_transition(&[], &[id], 0, 1, &mut writes)?;
        self.entries.flush()?;
        self.storage.write_batch(&writes)?;
        self.entries.publish_remove(&id);
        self.allocator.publish_transition(&[], 0, 1);
        self.index.remove(function, branch);

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

    pub(crate) fn publish_allocations(
        &mut self,
        reservations: &[SwitchId],
        added: usize,
        removed: usize,
    ) {
        self.allocator
            .publish_transition(reservations, added, removed);
    }

    pub(crate) fn publish_upsert(
        &mut self,
        switch: Switch,
        previous_function: Option<FunctionId>,
        encoded_size: usize,
    ) {
        let id = switch.id();
        let branch = switch.branch();
        let function = switch.function();
        self.entries.publish_insert(id, switch, encoded_size);
        if let Some(previous_function) = previous_function {
            self.index.remove(previous_function, branch);
        }
        self.index.insert(id, function, branch);
    }

    pub(crate) fn publish_remove(&mut self, id: SwitchId, function: FunctionId, branch: Address) {
        self.entries.publish_remove(&id);
        self.index.remove(function, branch);
    }
}
