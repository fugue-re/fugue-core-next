use std::ops::Bound;
use std::sync::Arc;

use super::{ProblemIndex, ProblemTableError};
use crate::ir::persistent::{PersistentIdAllocator, PersistentIndexRebuilder, PersistentTable};
use crate::ir::problem::{Problem, ProblemId, ProblemKey, ProblemKind, ProblemScope};
use crate::ir::{Address, AddressRange};
use crate::storage::entities::{
    CachedRef, Entity, EntityCache, EntityWrite, EntityWriteBatch, WriteBackWorker,
};
use crate::storage::{EntityStorage, EntityStorageError};

type Ref<'a> = CachedRef<'a, Problem>;

pub struct ProblemTable {
    allocator: PersistentIdAllocator<Problem>,
    index: ProblemIndex,
    entries: EntityCache<ProblemId, Problem>,
    storage: EntityStorage,
}

impl ProblemTable {
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
        entries: EntityCache<ProblemId, Problem>,
    ) -> Result<Self, EntityStorageError> {
        let allocator = PersistentIdAllocator::load(storage.clone(), PersistentTable::Problems)?;
        let mut rebuilder = allocator
            .is_none()
            .then(|| PersistentIndexRebuilder::new(&storage, PersistentTable::Problems));
        let mut index = ProblemIndex::new();

        for entry in entries.try_iter_range(Bound::Unbounded)? {
            let (id, problem) = entry?;
            index.insert(id, problem.key());
            if let Some(rebuilder) = &mut rebuilder {
                rebuilder.append(id, |_| Ok(()))?;
            }
        }

        let allocator = match allocator {
            Some(allocator) => allocator,
            None => rebuilder
                .expect("missing problem allocator requires index rebuild")
                .finish(|_| Ok(()))?,
        };
        Ok(Self {
            allocator,
            index,
            entries,
            storage,
        })
    }

    pub(crate) fn flush(&self) -> Result<(), EntityStorageError> {
        self.entries.flush()
    }

    pub(crate) fn pending_id(&self, offset: usize) -> ProblemId {
        self.allocator
            .pending_id(offset)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub(crate) fn try_get_by_id(
        &self,
        id: ProblemId,
    ) -> Result<Option<Ref<'_>>, EntityStorageError> {
        self.entries.try_get(&id)
    }

    pub(crate) fn try_get_by_key(
        &self,
        key: ProblemKey,
    ) -> Result<Option<Ref<'_>>, EntityStorageError> {
        let Some(id) = self.index.id(key) else {
            return Ok(None);
        };
        self.try_get_by_id(id)
    }

    pub(crate) fn contains(&self, address: Address) -> bool {
        self.index.contains(address)
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = ProblemKey> + '_ {
        self.index.keys()
    }

    pub(crate) fn for_each_key_in_range(&self, range: AddressRange, f: impl FnMut(ProblemKey)) {
        self.index.for_each_key_in_range(range, f);
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = Ref<'_>> + '_ {
        self.entries
            .try_iter()
            .unwrap_or_else(|e| e.into_fatal())
            .map(|entry| entry.unwrap_or_else(|e| e.into_fatal()).1)
    }

    pub(crate) fn entries_after(
        &self,
        after: Option<ProblemKey>,
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
        reservations: &[ProblemId],
        releases: &[ProblemId],
        added: usize,
        removed: usize,
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        self.allocator
            .append_transition(reservations, releases, added, removed, writes)
    }

    pub(crate) fn insert<F>(
        &mut self,
        scope: ProblemScope,
        kind: ProblemKind,
        f: F,
    ) -> Result<ProblemId, ProblemTableError>
    where
        F: FnOnce(ProblemId, ProblemScope) -> Result<Problem, ProblemTableError>,
    {
        let key = ProblemKey::scoped(scope, kind);
        if let Some(existing) = self.index.id(key) {
            let problem = f(existing, scope)?;
            if problem.key() != key {
                return Err(ProblemTableError::KeyMismatch);
            }
            self.entries.try_insert(existing, problem)?;
            self.index.insert(existing, key);
            return Ok(existing);
        }

        let id = self.pending_id(0);
        let problem = f(id, scope)?;
        if problem.key() != key {
            return Err(ProblemTableError::KeyMismatch);
        }
        let encoded =
            rkyv::to_bytes::<rkyv::rancor::Error>(&problem).map_err(EntityStorageError::encode)?;
        let encoded_size = encoded.len();
        let reservations = [id];
        let releases = [];
        let mut writes = EntityWriteBatch::new();
        writes.push(EntityWrite::insert_archived(
            Problem::ID.key_for(&id),
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
        self.storage.apply_batch(&writes)?;
        self.entries.publish_insert(id, problem, encoded_size);
        self.allocator
            .publish_transition(&reservations, reservations.len(), releases.len());
        self.index.insert(id, key);

        Ok(id)
    }

    pub(crate) fn try_modify_by_id<R>(
        &self,
        id: ProblemId,
        f: impl FnOnce(&mut Problem) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        let Some(previous) = self.entries.try_get(&id)? else {
            return Ok(None);
        };
        let mut problem = previous.as_ref().clone();
        drop(previous);
        let result = f(&mut problem);

        self.entries.try_insert(id, problem)?;

        Ok(Some(result))
    }

    pub(crate) fn try_remove_by_id(&mut self, id: ProblemId) -> Result<bool, EntityStorageError> {
        let key = match self.entries.try_get(&id)? {
            Some(problem) => problem.key(),
            None => return Ok(false),
        };

        let mut writes = EntityWriteBatch::new();
        writes.push(EntityWrite::remove(Problem::ID.key_for(&id)));
        self.allocator
            .append_transition(&[], &[id], 0, 1, &mut writes)?;
        self.entries.flush()?;
        self.storage.apply_batch(&writes)?;
        self.entries.publish_remove(&id);
        self.allocator.publish_transition(&[], 0, 1);
        self.index.remove(key);

        Ok(true)
    }

    pub(crate) fn try_remove_by_key(
        &mut self,
        key: ProblemKey,
    ) -> Result<bool, EntityStorageError> {
        let Some(id) = self.index.id(key) else {
            return Ok(false);
        };
        self.try_remove_by_id(id)
    }

    pub(crate) fn publish_allocations(
        &mut self,
        reservations: &[ProblemId],
        added: usize,
        removed: usize,
    ) {
        self.allocator
            .publish_transition(reservations, added, removed);
    }

    pub(crate) fn publish_upsert(&mut self, problem: Problem, encoded_size: usize) {
        let id = problem.id();
        let key = problem.key();
        self.entries.publish_insert(id, problem, encoded_size);
        self.index.insert(id, key);
    }

    pub(crate) fn publish_remove(&mut self, key: ProblemKey) {
        let Some(id) = self.index.id(key) else {
            return;
        };

        self.entries.publish_remove(&id);
        self.index.remove(key);
    }
}
