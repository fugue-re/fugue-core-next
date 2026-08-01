use std::ops::Bound;
use std::sync::Arc;

use super::{ProblemIndex, ProblemTableError};
use crate::ir::problem::{Problem, ProblemId, ProblemKey, ProblemKind, ProblemScope};
use crate::ir::{Address, AddressRange};
use crate::storage::entities::{CachedRef, EntityCache, WriteBackWorker};
use crate::storage::{EntityStorage, EntityStorageError};

type Ref<'a> = CachedRef<'a, Problem>;

pub struct ProblemTable {
    index: ProblemIndex,
    entries: EntityCache<ProblemId, Problem>,
}

impl ProblemTable {
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

    fn from_entries(entries: EntityCache<ProblemId, Problem>) -> Result<Self, EntityStorageError> {
        let mut index = ProblemIndex::new();

        for entry in entries.try_iter_range(Bound::Unbounded)? {
            let (id, problem) = entry?;
            index.insert(id, problem.key());
            index.allocator.mark_allocated(id);
        }

        Ok(Self { index, entries })
    }

    pub(crate) fn flush(&self) -> Result<(), EntityStorageError> {
        self.entries.flush()
    }

    pub(super) fn preview_id(&self, offset: usize) -> ProblemId {
        self.index.allocator.preview_id(offset)
    }

    pub(super) fn publish_upsert(&mut self, problem: Problem, encoded_len: usize, is_new: bool) {
        let id = problem.id();
        let key = problem.key();
        self.entries.publish_put(id, problem, encoded_len);
        self.index.insert(id, key);
        if is_new {
            let allocated = self.index.allocator.allocate();
            debug_assert_eq!(allocated, id);
        }
    }

    pub(super) fn publish_remove(&mut self, key: ProblemKey) {
        let Some(id) = self.index.id(key) else {
            return;
        };

        self.entries.publish_remove(&id);
        self.index.remove(key);
        self.index.allocator.release(id);
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
            self.entries.try_put(existing, problem)?;
            self.index.insert(existing, key);
            return Ok(existing);
        }

        let entries = &self.entries;
        let (id, ()) = self.index.allocator.try_allocate(|id| {
            let problem = f(id, scope)?;
            if problem.key() != key {
                return Err(ProblemTableError::KeyMismatch);
            }
            entries.try_put(id, problem)?;
            Ok(())
        })?;

        self.index.insert(id, key);

        Ok(id)
    }

    pub(crate) fn try_get_by_id(
        &self,
        id: ProblemId,
    ) -> Result<Option<Ref<'_>>, EntityStorageError> {
        self.entries.try_get(&id)
    }

    pub(crate) fn try_get_key(
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

    pub(crate) fn try_modify_by_id<R>(
        &mut self,
        id: ProblemId,
        f: impl FnOnce(&mut Problem) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        let Some(previous) = self.entries.try_get(&id)? else {
            return Ok(None);
        };
        let mut problem = previous.as_ref().clone();
        drop(previous);
        let result = f(&mut problem);

        self.entries.try_put(id, problem)?;

        Ok(Some(result))
    }

    pub(crate) fn try_remove_by_id(&mut self, id: ProblemId) -> Result<bool, EntityStorageError> {
        let key = match self.entries.try_get(&id)? {
            Some(problem) => problem.key(),
            None => return Ok(false),
        };

        self.entries.try_remove(&id)?;
        self.index.remove(key);
        self.index.allocator.release(id);

        Ok(true)
    }

    pub(crate) fn try_remove_key(&mut self, key: ProblemKey) -> Result<bool, EntityStorageError> {
        let Some(id) = self.index.id(key) else {
            return Ok(false);
        };
        self.try_remove_by_id(id)
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = ProblemKey> + '_ {
        self.index.keys()
    }

    pub(super) fn for_each_address_key_in(&self, range: AddressRange, f: impl FnMut(ProblemKey)) {
        self.index.for_each_address_key_in(range, f);
    }

    pub(crate) fn entries_after(
        &self,
        after: Option<ProblemKey>,
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
