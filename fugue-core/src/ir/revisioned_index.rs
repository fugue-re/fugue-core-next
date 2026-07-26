use std::sync::Arc;

use crate::ir::IndexHeader;
use crate::storage::EntityStorage;
use crate::storage::entities::{
    Entity, EntityCache, EntityKey, EntityStorageError, ProjectEntity, WriteBackWorker,
};

#[derive(Clone)]
pub(crate) struct RevisionedTwoWayIndex<F, I, E>
where
    F: EntityKey,
    I: EntityKey,
    E: Entity,
{
    forward: EntityCache<F, E>,
    inverse: EntityCache<I, E>,
    marker: ProjectEntity,
    storage: EntityStorage,
}

impl<F, I, E> RevisionedTwoWayIndex<F, I, E>
where
    F: EntityKey,
    I: EntityKey,
    E: Entity,
{
    pub(crate) fn new(
        storage: EntityStorage,
        worker: Option<Arc<WriteBackWorker>>,
        cache_bytes: usize,
        marker: ProjectEntity,
    ) -> Result<Self, EntityStorageError> {
        let forward = EntityCache::from_storage(storage.clone(), worker.clone(), cache_bytes)?;
        let inverse = EntityCache::from_storage(storage.clone(), worker, cache_bytes)?;
        Ok(Self {
            forward,
            inverse,
            marker,
            storage,
        })
    }

    pub(crate) fn ensure_current(
        &self,
        revision: u64,
        rebuild: impl FnOnce() -> Result<(), EntityStorageError>,
    ) -> Result<(), EntityStorageError> {
        let header = self
            .storage
            .get::<ProjectEntity, IndexHeader>(&self.marker)?;
        if header.is_some_and(|header| header.revision() == revision) {
            return Ok(());
        }

        rebuild()?;
        self.forward.flush()?;
        self.inverse.flush()?;
        self.mark_current(revision)
    }

    pub(crate) fn mark_current(&self, revision: u64) -> Result<(), EntityStorageError> {
        self.storage
            .insert(&self.marker, &IndexHeader::new(revision))
    }

    pub(crate) fn forward(&self) -> &EntityCache<F, E> {
        &self.forward
    }

    pub(crate) fn inverse(&self) -> &EntityCache<I, E> {
        &self.inverse
    }
}
