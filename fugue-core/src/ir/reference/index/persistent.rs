use std::ops::Bound;
use std::sync::Arc;

use crate::ir::reference::{
    Reference, ReferenceKey, ReferenceOrigin, ReferenceRecord, ReferenceTarget,
};
use crate::ir::{Address, IndexMetadata};
use crate::storage::EntityStorage;
use crate::storage::entities::{EntityCache, EntityStorageError, ProjectEntity, WriteBackWorker};
use crate::types::Revision;
use crate::types::common::{cursor_bound, cursor_bound_or_minimum};

use super::{InverseReferenceKey, PreparedReferenceIndexRecord};

pub struct ReferenceIndex {
    forward: EntityCache<ReferenceKey, ReferenceRecord>,
    inverse: EntityCache<InverseReferenceKey, ReferenceRecord>,
    storage: EntityStorage,
}

impl ReferenceIndex {
    const CACHE_BYTES: usize = 16 * 1024 * 1024;

    pub(crate) fn new(
        storage: EntityStorage,
        worker: Option<Arc<WriteBackWorker>>,
    ) -> Result<Self, EntityStorageError> {
        let forward =
            EntityCache::from_storage(storage.clone(), worker.clone(), Self::CACHE_BYTES)?;
        let inverse = EntityCache::from_storage(storage.clone(), worker, Self::CACHE_BYTES)?;

        Ok(Self {
            forward,
            inverse,
            storage,
        })
    }

    pub(crate) fn mark_current(&self, revision: Revision) -> Result<(), EntityStorageError> {
        self.storage.insert(
            &ProjectEntity::ReferenceIndex,
            &IndexMetadata::new(revision),
        )
    }

    pub(crate) fn metadata_revision(&self) -> Result<Option<Revision>, EntityStorageError> {
        let metadata = self
            .storage
            .get::<ProjectEntity, IndexMetadata>(&ProjectEntity::ReferenceIndex)?;
        Ok(metadata.map(|metadata| metadata.revision()))
    }

    pub(crate) fn flush(&self) -> Result<(), EntityStorageError> {
        self.forward.flush()?;
        self.inverse.flush()
    }

    pub(crate) fn insert(&self, reference: &Reference) -> Result<(), EntityStorageError> {
        let forward_key = ReferenceKey::new(reference.from(), reference.target());
        let inverse_key = InverseReferenceKey::new(reference.target(), reference.from());
        let record = ReferenceRecord::of(reference);
        self.forward.try_insert(forward_key, record)?;
        self.inverse.try_insert(inverse_key, record)?;
        Ok(())
    }

    pub(crate) fn remove(
        &self,
        from: Address,
        target: ReferenceTarget,
    ) -> Result<(), EntityStorageError> {
        self.forward.try_remove(&ReferenceKey::new(from, target))?;
        self.inverse
            .try_remove(&InverseReferenceKey::new(target, from))
    }

    pub(crate) fn get(
        &self,
        from: Address,
        target: ReferenceTarget,
    ) -> Result<Option<Reference>, EntityStorageError> {
        let Some(cached) = self.forward.try_get(&ReferenceKey::new(from, target))? else {
            return Ok(None);
        };
        Ok(Some(cached.as_ref().materialise(from, target)))
    }

    pub(crate) fn publish_records(
        &self,
        records: impl IntoIterator<Item = PreparedReferenceIndexRecord>,
    ) {
        for record in records {
            let PreparedReferenceIndexRecord {
                encoded_size,
                key,
                reference,
            } = record;
            let inverse = InverseReferenceKey::new(key.target(), key.from());
            match reference {
                Some(reference) => {
                    let record = ReferenceRecord::of(&reference);
                    self.forward.publish_insert(key, record, encoded_size);
                    self.inverse.publish_insert(inverse, record, encoded_size);
                }
                None => {
                    self.forward.publish_remove(&key);
                    self.inverse.publish_remove(&inverse);
                }
            }
        }
    }

    pub(crate) fn references_from(
        &self,
        from: Address,
        after: Option<&Reference>,
    ) -> Result<impl Iterator<Item = Result<Reference, EntityStorageError>> + '_, EntityStorageError>
    {
        let after = after.map(|after| ReferenceKey::new(after.from(), after.target()));
        let start = cursor_bound_or_minimum(after, ReferenceKey::minimum_for(from));
        Ok(self
            .forward
            .try_iter_range(start.as_ref())?
            .take_while(move |result| result.as_ref().map_or(true, |(key, _)| key.from() == from))
            .map(move |result| {
                result.map(|(key, cached)| cached.as_ref().materialise(key.from(), key.target()))
            }))
    }

    pub(crate) fn references_to(
        &self,
        target: ReferenceTarget,
        after: Option<&Reference>,
    ) -> Result<impl Iterator<Item = Result<Reference, EntityStorageError>> + '_, EntityStorageError>
    {
        let after = after.map(|after| InverseReferenceKey::new(after.target(), after.from()));
        let start = cursor_bound_or_minimum(after, InverseReferenceKey::minimum_for(target));
        Ok(self
            .inverse
            .try_iter_range(start.as_ref())?
            .take_while(move |result| {
                result
                    .as_ref()
                    .map_or(true, |(key, _)| key.target() == target)
            })
            .map(move |result| {
                result.map(|(key, cached)| cached.as_ref().materialise(key.from(), key.target()))
            }))
    }

    pub(crate) fn origins_after(
        &self,
        after: Option<&ReferenceKey>,
    ) -> Result<Vec<(ReferenceKey, ReferenceOrigin)>, EntityStorageError> {
        let start = cursor_bound(after);
        Ok(self
            .forward
            .try_iter_batch(start)?
            .into_iter()
            .map(|(key, cached)| (key, cached.origin()))
            .collect())
    }

    pub(crate) fn collect_range(
        &self,
        start: &ReferenceKey,
        end: Address,
        references: &mut Vec<Reference>,
    ) -> Result<(), EntityStorageError> {
        for result in self.forward.try_iter_range(Bound::Included(start))? {
            let (key, cached) = result?;
            if key.from() > end {
                break;
            }
            references.push(cached.as_ref().materialise(key.from(), key.target()));
        }
        Ok(())
    }
}
