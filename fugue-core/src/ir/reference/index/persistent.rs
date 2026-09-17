use std::ops::Bound;
use std::sync::Arc;

use bytes::Bytes;
use rustc_hash::FxHashSet;

use super::{InverseReferenceKey, PreparedReferenceIndexRecord, ReferenceEntry};
use crate::ir::persistent::{cursor_bound, cursor_bound_or_minimum};
use crate::ir::reference::{Reference, ReferenceKey, ReferenceKind, ReferenceTarget};
use crate::ir::{Address, IndexMetadata};
use crate::storage::EntityStorage;
use crate::storage::entities::{
    Entity, EntityCache, EntityStorageError, EntityWrite, EntityWriteBatch, ProjectEntity,
    WriteBackWorker,
};
use crate::types::Revision;

pub struct ReferenceIndex {
    forward: EntityCache<ReferenceKey, ReferenceEntry>,
    inverse: EntityCache<InverseReferenceKey, ReferenceEntry>,
    storage: EntityStorage,
}

impl ReferenceIndex {
    pub(crate) fn new(
        storage: EntityStorage,
        cache_bytes: usize,
        worker: Arc<WriteBackWorker>,
    ) -> Self {
        let forward = EntityCache::new(storage.clone(), cache_bytes, worker.clone());
        let inverse = EntityCache::new(storage.clone(), cache_bytes, worker);

        Self {
            forward,
            inverse,
            storage,
        }
    }

    pub(crate) fn try_get(
        &self,
        key: ReferenceKey,
    ) -> Result<Option<ReferenceEntry>, EntityStorageError> {
        Ok(self
            .forward
            .try_get(&key)?
            .map(|record| record.as_ref().clone()))
    }

    pub(crate) fn references_from(
        &self,
        from: Address,
        after: Option<ReferenceKey>,
    ) -> Result<impl Iterator<Item = Result<Reference, EntityStorageError>> + '_, EntityStorageError>
    {
        let start = cursor_bound_or_minimum(
            after,
            ReferenceKey::new(from, ReferenceTarget::minimum(), ReferenceKind::Flow),
        );
        Ok(self
            .forward
            .try_iter_range(start.as_ref())?
            .take_while(move |result| result.as_ref().map_or(true, |(key, _)| key.from() == from))
            .map(move |result| {
                result.map(|(key, cached)| {
                    cached
                        .as_ref()
                        .materialise(key)
                        .expect("stored reference entry must contain a visible reference")
                })
            }))
    }

    pub(crate) fn references_to(
        &self,
        target: ReferenceTarget,
        after: Option<ReferenceKey>,
    ) -> Result<impl Iterator<Item = Result<Reference, EntityStorageError>> + '_, EntityStorageError>
    {
        let after =
            after.map(|after| InverseReferenceKey::new(after.target(), after.from(), after.kind()));
        let start = cursor_bound_or_minimum(
            after,
            InverseReferenceKey::new(target, Address::MINIMUM, ReferenceKind::Flow),
        );
        Ok(self
            .inverse
            .try_iter_range(start.as_ref())?
            .take_while(move |result| {
                result
                    .as_ref()
                    .map_or(true, |(key, _)| key.target() == target)
            })
            .map(move |result| {
                result.map(|(key, cached)| {
                    cached
                        .as_ref()
                        .materialise(ReferenceKey::new(key.from(), key.target(), key.kind()))
                        .expect("stored reference entry must contain a visible reference")
                })
            }))
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
            references.push(
                cached
                    .as_ref()
                    .materialise(key)
                    .expect("stored reference entry must contain a visible reference"),
            );
        }
        Ok(())
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

    pub(crate) fn clear_derived(&self) -> Result<FxHashSet<ReferenceKey>, EntityStorageError> {
        let mut asserted = FxHashSet::default();
        let mut cursor = None;
        loop {
            let start = cursor_bound(cursor.as_ref());
            let batch = self
                .forward
                .try_iter_batch(start)?
                .into_iter()
                .map(|(key, cached)| (key, cached.as_ref().clone()))
                .collect::<Vec<_>>();
            let Some((last, _)) = batch.last() else {
                break;
            };
            cursor = Some(*last);

            for (key, mut entry) in batch {
                entry.clear_derived();
                if entry.is_empty() {
                    self.remove(key)?;
                } else {
                    asserted.insert(key);
                    self.insert(key, &entry)?;
                }
            }
        }
        Ok(asserted)
    }

    pub(crate) fn insert(
        &self,
        key: ReferenceKey,
        entry: &ReferenceEntry,
    ) -> Result<(), EntityStorageError> {
        let inverse_key = InverseReferenceKey::new(key.target(), key.from(), key.kind());
        self.forward.try_insert(key, entry.clone())?;
        self.inverse.try_insert(inverse_key, entry.clone())?;
        Ok(())
    }

    pub(crate) fn remove(&self, key: ReferenceKey) -> Result<(), EntityStorageError> {
        self.forward.try_remove(&key)?;
        self.inverse.try_remove(&InverseReferenceKey::new(
            key.target(),
            key.from(),
            key.kind(),
        ))
    }

    pub(crate) fn publish_batch(
        &self,
        records: impl IntoIterator<Item = PreparedReferenceIndexRecord>,
    ) {
        for record in records {
            let PreparedReferenceIndexRecord {
                encoded_size,
                entry,
                key,
            } = record;
            let inverse = InverseReferenceKey::new(key.target(), key.from(), key.kind());
            match entry {
                Some(entry) => {
                    self.forward
                        .publish_insert(key, entry.clone(), encoded_size);
                    self.inverse.publish_insert(inverse, entry, encoded_size);
                }
                None => {
                    self.forward.publish_remove(&key);
                    self.inverse.publish_remove(&inverse);
                }
            }
        }
    }
}

pub(crate) fn append_prepared_writes(
    records: &mut [PreparedReferenceIndexRecord],
    writes: &mut EntityWriteBatch,
) -> Result<(), EntityStorageError> {
    for prepared in records {
        let forward = ReferenceEntry::ID.key_for(&prepared.key);
        let inverse_key = InverseReferenceKey::new(
            prepared.key.target(),
            prepared.key.from(),
            prepared.key.kind(),
        );
        let inverse = ReferenceEntry::ID.key_for(&inverse_key);
        let Some(entry) = &prepared.entry else {
            writes.push(EntityWrite::remove(forward));
            writes.push(EntityWrite::remove(inverse));
            continue;
        };

        let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(entry)
            .map(Bytes::from_owner)
            .map_err(EntityStorageError::encode)?;
        prepared.encoded_size = encoded.len();
        writes.push(EntityWrite::insert(forward, encoded.clone()));
        writes.push(EntityWrite::insert(inverse, encoded));
    }
    Ok(())
}
