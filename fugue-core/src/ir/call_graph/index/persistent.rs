use std::sync::Arc;

use bytes::Bytes;

use super::{
    CallGraphEdgeRecord, InverseCallGraphEdgeKey, PreparedCallGraphBatch,
    PreparedCallGraphEdgeRecord,
};
use crate::ir::call_graph::CallGraphEdgeKey;
use crate::ir::{Address, IndexMetadata};
use crate::storage::EntityStorage;
use crate::storage::entities::cursor::{cursor_bound, cursor_bound_or_minimum};
use crate::storage::entities::{
    Entity, EntityCache, EntityStorageError, EntityWrite, EntityWriteBatch, ProjectEntity,
    WriteBackWorker,
};
use crate::types::Revision;

pub struct CallGraphIndex {
    forward: EntityCache<CallGraphEdgeKey, CallGraphEdgeRecord>,
    inverse: EntityCache<InverseCallGraphEdgeKey, CallGraphEdgeRecord>,
    storage: EntityStorage,
}

impl CallGraphIndex {
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

    pub(crate) fn callees(
        &self,
        caller: Address,
        after: Option<Address>,
    ) -> Result<impl Iterator<Item = Result<Address, EntityStorageError>> + '_, EntityStorageError>
    {
        let after = after.map(|after| CallGraphEdgeKey::new(caller, after));
        let start = cursor_bound_or_minimum(after, CallGraphEdgeKey::new(caller, Address::MINIMUM));
        Ok(self
            .forward
            .try_iter_range(start.as_ref())?
            .take_while(move |result| {
                result
                    .as_ref()
                    .map_or(true, |(key, _)| key.source() == caller)
            })
            .map(|result| result.map(|(key, _)| key.target())))
    }

    pub(crate) fn callers(
        &self,
        callee: Address,
        after: Option<Address>,
    ) -> Result<impl Iterator<Item = Result<Address, EntityStorageError>> + '_, EntityStorageError>
    {
        let after = after.map(|after| InverseCallGraphEdgeKey::new(after, callee));
        let start = cursor_bound_or_minimum(
            after,
            InverseCallGraphEdgeKey::new(Address::MINIMUM, callee),
        );
        Ok(self
            .inverse
            .try_iter_range(start.as_ref())?
            .take_while(move |result| {
                result
                    .as_ref()
                    .map_or(true, |(key, _)| key.callee() == callee)
            })
            .map(|result| result.map(|(key, _)| key.caller())))
    }

    pub(crate) fn edges(
        &self,
        after: Option<CallGraphEdgeKey>,
    ) -> Result<
        impl Iterator<Item = Result<CallGraphEdgeKey, EntityStorageError>> + '_,
        EntityStorageError,
    > {
        let start = cursor_bound(after);
        Ok(self
            .forward
            .try_iter_range(start.as_ref())?
            .map(|result| result.map(|(key, _)| key)))
    }

    pub(crate) fn mark_current(&self, revision: Revision) -> Result<(), EntityStorageError> {
        self.storage.insert(
            &ProjectEntity::CallGraphIndex,
            &IndexMetadata::new(revision),
        )
    }

    pub(crate) fn metadata_revision(&self) -> Result<Option<Revision>, EntityStorageError> {
        let metadata = self
            .storage
            .get::<ProjectEntity, IndexMetadata>(&ProjectEntity::CallGraphIndex)?;
        Ok(metadata.map(|metadata| metadata.revision()))
    }

    pub(crate) fn flush(&self) -> Result<(), EntityStorageError> {
        self.forward.flush()?;
        self.inverse.flush()
    }

    pub(crate) fn clear(&self) -> Result<(), EntityStorageError> {
        self.forward.try_clear()?;
        self.inverse.try_clear()
    }

    pub(crate) fn insert_edge(
        &self,
        caller: Address,
        callee: Address,
    ) -> Result<(), EntityStorageError> {
        self.forward
            .try_insert(CallGraphEdgeKey::new(caller, callee), CallGraphEdgeRecord)?;
        self.inverse.try_insert(
            InverseCallGraphEdgeKey::new(caller, callee),
            CallGraphEdgeRecord,
        )?;
        Ok(())
    }

    pub(crate) fn remove_edge(
        &self,
        caller: Address,
        callee: Address,
    ) -> Result<(), EntityStorageError> {
        self.forward
            .try_remove(&CallGraphEdgeKey::new(caller, callee))?;
        self.inverse
            .try_remove(&InverseCallGraphEdgeKey::new(caller, callee))
    }

    pub(crate) fn publish_batch(&self, batch: PreparedCallGraphBatch) {
        for edge in batch.edges {
            let inverse_key = InverseCallGraphEdgeKey::new(edge.key.source(), edge.key.target());
            if edge.present {
                self.forward
                    .publish_insert(edge.key, CallGraphEdgeRecord, edge.encoded_size);
                self.inverse
                    .publish_insert(inverse_key, CallGraphEdgeRecord, edge.encoded_size);
            } else {
                self.forward.publish_remove(&edge.key);
                self.inverse.publish_remove(&inverse_key);
            }
        }
    }
}

pub(crate) fn append_prepared_writes(
    edges: &mut [PreparedCallGraphEdgeRecord],
    writes: &mut EntityWriteBatch,
) -> Result<(), EntityStorageError> {
    let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(&CallGraphEdgeRecord)
        .map(Bytes::from_owner)
        .map_err(EntityStorageError::encode)?;
    for edge in edges {
        let inverse = InverseCallGraphEdgeKey::new(edge.key.source(), edge.key.target());
        if edge.present {
            edge.encoded_size = encoded.len();
            writes.push(EntityWrite::insert(
                CallGraphEdgeRecord::ID.key_for(&edge.key),
                encoded.clone(),
            ));
            writes.push(EntityWrite::insert(
                CallGraphEdgeRecord::ID.key_for(&inverse),
                encoded.clone(),
            ));
        } else {
            writes.push(EntityWrite::remove(
                CallGraphEdgeRecord::ID.key_for(&edge.key),
            ));
            writes.push(EntityWrite::remove(
                CallGraphEdgeRecord::ID.key_for(&inverse),
            ));
        }
    }
    Ok(())
}
