use std::ops::Bound;

use thiserror::Error;

use super::{
    EntityBytesAsIterator, EntityBytesBulkInserter, EntityBytesIterator,
    EntityBytesTransactionalReader, EntityBytesTransactionalWriter, EntityKeyBytesIterator,
    EntityStorageError, EntityStorageProvider, EntityStorageProviderFromLoadable,
};
use crate::loader::Loadable;
use crate::storage::{StoragePersistence, TRANSIENT};
use crate::types::{AttributeMap, BytesOrSlice};

#[derive(Debug, Error)]
#[error("{0} operation not supported")]
pub struct DummyEntityStorageError(&'static str);

impl From<DummyEntityStorageError> for EntityStorageError {
    fn from(err: DummyEntityStorageError) -> Self {
        EntityStorageError::unsupported(err)
    }
}

#[derive(Debug, Clone, Default)]
pub struct DummyEntityStorage;

impl DummyEntityStorage {
    pub fn new() -> Self {
        Self
    }
}

impl EntityStorageProviderFromLoadable for DummyEntityStorage {
    fn from_loadable(
        _loadable: &impl Loadable,
        _attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError> {
        Ok(DummyEntityStorage::new())
    }
}

impl EntityStorageProvider for DummyEntityStorage {
    fn get(&self, _key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        Err(DummyEntityStorageError("get").into())
    }

    fn get_as<F, T>(&self, _key: &[u8], _f: F) -> Result<Option<T>, EntityStorageError>
    where
        F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
    {
        Err(DummyEntityStorageError("get_as").into())
    }

    fn insert(&self, _key: &[u8], _value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        Err(DummyEntityStorageError("insert").into())
    }

    fn remove(&self, _key: &[u8]) -> Result<(), EntityStorageError> {
        Err(DummyEntityStorageError("remove").into())
    }

    fn contains(&self, _key: &[u8]) -> Result<bool, EntityStorageError> {
        Err(DummyEntityStorageError("contains").into())
    }

    fn iter_prefix_keys(
        &self,
        _prefix: &[u8],
    ) -> Result<EntityKeyBytesIterator<'_>, EntityStorageError> {
        Err(DummyEntityStorageError("iter_prefix_keys").into())
    }

    fn iter_prefix(&self, _prefix: &[u8]) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        Err(DummyEntityStorageError("iter_prefix").into())
    }

    fn iter_range(
        &self,
        _prefix: &[u8],
        _start: Bound<&[u8]>,
    ) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        Err(DummyEntityStorageError("iter_range").into())
    }

    fn iter_prefix_as<'a, F, T>(
        &'a self,
        _prefix: &[u8],
        _f: F,
    ) -> Result<EntityBytesAsIterator<'a, T>, EntityStorageError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<T, EntityStorageError> + 'a,
        T: 'a,
    {
        Err(DummyEntityStorageError("iter_prefix_as").into())
    }

    fn bulk_inserter(&self) -> Result<EntityBytesBulkInserter, EntityStorageError> {
        Err(DummyEntityStorageError("bulk_inserter").into())
    }

    fn transactional_reader(
        &self,
    ) -> Result<EntityBytesTransactionalReader<'_>, EntityStorageError> {
        Err(DummyEntityStorageError("transactional_reader").into())
    }

    fn transactional_writer(
        &self,
    ) -> Result<EntityBytesTransactionalWriter<'_>, EntityStorageError> {
        Err(DummyEntityStorageError("transactional_writer").into())
    }

    fn persistence(&self) -> StoragePersistence {
        TRANSIENT
    }
}
