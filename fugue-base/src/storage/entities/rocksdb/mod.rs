use std::path::PathBuf;

use rocksdb::DB;

use crate::loader::Loadable;
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;
use crate::types::{AttributeMap, BytesOrSlice};

pub mod options;

use super::{
    EntityBytesBulkInserter, EntityBytesIterator, EntityKeyBytesIterator, EntityStorageError,
    EntityStorageProvider, EntityStorageProviderFromLoadable,
};

impl From<rocksdb::Error> for EntityStorageError {
    fn from(error: rocksdb::Error) -> Self {
        EntityStorageError::backing(error)
    }
}

pub struct RocksDbEntityStorage {
    database: DB,
}

impl EntityStorageProviderFromLoadable for RocksDbEntityStorage {
    fn from_loadable(
        _loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError> {
        let db_path = attributes
            .get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH)
            .ok_or(EntityStorageError::NoProjectPath)?;

        // TODO: allow options to be passed in via attributes

        Ok(Self {
            database: DB::open_default(&db_path)?,
        })
    }
}

impl EntityStorageProvider for RocksDbEntityStorage {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        todo!()
    }

    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        todo!()
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        todo!()
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        todo!()
    }

    fn iter_prefix_keys(
        &self,
        prefix: &[u8],
    ) -> Result<EntityKeyBytesIterator<'_>, EntityStorageError> {
        todo!()
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        todo!()
    }

    fn bulk_inserter(&self) -> Result<EntityBytesBulkInserter, EntityStorageError> {
        todo!()
    }
}
