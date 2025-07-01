use std::path::PathBuf;

use crate::loader::Loadable;
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;
use crate::types::{AttributeMap, BytesOrSlice};

pub mod options;

use super::{
    EntityBytesBulkInserter, EntityBytesIterator, EntityKeyBytesIterator, EntityStorageError,
    EntityStorageProvider, EntityStorageProviderFromLoadable,
};

pub const ATTRIBUTE_ENTITY_STORAGE_ROCKSDB_OPTIONS: &str =
    "storage.entities.backend.rocksdb.options";

const PROJECT_ROCKSDB_DATA: &str = "entities.rdb";

impl From<rocksdb::Error> for EntityStorageError {
    fn from(error: rocksdb::Error) -> Self {
        EntityStorageError::backing(error)
    }
}

pub struct RocksDbEntityStorage {
    database: rocksdb::DB,
}

impl EntityStorageProviderFromLoadable for RocksDbEntityStorage {
    fn from_loadable(
        _loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError> {
        let project_path = attributes
            .get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH)
            .ok_or(EntityStorageError::NoProjectPath)?;

        let db_path = project_path.join(PROJECT_ROCKSDB_DATA);

        let mut options = rocksdb::Options::default();

        if let Some(db_options) =
            attributes.get_attr::<options::RocksDbOptions>(ATTRIBUTE_ENTITY_STORAGE_ROCKSDB_OPTIONS)
        {
            db_options.apply(&mut options);
        }

        Ok(Self {
            database: rocksdb::DB::open(&options, db_path)?,
        })
    }
}

impl EntityStorageProvider for RocksDbEntityStorage {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        // TODO: add get_as so we can operate on PinnedSlice?
        Ok(self.database
            .get(key)
            .map_err(EntityStorageError::backing)?
            .map(BytesOrSlice::from))
    }

    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        self.database.put(key, value).map_err(EntityStorageError::backing)
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        self.database.delete(key).map_err(EntityStorageError::backing)
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        // TODO: check if there's a more efficient way to check existence
        self.database
            .get_pinned(key)
            .map_err(EntityStorageError::backing)
            .map(|opt| opt.is_some())
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
