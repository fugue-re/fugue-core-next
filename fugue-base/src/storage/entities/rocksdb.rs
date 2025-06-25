use std::path::PathBuf;

use crate::loader::Loadable;
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;
use crate::types::{AttributeMap, BytesOrSlice};

use super::{
    EntityBytesBulkInserter, EntityBytesIterator, EntityKeyBytesIterator, EntityStorageError,
    EntityStorageProvider, EntityStorageProviderFromLoadable,
};

pub struct RocksDbEntityStorage;

impl EntityStorageProviderFromLoadable for RocksDbEntityStorage {
    fn from_loadable(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError> {
        let _project = attributes
            .get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH)
            .ok_or(EntityStorageError::NoProjectPath)?;

        todo!()
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
