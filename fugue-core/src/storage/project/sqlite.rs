use std::path::Path;

use crate::loader::Loadable;
use crate::storage::entities::{EntityStorageProviderFromLoadable, SqliteEntityStorage};
use crate::storage::segments::{
    InMemorySegmentStorage, MemoryMappedSegmentStorage, SegmentStorageProviderFromLoadable,
};
use crate::storage::{
    EntityStorage, PERSISTENT, PersistentStorageProvider, SegmentStorage, StorageContainer,
    StoragePersistence, StorageProvider, StorageProviderError, TRANSIENT,
};
use crate::types::AttributeMap;

use super::{DefaultProjectStorage, InMemoryProjectStorage, ProjectStorageProvider};

pub struct SqliteProvider<const PERSISTENCE: StoragePersistence>;

impl StorageProvider for SqliteProvider<TRANSIENT> {
    fn from_storage(
        _path: impl AsRef<Path>,
        _attributes: &mut AttributeMap,
    ) -> Result<StorageContainer, StorageProviderError> {
        Err(StorageProviderError::NotAStandaloneProject)
    }

    fn from_loadable(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<StorageContainer, StorageProviderError> {
        let entities = EntityStorage::new(SqliteEntityStorage::<TRANSIENT>::from_loadable(
            loadable, attributes,
        )?);
        let segments =
            SegmentStorage::new(InMemorySegmentStorage::from_loadable(loadable, attributes)?);

        Ok(StorageContainer::from_parts(entities, segments))
    }
}

impl ProjectStorageProvider for SqliteProvider<TRANSIENT> {
    type ProjectStorage = InMemoryProjectStorage;
    type StorageProvider = Self;
}

impl ProjectStorageProvider for SqliteProvider<PERSISTENT> {
    type ProjectStorage = DefaultProjectStorage;
    type StorageProvider = PersistentStorageProvider<
        SqliteEntityStorage<PERSISTENT>,
        MemoryMappedSegmentStorage<PERSISTENT>,
    >;
}
