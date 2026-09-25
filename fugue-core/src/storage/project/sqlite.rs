use std::path::Path;

use crate::loader::Loadable;
use crate::storage::entities::{EntityStorageProviderFromLoadable, SqliteEntityStorage};
use crate::storage::segments::InMemorySegmentStorage;
use crate::storage::{
    EntityStorage, PERSISTENT, PersistentStorageProvider, SegmentStorage, StorageContainer,
    StoragePersistence, StorageProvider, StorageProviderError, TRANSIENT,
};
use crate::types::AttributeMap;

pub struct SqliteProvider<const PERSISTENCE: StoragePersistence>;

impl StorageProvider for SqliteProvider<PERSISTENT> {
    fn from_storage(
        path: impl AsRef<Path>,
        attributes: &mut AttributeMap,
    ) -> Result<StorageContainer, StorageProviderError> {
        PersistentStorageProvider::<SqliteEntityStorage<PERSISTENT>>::from_storage(path, attributes)
    }

    fn from_loadable(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<StorageContainer, StorageProviderError> {
        PersistentStorageProvider::<SqliteEntityStorage<PERSISTENT>>::from_loadable(
            loadable, attributes,
        )
    }
}

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
        let (segments, image_resolution) =
            SegmentStorage::from_loadable::<InMemorySegmentStorage>(loadable, attributes)?
                .into_parts();

        Ok(StorageContainer::from_parts(entities, segments)?
            .with_image_resolution(image_resolution))
    }
}
