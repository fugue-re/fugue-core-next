use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

pub mod entities;
pub use entities::{
    DefaultPersistentEntityStorage, DefaultTransientEntityStorage, EntityStorage,
    EntityStorageError, EntityStorageProvider,
};

pub mod segments;
pub use segments::{
    DefaultPersistentSegmentStorage, DefaultTransientSegmentStorage, SegmentStorage,
    SegmentStorageError, SegmentStorageProvider,
};

use entities::{EntityStorageProviderFromLoadable, InMemoryEntityStorage};
use segments::{InMemorySegmentStorage, SegmentStorageProviderFromLoadable};

use crate::types::AttributeMap;
use crate::{loader::Loadable, types::attributes::ATTRIBUTE_PROJECT_PATH};

#[derive(Debug, Error)]
pub enum StorageProviderError {
    #[error("failed to create or load project: {0}")]
    CreateProject(std::io::Error),
    #[error("failed to clean-up project: {0}")]
    CleanupProject(std::io::Error),
    #[error("no project path specified")]
    NoProjectPath,

    #[error("failed to initialise entity storage: {0}")]
    EntityStorage(#[from] EntityStorageError),
    #[error("failed to initialise segment storage: {0}")]
    SegmentStorage(#[from] SegmentStorageError),
}

pub struct StorageContainer {
    pub entities: EntityStorage,
    pub segments: SegmentStorage,
    cleanup_handler: Option<Box<dyn StorageCleanupHandler>>,
}

impl Drop for StorageContainer {
    fn drop(&mut self) {
        // Ensure we only run the cleanup handler once.
        let Some(mut handler) = self.cleanup_handler.take() else {
            return;
        };

        if let Err(e) = handler.cleanup_storage() {
            tracing::error!("failed to cleanup storage: {e}");
        }
    }
}

pub trait StorageCleanupHandler: Send + Sync + 'static {
    /// This method is run when a Project is dropped, allowing the provider to perform cleanup
    /// tasks such as removing temporary files or packing segments and entity storage into a single
    /// file. Due to being called on drop, the error will be not be propagated, however, it will be
    /// logged.
    fn cleanup_storage(&mut self) -> Result<(), StorageProviderError>;
}

impl<F> StorageCleanupHandler for F
where
    F: FnMut() -> Result<(), StorageProviderError> + Send + Sync + 'static,
{
    fn cleanup_storage(&mut self) -> Result<(), StorageProviderError> {
        (*self)()
    }
}

impl StorageContainer {
    pub fn new<P>(loadable: &impl Loadable) -> Result<Self, StorageProviderError>
    where
        P: StorageProvider,
    {
        P::from_loadable(loadable)
    }

    pub fn from_parts(entities: EntityStorage, segments: SegmentStorage) -> Self {
        Self {
            entities,
            segments,
            cleanup_handler: None,
        }
    }

    pub fn set_cleanup_handler<F>(&mut self, handler: F)
    where
        F: StorageCleanupHandler + 'static,
    {
        self.cleanup_handler = Some(Box::new(handler));
    }

    pub fn with_cleanup_handler<F>(mut self, handler: F) -> Self
    where
        F: StorageCleanupHandler,
    {
        self.set_cleanup_handler(handler);
        self
    }

    pub fn entities(&self) -> &EntityStorage {
        &self.entities
    }

    pub fn entities_mut(&mut self) -> &mut EntityStorage {
        &mut self.entities
    }

    pub fn segments(&self) -> &SegmentStorage {
        &self.segments
    }

    pub fn segments_mut(&mut self) -> &mut SegmentStorage {
        &mut self.segments
    }
}

pub trait StorageProvider {
    fn from_loadable(loadable: &impl Loadable) -> Result<StorageContainer, StorageProviderError>;
}

// This provider uses the default transient storage provider for both segments and entities.
pub struct TransientStorageProvider;

impl StorageProvider for TransientStorageProvider {
    fn from_loadable(loadable: &impl Loadable) -> Result<StorageContainer, StorageProviderError> {
        let attributes = loadable.attributes();
        let entities =
            EntityStorage::new(InMemoryEntityStorage::from_loadable(loadable, attributes)?);
        let segments =
            SegmentStorage::new(InMemorySegmentStorage::from_loadable(loadable, attributes)?);
        Ok(StorageContainer::from_parts(entities, segments))
    }
}

// This provider uses the default transient storage provider for segments and default persistent
// storage provider for entities.
pub struct PersistentEntityStorageProvider;

impl StorageProvider for PersistentEntityStorageProvider {
    fn from_loadable(loadable: &impl Loadable) -> Result<StorageContainer, StorageProviderError> {
        let compressed = CompressedPersistentStorage::new(loadable)?;

        let entities = EntityStorage::new(DefaultPersistentEntityStorage::from_loadable(
            loadable,
            compressed.attributes(),
        )?);
        let segments = SegmentStorage::new(DefaultTransientSegmentStorage::from_loadable(
            loadable,
            compressed.attributes(),
        )?);

        Ok(StorageContainer::from_parts(entities, segments).with_cleanup_handler(compressed))
    }
}

// This provider uses the default persistent storage provider for both segments and entities.
pub struct PersistentStorageProvider;

impl StorageProvider for PersistentStorageProvider {
    fn from_loadable(loadable: &impl Loadable) -> Result<StorageContainer, StorageProviderError> {
        let compressed = CompressedPersistentStorage::new(loadable)?;

        let entities = EntityStorage::new(DefaultPersistentEntityStorage::from_loadable(
            loadable,
            compressed.attributes(),
        )?);

        let segments = SegmentStorage::new(DefaultTransientSegmentStorage::from_loadable(
            loadable,
            compressed.attributes(),
        )?);

        Ok(StorageContainer::from_parts(entities, segments).with_cleanup_handler(compressed))
    }
}

pub struct CompressedPersistentStorage {
    path: PathBuf,
    attributes: AttributeMap,
}

impl StorageCleanupHandler for CompressedPersistentStorage {
    fn cleanup_storage(&mut self) -> Result<(), StorageProviderError> {
        let packed = self.path.with_extension("fdbz");
        let unpacked = self.path.with_extension("fdb");

        fs::remove_dir_all(&unpacked).map_err(StorageProviderError::CleanupProject)?;

        todo!(
            "pack/repack {} with the contents of {}",
            packed.display(),
            unpacked.display()
        );

        // TODO: zip the contents of the unpacked directory into the packed file
        // and remove the unpacked directory.

        Ok(())
    }
}

impl CompressedPersistentStorage {
    pub fn new(loadable: &impl Loadable) -> Result<Self, StorageProviderError> {
        let path = loadable
            .attributes()
            .get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH)
            .ok_or(StorageProviderError::NoProjectPath)?;

        Self::create_or_load(&path)?;

        let mut attributes = AttributeMap::new();

        // Ensure we point to the (unpacked) project path.
        attributes.set_attr(ATTRIBUTE_PROJECT_PATH, path.with_extension("fdb"));

        Ok(Self { path, attributes })
    }

    pub fn attributes(&self) -> &AttributeMap {
        &self.attributes
    }

    fn create_or_load(path: &Path) -> Result<(), StorageProviderError> {
        if path.extension() != Some("fdbz".as_ref()) {
            return Err(StorageProviderError::CreateProject(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a project path with .fdbz extension",
            )));
        }

        if path.is_file() {
            // load file
            Self::load(path)?;
        } else if !path.exists() {
            Self::create(path)?;
        } else {
            return Err(StorageProviderError::CreateProject(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "project path exists but is not a file",
            )));
        }

        Ok(())
    }

    fn create(path: &Path) -> Result<(), StorageProviderError> {
        let unpacked = path.with_extension("fdb");
        if unpacked.exists() {
            return Err(StorageProviderError::CreateProject(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "project file already exists; potentially corrupted project",
            )));
        }

        fs::create_dir_all(path).map_err(StorageProviderError::CreateProject)?;

        Ok(())
    }

    fn load(path: &Path) -> Result<(), StorageProviderError> {
        let unpacked = path.with_extension("fdb");
        if unpacked.exists() {
            return Err(StorageProviderError::CreateProject(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "project file already exists; potentially corrupted project",
            )));
        }

        // TODO: validate the project; unpack the contents to the unpacked directory
        todo!(
            "load project from {} and unpack to {}",
            path.display(),
            unpacked.display()
        );

        Ok(())
    }
}
