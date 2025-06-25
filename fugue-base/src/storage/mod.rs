use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use object::ReadCacheOps;
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
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use crate::loader::Loadable;
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;
use crate::types::AttributeMap;

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
    pub fn new<P>(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, StorageProviderError>
    where
        P: StorageProvider,
    {
        P::from_loadable(loadable, attributes)
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
    fn from_loadable(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<StorageContainer, StorageProviderError>;
}

// This provider uses the default transient storage provider for both segments and entities.
pub struct TransientStorageProvider;

impl StorageProvider for TransientStorageProvider {
    fn from_loadable(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<StorageContainer, StorageProviderError> {
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
    fn from_loadable(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<StorageContainer, StorageProviderError> {
        let compressed = CompressedPersistentStorage::new(attributes)?;

        let entities = EntityStorage::new(DefaultPersistentEntityStorage::from_loadable(
            loadable, attributes,
        )?);
        let segments = SegmentStorage::new(DefaultTransientSegmentStorage::from_loadable(
            loadable, attributes,
        )?);

        Ok(StorageContainer::from_parts(entities, segments).with_cleanup_handler(compressed))
    }
}

// This provider uses the default persistent storage provider for both segments and entities.
pub struct PersistentStorageProvider;

impl StorageProvider for PersistentStorageProvider {
    fn from_loadable(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<StorageContainer, StorageProviderError> {
        let compressed = CompressedPersistentStorage::new(attributes)?;

        let entities = EntityStorage::new(DefaultPersistentEntityStorage::from_loadable(
            loadable, attributes,
        )?);
        let segments = SegmentStorage::new(DefaultTransientSegmentStorage::from_loadable(
            loadable, attributes,
        )?);

        Ok(StorageContainer::from_parts(entities, segments).with_cleanup_handler(compressed))
    }
}

pub struct CompressedPersistentStorage {
    path: PathBuf,
}

impl StorageCleanupHandler for CompressedPersistentStorage {
    fn cleanup_storage(&mut self) -> Result<(), StorageProviderError> {
        let packed = self.path.with_extension("fdbz");
        let unpacked = self.path.with_extension("fdb");

        let file = File::create(&packed).map_err(StorageProviderError::CleanupProject)?;
        let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Zstd);

        let mut zip = ZipWriter::new(file);

        for tracked in WalkDir::new(&unpacked)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            let path = tracked.path();
            let relative_path = path
                .strip_prefix(&unpacked)
                .expect("file/directory path should be relative to unpacked directory");

            if tracked.file_type().is_dir() {
                zip.add_directory_from_path(relative_path, options)
                    .map_err(|e| {
                        StorageProviderError::CleanupProject(io::Error::new(
                            io::ErrorKind::Other,
                            e,
                        ))
                    })?;
                continue;
            }

            let mut data = File::open(path).map_err(StorageProviderError::CleanupProject)?;
            let size = data.len().map_err(|_| {
                StorageProviderError::CleanupProject(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "failed to get file size",
                ))
            })?;

            // if not less than 4 GiB, use large file options
            let options = (size > u32::MAX as u64)
                .then(|| options.large_file(true))
                .unwrap_or(options);

            zip.start_file_from_path(relative_path, options)
                .map_err(|e| {
                    StorageProviderError::CleanupProject(io::Error::new(io::ErrorKind::Other, e))
                })?;

            std::io::copy(&mut data, &mut zip).map_err(StorageProviderError::CleanupProject)?;
        }

        zip.finish().map_err(|e| {
            StorageProviderError::CleanupProject(io::Error::new(io::ErrorKind::Other, e))
        })?;

        fs::remove_dir_all(&unpacked).map_err(StorageProviderError::CleanupProject)?;

        Ok(())
    }
}

impl CompressedPersistentStorage {
    pub fn new(attributes: &mut AttributeMap) -> Result<Self, StorageProviderError> {
        let path = attributes
            .get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH)
            .ok_or(StorageProviderError::NoProjectPath)?;

        Self::create_or_load(&path)?;

        let mut attributes = AttributeMap::new();

        // Ensure we point to the (unpacked) project path.
        attributes.set_attr(ATTRIBUTE_PROJECT_PATH, path.with_extension("fdb"));

        Ok(Self { path })
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
