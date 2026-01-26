use std::fs::{self, File};
use std::io::{self, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use bitflags::bitflags;
use fugue_bytes::BE;
use fugue_bytes::order::{ReadBytesExt as _, WriteBytesExt as _};
use hex_display::HexDisplayExt;
use thiserror::Error;
use walkdir::WalkDir;

use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

use crate::loader::Loadable;
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;
use crate::types::{AttributeMap, BytesOrMapping};

pub mod entities;
pub use entities::{
    DefaultPersistentEntityStorage, DefaultTransientEntityStorage, EntityStorage,
    EntityStorageError, EntityStorageProvider,
};
use entities::{
    EntityStorageProviderFromLoadable, EntityStorageProviderFromStorage, InMemoryEntityStorage,
};

pub mod project;
pub use project::{ProjectStorage, ProjectStorageProvider};

pub mod segments;
pub use segments::{
    DefaultPersistentSegmentStorage, DefaultTransientSegmentStorage, SegmentStorage,
    SegmentStorageError, SegmentStorageProvider,
};
use segments::{InMemorySegmentStorage, SegmentStorageProviderFromStorage};

// The magic bytes used to identify a Fugue project file.
//
// Currently, we have a magic number of `FDBZ` followed by another four
// bytes, which are reserved for future use or versioning.
//
pub const FUGUE_STORAGE_MAGIC: &[u8] = b"FDBZ";

bitflags! {
    /// Flags used to indicate the persistence of storage.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
    #[repr(transparent)]
    pub struct FugueStorageHeader: u32 {
        /// Indicates that the storage is self-contained, i.e., that both the segment and entity
        /// storage providers can be built without a loadable instance.
        const STANDALONE = 0x00000001;
    }
}

pub const PERSISTENT: bool = true;
pub const TRANSIENT: bool = false;

pub type StoragePersistence = bool;

pub const ATTRIBUTE_FUNCTION_CACHE_SIZE: &str = "storage.entities.function.cache_size";
pub const DEFAULT_FUNCTION_CACHE_SIZE: usize = 16 * 1024;

#[derive(Debug, Error)]
pub enum StorageProviderError {
    #[error("failed to create or load project: {0}")]
    CreateProject(std::io::Error),
    #[error("failed to clean-up project: {0}")]
    CleanupProject(std::io::Error),
    #[error("no project path specified")]
    NoProjectPath,
    #[error("failed to validate project magic bytes")]
    NotAValidProject,
    #[error("project is not a standalone project; cannot be loaded without a loadable instance")]
    NotAStandaloneProject,

    #[error("failed to initialise entity storage: {0}")]
    EntityStorage(#[from] EntityStorageError),
    #[error("failed to initialise segment storage: {0}")]
    SegmentStorage(#[from] SegmentStorageError),
}

impl StorageProviderError {
    pub fn create_project_already_exists<E>(e: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::CreateProject(io::Error::new(io::ErrorKind::AlreadyExists, e))
    }

    pub fn create_project_not_found<E>(e: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::CreateProject(io::Error::new(io::ErrorKind::NotFound, e))
    }

    pub fn create_project_invalid_input<E>(e: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::CreateProject(io::Error::new(io::ErrorKind::InvalidInput, e))
    }

    pub fn create_project<E>(e: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::CreateProject(io::Error::other(e))
    }

    pub fn cleanup_project_invalid_data<E>(e: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::CleanupProject(io::Error::new(io::ErrorKind::InvalidData, e))
    }

    pub fn cleanup_project<E>(e: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::CleanupProject(io::Error::other(e))
    }

    pub fn requires_loadable(&self) -> bool {
        matches!(self, Self::NotAStandaloneProject | Self::NotAValidProject)
            || matches!(self, Self::CreateProject(e) if e.kind() == io::ErrorKind::NotFound)
    }
}

pub struct StorageContainer {
    pub entities: EntityStorage,
    pub segments: SegmentStorage,
    cleanup_handler: StorageCleanupHandlerOneShot,
}

#[derive(Default)]
struct StorageCleanupHandlerOneShot(Option<Box<dyn StorageCleanupHandler>>);

impl StorageCleanupHandlerOneShot {
    fn set_handler(&mut self, handler: impl StorageCleanupHandler) {
        assert!(self.0.is_none(), "cleanup handler can only be set once");
        self.0 = Some(Box::new(handler));
    }
}

impl Drop for StorageCleanupHandlerOneShot {
    fn drop(&mut self) {
        // Ensure we only run the cleanup handler once.
        let Some(mut handler) = self.0.take() else {
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
    pub fn from_loadable<P>(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, StorageProviderError>
    where
        P: StorageProvider,
    {
        P::from_loadable(loadable, attributes)
    }

    pub fn from_storage<P>(
        path: impl AsRef<Path>,
        attributes: &mut AttributeMap,
    ) -> Result<Self, StorageProviderError>
    where
        P: StorageProvider,
    {
        P::from_storage(path, attributes)
    }

    pub fn from_parts(entities: EntityStorage, segments: SegmentStorage) -> Self {
        Self {
            entities,
            segments,
            cleanup_handler: StorageCleanupHandlerOneShot::default(),
        }
    }

    pub fn set_cleanup_handler(&mut self, handler: impl StorageCleanupHandler) {
        self.cleanup_handler.set_handler(handler);
    }

    pub fn with_cleanup_handler(mut self, handler: impl StorageCleanupHandler) -> Self {
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

    fn from_storage(
        path: impl AsRef<Path>,
        attributes: &mut AttributeMap,
    ) -> Result<StorageContainer, StorageProviderError>;
}

// This provider uses the default transient storage provider for both segments and entities.
pub struct TransientStorageProvider;

impl StorageProvider for TransientStorageProvider {
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
        let entities =
            EntityStorage::new(InMemoryEntityStorage::from_loadable(loadable, attributes)?);
        let segments =
            SegmentStorage::from_loadable::<InMemorySegmentStorage>(loadable, attributes)?;

        Ok(StorageContainer::from_parts(entities, segments))
    }
}

// This provider uses the default transient storage provider for segments and default persistent
// storage provider for entities.
pub struct PersistentEntityStorageProvider;

impl StorageProvider for PersistentEntityStorageProvider {
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
        let compressed = CompressedPersistentStorage::new(attributes)?;

        let entities = EntityStorage::new(DefaultPersistentEntityStorage::from_loadable(
            loadable, attributes,
        )?);
        let segments =
            SegmentStorage::from_loadable::<InMemorySegmentStorage>(loadable, attributes)?;

        Ok(StorageContainer::from_parts(entities, segments).with_cleanup_handler(compressed))
    }
}

// This provider uses the default persistent storage provider for both segments and entities.
pub struct PersistentStorageProvider<T, U = DefaultPersistentSegmentStorage>(
    std::marker::PhantomData<(T, U)>,
);

impl<T, U> StorageProvider for PersistentStorageProvider<T, U>
where
    T: EntityStorageProviderFromStorage,
    U: SegmentStorageProviderFromStorage,
{
    fn from_storage(
        path: impl AsRef<Path>,
        attributes: &mut AttributeMap,
    ) -> Result<StorageContainer, StorageProviderError> {
        let path = path.as_ref();
        let compressed = CompressedPersistentStorage::from_existing(path, attributes)?;

        let unpacked = path.with_extension("fdb");

        let entities = EntityStorage::new(T::from_storage(&unpacked, attributes)?);
        let segments = SegmentStorage::from_storage(&unpacked, attributes)?;

        Ok(StorageContainer::from_parts(entities, segments).with_cleanup_handler(compressed))
    }

    fn from_loadable(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<StorageContainer, StorageProviderError> {
        let compressed = CompressedPersistentStorage::new(attributes)?
            .with_header(FugueStorageHeader::STANDALONE);

        let entities = EntityStorage::new(T::from_loadable(loadable, attributes)?);
        let segments = SegmentStorage::from_loadable::<U>(loadable, attributes)?;

        Ok(StorageContainer::from_parts(entities, segments).with_cleanup_handler(compressed))
    }
}

pub type DefaultPersistentStorageProvider =
    PersistentStorageProvider<DefaultPersistentEntityStorage, DefaultPersistentSegmentStorage>;

pub struct CompressedPersistentStorage {
    header: FugueStorageHeader,
    path: PathBuf,
}

impl CompressedPersistentStorage {
    fn cleanup_storage_aux(&mut self) -> Result<(), StorageProviderError> {
        let packed = self.path.with_extension("fdbz");
        let unpacked = self.path.with_extension("fdb");

        let file = File::create(&packed).map_err(StorageProviderError::CleanupProject)?;
        let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Zstd);

        let mut writer = BufWriter::new(file);

        self.write_header(&mut writer)?;

        let mut zip = ZipWriter::new(writer);

        for tracked in WalkDir::new(&unpacked)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            let path = tracked.path();
            let relative_path = path
                .strip_prefix(&unpacked)
                .expect("file/directory path should be relative to unpacked directory");

            if relative_path == Path::new("") {
                // skip the root directory
                continue;
            }

            tracing::debug!(
                "packing `{}` into `{}` ({} bytes)",
                relative_path.display(),
                packed.display(),
                tracked
                    .metadata()
                    .map_err(StorageProviderError::cleanup_project)?
                    .len()
            );

            if tracked.file_type().is_dir() {
                zip.add_directory_from_path(relative_path, options)
                    .map_err(StorageProviderError::cleanup_project)?;
                continue;
            }

            let mut data = File::open(path).map_err(StorageProviderError::CleanupProject)?;

            let size = data.seek(SeekFrom::End(0)).map_err(|_| {
                StorageProviderError::cleanup_project_invalid_data("failed to obtain file size")
            })?;

            data.seek(SeekFrom::Start(0)).map_err(|_| {
                StorageProviderError::cleanup_project_invalid_data(
                    "failed to seek to start of file",
                )
            })?;

            // if not less than 4 GiB, use large file options
            let options = if size > u32::MAX as u64 {
                options.large_file(true)
            } else {
                options
            };

            zip.start_file_from_path(relative_path, options)
                .map_err(StorageProviderError::cleanup_project)?;

            std::io::copy(&mut data, &mut zip).map_err(StorageProviderError::CleanupProject)?;
        }

        zip.finish()
            .map_err(StorageProviderError::cleanup_project)?;

        fs::remove_dir_all(&unpacked).map_err(StorageProviderError::CleanupProject)?;

        Ok(())
    }
}

impl StorageCleanupHandler for CompressedPersistentStorage {
    fn cleanup_storage(&mut self) -> Result<(), StorageProviderError> {
        let result = self.cleanup_storage_aux();
        if result.is_err() {
            let path = self.path.with_extension("fdbz");
            if path.exists() && let Err(e) = fs::remove_file(&path) {
                tracing::error!(
                    "failed to remove packed project file `{}`: {e}",
                    path.display()
                );
            }
        }
        result
    }
}

impl CompressedPersistentStorage {
    pub fn new(attributes: &mut AttributeMap) -> Result<Self, StorageProviderError> {
        let path = attributes
            .get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH)
            .ok_or(StorageProviderError::NoProjectPath)?;

        Self::create_or_load(&path)?;

        // ensure we point to the (unpacked) project path
        attributes.set_attr(ATTRIBUTE_PROJECT_PATH, path.with_extension("fdb"));

        Ok(Self {
            path,
            header: FugueStorageHeader::empty(),
        })
    }

    pub fn from_existing(
        path: &Path,
        attributes: &mut AttributeMap,
    ) -> Result<Self, StorageProviderError> {
        if !path.exists() {
            return Err(StorageProviderError::create_project_not_found(format!(
                "`{}` does not exist",
                path.display()
            )));
        }

        let header = Self::load_standalone(path)?;

        // ensure we point to the (unpacked) project path
        attributes.set_attr(ATTRIBUTE_PROJECT_PATH, path.with_extension("fdb"));

        Ok(Self {
            path: path.to_path_buf(),
            header,
        })
    }

    pub fn header(&self) -> FugueStorageHeader {
        self.header
    }

    pub fn set_header(&mut self, header: FugueStorageHeader) -> &mut Self {
        self.header = header;
        self
    }

    pub fn with_header(mut self, header: FugueStorageHeader) -> Self {
        self.set_header(header);
        self
    }

    pub fn read_header(mut input: impl Read) -> Result<FugueStorageHeader, StorageProviderError> {
        let mut magic = [0u8; FUGUE_STORAGE_MAGIC.len()];

        input
            .read_exact(&mut magic)
            .map_err(|_| StorageProviderError::create_project("failed to read magic bytes"))?;

        if magic != FUGUE_STORAGE_MAGIC {
            tracing::error!(
                "project magic bytes do not match: expected {}, got {}",
                FUGUE_STORAGE_MAGIC.hex(),
                magic.hex(),
            );
            return Err(StorageProviderError::NotAValidProject);
        }

        let header = input
            .read_u32::<BE>()
            .map(FugueStorageHeader::from_bits_truncate)
            .map_err(|_| StorageProviderError::create_project("failed to read storage header"))?;

        Ok(header)
    }

    pub fn write_header(&self, mut output: impl Write) -> Result<(), StorageProviderError> {
        output
            .write_all(FUGUE_STORAGE_MAGIC)
            .map_err(|_| StorageProviderError::create_project("failed to write magic bytes"))?;

        output
            .write_u32::<BE>(self.header.bits())
            .map_err(|_| StorageProviderError::create_project("failed to write storage header"))?;

        Ok(())
    }

    fn create_or_load(path: &Path) -> Result<(), StorageProviderError> {
        if path.extension() != Some("fdbz".as_ref()) {
            return Err(StorageProviderError::create_project_invalid_input(
                "expected a project path with .fdbz extension",
            ));
        }

        if path.is_file() {
            // load file
            Self::load(path)?;
        } else if !path.exists() {
            Self::create(path)?;
        } else {
            return Err(StorageProviderError::create_project_invalid_input(
                "expected a file or a directory",
            ));
        }

        Ok(())
    }

    fn create(path: &Path) -> Result<(), StorageProviderError> {
        let unpacked = path.with_extension("fdb");
        if unpacked.exists() {
            return Err(StorageProviderError::create_project_already_exists(
                "unpacked project data already exists; potentially corrupted project",
            ));
        }

        fs::create_dir_all(unpacked).map_err(StorageProviderError::CreateProject)?;

        Ok(())
    }

    fn load_aux(input: impl Read + Seek, unpacked: &Path) -> Result<(), StorageProviderError> {
        let mut zip = ZipArchive::new(input).map_err(StorageProviderError::create_project)?;

        tracing::debug!("unpacking project to `{}`", unpacked.display());

        if !unpacked.exists() {
            tracing::debug!(
                "unpacked project directory does not exist `{}`",
                unpacked.display()
            );
        }

        zip.extract(unpacked)
            .map_err(StorageProviderError::create_project)?;

        Ok(())
    }

    fn load_with(
        path: &Path,
        standalone: bool,
    ) -> Result<FugueStorageHeader, StorageProviderError> {
        let unpacked = path.with_extension("fdb");
        if unpacked.exists() {
            return Err(StorageProviderError::create_project_already_exists(
                "unpacked project data already exists; potentially corrupted project",
            ));
        }

        tracing::trace!("loading project from `{}`", path.display());

        let mut input = Cursor::new(
            BytesOrMapping::from_file(path).map_err(StorageProviderError::create_project)?,
        );

        let header = Self::read_header(&mut input)?;

        tracing::trace!("project has the following properties: {header:?}");

        if standalone && !header.contains(FugueStorageHeader::STANDALONE) {
            tracing::error!(
                "project is not a standalone project; cannot be loaded without a loadable instance"
            );
            return Err(StorageProviderError::NotAStandaloneProject);
        }

        fs::create_dir_all(&unpacked).map_err(StorageProviderError::CreateProject)?;

        let result = Self::load_aux(input, &unpacked);

        if result.is_err() {
            // if we failed to load the project, we attempt to clean-up
            fs::remove_dir_all(&unpacked).map_err(StorageProviderError::CleanupProject)?;
        }

        result.map(|_| header)
    }

    fn load_standalone(path: &Path) -> Result<FugueStorageHeader, StorageProviderError> {
        Self::load_with(path, true)
    }

    fn load(path: &Path) -> Result<FugueStorageHeader, StorageProviderError> {
        Self::load_with(path, false)
    }
}
