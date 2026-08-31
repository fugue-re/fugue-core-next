use std::fs::{self, File};
use std::io::{self, BufWriter, Cursor, Error as IoError, Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bitflags::bitflags;
use hex_display::HexDisplayExt;
use thiserror::Error;
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

use crate::loader::{ImageResolution, Loadable};
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;
use crate::types::{AttributeMap, BytesOrMapping};

pub(crate) mod schema;

pub(crate) mod entities;
#[cfg(feature = "sqlite")]
pub use entities::SqliteEntityStorage;
#[cfg(feature = "mdbx")]
pub use entities::{ATTRIBUTE_ENTITY_STORAGE_MDBX_OPTIONS, MdbxEntityStorage, MdbxOptions};
#[cfg(feature = "rocksdb")]
pub use entities::{
    ATTRIBUTE_ENTITY_STORAGE_ROCKSDB_OPTIONS, RocksDbEntityStorage, RocksDbOptions,
};
pub use entities::{
    BufferedEntityWriter, DefaultPersistentEntityStorage, DefaultTransientEntityStorage,
    DummyEntityStorage, ENTITY_PROJECT_REVISION_ID, Entity, EntityBytesAsIterator,
    EntityBytesIterator, EntityBytesReadTransaction, EntityBytesWriteTransaction, EntityCodec,
    EntityId, EntityIterator, EntityKey, EntityKeyBytes, EntityKeyBytesIterator, EntityKeyCodec,
    EntityKeyId, EntityKeyIterator, EntityKeyPrefix, EntityMut, EntityReadTransaction, EntityRef,
    EntityStorage, EntityStorageError, EntityStorageProvider, EntityStorageProviderFromLoadable,
    EntityStorageProviderFromStorage, EntityStorageReadTransaction, EntityStorageWriteTransaction,
    EntityWrite, EntityWriteTransaction, InMemoryEntityStorage, MutableEntity, ProjectEntity,
    WriteBackAction, WriteBackWorker,
};

pub(crate) mod project;
#[cfg(feature = "sqlite")]
pub use project::SqliteProvider;
pub use project::{FundamentalProjectEntity, PersistableProjectEntity, ProjectEntityFromStorage};

pub(crate) mod segments;
pub use segments::{
    AddressSpace, AddressSpaceError, AddressSpaceId, AddressSpaceKind, DEFAULT_SPACE_ID,
    DefaultPersistentSegmentStorage, DefaultTransientSegmentStorage, InMemorySegmentStorage,
    MemoryMappedSegmentStorage, SegmentMapping, SegmentMappingBuilder, SegmentMappingCache,
    SegmentMappingFlags, SegmentMappingId, SegmentMappingKind, SegmentMappingProvenance,
    SegmentMappingRef, SegmentMappingView, SegmentProperties, SegmentStorage,
    SegmentStorageDescriptor, SegmentStorageError, SegmentStorageProvider,
    SegmentStorageProviderDescriptor, SegmentStorageProviderEntry,
    SegmentStorageProviderFromLoadable, SegmentStorageProviderFromSegmentRange,
    SegmentStorageProviderFromStorage, SegmentStorageProviderId, SegmentStorageProviderRegistry,
    SegmentSubMapping,
};

pub const FUGUE_STORAGE_MAGIC: &[u8] = b"FDBZ";

bitflags! {
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
    #[repr(transparent)]
    pub struct FugueStorageFlags: u32 {
        const STANDALONE = 0x00000001;
    }
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct FugueStorageMetadata {
    flags: u32,
}

pub const PERSISTENT: bool = true;
pub const TRANSIENT: bool = false;

pub type StoragePersistence = bool;

#[derive(Debug, Error)]
pub enum StorageProviderError {
    #[error("failed to clean-up project: {0}")]
    CleanupProject(IoError),
    #[error("failed to create or load project: {0}")]
    CreateProject(IoError),
    #[error("failed to initialise entity storage: {0}")]
    EntityStorage(#[from] EntityStorageError),
    #[error("no project path specified")]
    NoProjectPath,
    #[error("project is not a standalone project; cannot be loaded without a loadable instance")]
    NotAStandaloneProject,
    #[error("failed to validate project magic bytes")]
    NotAValidProject,
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
    entities: EntityStorage,
    image_resolution: Option<ImageResolution>,
    segments: SegmentStorage,
    write_back: Option<Arc<WriteBackWorker>>,
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

    pub fn from_parts(
        entities: EntityStorage,
        segments: SegmentStorage,
    ) -> Result<Self, StorageProviderError> {
        let write_back = if entities.is_transient() {
            None
        } else {
            Some(WriteBackWorker::new(entities.clone())?)
        };

        Ok(Self {
            entities,
            image_resolution: None,
            segments,
            write_back,
            cleanup_handler: StorageCleanupHandlerOneShot::default(),
        })
    }

    pub fn set_image_resolution(&mut self, image_resolution: ImageResolution) {
        self.image_resolution = Some(image_resolution);
    }

    pub fn with_image_resolution(mut self, image_resolution: ImageResolution) -> Self {
        self.set_image_resolution(image_resolution);
        self
    }

    pub fn set_cleanup_handler(&mut self, handler: impl StorageCleanupHandler) {
        self.cleanup_handler.set_handler(handler);
    }

    pub fn with_cleanup_handler(mut self, handler: impl StorageCleanupHandler) -> Self {
        self.set_cleanup_handler(handler);
        self
    }

    pub fn write_back(&self) -> Option<&Arc<WriteBackWorker>> {
        self.write_back.as_ref()
    }

    pub fn entities(&self) -> &EntityStorage {
        &self.entities
    }

    pub fn image_resolution(&self) -> Option<&ImageResolution> {
        self.image_resolution.as_ref()
    }

    pub(crate) fn entity<K, E>(&self, key: &K) -> Result<Option<E>, EntityStorageError>
    where
        K: EntityKey,
        E: Entity,
    {
        if let Some(pending) = self.pending_entity::<K, E>(key) {
            return match pending {
                WriteBackAction::Insert(bytes) => entities::decode_entity(&bytes).map(Some),
                WriteBackAction::Remove => Ok(None),
            };
        }

        self.entities.get::<K, E>(key)
    }

    pub(crate) fn contains_entity<K, E>(&self, key: &K) -> Result<bool, EntityStorageError>
    where
        K: EntityKey,
        E: Entity,
    {
        match self.pending_entity::<K, E>(key) {
            Some(WriteBackAction::Insert(_)) => Ok(true),
            Some(WriteBackAction::Remove) => Ok(false),
            None => self.entities.contains::<K, E>(key),
        }
    }

    fn pending_entity<K, E>(&self, key: &K) -> Option<WriteBackAction>
    where
        K: EntityKey,
        E: Entity,
    {
        self.write_back()?.pending(&E::ID.key_for(key))
    }

    pub(crate) fn table<T>(
        &self,
        cache_bytes: usize,
        with_worker: fn(
            EntityStorage,
            Arc<WriteBackWorker>,
            usize,
        ) -> Result<T, EntityStorageError>,
        new_transient: fn() -> T,
        table: &str,
    ) -> Result<T, EntityStorageError> {
        match self.write_back() {
            Some(worker) => with_worker(self.entities.clone(), worker.clone(), cache_bytes)
                .inspect_err(|e| tracing::error!("failed to load {table} table: {e}")),
            None => Ok(new_transient()),
        }
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
        let (segments, image_resolution) =
            SegmentStorage::from_loadable::<InMemorySegmentStorage>(loadable, attributes)?
                .into_parts();

        Ok(StorageContainer::from_parts(entities, segments)?
            .with_image_resolution(image_resolution))
    }
}

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
        let (segments, image_resolution) =
            SegmentStorage::from_loadable::<InMemorySegmentStorage>(loadable, attributes)?
                .into_parts();

        Ok(StorageContainer::from_parts(entities, segments)?
            .with_image_resolution(image_resolution)
            .with_cleanup_handler(compressed))
    }
}

pub struct PersistentStorageProvider<T, U = DefaultPersistentSegmentStorage>(PhantomData<(T, U)>);

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

        Ok(StorageContainer::from_parts(entities, segments)?.with_cleanup_handler(compressed))
    }

    fn from_loadable(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<StorageContainer, StorageProviderError> {
        let compressed =
            CompressedPersistentStorage::new(attributes)?.with_flags(FugueStorageFlags::STANDALONE);

        let entities = EntityStorage::new(T::from_loadable(loadable, attributes)?);
        let (segments, image_resolution) =
            SegmentStorage::from_loadable::<U>(loadable, attributes)?.into_parts();

        Ok(StorageContainer::from_parts(entities, segments)?
            .with_image_resolution(image_resolution)
            .with_cleanup_handler(compressed))
    }
}

pub type DefaultPersistentStorageProvider =
    PersistentStorageProvider<DefaultPersistentEntityStorage, DefaultPersistentSegmentStorage>;

#[cfg(any(feature = "mdbx", feature = "rocksdb", feature = "sqlite"))]
pub type DefaultProjectStorageProvider = DefaultPersistentStorageProvider;

#[cfg(all(
    not(feature = "mdbx"),
    not(feature = "rocksdb"),
    not(feature = "sqlite")
))]
pub type DefaultProjectStorageProvider = TransientStorageProvider;

pub struct CompressedPersistentStorage {
    flags: FugueStorageFlags,
    path: PathBuf,
}

impl StorageCleanupHandler for CompressedPersistentStorage {
    fn cleanup_storage(&mut self) -> Result<(), StorageProviderError> {
        let result = self.pack();
        if result.is_err() {
            let path = self.path.with_extension("fdbz");
            if path.exists()
                && let Err(e) = fs::remove_file(&path)
            {
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

        attributes.set_attr(ATTRIBUTE_PROJECT_PATH, path.with_extension("fdb"));

        Ok(Self {
            path,
            flags: FugueStorageFlags::empty(),
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

        let flags = Self::unpack(path, true)?;

        attributes.set_attr(ATTRIBUTE_PROJECT_PATH, path.with_extension("fdb"));

        Ok(Self {
            path: path.to_path_buf(),
            flags,
        })
    }

    pub fn flags(&self) -> FugueStorageFlags {
        self.flags
    }

    pub fn set_flags(&mut self, flags: FugueStorageFlags) -> &mut Self {
        self.flags = flags;
        self
    }

    pub fn with_flags(mut self, flags: FugueStorageFlags) -> Self {
        self.set_flags(flags);
        self
    }

    fn pack(&self) -> Result<(), StorageProviderError> {
        let packed = self.path.with_extension("fdbz");
        let unpacked = self.path.with_extension("fdb");

        let file = File::create(&packed).map_err(StorageProviderError::CleanupProject)?;
        let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Zstd);
        let mut writer = BufWriter::new(file);
        self.write_metadata(&mut writer)?;
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
            let options = if size > u32::MAX as u64 {
                options.large_file(true)
            } else {
                options
            };

            zip.start_file_from_path(relative_path, options)
                .map_err(StorageProviderError::cleanup_project)?;
            io::copy(&mut data, &mut zip).map_err(StorageProviderError::CleanupProject)?;
        }

        let mut writer = zip
            .finish()
            .map_err(StorageProviderError::cleanup_project)?;
        writer
            .flush()
            .map_err(StorageProviderError::cleanup_project)?;
        fs::remove_dir_all(&unpacked).map_err(StorageProviderError::CleanupProject)?;
        Ok(())
    }

    pub fn read_metadata(mut input: impl Read) -> Result<FugueStorageFlags, StorageProviderError> {
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

        let mut encoded = vec![0; size_of::<rkyv::Archived<FugueStorageMetadata>>()];
        input
            .read_exact(&mut encoded)
            .map_err(|_| StorageProviderError::create_project("failed to read storage metadata"))?;
        let metadata = rkyv::from_bytes::<FugueStorageMetadata, rkyv::rancor::Error>(&encoded)
            .map_err(|_| StorageProviderError::create_project("invalid storage metadata"))?;

        Ok(FugueStorageFlags::from_bits_truncate(metadata.flags))
    }

    pub fn write_metadata(&self, mut output: impl Write) -> Result<(), StorageProviderError> {
        output
            .write_all(FUGUE_STORAGE_MAGIC)
            .map_err(|_| StorageProviderError::create_project("failed to write magic bytes"))?;

        let metadata = FugueStorageMetadata {
            flags: self.flags.bits(),
        };
        let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(&metadata).map_err(|_| {
            StorageProviderError::create_project("failed to encode storage metadata")
        })?;
        output.write_all(&encoded).map_err(|_| {
            StorageProviderError::create_project("failed to write storage metadata")
        })?;

        Ok(())
    }

    fn create_or_load(path: &Path) -> Result<(), StorageProviderError> {
        if path.extension() != Some("fdbz".as_ref()) {
            return Err(StorageProviderError::create_project_invalid_input(
                "expected a project path with .fdbz extension",
            ));
        }

        if path.is_file() {
            Self::unpack(path, false)?;
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

    fn extract_archive(
        input: impl Read + Seek,
        unpacked: &Path,
    ) -> Result<(), StorageProviderError> {
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

    fn unpack(
        path: &Path,
        require_standalone: bool,
    ) -> Result<FugueStorageFlags, StorageProviderError> {
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

        let flags = Self::read_metadata(&mut input)?;

        tracing::trace!("project has the following properties: {flags:?}");

        if require_standalone && !flags.contains(FugueStorageFlags::STANDALONE) {
            tracing::error!(
                "project is not a standalone project; cannot be loaded without a loadable instance"
            );
            return Err(StorageProviderError::NotAStandaloneProject);
        }

        fs::create_dir_all(&unpacked).map_err(StorageProviderError::CreateProject)?;

        let result = Self::extract_archive(input, &unpacked);

        if result.is_err() {
            fs::remove_dir_all(&unpacked).map_err(StorageProviderError::CleanupProject)?;
        }

        result.map(|_| flags)
    }
}
