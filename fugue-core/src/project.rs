use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::arch::Arch;
use crate::ir::{Address, CodeBlockTable, FunctionTable, SymbolTable};
use crate::lifter::{Language, Lifter};
use crate::loader::{Loadable, LoadableFromBytes, LoadableFromFile, Loader, LoaderError};
use crate::storage::entities::{EntityStorage, EntityStorageError, ProjectEntity};
use crate::storage::project::{PersistableProjectEntity, ProjectEntityFromStorage};
use crate::storage::segments::SegmentStorage;
use crate::storage::{
    ATTRIBUTE_CODE_BLOCK_CACHE_SIZE, ATTRIBUTE_FUNCTION_CACHE_SIZE, DEFAULT_CODE_BLOCK_CACHE_BYTES,
    DEFAULT_FUNCTION_CACHE_BYTES, DefaultProjectStorageProvider, StorageContainer, StorageProvider,
    StorageProviderError, TransientStorageProvider,
};
use crate::types::AttributeMap;
use crate::types::attributes::{
    ATTRIBUTE_ENTRY_POINT, ATTRIBUTE_FILE_PATH, ATTRIBUTE_PROJECT_PATH,
};

pub struct Project {
    pub(crate) arch: Arch,
    pub(crate) language: &'static Language,
    pub(crate) symbols: SymbolTable,
    pub(crate) functions: FunctionTable,
    pub(crate) blocks: CodeBlockTable,
    pub(crate) attributes: AttributeMap,
    // NOTE: this must be that last field, so it will be dropped last.
    pub(crate) storage: StorageContainer,
}

impl Drop for Project {
    fn drop(&mut self) {
        if let Err(e) = self.persist() {
            tracing::error!("failed to persist project data: {e}");
        }
    }
}

pub struct ProjectRef<'a> {
    pub arch: &'a Arch,
    pub language: &'static Language,
    pub symbols: &'a SymbolTable,
    pub functions: &'a FunctionTable,
    pub blocks: &'a CodeBlockTable,
    pub attributes: &'a AttributeMap,
    pub storage: &'a StorageContainer,
}

pub struct ProjectMut<'a> {
    pub arch: &'a mut Arch,
    pub language: &'static Language,
    pub symbols: &'a mut SymbolTable,
    pub functions: &'a mut FunctionTable,
    pub blocks: &'a mut CodeBlockTable,
    pub attributes: &'a mut AttributeMap,
    pub storage: &'a mut StorageContainer,
}

#[derive(Debug, Error)]
pub enum ProjectError {
    #[error(transparent)]
    Loader(#[from] LoaderError),
    #[error("failed to create entity cache: {0}")]
    EntityStorage(#[from] EntityStorageError),
    #[error(transparent)]
    StorageProvider(#[from] StorageProviderError),
}

impl Project {
    pub fn new(loadable: &impl Loadable) -> Result<Self, ProjectError> {
        Self::new_with(loadable, AttributeMap::default())
    }

    pub fn new_with(
        loadable: &impl Loadable,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError> {
        Self::new_with_provider::<DefaultProjectStorageProvider>(loadable, attributes)
    }

    pub fn new_transient(loadable: &impl Loadable) -> Result<Self, ProjectError> {
        Self::new_with_provider::<TransientStorageProvider>(loadable, AttributeMap::default())
    }

    pub fn new_transient_with(
        loadable: &impl Loadable,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError> {
        Self::new_with_provider::<TransientStorageProvider>(loadable, attributes)
    }

    pub fn new_with_provider<P>(
        loadable: &impl Loadable,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError>
    where
        P: StorageProvider,
    {
        // NOTE: we make a copy of the loader attributes, as project attributes will be a superset.
        let mut attributes = attributes.into();

        attributes.merge_vacant(loadable.attributes());

        tracing::trace!("initialising project storage layer");

        let storage = StorageContainer::from_loadable::<P>(loadable, &mut attributes)?;

        Self::from_storage(Some(loadable), storage, attributes)
    }

    fn from_storage(
        loadable: Option<&impl Loadable>,
        storage: StorageContainer,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError> {
        let mut attributes = attributes.into();

        tracing::trace!("loading project architecture and lifter");

        let Some(arch) = storage
            .entities
            .get(&ProjectEntity::Architecture)?
            .or_else(|| loadable.map(|l| l.architecture()))
        else {
            tracing::error!("project not standalone and no loadable instance available");
            return Err(StorageProviderError::NotAStandaloneProject.into());
        };

        let language = arch.language();

        tracing::trace!("loading project attributes");

        if let Some(nattributes) = storage.entities.get(&ProjectEntity::Attributes)? {
            // NOTE: we prefer the most recently set attributes, and use the persisted
            // attributes for vacant keys.
            attributes.merge_vacant(&nattributes);
        }

        tracing::trace!("loading project symbols");

        let symbols_builder = || match SymbolTable::from_entity_storage(&storage.entities)? {
            Some(symbols) => Ok(symbols),
            None => {
                let Some(loadable) = loadable else {
                    tracing::error!("project not standalone and no loadable instance available");
                    return Err(StorageProviderError::NotAStandaloneProject.into());
                };

                let mut symbols = SymbolTable::default_from_entity_storage(&storage.entities)?;

                if let Some(loadable_symbols) = loadable.symbols() {
                    tracing::trace!(
                        "transfering {} symbols from loadable",
                        loadable_symbols.len()
                    );

                    for (index, _, entry) in loadable_symbols.iter_by_index() {
                        symbols.insert(index, entry.address(), entry.symbol(), entry.properties());
                    }
                }
                Ok(symbols)
            }
        };

        let symbols = match symbols_builder() {
            Ok(table) => table,
            Err(e) => {
                tracing::error!("failed to load symbol table: {e}");
                return Err(e);
            }
        };

        tracing::trace!("loading project functions");

        let cache_bytes = attributes
            .get_attr::<usize>(ATTRIBUTE_FUNCTION_CACHE_SIZE)
            .unwrap_or(DEFAULT_FUNCTION_CACHE_BYTES);

        let functions = if storage.entities.is_transient() {
            FunctionTable::new_transient()
        } else {
            match storage.writeback() {
                Some(worker) => {
                    FunctionTable::new_with(storage.entities.clone(), worker.clone(), cache_bytes)
                }
                None => FunctionTable::new(storage.entities.clone(), cache_bytes),
            }
            .inspect_err(|e| tracing::error!("failed to load function table: {e}"))?
        };

        tracing::trace!("loading project code blocks");

        let block_cache_bytes = attributes
            .get_attr::<usize>(ATTRIBUTE_CODE_BLOCK_CACHE_SIZE)
            .unwrap_or(DEFAULT_CODE_BLOCK_CACHE_BYTES);

        let blocks = if storage.entities.is_transient() {
            CodeBlockTable::new_transient()
        } else {
            match storage.writeback() {
                Some(worker) => CodeBlockTable::new_with(
                    storage.entities.clone(),
                    worker.clone(),
                    block_cache_bytes,
                ),
                None => CodeBlockTable::new(storage.entities.clone(), block_cache_bytes),
            }
            .inspect_err(|e| tracing::error!("failed to load code block table: {e}"))?
        };

        Ok(Self {
            arch,
            language,
            symbols,
            functions,
            blocks,
            attributes,
            storage,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProjectError> {
        Self::from_bytes_with(bytes, AttributeMap::default())
    }

    pub fn try_from_bytes<'a, L>(
        bytes: &'a [u8],
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError>
    where
        L: LoadableFromBytes<'a>,
    {
        Self::try_from_bytes_with::<L>(bytes, attributes)
    }

    pub fn from_bytes_with(
        bytes: &[u8],
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError> {
        Self::try_from_bytes_with::<Loader>(bytes, attributes)
    }

    pub fn from_bytes_with_provider<P>(bytes: &[u8]) -> Result<Self, ProjectError>
    where
        P: StorageProvider,
    {
        Self::from_bytes_with_provider_and_attributes::<P>(bytes, AttributeMap::default())
    }

    pub fn from_bytes_with_provider_and_attributes<P>(
        bytes: &[u8],
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError>
    where
        P: StorageProvider,
    {
        Self::try_from_bytes_with_provider::<P, Loader>(bytes, attributes)
    }

    pub fn try_from_bytes_with<'a, L>(
        bytes: &'a [u8],
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError>
    where
        L: LoadableFromBytes<'a>,
    {
        Self::try_from_bytes_with_provider::<DefaultProjectStorageProvider, L>(bytes, attributes)
    }

    pub fn try_from_bytes_with_provider<'a, P, L>(
        bytes: &'a [u8],
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError>
    where
        P: StorageProvider,
        L: LoadableFromBytes<'a>,
    {
        let mut attributes = attributes.into();

        if let Some(path) = attributes.get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH) {
            return match P::from_storage(path, &mut attributes) {
                Ok(storage) => Self::from_storage(None::<&L>, storage, attributes),
                Err(e) if e.requires_loadable() => L::from_bytes_with(bytes, attributes)
                    .map_err(ProjectError::from)
                    .and_then(|loader| {
                        Self::new_with_provider::<P>(&loader, AttributeMap::default())
                    }),
                Err(e) => Err(ProjectError::from(e)),
            };
        }

        L::from_bytes_with(bytes, attributes)
            .map_err(ProjectError::from)
            .and_then(|loader| Self::new_with_provider::<P>(&loader, AttributeMap::default()))
    }

    /// Loads or creates a project from the given file path.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ProjectError> {
        Self::from_file_with(path, AttributeMap::default())
    }

    pub fn try_from_file<L>(path: impl AsRef<Path>) -> Result<Self, ProjectError>
    where
        L: LoadableFromFile,
    {
        Self::try_from_file_with::<L>(path, AttributeMap::default())
    }

    /// Loads or creates a project from the given file path with the specified attributes.
    pub fn from_file_with(
        path: impl AsRef<Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError> {
        Self::try_from_file_with::<Loader>(path, attributes)
    }

    pub fn from_file_transient(path: impl AsRef<Path>) -> Result<Self, ProjectError> {
        Self::from_file_with_provider::<TransientStorageProvider>(path)
    }

    pub fn from_file_transient_with(
        path: impl AsRef<Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError> {
        Self::from_file_with_provider_and_attributes::<TransientStorageProvider>(path, attributes)
    }

    pub fn from_file_with_provider<P>(path: impl AsRef<Path>) -> Result<Self, ProjectError>
    where
        P: StorageProvider,
    {
        Self::from_file_with_provider_and_attributes::<P>(path, AttributeMap::default())
    }

    pub fn from_file_with_provider_and_attributes<P>(
        path: impl AsRef<Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError>
    where
        P: StorageProvider,
    {
        Self::try_from_file_with_provider::<P, Loader>(path, attributes)
    }

    pub fn try_from_file_with<L>(
        path: impl AsRef<Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError>
    where
        L: LoadableFromFile,
    {
        Self::try_from_file_with_provider::<DefaultProjectStorageProvider, L>(path, attributes)
    }

    pub fn try_from_file_with_provider<P, L>(
        path: impl AsRef<Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError>
    where
        P: StorageProvider,
        L: LoadableFromFile,
    {
        let path = path.as_ref();
        let mut attributes = attributes.into();

        if !attributes.contains(ATTRIBUTE_FILE_PATH) {
            attributes.set_attr(ATTRIBUTE_FILE_PATH, path);
        }

        if !attributes.contains(ATTRIBUTE_PROJECT_PATH) {
            attributes.set_attr(ATTRIBUTE_PROJECT_PATH, path.with_extension("fdbz"));
        }

        let project_path = attributes
            .get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH)
            .expect("valid project path");

        match P::from_storage(project_path, &mut attributes) {
            Ok(storage) => Self::from_storage(None::<&L>, storage, attributes),
            Err(e) if e.requires_loadable() => L::from_file_with(path, attributes)
                .map_err(ProjectError::from)
                .and_then(|loader| Self::new_with_provider::<P>(&loader, AttributeMap::default())),
            Err(e) => Err(ProjectError::from(e)),
        }
    }

    pub fn arch(&self) -> &Arch {
        &self.arch
    }

    pub fn lifter(&self) -> Lifter {
        self.arch.lifter()
    }

    pub fn language(&self) -> &'static Language {
        self.language
    }

    pub fn entry(&self) -> Option<Address> {
        self.attributes().get_attr::<Address>(ATTRIBUTE_ENTRY_POINT)
    }

    pub fn symbols(&self) -> &SymbolTable {
        &self.symbols
    }

    pub fn symbols_mut(&mut self) -> &mut SymbolTable {
        &mut self.symbols
    }

    pub fn blocks(&self) -> &CodeBlockTable {
        &self.blocks
    }

    pub fn blocks_mut(&mut self) -> &mut CodeBlockTable {
        &mut self.blocks
    }

    pub fn functions(&self) -> &FunctionTable {
        &self.functions
    }

    pub fn functions_mut(&mut self) -> &mut FunctionTable {
        &mut self.functions
    }

    pub fn entities(&self) -> &EntityStorage {
        &self.storage.entities
    }

    pub fn segments(&self) -> &SegmentStorage {
        &self.storage.segments
    }

    pub fn segments_mut(&mut self) -> &mut SegmentStorage {
        &mut self.storage.segments
    }

    pub fn storage(&self) -> &StorageContainer {
        &self.storage
    }

    pub fn storage_mut(&mut self) -> &mut StorageContainer {
        &mut self.storage
    }

    pub fn attributes(&self) -> &AttributeMap {
        &self.attributes
    }

    pub fn attributes_mut(&mut self) -> &mut AttributeMap {
        &mut self.attributes
    }

    pub(crate) fn persist(&self) -> Result<(), StorageProviderError> {
        if self.storage.entities.is_transient() {
            tracing::debug!("entity storage is transient; skipping persistenece");
            return Ok(());
        }

        tracing::debug!("persisting project data");

        tracing::debug!("persisting project architecture and lifter");
        self.storage
            .entities
            .insert(&ProjectEntity::Architecture, &self.arch)?;

        tracing::debug!("persisting project attributes");
        self.storage
            .entities
            .insert(&ProjectEntity::Attributes, &self.attributes)?;

        tracing::debug!("persisting symbol table");
        self.symbols.persist(&self.storage.entities)?;

        tracing::debug!("persisting function table");
        self.functions.persist(&self.storage.entities)?;

        tracing::debug!("persisting code block table");
        self.blocks.persist(&self.storage.entities)?;

        if let Some(worker) = self.storage.writeback() {
            tracing::debug!("draining write-back worker");
            worker.flush()?;
        }

        Ok(())
    }

    pub fn fields(&self) -> ProjectRef<'_> {
        ProjectRef {
            arch: &self.arch,
            language: self.language,
            symbols: &self.symbols,
            functions: &self.functions,
            blocks: &self.blocks,
            attributes: &self.attributes,
            storage: &self.storage,
        }
    }

    pub fn fields_mut(&mut self) -> ProjectMut<'_> {
        ProjectMut {
            arch: &mut self.arch,
            language: self.language,
            symbols: &mut self.symbols,
            functions: &mut self.functions,
            blocks: &mut self.blocks,
            attributes: &mut self.attributes,
            storage: &mut self.storage,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(any(feature = "sqlite", feature = "rocksdb", feature = "mdbx"))]
    use crate::attributes;
    #[cfg(any(feature = "sqlite", feature = "rocksdb", feature = "mdbx"))]
    use crate::storage::DefaultPersistentEntityStorage;
    #[cfg(any(feature = "sqlite", feature = "rocksdb", feature = "mdbx"))]
    use crate::storage::DefaultPersistentSegmentStorage;
    #[cfg(any(feature = "sqlite", feature = "rocksdb", feature = "mdbx"))]
    use crate::storage::PersistentStorageProvider;
    #[cfg(feature = "mdbx")]
    use crate::storage::entities::MdbxEntityStorage;
    #[cfg(feature = "rocksdb")]
    use crate::storage::entities::RocksDbEntityStorage;

    fn with_logging(
        f: impl FnOnce() -> Result<(), Box<dyn std::error::Error>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, f)
    }

    #[test]
    fn test_project() -> Result<(), Box<dyn std::error::Error>> {
        with_logging(|| {
            let project = Project::from_file_transient("tests/ls.elf")?;

            let mut bytes = [0u8; 32];
            project.segments().read_bytes(0x4000u32, &mut bytes)?;

            assert_eq!(
                &bytes,
                &[
                    0xF3, 0x0F, 0x1E, 0xFA, 0x48, 0x83, 0xEC, 0x08, 0x48, 0x8B, 0x05, 0xB9, 0xEF,
                    0x01, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x02, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x08,
                    0xC3, 0x00, 0x00, 0x00, 0x00, 0x00
                ]
            );

            Ok(())
        })
    }

    #[cfg(any(feature = "sqlite", feature = "rocksdb", feature = "mdbx"))]
    #[test]
    fn test_project_persistent_default() -> Result<(), Box<dyn std::error::Error>> {
        with_logging(|| {
            let project = Project::from_file_with_provider_and_attributes::<
                PersistentStorageProvider<
                    DefaultPersistentEntityStorage,
                    DefaultPersistentSegmentStorage,
                >,
            >(
                "tests/ls.elf",
                attributes![
                    ATTRIBUTE_PROJECT_PATH => "tests/ls.fdbz"
                ],
            )?;

            drop(project);

            Ok(())
        })
    }

    #[cfg(feature = "mdbx")]
    #[test]
    fn test_project_persistent_mdbx() -> Result<(), Box<dyn std::error::Error>> {
        with_logging(|| {
            let project = Project::from_file_with_provider_and_attributes::<
                PersistentStorageProvider<MdbxEntityStorage, DefaultPersistentSegmentStorage>,
            >(
                "tests/ls.elf",
                attributes![
                    ATTRIBUTE_PROJECT_PATH => "tests/ls.mdbx.fdbz"
                ],
            )?;

            drop(project);

            Ok(())
        })
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn test_project_standalone() -> Result<(), Box<dyn std::error::Error>> {
        with_logging(|| {
            let _project = Project::from_file_with_provider::<
                PersistentStorageProvider<RocksDbEntityStorage, DefaultPersistentSegmentStorage>,
            >("tests/test-project.rdb.fdbz")?;

            /*
            let functions = project.functions();

            // warm the cache!
            for addr in functions.keys()? {
                let addr = addr?;
                let _f = functions.get(&addr)?;
            }

            let mut iter = functions.iter()?;

            let t = Instant::now();
            let mut count = 0;

            while let Some(Ok((addr, f))) = iter.next() {
                println!("function at {addr:#x}");
                println!(
                    "function at {addr:#x} with {} instructions and {} blocks",
                    f.instructions().len(),
                    f.blocks().len()
                );
                count += 1;
            }

            println!(
                "iterated {count} functions in {}ms",
                t.elapsed().as_millis()
            );
            */

            Ok(())
        })
    }
}
