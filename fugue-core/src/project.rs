use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::arch::Arch;
use crate::ir::Address;
use crate::ir::traits::SymbolTable as _;
use crate::lifter::{Language, Lifter};
use crate::loader::{Loadable, LoadableFromBytes, LoadableFromFile, Loader, LoaderError};
use crate::storage::entities::{EntityStorage, EntityStorageError, ProjectEntity};
use crate::storage::project::{
    InMemoryProvider, PersistableProjectEntity, ProjectEntityFromStorage,
};
use crate::storage::segments::SegmentStorage;
use crate::storage::{
    ProjectStorage, ProjectStorageProvider, StorageContainer, StorageProvider, StorageProviderError,
};
use crate::types::AttributeMap;
use crate::types::attributes::{
    ATTRIBUTE_ENTRY_POINT, ATTRIBUTE_FILE_PATH, ATTRIBUTE_PROJECT_PATH,
};

pub type InMemoryProject = Project<InMemoryProvider>;

pub struct Project<S = InMemoryProvider>
where
    S: ProjectStorageProvider, {
    pub(crate) arch: Arch,
    pub(crate) language: &'static Language,
    pub(crate) symbols: <S::ProjectStorage as ProjectStorage>::SymbolTable,
    pub(crate) functions: <S::ProjectStorage as ProjectStorage>::FunctionTable,
    pub(crate) blocks: <S::ProjectStorage as ProjectStorage>::CodeBlockTable,
    pub(crate) attributes: AttributeMap,
    // NOTE: this must be that last field, so it will be dropped last.
    pub(crate) storage: StorageContainer,
    _marker: PhantomData<S>,
}

impl<S> Drop for Project<S>
where
    S: ProjectStorageProvider,
{
    fn drop(&mut self) {
        if let Err(e) = self.persist() {
            tracing::error!("failed to persist project data: {e}");
        }
    }
}

pub struct ProjectRef<'a, S>
where
    S: ProjectStorageProvider, {
    pub arch: &'a Arch,
    pub language: &'static Language,
    pub symbols: &'a <S::ProjectStorage as ProjectStorage>::SymbolTable,
    pub functions: &'a <S::ProjectStorage as ProjectStorage>::FunctionTable,
    pub blocks: &'a <S::ProjectStorage as ProjectStorage>::CodeBlockTable,
    pub attributes: &'a AttributeMap,
    pub storage: &'a StorageContainer,
    _marker: PhantomData<S>,
}

pub struct ProjectMut<'a, S>
where
    S: ProjectStorageProvider, {
    pub arch: &'a mut Arch,
    pub language: &'static Language,
    pub symbols: &'a mut <S::ProjectStorage as ProjectStorage>::SymbolTable,
    pub functions: &'a mut <S::ProjectStorage as ProjectStorage>::FunctionTable,
    pub blocks: &'a mut <S::ProjectStorage as ProjectStorage>::CodeBlockTable,
    pub attributes: &'a mut AttributeMap,
    pub storage: &'a mut StorageContainer,
    _marker: PhantomData<S>,
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

impl<S> Project<S>
where
    S: ProjectStorageProvider,
{
    pub fn new(loadable: &impl Loadable) -> Result<Self, ProjectError> {
        Self::new_with(loadable, AttributeMap::default())
    }

    pub fn new_with(
        loadable: &impl Loadable,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError> {
        // NOTE: we make a copy of the loader attributes, as project attributes will be a superset.
        let mut attributes = attributes.into();

        attributes.merge_vacant(loadable.attributes());

        tracing::trace!("initialising project storage layer");

        let storage =
            StorageContainer::from_loadable::<S::StorageProvider>(loadable, &mut attributes)?;

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

        let symbols_builder = || match S::ProjectStorage::symbol_table(&storage.entities)? {
            Some(symbols) => Ok(symbols),
            None => {
                let Some(loadable) = loadable else {
                    tracing::error!("project not standalone and no loadable instance available");
                    return Err(StorageProviderError::NotAStandaloneProject.into());
                };

                let mut symbols =
                    <S::ProjectStorage as ProjectStorage>::SymbolTable::default_from_entity_storage(&storage.entities)?;

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

        let functions_builder = || match S::ProjectStorage::function_table(&storage.entities)? {
            Some(functions) => Ok(functions),
            None => {
                <S::ProjectStorage as ProjectStorage>::FunctionTable::default_from_entity_storage(
                    &storage.entities,
                )
                .map_err(ProjectError::from)
            }
        };

        let functions = match functions_builder() {
            Ok(table) => table,
            Err(e) => {
                tracing::error!("failed to load function table: {e}");
                return Err(e);
            }
        };

        tracing::trace!("loading project code blocks");

        let blocks_builder = || match S::ProjectStorage::code_block_table(&storage.entities)? {
            Some(blocks) => Ok(blocks),
            None => {
                <S::ProjectStorage as ProjectStorage>::CodeBlockTable::default_from_entity_storage(
                    &storage.entities,
                )
                .map_err(ProjectError::from)
            }
        };

        let blocks = match blocks_builder() {
            Ok(table) => table,
            Err(e) => {
                tracing::error!("failed to load code block table: {e}");
                return Err(e);
            }
        };

        Ok(Self {
            arch,
            language,
            symbols,
            functions,
            blocks,
            attributes,
            storage,
            _marker: PhantomData,
        })
    }

    pub fn from_bytes<P>(bytes: &[u8]) -> Result<Self, ProjectError> {
        Self::from_bytes_with(bytes, AttributeMap::default())
    }

    pub fn try_from_bytes<'a, L>(
        bytes: &'a [u8],
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError>
    where
        L: LoadableFromBytes<'a>, {
        Self::try_from_bytes_with::<L>(bytes, attributes)
    }

    pub fn from_bytes_with(
        bytes: &[u8],
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError> {
        Self::try_from_bytes_with::<Loader>(bytes, attributes)
    }

    pub fn try_from_bytes_with<'a, L>(
        bytes: &'a [u8],
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError>
    where
        L: LoadableFromBytes<'a>, {
        let mut attributes = attributes.into();

        if let Some(path) = attributes.get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH) {
            return match S::StorageProvider::from_storage(path, &mut attributes) {
                Ok(storage) => Self::from_storage(None::<&L>, storage, attributes),
                Err(e) if e.requires_loadable() => L::from_bytes_with(bytes, attributes)
                    .map_err(ProjectError::from)
                    .and_then(|loader| Self::new(&loader)),
                Err(e) => Err(ProjectError::from(e)),
            };
        }

        L::from_bytes_with(bytes, attributes)
            .map_err(ProjectError::from)
            .and_then(|loader| Self::new(&loader))
    }

    /// Loads or creates a project from the given file path.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ProjectError> {
        Self::from_file_with(path, AttributeMap::default())
    }

    pub fn try_from_file<L>(path: impl AsRef<Path>) -> Result<Self, ProjectError>
    where
        L: LoadableFromFile, {
        Self::try_from_file_with::<L>(path, AttributeMap::default())
    }

    /// Loads or creates a project from the given file path with the specified attributes.
    pub fn from_file_with(
        path: impl AsRef<Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError> {
        Self::try_from_file_with::<Loader>(path, attributes)
    }

    pub fn try_from_file_with<L>(
        path: impl AsRef<Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError>
    where
        L: LoadableFromFile, {
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

        match S::StorageProvider::from_storage(project_path, &mut attributes) {
            Ok(storage) => Self::from_storage(None::<&L>, storage, attributes),
            Err(e) if e.requires_loadable() => L::from_file_with(path, attributes)
                .map_err(ProjectError::from)
                .and_then(|loader| Self::new(&loader)),
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

    pub fn symbols(&self) -> &<S::ProjectStorage as ProjectStorage>::SymbolTable {
        &self.symbols
    }

    pub fn symbols_mut(&mut self) -> &mut <S::ProjectStorage as ProjectStorage>::SymbolTable {
        &mut self.symbols
    }

    pub fn blocks(&self) -> &<S::ProjectStorage as ProjectStorage>::CodeBlockTable {
        &self.blocks
    }

    pub fn blocks_mut(&mut self) -> &mut <S::ProjectStorage as ProjectStorage>::CodeBlockTable {
        &mut self.blocks
    }

    pub fn functions(&self) -> &<S::ProjectStorage as ProjectStorage>::FunctionTable {
        &self.functions
    }

    pub fn functions_mut(&mut self) -> &mut <S::ProjectStorage as ProjectStorage>::FunctionTable {
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

        Ok(())
    }

    pub fn fields(&self) -> ProjectRef<S> {
        ProjectRef {
            arch: &self.arch,
            language: self.language,
            symbols: &self.symbols,
            functions: &self.functions,
            blocks: &self.blocks,
            attributes: &self.attributes,
            storage: &self.storage,
            _marker: PhantomData,
        }
    }

    pub fn fields_mut(&mut self) -> ProjectMut<S> {
        ProjectMut {
            arch: &mut self.arch,
            language: self.language,
            symbols: &mut self.symbols,
            functions: &mut self.functions,
            blocks: &mut self.blocks,
            attributes: &mut self.attributes,
            storage: &mut self.storage,
            _marker: PhantomData,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::attributes;
    #[cfg(feature = "mdbx")]
    use crate::storage::entities::MdbxEntityStorage;
    #[cfg(feature = "rocksdb")]
    use crate::storage::entities::RocksDbEntityStorage;
    use crate::storage::project::{
        DefaultPersistentProjectStorageProvider, DefaultTransientProjectStorageProvider,
    };
    use crate::storage::{DefaultPersistentEntityStorage, DefaultPersistentSegmentStorage};

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
            let project =
                Project::<DefaultTransientProjectStorageProvider>::from_file("tests/ls.elf")?;

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

    #[test]
    fn test_project_persistent_default() -> Result<(), Box<dyn std::error::Error>> {
        with_logging(|| {
            let project = Project::<
                DefaultPersistentProjectStorageProvider<
                    DefaultPersistentEntityStorage,
                    DefaultPersistentSegmentStorage,
                >,
            >::from_file_with(
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
            let project = Project::<
                DefaultPersistentProjectStorageProvider<
                    MdbxEntityStorage,
                    DefaultPersistentSegmentStorage,
                >,
            >::from_file_with(
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
            let _project = Project::<
                DefaultPersistentProjectStorageProvider<
                    RocksDbEntityStorage,
                    DefaultPersistentSegmentStorage,
                >,
            >::from_file("tests/test-project.rdb.fdbz")?;

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
