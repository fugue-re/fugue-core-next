use std::path::Path;

use thiserror::Error;

use crate::arch::Arch;
use crate::entities::Function;
use crate::lifter::{HybridLifter, Language};
use crate::loader::{
    ExternSymbols, Loadable, LoadableFromBytes, Loader, LoaderError, LocalSymbols, SymbolEntry,
};
use crate::storage::entities::{EntityCache, EntityStorage, EntityStorageError, ProjectEntity};
use crate::storage::segments::SegmentStorage;
use crate::storage::{
    ATTRIBUTE_FUNCTION_CACHE_SIZE, DEFAULT_FUNCTION_CACHE_SIZE, StorageContainer, StorageProvider,
    StorageProviderError,
};
use crate::types::attributes::{ATTRIBUTE_FILE_PATH, ATTRIBUTE_PROJECT_PATH};
use crate::types::{Address, AttributeMap};

pub struct Project {
    pub(crate) arch: Arch,
    pub(crate) lifter: HybridLifter,
    pub(crate) language: &'static Language,
    pub(crate) entry: Option<Address>,
    pub(crate) local_symbols: Option<LocalSymbols>,
    pub(crate) extern_symbols: Option<ExternSymbols>,
    pub(crate) functions: EntityCache<Address, Function>,
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
    pub lifter: &'a HybridLifter,
    pub language: &'static Language,
    pub entry: Option<Address>,
    pub local_symbols: Option<&'a LocalSymbols>,
    pub extern_symbols: Option<&'a ExternSymbols>,
    pub functions: &'a EntityCache<Address, Function>,
    pub attributes: &'a AttributeMap,
    pub storage: &'a StorageContainer,
}

pub struct ProjectMut<'a> {
    pub arch: &'a mut Arch,
    pub lifter: &'a mut HybridLifter,
    pub language: &'static Language,
    pub entry: Option<Address>,
    pub local_symbols: Option<&'a mut LocalSymbols>,
    pub extern_symbols: Option<&'a mut ExternSymbols>,
    pub functions: &'a EntityCache<Address, Function>,
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
    pub fn new<P>(loadable: &impl Loadable) -> Result<Self, ProjectError>
    where
        P: StorageProvider,
    {
        Self::new_with::<P>(loadable, AttributeMap::default())
    }

    pub fn new_with<P>(
        loadable: &impl Loadable,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError>
    where
        P: StorageProvider,
    {
        let arch = loadable.architecture();
        let lifter = HybridLifter::new(arch.disassembler(), arch.lifter());
        let language = arch.language();

        // NOTE: we make a copy of the loader attributes, as project attributes will be a superset.
        let mut attributes = attributes.into();

        attributes.merge_vacant(loadable.attributes());

        let storage = StorageContainer::new::<P>(loadable, &mut attributes)?;

        if let Some(nattributes) = storage.entities.get(&ProjectEntity::Attributes)? {
            // NOTE: we prefer the most recently set attributes, and use the persisted
            // attributes for vacant keys.
            attributes.merge_vacant(&nattributes);
        }

        let local_symbols = storage
            .entities
            .get(&ProjectEntity::LocalSymbols)?
            .map(Some)
            .unwrap_or_else(|| loadable.local_symbols().cloned());

        let extern_symbols = storage
            .entities
            .get(&ProjectEntity::ExternSymbols)?
            .map(Some)
            .unwrap_or_else(|| loadable.extern_symbols().cloned());

        let function_cache_size = attributes
            .get_attr::<usize>(ATTRIBUTE_FUNCTION_CACHE_SIZE)
            .unwrap_or(DEFAULT_FUNCTION_CACHE_SIZE);

        let functions = EntityCache::new(storage.entities.clone(), function_cache_size)?;

        Ok(Self {
            arch,
            lifter,
            language,
            entry: loadable.entry(),
            local_symbols,
            extern_symbols,
            functions,
            attributes,
            storage,
        })
    }

    pub fn from_bytes<P>(bytes: &[u8]) -> Result<Self, ProjectError>
    where
        P: StorageProvider,
    {
        Self::from_bytes_with::<P>(bytes, AttributeMap::default())
    }

    pub fn from_bytes_with<P>(
        bytes: &[u8],
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError>
    where
        P: StorageProvider,
    {
        Loader::from_bytes_with(bytes, attributes)
            .map_err(ProjectError::from)
            .and_then(|loader| Self::new::<P>(&loader))
    }

    pub fn from_file<P>(path: impl AsRef<Path>) -> Result<Self, ProjectError>
    where
        P: StorageProvider,
    {
        Self::from_file_with::<P>(path, AttributeMap::default())
    }

    pub fn from_file_with<P>(
        path: impl AsRef<Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, ProjectError>
    where
        P: StorageProvider,
    {
        let path = path.as_ref();
        let mut attributes = attributes.into();

        if !attributes.contains(ATTRIBUTE_FILE_PATH) {
            attributes.set_attr(ATTRIBUTE_FILE_PATH, path);
        }

        if !attributes.contains(ATTRIBUTE_PROJECT_PATH) {
            attributes.set_attr(ATTRIBUTE_PROJECT_PATH, path.with_extension("fdbz"));
        }

        Loader::from_file_with(path, attributes)
            .map_err(ProjectError::from)
            .and_then(|loader| Self::new::<P>(&loader))
    }

    pub fn architecture(&self) -> &Arch {
        &self.arch
    }

    pub fn lifter(&self) -> &HybridLifter {
        &self.lifter
    }

    pub fn lifter_mut(&mut self) -> &mut HybridLifter {
        &mut self.lifter
    }

    pub fn language(&self) -> &'static Language {
        self.language
    }

    pub fn entry(&self) -> Option<Address> {
        self.entry
    }

    pub fn local_symbols(&self) -> Option<&LocalSymbols> {
        self.local_symbols.as_ref()
    }

    pub fn iter_local_symbols<'a>(&'a self) -> impl Iterator<Item = SymbolEntry> + 'a {
        self.local_symbols
            .as_ref()
            .into_iter()
            .flat_map(|symbols| symbols.iter())
    }

    pub fn extern_symbols(&self) -> Option<&ExternSymbols> {
        self.extern_symbols.as_ref()
    }

    pub fn iter_extern_symbols<'a>(&'a self) -> impl Iterator<Item = SymbolEntry> + 'a {
        self.extern_symbols
            .as_ref()
            .into_iter()
            .flat_map(|symbols| symbols.iter())
    }

    pub fn functions(&self) -> &EntityCache<Address, Function> {
        &self.functions
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

    pub fn persist(&self) -> Result<(), StorageProviderError> {
        // NOTE: the function cache is already persisted in the background, so we don't need to
        // persist it here.
        tracing::debug!("persisting project data");

        tracing::debug!("persisting project attributes");
        self.storage
            .entities
            .insert(&ProjectEntity::Attributes, &self.attributes)?;

        if let Some(local_symbols) = self.local_symbols.as_ref() {
            tracing::debug!("persisting local symbol table");
            self.storage
                .entities
                .insert(&ProjectEntity::LocalSymbols, local_symbols)?;
        }

        if let Some(extern_symbols) = self.extern_symbols.as_ref() {
            tracing::debug!("persisting external symbol table");
            self.storage
                .entities
                .insert(&ProjectEntity::ExternSymbols, extern_symbols)?;
        }

        Ok(())
    }

    pub fn fields(&self) -> ProjectRef {
        ProjectRef {
            arch: &self.arch,
            lifter: &self.lifter,
            language: self.language,
            entry: self.entry,
            local_symbols: self.local_symbols.as_ref(),
            extern_symbols: self.extern_symbols.as_ref(),
            functions: &self.functions,
            attributes: &self.attributes,
            storage: &self.storage,
        }
    }

    pub fn fields_mut(&mut self) -> ProjectMut {
        ProjectMut {
            arch: &mut self.arch,
            lifter: &mut self.lifter,
            language: self.language,
            entry: self.entry,
            local_symbols: self.local_symbols.as_mut(),
            extern_symbols: self.extern_symbols.as_mut(),
            functions: &self.functions,
            attributes: &mut self.attributes,
            storage: &mut self.storage,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        attributes,
        storage::{PersistentStorageProvider, TransientStorageProvider},
    };

    use super::*;

    #[test]
    fn test_project() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let project = Project::from_file::<TransientStorageProvider>("tests/ls.elf")?;

            let mut bytes = [0u8; 32];
            project
                .segments()
                .read_bytes(0x4000u32.into(), &mut bytes)?;

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
    fn test_project_persistent() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let project = Project::from_file_with::<PersistentStorageProvider>(
                "tests/ls.elf",
                attributes![
                    ATTRIBUTE_PROJECT_PATH => "tests/ls.fdbz"
                ],
            )?;

            drop(project);

            Ok(())
        })
    }
}
