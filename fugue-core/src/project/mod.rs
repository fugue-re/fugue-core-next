use std::any::Any;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;

use crate::arch::Arch;
use crate::il::common::{IlError, IlFormId, IlGenerationError, PersistableIl};
use crate::il::ecode::ECodeIr;
use crate::il::mcode::MCodeIr;
use crate::il::pcode::{PCodeError, PCodeIr};
use crate::il::registry::{IlFormRegistration, IlRegistry};
use crate::il::storage::{IlPersist, IlStorageError};
use crate::ir::block::{ATTRIBUTE_CODE_BLOCK_CACHE_SIZE, DEFAULT_CODE_BLOCK_CACHE_BYTES};
use crate::ir::function::{ATTRIBUTE_FUNCTION_CACHE_SIZE, DEFAULT_FUNCTION_CACHE_BYTES};
use crate::ir::problem::{ATTRIBUTE_PROBLEM_CACHE_SIZE, DEFAULT_PROBLEM_CACHE_BYTES};
use crate::ir::switch::{ATTRIBUTE_SWITCH_CACHE_SIZE, DEFAULT_SWITCH_CACHE_BYTES};
use crate::ir::symbol::{ATTRIBUTE_SYMBOL_CACHE_SIZE, DEFAULT_SYMBOL_CACHE_BYTES};
use crate::ir::{
    Address, CallGraphIndex, CodeBlockTable, FunctionId, FunctionTable, FunctionTableError,
    IncompleteFunctionError, ProblemTable, ProblemTableError, ReferenceIndex, SwitchTable,
    SwitchTableError, SymbolTable, TransientSymbolTable,
};
use crate::lifter::{Language, Lifter, LifterError};
use crate::loader::{Loadable, LoadableFromBytes, LoadableFromFile, Loader, LoaderError};
use crate::platform::Platform;
use crate::storage::entities::schema::ENTITY_PROJECT_REVISION_ID;
use crate::storage::entities::{Entity, EntityId, EntityStorageError, ProjectEntity};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::segments::SegmentStorage;
use crate::storage::{
    DefaultProjectStorageProvider, SegmentStorageError, StorageContainer, StorageProvider,
    StorageProviderError, TransientStorageProvider,
};
use crate::types::attributes::{
    ATTRIBUTE_ENTRY_POINT, ATTRIBUTE_INPUT_PATH, ATTRIBUTE_PROJECT_PATH,
};
use crate::types::{AttributeMap, Revision};

mod analysis;
pub(crate) use analysis::CoverageReconfiguration;
pub use analysis::{AnalysisCoverage, AnalysisPhase};

mod change;
pub(crate) use change::MAX_DETAILED_CHANGE_RECORDS;
pub use change::{
    ChangeCategory, ChangeKinds, ChangeProvenance, ChangeRecord, ChangeSet, ChangeSource,
    FunctionChangeKind,
};

pub(crate) mod read;
pub use read::ReadSet;

pub(crate) mod transaction;
pub use transaction::ProjectTransaction;

pub struct Project {
    arch: Arch,
    language: &'static Language,
    symbols: SymbolTable,
    functions: FunctionTable,
    blocks: CodeBlockTable,
    call_graph: CallGraphIndex,
    references: ReferenceIndex,
    problems: ProblemTable,
    coverage: AnalysisCoverage,
    switches: SwitchTable,
    platform: Platform,
    attributes: AttributeMap,
    revisions: ProjectRevisionState,
    persistable: bool,
    // NOTE: this must be that last field, so it will be dropped last.
    storage: StorageContainer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct ProjectRevisionState {
    revision: Revision,
    semantic_revision: Revision,
}

impl ProjectRevisionState {
    fn new(revision: Revision, semantic_revision: Revision) -> Self {
        Self {
            revision,
            semantic_revision,
        }
    }

    fn revision(&self) -> Revision {
        self.revision
    }

    fn semantic_revision(&self) -> Revision {
        self.semantic_revision
    }

    fn advance(&mut self, semantic: bool) -> Revision {
        self.revision = self.revision.next();
        if semantic {
            self.semantic_revision = self.revision;
        }
        self.revision
    }
}

impl Entity for ProjectRevisionState {
    const ID: EntityId = ENTITY_PROJECT_REVISION_ID;
}

impl Drop for Project {
    fn drop(&mut self) {
        if !self.persistable {
            return;
        }

        if let Err(e) = self.persist() {
            tracing::error!("failed to persist project data: {e}");
        }
    }
}

#[derive(Debug, Error)]
pub enum ProjectError {
    #[error("failed to create entity cache: {0}")]
    EntityStorage(#[from] EntityStorageError),
    #[error(transparent)]
    Function(#[from] FunctionTableError),
    #[error(transparent)]
    Generation(IlGenerationError),
    #[error(transparent)]
    Il(#[from] IlError),
    #[error(transparent)]
    IncompleteFunction(#[from] IncompleteFunctionError),
    #[error(transparent)]
    Lifter(#[from] LifterError),
    #[error(transparent)]
    Loader(#[from] LoaderError),
    #[error(transparent)]
    PCode(#[from] PCodeError),
    #[error(transparent)]
    Problem(#[from] ProblemTableError),
    #[error(transparent)]
    SegmentStorage(#[from] SegmentStorageError),
    #[error(transparent)]
    StorageProvider(#[from] StorageProviderError),
    #[error(transparent)]
    Switch(#[from] SwitchTableError),
}

impl From<IlStorageError> for ProjectError {
    fn from(error: IlStorageError) -> Self {
        match error {
            IlStorageError::Il(error) => Self::Il(error),
            IlStorageError::Storage(error) => Self::EntityStorage(error),
        }
    }
}

impl From<IlGenerationError> for ProjectError {
    fn from(error: IlGenerationError) -> Self {
        match error {
            IlGenerationError::Il(error) => Self::Il(error),
            error => Self::Generation(error),
        }
    }
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
            .entities()
            .get(&ProjectEntity::Architecture)?
            .or_else(|| loadable.map(|l| l.architecture()))
        else {
            tracing::error!("project not standalone and no loadable instance available");
            return Err(StorageProviderError::NotAStandaloneProject.into());
        };

        let language = arch.language();
        let platform = loadable
            .map(Loadable::platform)
            .or(storage
                .entities()
                .get::<ProjectEntity, Platform>(&ProjectEntity::Platform)?)
            .unwrap_or_else(|| arch.platform());

        tracing::trace!("loading project attributes");

        if let Some(nattributes) = storage.entities().get(&ProjectEntity::Attributes)? {
            // NOTE: we prefer the most recently set attributes, and use the persisted
            // attributes for vacant keys.
            attributes.merge_vacant(&nattributes);
        }

        if let (Some(loadable), Some(resolution)) = (loadable, storage.image_resolution())
            && let Some(entry) = loadable
                .entry_point()
                .and_then(|entry| resolution.resolve_address(entry))
        {
            attributes.set_attr(ATTRIBUTE_ENTRY_POINT, entry);
        }

        tracing::trace!("loading project symbols");

        let symbol_cache_bytes = attributes
            .get_attr::<usize>(ATTRIBUTE_SYMBOL_CACHE_SIZE)
            .unwrap_or(DEFAULT_SYMBOL_CACHE_BYTES);

        let mut symbols = storage.table(
            symbol_cache_bytes,
            SymbolTable::with_worker,
            SymbolTable::new_transient,
            "symbol",
        )?;

        if !SymbolTable::persisted(storage.entities())? {
            let Some(loadable) = loadable else {
                tracing::error!("project not standalone and no loadable instance available");
                return Err(StorageProviderError::NotAStandaloneProject.into());
            };

            if let (Some(loadable_symbols), Some(resolution)) =
                (loadable.image_symbols(), storage.image_resolution())
            {
                tracing::trace!(
                    "transfering {} symbols from loadable",
                    loadable_symbols.len()
                );

                let mut resolved = TransientSymbolTable::new();
                for (_, entry) in loadable_symbols.iter() {
                    let Some(address) = resolution.resolve_address(entry.address()) else {
                        continue;
                    };
                    for &index in entry.indices() {
                        resolved.insert(index, address, entry.symbol(), entry.properties());
                    }
                }
                symbols.initialise(resolved)?;
            }
        }

        tracing::trace!("loading project functions");

        let cache_bytes = attributes
            .get_attr::<usize>(ATTRIBUTE_FUNCTION_CACHE_SIZE)
            .unwrap_or(DEFAULT_FUNCTION_CACHE_BYTES);

        let functions = storage.table(
            cache_bytes,
            FunctionTable::with_worker,
            FunctionTable::new_transient,
            "function",
        )?;

        tracing::trace!("loading project code blocks");

        let block_cache_bytes = attributes
            .get_attr::<usize>(ATTRIBUTE_CODE_BLOCK_CACHE_SIZE)
            .unwrap_or(DEFAULT_CODE_BLOCK_CACHE_BYTES);

        let blocks = storage.table(
            block_cache_bytes,
            CodeBlockTable::with_worker,
            CodeBlockTable::new_transient,
            "code block",
        )?;

        let switch_cache_bytes = attributes
            .get_attr::<usize>(ATTRIBUTE_SWITCH_CACHE_SIZE)
            .unwrap_or(DEFAULT_SWITCH_CACHE_BYTES);

        let switches = storage.table(
            switch_cache_bytes,
            SwitchTable::with_worker,
            SwitchTable::new_transient,
            "switch",
        )?;

        let problem_cache_bytes = attributes
            .get_attr::<usize>(ATTRIBUTE_PROBLEM_CACHE_SIZE)
            .unwrap_or(DEFAULT_PROBLEM_CACHE_BYTES);

        let problems = storage.table(
            problem_cache_bytes,
            ProblemTable::with_worker,
            ProblemTable::new_transient,
            "problem",
        )?;

        let coverage = AnalysisCoverage::from_storage(storage.entities())?;

        let revision_record = storage
            .entities()
            .get::<ProjectEntity, ProjectRevisionState>(&ProjectEntity::Revision)?;
        let revisions = revision_record
            .unwrap_or_else(|| ProjectRevisionState::new(Revision::default(), Revision::default()));

        let mut call_graph = match storage.write_back() {
            Some(worker) => CallGraphIndex::new(storage.entities().clone(), Some(worker.clone()))?,
            None => CallGraphIndex::new_transient(),
        };
        call_graph.ensure_current(functions.iter(), &blocks, revisions.revision())?;

        let mut references = match storage.write_back() {
            Some(worker) => ReferenceIndex::new(storage.entities().clone(), Some(worker.clone()))?,
            None => ReferenceIndex::new_transient(),
        };
        references.ensure_current(functions.iter(), &blocks, revisions.revision())?;

        Ok(Self {
            arch,
            language,
            symbols,
            functions,
            blocks,
            call_graph,
            references,
            problems,
            coverage,
            switches,
            platform,
            attributes,
            revisions,
            persistable: true,
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
                Err(e) if e.requires_loadable() => L::from_bytes_with(bytes, attributes.clone())
                    .map_err(ProjectError::from)
                    .and_then(|loader| Self::new_with_provider::<P>(&loader, attributes)),
                Err(e) => Err(ProjectError::from(e)),
            };
        }

        L::from_bytes_with(bytes, attributes.clone())
            .map_err(ProjectError::from)
            .and_then(|loader| Self::new_with_provider::<P>(&loader, attributes))
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

        if !attributes.contains(ATTRIBUTE_INPUT_PATH) {
            attributes.set_attr(ATTRIBUTE_INPUT_PATH, path);
        }

        if !attributes.contains(ATTRIBUTE_PROJECT_PATH) {
            attributes.set_attr(ATTRIBUTE_PROJECT_PATH, path.with_extension("fdbz"));
        }

        let project_path = attributes
            .get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH)
            .expect("valid project path");

        match P::from_storage(project_path, &mut attributes) {
            Ok(storage) => Self::from_storage(None::<&L>, storage, attributes),
            Err(e) if e.requires_loadable() => L::from_file_with(path, attributes.clone())
                .map_err(ProjectError::from)
                .and_then(|loader| Self::new_with_provider::<P>(&loader, attributes)),
            Err(e) => Err(ProjectError::from(e)),
        }
    }

    pub fn arch(&self) -> &Arch {
        &self.arch
    }

    pub fn platform(&self) -> &Platform {
        &self.platform
    }

    pub fn lifter(&self) -> Lifter {
        self.arch.lifter()
    }

    pub fn language(&self) -> &'static Language {
        self.language
    }

    pub fn revision(&self) -> Revision {
        self.revisions.revision()
    }

    pub(crate) fn semantic_revision(&self) -> Revision {
        self.revisions.semantic_revision()
    }

    pub fn symbols(&self) -> &SymbolTable {
        &self.symbols
    }

    pub fn blocks(&self) -> &CodeBlockTable {
        &self.blocks
    }

    pub fn functions(&self) -> &FunctionTable {
        &self.functions
    }

    pub fn call_graph(&self) -> &CallGraphIndex {
        &self.call_graph
    }

    pub fn references(&self) -> &ReferenceIndex {
        &self.references
    }

    pub fn problems(&self) -> &ProblemTable {
        &self.problems
    }

    pub fn coverage(&self) -> &AnalysisCoverage {
        &self.coverage
    }

    pub(crate) fn coverage_mut(&mut self) -> &mut AnalysisCoverage {
        &mut self.coverage
    }

    pub fn switches(&self) -> &SwitchTable {
        &self.switches
    }

    pub fn segments(&self) -> &SegmentStorage {
        self.storage.segments()
    }

    pub fn attributes(&self) -> &AttributeMap {
        &self.attributes
    }

    pub fn attributes_mut(&mut self) -> &mut AttributeMap {
        &mut self.attributes
    }

    pub fn entry_point(&self) -> Option<Address> {
        self.attributes().get_attr::<Address>(ATTRIBUTE_ENTRY_POINT)
    }

    pub fn pcode(&self, function: FunctionId) -> Result<Option<PCodeIr>, ProjectError> {
        self.lifted(function)
    }

    pub fn ecode(&self, function: FunctionId) -> Result<Option<ECodeIr>, ProjectError> {
        self.lifted(function)
    }

    pub fn mcode(&self, function: FunctionId) -> Result<Option<MCodeIr>, ProjectError> {
        self.lifted(function)
    }

    pub(crate) fn lifted<T>(&self, function: FunctionId) -> Result<Option<T>, ProjectError>
    where
        T: PersistableIl,
    {
        T::load_current(&self.storage, function, self.revisions.semantic_revision())
            .map_err(ProjectError::from)
    }

    pub(crate) fn lifted_erased(
        &self,
        registry: &IlRegistry,
        function: FunctionId,
        form: &IlFormId,
    ) -> Result<Option<Box<dyn Any + Send + Sync>>, ProjectError> {
        let Some(load) = registry.form(form).and_then(IlFormRegistration::load) else {
            return Ok(None);
        };

        load(&self.storage, function, self.revisions.semantic_revision())
            .map_err(ProjectError::from)
    }

    pub fn transaction(&mut self, source: impl Into<ChangeSource>) -> ProjectTransaction<'_> {
        ProjectTransaction::new(self, source.into(), IlRegistry::standard().clone())
    }

    pub(crate) fn transaction_with_registry(
        &mut self,
        source: impl Into<ChangeSource>,
        registry: Arc<IlRegistry>,
    ) -> ProjectTransaction<'_> {
        ProjectTransaction::new(self, source.into(), registry)
    }

    fn persist(&mut self) -> Result<(), StorageProviderError> {
        if !self.persistable {
            tracing::warn!("project persistence abandoned; skipping persistence");
            return Ok(());
        }

        if self.storage.entities().is_transient() {
            tracing::debug!("entity storage is transient; skipping persistence");
            return Ok(());
        }

        tracing::debug!("persisting project data");

        tracing::debug!("persisting project architecture and lifter");
        self.storage
            .entities()
            .insert(&ProjectEntity::Architecture, &self.arch)?;

        tracing::debug!("persisting project platform");
        self.storage
            .entities()
            .insert(&ProjectEntity::Platform, &self.platform)?;

        tracing::debug!("persisting project attributes");
        self.storage
            .entities()
            .insert(&ProjectEntity::Attributes, &self.attributes)?;

        tracing::debug!("persisting symbol table");
        self.symbols.persist(self.storage.entities())?;

        tracing::debug!("persisting function table");
        self.functions.persist(self.storage.entities())?;

        tracing::debug!("persisting code block table");
        self.blocks.persist(self.storage.entities())?;

        tracing::debug!("persisting switch table");
        self.switches.persist(self.storage.entities())?;

        tracing::debug!("persisting problem table");
        self.problems.persist(self.storage.entities())?;

        tracing::debug!("persisting analysis coverage");
        self.coverage.persist(self.storage.entities())?;

        if let Some(worker) = self.storage.write_back() {
            tracing::debug!("draining write-back worker");
            worker.flush()?;
        }

        tracing::debug!("persisting call graph marker");
        self.call_graph.mark_current(self.revision())?;

        tracing::debug!("persisting reference index marker");
        self.references.mark_current(self.revision())?;

        tracing::debug!("persisting segment metadata");
        self.storage.segments_mut().persist_storage()?;

        tracing::debug!("persisting project revision");
        self.storage
            .entities()
            .insert(&ProjectEntity::Revision, &self.revisions)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::{IlArtefact, IlError, IlGraph, IlMetadata};
    use crate::il::pcode::PCodeIr;
    use crate::ir::FunctionId;

    #[test]
    fn project_pcode_rejects_stale_input_revision() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let stale_revision = project.semantic_revision();
        {
            let mut transaction = project.transaction("test");
            transaction.create_space()?;
            transaction.commit()?;
        }

        let ir = PCodeIr::new(
            IlMetadata::new(function, stale_revision),
            IlGraph::default(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let mut staging = crate::il::storage::IlStaging::default();
        staging.replace(&project.storage, ir)?;
        let writes = staging.prepare()?;
        project.storage.entities().apply_batch(&writes)?;

        assert!(matches!(
            project.pcode(function),
            Err(ProjectError::Il(IlError::StaleArtefact { ref form, .. })) if *form == PCodeIr::FORM
        ));

        Ok(())
    }
}
