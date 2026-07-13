use std::path::{Path, PathBuf};

use smallvec::SmallVec;
use thiserror::Error;
use tracing::Span;

use crate::analysis::function::recovery::{FunctionRecoveryError, PartialFunction};
use crate::analysis::{AnalysisError, AnalysisGroup};
use crate::arch::Arch;
use crate::engine::change::{ChangeRecord, ChangeSet, FunctionChangeKind, Revision};
use crate::ir::function::table::FunctionTableRevert;
use crate::ir::symbol::SymbolTableRevert;
use crate::ir::{
    Address, AddressRange, CallGraphIndex, CodeBlockTable, FunctionId, FunctionTable, RawAddress,
    Symbol, SymbolEntry, SymbolId, SymbolIndex, SymbolTable,
};
use crate::lifter::{Language, Lifter};
use crate::loader::{Loadable, LoadableFromBytes, LoadableFromFile, Loader, LoaderError};
use crate::platform::Platform;
use crate::storage::entities::schema::ENTITY_PROJECT_REVISION_ID;
use crate::storage::entities::{Entity, EntityId, EntityStorageError, ProjectEntity};
use crate::storage::project::{PersistableProjectEntity, ProjectEntityFromStorage};
use crate::storage::segments::mapping::{
    SegmentMappingBuilder, SegmentMappingFlags, SegmentMappingId, SegmentMappingKind,
    SegmentMappingProvenance,
};
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::segments::{SegmentStorage, SegmentStorageRevert, SegmentWriteRevert};
use crate::storage::{
    ATTRIBUTE_CODE_BLOCK_CACHE_SIZE, ATTRIBUTE_FUNCTION_CACHE_SIZE, DEFAULT_CODE_BLOCK_CACHE_BYTES,
    DEFAULT_FUNCTION_CACHE_BYTES, DefaultProjectStorageProvider, SegmentStorageError,
    StorageContainer, StorageProvider, StorageProviderError, TransientStorageProvider,
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
    pub(crate) call_graph: CallGraphIndex,
    pub(crate) platform: Platform,
    restored_revision: Option<Revision>,
    pub(crate) attributes: AttributeMap,
    pub(crate) revision: Revision,
    transaction_active: bool,
    persistable: bool,
    // NOTE: this must be that last field, so it will be dropped last.
    pub(crate) storage: StorageContainer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct ProjectRevision {
    revision: Revision,
}

impl ProjectRevision {
    fn new(revision: Revision) -> Self {
        Self { revision }
    }

    fn revision(&self) -> Revision {
        self.revision
    }
}

impl Entity for ProjectRevision {
    const ID: EntityId = ENTITY_PROJECT_REVISION_ID;
}

#[allow(unknown_lints, pub_field_in_struct)]
pub struct ProjectRef<'a> {
    pub arch: &'a Arch,
    pub language: &'static Language,
    pub platform: &'a Platform,
    pub symbols: &'a SymbolTable,
    pub functions: &'a FunctionTable,
    pub blocks: &'a CodeBlockTable,
    pub attributes: &'a AttributeMap,
}

#[allow(unknown_lints, pub_field_in_struct)]
pub struct ProjectMut<'a> {
    pub arch: &'a mut Arch,
    pub language: &'static Language,
    pub platform: &'a mut Platform,
    pub symbols: &'a mut SymbolTable,
    pub functions: &'a mut FunctionTable,
    pub blocks: &'a mut CodeBlockTable,
    pub call_graph: &'a mut CallGraphIndex,
    pub attributes: &'a mut AttributeMap,
    pub storage: &'a mut StorageContainer,
}

impl Drop for Project {
    fn drop(&mut self) {
        if !self.persistable {
            return;
        }

        if let Err(e) = self.save() {
            tracing::error!("failed to persist project data: {e}");
        }
    }
}

#[derive(Debug, Error)]
pub enum ProjectError {
    #[error("failed to create entity cache: {0}")]
    EntityStorage(#[from] EntityStorageError),
    #[error(transparent)]
    FunctionRecovery(#[from] FunctionRecoveryError),
    #[error(transparent)]
    Loader(#[from] LoaderError),
    #[error(transparent)]
    SegmentStorage(#[from] SegmentStorageError),
    #[error(transparent)]
    StorageProvider(#[from] StorageProviderError),
}

impl ProjectError {
    pub(crate) fn is_write_back_poisoned(&self) -> bool {
        match self {
            Self::EntityStorage(error) => error.is_write_back_poisoned(),
            Self::StorageProvider(StorageProviderError::EntityStorage(error)) => {
                error.is_write_back_poisoned()
            }
            _ => false,
        }
    }
}

pub struct ProjectTransaction<'p> {
    project: &'p mut Project,
    records: Vec<ChangeRecord>,
    function_reverts: Vec<FunctionTableRevert>,
    symbol_reverts: Vec<SymbolTableRevert>,
    segment_reverts: Vec<SegmentStorageRevert>,
    segment_write_reverts: Vec<SegmentWriteRevert>,
    abandoned: bool,
    committed: bool,
    span: Span,
}

impl Drop for ProjectTransaction<'_> {
    fn drop(&mut self) {
        let span = self.span.clone();
        let _entered = span.enter();
        if !self.abandoned && !std::thread::panicking() {
            debug_assert!(self.committed, "project transaction dropped without commit");
        }
        self.project.transaction_active = false;
    }
}

impl ProjectTransaction<'_> {
    pub fn project(&self) -> &Project {
        self.project
    }

    pub(crate) fn abandon(&mut self) {
        self.abandoned = true;
        self.project.abandon_persistence();
    }

    pub(crate) fn analyse_with<S>(
        &mut self,
        passes: &mut AnalysisGroup<S>,
        state: &mut S,
    ) -> Result<(), AnalysisError>
    where
        S: 'static,
    {
        passes.analyse_with(self.project, state)
    }

    pub fn add_function(&mut self, function: PartialFunction) -> Result<FunctionId, ProjectError> {
        let entry = function.entry();
        let revert = FunctionTableRevert::capture(
            &self.project.functions,
            &self.project.blocks,
            entry,
            function.blocks().len(),
        );
        let old_blocks = self
            .project
            .functions
            .get_by_address(entry)
            .map(|function| {
                function
                    .blocks()
                    .map(|(_, id)| id)
                    .collect::<SmallVec<[_; 8]>>()
            });
        let mut covered = self
            .project
            .blocks
            .coverage(old_blocks.iter().flatten().copied());
        let id = match function.commit(&mut self.project.functions, &mut self.project.blocks) {
            Ok(id) => id,
            Err(error) => {
                revert.restore(
                    &mut self.project.functions,
                    &mut self.project.blocks,
                    &mut self.project.call_graph,
                )?;
                return Err(error.into());
            }
        };
        let targets = self
            .project
            .functions
            .get_by_address(entry)
            .map(|function| {
                self.project
                    .blocks
                    .coverage_into(function.blocks().map(|(_, id)| id), &mut covered);
                CallGraphIndex::function_call_targets(&function, &self.project.blocks)
            })
            .unwrap_or_default();
        self.function_reverts.push(revert);
        self.project.call_graph.set_function_edges(entry, targets)?;

        if let Some(blocks) = old_blocks {
            for block in blocks {
                self.project.blocks.remove_by_id(block);
            }

            self.records.push(ChangeRecord::FunctionChanged {
                entry,
                kind: FunctionChangeKind::Body,
                coverage: covered,
            });
        } else {
            self.records.push(ChangeRecord::FunctionAdded {
                entry,
                coverage: covered,
            });
        }
        Ok(id)
    }

    pub fn remove_function(&mut self, entry: Address) -> Result<bool, ProjectError> {
        let Some(function) = self.project.functions.get_by_address(entry) else {
            return Ok(false);
        };
        let id = function.id();
        drop(function);

        self.remove_function_by_id(id)
    }

    pub fn remove_function_by_id(&mut self, id: FunctionId) -> Result<bool, ProjectError> {
        let Some(function) = self.project.functions.get_by_id(id) else {
            return Ok(false);
        };
        let entry = function.entry();
        let revert =
            FunctionTableRevert::capture(&self.project.functions, &self.project.blocks, entry, 0);
        let blocks = function
            .blocks()
            .map(|(_, id)| id)
            .collect::<SmallVec<[_; 8]>>();

        drop(function);

        let covered = self.project.blocks.coverage(blocks.iter().copied());

        self.function_reverts.push(revert);
        self.project.call_graph.remove_function_edges(entry)?;

        for block in blocks {
            self.project.blocks.remove_by_id(block);
        }

        self.project.functions.remove_by_id(id);
        self.records.push(ChangeRecord::FunctionRemoved {
            entry,
            coverage: covered,
        });

        Ok(true)
    }

    pub fn insert_symbol(&mut self, index: SymbolIndex, entry: SymbolEntry) -> SymbolId {
        let address = entry.address();
        let symbol = entry.symbol();
        let removed = self
            .project
            .symbols
            .get_by_index(index)
            .and_then(|(_, existing)| {
                (*existing != entry && existing.indices().len() == 1)
                    .then(|| (existing.address(), existing.symbol()))
            });
        let mut revert = self.project.symbols.insert_revert(index, &entry);
        let (is_new, id) = self
            .project
            .symbols
            .insert(index, address, symbol, entry.properties());
        revert.touch(id);

        if let Some((address, symbol)) = removed {
            self.record_symbol_removed(address, symbol);
        }

        if is_new {
            self.records
                .push(ChangeRecord::SymbolAdded { address, symbol });
        }

        self.symbol_reverts.push(revert);

        id
    }

    pub fn remove_symbol(&mut self, symbol: impl AsRef<str>) -> usize {
        let symbol = symbol.as_ref();
        let revert = self.project.symbols.remove_symbol_revert(symbol);
        let removed = self
            .project
            .symbols
            .get(symbol)
            .map(|entries| {
                entries
                    .map(|(_, entry)| (entry.address(), entry.symbol()))
                    .collect::<SmallVec<[_; 4]>>()
            })
            .unwrap_or_default();
        let count = self.project.symbols.remove(symbol);
        self.record_symbols_removed(removed);
        if count > 0 {
            self.symbol_reverts.push(revert);
        }
        count
    }

    pub fn remove_symbols_by_address(&mut self, address: Address) -> usize {
        let revert = self.project.symbols.remove_address_revert(address);
        let removed = self
            .project
            .symbols
            .get_by_address(address)
            .map(|(_, entry)| (entry.address(), entry.symbol()))
            .collect::<SmallVec<[_; 4]>>();
        let count = self.project.symbols.remove_by_address(address);
        self.record_symbols_removed(removed);
        if count > 0 {
            self.symbol_reverts.push(revert);
        }
        count
    }

    pub fn remove_symbol_by_id(&mut self, id: SymbolId) -> bool {
        let revert = self.project.symbols.remove_id_revert(id);
        let removed = self
            .project
            .symbols
            .get_by_id(id)
            .map(|entry| (entry.address(), entry.symbol()));

        if !self.project.symbols.remove_by_id(id) {
            return false;
        }

        if let Some((address, symbol)) = removed {
            self.record_symbol_removed(address, symbol);
            self.symbol_reverts.push(revert);
        }

        true
    }

    pub fn remove_symbol_by_index(&mut self, index: SymbolIndex) -> bool {
        let revert = self.project.symbols.remove_index_revert(index);
        let removed = self
            .project
            .symbols
            .get_by_index(index)
            .map(|(_, entry)| (entry.address(), entry.symbol()));

        if !self.project.symbols.remove_by_index(index) {
            return false;
        }

        if let Some((address, symbol)) = removed {
            self.record_symbol_removed(address, symbol);
            self.symbol_reverts.push(revert);
        }

        true
    }

    pub fn create_mapping_from_builder(
        &mut self,
        builder: SegmentMappingBuilder,
    ) -> Result<SegmentMappingId, ProjectError> {
        let mut revert = self.project.storage.segments.empty_revert();
        let mapping = self
            .project
            .storage
            .segments
            .create_mapping_from_builder(builder)?;
        revert.touch_mapping(mapping);
        self.segment_reverts.push(revert);
        self.records
            .push(ChangeRecord::SegmentMappingCreated { mapping });
        Ok(mapping)
    }

    pub fn create_space(&mut self) -> Result<AddressSpaceId, ProjectError> {
        let mut revert = self.project.storage.segments.empty_revert();
        let space = self.project.storage.segments.create_space()?;
        revert.touch_space(space);
        self.segment_reverts.push(revert);
        self.records.push(ChangeRecord::SpaceCreated { space });
        Ok(space)
    }

    pub fn add_mapping_to_space(
        &mut self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        let revert = self
            .project
            .storage
            .segments
            .space_mapping_revert(space, mapping);
        self.project
            .storage
            .segments
            .add_mapping_to_space(space, mapping)?;
        self.segment_reverts.push(revert);
        self.record_mapping_added(space, mapping);

        Ok(())
    }

    pub fn add_mapping_to_space_top(
        &mut self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        let revert = self
            .project
            .storage
            .segments
            .space_mapping_revert(space, mapping);
        self.project
            .storage
            .segments
            .add_mapping_to_space_top(space, mapping)?;
        self.segment_reverts.push(revert);
        self.record_mapping_added(space, mapping);

        Ok(())
    }

    pub fn add_mapping_to_space_bottom(
        &mut self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        let revert = self
            .project
            .storage
            .segments
            .space_mapping_revert(space, mapping);
        self.project
            .storage
            .segments
            .add_mapping_to_space_bottom(space, mapping)?;
        self.segment_reverts.push(revert);
        self.record_mapping_added(space, mapping);

        Ok(())
    }

    pub fn remove_mapping(&mut self, id: SegmentMappingId) -> Result<(), ProjectError> {
        let removed = self
            .project
            .storage
            .segments
            .mapping_placements(id)
            .collect::<SmallVec<[_; 4]>>();

        let revert = self.project.storage.segments.remove_mapping_tracked(id)?;
        self.segment_reverts.push(revert);
        self.record_mapping_removed(id, removed);

        Ok(())
    }

    pub fn remap_mapping(
        &mut self,
        id: SegmentMappingId,
        new_start: impl Into<Address>,
    ) -> Result<(), ProjectError> {
        let new_start = new_start.into();
        let revert = self
            .project
            .storage
            .segments
            .mapping_remap_revert(id, new_start);
        let removed = self
            .project
            .storage
            .segments
            .mapping_placements(id)
            .collect::<SmallVec<[_; 4]>>();

        self.project.storage.segments.remap_mapping(id, new_start)?;
        self.segment_reverts.push(revert);
        self.record_mapping_removed(id, removed);
        self.record_mapping_added_to_placements(id);

        Ok(())
    }

    pub fn resize_mapping(
        &mut self,
        id: SegmentMappingId,
        new_size: u64,
    ) -> Result<(), ProjectError> {
        let revert = self
            .project
            .storage
            .segments
            .mapping_resize_revert(id, new_size);
        let removed = self
            .project
            .storage
            .segments
            .mapping_placements(id)
            .collect::<SmallVec<[_; 4]>>();

        self.project.storage.segments.resize_mapping(id, new_size)?;
        self.segment_reverts.push(revert);
        self.record_mapping_removed(id, removed);
        self.record_mapping_added_to_placements(id);

        Ok(())
    }

    pub fn update_mapping_metadata(
        &mut self,
        id: SegmentMappingId,
        kind: SegmentMappingKind,
        provenance: SegmentMappingProvenance,
        flags: SegmentMappingFlags,
    ) -> Result<(), ProjectError> {
        let revert = self.project.storage.segments.mapping_metadata_revert(id);
        self.project
            .storage
            .segments
            .update_mapping_metadata(id, kind, provenance, flags)?;
        self.segment_reverts.push(revert);
        self.records
            .push(ChangeRecord::SegmentMappingChanged { mapping: id });

        Ok(())
    }

    pub fn prioritise_mapping(
        &mut self,
        space: AddressSpaceId,
        id: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        let revert = self
            .project
            .storage
            .segments
            .space_mapping_revert(space, id);
        self.project
            .storage
            .segments
            .prioritise_mapping(space, id)?;
        self.segment_reverts.push(revert);
        self.record_mapping_added(space, id);

        Ok(())
    }

    pub fn deprioritise_mapping(
        &mut self,
        space: AddressSpaceId,
        id: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        let revert = self
            .project
            .storage
            .segments
            .space_mapping_revert(space, id);
        self.project
            .storage
            .segments
            .deprioritise_mapping(space, id)?;
        self.segment_reverts.push(revert);
        self.record_mapping_added(space, id);

        Ok(())
    }

    pub fn write_bytes(&mut self, addr: Address, bytes: &[u8]) -> Result<(), ProjectError> {
        let (written, revert) = self.project.storage.segments.write_bytes_to_space_tracked(
            addr.space(),
            addr,
            bytes,
        )?;

        if written == bytes.len() {
            if let Some(range) = Self::bytes_range(addr.space(), addr.raw_address(), written as u64)
            {
                self.records.push(ChangeRecord::BytesWritten { range });
            }
            self.segment_write_reverts.push(revert);
            Ok(())
        } else {
            revert.restore(&mut self.project.storage.segments)?;
            Err(SegmentStorageError::InvalidAddressRange.into())
        }
    }

    pub fn write_bytes_to_space(
        &mut self,
        space: AddressSpaceId,
        addr: impl Into<RawAddress>,
        bytes: &[u8],
    ) -> Result<(), ProjectError> {
        let addr = Address::new(space, addr.into());
        self.write_bytes(addr, bytes)
    }

    fn mapping_range(space: AddressSpaceId, start: Address, size: u64) -> AddressRange {
        Self::bytes_range(space, start.raw_address(), size)
            .unwrap_or_else(|| AddressRange::new(space, start.raw_address(), start.raw_address()))
    }

    fn bytes_range(space: AddressSpaceId, start: RawAddress, len: u64) -> Option<AddressRange> {
        let end = len
            .checked_sub(1)
            .and_then(|last| start.checked_add(last))?;

        Some(AddressRange::new(space, start, end))
    }

    fn record_mapping_added(&mut self, space: AddressSpaceId, id: SegmentMappingId) {
        if let Some(mapping) = self.project.storage.segments.mapping(id) {
            self.records.push(ChangeRecord::SegmentMapped {
                mapping: id,
                range: Self::mapping_range(space, mapping.start(), mapping.size()),
            });
        }
    }

    fn record_mapping_added_to_placements(&mut self, id: SegmentMappingId) {
        let added = self
            .project
            .storage
            .segments
            .mapping_placements(id)
            .collect::<SmallVec<[_; 4]>>();

        for (space, range) in added {
            self.records.push(ChangeRecord::SegmentMapped {
                mapping: id,
                range: AddressRange::new(space, range.0, range.1),
            });
        }
    }

    fn record_mapping_removed(
        &mut self,
        id: SegmentMappingId,
        removed: impl IntoIterator<Item = (AddressSpaceId, (RawAddress, RawAddress))>,
    ) {
        for (space, range) in removed {
            self.records.push(ChangeRecord::SegmentUnmapped {
                mapping: id,
                range: AddressRange::new(space, range.0, range.1),
            });
        }
    }

    fn record_symbols_removed(&mut self, removed: impl IntoIterator<Item = (Address, Symbol)>) {
        for (address, symbol) in removed {
            self.record_symbol_removed(address, symbol);
        }
    }

    fn record_symbol_removed(&mut self, address: Address, symbol: Symbol) {
        self.records
            .push(ChangeRecord::SymbolRemoved { address, symbol });
    }

    pub fn commit(mut self) -> Result<ChangeSet, ProjectError> {
        let span = self.span.clone();
        let _entered = span.enter();
        if !self.records.is_empty() {
            let revision = self.project.revision.next();
            self.project.revision = revision;
        }
        self.committed = true;
        Ok(ChangeSet::with_records(
            self.project.revision,
            std::mem::take(&mut self.records),
        ))
    }

    pub fn rollback(mut self) -> Result<(), ProjectError> {
        let _entered = self.span.enter();
        self.committed = true;
        while let Some(revert) = self.function_reverts.pop() {
            revert.restore(
                &mut self.project.functions,
                &mut self.project.blocks,
                &mut self.project.call_graph,
            )?;
        }
        while let Some(revert) = self.symbol_reverts.pop() {
            revert.restore(&mut self.project.symbols);
        }
        while let Some(revert) = self.segment_write_reverts.pop() {
            revert.restore(&mut self.project.storage.segments)?;
        }
        while let Some(revert) = self.segment_reverts.pop() {
            revert.restore(&mut self.project.storage.segments);
        }
        self.records.clear();
        Ok(())
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
        let platform = loadable
            .map(Loadable::platform)
            .unwrap_or_else(|| arch.platform());

        tracing::trace!("loading project attributes");

        if let Some(nattributes) = storage.entities.get(&ProjectEntity::Attributes)? {
            // NOTE: we prefer the most recently set attributes, and use the persisted
            // attributes for vacant keys.
            attributes.merge_vacant(&nattributes);
        }

        if let (Some(loadable), Some(resolution)) = (loadable, storage.image_resolution.as_ref())
            && let Some(entry) = loadable
                .entry_point()
                .and_then(|entry| resolution.resolve_address(entry))
        {
            attributes.set_attr(ATTRIBUTE_ENTRY_POINT, entry);
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

                if let (Some(loadable_symbols), Some(resolution)) =
                    (loadable.image_symbols(), storage.image_resolution.as_ref())
                {
                    tracing::trace!(
                        "transfering {} symbols from loadable",
                        loadable_symbols.len()
                    );

                    for (index, _, entry) in loadable_symbols.iter_by_index() {
                        if let Some(address) = resolution.resolve_address(entry.address()) {
                            symbols.insert(index, address, entry.symbol(), entry.properties());
                        }
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
            match storage.write_back() {
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
            match storage.write_back() {
                Some(worker) => CodeBlockTable::new_with(
                    storage.entities.clone(),
                    worker.clone(),
                    block_cache_bytes,
                ),
                None => CodeBlockTable::new(storage.entities.clone(), block_cache_bytes),
            }
            .inspect_err(|e| tracing::error!("failed to load code block table: {e}"))?
        };

        let revision = storage
            .entities
            .get::<ProjectEntity, ProjectRevision>(&ProjectEntity::Revision)?
            .map(|revision| revision.revision())
            .unwrap_or_default();
        let restored_revision = (revision != Revision::default()).then_some(revision);

        let call_graph = match storage.write_back() {
            Some(worker) => CallGraphIndex::new_with(storage.entities.clone(), worker.clone()),
            None => CallGraphIndex::new(storage.entities.clone())?,
        };
        call_graph.ensure_current(functions.iter(), &blocks, revision.value())?;

        Ok(Self {
            arch,
            language,
            symbols,
            functions,
            blocks,
            call_graph,
            platform,
            restored_revision,
            attributes,
            revision,
            transaction_active: false,
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

    pub fn entry(&self) -> Option<Address> {
        self.attributes().get_attr::<Address>(ATTRIBUTE_ENTRY_POINT)
    }

    pub fn revision(&self) -> Revision {
        self.revision
    }

    pub fn restored_revision(&self) -> Option<Revision> {
        self.restored_revision
    }

    pub(crate) fn abandon_persistence(&mut self) {
        self.persistable = false;
    }

    pub fn transaction(&mut self, reason: impl AsRef<str>) -> ProjectTransaction<'_> {
        let span = tracing::debug_span!("project_transaction", reason = reason.as_ref());
        assert!(
            !self.transaction_active,
            "project transaction already active"
        );
        self.transaction_active = true;
        ProjectTransaction {
            project: self,
            records: Vec::new(),
            function_reverts: Vec::new(),
            symbol_reverts: Vec::new(),
            segment_reverts: Vec::new(),
            segment_write_reverts: Vec::new(),
            abandoned: false,
            committed: false,
            span,
        }
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

    pub fn call_graph(&self) -> &CallGraphIndex {
        &self.call_graph
    }

    pub fn functions_mut(&mut self) -> &mut FunctionTable {
        &mut self.functions
    }

    pub(crate) fn storage(&self) -> &StorageContainer {
        &self.storage
    }

    pub fn storage_mut(&mut self) -> &mut StorageContainer {
        &mut self.storage
    }

    pub fn segments(&self) -> &SegmentStorage {
        &self.storage.segments
    }

    pub fn segments_mut(&mut self) -> &mut SegmentStorage {
        &mut self.storage.segments
    }

    pub fn attributes(&self) -> &AttributeMap {
        &self.attributes
    }

    pub fn attributes_mut(&mut self) -> &mut AttributeMap {
        &mut self.attributes
    }

    pub fn fields(&self) -> ProjectRef<'_> {
        ProjectRef {
            arch: &self.arch,
            language: self.language,
            platform: &self.platform,
            symbols: &self.symbols,
            functions: &self.functions,
            blocks: &self.blocks,
            attributes: &self.attributes,
        }
    }

    pub fn fields_mut(&mut self) -> ProjectMut<'_> {
        ProjectMut {
            arch: &mut self.arch,
            language: self.language,
            platform: &mut self.platform,
            symbols: &mut self.symbols,
            functions: &mut self.functions,
            blocks: &mut self.blocks,
            call_graph: &mut self.call_graph,
            attributes: &mut self.attributes,
            storage: &mut self.storage,
        }
    }

    pub fn save(&mut self) -> Result<(), ProjectError> {
        self.persist().map_err(ProjectError::from)
    }

    pub(crate) fn persist(&self) -> Result<(), StorageProviderError> {
        if !self.persistable {
            tracing::warn!("project persistence abandoned; skipping persistence");
            return Ok(());
        }

        if self.storage.entities.is_transient() {
            tracing::debug!("entity storage is transient; skipping persistence");
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

        if let Some(worker) = self.storage.write_back() {
            tracing::debug!("draining write-back worker");
            worker.flush()?;
        }

        tracing::debug!("persisting call graph marker");
        self.call_graph.mark_current(self.revision.value())?;

        tracing::debug!("persisting project revision");
        self.storage.entities.insert(
            &ProjectEntity::Revision,
            &ProjectRevision::new(self.revision),
        )?;

        Ok(())
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
    #[ignore = "requires local language data and binary fixtures"]
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

            Ok(())
        })
    }
}
