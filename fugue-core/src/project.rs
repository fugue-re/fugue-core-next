use std::path::{Path, PathBuf};

use smallvec::SmallVec;
use thiserror::Error;
use tracing::Span;

use crate::analysis::control::{CancellationToken, Cancelled};
use crate::analysis::{AnalysisError, AnalysisGroup};
use crate::arch::Arch;
use crate::engine::change::{ChangeRecord, ChangeSet, ChangeSource, FunctionChangeKind, Revision};
use crate::il::common::{IlArtefact, IlError, IlLevel};
use crate::il::ecode::ssa::{ECodeSsaIr, ECodeToSsa};
use crate::il::ecode::{ECodeIr, PCodeToECode};
use crate::il::pcode::{PCodeCanonicaliser, PCodeError, PCodeIr};
use crate::il::storage::{IlPersist, IlRevert, IlStorageError};
use crate::ir::function::FunctionTableRevert;
use crate::ir::reference::ReferenceRevert;
use crate::ir::switch::SwitchTableRevert;
use crate::ir::symbol::SymbolTableRevert;
use crate::ir::{
    Address, AddressRange, AddressRangeSet, CallGraphIndex, CodeBlockTable, FunctionId,
    FunctionTable, IncompleteFunction, IncompleteFunctionError, RawAddress, Reference,
    ReferenceIndex, ReferenceKind, ReferenceOrigin, ReferenceTarget, Switch, SwitchId, SwitchTable,
    SwitchTableError, Symbol, SymbolEntry, SymbolId, SymbolIndex, SymbolTable,
};
use crate::lifter::{Language, Lifter, LifterError};
use crate::loader::{Loadable, LoadableFromBytes, LoadableFromFile, Loader, LoaderError};
use crate::platform::Platform;
use crate::storage::entities::schema::ENTITY_PROJECT_REVISION_ID;
use crate::storage::entities::{Entity, EntityId, EntityStorageError, ProjectEntity};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::segments::mapping::{
    SegmentMappingBuilder, SegmentMappingFlags, SegmentMappingId, SegmentMappingKind,
    SegmentMappingProvenance,
};
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::segments::{SegmentStorage, SegmentStorageRevert, SegmentWriteRevert};
use crate::storage::{
    ATTRIBUTE_CODE_BLOCK_CACHE_SIZE, ATTRIBUTE_FUNCTION_CACHE_SIZE, ATTRIBUTE_SWITCH_CACHE_SIZE,
    ATTRIBUTE_SYMBOL_CACHE_SIZE, DEFAULT_CODE_BLOCK_CACHE_BYTES, DEFAULT_FUNCTION_CACHE_BYTES,
    DEFAULT_SWITCH_CACHE_BYTES, DEFAULT_SYMBOL_CACHE_BYTES, DefaultProjectStorageProvider,
    SegmentStorageError, StorageContainer, StorageProvider, StorageProviderError,
    TransientStorageProvider,
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
    pub(crate) references: ReferenceIndex,
    pub(crate) switches: SwitchTable,
    pub(crate) platform: Platform,
    restored_revision: Option<Revision>,
    pub(crate) attributes: AttributeMap,
    pub(crate) revision: Revision,
    semantic_revision: Revision,
    transaction_active: bool,
    persistable: bool,
    canonicaliser: PCodeCanonicaliser,
    ecode_to_ssa: ECodeToSsa,
    pcode_to_ecode: PCodeToECode,
    // NOTE: this must be that last field, so it will be dropped last.
    pub(crate) storage: StorageContainer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct ProjectRevision {
    revision: Revision,
    semantic_revision: Revision,
}

impl ProjectRevision {
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
    SegmentStorage(#[from] SegmentStorageError),
    #[error(transparent)]
    StorageProvider(#[from] StorageProviderError),
    #[error(transparent)]
    Switch(#[from] SwitchTableError),
}

impl From<Cancelled> for ProjectError {
    fn from(cancelled: Cancelled) -> Self {
        Self::Il(IlError::from(cancelled))
    }
}

impl From<IlStorageError> for ProjectError {
    fn from(error: IlStorageError) -> Self {
        match error {
            IlStorageError::Il(error) => Self::Il(error),
            IlStorageError::Storage(error) => Self::EntityStorage(error),
        }
    }
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
    ir_reverts: Vec<IlRevert>,
    function_reverts: Vec<FunctionTableRevert>,
    symbol_reverts: Vec<SymbolTableRevert>,
    segment_reverts: Vec<SegmentStorageRevert>,
    segment_write_reverts: Vec<SegmentWriteRevert>,
    reference_reverts: Vec<ReferenceRevert>,
    switch_reverts: Vec<SwitchTableRevert>,
    source: ChangeSource,
    committed: bool,
    span: Span,
}

impl Drop for ProjectTransaction<'_> {
    fn drop(&mut self) {
        let span = self.span.clone();
        let _entered = span.enter();
        if !std::thread::panicking() {
            debug_assert!(self.committed, "project transaction dropped without commit");
        }
        self.project.transaction_active = false;
    }
}

impl ProjectTransaction<'_> {
    pub fn project(&self) -> &Project {
        self.project
    }

    pub(crate) fn materialise_lifted<T>(&mut self, ir: &mut T) -> Result<(), ProjectError>
    where
        T: IlArtefact,
        IlRevert: From<(FunctionId, Option<T>)>,
    {
        if self.records.iter().any(ChangeRecord::affects_lifted_inputs) {
            return Err(IlError::publish_after_semantic_mutation().into());
        }

        ir.metadata_mut()
            .set_input_revision(self.project.semantic_revision);

        let revert = ir.persist(&self.project.storage.entities)?;
        self.ir_reverts.push(revert);
        self.records.push(ChangeRecord::LiftedMaterialised {
            function: ir.metadata().function(),
            level: T::LEVEL,
        });

        Ok(())
    }

    pub fn flush_derived_references(&mut self, function: FunctionId) -> Result<bool, ProjectError> {
        let Some(body) = self.current_lifted::<PCodeIr>(function)? else {
            return Ok(false);
        };

        let Some((revert, coverage)) = self.replace_ir_derived_references(&body)? else {
            return Ok(false);
        };

        self.reference_reverts.push(revert);
        self.records
            .push(ChangeRecord::ReferencesChanged { coverage });

        Ok(true)
    }

    fn replace_ir_derived_references(
        &mut self,
        artefact: &PCodeIr,
    ) -> Result<Option<(ReferenceRevert, AddressRangeSet)>, ProjectError> {
        let mut coverage = AddressRangeSet::new();
        let derived = artefact.data_references().collect::<Vec<_>>();

        artefact.reference_coverage_into(&mut coverage);

        let function = artefact.metadata().function();
        if function != FunctionId::INVALID
            && let Some(function) = self.project.functions.get_by_id(function)
        {
            let blocks = function
                .blocks()
                .map(|(_, id)| id)
                .collect::<SmallVec<[_; 8]>>();
            self.project.blocks.coverage_into(blocks, &mut coverage);
        }

        for reference in &derived {
            coverage.insert_range(AddressRange::point(reference.from()));
        }

        if coverage.is_empty() {
            return Ok(None);
        }

        let revert = ReferenceRevert::capture(&self.project.references, &coverage)?;

        if ReferenceIndex::derived_kind_matches(revert.previous(), &derived, ReferenceKind::Data) {
            return Ok(None);
        }

        if let Err(error) = self.project.references.replace_derived_of_kind(
            revert.previous(),
            derived,
            ReferenceKind::Data,
        ) {
            revert.restore(&self.project.references)?;
            return Err(error.into());
        }

        Ok(Some((revert, coverage)))
    }

    pub fn remove_lifted(
        &mut self,
        function: FunctionId,
        level: IlLevel,
    ) -> Result<bool, ProjectError> {
        let removed = match level {
            IlLevel::PCode => {
                let Some(revert) = PCodeIr::remove(&self.project.storage.entities, function)?
                else {
                    return Ok(false);
                };

                let previous = revert
                    .previous_pcode()
                    .expect("PCode removal revert contains the previous PCode artefact");
                self.remove_references_derived_from(previous)?;
                self.ir_reverts.push(revert);
                true
            }
            IlLevel::ECode => {
                let Some(revert) = ECodeIr::remove(&self.project.storage.entities, function)?
                else {
                    return Ok(false);
                };

                self.ir_reverts.push(revert);
                true
            }
            IlLevel::ECodeSsa => {
                let Some(revert) = ECodeSsaIr::remove(&self.project.storage.entities, function)?
                else {
                    return Ok(false);
                };

                self.ir_reverts.push(revert);
                true
            }
        };

        self.records
            .push(ChangeRecord::LiftedRemoved { function, level });

        Ok(removed)
    }

    fn remove_references_derived_from(&mut self, previous: &PCodeIr) -> Result<(), ProjectError> {
        let mut coverage = AddressRangeSet::new();
        for run in previous.source_spans() {
            coverage.insert_range(AddressRange::point(run.address()));
        }

        if coverage.is_empty() {
            return Ok(());
        }

        let revert = ReferenceRevert::capture(&self.project.references, &coverage)?;
        let touched = revert
            .previous()
            .iter()
            .any(|reference| reference.origin().is_derived() && reference.is_data());

        if !touched {
            return Ok(());
        }

        self.project.references.replace_derived_of_kind(
            revert.previous(),
            [],
            ReferenceKind::Data,
        )?;
        self.reference_reverts.push(revert);
        self.records
            .push(ChangeRecord::ReferencesChanged { coverage });

        Ok(())
    }

    pub fn remove_lifted_from(
        &mut self,
        function: FunctionId,
        first_invalid: IlLevel,
    ) -> Result<usize, ProjectError> {
        let mut removed = 0usize;

        for level in first_invalid.descendants_from() {
            if self.remove_lifted(function, level)? {
                removed += 1;
            }
        }

        Ok(removed)
    }

    pub fn remove_lifted_in_range(
        &mut self,
        range: &AddressRange,
        first_invalid: IlLevel,
    ) -> Result<usize, ProjectError> {
        let functions = self
            .project
            .functions
            .overlaps(&self.project.blocks, range)
            .collect::<SmallVec<[_; 8]>>();
        let mut removed = 0usize;

        for function in functions {
            removed += self.remove_lifted_from(function, first_invalid)?;
        }

        Ok(removed)
    }

    pub fn ensure_lifted(
        &mut self,
        function: FunctionId,
        level: IlLevel,
        cancellation: &CancellationToken,
    ) -> Result<bool, ProjectError> {
        cancellation.check()?;

        match level {
            IlLevel::PCode => self.ensure_pcode(function, cancellation),
            IlLevel::ECode => self.ensure_ecode(function, cancellation),
            IlLevel::ECodeSsa => self.ensure_ecode_ssa(function, cancellation),
        }
    }

    pub fn ensure_pcode(
        &mut self,
        function: FunctionId,
        cancellation: &CancellationToken,
    ) -> Result<bool, ProjectError> {
        cancellation.check()?;

        self.ensure_pcode_ir(function, cancellation)
            .map(|(materialised, _)| materialised)
    }

    fn ensure_pcode_ir(
        &mut self,
        function: FunctionId,
        cancellation: &CancellationToken,
    ) -> Result<(bool, PCodeIr), ProjectError> {
        if let Some(ir) = self.current_lifted::<PCodeIr>(function)? {
            return Ok((false, ir));
        }

        if function.is_invalid() {
            return Err(IlError::missing_artefact(function, IlLevel::PCode).into());
        }

        let mut ir = self.project.canonicaliser.build_function(
            self.project.language,
            &self.project.functions,
            &self.project.blocks,
            &self.project.storage.segments,
            function,
            self.project.semantic_revision,
            cancellation,
        )?;

        if cfg!(debug_assertions)
            && let Err(error) = ir.verify()
        {
            panic!("canonicalised pcode for {function:?} fails verification: {error}");
        }

        self.materialise_lifted(&mut ir)?;
        Ok((true, ir))
    }

    pub fn ensure_ecode(
        &mut self,
        function: FunctionId,
        cancellation: &CancellationToken,
    ) -> Result<bool, ProjectError> {
        cancellation.check()?;

        self.ensure_ecode_ir(function, cancellation)
            .map(|(materialised, _)| materialised)
    }

    fn ensure_ecode_ir(
        &mut self,
        function: FunctionId,
        cancellation: &CancellationToken,
    ) -> Result<(bool, ECodeIr), ProjectError> {
        if let Some(ir) = self.current_lifted::<ECodeIr>(function)? {
            return Ok((false, ir));
        }

        let (_, source) = self.ensure_pcode_ir(function, cancellation)?;
        let mut ir =
            self.project
                .pcode_to_ecode
                .transform(&source, &self.project.arch, cancellation)?;

        if cfg!(debug_assertions) {
            ir.verify().expect("transformed ecode fails verification");
        }

        self.materialise_lifted(&mut ir)?;

        Ok((true, ir))
    }

    pub fn ensure_ecode_ssa(
        &mut self,
        function: FunctionId,
        cancellation: &CancellationToken,
    ) -> Result<bool, ProjectError> {
        if self.current_lifted::<ECodeSsaIr>(function)?.is_some() {
            return self.ensure_ecode(function, cancellation);
        }

        let (_, source) = self.ensure_ecode_ir(function, cancellation)?;
        let mut ir = self
            .project
            .ecode_to_ssa
            .transform_optimised(&source, cancellation)?;

        self.materialise_lifted(&mut ir)?;

        Ok(true)
    }

    fn current_lifted<T>(&self, function: FunctionId) -> Result<Option<T>, ProjectError>
    where
        T: IlArtefact,
    {
        match T::load_current(
            &self.project.storage.entities,
            function,
            self.project.semantic_revision,
        ) {
            Ok(ir) => Ok(ir),
            Err(IlStorageError::Il(
                IlError::StaleArtefact { .. } | IlError::SchemaMismatch { .. },
            )) => Ok(None),
            Err(error) => Err(error.into()),
        }
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

    pub fn add_function(
        &mut self,
        function: IncompleteFunction,
    ) -> Result<FunctionId, ProjectError> {
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
                self.restore_function(revert)?;
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
        self.remove_lifted_from(id, IlLevel::PCode)?;

        let derived = self
            .project
            .functions
            .get_by_address(entry)
            .map(|function| function.flow_references(&self.project.blocks))
            .unwrap_or_default();
        let reference_revert = ReferenceRevert::capture(&self.project.references, &covered)?;
        let references_touched = !derived.is_empty() || reference_revert.had_derived();
        self.project.references.replace_derived_of_kind(
            reference_revert.previous(),
            derived,
            ReferenceKind::Flow,
        )?;
        self.reference_reverts.push(reference_revert);

        let reference_coverage = references_touched.then(|| covered.clone());

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

        if let Some(coverage) = reference_coverage {
            self.records
                .push(ChangeRecord::ReferencesChanged { coverage });
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

        let reference_revert = ReferenceRevert::capture(&self.project.references, &covered)?;
        let references_touched = reference_revert
            .previous()
            .iter()
            .any(|reference| reference.origin().is_derived() && reference.is_flow());
        self.project.references.replace_derived_of_kind(
            reference_revert.previous(),
            [],
            ReferenceKind::Flow,
        )?;
        self.reference_reverts.push(reference_revert);

        self.remove_switches_of_function(id)?;

        let reference_coverage = references_touched.then(|| covered.clone());

        for block in blocks {
            self.project.blocks.remove_by_id(block);
        }

        self.project.functions.remove_by_id(id);
        self.remove_lifted_from(id, IlLevel::PCode)?;
        self.records.push(ChangeRecord::FunctionRemoved {
            entry,
            coverage: covered,
        });

        if let Some(coverage) = reference_coverage {
            self.records
                .push(ChangeRecord::ReferencesChanged { coverage });
        }

        Ok(true)
    }

    pub fn add_reference(&mut self, reference: Reference) -> Result<bool, ProjectError> {
        let reference = reference.with_origin(ReferenceOrigin::Asserted);
        let from = reference.from();
        let target = reference.target();

        let existing = self.project.references.get(from, target)?;
        let resolved = match existing {
            Some(existing)
                if existing.origin().is_asserted() && existing.kind() == reference.kind() =>
            {
                existing.with_merged_properties(reference.properties())
            }
            _ => reference,
        };

        if let Some(existing) = existing
            && existing.origin().is_asserted()
            && existing.kind() == resolved.kind()
            && existing.properties() == resolved.properties()
        {
            return Ok(false);
        }

        let revert = ReferenceRevert::edge(from, target, existing);
        self.project.references.insert(&resolved)?;
        self.reference_reverts.push(revert);

        self.records.push(ChangeRecord::ReferenceAdded {
            from,
            target,
            kind: resolved.kind(),
        });
        Ok(true)
    }

    pub fn add_switch<F>(&mut self, branch: Address, f: F) -> Result<SwitchId, ProjectError>
    where
        F: FnOnce(SwitchId, Address) -> Switch,
    {
        let function = self
            .project
            .functions
            .function_containing(&self.project.blocks, branch);
        let revert = SwitchTableRevert::capture(&self.project.switches, branch)?;
        let id = self.project.switches.insert(branch, move |id, branch| {
            let switch = f(id, branch);
            Ok(match function {
                Some(function) => switch.with_function(function),
                None => switch,
            })
        })?;
        self.switch_reverts.push(revert);
        self.records.push(ChangeRecord::SwitchAdded { branch });
        self.refresh_switch_references(branch)?;
        Ok(id)
    }

    pub fn modify_switch<R>(
        &mut self,
        branch: Address,
        f: impl FnOnce(&mut Switch) -> R,
    ) -> Result<Option<R>, ProjectError> {
        let function = self
            .project
            .functions
            .function_containing(&self.project.blocks, branch);
        let revert = SwitchTableRevert::capture(&self.project.switches, branch)?;
        let Some(result) = self
            .project
            .switches
            .try_modify_by_branch(branch, |switch| {
                let result = f(switch);
                if let Some(function) = function {
                    switch.set_function(function);
                }
                result
            })?
        else {
            return Ok(None);
        };
        self.switch_reverts.push(revert);
        self.records.push(ChangeRecord::SwitchAdded { branch });
        self.refresh_switch_references(branch)?;
        Ok(Some(result))
    }

    pub fn remove_switch(&mut self, branch: Address) -> Result<bool, ProjectError> {
        let revert = SwitchTableRevert::capture(&self.project.switches, branch)?;
        let removed = self.project.switches.try_remove_by_branch(branch)?;
        if removed {
            self.switch_reverts.push(revert);
            self.replace_switch_references(branch, [])?;
            self.records.push(ChangeRecord::SwitchRemoved { branch });
        }
        Ok(removed)
    }

    fn remove_switches_of_function(&mut self, function: FunctionId) -> Result<(), ProjectError> {
        let branches = self
            .project
            .switches
            .branches_of_function(function)
            .collect::<Vec<_>>();

        for branch in branches {
            self.remove_switch(branch)?;
        }

        Ok(())
    }

    fn refresh_switch_references(&mut self, branch: Address) -> Result<bool, ProjectError> {
        let references = self
            .project
            .switches
            .get_by_branch(branch)
            .map(|switch| switch.derived_references().collect::<Vec<_>>())
            .unwrap_or_default();
        self.replace_switch_references(branch, references)
    }

    fn replace_switch_references(
        &mut self,
        branch: Address,
        references: impl IntoIterator<Item = Reference>,
    ) -> Result<bool, ProjectError> {
        let mut coverage = AddressRangeSet::new();
        coverage.insert_range(AddressRange::point(branch));

        let revert = ReferenceRevert::capture(&self.project.references, &coverage)?;
        let (flow, data) = references
            .into_iter()
            .partition::<Vec<_>, _>(Reference::is_flow);

        let flow_matches =
            ReferenceIndex::derived_kind_matches(revert.previous(), &flow, ReferenceKind::Flow);
        let data_matches =
            ReferenceIndex::derived_kind_matches(revert.previous(), &data, ReferenceKind::Data);
        if flow_matches && data_matches {
            return Ok(false);
        }

        let result = (|| {
            if !flow_matches {
                self.project.references.replace_derived_of_kind(
                    revert.previous(),
                    flow,
                    ReferenceKind::Flow,
                )?;
            }
            if !data_matches {
                self.project.references.replace_derived_of_kind(
                    revert.previous(),
                    data,
                    ReferenceKind::Data,
                )?;
            }
            Ok::<_, ProjectError>(())
        })();
        if let Err(error) = result {
            revert.restore(&self.project.references)?;
            return Err(error);
        }

        self.reference_reverts.push(revert);
        self.records
            .push(ChangeRecord::ReferencesChanged { coverage });
        Ok(true)
    }

    pub fn remove_reference(
        &mut self,
        from: Address,
        target: ReferenceTarget,
    ) -> Result<bool, ProjectError> {
        let Some(existing) = self.project.references.get(from, target)? else {
            return Ok(false);
        };

        let revert = ReferenceRevert::edge(from, target, Some(existing));
        self.project.references.remove(from, target)?;
        self.reference_reverts.push(revert);

        self.records.push(ChangeRecord::ReferenceRemoved {
            from,
            target,
            kind: existing.kind(),
        });
        Ok(true)
    }

    pub fn add_symbol(
        &mut self,
        index: SymbolIndex,
        entry: SymbolEntry,
    ) -> Result<SymbolId, ProjectError> {
        let address = entry.address();
        let symbol = entry.symbol();
        let removed = self
            .project
            .symbols
            .try_get_by_index(index)?
            .and_then(|(_, existing)| {
                (*existing != entry && existing.indices().len() == 1)
                    .then(|| (existing.address(), existing.symbol()))
            });
        let revert = self.project.symbols.insert_revert(index, &entry)?;
        self.symbol_reverts.push(revert);
        let insertion = self
            .project
            .symbols
            .insert(index, address, symbol, entry.properties())?;
        self.symbol_reverts
            .last_mut()
            .expect("symbol revert was just added")
            .touch(insertion.id());

        if let Some((address, symbol)) = removed {
            self.record_symbol_removed(address, symbol);
        }

        if insertion.is_new() {
            self.records
                .push(ChangeRecord::SymbolAdded { address, symbol });
        }

        Ok(insertion.id())
    }

    pub fn remove_symbol(&mut self, symbol: impl AsRef<str>) -> Result<usize, ProjectError> {
        let symbol = symbol.as_ref();
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
        if removed.is_empty() {
            return Ok(0);
        }

        let revert = self.project.symbols.remove_symbol_revert(symbol)?;
        self.symbol_reverts.push(revert);
        let count = self.project.symbols.try_remove(symbol)?;
        self.record_symbols_removed(removed);
        Ok(count)
    }

    pub fn remove_symbols_by_address(&mut self, address: Address) -> Result<usize, ProjectError> {
        let removed = self
            .project
            .symbols
            .get_by_address(address)
            .map(|(_, entry)| (entry.address(), entry.symbol()))
            .collect::<SmallVec<[_; 4]>>();
        if removed.is_empty() {
            return Ok(0);
        }

        let revert = self.project.symbols.remove_address_revert(address)?;
        self.symbol_reverts.push(revert);
        let count = self.project.symbols.try_remove_by_address(address)?;
        self.record_symbols_removed(removed);
        Ok(count)
    }

    pub fn remove_symbol_by_id(&mut self, id: SymbolId) -> Result<bool, ProjectError> {
        let removed = self
            .project
            .symbols
            .try_get_by_id(id)?
            .map(|entry| (entry.address(), entry.symbol()));

        let Some((address, symbol)) = removed else {
            return Ok(false);
        };

        let revert = self.project.symbols.remove_id_revert(id)?;
        self.symbol_reverts.push(revert);
        self.project.symbols.try_remove_by_id(id)?;
        self.record_symbol_removed(address, symbol);

        Ok(true)
    }

    pub fn remove_symbol_by_index(&mut self, index: SymbolIndex) -> Result<bool, ProjectError> {
        let removed = self
            .project
            .symbols
            .try_get_by_index(index)?
            .map(|(_, entry)| (entry.address(), entry.symbol()));

        let Some((address, symbol)) = removed else {
            return Ok(false);
        };

        let revert = self.project.symbols.remove_index_revert(index)?;
        self.symbol_reverts.push(revert);
        self.project.symbols.try_remove_by_index(index)?;
        self.record_symbol_removed(address, symbol);

        Ok(true)
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
        self.remove_lifted_for_mapping(space, mapping)?;

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
        self.remove_lifted_for_mapping(space, mapping)?;

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
        self.remove_lifted_for_mapping(space, mapping)?;

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
        self.record_mapping_removed(id, removed.iter().copied());
        self.remove_lifted_for_placements(removed)?;

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
        self.record_mapping_removed(id, removed.iter().copied());
        self.remove_lifted_for_placements(removed)?;
        self.record_mapping_added_to_placements(id);
        self.remove_lifted_for_mapping_placements(id)?;

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
        self.record_mapping_removed(id, removed.iter().copied());
        self.remove_lifted_for_placements(removed)?;
        self.record_mapping_added_to_placements(id);
        self.remove_lifted_for_mapping_placements(id)?;

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
        self.remove_lifted_for_mapping(space, id)?;

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
        self.remove_lifted_for_mapping(space, id)?;

        Ok(())
    }

    pub fn write_bytes(&mut self, addr: Address, bytes: &[u8]) -> Result<(), ProjectError> {
        let (written, revert) = self.project.storage.segments.write_bytes_to_space_tracked(
            addr.space(),
            addr,
            bytes,
        )?;

        if written == bytes.len() {
            self.segment_write_reverts.push(revert);
            if let Some(range) = Self::bytes_range(addr.space(), addr.raw_address(), written as u64)
            {
                self.records.push(ChangeRecord::BytesWritten { range });
                self.remove_lifted_in_range(&range, IlLevel::PCode)?;
            }
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

    fn remove_lifted_for_mapping(
        &mut self,
        space: AddressSpaceId,
        id: SegmentMappingId,
    ) -> Result<usize, ProjectError> {
        let Some(mapping) = self.project.storage.segments.mapping(id) else {
            return Ok(0);
        };

        let range = Self::mapping_range(space, mapping.start(), mapping.size());
        self.remove_lifted_in_range(&range, IlLevel::PCode)
    }

    fn remove_lifted_for_mapping_placements(
        &mut self,
        id: SegmentMappingId,
    ) -> Result<usize, ProjectError> {
        let placements = self
            .project
            .storage
            .segments
            .mapping_placements(id)
            .collect::<SmallVec<[_; 4]>>();

        self.remove_lifted_for_placements(placements)
    }

    fn remove_lifted_for_placements(
        &mut self,
        placements: impl IntoIterator<Item = (AddressSpaceId, (RawAddress, RawAddress))>,
    ) -> Result<usize, ProjectError> {
        let mut removed = 0usize;

        for (space, range) in placements {
            let range = AddressRange::new(space, range.0, range.1);
            removed += self.remove_lifted_in_range(&range, IlLevel::PCode)?;
        }

        Ok(removed)
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

    fn restore_function(&mut self, revert: FunctionTableRevert) -> Result<(), ProjectError> {
        let entry = revert.entry();
        self.project.call_graph.remove_function_edges(entry)?;
        revert.restore(&mut self.project.functions, &mut self.project.blocks)?;

        let targets = self
            .project
            .functions
            .get_by_address(entry)
            .map(|function| CallGraphIndex::function_call_targets(&function, &self.project.blocks))
            .unwrap_or_default();
        self.project.call_graph.set_function_edges(entry, targets)?;

        Ok(())
    }

    pub fn commit(mut self) -> Result<ChangeSet, ProjectError> {
        let span = self.span.clone();
        let _entered = span.enter();
        if !self.records.is_empty() {
            let revision = self.project.revision.next();
            if self.records.iter().any(ChangeRecord::affects_lifted_inputs) {
                self.project.semantic_revision = revision;
            }
            self.project.revision = revision;
        }
        self.committed = true;
        Ok(
            ChangeSet::with_records(self.project.revision, std::mem::take(&mut self.records))
                .attributed_to(self.source.clone()),
        )
    }

    pub fn rollback(mut self) -> Result<(), ProjectError> {
        let span = self.span.clone();
        let _entered = span.enter();
        self.committed = true;
        while let Some(revert) = self.ir_reverts.pop() {
            revert.restore(&self.project.storage.entities)?;
        }
        while let Some(revert) = self.reference_reverts.pop() {
            revert.restore(&self.project.references)?;
        }
        while let Some(revert) = self.switch_reverts.pop() {
            revert.restore(&mut self.project.switches)?;
        }
        while let Some(revert) = self.function_reverts.pop() {
            self.restore_function(revert)?;
        }
        while let Some(revert) = self.symbol_reverts.pop() {
            revert.restore(&mut self.project.symbols)?;
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

        let symbol_cache_bytes = attributes
            .get_attr::<usize>(ATTRIBUTE_SYMBOL_CACHE_SIZE)
            .unwrap_or(DEFAULT_SYMBOL_CACHE_BYTES);

        let mut symbols = storage.table(
            symbol_cache_bytes,
            SymbolTable::with_worker,
            SymbolTable::new_transient,
            "symbol",
        )?;

        if !SymbolTable::persisted(&storage.entities)? {
            let Some(loadable) = loadable else {
                tracing::error!("project not standalone and no loadable instance available");
                return Err(StorageProviderError::NotAStandaloneProject.into());
            };

            if let (Some(loadable_symbols), Some(resolution)) =
                (loadable.image_symbols(), storage.image_resolution.as_ref())
            {
                tracing::trace!(
                    "transfering {} symbols from loadable",
                    loadable_symbols.len()
                );

                for (index, _, entry) in loadable_symbols.iter_by_index() {
                    if let Some(address) = resolution.resolve_address(entry.address()) {
                        symbols.insert(index, address, entry.symbol(), entry.properties())?;
                    }
                }
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

        let revision_record = storage
            .entities
            .get::<ProjectEntity, ProjectRevision>(&ProjectEntity::Revision)?;
        let revision = revision_record
            .as_ref()
            .map(ProjectRevision::revision)
            .unwrap_or_default();
        let semantic_revision = revision_record
            .as_ref()
            .map(ProjectRevision::semantic_revision)
            .unwrap_or(revision);
        let restored_revision = (revision != Revision::default()).then_some(revision);

        let call_graph =
            CallGraphIndex::new(storage.entities.clone(), storage.write_back().cloned())?;
        call_graph.ensure_current(functions.iter(), &blocks, revision.value())?;

        let references =
            ReferenceIndex::new(storage.entities.clone(), storage.write_back().cloned())?;
        references.ensure_current(functions.iter(), &blocks, revision.value())?;

        Ok(Self {
            arch,
            language,
            symbols,
            functions,
            blocks,
            call_graph,
            references,
            switches,
            platform,
            restored_revision,
            attributes,
            revision,
            semantic_revision,
            transaction_active: false,
            canonicaliser: PCodeCanonicaliser::default(),
            ecode_to_ssa: ECodeToSsa::default(),
            pcode_to_ecode: PCodeToECode::default(),
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

    pub fn pcode(&self, function: FunctionId) -> Result<Option<PCodeIr>, ProjectError> {
        self.lifted(function)
    }

    pub fn ecode(&self, function: FunctionId) -> Result<Option<ECodeIr>, ProjectError> {
        self.lifted(function)
    }

    pub fn ecode_ssa(&self, function: FunctionId) -> Result<Option<ECodeSsaIr>, ProjectError> {
        self.lifted(function)
    }

    pub(crate) fn lifted<T>(&self, function: FunctionId) -> Result<Option<T>, ProjectError>
    where
        T: IlArtefact,
    {
        T::load_current(&self.storage.entities, function, self.semantic_revision)
            .map_err(ProjectError::from)
    }

    pub(crate) fn abandon_persistence(&mut self) {
        self.persistable = false;
    }

    pub fn transaction(&mut self, source: impl Into<ChangeSource>) -> ProjectTransaction<'_> {
        let source = source.into();
        let span = tracing::debug_span!("project_transaction", reason = source.label());
        assert!(
            !self.transaction_active,
            "project transaction already active"
        );
        self.transaction_active = true;
        ProjectTransaction {
            project: self,
            records: Vec::new(),
            ir_reverts: Vec::new(),
            function_reverts: Vec::new(),
            symbol_reverts: Vec::new(),
            segment_reverts: Vec::new(),
            segment_write_reverts: Vec::new(),
            reference_reverts: Vec::new(),
            switch_reverts: Vec::new(),
            source,
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

    pub fn references(&self) -> &ReferenceIndex {
        &self.references
    }

    pub fn switches(&self) -> &SwitchTable {
        &self.switches
    }

    pub fn switches_mut(&mut self) -> &mut SwitchTable {
        &mut self.switches
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

        tracing::debug!("persisting switch table");
        self.switches.persist(&self.storage.entities)?;

        if let Some(worker) = self.storage.write_back() {
            tracing::debug!("draining write-back worker");
            worker.flush()?;
        }

        tracing::debug!("persisting call graph marker");
        self.call_graph.mark_current(self.revision.value())?;

        tracing::debug!("persisting reference index marker");
        self.references.mark_current(self.revision.value())?;

        tracing::debug!("persisting project revision");
        self.storage.entities.insert(
            &ProjectEntity::Revision,
            &ProjectRevision::new(self.revision, self.semantic_revision),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::io;

    use fugue_lifter::runtime::pcode::Inputs;

    use super::*;
    #[cfg(any(feature = "sqlite", feature = "rocksdb", feature = "mdbx"))]
    use crate::attributes;
    use crate::il::common::{
        IlArtefact, IlBlock, IlBlockId, IlBlockProperties, IlDominance, IlGraph, IlIndexRange,
        IlMetadata, IlSchemaVersion, IlSourceSpan, IlValueId,
    };
    use crate::il::ecode::ssa::{
        ECODE_SSA_SCHEMA_VERSION, ECodeSsaBuilder, ECodeSsaLiveness, ECodeSsaUses,
    };
    use crate::il::ecode::{ECODE_SCHEMA_VERSION, ECodeBuilder, ECodeStmtOpcode};
    use crate::il::pcode::{
        LifterSpaceHandle, PCODE_SCHEMA_VERSION, PCodeBuilder, PCodeLocation,
        PCodeLocationProperties, PCodeOp, PCodeOpcode,
    };
    use crate::ir::{
        AddressWithContext, IncompleteCodeBlock, Insn, InsnEntry, InsnProperties,
        ReferenceProperties, SwitchCase, SwitchModel, SymbolProperties, SymbolTableSelector,
    };
    use crate::lifter::{ContextSet, Op, RawPCodeOp, Varnode, resolve_language};
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
    use crate::storage::segments::DEFAULT_SPACE_ID;

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

    fn pcode_reference_ir(
        function: FunctionId,
        source: Address,
        target_space: AddressSpaceId,
        target_offset: u64,
        opcode: PCodeOpcode,
    ) -> Result<PCodeIr, Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let header = IlMetadata::new(function, PCODE_SCHEMA_VERSION, 0);
        let mut builder = PCodeBuilder::new(language, header, IlGraph::default());

        builder.replace_source_spans(vec![IlSourceSpan::new(
            IlIndexRange::new(0, 1)?,
            source,
            0,
            1,
        )]);

        let pointer = builder.push_location(PCodeLocation::new(
            LifterSpaceHandle::new(0),
            target_offset,
            8,
            PCodeLocationProperties::CONSTANT,
        ))?;
        let value = builder.push_location(PCodeLocation::new(
            LifterSpaceHandle::new(1),
            0,
            8,
            PCodeLocationProperties::REGISTER,
        ))?;
        let operands = match opcode {
            PCodeOpcode::Store => builder.push_operands([pointer, value])?,
            _ => builder.push_operands([pointer])?,
        };
        let output = opcode.requires_output().then_some(value);

        builder.push_operation(PCodeOp::new(
            opcode,
            output,
            operands,
            0,
            Some(target_space),
        ));

        Ok(builder.build(&CancellationToken::default())?)
    }

    fn pcode_copy_ir(
        function: FunctionId,
        source: Address,
    ) -> Result<PCodeIr, Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let header = IlMetadata::new(function, PCODE_SCHEMA_VERSION, 0);
        let mut builder = PCodeBuilder::new(language, header, IlGraph::default());

        builder.replace_source_spans(vec![IlSourceSpan::new(
            IlIndexRange::new(0, 1)?,
            source,
            0,
            1,
        )]);

        let location = builder.push_location(PCodeLocation::new(
            LifterSpaceHandle::new(1),
            0,
            8,
            PCodeLocationProperties::REGISTER,
        ))?;
        let operands = builder.push_operands([location])?;

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(location),
            operands,
            0,
            None,
        ));

        Ok(builder.build(&CancellationToken::default())?)
    }

    fn lift_test_ecode(source: &PCodeIr) -> Result<ECodeIr, IlError> {
        PCodeToECode::default().transform(
            source,
            &Arch::new(resolve_language("x86:LE:64").expect("test language should resolve")),
            &CancellationToken::default(),
        )
    }

    fn flow_resolved_load_function(
        entry: Address,
        data_offset: u64,
    ) -> Result<IncompleteFunction, Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let operation = RawPCodeOp {
            op: Op::Load(language.default_space()),
            inputs: Inputs::one(Varnode::constant(data_offset, 8)),
            output: Varnode::new(language.register_space(), 0, 8),
        };
        let operations = [operation];
        let insn = Insn::from_resolved_flow(language, entry, 1, &operations)?;
        let mut function = IncompleteFunction::new(entry);

        let insn = match function.insn_entry(entry) {
            InsnEntry::Vacant(entry) => entry.insert(insn),
            InsnEntry::Occupied(_) => {
                return Err(io::Error::other("test instruction unexpectedly occupied").into());
            }
        };

        function.push_block(IncompleteCodeBlock::new(
            entry,
            1,
            vec![insn],
            ContextSet::default(),
        ));

        Ok(function)
    }

    fn calling_function(
        entry: Address,
        callee: Address,
        length: usize,
    ) -> Result<IncompleteFunction, Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let operation = RawPCodeOp {
            op: Op::Call,
            inputs: Inputs::one(Varnode::new(language.default_space(), callee.offset(), 8)),
            output: Varnode::INVALID,
        };
        let operations = [operation];
        let insn = Insn::from_resolved_flow(language, entry, length, &operations)?;
        let mut function = IncompleteFunction::new(entry);

        let insn = match function.insn_entry(entry) {
            InsnEntry::Vacant(entry) => entry.insert(insn),
            InsnEntry::Occupied(_) => {
                return Err(io::Error::other("test instruction unexpectedly occupied").into());
            }
        };

        function.push_block(
            IncompleteCodeBlock::try_new(entry, length, vec![insn], ContextSet::default())
                .expect("test block length must be valid"),
        );

        Ok(function)
    }

    fn disassembled_function(
        entry: Address,
        length: usize,
    ) -> Result<IncompleteFunction, Box<dyn std::error::Error>> {
        let insn = Insn::from_disassembly(entry, length, InsnProperties::NEEDS_FLOW_RESOLUTION)?;
        let mut function = IncompleteFunction::new(entry);

        let insn = match function.insn_entry(entry) {
            InsnEntry::Vacant(entry) => entry.insert(insn),
            InsnEntry::Occupied(_) => {
                return Err(io::Error::other("test instruction unexpectedly occupied").into());
            }
        };

        function.push_block(
            IncompleteCodeBlock::try_new(entry, length, vec![insn], ContextSet::default())
                .expect("test block length must be valid"),
        );

        Ok(function)
    }

    fn writable_address(project: &Project) -> Result<Address, Box<dyn std::error::Error>> {
        project
            .segments()
            .iter_views(DEFAULT_SPACE_ID)?
            .find(|view| view.properties().is_writable())
            .map(|view| view.start())
            .ok_or_else(|| io::Error::other("fixture writable segment missing").into())
    }

    fn incomplete_function(entry: Address, len: usize) -> IncompleteFunction {
        let mut function = IncompleteFunction::new(entry);
        function.push_block(
            IncompleteCodeBlock::try_new(entry, len, Vec::new(), ContextSet::default())
                .expect("test block length must be valid"),
        );

        function
    }

    fn tagged_source_spans(payload: &[u8]) -> Vec<IlSourceSpan> {
        let tag = payload.first().copied().unwrap_or_default();
        vec![IlSourceSpan::new(
            IlIndexRange::EMPTY,
            Address::new(DEFAULT_SPACE_ID, u64::from(tag)),
            u32::from(tag),
            u32::try_from(payload.len()).expect("test payload length should fit"),
        )]
    }

    fn single_block_graph() -> IlGraph {
        IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::EMPTY,
                IlBlockProperties::ENTRY | IlBlockProperties::EXIT,
            )],
            Vec::new(),
        )
    }

    fn pcode_for_test(function: FunctionId, graph: IlGraph) -> PCodeIr {
        let language = resolve_language("x86:LE:64").expect("test language should resolve");
        PCodeBuilder::new(
            language,
            IlMetadata::new(function, PCODE_SCHEMA_VERSION, 0),
            graph,
        )
        .build(&CancellationToken::default())
        .expect("test PCode IR should verify")
    }

    fn tagged_pcode(function: FunctionId, payload: &[u8]) -> PCodeIr {
        let language = resolve_language("x86:LE:64").expect("test language should resolve");
        let mut builder = PCodeBuilder::new(
            language,
            IlMetadata::new(function, PCODE_SCHEMA_VERSION, 0),
            IlGraph::default(),
        );
        builder.replace_source_spans(tagged_source_spans(payload));
        builder
            .build(&CancellationToken::default())
            .expect("test PCode IR should verify")
    }

    fn ecode_for_test(function: FunctionId, graph: IlGraph) -> ECodeIr {
        ECodeBuilder::new(IlMetadata::new(function, ECODE_SCHEMA_VERSION, 0), graph)
            .build(&CancellationToken::default())
            .expect("test LIR should verify")
    }

    fn ecode_ssa_for_test(function: FunctionId, graph: IlGraph) -> ECodeSsaIr {
        ECodeSsaBuilder::new(
            IlMetadata::new(function, ECODE_SSA_SCHEMA_VERSION, 0),
            graph,
        )
        .build(&CancellationToken::default())
        .expect("test LIR SSA should verify")
    }

    fn first_mapping_placement(
        project: &Project,
    ) -> (AddressSpaceId, SegmentMappingId, (RawAddress, RawAddress)) {
        let (space, mapping) = project
            .segments()
            .spaces()
            .find_map(|space| {
                space
                    .priority_list()
                    .first()
                    .map(|mapping_ref| (space.id(), mapping_ref.mapping_id()))
            })
            .expect("fixture should contain at least one mapping");
        let range = project
            .segments()
            .mapping_placements(mapping)
            .find_map(|(mapped_space, range)| (mapped_space == space).then_some(range))
            .expect("mapping should have a placement in its priority space");

        (space, mapping, range)
    }

    #[test]
    fn project_pcode_rejects_stale_input_revision() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let stale_revision = project.semantic_revision;
        {
            let mut transaction = project.transaction("test");
            transaction.create_space()?;
            transaction.commit()?;
        }

        let ir = PCodeIr::new(
            IlMetadata::new(function, PCODE_SCHEMA_VERSION, stale_revision),
            IlGraph::default(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        project.storage.entities.insert(&function, &ir)?;

        assert!(matches!(
            project.pcode(function),
            Err(ProjectError::Il(IlError::StaleArtefact {
                level: IlLevel::PCode,
                ..
            }))
        ));

        Ok(())
    }

    #[test]
    fn project_pcode_rejects_schema_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let schema = IlSchemaVersion::new(PCODE_SCHEMA_VERSION.value() + 1);
        let ir = PCodeIr::new(
            IlMetadata::new(function, schema, project.semantic_revision),
            IlGraph::default(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        project.storage.entities.insert(&function, &ir)?;

        assert!(matches!(
            project.pcode(function),
            Err(ProjectError::Il(IlError::SchemaMismatch {
                level: IlLevel::PCode,
                expected,
                found,
            })) if expected == PCODE_SCHEMA_VERSION.value() && found == schema.value()
        ));

        Ok(())
    }

    #[test]
    fn project_remove_lifted_clears_derived_data_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target_space = AddressSpaceId::new(2);
        let target = Address::new(target_space, 0x4000u64);
        let mut load =
            pcode_reference_ir(function, source, target_space, 0x4000, PCodeOpcode::Load)?;

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut load)?;
            assert!(transaction.flush_derived_references(function)?);
            transaction.commit()?;
        }

        assert!(
            project
                .references
                .get(source, ReferenceTarget::from(target))?
                .is_some()
        );

        {
            let mut transaction = project.transaction("test");
            assert!(transaction.remove_lifted(function, IlLevel::PCode)?);
            transaction.commit()?;
        }

        assert!(
            project
                .references
                .get(source, ReferenceTarget::from(target))?
                .is_none()
        );

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut load)?;
            assert!(transaction.flush_derived_references(function)?);
            transaction.commit()?;
        }

        {
            let mut transaction = project.transaction("test");
            assert!(transaction.remove_lifted(function, IlLevel::PCode)?);
            transaction.rollback()?;
        }

        let restored = project
            .references
            .get(source, ReferenceTarget::from(target))?
            .expect("rollback should restore the artefact's derived data reference");
        assert!(restored.is_read());
        assert!(project.pcode(function)?.is_some());

        Ok(())
    }

    #[test]
    fn project_flush_derived_references_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target_space = AddressSpaceId::new(2);
        let mut load =
            pcode_reference_ir(function, source, target_space, 0x4000, PCodeOpcode::Load)?;

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut load)?;
            assert!(transaction.flush_derived_references(function)?);
            transaction.commit()?;
        }

        let changes = {
            let mut transaction = project.transaction("test");
            assert!(!transaction.flush_derived_references(function)?);
            transaction.commit()?
        };
        assert!(
            !changes
                .records()
                .iter()
                .any(|record| matches!(record, ChangeRecord::ReferencesChanged { .. }))
        );

        Ok(())
    }

    #[test]
    fn project_flush_derived_references_replaces_derived_data_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target_space = AddressSpaceId::new(2);
        let target = Address::new(target_space, 0x4000u64);
        let mut load =
            pcode_reference_ir(function, source, target_space, 0x4000, PCodeOpcode::Load)?;
        let mut copy = pcode_copy_ir(function, source)?;

        let changes = {
            let mut transaction = project.transaction("test");
            assert!(!transaction.flush_derived_references(function)?);
            transaction.materialise_lifted(&mut load)?;
            assert!(transaction.flush_derived_references(function)?);
            transaction.commit()?
        };

        let reference = project
            .references
            .get(source, ReferenceTarget::from(target))?
            .expect("flushing PCode references should install a derived data reference");
        assert!(reference.is_read());
        assert!(reference.origin().is_derived());

        let incoming = project
            .references
            .references_to(ReferenceTarget::from(target), None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert!(
            incoming
                .iter()
                .any(|reference| reference.from() == source && reference.is_read()),
            "inverse query should observe the flushed data reference"
        );

        assert!(
            changes
                .records()
                .contains(&ChangeRecord::ReferencesChanged {
                    coverage: {
                        let mut coverage = AddressRangeSet::new();
                        coverage.insert_range(AddressRange::point(source));
                        coverage
                    },
                })
        );

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut copy)?;
            assert!(transaction.flush_derived_references(function)?);
            transaction.commit()?;
        }

        assert!(
            project
                .references
                .get(source, ReferenceTarget::from(target))?
                .is_none()
        );

        Ok(())
    }

    #[test]
    fn project_switch_insert_rolls_back() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let branch = Address::new(AddressSpaceId::new(1), 0x1000u64);

        {
            let mut transaction = project.transaction("test");
            transaction.add_switch(branch, |id, branch| {
                Switch::new(id, branch, SwitchModel::Explicit)
            })?;
            assert!(
                transaction
                    .project()
                    .switches()
                    .get_by_branch(branch)
                    .is_some()
            );
            transaction.rollback()?;
        }

        assert!(project.switches().get_by_branch(branch).is_none());
        Ok(())
    }

    #[test]
    fn project_removing_function_removes_its_switches() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = Address::new(AddressSpaceId::new(1), 0x2000u64);
        let target = Address::new(AddressSpaceId::new(1), 0x3000u64);
        let default = Address::new(AddressSpaceId::new(1), 0x3500u64);

        let (function_id, changes) = {
            let mut transaction = project.transaction("test");
            let function_id =
                transaction.add_function(flow_resolved_load_function(entry, 0x4000)?)?;
            transaction.add_switch(entry, |id, branch| {
                let mut switch = Switch::new(id, branch, SwitchModel::Explicit);
                switch.add_case(SwitchCase::new(AddressWithContext::new(
                    target,
                    ContextSet::default(),
                )));
                switch
            })?;
            assert!(
                transaction
                    .modify_switch(entry, |switch| {
                        switch.set_default_case(SwitchCase::new(AddressWithContext::new(
                            default,
                            ContextSet::default(),
                        )));
                    })?
                    .is_some()
            );
            let changes = transaction.commit()?;
            (function_id, changes)
        };

        let switch = project
            .switches()
            .get_by_branch(entry)
            .expect("switch present");
        assert_eq!(switch.function(), function_id);
        for destination in [target, default] {
            let reference = project
                .references
                .get(entry, ReferenceTarget::from(destination))?;
            assert!(reference.is_some_and(|reference| reference.origin().is_derived()));
        }
        assert_eq!(
            changes
                .records()
                .iter()
                .filter(|record| {
                    matches!(record, ChangeRecord::SwitchAdded { branch } if *branch == entry)
                })
                .count(),
            2
        );

        {
            let mut transaction = project.transaction("test");
            assert!(transaction.remove_function_by_id(function_id)?);
            transaction.commit()?;
        }

        assert!(project.switches().get_by_branch(entry).is_none());
        for destination in [target, default] {
            assert!(
                project
                    .references
                    .get(entry, ReferenceTarget::from(destination))?
                    .is_none()
            );
        }
        Ok(())
    }

    #[test]
    fn project_flush_derived_references_rolls_back() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target_space = AddressSpaceId::new(2);
        let target = Address::new(target_space, 0x4000u64);
        let mut load =
            pcode_reference_ir(function, source, target_space, 0x4000, PCodeOpcode::Load)?;
        let mut store =
            pcode_reference_ir(function, source, target_space, 0x4000, PCodeOpcode::Store)?;

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut load)?;
            assert!(transaction.flush_derived_references(function)?);
            transaction.commit()?;
        }

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut store)?;
            assert!(transaction.flush_derived_references(function)?);
            transaction.rollback()?;
        }

        let reference = project
            .references
            .get(source, ReferenceTarget::from(target))?
            .expect("rollback should restore the previous derived reference");
        assert!(reference.is_read());
        assert!(!reference.is_write());

        Ok(())
    }

    #[test]
    fn project_function_add_does_not_materialise_flow_resolved_data_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = Address::new(AddressSpaceId::new(7), 0x1000u64);
        let data_offset = 0x4000u64;
        let target = Address::new(entry.space(), data_offset);
        let function = flow_resolved_load_function(entry, data_offset)?;

        {
            let mut transaction = project.transaction("test");
            transaction.add_function(function)?;
            transaction.commit()?;
        }

        assert!(
            project
                .references
                .get(entry, ReferenceTarget::from(target))?
                .is_none()
        );

        Ok(())
    }

    #[test]
    fn project_ensure_pcode_preserves_flow_references() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project)?;
        let bytes = [0x48, 0x89, 0xd8];
        let callee = entry
            .checked_add(0x40u64)
            .ok_or_else(|| io::Error::other("callee address overflow"))?;
        let function = calling_function(entry, callee, bytes.len())?;
        let function = {
            let mut transaction = project.transaction("test");
            transaction
                .write_bytes(entry, &bytes)
                .expect("write call bytes");
            let function = transaction.add_function(function).expect("add function");
            transaction.commit()?;
            function
        };

        let flow = project
            .references
            .get(entry, ReferenceTarget::from(callee))?
            .expect("function add should derive the call flow reference");
        assert!(flow.is_call());

        {
            let mut transaction = project.transaction("test");
            transaction
                .ensure_pcode(function, &CancellationToken::default())
                .expect("ensure pcode");
            transaction.commit()?;
        }

        let preserved = project
            .references
            .get(entry, ReferenceTarget::from(callee))?
            .expect("materialising PCode should preserve the call flow reference");
        assert!(preserved.is_call());

        Ok(())
    }

    #[test]
    fn project_ensure_pcode_builds_from_recovered_instruction_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project)?;
        let bytes = [0x48, 0x89, 0xd8];
        let function = disassembled_function(entry, bytes.len())?;
        let function = {
            let mut transaction = project.transaction("test");
            transaction.write_bytes(entry, &bytes)?;
            let function = transaction.add_function(function)?;
            transaction.commit()?;
            function
        };

        let materialised_pcode = {
            let mut transaction = project.transaction("test");
            let materialised = transaction.ensure_pcode(function, &CancellationToken::default())?;
            transaction.commit()?;
            materialised
        };
        let materialised_ecode = {
            let mut transaction = project.transaction("test");
            let materialised = transaction.ensure_ecode(function, &CancellationToken::default())?;
            transaction.commit()?;
            materialised
        };
        let pcode = project
            .pcode(function)?
            .expect("pcode should be materialised");
        let ecode = project
            .ecode(function)?
            .expect("ecode should be materialised");

        assert!(materialised_pcode);
        assert!(materialised_ecode);
        assert!(!pcode.operations().is_empty());
        assert_eq!(pcode.source_spans().len(), 1);
        assert_eq!(pcode.source_spans()[0].address(), entry);
        assert!(
            ecode
                .statements()
                .iter()
                .any(|statement| statement.opcode() == ECodeStmtOpcode::WriteRegister)
        );

        Ok(())
    }

    #[test]
    fn project_ensure_pcode_records_zero_operation_source_gap()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project)?;
        let bytes = [0x90];
        let function = disassembled_function(entry, bytes.len())?;
        let function = {
            let mut transaction = project.transaction("test");
            transaction.write_bytes(entry, &bytes)?;
            let function = transaction.add_function(function)?;
            transaction.commit()?;
            function
        };

        {
            let mut transaction = project.transaction("test");
            transaction.ensure_pcode(function, &CancellationToken::default())?;
            transaction.commit()?;
        }

        let pcode = project
            .pcode(function)?
            .expect("pcode should be materialised");
        let source_spans = pcode.source_spans();

        assert!(pcode.operations().is_empty());
        assert_eq!(source_spans.len(), 1);
        assert_eq!(source_spans[0].address(), entry);
        assert!(source_spans[0].destination().is_empty());
        assert_eq!(source_spans[0].pcode_count(), 0);

        Ok(())
    }

    #[test]
    fn project_ensure_pcode_resolves_default_space_load() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project)?;
        let bytes = [0x48, 0x8b, 0x03];
        let function = disassembled_function(entry, bytes.len())?;
        let function = {
            let mut transaction = project.transaction("test");
            transaction.write_bytes(entry, &bytes)?;
            let function = transaction.add_function(function)?;
            transaction.commit()?;
            function
        };

        let mut transaction = project.transaction("test");
        assert!(transaction.ensure_pcode(function, &CancellationToken::default())?);
        transaction.commit()?;

        let pcode = project.pcode(function)?.expect("pcode is materialised");
        let load = pcode
            .operations()
            .iter()
            .find(|operation| operation.opcode() == PCodeOpcode::Load)
            .expect("load survives canonicalisation");
        assert_eq!(load.effect_space(), Some(entry.space()));

        Ok(())
    }

    #[test]
    fn project_ecode_materialise_preserves_flushed_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target_space = AddressSpaceId::new(2);
        let target = Address::new(target_space, 0x4000u64);
        let mut pcode =
            pcode_reference_ir(function, source, target_space, 0x4000, PCodeOpcode::Load)?;

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut pcode)?;
            assert!(transaction.flush_derived_references(function)?);
            transaction.commit()?;
        }

        let pcode = project
            .pcode(function)?
            .expect("pcode should be materialised");
        let mut ecode = lift_test_ecode(&pcode)?;

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut ecode)?;
            transaction.commit()?;
        }

        let reference = project
            .references
            .get(source, ReferenceTarget::from(target))?
            .expect("ecode publication should not remove PCode-derived references");
        assert!(reference.is_read());
        assert!(reference.origin().is_derived());

        Ok(())
    }

    #[test]
    #[ignore = "requires local language data and binary fixtures"]
    fn project() -> Result<(), Box<dyn std::error::Error>> {
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
    fn project_persistent_default() -> Result<(), Box<dyn std::error::Error>> {
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
    fn project_persistent_mdbx() -> Result<(), Box<dyn std::error::Error>> {
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
    fn project_standalone() -> Result<(), Box<dyn std::error::Error>> {
        with_logging(|| {
            let _project = Project::from_file_with_provider::<
                PersistentStorageProvider<RocksDbEntityStorage, DefaultPersistentSegmentStorage>,
            >("tests/test-project.rdb.fdbz")?;

            Ok(())
        })
    }

    #[test]
    fn lifted_materialise_remove_and_rollback() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let mut materialised = tagged_pcode(function, &[1, 2, 3]);

        let changes = {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut materialised)?;
            transaction.commit()?
        };

        assert!(
            changes
                .records()
                .contains(&ChangeRecord::LiftedMaterialised {
                    function,
                    level: IlLevel::PCode,
                })
        );
        assert_eq!(project.pcode(function)?.as_ref(), Some(&materialised));

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut tagged_pcode(function, &[4, 5, 6]))?;
            transaction.rollback()?;
        }

        assert_eq!(project.pcode(function)?.as_ref(), Some(&materialised));

        let changes = {
            let mut transaction = project.transaction("test");
            assert!(transaction.remove_lifted(function, IlLevel::PCode)?);
            transaction.commit()?
        };

        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function,
            level: IlLevel::PCode,
        }));
        assert!(project.pcode(function)?.is_none());

        Ok(())
    }

    #[test]
    fn lifted_materialise_and_read() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let mut body = pcode_for_test(FunctionId::default(), IlGraph::default());

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut body)?;
            transaction.commit()?;
        }

        let read = project
            .pcode(FunctionId::default())?
            .expect("PCode IR should be materialised");

        assert_eq!(read.operations(), body.operations());
        assert_eq!(read.metadata().input_revision(), project.semantic_revision);

        Ok(())
    }

    #[test]
    fn project_reads_ecode_ssa_derived_tables() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut pcode_for_test(function, single_block_graph()))?;
            transaction.materialise_lifted(&mut ecode_for_test(function, single_block_graph()))?;
            transaction
                .materialise_lifted(&mut ecode_ssa_for_test(function, single_block_graph()))?;
            transaction.commit()?;
        }

        let entry = IlBlockId::try_from_index(0)?;
        let value = IlValueId::try_from_index(0)?;
        let ir = project
            .ecode_ssa(function)?
            .expect("SSA IR should be available");
        let uses = ir.analyse::<ECodeSsaUses>();
        let dominance = ir.analyse::<IlDominance>();
        let frontiers = dominance.frontiers(ir.graph().blocks(), ir.graph().successors());
        let liveness = ir.analyse::<ECodeSsaLiveness>();

        assert!(uses.uses_for(value).is_empty());
        assert!(dominance.dominates(entry, entry));
        assert!(frontiers.frontier(entry).is_empty());
        assert!(liveness.live_in(entry).is_empty());
        assert!(liveness.live_out(entry).is_empty());

        Ok(())
    }

    #[test]
    fn ensure_lifted_builds_ecode_from_pcode() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let mut body = pcode_for_test(function, IlGraph::default());

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut body)?;
            transaction.commit()?;
        }

        let changes = {
            let mut transaction = project.transaction("test");
            assert!(!transaction.ensure_pcode(function, &CancellationToken::default())?);
            assert!(transaction.ensure_ecode(function, &CancellationToken::default())?);
            transaction.commit()?
        };

        assert!(project.pcode(function)?.is_some());
        assert!(project.ecode(function)?.is_some());
        assert!(
            changes
                .records()
                .contains(&ChangeRecord::LiftedMaterialised {
                    function,
                    level: IlLevel::ECode,
                })
        );

        let changes = {
            let mut transaction = project.transaction("test");
            assert!(!transaction.ensure_ecode(function, &CancellationToken::default())?);
            transaction.commit()?
        };

        assert!(changes.records().is_empty());

        Ok(())
    }

    #[test]
    fn ensure_lifted_builds_ssa_through_ecode() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let mut body = pcode_for_test(function, IlGraph::default());

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut body)?;
            transaction.commit()?;
        }

        let changes = {
            let mut transaction = project.transaction("test");
            assert!(transaction.ensure_ecode_ssa(function, &CancellationToken::default())?);
            transaction.commit()?
        };

        assert!(project.ecode(function)?.is_some());
        assert!(project.ecode_ssa(function)?.is_some());
        assert!(
            changes
                .records()
                .contains(&ChangeRecord::LiftedMaterialised {
                    function,
                    level: IlLevel::ECode,
                })
        );
        assert!(
            changes
                .records()
                .contains(&ChangeRecord::LiftedMaterialised {
                    function,
                    level: IlLevel::ECodeSsa,
                })
        );

        Ok(())
    }

    #[test]
    fn lifted_descendant_removal_preserves_parent() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut tagged_pcode(function, &[1]))?;
            transaction.materialise_lifted(&mut ecode_for_test(function, IlGraph::default()))?;
            transaction
                .materialise_lifted(&mut ecode_ssa_for_test(function, IlGraph::default()))?;
            transaction.commit()?;
        }

        {
            let mut transaction = project.transaction("test");
            assert_eq!(transaction.remove_lifted_from(function, IlLevel::ECode)?, 2);
            transaction.rollback()?;
        }

        assert!(project.ecode(function)?.is_some());
        assert!(project.ecode_ssa(function)?.is_some());

        let changes = {
            let mut transaction = project.transaction("test");
            assert_eq!(transaction.remove_lifted_from(function, IlLevel::ECode)?, 2);
            transaction.commit()?
        };

        assert!(project.pcode(function)?.is_some());
        assert!(project.ecode(function)?.is_none());
        assert!(project.ecode_ssa(function)?.is_none());
        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function,
            level: IlLevel::ECode,
        }));
        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function,
            level: IlLevel::ECodeSsa,
        }));

        Ok(())
    }

    #[test]
    fn replacing_function_invalidates_lifted() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = Address::from(0x4000u64);

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(incomplete_function(entry, 1))?;
            transaction.commit()?;
            function
        };

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut tagged_pcode(function, &[1]))?;
            transaction.materialise_lifted(&mut ecode_for_test(function, IlGraph::default()))?;
            transaction.commit()?;
        }

        let changes = {
            let mut transaction = project.transaction("test");
            assert_eq!(
                transaction.add_function(incomplete_function(entry, 2))?,
                function
            );
            transaction.commit()?
        };

        assert!(project.pcode(function)?.is_none());
        assert!(project.ecode(function)?.is_none());
        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function,
            level: IlLevel::PCode,
        }));
        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function,
            level: IlLevel::ECode,
        }));

        Ok(())
    }

    #[test]
    fn function_replacement_rollback_restores_lifted() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = Address::from(0x4000u64);

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(incomplete_function(entry, 1))?;
            transaction.commit()?;
            function
        };
        let mut materialised = tagged_pcode(function, &[1]);

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut materialised)?;
            transaction.commit()?;
        }

        {
            let mut transaction = project.transaction("test");
            transaction.add_function(incomplete_function(entry, 2))?;
            transaction.rollback()?;
        }

        assert_eq!(project.pcode(function)?, Some(materialised));

        let block = project
            .functions()
            .get_by_id(function)
            .and_then(|function| function.blocks().next().map(|(_, block)| block))
            .and_then(|block| project.blocks().get_by_id(block))
            .expect("function body should be restored");
        assert_eq!(block.len(), 1);

        Ok(())
    }

    #[test]
    fn function_replacement_rollback_restores_call_graph() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = Address::from(0x4000u64);
        let old_callee = Address::from(0x5000u64);
        let new_callee = Address::from(0x6000u64);

        {
            let mut transaction = project.transaction("test");
            transaction.add_function(calling_function(entry, old_callee, 1)?)?;
            transaction.commit()?;
        }

        assert_eq!(
            project
                .call_graph
                .callees(entry, None)?
                .collect::<Result<Vec<_>, _>>()?,
            vec![old_callee]
        );

        {
            let mut transaction = project.transaction("test");
            transaction.add_function(calling_function(entry, new_callee, 1)?)?;
            assert_eq!(
                transaction
                    .project()
                    .call_graph
                    .callees(entry, None)?
                    .collect::<Result<Vec<_>, _>>()?,
                vec![new_callee]
            );
            transaction.rollback()?;
        }

        assert_eq!(
            project
                .call_graph
                .callees(entry, None)?
                .collect::<Result<Vec<_>, _>>()?,
            vec![old_callee]
        );

        Ok(())
    }

    #[test]
    fn removing_function_invalidates_lifted() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = Address::from(0x4000u64);

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(incomplete_function(entry, 1))?;
            transaction.commit()?;
            function
        };

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut tagged_pcode(function, &[1]))?;
            transaction.commit()?;
        }

        let changes = {
            let mut transaction = project.transaction("test");
            assert!(transaction.remove_function_by_id(function)?);
            transaction.commit()?
        };

        assert!(project.pcode(function)?.is_none());
        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function,
            level: IlLevel::PCode,
        }));

        Ok(())
    }

    #[test]
    fn byte_write_invalidates_lifted() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project)?;

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(incomplete_function(entry, 2))?;
            transaction.commit()?;
            function
        };

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut tagged_pcode(function, &[1]))?;
            transaction.commit()?;
        }

        let changes = {
            let mut transaction = project.transaction("test");
            transaction.write_bytes(entry + 1u64, &[0xa5])?;
            transaction.commit()?
        };

        assert!(project.pcode(function)?.is_none());
        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function,
            level: IlLevel::PCode,
        }));

        Ok(())
    }

    #[test]
    fn byte_write_invalidates_lifted_descendants() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project)?;

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(incomplete_function(entry, 2))?;
            transaction.commit()?;
            function
        };

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut tagged_pcode(function, &[1]))?;
            transaction.materialise_lifted(&mut ecode_for_test(function, IlGraph::default()))?;
            transaction
                .materialise_lifted(&mut ecode_ssa_for_test(function, IlGraph::default()))?;
            transaction.commit()?;
        }

        let changes = {
            let mut transaction = project.transaction("test");
            transaction.write_bytes(entry + 1u64, &[0xa5])?;
            transaction.commit()?
        };

        assert!(project.pcode(function)?.is_none());
        assert!(project.ecode(function)?.is_none());
        assert!(project.ecode_ssa(function)?.is_none());
        for level in [IlLevel::PCode, IlLevel::ECode, IlLevel::ECodeSsa] {
            assert!(
                changes
                    .records()
                    .contains(&ChangeRecord::LiftedRemoved { function, level })
            );
        }

        Ok(())
    }

    #[test]
    fn symbol_rename_preserves_lifted() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project)?;
        let index = SymbolIndex::new(SymbolTableSelector::new(253), 250);

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(incomplete_function(entry, 2))?;
            transaction.add_symbol(
                index,
                SymbolEntry::new(entry, "old_display_name", SymbolProperties::FUNCTION),
            )?;
            transaction.commit()?;
            function
        };

        let mut pcode = tagged_pcode(function, &[1]);
        let mut ecode = ecode_for_test(function, IlGraph::default());
        let mut ssa = ecode_ssa_for_test(function, IlGraph::default());

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut pcode)?;
            transaction.materialise_lifted(&mut ecode)?;
            transaction.materialise_lifted(&mut ssa)?;
            transaction.commit()?;
        }

        let semantic_revision = project.semantic_revision;
        let changes = {
            let mut transaction = project.transaction("test");
            transaction.add_symbol(
                index,
                SymbolEntry::new(entry, "new_display_name", SymbolProperties::FUNCTION),
            )?;
            transaction.commit()?
        };

        assert_eq!(project.semantic_revision, semantic_revision);
        assert!(
            !changes
                .records()
                .iter()
                .any(|record| matches!(record, ChangeRecord::LiftedRemoved { .. }))
        );
        assert_eq!(project.pcode(function)?, Some(pcode));
        assert_eq!(project.ecode(function)?, Some(ecode));
        assert_eq!(project.ecode_ssa(function)?, Some(ssa));

        Ok(())
    }

    #[test]
    fn reference_edits_preserve_lifted() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project)?;
        let target = entry + 0x10u64;

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(incomplete_function(entry, 2))?;
            transaction.commit()?;
            function
        };

        let mut pcode = tagged_pcode(function, &[1]);
        let mut ecode = ecode_for_test(function, IlGraph::default());
        let mut ssa = ecode_ssa_for_test(function, IlGraph::default());

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut pcode)?;
            transaction.materialise_lifted(&mut ecode)?;
            transaction.materialise_lifted(&mut ssa)?;
            transaction.commit()?;
        }

        let semantic_revision = project.semantic_revision;
        let changes = {
            let mut transaction = project.transaction("test");
            assert!(transaction.add_reference(Reference::data(
                entry,
                target,
                ReferenceProperties::READ
            ))?);
            transaction.commit()?
        };

        assert_eq!(project.semantic_revision, semantic_revision);
        assert!(
            !changes
                .records()
                .iter()
                .any(|record| matches!(record, ChangeRecord::LiftedRemoved { .. }))
        );

        let changes = {
            let mut transaction = project.transaction("test");
            assert!(transaction.remove_reference(entry, ReferenceTarget::from(target))?);
            transaction.commit()?
        };

        assert_eq!(project.semantic_revision, semantic_revision);
        assert!(
            !changes
                .records()
                .iter()
                .any(|record| matches!(record, ChangeRecord::LiftedRemoved { .. }))
        );
        assert_eq!(project.pcode(function)?, Some(pcode));
        assert_eq!(project.ecode(function)?, Some(ecode));
        assert_eq!(project.ecode_ssa(function)?, Some(ssa));

        Ok(())
    }

    #[test]
    fn byte_write_rollback_restores_lifted() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project)?;

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(incomplete_function(entry, 1))?;
            transaction.commit()?;
            function
        };
        let mut materialised = tagged_pcode(function, &[1]);

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut materialised)?;
            transaction.commit()?;
        }

        {
            let mut transaction = project.transaction("test");
            transaction.write_bytes(entry, &[0xa5])?;
            transaction.rollback()?;
        }

        assert_eq!(project.pcode(function)?, Some(materialised));

        Ok(())
    }

    #[test]
    fn mapping_removal_invalidates_lifted() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let (space, mapping, range) = first_mapping_placement(&project);
        let entry = Address::new(space, range.0);

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(incomplete_function(entry, 1))?;
            transaction.commit()?;
            function
        };

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut tagged_pcode(function, &[1]))?;
            transaction.commit()?;
        }

        let changes = {
            let mut transaction = project.transaction("test");
            transaction.remove_mapping(mapping)?;
            transaction.commit()?
        };

        assert!(project.pcode(function)?.is_none());
        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function,
            level: IlLevel::PCode,
        }));

        Ok(())
    }

    #[test]
    fn mapping_removal_rollback_restores_lifted() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let (space, mapping, range) = first_mapping_placement(&project);
        let entry = Address::new(space, range.0);

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(incomplete_function(entry, 1))?;
            transaction.commit()?;
            function
        };
        let mut materialised = tagged_pcode(function, &[1]);

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut materialised)?;
            transaction.commit()?;
        }

        {
            let mut transaction = project.transaction("test");
            transaction.remove_mapping(mapping)?;
            transaction.rollback()?;
        }

        assert_eq!(project.pcode(function)?, Some(materialised));

        Ok(())
    }

    #[test]
    fn mapping_remap_invalidates_old_and_new_ranges() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let (space, mapping, old_range) = first_mapping_placement(&project);
        let old_entry = Address::new(space, old_range.0);
        let new_start = project
            .segments()
            .mapping(mapping)
            .expect("mapping should exist")
            .start()
            + 0x1000000u64;
        let new_entry = Address::new(space, new_start.raw_address());

        let (old_function, new_function) = {
            let mut transaction = project.transaction("test");
            let old_function = transaction.add_function(incomplete_function(old_entry, 1))?;
            let new_function = transaction.add_function(incomplete_function(new_entry, 1))?;
            transaction.commit()?;
            (old_function, new_function)
        };

        {
            let mut transaction = project.transaction("test");
            transaction.materialise_lifted(&mut tagged_pcode(old_function, &[1]))?;
            transaction.materialise_lifted(&mut tagged_pcode(new_function, &[2]))?;
            transaction.commit()?;
        }

        let changes = {
            let mut transaction = project.transaction("test");
            transaction.remap_mapping(mapping, new_start)?;
            transaction.commit()?
        };

        assert!(project.pcode(old_function)?.is_none());
        assert!(project.pcode(new_function)?.is_none());
        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function: old_function,
            level: IlLevel::PCode,
        }));
        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function: new_function,
            level: IlLevel::PCode,
        }));

        Ok(())
    }
}
