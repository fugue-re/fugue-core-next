use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use smallvec::SmallVec;
use thiserror::Error;
use tracing::Span;

use crate::analysis::function::recovery::{FunctionRecoveryError, PartialFunction};
use crate::analysis::{AnalysisError, AnalysisGroup};
use crate::arch::Arch;
use crate::engine::change::{ChangeRecord, ChangeSet, ChangeSource, FunctionChangeKind, Revision};
use crate::il::common::{
    ArtefactDigest, ArtefactHeader, Block, BlockId, BuildCancellation, CommonBody, Finish, IlError,
    IrArtefact, IrArtefactKey, IrLevel, PackedRange, RawIrArtefact, Scratch, SourceRun, Transform,
    TransformContext, Verify,
};
use crate::il::llil::LlilBody;
use crate::il::llil::ssa::transform::LlilToSsa;
use crate::il::llil::ssa::{Dominance, DominanceFrontier, Liveness, SsaBody, UseIndex};
use crate::il::llil::transform::PCodeToLlil;
use crate::il::pcode::{
    PCODE_SCHEMA_VERSION, PCodeAddressContext, PCodeBody, PCodeBuilder, PCodeCanonicaliser,
    PCodeError, PCodeOp,
};
use crate::ir::function::table::FunctionTableRevert;
use crate::ir::reference::ReferenceRevert;
use crate::ir::symbol::SymbolTableRevert;
use crate::ir::{
    Address, AddressRange, AddressRangeSet, CallGraphIndex, CodeBlockTable, FunctionId,
    FunctionTable, RawAddress, Reference, ReferenceClass, ReferenceIndex, ReferenceOrigin,
    ReferenceTarget, Symbol, SymbolEntry, SymbolId, SymbolIndex, SymbolTable,
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
    ATTRIBUTE_CODE_BLOCK_CACHE_SIZE, ATTRIBUTE_FUNCTION_CACHE_SIZE, ATTRIBUTE_SYMBOL_CACHE_SIZE,
    DEFAULT_CODE_BLOCK_CACHE_BYTES, DEFAULT_FUNCTION_CACHE_BYTES, DEFAULT_SYMBOL_CACHE_BYTES,
    DefaultProjectStorageProvider, SegmentStorageError, StorageContainer, StorageProvider,
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
    pub(crate) call_graph: CallGraphIndex,
    pub(crate) references: ReferenceIndex,
    pub(crate) platform: Platform,
    restored_revision: Option<Revision>,
    pub(crate) attributes: AttributeMap,
    pub(crate) revision: Revision,
    semantic_revision: Revision,
    transaction_active: bool,
    persistable: bool,
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
    FunctionRecovery(#[from] FunctionRecoveryError),
    #[error(transparent)]
    Il(#[from] IlError),
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
    ir_artefact_reverts: Vec<IrArtefactRevert>,
    function_reverts: Vec<FunctionTableRevert>,
    symbol_reverts: Vec<SymbolTableRevert>,
    segment_reverts: Vec<SegmentStorageRevert>,
    segment_write_reverts: Vec<SegmentWriteRevert>,
    reference_reverts: Vec<ReferenceRevert>,
    scratch: Scratch,
    source: ChangeSource,
    committed: bool,
    span: Span,
}

const IR_TRANSFORM_SCRATCH_CAP: usize = 64 * 1024;

struct IrArtefactRevert {
    key: IrArtefactKey,
    previous: Option<RawIrArtefact>,
}

impl IrArtefactRevert {
    fn new(key: IrArtefactKey, previous: Option<RawIrArtefact>) -> Self {
        Self { key, previous }
    }

    fn restore(self, project: &mut Project) -> Result<(), ProjectError> {
        match self.previous {
            Some(artefact) => project.storage.entities.insert(&self.key, &artefact)?,
            None => project
                .storage
                .entities
                .remove::<IrArtefactKey, RawIrArtefact>(&self.key)?,
        }

        Ok(())
    }
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

    pub fn publish_ir_artefact(
        &mut self,
        mut artefact: RawIrArtefact,
    ) -> Result<ArtefactHeader, ProjectError> {
        if self.records.iter().any(ChangeRecord::affects_ir_inputs) {
            return Err(IlError::publish_after_semantic_mutation().into());
        }

        artefact.set_input_revision(self.project.semantic_revision.value());
        artefact.verify()?;
        self.project.verify_ir_artefact_payload(&artefact)?;

        let key = IrArtefactKey::new(artefact.header().function(), artefact.header().level());
        let previous = self
            .project
            .stored_ir_artefact(key.function(), key.level())?;

        self.project.storage.entities.insert(&key, &artefact)?;
        self.ir_artefact_reverts
            .push(IrArtefactRevert::new(key, previous));
        self.records.push(ChangeRecord::IrArtefactPublished {
            function: key.function(),
            level: key.level(),
        });

        Ok(*artefact.header())
    }

    pub fn publish_ir_body<T>(&mut self, artefact: &mut T) -> Result<(), ProjectError>
    where
        T: IrArtefact,
    {
        let raw = artefact.to_raw_artefact()?;
        let header = self.publish_ir_artefact(raw)?;
        *artefact.header_mut() = header;

        Ok(())
    }

    pub fn flush_ir_references(&mut self, function: FunctionId) -> Result<bool, ProjectError> {
        let Some(body) = self.ir_body_for_output::<PCodeBody>(function)? else {
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

    fn replace_ir_derived_references<T>(
        &mut self,
        artefact: &T,
    ) -> Result<Option<(ReferenceRevert, AddressRangeSet)>, ProjectError>
    where
        T: IrArtefact,
    {
        let mut coverage = AddressRangeSet::new();
        let mut derived = Vec::new();

        artefact.collect_reference_coverage(&mut coverage);
        artefact.collect_derived_references(&mut derived);

        let function = artefact.header().function();
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

        if ReferenceIndex::derived_class_matches(revert.previous(), &derived, ReferenceClass::Data)
        {
            return Ok(None);
        }

        if let Err(error) = self.project.references.replace_derived_in_class(
            revert.previous(),
            derived,
            ReferenceClass::Data,
        ) {
            revert.restore(&self.project.references)?;
            return Err(error.into());
        }

        Ok(Some((revert, coverage)))
    }

    pub fn remove_ir_artefact(
        &mut self,
        function: FunctionId,
        level: IrLevel,
    ) -> Result<bool, ProjectError> {
        let key = IrArtefactKey::new(function, level);
        let Some(previous) = self.project.stored_ir_artefact(function, level)? else {
            return Ok(false);
        };

        self.remove_references_derived_from(&previous)?;
        self.project
            .storage
            .entities
            .remove::<IrArtefactKey, RawIrArtefact>(&key)?;
        self.ir_artefact_reverts
            .push(IrArtefactRevert::new(key, Some(previous)));
        self.records
            .push(ChangeRecord::IrArtefactRemoved { function, level });

        Ok(true)
    }

    fn remove_references_derived_from(
        &mut self,
        artefact: &RawIrArtefact,
    ) -> Result<(), ProjectError> {
        if artefact.header().level() != IrLevel::PCode {
            return Ok(());
        }

        let mut coverage = AddressRangeSet::new();
        for run in artefact.body().source_runs() {
            coverage.insert_range(AddressRange::point(run.machine_address()));
        }

        if coverage.is_empty() {
            return Ok(());
        }

        let revert = ReferenceRevert::capture(&self.project.references, &coverage)?;
        let touched = revert
            .previous()
            .iter()
            .any(|reference| reference.origin().is_derived() && reference.kind().is_data());

        if !touched {
            return Ok(());
        }

        self.project.references.replace_derived_in_class(
            revert.previous(),
            [],
            ReferenceClass::Data,
        )?;
        self.reference_reverts.push(revert);
        self.records
            .push(ChangeRecord::ReferencesChanged { coverage });

        Ok(())
    }

    pub fn remove_ir_artefacts_from(
        &mut self,
        function: FunctionId,
        first_invalid: IrLevel,
    ) -> Result<usize, ProjectError> {
        let mut removed = 0usize;

        for level in first_invalid.descendants_from() {
            if self.remove_ir_artefact(function, level)? {
                removed += 1;
            }
        }

        Ok(removed)
    }

    pub fn remove_ir_artefacts_in_range(
        &mut self,
        range: &AddressRange,
        first_invalid: IrLevel,
    ) -> Result<usize, ProjectError> {
        let functions = self
            .project
            .functions
            .ids_intersecting_range(&self.project.blocks, range);
        let mut removed = 0usize;

        for function in functions {
            removed += self.remove_ir_artefacts_from(function, first_invalid)?;
        }

        Ok(removed)
    }

    pub fn ensure_ir(
        &mut self,
        function: FunctionId,
        level: IrLevel,
        status: &dyn BuildCancellation,
    ) -> Result<bool, ProjectError> {
        if status.is_cancelled() {
            return Err(IlError::cancelled().into());
        }

        match level {
            IrLevel::PCode => self.ensure_pcode(function, status),
            IrLevel::Llil => self.ensure_llil(function, status),
            IrLevel::LlilSsa => self.ensure_llil_ssa(function, status),
            IrLevel::MappedMlil | IrLevel::Mlil => {
                Err(IlError::mlil_build_scheduling_unsupported().into())
            }
        }
    }

    pub fn ensure_pcode(
        &mut self,
        function: FunctionId,
        status: &dyn BuildCancellation,
    ) -> Result<bool, ProjectError> {
        if status.is_cancelled() {
            return Err(IlError::cancelled().into());
        }

        self.ensure_pcode_body(function, status)
            .map(|(published, _)| published)
    }

    fn ensure_pcode_body(
        &mut self,
        function: FunctionId,
        status: &dyn BuildCancellation,
    ) -> Result<(bool, PCodeBody), ProjectError> {
        if let Some(body) = self.ir_body_for_output::<PCodeBody>(function)? {
            return Ok((false, body));
        }

        if function.is_invalid() {
            return Err(IlError::missing_artefact(function, IrLevel::PCode).into());
        }

        let body = self.build_pcode(function, status);
        self.scratch.reset();
        let mut body = body?;
        self.publish_ir_body(&mut body)?;
        Ok((true, body))
    }

    fn build_pcode(
        &mut self,
        function: FunctionId,
        status: &dyn BuildCancellation,
    ) -> Result<PCodeBody, ProjectError> {
        let Some(function_body) = self.project.functions.get_by_id(function) else {
            return Err(IlError::missing_artefact(function, IrLevel::PCode).into());
        };

        let mut lifter = Lifter::new(self.project.language);
        let mut code_block_ids = Vec::new();
        let mut block_id_by_code_block = BTreeMap::new();

        for (_, code_block) in function_body.blocks() {
            let block_id = BlockId::try_from_index(code_block_ids.len())?;
            block_id_by_code_block.insert(code_block, block_id);
            code_block_ids.push(code_block);
        }

        let header = ArtefactHeader::new(
            function,
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            self.project.semantic_revision.value(),
        );
        let mut builder = PCodeBuilder::new(header, CommonBody::default());
        let mut blocks = Vec::new();
        let mut successors = Vec::new();
        let mut source_runs = Vec::new();
        let mut annotations = Vec::new();
        let mut operations = Vec::<PCodeOp>::new();

        for code_block_id in code_block_ids {
            if status.is_cancelled() {
                return Err(IlError::cancelled().into());
            }

            let Some(code_block) = self.project.blocks.get_by_id(code_block_id) else {
                return Err(IlError::missing_artefact(function, IrLevel::PCode).into());
            };

            let block_start = builder.operation_count();

            for insn in code_block.instructions() {
                operations.clear();
                let bytes = self.scratch.bytes_with_len(insn.len());
                self.project
                    .storage
                    .segments
                    .read_bytes(insn.address(), bytes)?;
                let lifted_len = lifter.lift_into(insn.address(), bytes, &mut operations)?;
                let source_start = builder.operation_count();

                annotations.clear();
                let emitted = PCodeCanonicaliser::push_direct_target_annotations(
                    self.project.language,
                    insn.address(),
                    lifted_len,
                    &operations,
                    source_start,
                    &mut annotations,
                )?;
                let mut context = PCodeAddressContext::new(insn.address(), &annotations);
                builder.push_lifter_stream_next(
                    &operations,
                    self.project.language,
                    &mut context,
                )?;

                source_runs.push(SourceRun::new(
                    PackedRange::new(source_start, builder.operation_count())?,
                    insn.address(),
                    0,
                    u32::try_from(emitted)
                        .map_err(|_| IlError::integer_overflow("PCode source run count"))?,
                ));
            }

            let successor_start = successors.len();

            for successor in code_block.successors().iter() {
                if let Some(successor) = block_id_by_code_block.get(&successor).copied() {
                    successors.push(successor);
                }
            }

            let mut flags = 0u16;
            if code_block.address() == function_body.entry() {
                flags |= Block::ENTRY;
            }
            if code_block.successors().is_empty() {
                flags |= Block::EXIT;
            }

            blocks.push(Block::new(
                PackedRange::new(block_start, builder.operation_count())?,
                PackedRange::new(successor_start, successors.len())?,
                flags,
            ));
        }

        let common = CommonBody::new(blocks, successors, source_runs, Vec::new());
        builder.replace_common(common);

        Ok(builder.finish(status)?)
    }

    pub fn ensure_llil(
        &mut self,
        function: FunctionId,
        status: &dyn BuildCancellation,
    ) -> Result<bool, ProjectError> {
        if status.is_cancelled() {
            return Err(IlError::cancelled().into());
        }

        self.ensure_llil_body(function, status)
            .map(|(published, _)| published)
    }

    fn ensure_llil_body(
        &mut self,
        function: FunctionId,
        status: &dyn BuildCancellation,
    ) -> Result<(bool, LlilBody), ProjectError> {
        if let Some(body) = self.ir_body_for_output::<LlilBody>(function)? {
            return Ok((false, body));
        }

        let (_, source) = self.ensure_pcode_body(function, status)?;
        let mut body = {
            let mut context = TransformContext::new(status, &mut self.scratch);
            let mut transform = PCodeToLlil;
            transform.transform(&source, &mut context)?
        };

        self.publish_ir_body(&mut body)?;

        Ok((true, body))
    }

    pub fn ensure_llil_ssa(
        &mut self,
        function: FunctionId,
        status: &dyn BuildCancellation,
    ) -> Result<bool, ProjectError> {
        if self.ir_body_for_output::<SsaBody>(function)?.is_some() {
            return self.ensure_llil(function, status);
        }

        let (_, source) = self.ensure_llil_body(function, status)?;
        let mut body = {
            let mut context = TransformContext::new(status, &mut self.scratch);
            let mut transform = LlilToSsa;
            transform.transform(&source, &mut context)?
        };

        self.publish_ir_body(&mut body)?;

        Ok(true)
    }

    fn ir_body_for_output<T>(&self, function: FunctionId) -> Result<Option<T>, ProjectError>
    where
        T: IrArtefact,
    {
        match self
            .project
            .ir_body_at_revision::<T>(function, self.project.semantic_revision)
        {
            Ok(Some(artefact)) => T::from_raw_artefact(artefact)
                .map(Some)
                .map_err(ProjectError::from),
            Ok(None) => Ok(None),
            Err(ProjectError::Il(IlError::MissingArtefact { .. })) => Ok(None),
            Err(ProjectError::Il(IlError::StaleArtefact { .. })) => Ok(None),
            Err(ProjectError::Il(IlError::ParentDigestMismatch { .. })) => Ok(None),
            Err(error) => Err(error),
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
        self.remove_ir_artefacts_from(id, IrLevel::PCode)?;

        let derived = self
            .project
            .functions
            .get_by_address(entry)
            .map(|function| {
                self.project
                    .blocks
                    .flow_references(function.blocks().map(|(_, id)| id))
            })
            .unwrap_or_default();
        let reference_revert = ReferenceRevert::capture(&self.project.references, &covered)?;
        let references_touched = !derived.is_empty() || reference_revert.had_derived();
        self.project.references.replace_derived_in_class(
            reference_revert.previous(),
            derived,
            ReferenceClass::Flow,
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
            .any(|reference| reference.origin().is_derived() && reference.kind().is_flow());
        self.project.references.replace_derived_in_class(
            reference_revert.previous(),
            [],
            ReferenceClass::Flow,
        )?;
        self.reference_reverts.push(reference_revert);

        let reference_coverage = references_touched.then(|| covered.clone());

        for block in blocks {
            self.project.blocks.remove_by_id(block);
        }

        self.project.functions.remove_by_id(id);
        self.remove_ir_artefacts_from(id, IrLevel::PCode)?;
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
                if existing.origin().is_asserted()
                    && existing.kind().class() == reference.kind().class() =>
            {
                Reference::new(from, target, existing.kind().merged(reference.kind()))
            }
            _ => reference,
        };

        if let Some(existing) = existing
            && existing.origin().is_asserted()
            && existing.kind() == resolved.kind()
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
        self.remove_ir_artefacts_for_mapping(space, mapping)?;

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
        self.remove_ir_artefacts_for_mapping(space, mapping)?;

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
        self.remove_ir_artefacts_for_mapping(space, mapping)?;

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
        self.remove_ir_artefacts_for_placements(removed)?;

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
        self.remove_ir_artefacts_for_placements(removed)?;
        self.record_mapping_added_to_placements(id);
        self.remove_ir_artefacts_for_mapping_placements(id)?;

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
        self.remove_ir_artefacts_for_placements(removed)?;
        self.record_mapping_added_to_placements(id);
        self.remove_ir_artefacts_for_mapping_placements(id)?;

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
        self.remove_ir_artefacts_for_mapping(space, id)?;

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
        self.remove_ir_artefacts_for_mapping(space, id)?;

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
                self.remove_ir_artefacts_in_range(&range, IrLevel::PCode)?;
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

    fn remove_ir_artefacts_for_mapping(
        &mut self,
        space: AddressSpaceId,
        id: SegmentMappingId,
    ) -> Result<usize, ProjectError> {
        let Some(mapping) = self.project.storage.segments.mapping(id) else {
            return Ok(0);
        };

        let range = Self::mapping_range(space, mapping.start(), mapping.size());
        self.remove_ir_artefacts_in_range(&range, IrLevel::PCode)
    }

    fn remove_ir_artefacts_for_mapping_placements(
        &mut self,
        id: SegmentMappingId,
    ) -> Result<usize, ProjectError> {
        let placements = self
            .project
            .storage
            .segments
            .mapping_placements(id)
            .collect::<SmallVec<[_; 4]>>();

        self.remove_ir_artefacts_for_placements(placements)
    }

    fn remove_ir_artefacts_for_placements(
        &mut self,
        placements: impl IntoIterator<Item = (AddressSpaceId, (RawAddress, RawAddress))>,
    ) -> Result<usize, ProjectError> {
        let mut removed = 0usize;

        for (space, range) in placements {
            let range = AddressRange::new(space, range.0, range.1);
            removed += self.remove_ir_artefacts_in_range(&range, IrLevel::PCode)?;
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

    pub fn commit(mut self) -> Result<ChangeSet, ProjectError> {
        let span = self.span.clone();
        let _entered = span.enter();
        if !self.records.is_empty() {
            let revision = self.project.revision.next();
            if self.records.iter().any(ChangeRecord::affects_ir_inputs) {
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
        let _entered = self.span.enter();
        self.committed = true;
        while let Some(revert) = self.ir_artefact_reverts.pop() {
            revert.restore(self.project)?;
        }
        while let Some(revert) = self.reference_reverts.pop() {
            revert.restore(&self.project.references)?;
        }
        while let Some(revert) = self.function_reverts.pop() {
            revert.restore(
                &mut self.project.functions,
                &mut self.project.blocks,
                &mut self.project.call_graph,
            )?;
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

        let symbol_cache_bytes = attributes
            .get_attr::<usize>(ATTRIBUTE_SYMBOL_CACHE_SIZE)
            .unwrap_or(DEFAULT_SYMBOL_CACHE_BYTES);

        let mut symbols = if storage.entities.is_transient() {
            SymbolTable::new_transient()
        } else {
            match storage.write_back() {
                Some(worker) => SymbolTable::new_with(
                    storage.entities.clone(),
                    worker.clone(),
                    symbol_cache_bytes,
                ),
                None => SymbolTable::new(storage.entities.clone(), symbol_cache_bytes),
            }
            .inspect_err(|e| tracing::error!("failed to load symbol table: {e}"))?
        };

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
                        symbols.insert(index, address, entry.symbol(), entry.properties());
                    }
                }
            }
        }

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

        let call_graph = match storage.write_back() {
            Some(worker) => CallGraphIndex::new_with(storage.entities.clone(), worker.clone()),
            None => CallGraphIndex::new(storage.entities.clone())?,
        };
        call_graph.ensure_current(functions.iter(), &blocks, revision.value())?;

        let references = match storage.write_back() {
            Some(worker) => ReferenceIndex::new_with(storage.entities.clone(), worker.clone()),
            None => ReferenceIndex::new(storage.entities.clone())?,
        };
        references.ensure_current(functions.iter(), &blocks, revision.value())?;

        Ok(Self {
            arch,
            language,
            symbols,
            functions,
            blocks,
            call_graph,
            references,
            platform,
            restored_revision,
            attributes,
            revision,
            semantic_revision,
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

    pub fn semantic_revision(&self) -> Revision {
        self.semantic_revision
    }

    pub fn restored_revision(&self) -> Option<Revision> {
        self.restored_revision
    }

    pub fn ir_artefact(
        &self,
        function: FunctionId,
        level: IrLevel,
    ) -> Result<Option<RawIrArtefact>, ProjectError> {
        self.ir_artefact_at_revision(function, level, self.semantic_revision)
    }

    fn ir_artefact_at_revision(
        &self,
        function: FunctionId,
        level: IrLevel,
        revision: Revision,
    ) -> Result<Option<RawIrArtefact>, ProjectError> {
        let Some(artefact) = self.stored_ir_artefact(function, level)? else {
            return Ok(None);
        };

        artefact.header().verify_input_revision(revision.value())?;
        self.verify_ir_artefact_payload(&artefact)?;

        Ok(Some(artefact))
    }

    fn stored_ir_artefact(
        &self,
        function: FunctionId,
        level: IrLevel,
    ) -> Result<Option<RawIrArtefact>, ProjectError> {
        let key = IrArtefactKey::new(function, level);
        let Some(artefact) = self
            .storage
            .entities
            .get_as::<IrArtefactKey, RawIrArtefact, _, _>(&key, |bytes| {
                RawIrArtefact::verify_archived(bytes).map_err(EntityStorageError::decode)?;

                rkyv::from_bytes::<RawIrArtefact, rkyv::rancor::Error>(bytes)
                    .map_err(EntityStorageError::decode)
            })?
        else {
            return Ok(None);
        };

        artefact.verify_identity(function, level)?;
        artefact.verify()?;

        Ok(Some(artefact))
    }

    fn verify_ir_artefact_payload(&self, artefact: &RawIrArtefact) -> Result<(), ProjectError> {
        let level = artefact.header().level();

        match level {
            IrLevel::PCode => artefact.verify_as::<PCodeBody>()?,
            IrLevel::Llil => artefact.verify_as::<LlilBody>()?,
            IrLevel::LlilSsa => artefact.verify_as::<SsaBody>()?,
            IrLevel::MappedMlil | IrLevel::Mlil => {
                return Err(IlError::artefact_level_unsupported(level).into());
            }
        }

        self.verify_ir_parent_digest(artefact)?;

        Ok(())
    }

    fn verify_ir_parent_digest(&self, artefact: &RawIrArtefact) -> Result<(), ProjectError> {
        let level = artefact.header().level();
        let Some(parent_level) = level.parent() else {
            return Ok(());
        };

        let parent_digest = artefact.header().parent_digest();
        if parent_digest == ArtefactDigest::ZERO {
            return Err(IlError::missing_parent_digest(level).into());
        }

        let function = artefact.header().function();
        let Some(parent) = self.stored_ir_artefact(function, parent_level)? else {
            return Err(IlError::missing_artefact(function, parent_level).into());
        };

        if parent.header().content_digest() != parent_digest {
            return Err(IlError::parent_digest_mismatch(level).into());
        }

        Ok(())
    }

    fn ir_body_at_revision<T>(
        &self,
        function: FunctionId,
        revision: Revision,
    ) -> Result<Option<RawIrArtefact>, ProjectError>
    where
        T: IrArtefact,
    {
        self.ir_artefact_at_revision(function, T::LEVEL, revision)
    }

    pub fn ir_body<T>(&self, function: FunctionId) -> Result<Option<T>, ProjectError>
    where
        T: IrArtefact,
    {
        self.ir_artefact(function, T::LEVEL)?
            .map(T::from_raw_artefact)
            .transpose()
            .map_err(ProjectError::from)
    }

    pub fn pcode_body(&self, function: FunctionId) -> Result<Option<PCodeBody>, ProjectError> {
        self.ir_body(function)
    }

    pub fn llil_body(&self, function: FunctionId) -> Result<Option<LlilBody>, ProjectError> {
        self.ir_body(function)
    }

    pub fn llil_ssa_body(&self, function: FunctionId) -> Result<Option<SsaBody>, ProjectError> {
        self.ir_body(function)
    }

    pub fn llil_ssa_use_index(
        &self,
        function: FunctionId,
    ) -> Result<Option<UseIndex>, ProjectError> {
        self.llil_ssa_body(function)?
            .map(|body| body.use_index())
            .transpose()
            .map_err(ProjectError::from)
    }

    pub fn llil_ssa_dominance(
        &self,
        function: FunctionId,
    ) -> Result<Option<Dominance>, ProjectError> {
        self.llil_ssa_body(function)?
            .map(|body| body.dominance())
            .transpose()
            .map_err(ProjectError::from)
    }

    pub fn llil_ssa_dominance_frontiers(
        &self,
        function: FunctionId,
    ) -> Result<Option<DominanceFrontier>, ProjectError> {
        self.llil_ssa_body(function)?
            .map(|body| body.dominance_frontiers())
            .transpose()
            .map_err(ProjectError::from)
    }

    pub fn llil_ssa_liveness(
        &self,
        function: FunctionId,
    ) -> Result<Option<Liveness>, ProjectError> {
        self.llil_ssa_body(function)?
            .map(|body| body.liveness())
            .transpose()
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
            ir_artefact_reverts: Vec::new(),
            function_reverts: Vec::new(),
            symbol_reverts: Vec::new(),
            segment_reverts: Vec::new(),
            segment_write_reverts: Vec::new(),
            reference_reverts: Vec::new(),
            scratch: Scratch::new(IR_TRANSFORM_SCRATCH_CAP),
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
    use crate::analysis::function::recovery::{InsnEntry, PartialCodeBlock};
    #[cfg(any(feature = "sqlite", feature = "rocksdb", feature = "mdbx"))]
    use crate::attributes;
    use crate::il::common::{
        ArtefactHeader, BuildStatus, CommonBody, Finish, PackedRange, SchemaVersion, Scratch,
        SourceRun, Transform, TransformContext,
    };
    use crate::il::llil::StatementOpcode;
    use crate::il::llil::transform::PCodeToLlil;
    use crate::il::pcode::{
        AddressAnnotationRole, LifterSpaceHandle, Location, Op, Opcode, Operation,
        PCODE_SCHEMA_VERSION, PCodeBuilder, PCodeError, PCodeOp, Varnode,
    };
    use crate::ir::{Insn, InsnProperties, ReferenceTarget};
    use crate::lifter::{ContextSet, resolve_language};
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
    use crate::types::BytesOrSlice;

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

    fn pcode_reference_body(
        function: FunctionId,
        source: Address,
        target_space: AddressSpaceId,
        target_offset: u64,
        opcode: Opcode,
    ) -> Result<PCodeBody, IlError> {
        let header = ArtefactHeader::new(function, IrLevel::PCode, PCODE_SCHEMA_VERSION, 0);
        let common = CommonBody::new(
            Vec::new(),
            Vec::new(),
            vec![SourceRun::new(PackedRange::new(0, 1)?, source, 0, 1)],
            Vec::new(),
        );
        let mut builder = PCodeBuilder::new(header, common);
        let pointer = builder.push_location(Location::new(
            LifterSpaceHandle::new(0),
            target_offset,
            8,
            Location::CONSTANT,
        ))?;
        let value = builder.push_location(Location::new(
            LifterSpaceHandle::new(1),
            0,
            8,
            Location::REGISTER,
        ))?;
        let operands = match opcode {
            Opcode::Store => builder.push_operands([pointer, value])?,
            _ => builder.push_operands([pointer])?,
        };
        let output = opcode.requires_output().then_some(value);

        builder.push_operation(Operation::new(
            opcode,
            output,
            operands,
            0,
            Some(target_space),
        ));
        builder.finish(&BuildStatus::new())
    }

    fn pcode_copy_body(function: FunctionId, source: Address) -> Result<PCodeBody, IlError> {
        let header = ArtefactHeader::new(function, IrLevel::PCode, PCODE_SCHEMA_VERSION, 0);
        let common = CommonBody::new(
            Vec::new(),
            Vec::new(),
            vec![SourceRun::new(PackedRange::new(0, 1)?, source, 0, 1)],
            Vec::new(),
        );
        let mut builder = PCodeBuilder::new(header, common);
        let location = builder.push_location(Location::new(
            LifterSpaceHandle::new(1),
            0,
            8,
            Location::REGISTER,
        ))?;
        let operands = builder.push_operands([location])?;

        builder.push_operation(Operation::new(
            Opcode::Copy,
            Some(location),
            operands,
            0,
            None,
        ));
        builder.finish(&BuildStatus::new())
    }

    fn lower_test_llil(source: &PCodeBody) -> Result<LlilBody, IlError> {
        let mut scratch = Scratch::new(1024);
        let status = BuildStatus::new();
        let mut context = TransformContext::new(&status, &mut scratch);
        let mut transform = PCodeToLlil;

        transform.transform(source, &mut context)
    }

    fn flow_resolved_load_function(
        entry: Address,
        data_offset: u64,
    ) -> Result<PartialFunction, Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let operation = PCodeOp {
            op: Op::Load(language.default_space()),
            inputs: Inputs::one(Varnode::constant(data_offset, 8)),
            output: Varnode::new(language.register_space(), 0, 8),
        };
        let operations = [operation];
        let insn = Insn::from_resolved_flow(language, entry, 1, &operations)?;
        let mut function = PartialFunction::new(entry);

        match function.insn_entry(entry) {
            InsnEntry::Vacant(entry) => {
                entry.insert(insn);
            }
            InsnEntry::Occupied(_) => {
                return Err(io::Error::other("test instruction unexpectedly occupied").into());
            }
        }

        function.push_block(PartialCodeBlock::new(
            entry,
            1,
            vec![0],
            ContextSet::default(),
        ));

        Ok(function)
    }

    fn calling_function(
        entry: Address,
        callee: Address,
        length: usize,
    ) -> Result<PartialFunction, Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let operation = PCodeOp {
            op: Op::Call,
            inputs: Inputs::one(Varnode::new(language.default_space(), callee.offset(), 8)),
            output: Varnode::INVALID,
        };
        let operations = [operation];
        let insn = Insn::from_resolved_flow(language, entry, length, &operations)?;
        let mut function = PartialFunction::new(entry);

        match function.insn_entry(entry) {
            InsnEntry::Vacant(entry) => {
                entry.insert(insn);
            }
            InsnEntry::Occupied(_) => {
                return Err(io::Error::other("test instruction unexpectedly occupied").into());
            }
        }

        function.push_block(PartialCodeBlock::new(
            entry,
            length,
            vec![0],
            ContextSet::default(),
        ));

        Ok(function)
    }

    fn disassembled_function(
        entry: Address,
        length: usize,
    ) -> Result<PartialFunction, Box<dyn std::error::Error>> {
        let insn = Insn::from_disassembly(entry, length, InsnProperties::NEEDS_FLOW_RESOLUTION)?;
        let mut function = PartialFunction::new(entry);

        match function.insn_entry(entry) {
            InsnEntry::Vacant(entry) => {
                entry.insert(insn);
            }
            InsnEntry::Occupied(_) => {
                return Err(io::Error::other("test instruction unexpectedly occupied").into());
            }
        }

        function.push_block(PartialCodeBlock::new(
            entry,
            length,
            vec![0],
            ContextSet::default(),
        ));

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

    #[test]
    fn project_ir_artefact_rejects_digest_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let level = IrLevel::PCode;
        let key = IrArtefactKey::new(function, level);
        let header = ArtefactHeader::new(function, level, SchemaVersion::new(1), 0);
        let artefact = RawIrArtefact::new(header, CommonBody::default(), vec![1, 2, 3]);
        let mut bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&artefact)?.to_vec();
        let payload = bytes
            .windows(3)
            .position(|window| window == [1, 2, 3])
            .expect("payload bytes should be present");

        bytes[payload] = 9;
        project
            .storage
            .entities
            .insert_bytes::<IrArtefactKey, RawIrArtefact>(&key, BytesOrSlice::from(bytes))?;

        assert!(matches!(
            project.ir_artefact(function, level),
            Err(ProjectError::Il(IlError::DigestMismatch))
        ));

        Ok(())
    }

    #[test]
    fn project_ir_artefact_rejects_corrupt_dialect_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let level = IrLevel::PCode;
        let key = IrArtefactKey::new(function, level);
        let header = ArtefactHeader::new(function, level, PCODE_SCHEMA_VERSION, 0);
        let artefact = RawIrArtefact::new(header, CommonBody::default(), vec![1, 2, 3]);

        project.storage.entities.insert(&key, &artefact)?;

        assert!(matches!(
            project.ir_artefact(function, level),
            Err(ProjectError::Il(IlError::ArtefactDecode {
                level: IrLevel::PCode
            }))
        ));

        Ok(())
    }

    #[test]
    fn project_ir_artefact_rejects_unsupported_dialect_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();

        for level in [IrLevel::MappedMlil, IrLevel::Mlil] {
            let key = IrArtefactKey::new(function, level);
            let header = ArtefactHeader::new(function, level, SchemaVersion::new(1), 0);
            let artefact = RawIrArtefact::new(header, CommonBody::default(), Vec::new());

            project.storage.entities.insert(&key, &artefact)?;

            assert!(matches!(
                project.ir_artefact(function, level),
                Err(ProjectError::Il(IlError::ArtefactLevelUnsupported { level: found }))
                    if found == level
            ));
        }

        Ok(())
    }

    #[test]
    fn project_ir_artefact_rejects_stale_input_revision() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let level = IrLevel::PCode;
        let stale_revision = project.revision().value();
        {
            let mut transaction = project.transaction("test");
            transaction.create_space()?;
            transaction.commit()?;
        }

        let key = IrArtefactKey::new(function, level);
        let header = ArtefactHeader::new(function, level, SchemaVersion::new(1), stale_revision);
        let artefact = RawIrArtefact::new(header, CommonBody::default(), Vec::new());
        project.storage.entities.insert(&key, &artefact)?;

        assert!(matches!(
            project.ir_artefact(function, level),
            Err(ProjectError::Il(IlError::StaleArtefact { .. }))
        ));

        Ok(())
    }

    #[test]
    fn project_ir_artefact_rejects_wrong_stored_level() -> Result<(), Box<dyn std::error::Error>> {
        let project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let key = IrArtefactKey::new(function, IrLevel::PCode);
        let header = ArtefactHeader::new(function, IrLevel::Llil, SchemaVersion::new(1), 0);
        let artefact = RawIrArtefact::new(header, CommonBody::default(), Vec::new());

        project.storage.entities.insert(&key, &artefact)?;

        assert!(matches!(
            project.ir_artefact(function, IrLevel::PCode),
            Err(ProjectError::Il(IlError::UnexpectedLevel {
                expected: IrLevel::PCode,
                found: IrLevel::Llil,
            }))
        ));

        Ok(())
    }

    #[test]
    fn project_ir_artefact_rejects_wrong_stored_function() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project)?;
        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(disassembled_function(entry, 1)?)?;

            transaction.commit()?;

            function
        };
        let key = IrArtefactKey::new(function, IrLevel::PCode);
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            SchemaVersion::new(1),
            0,
        );
        let artefact = RawIrArtefact::new(header, CommonBody::default(), Vec::new());

        project.storage.entities.insert(&key, &artefact)?;

        assert!(matches!(
            project.ir_artefact(function, IrLevel::PCode),
            Err(ProjectError::Il(IlError::UnexpectedFunction { expected, found }))
                if expected == function && found == FunctionId::default()
        ));

        Ok(())
    }

    #[test]
    fn project_remove_ir_artefact_clears_derived_data_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target_space = AddressSpaceId::new(2);
        let target = Address::new(target_space, 0x4000u64);
        let mut load = pcode_reference_body(function, source, target_space, 0x4000, Opcode::Load)?;

        {
            let mut transaction = project.transaction("test");
            transaction.publish_ir_body(&mut load)?;
            assert!(transaction.flush_ir_references(function)?);
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
            assert!(transaction.remove_ir_artefact(function, IrLevel::PCode)?);
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
            transaction.publish_ir_body(&mut load)?;
            assert!(transaction.flush_ir_references(function)?);
            transaction.commit()?;
        }

        {
            let mut transaction = project.transaction("test");
            assert!(transaction.remove_ir_artefact(function, IrLevel::PCode)?);
            transaction.rollback()?;
        }

        let restored = project
            .references
            .get(source, ReferenceTarget::from(target))?
            .expect("rollback should restore the artefact's derived data reference");
        assert!(restored.kind().is_read());
        assert!(project.ir_artefact(function, IrLevel::PCode)?.is_some());

        Ok(())
    }

    #[test]
    fn project_flush_ir_references_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target_space = AddressSpaceId::new(2);
        let mut load = pcode_reference_body(function, source, target_space, 0x4000, Opcode::Load)?;

        {
            let mut transaction = project.transaction("test");
            transaction.publish_ir_body(&mut load)?;
            assert!(transaction.flush_ir_references(function)?);
            transaction.commit()?;
        }

        let changes = {
            let mut transaction = project.transaction("test");
            assert!(!transaction.flush_ir_references(function)?);
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
    fn project_flush_ir_references_replaces_derived_data_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target_space = AddressSpaceId::new(2);
        let target = Address::new(target_space, 0x4000u64);
        let mut load = pcode_reference_body(function, source, target_space, 0x4000, Opcode::Load)?;
        let mut copy = pcode_copy_body(function, source)?;

        let changes = {
            let mut transaction = project.transaction("test");
            assert!(!transaction.flush_ir_references(function)?);
            transaction.publish_ir_body(&mut load)?;
            assert!(transaction.flush_ir_references(function)?);
            transaction.commit()?
        };

        let reference = project
            .references
            .get(source, ReferenceTarget::from(target))?
            .expect("flushing PCode references should install a derived data reference");
        assert!(reference.kind().is_read());
        assert!(reference.origin().is_derived());

        let incoming = project
            .references
            .references_to(ReferenceTarget::from(target), None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert!(
            incoming
                .iter()
                .any(|reference| reference.from() == source && reference.kind().is_read()),
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
            transaction.publish_ir_body(&mut copy)?;
            assert!(transaction.flush_ir_references(function)?);
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
    fn project_flush_ir_references_rolls_back() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target_space = AddressSpaceId::new(2);
        let target = Address::new(target_space, 0x4000u64);
        let mut load = pcode_reference_body(function, source, target_space, 0x4000, Opcode::Load)?;
        let mut store =
            pcode_reference_body(function, source, target_space, 0x4000, Opcode::Store)?;

        {
            let mut transaction = project.transaction("test");
            transaction.publish_ir_body(&mut load)?;
            assert!(transaction.flush_ir_references(function)?);
            transaction.commit()?;
        }

        {
            let mut transaction = project.transaction("test");
            transaction.publish_ir_body(&mut store)?;
            assert!(transaction.flush_ir_references(function)?);
            transaction.rollback()?;
        }

        let reference = project
            .references
            .get(source, ReferenceTarget::from(target))?
            .expect("rollback should restore the previous derived reference");
        assert!(reference.kind().is_read());
        assert!(!reference.kind().is_write());

        Ok(())
    }

    #[test]
    fn project_function_add_does_not_publish_flow_resolved_data_references()
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
        assert!(flow.kind().is_call());

        {
            let mut transaction = project.transaction("test");
            transaction
                .ensure_pcode(function, &BuildStatus::new())
                .expect("ensure pcode");
            transaction.commit()?;
        }

        let preserved = project
            .references
            .get(entry, ReferenceTarget::from(callee))?
            .expect("publishing PCode should preserve the call flow reference");
        assert!(preserved.kind().is_call());

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

        let published_pcode = {
            let mut transaction = project.transaction("test");
            let published = transaction.ensure_pcode(function, &BuildStatus::new())?;
            transaction.commit()?;
            published
        };
        let published_llil = {
            let mut transaction = project.transaction("test");
            let published = transaction.ensure_llil(function, &BuildStatus::new())?;
            transaction.commit()?;
            published
        };
        let body = project
            .pcode_body(function)?
            .expect("PCode body should be published");
        let llil = project
            .llil_body(function)?
            .expect("LLIL body should be published");

        assert!(published_pcode);
        assert!(published_llil);
        assert!(!body.operations().is_empty());
        assert_eq!(body.common().source_runs().len(), 1);
        assert_eq!(body.common().source_runs()[0].machine_address(), entry);
        assert!(
            llil.statements()
                .iter()
                .any(|statement| statement.opcode() == StatementOpcode::WriteRegister)
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
            transaction.ensure_pcode(function, &BuildStatus::new())?;
            transaction.commit()?;
        }

        let body = project
            .pcode_body(function)?
            .expect("PCode body should be published");
        let source_runs = body.common().source_runs();

        assert!(body.operations().is_empty());
        assert_eq!(source_runs.len(), 1);
        assert_eq!(source_runs[0].machine_address(), entry);
        assert!(source_runs[0].destination().is_empty());
        assert_eq!(source_runs[0].pcode_count(), 0);

        Ok(())
    }

    #[test]
    fn project_ensure_pcode_rejects_missing_computed_space()
    -> Result<(), Box<dyn std::error::Error>> {
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
        let result = transaction.ensure_pcode(function, &BuildStatus::new());

        match result {
            Err(ProjectError::PCode(PCodeError::MissingAnnotation {
                role: AddressAnnotationRole::ComputedSpace,
                ..
            })) => {}
            other => panic!("unexpected ensure_pcode result: {other:?}"),
        }

        assert_eq!(transaction.scratch.bytes().len(), 0);

        transaction.rollback()?;

        Ok(())
    }

    #[test]
    fn project_llil_publish_preserves_flushed_references() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target_space = AddressSpaceId::new(2);
        let target = Address::new(target_space, 0x4000u64);
        let mut pcode = pcode_reference_body(function, source, target_space, 0x4000, Opcode::Load)?;

        {
            let mut transaction = project.transaction("test");
            transaction.publish_ir_body(&mut pcode)?;
            assert!(transaction.flush_ir_references(function)?);
            transaction.commit()?;
        }

        let pcode = project
            .pcode_body(function)?
            .expect("PCode body should be published");
        let mut llil = lower_test_llil(&pcode)?;

        {
            let mut transaction = project.transaction("test");
            transaction.publish_ir_body(&mut llil)?;
            transaction.commit()?;
        }

        let reference = project
            .references
            .get(source, ReferenceTarget::from(target))?
            .expect("LLIL publication should not remove PCode-derived references");
        assert!(reference.kind().is_read());
        assert!(reference.origin().is_derived());

        Ok(())
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
