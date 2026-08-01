use std::collections::{BTreeMap, BTreeSet};
use std::{mem, thread};

use bytes::Bytes;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use tracing::Span;

use super::segment::SegmentMetadataStage;
use super::{Project, ProjectError};
use crate::engine::ReadSet;
use crate::engine::change::{
    ChangeCategory, ChangeKinds, ChangeRecord, ChangeSet, ChangeSource, FunctionChangeKind,
    MAX_DETAILED_CHANGE_RECORDS, Revision,
};
use crate::il::common::{IlError, IlLevel};
use crate::il::ecode::ECodeIr;
use crate::il::ecode::ssa::ECodeSsaIr;
use crate::il::pcode::PCodeIr;
use crate::il::storage::{IlStage, StagedIl};
use crate::ir::{
    Address, AddressRange, AddressRangeSet, CallGraphStage, CodeBlockTable, Function, FunctionId,
    FunctionMaterialisation, FunctionProperties, FunctionRef, FunctionTable, FunctionTableStage,
    IncompleteFunction, IncompleteFunctionError, Problem, ProblemKey, ProblemKind, ProblemScope,
    ProblemTable, RawAddress, Reference, ReferenceIndex, ReferenceKey, ReferenceKind,
    ReferenceOrigin, ReferenceTarget, Switch, SwitchId, SwitchRef, SwitchTable, SymbolEntry,
    SymbolId, SymbolIndex, SymbolIndexState, SymbolProperties, SymbolTable,
};
use crate::storage::SegmentStorageError;
use crate::storage::entities::{EntityWrite, EntityWriteBatch, schema};
use crate::storage::segments::mapping::{
    SegmentMappingBuilder, SegmentMappingFlags, SegmentMappingId, SegmentMappingKind,
    SegmentMappingProvenance,
};
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::segments::{SegmentStorage, SegmentWriteRevert};

struct PreparedProblemMutation {
    encoded_len: usize,
    is_new: bool,
    key: ProblemKey,
    problem: Option<Problem>,
}

struct PreparedSwitchMutation {
    branch: Address,
    encoded_len: usize,
    previous: Option<PreviousSwitch>,
    switch: Option<Switch>,
}

#[derive(Clone, Copy)]
struct PreviousSwitch {
    function: FunctionId,
    id: SwitchId,
}

struct PreparedSymbolMutation {
    encoded_len: usize,
    entry: Option<SymbolEntry>,
    id: SymbolId,
    previous: Option<SymbolIndexState>,
}

struct PreparedReferenceMutation {
    encoded_len: usize,
    key: ReferenceKey,
    previous: Option<Reference>,
    reference: Option<Reference>,
}

#[derive(Clone, Copy)]
struct StagedReferenceMutation {
    previous: Option<Reference>,
    reference: Option<Reference>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum StagedChangeKey {
    Function(Address),
    SegmentMapped(SegmentMappingId, AddressRange),
    SegmentMappingChanged(SegmentMappingId),
    SegmentMappingCreated(SegmentMappingId),
    SegmentUnmapped(SegmentMappingId, AddressRange),
}

impl StagedChangeKey {
    fn for_record(record: &ChangeRecord) -> Option<Self> {
        match record {
            ChangeRecord::FunctionAdded { entry, .. }
            | ChangeRecord::FunctionChanged { entry, .. }
            | ChangeRecord::FunctionRemoved { entry, .. } => Some(Self::Function(*entry)),
            ChangeRecord::SegmentMapped { mapping, range } => {
                Some(Self::SegmentMapped(*mapping, *range))
            }
            ChangeRecord::SegmentMappingChanged { mapping } => {
                Some(Self::SegmentMappingChanged(*mapping))
            }
            ChangeRecord::SegmentMappingCreated { mapping } => {
                Some(Self::SegmentMappingCreated(*mapping))
            }
            ChangeRecord::SegmentUnmapped { mapping, range } => {
                Some(Self::SegmentUnmapped(*mapping, *range))
            }
            _ => None,
        }
    }
}

#[derive(Default)]
struct StagedChanges {
    collapsed: bool,
    indices: FxHashMap<StagedChangeKey, usize>,
    kind_counts: [usize; u32::BITS as usize],
    kinds: ChangeKinds,
    records: Vec<ChangeRecord>,
    semantic_count: usize,
}

impl StagedChanges {
    fn reserve(&mut self, additional: usize) {
        let additional = additional.min(MAX_DETAILED_CHANGE_RECORDS);
        self.indices.reserve(additional);
        self.records.reserve(additional);
    }

    fn push(&mut self, record: ChangeRecord) {
        if self.collapsed {
            self.kinds |= record.kind();
            self.semantic_count += usize::from(record.affects_lifted_inputs());
            return;
        }

        if let Some(key) = StagedChangeKey::for_record(&record)
            && let Some(index) = self.indices.get(&key).copied()
        {
            let previous = mem::replace(
                &mut self.records[index],
                ChangeRecord::Resynchronise {
                    to: Revision::new(0),
                },
            );
            self.remove_metadata(&previous);
            match Self::coalesce(previous, record) {
                Some(record) => {
                    self.add_metadata(&record);
                    self.records[index] = record;
                }
                None => {
                    self.records.swap_remove(index);
                    self.indices.remove(&key);
                    if let Some(record) = self.records.get(index)
                        && let Some(moved) = StagedChangeKey::for_record(record)
                        && let Some(position) = self.indices.get_mut(&moved)
                    {
                        *position = index;
                    }
                }
            }
            return;
        }

        if self.records.len() == MAX_DETAILED_CHANGE_RECORDS {
            self.kinds |= record.kind();
            self.semantic_count += usize::from(record.affects_lifted_inputs());
            self.records.clear();
            self.indices.clear();
            self.kind_counts.fill(0);
            self.records.push(ChangeRecord::Resynchronise {
                to: Revision::new(0),
            });
            self.collapsed = true;
        } else {
            self.add_metadata(&record);
            if let Some(key) = StagedChangeKey::for_record(&record) {
                self.indices.insert(key, self.records.len());
            }
            self.records.push(record);
        }
    }

    fn coalesce(previous: ChangeRecord, current: ChangeRecord) -> Option<ChangeRecord> {
        let merge_coverage = |mut previous: AddressRangeSet, current: AddressRangeSet| {
            for range in current.ranges() {
                previous.insert_range(range);
            }
            previous
        };

        match (previous, current) {
            (
                ChangeRecord::FunctionAdded { entry, coverage },
                ChangeRecord::FunctionAdded {
                    coverage: current, ..
                }
                | ChangeRecord::FunctionChanged {
                    coverage: current, ..
                },
            ) => Some(ChangeRecord::FunctionAdded {
                entry,
                coverage: merge_coverage(coverage, current),
            }),
            (ChangeRecord::FunctionAdded { .. }, ChangeRecord::FunctionRemoved { .. }) => None,
            (
                ChangeRecord::FunctionChanged {
                    entry,
                    kind,
                    coverage,
                },
                ChangeRecord::FunctionAdded {
                    coverage: current, ..
                },
            ) => Some(ChangeRecord::FunctionChanged {
                entry,
                kind,
                coverage: merge_coverage(coverage, current),
            }),
            (
                ChangeRecord::FunctionChanged {
                    entry,
                    kind,
                    coverage,
                },
                ChangeRecord::FunctionChanged {
                    kind: current_kind,
                    coverage: current,
                    ..
                },
            ) => Some(ChangeRecord::FunctionChanged {
                entry,
                kind: if kind == FunctionChangeKind::Body
                    || current_kind == FunctionChangeKind::Body
                {
                    FunctionChangeKind::Body
                } else {
                    FunctionChangeKind::Properties
                },
                coverage: merge_coverage(coverage, current),
            }),
            (
                ChangeRecord::FunctionChanged {
                    entry, coverage, ..
                },
                ChangeRecord::FunctionRemoved {
                    coverage: current, ..
                },
            ) => Some(ChangeRecord::FunctionRemoved {
                entry,
                coverage: merge_coverage(coverage, current),
            }),
            (
                ChangeRecord::FunctionRemoved { entry, coverage },
                ChangeRecord::FunctionAdded {
                    coverage: current, ..
                }
                | ChangeRecord::FunctionChanged {
                    coverage: current, ..
                },
            ) => Some(ChangeRecord::FunctionChanged {
                entry,
                kind: FunctionChangeKind::Body,
                coverage: merge_coverage(coverage, current),
            }),
            (
                ChangeRecord::FunctionRemoved { entry, coverage },
                ChangeRecord::FunctionRemoved {
                    coverage: current, ..
                },
            ) => Some(ChangeRecord::FunctionRemoved {
                entry,
                coverage: merge_coverage(coverage, current),
            }),
            (previous, _) => Some(previous),
        }
    }

    fn add_metadata(&mut self, record: &ChangeRecord) {
        let bits = record.kind().bits();
        for index in 0..u32::BITS {
            let bit = 1u32 << index;
            if bits & bit == 0 {
                continue;
            }
            self.kind_counts[index as usize] += 1;
            self.kinds.insert(ChangeKinds::from_bits_retain(bit));
        }
        self.semantic_count += usize::from(record.affects_lifted_inputs());
    }

    fn remove_metadata(&mut self, record: &ChangeRecord) {
        let bits = record.kind().bits();
        for index in 0..u32::BITS {
            let bit = 1u32 << index;
            if bits & bit == 0 {
                continue;
            }
            let count = &mut self.kind_counts[index as usize];
            *count = count
                .checked_sub(1)
                .expect("staged change metadata count must match its records");
            if *count == 0 {
                self.kinds.remove(ChangeKinds::from_bits_retain(bit));
            }
        }
        self.semantic_count -= usize::from(record.affects_lifted_inputs());
    }

    fn clear(&mut self) {
        self.collapsed = false;
        self.indices.clear();
        self.kind_counts.fill(0);
        self.kinds = ChangeKinds::empty();
        self.records.clear();
        self.semantic_count = 0;
    }

    fn finish(mut self, revision: Revision, source: ChangeSource) -> ChangeSet {
        if self.collapsed {
            self.records[0] = ChangeRecord::Resynchronise { to: revision };
        }

        ChangeSet::with_records(revision, self.records).with_provenance(source)
    }

    fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn is_collapsed(&self) -> bool {
        self.collapsed
    }

    fn kinds(&self) -> ChangeKinds {
        self.kinds
    }

    fn records(&self) -> &[ChangeRecord] {
        &self.records
    }

    fn semantic(&self) -> bool {
        self.semantic_count != 0
    }
}

pub struct ProjectTransaction<'p> {
    project: &'p mut Project,
    changes: StagedChanges,
    reads: ReadSet,
    reads_collapsed: bool,
    il_stage: IlStage,
    function_stage: FunctionTableStage,
    call_graph_stage: CallGraphStage,
    symbol_mutations: BTreeMap<SymbolId, Option<SymbolEntry>>,
    symbol_indices: BTreeMap<SymbolIndex, Option<SymbolId>>,
    symbol_reservations: Vec<SymbolId>,
    cancelled_symbols: Vec<SymbolId>,
    segment_stage: SegmentMetadataStage,
    segment_write_reverts: Vec<SegmentWriteRevert>,
    reference_mutations: BTreeMap<ReferenceKey, StagedReferenceMutation>,
    asserted_references: BTreeSet<ReferenceKey>,
    derived_reference_coverage: AddressRangeSet,
    problem_mutations: BTreeMap<ProblemKey, Option<Problem>>,
    switch_mutations: BTreeMap<Address, Option<Switch>>,
    switch_reservations: Vec<SwitchId>,
    cancelled_switches: Vec<SwitchId>,
    source: ChangeSource,
    worker_limit: usize,
    committed: bool,
    span: Span,
}

impl Drop for ProjectTransaction<'_> {
    fn drop(&mut self) {
        let span = self.span.clone();
        let _entered = span.enter();
        if !self.committed
            && let Err(error) = self.restore_eager_writes()
        {
            tracing::error!("failed to roll back an abandoned transaction: {error}");
            self.project.abandon_persistence();
        }
    }
}

impl ProjectTransaction<'_> {
    pub(super) fn new(project: &mut Project, source: ChangeSource) -> ProjectTransaction<'_> {
        let span = tracing::debug_span!("project_transaction", reason = source.label());

        ProjectTransaction {
            project,
            changes: StagedChanges::default(),
            reads: ReadSet::new(),
            reads_collapsed: false,
            il_stage: IlStage::default(),
            function_stage: FunctionTableStage::default(),
            call_graph_stage: CallGraphStage::default(),
            symbol_mutations: BTreeMap::new(),
            symbol_indices: BTreeMap::new(),
            symbol_reservations: Vec::new(),
            cancelled_symbols: Vec::new(),
            segment_stage: SegmentMetadataStage::default(),
            segment_write_reverts: Vec::new(),
            reference_mutations: BTreeMap::new(),
            asserted_references: BTreeSet::new(),
            derived_reference_coverage: AddressRangeSet::new(),
            problem_mutations: BTreeMap::new(),
            switch_mutations: BTreeMap::new(),
            switch_reservations: Vec::new(),
            cancelled_switches: Vec::new(),
            source,
            worker_limit: 1,
            committed: false,
            span,
        }
    }

    pub(crate) fn set_worker_limit(&mut self, limit: usize) {
        self.worker_limit = limit.max(1);
    }

    pub(crate) fn materialise_lifted<T>(&mut self, mut ir: T) -> Result<(), ProjectError>
    where
        T: StagedIl,
    {
        if self.changes.semantic() {
            return Err(IlError::publish_after_semantic_mutation().into());
        }

        ir.metadata_mut()
            .set_input_revision(self.project.semantic_revision());

        self.il_stage.replace(&self.project.storage, ir)?;

        Ok(())
    }

    pub(crate) fn replace_derived_references(
        &mut self,
        coverage: AddressRangeSet,
        kind: ReferenceKind,
        derived: impl IntoIterator<Item = Reference>,
    ) -> Result<bool, ProjectError> {
        self.replace_derived_reference_batches(vec![(
            coverage,
            kind,
            derived.into_iter().collect(),
        )])
    }

    fn replace_derived_reference_batches(
        &mut self,
        mut replacements: Vec<(AddressRangeSet, ReferenceKind, Vec<Reference>)>,
    ) -> Result<bool, ProjectError> {
        let mut combined_coverage = AddressRangeSet::new();
        let flow_reference_count = replacements
            .iter()
            .filter(|(_, kind, _)| kind.is_flow())
            .map(|(_, _, derived)| derived.len())
            .sum();
        let mut supported_flow = FxHashMap::<ReferenceKey, Reference>::with_capacity_and_hasher(
            flow_reference_count,
            Default::default(),
        );
        for (coverage, _, derived) in &mut replacements {
            for reference in derived {
                coverage.insert_range(AddressRange::point(reference.from()));
            }
            for range in coverage.ranges() {
                combined_coverage.insert_range(range);
            }
        }
        for (_, kind, derived) in &replacements {
            if !kind.is_flow() {
                continue;
            }
            for &reference in derived {
                let key = ReferenceKey::new(reference.from(), reference.target());
                supported_flow
                    .entry(key)
                    .and_modify(|supported| {
                        *supported = supported.with_merged_properties(reference.properties());
                    })
                    .or_insert(reference);
            }
        }

        if combined_coverage.is_empty() {
            return Ok(false);
        }

        let mut current = self
            .staged_references_in(&combined_coverage)?
            .into_iter()
            .map(|reference| {
                (
                    ReferenceKey::new(reference.from(), reference.target()),
                    reference,
                )
            })
            .collect::<BTreeMap<_, _>>();
        if current.is_empty() {
            let mut changed = false;
            for (coverage, _, derived) in replacements {
                if derived.is_empty() {
                    continue;
                }
                for reference in derived {
                    let key = ReferenceKey::new(reference.from(), reference.target());
                    self.stage_reference_mutation(key, None, Some(reference));
                }
                for range in coverage.ranges() {
                    self.derived_reference_coverage.insert_range(range);
                }
                changed = true;
            }
            return Ok(changed);
        }

        let mut changed = false;

        for (coverage, kind, derived) in replacements {
            let mut covered = Vec::new();
            for range in coverage.ranges() {
                let start = ReferenceKey::minimum_for(range.start_address());
                for (&key, &reference) in current.range(start..) {
                    if key.from() > range.end_address() {
                        break;
                    }
                    covered.push(reference);
                }
            }
            if covered.is_empty() {
                if derived.is_empty() {
                    continue;
                }
                for reference in derived {
                    let key = ReferenceKey::new(reference.from(), reference.target());
                    current.insert(key, reference);
                    self.stage_reference_mutation(key, None, Some(reference));
                }
                for range in coverage.ranges() {
                    self.derived_reference_coverage.insert_range(range);
                }
                changed = true;
                continue;
            }
            if ReferenceIndex::derived_kind_matches(&covered, &derived, kind) {
                continue;
            }

            let mut occupied = BTreeSet::new();
            for reference in covered {
                let key = ReferenceKey::new(reference.from(), reference.target());
                if reference.origin().is_derived() && reference.kind() == kind {
                    let supported = match supported_flow.get(&key) {
                        Some(&supported) => Some(supported),
                        None if kind.is_flow() => {
                            self.function_stage.supported_backing_flow_reference(
                                &self.project.functions,
                                &self.project.blocks,
                                reference,
                            )?
                        }
                        None => None,
                    };
                    if let Some(supported) = supported {
                        current.insert(key, supported);
                        if supported != reference {
                            self.stage_reference_mutation(key, Some(reference), Some(supported));
                        }
                        continue;
                    }
                    current.remove(&key);
                    self.stage_reference_mutation(key, Some(reference), None);
                } else {
                    occupied.insert(key);
                }
            }
            for reference in derived {
                let key = ReferenceKey::new(reference.from(), reference.target());
                if !occupied.contains(&key) {
                    current.insert(key, reference);
                    self.stage_reference_mutation(key, None, Some(reference));
                }
            }

            for range in coverage.ranges() {
                self.derived_reference_coverage.insert_range(range);
            }
            changed = true;
        }

        Ok(changed)
    }

    pub fn remove_lifted(
        &mut self,
        function: FunctionId,
        level: IlLevel,
    ) -> Result<bool, ProjectError> {
        let removed = match level {
            IlLevel::PCode => {
                let Some(previous) = self
                    .il_stage
                    .remove::<PCodeIr>(&self.project.storage, function)?
                else {
                    return Ok(false);
                };

                let mut coverage = AddressRangeSet::new();
                for source in previous.source_spans() {
                    coverage.insert_range(AddressRange::point(source.address()));
                }
                self.replace_derived_references(coverage, ReferenceKind::Data, [])?;
                true
            }
            IlLevel::ECode => {
                let Some(_) = self
                    .il_stage
                    .remove::<ECodeIr>(&self.project.storage, function)?
                else {
                    return Ok(false);
                };

                true
            }
            IlLevel::ECodeSsa => {
                let Some(_) = self
                    .il_stage
                    .remove::<ECodeSsaIr>(&self.project.storage, function)?
                else {
                    return Ok(false);
                };

                true
            }
        };

        Ok(removed)
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

    pub fn project(&mut self, kinds: ChangeKinds) -> &Project {
        self.reads.record_unbounded(kinds);
        self.project
    }

    fn record_read(&mut self, kinds: ChangeKinds, range: AddressRange) {
        self.reads_collapsed |= self.reads.record(kinds, range);
    }

    fn record_unbounded_read(&mut self, kinds: ChangeKinds) {
        self.reads.record_unbounded(kinds);
    }

    pub fn function_at(
        &mut self,
        address: Address,
    ) -> Result<Option<FunctionRef<'_>>, ProjectError> {
        self.record_read(ChangeKinds::FUNCTIONS, AddressRange::point(address));
        self.project
            .functions
            .staged_by_address(&self.function_stage, address)
            .map(|function| function.map(crate::storage::EntityRef::owned))
            .map_err(ProjectError::from)
    }

    pub fn function_callees(&mut self, entry: Address) -> Result<Vec<Address>, ProjectError> {
        self.record_read(ChangeKinds::FUNCTIONS, AddressRange::point(entry));
        if let Some(callees) = self.call_graph_stage.function_edges(entry) {
            return Ok(callees.iter().copied().collect());
        }

        self.project
            .call_graph
            .callees(entry, None)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(ProjectError::from)
    }

    pub fn switch_at(&mut self, branch: Address) -> Option<SwitchRef<'_>> {
        self.record_read(ChangeKinds::SWITCHES, AddressRange::point(branch));
        match self.switch_mutations.get(&branch) {
            Some(Some(switch)) => Some(crate::storage::EntityRef::owned(switch.clone())),
            Some(None) => None,
            None => self.project.switches().get_by_branch(branch),
        }
    }

    pub fn has_problem(&mut self, address: Address) -> bool {
        self.record_read(ChangeKinds::PROBLEMS, AddressRange::point(address));
        if self
            .problem_mutations
            .iter()
            .any(|(key, problem)| key.address() == Some(address) && problem.is_some())
        {
            return true;
        }

        self.project
            .problems()
            .keys()
            .filter(|key| key.address() == Some(address))
            .any(|key| !self.problem_mutations.contains_key(&key))
    }

    pub fn functions(&mut self) -> &FunctionTable {
        self.record_unbounded_read(ChangeKinds::FUNCTIONS);
        self.project.functions()
    }

    pub fn blocks(&mut self) -> &CodeBlockTable {
        self.record_unbounded_read(ChangeKinds::FUNCTIONS);
        self.project.blocks()
    }

    pub fn symbols(&mut self) -> &SymbolTable {
        self.record_unbounded_read(ChangeKinds::SYMBOLS);
        self.project.symbols()
    }

    pub fn switches(&mut self) -> &SwitchTable {
        self.record_unbounded_read(ChangeKinds::SWITCHES);
        self.project.switches()
    }

    pub fn problems(&mut self) -> &ProblemTable {
        self.record_unbounded_read(ChangeKinds::PROBLEMS);
        self.project.problems()
    }

    pub fn segments(&mut self) -> &SegmentStorage {
        self.record_unbounded_read(ChangeKinds::SEGMENTS | ChangeKinds::SPACE_CREATED);
        self.project.segments()
    }

    pub fn absorb_reads(&mut self, reads: &ReadSet) {
        self.reads_collapsed |= self.reads.merge(reads);
    }

    pub(crate) fn take_reads(&mut self) -> ReadSet {
        mem::take(&mut self.reads)
    }

    pub(crate) fn reads_collapsed(&self) -> bool {
        self.reads_collapsed
    }

    pub fn add_function(
        &mut self,
        function: IncompleteFunction,
    ) -> Result<FunctionId, ProjectError> {
        let (id, coverage, references) = self.stage_function_replacement(function)?;
        self.replace_derived_references(coverage, ReferenceKind::Flow, references)?;
        Ok(id)
    }

    pub(crate) fn add_functions(
        &mut self,
        functions: impl IntoIterator<Item = IncompleteFunction>,
    ) -> Result<(), ProjectError> {
        let revision = self.project.revision();
        let functions = functions.into_iter();
        if self.worker_limit == 1 {
            return self.stage_function_batch(functions.map(|function| {
                function
                    .with_input_revision(revision)
                    .prepare_materialisation()
            }));
        }

        let functions = functions.collect::<Vec<_>>();
        let workers = thread::available_parallelism()
            .map_or(1, usize::from)
            .min(self.worker_limit)
            .min(functions.len());
        if workers <= 1 {
            return self.stage_function_batch(functions.into_iter().map(|function| {
                function
                    .with_input_revision(revision)
                    .prepare_materialisation()
            }));
        }

        let chunk_size = functions.len().div_ceil(workers);
        let mut functions = functions.into_iter().map(Some).collect::<Vec<_>>();
        let mut prepared = Vec::with_capacity(functions.len());
        prepared.resize_with(functions.len(), || None);
        thread::scope(|scope| {
            for (functions, prepared) in functions
                .chunks_mut(chunk_size)
                .zip(prepared.chunks_mut(chunk_size))
            {
                scope.spawn(move || {
                    for (function, prepared) in functions.iter_mut().zip(prepared) {
                        let function = function
                            .take()
                            .expect("function must only be materialised once");
                        *prepared = Some(
                            function
                                .with_input_revision(revision)
                                .prepare_materialisation(),
                        );
                    }
                });
            }
        });

        self.stage_function_batch(
            prepared
                .into_iter()
                .map(|prepared| prepared.expect("worker must materialise every function")),
        )
    }

    fn stage_function_batch(
        &mut self,
        functions: impl IntoIterator<Item = Result<FunctionMaterialisation, IncompleteFunctionError>>,
    ) -> Result<(), ProjectError> {
        let functions = functions.into_iter();
        let expected = functions.size_hint().0;
        self.function_stage.reserve_functions(expected);
        self.changes.reserve(expected);
        let mut references = Vec::with_capacity(expected);
        for function in functions {
            let function = function?;
            let (_, coverage, derived) = self.stage_function_materialisation(function)?;
            references.push((coverage, ReferenceKind::Flow, derived));
        }
        self.replace_derived_reference_batches(references)?;
        Ok(())
    }

    fn stage_function_replacement(
        &mut self,
        function: IncompleteFunction,
    ) -> Result<(FunctionId, AddressRangeSet, Vec<Reference>), ProjectError> {
        let function = function.with_input_revision(self.project.revision());
        self.stage_function_materialisation(function.prepare_materialisation()?)
    }

    fn stage_function_materialisation(
        &mut self,
        function: FunctionMaterialisation,
    ) -> Result<(FunctionId, AddressRangeSet, Vec<Reference>), ProjectError> {
        let entry = function.entry();
        let mut mutation = self.project.functions.stage_materialised_replacement(
            &self.project.blocks,
            &mut self.function_stage,
            function,
        )?;
        let id = mutation.id();
        let replaces_existing = mutation.replaces_existing();
        let previous_coverage = mutation.take_previous_coverage();
        let coverage = mutation.take_coverage();
        let covered = if replaces_existing {
            previous_coverage.union(&coverage)
        } else {
            coverage
        };
        let reference_coverage = covered.clone();
        self.call_graph_stage.set_function_edges(
            entry,
            mutation.call_targets(),
            !replaces_existing,
        );
        if replaces_existing {
            self.remove_lifted_from(id, IlLevel::PCode)?;
        }

        let references = mutation.references();

        if replaces_existing {
            self.changes.push(ChangeRecord::FunctionChanged {
                entry,
                kind: FunctionChangeKind::Body,
                coverage: covered,
            });
        } else {
            self.changes.push(ChangeRecord::FunctionAdded {
                entry,
                coverage: covered,
            });
        }

        Ok((id, reference_coverage, references))
    }

    pub fn set_function_properties(
        &mut self,
        entry: Address,
        properties: FunctionProperties,
    ) -> Result<bool, ProjectError> {
        let Some(coverage) = self.project.functions.stage_properties(
            &self.project.blocks,
            &mut self.function_stage,
            entry,
            properties,
            self.project.revision(),
        )?
        else {
            return Ok(false);
        };

        self.changes.push(ChangeRecord::FunctionChanged {
            entry,
            kind: FunctionChangeKind::Properties,
            coverage,
        });

        Ok(true)
    }

    pub fn split_function(
        &mut self,
        entry: Address,
        at: Address,
    ) -> Result<Option<FunctionId>, ProjectError> {
        let Some(function) = self
            .project
            .functions
            .staged_by_address(&self.function_stage, entry)?
        else {
            return Ok(None);
        };

        let kept = function
            .blocks()
            .filter(|(address, _)| *address < at)
            .collect::<SmallVec<[_; 8]>>();
        let moved = function
            .blocks()
            .filter(|(address, _)| *address >= at)
            .collect::<SmallVec<[_; 8]>>();
        let edges = function.edges().collect::<SmallVec<[_; 16]>>();
        let tail_call_sites = function.tail_call_sites().collect::<SmallVec<[_; 2]>>();

        if moved.is_empty() || kept.is_empty() {
            return Ok(None);
        }

        let Some(retained) = IncompleteFunction::from_committed(
            entry,
            &kept,
            edges.iter().copied(),
            tail_call_sites.iter().copied(),
            &self.project.blocks,
        ) else {
            return Ok(None);
        };
        let Some(split) = IncompleteFunction::from_committed(
            at,
            &moved,
            edges,
            tail_call_sites,
            &self.project.blocks,
        ) else {
            return Ok(None);
        };

        let split = self.add_function(split)?;
        self.add_function(retained)?;

        Ok(Some(split))
    }

    pub fn merge_functions(&mut self, into: Address, from: Address) -> Result<bool, ProjectError> {
        if into == from {
            return Ok(false);
        }

        let Some(target) = self
            .project
            .functions
            .staged_by_address(&self.function_stage, into)?
        else {
            return Ok(false);
        };
        let mut blocks = target.blocks().collect::<SmallVec<[_; 8]>>();
        let mut edges = target.edges().collect::<SmallVec<[_; 16]>>();
        let mut tail_call_sites = target.tail_call_sites().collect::<SmallVec<[_; 2]>>();

        let Some(source) = self
            .project
            .functions
            .staged_by_address(&self.function_stage, from)?
        else {
            return Ok(false);
        };
        let source_id = source.id();
        blocks.extend(source.blocks());
        edges.extend(source.edges());
        tail_call_sites.extend(source.tail_call_sites());

        blocks.sort_unstable_by_key(|(address, _)| *address);

        let Some(merged) = IncompleteFunction::from_committed(
            into,
            &blocks,
            edges,
            tail_call_sites,
            &self.project.blocks,
        ) else {
            return Ok(false);
        };

        self.add_function(merged)?;
        self.remove_function_by_id(source_id)?;

        Ok(true)
    }

    pub fn remove_function(&mut self, entry: Address) -> Result<bool, ProjectError> {
        let Some(function) = self
            .project
            .functions
            .staged_by_address(&self.function_stage, entry)?
        else {
            return Ok(false);
        };
        let id = function.id();

        self.remove_function_by_id(id)
    }

    pub fn remove_function_by_id(&mut self, id: FunctionId) -> Result<bool, ProjectError> {
        let Some(function) = self.stage_function_removal(id)? else {
            return Ok(false);
        };

        if self.source.category() == ChangeCategory::Agent {
            self.insert_problem(function.entry(), ProblemKind::HinderedByAssertedFact)?;
        }

        Ok(true)
    }

    fn stage_function_removal(&mut self, id: FunctionId) -> Result<Option<Function>, ProjectError> {
        let Some((function, covered)) = self.project.functions.stage_removal(
            &self.project.blocks,
            &mut self.function_stage,
            id,
        )?
        else {
            return Ok(None);
        };
        let entry = function.entry();
        self.call_graph_stage.remove_function_edges(entry);

        self.replace_derived_references(covered.clone(), ReferenceKind::Flow, [])?;

        self.remove_switches_of_function(id)?;

        self.remove_lifted_from(id, IlLevel::PCode)?;

        self.changes.push(ChangeRecord::FunctionRemoved {
            entry,
            coverage: covered,
        });

        Ok(Some(function))
    }

    pub fn add_reference(&mut self, reference: Reference) -> Result<bool, ProjectError> {
        let reference = reference.with_origin(ReferenceOrigin::Asserted);
        let from = reference.from();
        let target = reference.target();

        let key = ReferenceKey::new(from, target);
        let existing = self.staged_reference(key)?;
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

        self.stage_reference_mutation(key, existing, Some(resolved));
        self.asserted_references.insert(key);
        Ok(true)
    }

    pub fn add_switch<F>(&mut self, branch: Address, f: F) -> Result<SwitchId, ProjectError>
    where
        F: FnOnce(SwitchId, Address) -> Switch,
    {
        let function = self.project.functions.staged_function_owning_address(
            &self.project.blocks,
            &self.function_stage,
            branch,
        )?;
        let existing = self.staged_switch(branch)?;
        let id = match existing {
            Some(ref switch) => switch.id(),
            None => {
                let id = self
                    .project
                    .switches
                    .preview_id(self.switch_reservations.len());
                self.switch_reservations.push(id);
                id
            }
        };
        let switch = f(id, branch);
        if switch.branch() != branch {
            return Err(crate::ir::SwitchTableError::AddressMismatch.into());
        }
        let switch = match function {
            Some(function) => switch.with_function(function),
            None => switch,
        };
        self.synchronise_switch_references(&switch)?;
        self.switch_mutations.insert(branch, Some(switch));
        Ok(id)
    }

    pub fn insert_problem(
        &mut self,
        address: Address,
        kind: ProblemKind,
    ) -> Result<(), ProjectError> {
        self.insert_scoped_problem(ProblemScope::Address(address), kind)
    }

    pub(crate) fn insert_scoped_problem(
        &mut self,
        scope: ProblemScope,
        kind: ProblemKind,
    ) -> Result<(), ProjectError> {
        let key = ProblemKey::scoped(scope, kind);
        let observed_revision = self.project.revision();
        let (mut problem, repeated) = match self.problem_mutations.get(&key) {
            Some(Some(problem)) => (problem.clone(), true),
            Some(None) | None => match self.project.problems.try_get_key(key)? {
                Some(problem) => (problem.as_ref().clone(), true),
                None => (
                    Problem::new_scoped(
                        crate::ir::ProblemId::INVALID,
                        scope,
                        kind,
                        observed_revision,
                    ),
                    false,
                ),
            },
        };

        if repeated {
            problem.record_attempt(observed_revision);
        }
        self.problem_mutations.insert(key, Some(problem));
        Ok(())
    }

    pub fn modify_switch<R>(
        &mut self,
        branch: Address,
        f: impl FnOnce(&mut Switch) -> R,
    ) -> Result<Option<R>, ProjectError> {
        let function = self.project.functions.staged_function_owning_address(
            &self.project.blocks,
            &self.function_stage,
            branch,
        )?;
        let Some(mut switch) = self.staged_switch(branch)? else {
            return Ok(None);
        };
        let result = f(&mut switch);
        switch.set_function(function.unwrap_or(FunctionId::INVALID));
        self.synchronise_switch_references(&switch)?;
        self.switch_mutations.insert(branch, Some(switch));
        Ok(Some(result))
    }

    pub fn remove_switch(&mut self, branch: Address) -> Result<bool, ProjectError> {
        let Some(switch) = self.staged_switch(branch)? else {
            return Ok(false);
        };

        self.replace_switch_references(branch, [])?;
        if self.project.switches.try_get_by_branch(branch)?.is_some() {
            self.switch_mutations.insert(branch, None);
        } else {
            self.switch_mutations.remove(&branch);
            self.cancelled_switches.push(switch.id());
        }
        Ok(true)
    }

    fn remove_switches_of_function(&mut self, function: FunctionId) -> Result<(), ProjectError> {
        let mut branches = self
            .project
            .switches
            .branches_of_function(function)
            .collect::<BTreeSet<_>>();
        for (&branch, switch) in &self.switch_mutations {
            match switch {
                Some(switch) if switch.function() == function => {
                    branches.insert(branch);
                }
                Some(_) | None => {
                    branches.remove(&branch);
                }
            }
        }

        for branch in branches {
            self.remove_switch(branch)?;
        }

        Ok(())
    }

    fn synchronise_switch_references(&mut self, switch: &Switch) -> Result<bool, ProjectError> {
        let references = switch.derived_references().collect::<SmallVec<[_; 8]>>();
        self.replace_switch_references(switch.branch(), references)
    }

    fn staged_switch(&self, branch: Address) -> Result<Option<Switch>, ProjectError> {
        match self.switch_mutations.get(&branch) {
            Some(switch) => Ok(switch.clone()),
            None => Ok(self
                .project
                .switches
                .try_get_by_branch(branch)?
                .map(|switch| switch.as_ref().clone())),
        }
    }

    fn replace_switch_references(
        &mut self,
        branch: Address,
        references: impl IntoIterator<Item = Reference>,
    ) -> Result<bool, ProjectError> {
        let mut coverage = AddressRangeSet::new();
        coverage.insert_range(AddressRange::point(branch));

        let (flow, data) = references
            .into_iter()
            .partition::<Vec<_>, _>(Reference::is_flow);
        let flow_changed =
            self.replace_derived_references(coverage.clone(), ReferenceKind::Flow, flow)?;
        let data_changed = self.replace_derived_references(coverage, ReferenceKind::Data, data)?;
        Ok(flow_changed || data_changed)
    }

    pub fn remove_reference(
        &mut self,
        from: Address,
        target: ReferenceTarget,
    ) -> Result<bool, ProjectError> {
        let key = ReferenceKey::new(from, target);
        let Some(previous) = self.staged_reference(key)? else {
            return Ok(false);
        };

        self.stage_reference_mutation(key, Some(previous), None);
        self.asserted_references.insert(key);
        Ok(true)
    }

    fn stage_reference_mutation(
        &mut self,
        key: ReferenceKey,
        previous: Option<Reference>,
        reference: Option<Reference>,
    ) {
        if let Some(mutation) = self.reference_mutations.get_mut(&key) {
            mutation.reference = reference;
        } else {
            self.reference_mutations.insert(
                key,
                StagedReferenceMutation {
                    previous,
                    reference,
                },
            );
        }
    }

    fn staged_reference(&self, key: ReferenceKey) -> Result<Option<Reference>, ProjectError> {
        match self.reference_mutations.get(&key) {
            Some(mutation) => Ok(mutation.reference),
            None => self
                .project
                .references
                .get(key.from(), key.target())
                .map_err(ProjectError::from),
        }
    }

    fn staged_references_in(
        &self,
        coverage: &AddressRangeSet,
    ) -> Result<Vec<Reference>, ProjectError> {
        let mut references = self
            .project
            .references
            .references_in(coverage)?
            .into_iter()
            .map(|reference| {
                (
                    ReferenceKey::new(reference.from(), reference.target()),
                    reference,
                )
            })
            .collect::<BTreeMap<_, _>>();
        for range in coverage.ranges() {
            let start = ReferenceKey::minimum_for(range.start_address());
            for (&key, mutation) in self.reference_mutations.range(start..) {
                if key.from() > range.end_address() {
                    break;
                }
                match mutation.reference {
                    Some(reference) => {
                        references.insert(key, reference);
                    }
                    None => {
                        references.remove(&key);
                    }
                }
            }
        }
        Ok(references.into_values().collect())
    }

    pub fn add_symbol(
        &mut self,
        index: SymbolIndex,
        entry: SymbolEntry,
    ) -> Result<SymbolId, ProjectError> {
        let entry = entry.with_index(index);
        if let Some(existing_id) = self.staged_symbol_id_by_index(index) {
            let Some(mut existing) = self.staged_symbol(existing_id)? else {
                unreachable!("staged symbol index refers to an existing entry");
            };
            if existing == entry {
                return Ok(existing_id);
            }

            if existing.indices().len() > 1 {
                existing.remove_index(index);
                self.stage_symbol(existing_id, Some(existing))?;
            } else {
                self.remove_staged_symbol(existing_id)?;
            }
        }

        self.insert_or_update_symbol(index, entry)
    }

    pub fn set_symbol_properties(
        &mut self,
        id: SymbolId,
        properties: SymbolProperties,
    ) -> Result<bool, ProjectError> {
        let Some(mut entry) = self.staged_symbol(id)? else {
            return Ok(false);
        };

        if entry.properties() == properties {
            return Ok(false);
        }

        entry.set_properties(properties);
        self.stage_symbol(id, Some(entry))?;

        Ok(true)
    }

    pub fn remove_symbol(&mut self, symbol: impl AsRef<str>) -> Result<usize, ProjectError> {
        let symbol = crate::ir::Symbol::from_existing(symbol.as_ref());
        let Some(symbol) = symbol else {
            return Ok(0);
        };
        let ids = self.symbol_ids_matching(|entry| entry.symbol() == symbol)?;
        let count = ids.len();
        for id in ids {
            self.remove_staged_symbol(id)?;
        }
        Ok(count)
    }

    pub fn remove_symbols_by_address(&mut self, address: Address) -> Result<usize, ProjectError> {
        let ids = self.symbol_ids_matching(|entry| entry.address() == address)?;
        let count = ids.len();
        for id in ids {
            self.remove_staged_symbol(id)?;
        }
        Ok(count)
    }

    pub fn remove_symbol_by_id(&mut self, id: SymbolId) -> Result<bool, ProjectError> {
        if self.staged_symbol(id)?.is_none() {
            return Ok(false);
        }
        self.remove_staged_symbol(id)?;

        Ok(true)
    }

    pub fn remove_symbol_by_index(&mut self, index: SymbolIndex) -> Result<bool, ProjectError> {
        let Some(id) = self.staged_symbol_id_by_index(index) else {
            return Ok(false);
        };
        self.remove_staged_symbol(id)?;

        Ok(true)
    }

    fn insert_or_update_symbol(
        &mut self,
        index: SymbolIndex,
        entry: SymbolEntry,
    ) -> Result<SymbolId, ProjectError> {
        if let Some(id) = self.find_symbol_referent(&entry)? {
            let mut existing = self
                .staged_symbol(id)?
                .expect("symbol referent was resolved from an existing entry");
            existing.add_index(index);
            existing.update_visibility(entry.properties());
            self.stage_symbol(id, Some(existing))?;
            return Ok(id);
        }

        let id = self
            .project
            .symbols
            .preview_id(self.symbol_reservations.len());
        self.symbol_reservations.push(id);
        self.stage_symbol(id, Some(entry))?;
        Ok(id)
    }

    fn find_symbol_referent(&self, entry: &SymbolEntry) -> Result<Option<SymbolId>, ProjectError> {
        for (id, _) in self.project.symbols.get_by_address(entry.address()) {
            if let Some(candidate) = self.staged_symbol(id)?
                && candidate.has_same_referent(entry)
            {
                return Ok(Some(id));
            }
        }

        Ok(self.symbol_mutations.iter().find_map(|(&id, candidate)| {
            candidate
                .as_ref()
                .is_some_and(|candidate| candidate.has_same_referent(entry))
                .then_some(id)
        }))
    }

    fn staged_symbol(&self, id: SymbolId) -> Result<Option<SymbolEntry>, ProjectError> {
        match self.symbol_mutations.get(&id) {
            Some(entry) => Ok(entry.clone()),
            None => Ok(self
                .project
                .symbols
                .try_get_by_id(id)?
                .map(|entry| entry.as_ref().clone())),
        }
    }

    fn staged_symbol_id_by_index(&self, index: SymbolIndex) -> Option<SymbolId> {
        match self.symbol_indices.get(&index) {
            Some(id) => *id,
            None => self.project.symbols.get_id_by_index(index).and_then(|id| {
                self.symbol_mutations.get(&id).map_or(Some(id), |entry| {
                    entry
                        .as_ref()
                        .filter(|entry| entry.indices().contains(&index))
                        .map(|_| id)
                })
            }),
        }
    }

    fn stage_symbol(
        &mut self,
        id: SymbolId,
        entry: Option<SymbolEntry>,
    ) -> Result<(), ProjectError> {
        if let Some(previous) = self.staged_symbol(id)? {
            for &index in previous.indices() {
                if self.staged_symbol_id_by_index(index) == Some(id) {
                    self.symbol_indices.insert(index, None);
                }
            }
        }
        if let Some(entry) = &entry {
            for &index in entry.indices() {
                self.symbol_indices.insert(index, Some(id));
            }
        }
        self.symbol_mutations.insert(id, entry);
        Ok(())
    }

    fn remove_staged_symbol(&mut self, id: SymbolId) -> Result<(), ProjectError> {
        self.stage_symbol(id, None)?;
        if self.project.symbols.try_get_by_id(id)?.is_none() {
            self.symbol_mutations.remove(&id);
            self.cancelled_symbols.push(id);
        }
        Ok(())
    }

    fn symbol_ids_matching(
        &self,
        mut predicate: impl FnMut(&SymbolEntry) -> bool,
    ) -> Result<BTreeSet<SymbolId>, ProjectError> {
        let mut ids = BTreeSet::new();
        for (id, _) in self.project.symbols.iter() {
            if let Some(entry) = self.staged_symbol(id)?
                && predicate(&entry)
            {
                ids.insert(id);
            }
        }
        for (&id, entry) in &self.symbol_mutations {
            if entry.as_ref().is_some_and(&mut predicate) {
                ids.insert(id);
            } else {
                ids.remove(&id);
            }
        }
        Ok(ids)
    }

    pub fn create_mapping(
        &mut self,
        builder: SegmentMappingBuilder,
    ) -> Result<SegmentMappingId, ProjectError> {
        let mapping = self
            .segment_stage
            .create_mapping(&self.project.storage.segments, builder)?;
        self.changes
            .push(ChangeRecord::SegmentMappingCreated { mapping });
        Ok(mapping)
    }

    pub fn create_space(&mut self) -> Result<AddressSpaceId, ProjectError> {
        let space = self
            .segment_stage
            .create_space(&self.project.storage.segments)?;
        self.changes.push(ChangeRecord::SpaceCreated { space });
        Ok(space)
    }

    pub fn add_mapping_to_space(
        &mut self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        self.segment_stage
            .add_mapping(&self.project.storage.segments, space, mapping)?;
        self.record_mapping_added(space, mapping)?;
        self.invalidate_functions_for_mapping(space, mapping)?;

        Ok(())
    }

    pub fn add_mapping_to_space_top(
        &mut self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        self.segment_stage
            .add_mapping_top(&self.project.storage.segments, space, mapping)?;
        self.record_mapping_added(space, mapping)?;
        self.invalidate_functions_for_mapping(space, mapping)?;

        Ok(())
    }

    pub fn add_mapping_to_space_bottom(
        &mut self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        self.segment_stage
            .add_mapping_bottom(&self.project.storage.segments, space, mapping)?;
        self.record_mapping_added(space, mapping)?;
        self.invalidate_functions_for_mapping(space, mapping)?;

        Ok(())
    }

    pub fn remove_mapping(&mut self, id: SegmentMappingId) -> Result<(), ProjectError> {
        let removed = self
            .segment_stage
            .remove_mapping(&self.project.storage.segments, id)?;
        self.record_mapping_removed(id, removed.iter().copied());
        self.invalidate_functions_for_placements(removed)?;

        Ok(())
    }

    pub fn remap_mapping(
        &mut self,
        id: SegmentMappingId,
        new_start: impl Into<Address>,
    ) -> Result<(), ProjectError> {
        let new_start = new_start.into();
        let removed = self
            .segment_stage
            .mapping_placements(&self.project.storage.segments, id)?;
        self.segment_stage
            .remap_mapping(&self.project.storage.segments, id, new_start)?;
        self.record_mapping_removed(id, removed.iter().copied());
        self.invalidate_functions_for_placements(removed)?;
        self.record_mapping_added_to_placements(id)?;
        self.invalidate_functions_for_mapping_placements(id)?;

        Ok(())
    }

    pub fn resize_mapping(
        &mut self,
        id: SegmentMappingId,
        new_size: u64,
    ) -> Result<(), ProjectError> {
        let removed = self
            .segment_stage
            .mapping_placements(&self.project.storage.segments, id)?;
        self.segment_stage
            .resize_mapping(&self.project.storage.segments, id, new_size)?;
        self.record_mapping_removed(id, removed.iter().copied());
        self.invalidate_functions_for_placements(removed)?;
        self.record_mapping_added_to_placements(id)?;
        self.invalidate_functions_for_mapping_placements(id)?;

        Ok(())
    }

    pub fn update_mapping_metadata(
        &mut self,
        id: SegmentMappingId,
        kind: SegmentMappingKind,
        provenance: SegmentMappingProvenance,
        flags: SegmentMappingFlags,
    ) -> Result<(), ProjectError> {
        self.segment_stage.update_mapping_metadata(
            &self.project.storage.segments,
            id,
            kind,
            provenance,
            flags,
        )?;
        self.changes
            .push(ChangeRecord::SegmentMappingChanged { mapping: id });

        Ok(())
    }

    pub fn prioritise_mapping(
        &mut self,
        space: AddressSpaceId,
        id: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        self.segment_stage
            .prioritise_mapping(&self.project.storage.segments, space, id)?;
        self.record_mapping_added(space, id)?;
        self.invalidate_functions_for_mapping(space, id)?;

        Ok(())
    }

    pub fn deprioritise_mapping(
        &mut self,
        space: AddressSpaceId,
        id: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        self.segment_stage
            .deprioritise_mapping(&self.project.storage.segments, space, id)?;
        self.record_mapping_added(space, id)?;
        self.invalidate_functions_for_mapping(space, id)?;

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
            if let Some(range) = AddressRange::from_size(addr, written as u64) {
                self.changes.push(ChangeRecord::BytesWritten { range });
                self.invalidate_functions_in_range(&range)?;
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

    fn invalidate_functions_for_mapping(
        &mut self,
        space: AddressSpaceId,
        id: SegmentMappingId,
    ) -> Result<usize, ProjectError> {
        let Some(range) =
            self.segment_stage
                .mapping_range(&self.project.storage.segments, space, id)?
        else {
            return Ok(0);
        };
        self.invalidate_functions_in_range(&range)
    }

    fn invalidate_functions_for_mapping_placements(
        &mut self,
        id: SegmentMappingId,
    ) -> Result<usize, ProjectError> {
        let placements = self
            .segment_stage
            .mapping_placements(&self.project.storage.segments, id)?;

        self.invalidate_functions_for_placements(placements)
    }

    fn invalidate_functions_for_placements(
        &mut self,
        placements: impl IntoIterator<Item = (AddressSpaceId, (RawAddress, RawAddress))>,
    ) -> Result<usize, ProjectError> {
        let mut invalidated = 0usize;

        for (space, range) in placements {
            let range = AddressRange::new(space, range.0, range.1);
            invalidated += self.invalidate_functions_in_range(&range)?;
        }

        Ok(invalidated)
    }

    fn invalidate_functions_in_range(
        &mut self,
        range: &AddressRange,
    ) -> Result<usize, ProjectError> {
        let functions = self.project.functions.staged_overlaps(
            &self.project.blocks,
            &self.function_stage,
            range,
        )?;
        let mut invalidated = 0usize;

        for id in functions {
            let Some(origin) = self
                .project
                .functions
                .staged_origin(&self.function_stage, id)?
            else {
                continue;
            };

            if origin.is_asserted() {
                let function = self
                    .project
                    .functions
                    .staged_by_id(&self.function_stage, id)?
                    .expect("staged function origin requires a function");
                self.remove_lifted_from(id, IlLevel::PCode)?;
                self.insert_problem(function.entry(), ProblemKind::HinderedByAssertedFact)?;
            } else if self.stage_function_removal(id)?.is_some() {
                invalidated += 1;
            }
        }

        Ok(invalidated)
    }

    fn record_mapping_added(
        &mut self,
        space: AddressSpaceId,
        id: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        if let Some(range) =
            self.segment_stage
                .mapping_range(&self.project.storage.segments, space, id)?
        {
            self.changes
                .push(ChangeRecord::SegmentMapped { mapping: id, range });
        }
        Ok(())
    }

    fn record_mapping_added_to_placements(
        &mut self,
        id: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        let added = self
            .segment_stage
            .mapping_placements(&self.project.storage.segments, id)?;

        for (space, range) in added {
            self.changes.push(ChangeRecord::SegmentMapped {
                mapping: id,
                range: AddressRange::new(space, range.0, range.1),
            });
        }
        Ok(())
    }

    fn record_mapping_removed(
        &mut self,
        id: SegmentMappingId,
        removed: impl IntoIterator<Item = (AddressSpaceId, (RawAddress, RawAddress))>,
    ) {
        for (space, range) in removed {
            self.changes.push(ChangeRecord::SegmentUnmapped {
                mapping: id,
                range: AddressRange::new(space, range.0, range.1),
            });
        }
    }

    pub fn commit(mut self) -> Result<ChangeSet, ProjectError> {
        let span = self.span.clone();
        let _entered = span.enter();
        let changes = &mut self.changes;
        self.il_stage
            .for_each_change(|function, level, materialised| {
                changes.push(if materialised {
                    ChangeRecord::LiftedMaterialised { function, level }
                } else {
                    ChangeRecord::LiftedRemoved { function, level }
                });
            });
        self.invalidate_semantic_problems();
        let (problems, mut writes) = self.prepare_problems()?;
        let (switches, switch_writes) = self.prepare_switches()?;
        writes.extend(switch_writes);
        let (symbols, symbol_writes) = self.prepare_symbols()?;
        writes.extend(symbol_writes);
        let (references, reference_writes) = self.prepare_references()?;
        writes.extend(reference_writes);
        let function_stage = std::mem::take(&mut self.function_stage);
        let (functions, function_writes) =
            function_stage.prepare(&self.project.functions, &self.project.blocks)?;
        writes.extend(function_writes);
        let (call_graph, call_graph_writes) = self
            .project
            .call_graph
            .prepare_stage(&self.call_graph_stage)?;
        writes.extend(call_graph_writes);
        writes.extend(self.il_stage.prepare()?);
        writes.sort_unstable_by(|left, right| left.key().cmp(right.key()));
        if !writes.is_empty() {
            if let Some(worker) = self.project.storage.write_back() {
                worker.flush()?;
            }
            self.project.storage.entities.apply_batch(&writes)?;
        }
        std::mem::take(&mut self.segment_stage).publish(&mut self.project.storage.segments);
        self.publish_problems(problems);
        self.publish_switches(switches);
        self.publish_symbols(symbols);
        functions.publish(&mut self.project.functions, &mut self.project.blocks);
        self.project.call_graph.publish_stage(call_graph);
        self.publish_references(references);
        if !self.changes.is_empty() {
            self.project.revisions.advance(self.changes.semantic());
        }
        self.committed = true;
        let changes = std::mem::take(&mut self.changes);
        Ok(changes.finish(self.project.revision(), self.source.clone()))
    }

    fn invalidate_semantic_problems(&mut self) {
        let mut candidates = BTreeSet::new();
        let mut has_global_input_change = false;

        for record in self.changes.records() {
            let ranges = record.ranges();
            if ranges.is_empty() {
                has_global_input_change = true;
                continue;
            }

            for range in ranges {
                self.project.problems.for_each_address_key_in(range, |key| {
                    candidates.insert(key);
                });
            }
        }

        if has_global_input_change {
            candidates.extend(self.project.problems.keys());
        }

        for key in candidates {
            if self.problem_mutations.contains_key(&key)
                || (!self.changes.is_collapsed()
                    && !self.changes.records().iter().any(|record| {
                        key.kind().input_kinds().intersects(record.kind())
                            && Self::problem_scope_affected(key.scope(), record)
                    }))
                || (self.changes.is_collapsed()
                    && !key.kind().input_kinds().intersects(self.changes.kinds()))
            {
                continue;
            }

            self.problem_mutations.insert(key, None);
        }
    }

    fn problem_scope_affected(scope: ProblemScope, record: &ChangeRecord) -> bool {
        let ranges = record.ranges();
        if ranges.is_empty() {
            return true;
        }

        match scope {
            ProblemScope::Global => true,
            ProblemScope::AddressSpace(space) => ranges.iter().any(|range| range.space() == space),
            ProblemScope::Address(address) => {
                ranges.iter().any(|range| range.contains_address(address))
            }
            ProblemScope::Range(problem) => ranges.iter().any(|range| range.intersects(&problem)),
        }
    }

    fn prepare_problems(
        &mut self,
    ) -> Result<(Vec<PreparedProblemMutation>, EntityWriteBatch), ProjectError> {
        let persistent = self.project.problems.is_persistent();
        let mutations = std::mem::take(&mut self.problem_mutations);
        let mut inserted = 0usize;
        let mut prepared = Vec::with_capacity(mutations.len());
        let mut writes = Vec::with_capacity(if persistent { mutations.len() } else { 0 });

        for (key, mutation) in mutations {
            let previous = self.project.problems.try_get_key(key)?;
            let is_new = previous.is_none();
            let previous_id = previous.as_ref().map(|problem| problem.id());
            drop(previous);

            match mutation {
                Some(problem) => {
                    let problem = if is_new {
                        let id = self.project.problems.preview_id(inserted);
                        inserted += 1;
                        problem.with_id(id)
                    } else {
                        problem
                    };
                    let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(&problem)
                        .map_err(crate::storage::EntityStorageError::encode)?;
                    let encoded_len = encoded.len();
                    if persistent {
                        writes.push(EntityWrite::insert_archive(
                            schema::make_key::<crate::ir::ProblemId, Problem>(&problem.id()),
                            encoded,
                        ));
                    }
                    prepared.push(PreparedProblemMutation {
                        encoded_len,
                        is_new,
                        key,
                        problem: Some(problem),
                    });
                }
                None => {
                    let Some(id) = previous_id else {
                        continue;
                    };
                    if persistent {
                        writes.push(EntityWrite::remove(schema::make_key::<
                            crate::ir::ProblemId,
                            Problem,
                        >(&id)));
                    }
                    prepared.push(PreparedProblemMutation {
                        encoded_len: 0,
                        is_new: false,
                        key,
                        problem: None,
                    });
                }
            }
        }

        Ok((prepared, writes))
    }

    fn publish_problems(&mut self, problems: Vec<PreparedProblemMutation>) {
        for mutation in problems {
            let scope = mutation.key.scope();
            let kind = mutation.key.kind();
            match mutation.problem {
                Some(problem) => {
                    self.project.problems.publish_upsert(
                        problem,
                        mutation.encoded_len,
                        mutation.is_new,
                    );
                    self.changes
                        .push(ChangeRecord::ProblemRecorded { scope, kind });
                }
                None => {
                    self.project.problems.publish_remove(mutation.key);
                    self.changes
                        .push(ChangeRecord::ProblemResolved { scope, kind });
                }
            }
        }
    }

    fn prepare_switches(
        &mut self,
    ) -> Result<(Vec<PreparedSwitchMutation>, EntityWriteBatch), ProjectError> {
        let persistent = self.project.switches.is_persistent();
        let mutations = std::mem::take(&mut self.switch_mutations);
        let mut prepared = Vec::with_capacity(mutations.len());
        let mut writes = Vec::with_capacity(if persistent { mutations.len() } else { 0 });

        for (branch, mutation) in mutations {
            let previous = self.project.switches.try_get_by_branch(branch)?;
            if previous
                .as_ref()
                .is_some_and(|previous| mutation.as_ref() == Some(previous.as_ref()))
            {
                continue;
            }
            if mutation.is_none() && previous.is_none() {
                continue;
            }
            let previous = previous.map(|switch| PreviousSwitch {
                function: switch.function(),
                id: switch.id(),
            });
            match &mutation {
                Some(switch) => {
                    let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(switch)
                        .map_err(crate::storage::EntityStorageError::encode)?;
                    let encoded_len = encoded.len();
                    if persistent {
                        writes.push(EntityWrite::insert_archive(
                            schema::make_key::<SwitchId, Switch>(&switch.id()),
                            encoded,
                        ));
                    }
                    prepared.push(PreparedSwitchMutation {
                        branch,
                        encoded_len,
                        previous,
                        switch: mutation,
                    });
                }
                None => {
                    let id = previous
                        .expect("prepared switch removal has a previous switch")
                        .id;
                    if persistent {
                        writes.push(EntityWrite::remove(schema::make_key::<SwitchId, Switch>(
                            &id,
                        )));
                    }
                    prepared.push(PreparedSwitchMutation {
                        branch,
                        encoded_len: 0,
                        previous,
                        switch: None,
                    });
                }
            }
        }

        Ok((prepared, writes))
    }

    fn publish_switches(&mut self, switches: Vec<PreparedSwitchMutation>) {
        self.project
            .switches
            .publish_reservations(&self.switch_reservations);
        for id in self.cancelled_switches.drain(..) {
            self.project.switches.publish_release(id);
        }
        for mutation in switches {
            match mutation.switch {
                Some(switch) => {
                    self.project.switches.publish_upsert(
                        switch,
                        mutation.previous.map(|previous| previous.function),
                        mutation.encoded_len,
                    );
                    self.changes.push(ChangeRecord::SwitchAdded {
                        branch: mutation.branch,
                    });
                }
                None => {
                    let previous = mutation
                        .previous
                        .expect("prepared switch removal has a previous switch");
                    self.project.switches.publish_remove(
                        previous.id,
                        previous.function,
                        mutation.branch,
                    );
                    self.changes.push(ChangeRecord::SwitchRemoved {
                        branch: mutation.branch,
                    });
                }
            }
        }
    }

    fn prepare_symbols(
        &mut self,
    ) -> Result<(Vec<PreparedSymbolMutation>, EntityWriteBatch), ProjectError> {
        let persistent = self.project.symbols.is_persistent();
        let mutations = std::mem::take(&mut self.symbol_mutations);
        let mut prepared = Vec::with_capacity(mutations.len());
        let mut writes = Vec::with_capacity(if persistent { mutations.len() } else { 0 });

        for (id, mutation) in mutations {
            let previous = self.project.symbols.try_get_by_id(id)?;
            if previous
                .as_ref()
                .is_some_and(|previous| mutation.as_ref() == Some(previous.as_ref()))
            {
                continue;
            }
            if mutation.is_none() && previous.is_none() {
                continue;
            }
            let previous = previous.map(|entry| SymbolIndexState::new(&entry));

            match &mutation {
                Some(entry) => {
                    let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(entry)
                        .map_err(crate::storage::EntityStorageError::encode)?;
                    let encoded_len = encoded.len();
                    if persistent {
                        writes.push(EntityWrite::insert_archive(
                            schema::make_key::<SymbolId, SymbolEntry>(&id),
                            encoded,
                        ));
                    }
                    prepared.push(PreparedSymbolMutation {
                        encoded_len,
                        entry: mutation,
                        id,
                        previous,
                    });
                }
                None => {
                    if persistent {
                        writes.push(EntityWrite::remove(schema::make_key::<SymbolId, SymbolEntry>(
                            &id,
                        )));
                    }
                    prepared.push(PreparedSymbolMutation {
                        encoded_len: 0,
                        entry: None,
                        id,
                        previous,
                    });
                }
            }
        }

        let mut added = 0usize;
        let mut removed = 0usize;
        let mut releases = self.cancelled_symbols.clone();
        for mutation in &prepared {
            self.project.symbols.append_index_writes(
                mutation.id,
                mutation.entry.as_ref(),
                mutation.previous.as_ref(),
                &mut writes,
            )?;
            match (&mutation.entry, &mutation.previous) {
                (Some(_), None) => added += 1,
                (None, Some(_)) => {
                    removed += 1;
                    releases.push(mutation.id);
                }
                _ => {}
            }
        }
        self.project.symbols.append_allocator_writes(
            &self.symbol_reservations,
            &releases,
            added,
            removed,
            &mut writes,
        )?;

        Ok((prepared, writes))
    }

    fn publish_symbols(&mut self, symbols: Vec<PreparedSymbolMutation>) {
        let added = symbols
            .iter()
            .filter(|mutation| mutation.entry.is_some() && mutation.previous.is_none())
            .count();
        let removed = symbols
            .iter()
            .filter(|mutation| mutation.entry.is_none() && mutation.previous.is_some())
            .count();
        self.project.symbols.publish_prepared(
            &self.symbol_reservations,
            &self.cancelled_symbols,
            added,
            removed,
        );

        for mutation in symbols.iter().filter(|mutation| mutation.entry.is_none()) {
            let previous = mutation
                .previous
                .as_ref()
                .expect("prepared symbol removal has a previous entry");
            self.project.symbols.publish_remove(mutation.id, previous);
            self.changes.push(ChangeRecord::SymbolRemoved {
                address: previous.address(),
                symbol: previous.symbol(),
            });
        }

        for mutation in symbols
            .into_iter()
            .filter(|mutation| mutation.entry.is_some())
        {
            let entry = mutation
                .entry
                .expect("prepared symbol upsert has a final entry");
            let address = entry.address();
            let symbol = entry.symbol();
            self.project.symbols.publish_upsert(
                mutation.id,
                entry,
                mutation.previous.as_ref(),
                mutation.encoded_len,
            );
            self.changes.push(if mutation.previous.is_some() {
                ChangeRecord::SymbolChanged { address, symbol }
            } else {
                ChangeRecord::SymbolAdded { address, symbol }
            });
        }
    }

    fn prepare_references(
        &mut self,
    ) -> Result<(Vec<PreparedReferenceMutation>, EntityWriteBatch), ProjectError> {
        let mutations = mem::take(&mut self.reference_mutations);
        let mut prepared = Vec::with_capacity(mutations.len());
        let mut writes = Vec::with_capacity(mutations.len().saturating_mul(2));

        for (key, mutation) in mutations {
            let StagedReferenceMutation {
                previous,
                reference,
            } = mutation;
            let unchanged = match (&reference, previous) {
                (Some(reference), Some(previous)) => reference.same_fact(&previous),
                (None, None) => true,
                _ => false,
            };
            if unchanged {
                continue;
            }

            let encoded_len = if self.project.references.is_transient() {
                0
            } else {
                let (encoded_len, encoded) =
                    ReferenceIndex::encode_mutation(key, reference.as_ref())?;
                writes.extend(encoded);
                encoded_len
            };
            prepared.push(PreparedReferenceMutation {
                encoded_len,
                key,
                previous,
                reference,
            });
        }

        Ok((prepared, writes))
    }

    fn publish_references(&mut self, references: Vec<PreparedReferenceMutation>) {
        self.project.references.publish_mutations(
            references
                .iter()
                .map(|mutation| (mutation.key, mutation.reference, mutation.encoded_len)),
        );

        let mut derived_changed = false;
        for mutation in references {
            derived_changed |= self
                .derived_reference_coverage
                .contains(mutation.key.from());

            if !self.asserted_references.contains(&mutation.key) {
                continue;
            }
            match mutation.reference {
                Some(reference) => self.changes.push(ChangeRecord::ReferenceAdded {
                    from: mutation.key.from(),
                    target: mutation.key.target(),
                    kind: reference.kind(),
                }),
                None => self.changes.push(ChangeRecord::ReferenceRemoved {
                    from: mutation.key.from(),
                    target: mutation.key.target(),
                    kind: mutation
                        .previous
                        .expect("prepared reference removal has a previous reference")
                        .kind(),
                }),
            }
        }

        if derived_changed {
            self.changes.push(ChangeRecord::ReferencesChanged {
                coverage: self.derived_reference_coverage.clone(),
            });
        }
    }

    fn restore_eager_writes(&mut self) -> Result<(), ProjectError> {
        while let Some(revert) = self.segment_write_reverts.pop() {
            revert.restore(&mut self.project.storage.segments)?;
        }
        self.changes.clear();
        Ok(())
    }

    pub(crate) fn reject(mut self) -> Result<(), ProjectError> {
        let span = self.span.clone();
        let _entered = span.enter();
        self.committed = true;
        self.restore_eager_writes()
    }
}

#[cfg(test)]
mod test;
