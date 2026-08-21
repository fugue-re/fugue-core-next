use std::collections::{BTreeMap, BTreeSet};
use std::mem;
use std::sync::Arc;

use rustc_hash::FxHashMap;
use tracing::Span;

use super::segment::SegmentMetadataStaging;
use super::{
    ChangeKinds, ChangeRecord, ChangeSet, ChangeSource, FunctionChangeKind,
    MAX_DETAILED_CHANGE_RECORDS, Project, ProjectError, ReadSet,
};
use crate::il::registry::IlRegistry;
use crate::il::storage::{IlStagedChange, IlStaging};
use crate::ir::{
    Address, AddressRange, AddressRangeSet, CallGraphStaging, CodeBlockTable, FunctionId,
    FunctionRef, FunctionTable, FunctionTableStaging, PreparedReferenceIndexRecord, Problem,
    ProblemKey, ProblemScope, ProblemTable, Reference, ReferenceIndex, ReferenceKey, Switch,
    SwitchId, SwitchRef, SwitchTable, SymbolEntry, SymbolId, SymbolIndex, SymbolIndexState,
    SymbolTable,
};
use crate::storage::entities::{Entity, EntityWrite, EntityWriteBatch};
use crate::storage::segments::mapping::SegmentMappingId;
use crate::storage::segments::{SegmentStorage, SegmentWriteRevert};
use crate::storage::{EntityRef, EntityStorageError};
use crate::types::Revision;

mod function;
mod il;
mod problem;
mod reference;
mod segment;
mod switch;
mod symbol;

struct PreparedProblemRecord {
    encoded_size: usize,
    is_new: bool,
    key: ProblemKey,
    problem: Option<Problem>,
}

struct PreparedSwitchRecord {
    branch: Address,
    encoded_size: usize,
    previous: Option<PreviousSwitch>,
    switch: Option<Switch>,
}

#[derive(Clone, Copy)]
struct PreviousSwitch {
    function: FunctionId,
    id: SwitchId,
}

struct PreparedSymbolRecord {
    encoded_size: usize,
    entry: Option<SymbolEntry>,
    id: SymbolId,
    previous: Option<SymbolIndexState>,
}

struct PreparedReferenceRecord {
    index_record: PreparedReferenceIndexRecord,
    previous: Option<Reference>,
}

#[derive(Clone, Copy)]
struct StagedReferenceRecord {
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
struct ChangeStaging {
    collapsed: bool,
    indices: FxHashMap<StagedChangeKey, usize>,
    kind_counts: [usize; u32::BITS as usize],
    kinds: ChangeKinds,
    records: Vec<ChangeRecord>,
    semantic_count: usize,
}

impl ChangeStaging {
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
    registry: Arc<IlRegistry>,
    changes: ChangeStaging,
    reads: ReadSet,
    reads_collapsed: bool,
    il_staging: IlStaging,
    function_staging: FunctionTableStaging,
    call_graph_staging: CallGraphStaging,
    staged_symbols: BTreeMap<SymbolId, Option<SymbolEntry>>,
    symbol_indices: BTreeMap<SymbolIndex, Option<SymbolId>>,
    symbol_reservations: Vec<SymbolId>,
    cancelled_symbols: Vec<SymbolId>,
    segment_staging: SegmentMetadataStaging,
    segment_write_reverts: Vec<SegmentWriteRevert>,
    staged_references: BTreeMap<ReferenceKey, StagedReferenceRecord>,
    asserted_references: BTreeSet<ReferenceKey>,
    derived_reference_coverage: AddressRangeSet,
    staged_problems: BTreeMap<ProblemKey, Option<Problem>>,
    staged_switches: BTreeMap<Address, Option<Switch>>,
    switch_reservations: Vec<SwitchId>,
    cancelled_switches: Vec<SwitchId>,
    source: ChangeSource,
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
    pub(crate) fn new(
        project: &mut Project,
        source: ChangeSource,
        registry: Arc<IlRegistry>,
    ) -> ProjectTransaction<'_> {
        let span = tracing::debug_span!("project_transaction", reason = source.label());

        ProjectTransaction {
            project,
            registry,
            changes: ChangeStaging::default(),
            reads: ReadSet::new(),
            reads_collapsed: false,
            il_staging: IlStaging::default(),
            function_staging: FunctionTableStaging::default(),
            call_graph_staging: CallGraphStaging::default(),
            staged_symbols: BTreeMap::new(),
            symbol_indices: BTreeMap::new(),
            symbol_reservations: Vec::new(),
            cancelled_symbols: Vec::new(),
            segment_staging: SegmentMetadataStaging::default(),
            segment_write_reverts: Vec::new(),
            staged_references: BTreeMap::new(),
            asserted_references: BTreeSet::new(),
            derived_reference_coverage: AddressRangeSet::new(),
            staged_problems: BTreeMap::new(),
            staged_switches: BTreeMap::new(),
            switch_reservations: Vec::new(),
            cancelled_switches: Vec::new(),
            source,
            committed: false,
            span,
        }
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
            .staged_by_address(&self.function_staging, address)
            .map(|function| function.map(EntityRef::owned))
            .map_err(ProjectError::from)
    }

    pub fn function_callees(&mut self, entry: Address) -> Result<Vec<Address>, ProjectError> {
        self.record_read(ChangeKinds::FUNCTIONS, AddressRange::point(entry));
        if let Some(callees) = self.call_graph_staging.function_edges(entry) {
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
        match self.staged_switches.get(&branch) {
            Some(Some(switch)) => Some(EntityRef::owned(switch.clone())),
            Some(None) => None,
            None => self.project.switches().get_by_branch(branch),
        }
    }

    pub fn contains_problem(&mut self, address: Address) -> bool {
        self.record_read(ChangeKinds::PROBLEMS, AddressRange::point(address));
        if self
            .staged_problems
            .iter()
            .any(|(key, problem)| key.address() == Some(address) && problem.is_some())
        {
            return true;
        }

        self.project
            .problems()
            .keys()
            .filter(|key| key.address() == Some(address))
            .any(|key| !self.staged_problems.contains_key(&key))
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

    pub fn commit(mut self) -> Result<ChangeSet, ProjectError> {
        let span = self.span.clone();
        let _entered = span.enter();
        let changes = &mut self.changes;
        self.il_staging.for_each_change(|change| {
            changes.push(match change {
                IlStagedChange::Materialised { function, form } => {
                    ChangeRecord::LiftedMaterialised { function, form }
                }
                IlStagedChange::Removed { function, form } => {
                    ChangeRecord::LiftedRemoved { function, form }
                }
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
        let function_staging = mem::take(&mut self.function_staging);
        let (function_batch, function_writes) =
            function_staging.prepare(&self.project.functions, &self.project.blocks)?;
        writes.extend(function_writes);
        let (call_graph_batch, call_graph_writes) =
            self.project.call_graph.prepare(&self.call_graph_staging)?;
        writes.extend(call_graph_writes);
        writes.extend(self.il_staging.prepare()?);
        writes.sort_by_key();
        if !writes.is_empty() {
            if let Some(worker) = self.project.storage.write_back() {
                worker.flush()?;
            }
            self.project.storage.entities().apply_batch(&writes)?;
        }
        mem::take(&mut self.segment_staging).publish(self.project.storage.segments_mut());
        self.publish_problems(problems);
        self.publish_switches(switches);
        self.publish_symbols(symbols);
        function_batch.publish(&mut self.project.functions, &mut self.project.blocks);
        self.project.call_graph.publish(call_graph_batch);
        self.publish_references(references);
        if !self.changes.is_empty() {
            self.project.revisions.advance(self.changes.semantic());
        }
        self.committed = true;
        let changes = mem::take(&mut self.changes);
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
                self.project.problems.for_each_key_in_range(range, |key| {
                    candidates.insert(key);
                });
            }
        }

        if has_global_input_change {
            candidates.extend(self.project.problems.keys());
        }

        for key in candidates {
            if self.staged_problems.contains_key(&key)
                || (!self.changes.is_collapsed()
                    && !self.changes.records().iter().any(|record| {
                        ChangeKinds::for_problem(key.kind()).intersects(record.kind())
                            && Self::problem_scope_affected(key.scope(), record)
                    }))
                || (self.changes.is_collapsed()
                    && !ChangeKinds::for_problem(key.kind()).intersects(self.changes.kinds()))
            {
                continue;
            }

            self.staged_problems.insert(key, None);
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
    ) -> Result<(Vec<PreparedProblemRecord>, EntityWriteBatch), ProjectError> {
        let persistent = self.project.problems.is_persistent();
        let records = mem::take(&mut self.staged_problems);
        let mut inserted = 0usize;
        let mut batch = Vec::with_capacity(records.len());
        let mut writes =
            EntityWriteBatch::with_capacity(if persistent { records.len() } else { 0 });

        for (key, record) in records {
            let previous = self.project.problems.try_get_by_key(key)?;
            let is_new = previous.is_none();
            let previous_id = previous.as_ref().map(|problem| problem.id());
            drop(previous);

            match record {
                Some(problem) => {
                    let problem = if is_new {
                        let id = self.project.problems.pending_id(inserted);
                        inserted += 1;
                        problem.with_id(id)
                    } else {
                        problem
                    };
                    let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(&problem)
                        .map_err(EntityStorageError::encode)?;
                    let encoded_size = encoded.len();
                    if persistent {
                        writes.push(EntityWrite::insert_archived(
                            Problem::ID.key_for(&problem.id()),
                            encoded,
                        ));
                    }
                    batch.push(PreparedProblemRecord {
                        encoded_size,
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
                        writes.push(EntityWrite::remove(Problem::ID.key_for(&id)));
                    }
                    batch.push(PreparedProblemRecord {
                        encoded_size: 0,
                        is_new: false,
                        key,
                        problem: None,
                    });
                }
            }
        }

        Ok((batch, writes))
    }

    fn publish_problems(&mut self, problems: Vec<PreparedProblemRecord>) {
        for record in problems {
            let scope = record.key.scope();
            let kind = record.key.kind();
            match record.problem {
                Some(problem) => {
                    self.project.problems.publish_upsert(
                        problem,
                        record.encoded_size,
                        record.is_new,
                    );
                    self.changes
                        .push(ChangeRecord::ProblemRecorded { scope, kind });
                }
                None => {
                    self.project.problems.publish_remove(record.key);
                    self.changes
                        .push(ChangeRecord::ProblemResolved { scope, kind });
                }
            }
        }
    }

    fn prepare_switches(
        &mut self,
    ) -> Result<(Vec<PreparedSwitchRecord>, EntityWriteBatch), ProjectError> {
        let persistent = self.project.switches.is_persistent();
        let records = mem::take(&mut self.staged_switches);
        let mut batch = Vec::with_capacity(records.len());
        let mut writes =
            EntityWriteBatch::with_capacity(if persistent { records.len() } else { 0 });

        for (branch, record) in records {
            let previous = self.project.switches.try_get_by_branch(branch)?;
            if previous
                .as_ref()
                .is_some_and(|previous| record.as_ref() == Some(previous.as_ref()))
            {
                continue;
            }
            if record.is_none() && previous.is_none() {
                continue;
            }
            let previous = previous.map(|switch| PreviousSwitch {
                function: switch.function(),
                id: switch.id(),
            });
            match &record {
                Some(switch) => {
                    let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(switch)
                        .map_err(EntityStorageError::encode)?;
                    let encoded_size = encoded.len();
                    if persistent {
                        writes.push(EntityWrite::insert_archived(
                            Switch::ID.key_for(&switch.id()),
                            encoded,
                        ));
                    }
                    batch.push(PreparedSwitchRecord {
                        branch,
                        encoded_size,
                        previous,
                        switch: record,
                    });
                }
                None => {
                    let id = previous
                        .expect("prepared switch removal has a previous switch")
                        .id;
                    if persistent {
                        writes.push(EntityWrite::remove(Switch::ID.key_for(&id)));
                    }
                    batch.push(PreparedSwitchRecord {
                        branch,
                        encoded_size: 0,
                        previous,
                        switch: None,
                    });
                }
            }
        }

        Ok((batch, writes))
    }

    fn publish_switches(&mut self, switches: Vec<PreparedSwitchRecord>) {
        self.project
            .switches
            .publish_reservations(&self.switch_reservations);
        for id in self.cancelled_switches.drain(..) {
            self.project.switches.publish_release(id);
        }
        for record in switches {
            match record.switch {
                Some(switch) => {
                    self.project.switches.publish_upsert(
                        switch,
                        record.previous.map(|previous| previous.function),
                        record.encoded_size,
                    );
                    self.changes.push(ChangeRecord::SwitchAdded {
                        branch: record.branch,
                    });
                }
                None => {
                    let previous = record
                        .previous
                        .expect("prepared switch removal has a previous switch");
                    self.project.switches.publish_remove(
                        previous.id,
                        previous.function,
                        record.branch,
                    );
                    self.changes.push(ChangeRecord::SwitchRemoved {
                        branch: record.branch,
                    });
                }
            }
        }
    }

    fn prepare_symbols(
        &mut self,
    ) -> Result<(Vec<PreparedSymbolRecord>, EntityWriteBatch), ProjectError> {
        let persistent = self.project.symbols.is_persistent();
        let records = mem::take(&mut self.staged_symbols);
        let mut batch = Vec::with_capacity(records.len());
        let mut writes =
            EntityWriteBatch::with_capacity(if persistent { records.len() } else { 0 });

        for (id, record) in records {
            let previous = self.project.symbols.try_get_by_id(id)?;
            if previous
                .as_ref()
                .is_some_and(|previous| record.as_ref() == Some(previous.as_ref()))
            {
                continue;
            }
            if record.is_none() && previous.is_none() {
                continue;
            }
            let previous = previous.map(|entry| SymbolIndexState::new(&entry));

            match &record {
                Some(entry) => {
                    let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(entry)
                        .map_err(EntityStorageError::encode)?;
                    let encoded_size = encoded.len();
                    if persistent {
                        writes.push(EntityWrite::insert_archived(
                            SymbolEntry::ID.key_for(&id),
                            encoded,
                        ));
                    }
                    batch.push(PreparedSymbolRecord {
                        encoded_size,
                        entry: record,
                        id,
                        previous,
                    });
                }
                None => {
                    if persistent {
                        writes.push(EntityWrite::remove(SymbolEntry::ID.key_for(&id)));
                    }
                    batch.push(PreparedSymbolRecord {
                        encoded_size: 0,
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
        for record in &batch {
            self.project.symbols.append_prepared_writes(
                record.id,
                record.entry.as_ref(),
                record.previous.as_ref(),
                &mut writes,
            )?;
            match (&record.entry, &record.previous) {
                (Some(_), None) => added += 1,
                (None, Some(_)) => {
                    removed += 1;
                    releases.push(record.id);
                }
                _ => {}
            }
        }
        self.project.symbols.append_prepared_transition_writes(
            &self.symbol_reservations,
            &releases,
            added,
            removed,
            &mut writes,
        )?;

        Ok((batch, writes))
    }

    fn publish_symbols(&mut self, symbols: Vec<PreparedSymbolRecord>) {
        let added = symbols
            .iter()
            .filter(|record| record.entry.is_some() && record.previous.is_none())
            .count();
        let removed = symbols
            .iter()
            .filter(|record| record.entry.is_none() && record.previous.is_some())
            .count();
        self.project.symbols.publish_prepared(
            &self.symbol_reservations,
            &self.cancelled_symbols,
            added,
            removed,
        );

        for record in symbols.iter().filter(|record| record.entry.is_none()) {
            let previous = record
                .previous
                .as_ref()
                .expect("prepared symbol removal has a previous entry");
            self.project.symbols.publish_remove(record.id, previous);
            self.changes.push(ChangeRecord::SymbolRemoved {
                address: previous.address(),
                symbol: previous.symbol(),
            });
        }

        for record in symbols.into_iter().filter(|record| record.entry.is_some()) {
            let entry = record
                .entry
                .expect("prepared symbol upsert has a final entry");
            let address = entry.address();
            let symbol = entry.symbol();
            self.project.symbols.publish_upsert(
                record.id,
                entry,
                record.previous.as_ref(),
                record.encoded_size,
            );
            self.changes.push(if record.previous.is_some() {
                ChangeRecord::SymbolChanged { address, symbol }
            } else {
                ChangeRecord::SymbolAdded { address, symbol }
            });
        }
    }

    fn prepare_references(
        &mut self,
    ) -> Result<(Vec<PreparedReferenceRecord>, EntityWriteBatch), ProjectError> {
        let records = mem::take(&mut self.staged_references);
        let mut batch = Vec::with_capacity(records.len());
        let mut writes = EntityWriteBatch::with_capacity(records.len().saturating_mul(2));

        for (key, record) in records {
            let StagedReferenceRecord {
                previous,
                reference,
            } = record;
            let unchanged = match (&reference, previous) {
                (Some(reference), Some(previous)) => reference.same_fact(&previous),
                (None, None) => true,
                _ => false,
            };
            if unchanged {
                continue;
            }

            let index_record = if self.project.references.is_persistent() {
                let (index_record, encoded) = ReferenceIndex::prepare_record(key, reference)?;
                writes.extend(encoded);
                index_record
            } else {
                PreparedReferenceIndexRecord::new(key, reference, 0)
            };
            batch.push(PreparedReferenceRecord {
                index_record,
                previous,
            });
        }

        Ok((batch, writes))
    }

    fn publish_references(&mut self, references: Vec<PreparedReferenceRecord>) {
        self.project
            .references
            .publish_records(references.iter().map(|record| record.index_record));

        let mut derived_changed = false;
        for record in references {
            let index_record = record.index_record;
            let key = index_record.key();
            derived_changed |= self.derived_reference_coverage.contains(key.from());

            if !self.asserted_references.contains(&key) {
                continue;
            }
            match index_record.reference() {
                Some(reference) => self.changes.push(ChangeRecord::ReferenceAdded {
                    from: key.from(),
                    target: key.target(),
                    kind: reference.kind(),
                }),
                None => self.changes.push(ChangeRecord::ReferenceRemoved {
                    from: key.from(),
                    target: key.target(),
                    kind: record
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
            revert.restore(self.project.storage.segments_mut())?;
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
