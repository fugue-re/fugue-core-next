use std::collections::{BTreeMap, BTreeSet};
use std::mem;
use std::sync::Arc;

use rustc_hash::FxHashMap;
use tracing::Span;

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
use crate::storage::segments::SegmentStorage;
use crate::storage::segments::mapping::SegmentMappingId;
use crate::storage::segments::staging::SegmentStorageStaging;
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
    fn is_empty(&self) -> bool {
        self.records.is_empty()
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

    fn finish(mut self, revision: Revision, source: ChangeSource) -> ChangeSet {
        if self.collapsed {
            self.records[0] = ChangeRecord::Resynchronise { to: revision };
        }

        ChangeSet::with_records(revision, self.records).with_provenance(source)
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
    segment_staging: SegmentStorageStaging,
    staged_references: BTreeMap<ReferenceKey, StagedReferenceRecord>,
    asserted_references: BTreeSet<ReferenceKey>,
    derived_reference_coverage: AddressRangeSet,
    staged_problems: BTreeMap<ProblemKey, Option<Problem>>,
    staged_switches: BTreeMap<Address, Option<Switch>>,
    switch_reservations: Vec<SwitchId>,
    cancelled_switches: Vec<SwitchId>,
    source: ChangeSource,
    span: Span,
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
            segment_staging: SegmentStorageStaging::default(),
            staged_references: BTreeMap::new(),
            asserted_references: BTreeSet::new(),
            derived_reference_coverage: AddressRangeSet::new(),
            staged_problems: BTreeMap::new(),
            staged_switches: BTreeMap::new(),
            switch_reservations: Vec::new(),
            cancelled_switches: Vec::new(),
            source,
            span,
        }
    }

    pub(crate) fn reads_collapsed(&self) -> bool {
        self.reads_collapsed
    }

    pub fn project(&mut self, kinds: ChangeKinds) -> &Project {
        self.reads.record_unbounded(kinds);
        self.project
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

    fn record_read(&mut self, kinds: ChangeKinds, range: AddressRange) {
        self.reads_collapsed |= self.reads.record(kinds, range);
    }

    fn record_unbounded_read(&mut self, kinds: ChangeKinds) {
        self.reads.record_unbounded(kinds);
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

    pub fn absorb_reads(&mut self, reads: &ReadSet) {
        self.reads_collapsed |= self.reads.merge(reads);
    }

    pub(crate) fn take_reads(&mut self) -> ReadSet {
        mem::take(&mut self.reads)
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
        let segment_batch = mem::take(&mut self.segment_staging).prepare();
        writes.sort_by_key();
        if !writes.is_empty() {
            if let Some(worker) = self.project.storage.write_back() {
                worker.flush()?;
            }
            self.project.storage.entities().apply_batch(&writes)?;
        }
        segment_batch.publish(self.project.storage.segments_mut());
        self.publish_problems(problems);
        self.publish_switches(switches);
        self.publish_symbols(symbols);
        function_batch.publish(&mut self.project.functions, &mut self.project.blocks);
        self.project.call_graph.publish(call_graph_batch);
        self.publish_references(references);
        if !self.changes.is_empty() {
            self.project.revisions.advance(self.changes.semantic());
        }
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
                || (!self.changes.collapsed
                    && !self.changes.records().iter().any(|record| {
                        ChangeKinds::for_problem(key.kind()).intersects(record.kind())
                            && Self::problem_scope_affected(key.scope(), record)
                    }))
                || (self.changes.collapsed
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
}

#[cfg(test)]
mod test {
    use std::io;

    use fugue_lifter::runtime::pcode::Inputs;

    use super::*;
    use crate::il::common::{IlArtefact, IlGraph, IlIndexRange, IlMetadata, IlSourceSpan};
    use crate::il::ecode::{ECodeBuilder, ECodeIr};
    use crate::il::pcode::{PCodeBuilder, PCodeIr};
    use crate::ir::{
        Address, IncompleteCodeBlock, IncompleteFunction, Insn, InsnEntry, ProblemKind, Reference,
        ReferenceOrigin, ReferenceProperties, ReferenceTarget, SymbolEntry, SymbolIndex,
        SymbolProperties, SymbolTableSelector,
    };
    use crate::lifter::{ContextSet, Op, RawPCodeOp, Varnode, resolve_language};
    use crate::storage::{AddressSpaceId, DEFAULT_SPACE_ID};

    fn calling_function(
        entry: Address,
        callee: Address,
        size: usize,
    ) -> Result<IncompleteFunction, Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let operation = RawPCodeOp {
            op: Op::Call,
            inputs: Inputs::one(Varnode::new(language.default_space(), callee.offset(), 8)),
            output: Varnode::INVALID,
        };
        let operations = [operation];
        let insn = Insn::from_resolved_flow(language, entry, size, &operations)?;
        let mut function = IncompleteFunction::new(entry);

        let insn = match function.insn_entry(entry) {
            InsnEntry::Vacant(entry) => entry.insert(insn),
            InsnEntry::Occupied(_) => {
                return Err(io::Error::other("test instruction unexpectedly occupied").into());
            }
        };

        function.push_block(
            IncompleteCodeBlock::try_new(entry, size, vec![insn], ContextSet::default())
                .expect("test block size must be valid"),
        );

        Ok(function)
    }

    fn writable_address(
        project: &Project,
        minimum_size: u64,
    ) -> Result<Address, Box<dyn std::error::Error>> {
        project
            .segments()
            .iter_views(DEFAULT_SPACE_ID)?
            .find(|view| view.properties().is_writable() && view.size() >= minimum_size)
            .map(|view| view.start())
            .ok_or_else(|| io::Error::other("fixture writable segment missing").into())
    }

    fn incomplete_function(entry: Address, len: usize) -> IncompleteFunction {
        let mut function = IncompleteFunction::new(entry);
        function.push_block(
            IncompleteCodeBlock::try_new(entry, len, Vec::new(), ContextSet::default())
                .expect("test block size must be valid"),
        );

        function
    }

    fn tagged_source_spans(payload: &[u8]) -> Vec<IlSourceSpan> {
        let tag = payload.first().copied().unwrap_or_default();
        vec![IlSourceSpan::new(
            IlIndexRange::EMPTY,
            Address::new(DEFAULT_SPACE_ID, u64::from(tag)),
            u32::from(tag),
            u32::try_from(payload.len()).expect("test payload size should fit"),
        )]
    }

    fn tagged_pcode(function: FunctionId, payload: &[u8]) -> PCodeIr {
        let mut builder = PCodeBuilder::new(IlMetadata::new(function, 0), IlGraph::default());
        builder.set_source_spans(tagged_source_spans(payload));
        builder.build().expect("test PCode IR should verify")
    }

    fn ecode_for_test(function: FunctionId, graph: IlGraph) -> ECodeIr {
        ECodeBuilder::new(IlMetadata::new(function, 0), graph)
            .build()
            .expect("test ECode IR should verify")
    }

    fn first_mapping_placement(
        project: &Project,
    ) -> (AddressSpaceId, SegmentMappingId, AddressRange) {
        let (space, mapping) = project
            .segments()
            .spaces()
            .find_map(|space| {
                space
                    .priority_list()
                    .next()
                    .map(|mapping_ref| (space.id(), mapping_ref.mapping_id()))
            })
            .expect("fixture should contain at least one mapping");
        let range = project
            .segments()
            .mapping_placements(mapping)
            .find(|range| range.space() == space)
            .expect("mapping should have a placement in its priority space");

        (space, mapping, range)
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
            transaction.replace_lifted(tagged_pcode(function, &[1]))?;
            transaction.replace_lifted(ecode_for_test(function, IlGraph::default()))?;
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
            form: PCodeIr::FORM,
        }));
        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function,
            form: ECodeIr::FORM,
        }));

        Ok(())
    }

    #[test]
    fn rejecting_function_replacement_preserves_lifted_ir() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = Address::from(0x4000u64);

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(incomplete_function(entry, 1))?;
            transaction.commit()?;
            function
        };
        let materialised = tagged_pcode(function, &[1]);

        {
            let mut transaction = project.transaction("test");
            transaction.replace_lifted(materialised.clone())?;
            transaction.commit()?;
        }
        let materialised = project
            .pcode(function)?
            .expect("materialised PCode should be readable");

        {
            let mut transaction = project.transaction("test");
            transaction.add_function(incomplete_function(entry, 2))?;
            drop(transaction);
        }

        assert_eq!(project.pcode(function)?, Some(materialised));

        let block = project
            .functions()
            .get_by_id(function)
            .and_then(|function| function.blocks().next().map(|(_, block)| block))
            .and_then(|block| project.blocks().get_by_id(block))
            .expect("function body should be restored");
        assert_eq!(block.size(), 1);

        Ok(())
    }

    #[test]
    fn rejecting_function_replacement_preserves_call_graph()
    -> Result<(), Box<dyn std::error::Error>> {
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
            assert_eq!(transaction.function_callees(entry)?, vec![new_callee]);
            drop(transaction);
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
            transaction.replace_lifted(tagged_pcode(function, &[1]))?;
            transaction.commit()?;
        }

        let changes = {
            let mut transaction = project.transaction("test");
            assert!(transaction.remove_function_by_id(function, ReferenceOrigin::Derived)?);
            transaction.commit()?
        };

        assert!(project.pcode(function)?.is_none());
        assert!(project.functions().get_by_address(entry).is_none());
        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function,
            form: PCodeIr::FORM,
        }));
        assert!(changes.records().iter().any(|record| {
            matches!(
                record,
                ChangeRecord::FunctionRemoved {
                    entry: removed, ..
                } if *removed == entry
            )
        }));

        Ok(())
    }

    #[test]
    fn byte_write_invalidates_lifted() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project, 1)?;

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(incomplete_function(entry, 2))?;
            transaction.commit()?;
            function
        };

        {
            let mut transaction = project.transaction("test");
            transaction.replace_lifted(tagged_pcode(function, &[1]))?;
            transaction.commit()?;
        }

        let changes = {
            let mut transaction = project.transaction("test");
            transaction.write_bytes(entry + 1u64, &[0xa5])?;
            transaction.commit()?
        };

        assert!(project.pcode(function)?.is_none());
        assert!(project.functions().get_by_address(entry).is_none());
        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function,
            form: PCodeIr::FORM,
        }));
        assert!(changes.records().iter().any(|record| {
            matches!(
                record,
                ChangeRecord::FunctionRemoved {
                    entry: removed, ..
                } if *removed == entry
            )
        }));

        Ok(())
    }

    #[test]
    fn byte_write_preserves_asserted_function_with_problem()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project, 1)?;

        {
            let mut transaction = project.transaction("test");
            transaction.add_function(
                incomplete_function(entry, 2).with_origin(ReferenceOrigin::Asserted),
            )?;
            transaction.commit()?;
        }

        let changes = {
            let mut transaction = project.transaction("test");
            transaction.write_bytes(entry + 1u64, &[0xa5])?;
            transaction.commit()?
        };

        assert!(
            project
                .functions()
                .get_by_address(entry)
                .is_some_and(|function| function.is_asserted())
        );
        assert!(
            project
                .problems()
                .get(entry, ProblemKind::HinderedByAssertedFact)
                .is_some()
        );
        assert!(
            changes
                .records()
                .iter()
                .all(|record| !matches!(record, ChangeRecord::FunctionRemoved { .. }))
        );

        Ok(())
    }

    #[test]
    fn byte_write_invalidates_lifted_descendants() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project, 1)?;

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(incomplete_function(entry, 2))?;
            transaction.commit()?;
            function
        };

        {
            let mut transaction = project.transaction("test");
            transaction.replace_lifted(tagged_pcode(function, &[1]))?;
            transaction.replace_lifted(ecode_for_test(function, IlGraph::default()))?;
            transaction.commit()?;
        }

        let changes = {
            let mut transaction = project.transaction("test");
            transaction.write_bytes(entry + 1u64, &[0xa5])?;
            transaction.commit()?
        };

        assert!(project.pcode(function)?.is_none());
        assert!(project.ecode(function)?.is_none());
        for form in [PCodeIr::FORM, ECodeIr::FORM] {
            assert!(
                changes
                    .records()
                    .contains(&ChangeRecord::LiftedRemoved { function, form })
            );
        }

        Ok(())
    }

    #[test]
    fn symbol_rename_preserves_lifted() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project, 1)?;
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

        let pcode = tagged_pcode(function, &[1]);
        let ecode = ecode_for_test(function, IlGraph::default());

        {
            let mut transaction = project.transaction("test");
            transaction.replace_lifted(pcode.clone())?;
            transaction.replace_lifted(ecode.clone())?;
            transaction.commit()?;
        }
        let pcode = project
            .pcode(function)?
            .expect("materialised PCode should be readable");
        let ecode = project
            .ecode(function)?
            .expect("materialised ECode should be readable");

        let semantic_revision = project.semantic_revision();
        let changes = {
            let mut transaction = project.transaction("test");
            transaction.add_symbol(
                index,
                SymbolEntry::new(entry, "new_display_name", SymbolProperties::FUNCTION),
            )?;
            transaction.commit()?
        };

        assert_eq!(project.semantic_revision(), semantic_revision);
        assert!(
            !changes
                .records()
                .iter()
                .any(|record| matches!(record, ChangeRecord::LiftedRemoved { .. }))
        );
        assert_eq!(project.pcode(function)?, Some(pcode));
        assert_eq!(project.ecode(function)?, Some(ecode));

        Ok(())
    }

    #[test]
    fn reference_edits_preserve_lifted() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project, 1)?;
        let target = entry + 0x10u64;

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(incomplete_function(entry, 2))?;
            transaction.commit()?;
            function
        };

        let pcode = tagged_pcode(function, &[1]);
        let ecode = ecode_for_test(function, IlGraph::default());

        {
            let mut transaction = project.transaction("test");
            transaction.replace_lifted(pcode.clone())?;
            transaction.replace_lifted(ecode.clone())?;
            transaction.commit()?;
        }
        let pcode = project
            .pcode(function)?
            .expect("materialised PCode should be readable");
        let ecode = project
            .ecode(function)?
            .expect("materialised ECode should be readable");

        let semantic_revision = project.semantic_revision();
        let changes = {
            let mut transaction = project.transaction("test");
            assert!(transaction.add_reference(Reference::data(
                entry,
                target,
                ReferenceProperties::READ
            ))?);
            transaction.commit()?
        };

        assert_eq!(project.semantic_revision(), semantic_revision);
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

        assert_eq!(project.semantic_revision(), semantic_revision);
        assert!(
            !changes
                .records()
                .iter()
                .any(|record| matches!(record, ChangeRecord::LiftedRemoved { .. }))
        );
        assert_eq!(project.pcode(function)?, Some(pcode));
        assert_eq!(project.ecode(function)?, Some(ecode));

        Ok(())
    }

    #[test]
    fn rejecting_byte_write_preserves_lifted_ir() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project, 1)?;

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(incomplete_function(entry, 1))?;
            transaction.commit()?;
            function
        };
        let materialised = tagged_pcode(function, &[1]);

        {
            let mut transaction = project.transaction("test");
            transaction.replace_lifted(materialised.clone())?;
            transaction.commit()?;
        }
        let materialised = project
            .pcode(function)?
            .expect("materialised PCode should be readable");

        {
            let mut transaction = project.transaction("test");
            transaction.write_bytes(entry, &[0xa5])?;
            drop(transaction);
        }

        assert_eq!(project.pcode(function)?, Some(materialised));

        Ok(())
    }

    #[test]
    fn mapping_removal_invalidates_lifted() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let (_, mapping, range) = first_mapping_placement(&project);
        let entry = range.start_address();

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(incomplete_function(entry, 1))?;
            transaction.commit()?;
            function
        };

        {
            let mut transaction = project.transaction("test");
            transaction.replace_lifted(tagged_pcode(function, &[1]))?;
            transaction.commit()?;
        }

        let changes = {
            let mut transaction = project.transaction("test");
            transaction.remove_mapping(mapping)?;
            transaction.commit()?
        };

        assert!(project.pcode(function)?.is_none());
        assert!(project.functions().get_by_address(entry).is_none());
        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function,
            form: PCodeIr::FORM,
        }));
        assert!(changes.records().iter().any(|record| {
            matches!(
                record,
                ChangeRecord::FunctionRemoved {
                    entry: removed, ..
                } if *removed == entry
            )
        }));

        Ok(())
    }

    #[test]
    fn rejecting_mapping_removal_preserves_lifted_ir() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let (_, mapping, range) = first_mapping_placement(&project);
        let entry = range.start_address();

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(incomplete_function(entry, 1))?;
            transaction.commit()?;
            function
        };
        let materialised = tagged_pcode(function, &[1]);

        {
            let mut transaction = project.transaction("test");
            transaction.replace_lifted(materialised.clone())?;
            transaction.commit()?;
        }
        let materialised = project
            .pcode(function)?
            .expect("materialised PCode should be readable");

        {
            let mut transaction = project.transaction("test");
            transaction.remove_mapping(mapping)?;
            drop(transaction);
        }

        assert_eq!(project.pcode(function)?, Some(materialised));

        Ok(())
    }

    #[test]
    fn mapping_remap_invalidates_old_and_new_ranges() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let (space, mapping, old_range) = first_mapping_placement(&project);
        let old_entry = old_range.start_address();
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
            transaction.replace_lifted(tagged_pcode(old_function, &[1]))?;
            transaction.replace_lifted(tagged_pcode(new_function, &[2]))?;
            transaction.commit()?;
        }

        let changes = {
            let mut transaction = project.transaction("test");
            transaction.remap_mapping(mapping, new_start)?;
            transaction.commit()?
        };

        assert!(project.pcode(old_function)?.is_none());
        assert!(project.pcode(new_function)?.is_none());
        assert!(project.functions().get_by_address(old_entry).is_none());
        assert!(project.functions().get_by_address(new_entry).is_none());
        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function: old_function,
            form: PCodeIr::FORM,
        }));
        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function: new_function,
            form: PCodeIr::FORM,
        }));

        Ok(())
    }

    #[test]
    fn repeated_function_changes_keep_one_semantic_record() {
        let mut changes = ChangeStaging::default();
        let entry = Address::in_default_space(0x1000u64);
        let mut coverage = AddressRangeSet::new();
        coverage.insert(entry);

        for _ in 0..=MAX_DETAILED_CHANGE_RECORDS {
            changes.push(ChangeRecord::FunctionChanged {
                entry,
                kind: FunctionChangeKind::Body,
                coverage: coverage.clone(),
            });
        }

        assert!(!changes.collapsed);
        assert_eq!(changes.records().len(), 1);
        assert_eq!(
            changes.records(),
            [ChangeRecord::FunctionChanged {
                entry,
                kind: FunctionChangeKind::Body,
                coverage,
            }]
        );
    }

    #[test]
    fn adding_then_removing_a_function_has_no_change() {
        let mut changes = ChangeStaging::default();
        let entry = Address::in_default_space(0x2000u64);
        let mut coverage = AddressRangeSet::new();
        coverage.insert(entry);

        changes.push(ChangeRecord::FunctionAdded {
            entry,
            coverage: coverage.clone(),
        });
        changes.push(ChangeRecord::FunctionRemoved { entry, coverage });

        assert!(changes.is_empty());
        assert!(!changes.semantic());
        assert!(changes.kinds().is_empty());
    }

    #[test]
    fn removing_then_adding_a_function_has_only_the_net_change_kind() {
        let mut changes = ChangeStaging::default();
        let entry = Address::in_default_space(0x2000u64);
        let mut coverage = AddressRangeSet::new();
        coverage.insert(entry);

        changes.push(ChangeRecord::FunctionRemoved {
            entry,
            coverage: coverage.clone(),
        });
        changes.push(ChangeRecord::FunctionAdded {
            entry,
            coverage: coverage.clone(),
        });

        assert_eq!(changes.kinds(), ChangeKinds::FUNCTION_CHANGED);
        assert_eq!(
            changes.records(),
            [ChangeRecord::FunctionChanged {
                entry,
                kind: FunctionChangeKind::Body,
                coverage,
            }]
        );
    }

    #[test]
    fn staged_change_detail_collapses_at_its_memory_bound() {
        let mut changes = ChangeStaging::default();

        for index in 0..=MAX_DETAILED_CHANGE_RECORDS {
            changes.push(ChangeRecord::FunctionAdded {
                entry: Address::in_default_space(index as u64),
                coverage: AddressRangeSet::new(),
            });
        }

        assert!(changes.collapsed);
        assert_eq!(changes.records().len(), 1);
        assert!(changes.semantic());
        assert!(changes.kinds().contains(ChangeKinds::FUNCTION_ADDED));

        let revision = Revision::new(7);
        let published = changes.finish(revision, ChangeSource::agent("test"));
        assert_eq!(
            published.records(),
            [ChangeRecord::Resynchronise { to: revision }]
        );
    }
}
