use std::any::Any;
use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::sync::{Arc, OnceLock};

use flume::{Receiver, Sender, TryRecvError};
use parking_lot::RwLock;
use smallvec::SmallVec;

use super::change::{
    ChangeKinds, ChangeProvenance, ChangeRecord, ChangeSet, ChangeSource,
    MAX_DETAILED_CHANGE_RECORDS, Revision,
};
use super::coverage;
use super::scheduler::{
    AnalysisWorkQueue, Degradation, DegradationReport, ScheduledAnalyser, WORK_SLICE_BYTES,
    WorkBatch,
};
use super::subscription::Subscriber;
use super::update::{MappingCreationResult, ProjectUpdate, SpaceCreationResult};
use super::view::DependencyIndex;
use super::{
    AnalyserProvider, AnalysisContext, AnalysisEngineConfig, AnalysisPhase, EngineError,
    MAX_COMPLETION_ROUNDS, ProjectView, RETRACTED_BY_BYTE_CHANGE, WORK_BATCH_ITEMS, WorkCause,
};
use super::{EngineMetrics, ReadSet};
use crate::analysis::AnalysisError;
use crate::analysis::control::{CancellationToken, Cancelled, Progress};
use crate::il::common::{IlArtefact, IlError, IlLevel};
use crate::il::ecode::ssa::{ECodeSsaIr, ECodeToSsa};
use crate::il::ecode::{ECodeIr, PCodeToECode};
use crate::il::pcode::{PCodeCanonicaliser, PCodeFunctionInput, PCodeIr};
use crate::ir::{AddressRangeSet, FunctionId, ProblemKind, ProblemScope, Reference, ReferenceKind};
use crate::project::{Project, ProjectError, ProjectTransaction};
use crate::queries::{LiftedLookup, QueryCachedIl, QueryEngine};
use crate::registry;
use crate::storage::segments::mapping::SegmentMappingBuilder;

pub(crate) enum Intake {
    Analyse(Sender<Result<(), EngineError>>),
    Cancel,
    CreateMapping {
        builder: SegmentMappingBuilder,
        reply: Sender<Result<MappingCreationResult, EngineError>>,
    },
    CreateSpace(Sender<Result<SpaceCreationResult, EngineError>>),
    Direct {
        kind: ChangeKinds,
        regions: AddressRangeSet,
    },
    EnsureLifted {
        function: FunctionId,
        level: IlLevel,
        reply: Sender<Result<ChangeSet, EngineError>>,
    },
    GenerateLifted {
        function: FunctionId,
        level: IlLevel,
        reply: Sender<Result<Option<Arc<dyn Any + Send + Sync>>, EngineError>>,
    },
    Shutdown,
    Subscribe(Subscriber),
    Updates {
        updates: SmallVec<[ProjectUpdate; 1]>,
        reply: Sender<Result<ChangeSet, EngineError>>,
    },
}

enum TransactionResult<T, E> {
    Committed {
        value: T,
        changes: ChangeSet,
        reads: ReadSet,
        reads_collapsed: bool,
    },
    Rejected(E),
}

struct AnalysisProduction {
    base: Revision,
    outcome: Result<(), Cancelled>,
    reads: ReadSet,
    reads_collapsed: bool,
    updates: Vec<ProjectUpdate>,
}

impl AnalysisProduction {
    fn from_analysis(
        base: Revision,
        analysis: Result<(), AnalysisError>,
        reads: ReadSet,
        reads_collapsed: bool,
        updates: Vec<ProjectUpdate>,
    ) -> Result<Self, AnalysisError> {
        let outcome = match analysis {
            Ok(()) => Ok(()),
            Err(AnalysisError::Cancelled(cancelled)) => Err(cancelled),
            Err(error) => return Err(error),
        };
        Ok(Self {
            base,
            outcome,
            reads,
            reads_collapsed,
            updates,
        })
    }
}

struct AnalysisAdmission {
    outcome: Result<(), Cancelled>,
    reads: ReadSet,
    reads_collapsed: bool,
}

enum AnalysisAdmissionResult {
    Committed(AnalysisAdmission),
    Conflict,
    Rejected(AnalysisError),
}

pub(super) struct Worker {
    analysers: Vec<ScheduledAnalyser>,
    config: AnalysisEngineConfig,
    pending_diagnostics: PendingDiagnostics,
    cancellation: CancellationToken,
    poison: Arc<OnceLock<String>>,
    progress: Progress,
    project: Arc<RwLock<Project>>,
    queries: QueryEngine,
    queue: AnalysisWorkQueue,
    dependencies: DependencyIndex,
    recent_changes: RecentChanges,
    metrics: EngineMetrics,
    subscribers: Vec<Subscriber>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AdmissionConflict {
    InputsChanged,
    ResynchronisationRequired,
}

pub(super) struct RecentChanges {
    changes: VecDeque<ChangeSet>,
    floor: Revision,
    latest: Revision,
    records: usize,
}

impl RecentChanges {
    pub(super) fn new(revision: Revision) -> Self {
        Self {
            changes: VecDeque::new(),
            floor: revision,
            latest: revision,
            records: 0,
        }
    }

    pub(super) fn record(&mut self, changes: &ChangeSet) {
        debug_assert!(changes.revision() >= self.latest);
        self.latest = changes.revision();

        if changes.len() > MAX_DETAILED_CHANGE_RECORDS {
            self.changes.clear();
            self.floor = changes.revision();
            self.records = 0;
            return;
        }

        self.records += changes.len();
        self.changes.push_back(changes.clone());
        while self.records > MAX_DETAILED_CHANGE_RECORDS {
            let discarded = self
                .changes
                .pop_front()
                .expect("an over-budget change window must contain a change");
            self.floor = self.floor.max(discarded.revision());
            self.records -= discarded.len();
        }
    }

    pub(super) fn conflict(&self, base: Revision, reads: &ReadSet) -> Option<AdmissionConflict> {
        if base == self.latest {
            return None;
        }
        if base < self.floor || base > self.latest {
            return Some(AdmissionConflict::ResynchronisationRequired);
        }
        self.changes
            .iter()
            .filter(|changes| changes.revision() > base)
            .any(|changes| reads.conflicts_with(changes))
            .then_some(AdmissionConflict::InputsChanged)
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.queries.mark_dead();
    }
}

#[derive(Default)]
pub(super) struct PendingDiagnostics {
    scopes: BTreeMap<ProblemKind, ProblemScope>,
}

impl PendingDiagnostics {
    pub(super) fn defer(&mut self, scope: ProblemScope, kind: ProblemKind) {
        self.scopes
            .entry(kind)
            .and_modify(|existing| *existing = existing.covering(scope))
            .or_insert(scope);
    }

    fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (ProblemScope, ProblemKind)> + '_ {
        self.scopes.iter().map(|(&kind, &scope)| (scope, kind))
    }

    pub(super) fn acknowledge(&mut self, diagnostics: &[(ProblemScope, ProblemKind)]) {
        for (_, kind) in diagnostics {
            self.scopes.remove(kind);
        }
    }
}

#[derive(Default)]
struct PreparedLiftedArtefacts {
    pcode: Option<PCodeIr>,
    ecode: Option<ECodeIr>,
    ecode_ssa: Option<ECodeSsaIr>,
    pcode_references: Option<PreparedDerivedReferences>,
}

struct PreparedDerivedReferences {
    coverage: AddressRangeSet,
    references: Vec<Reference>,
}

trait GeneratedIl: QueryCachedIl + Send + Sync + 'static {
    fn take(prepared: &mut PreparedLiftedArtefacts) -> Option<Self>;
}

impl GeneratedIl for PCodeIr {
    fn take(prepared: &mut PreparedLiftedArtefacts) -> Option<Self> {
        prepared.pcode.take()
    }
}

impl GeneratedIl for ECodeIr {
    fn take(prepared: &mut PreparedLiftedArtefacts) -> Option<Self> {
        prepared.ecode.take()
    }
}

impl GeneratedIl for ECodeSsaIr {
    fn take(prepared: &mut PreparedLiftedArtefacts) -> Option<Self> {
        prepared.ecode_ssa.take()
    }
}

impl PreparedLiftedArtefacts {
    fn admit(self, transaction: &mut ProjectTransaction<'_>) -> Result<(), ProjectError> {
        if let Some(pcode) = self.pcode {
            transaction.materialise_lifted(pcode)?;
            if let Some(references) = self.pcode_references {
                transaction.replace_derived_references(
                    references.coverage,
                    ReferenceKind::Data,
                    references.references,
                )?;
            }
        }
        if let Some(ecode) = self.ecode {
            transaction.materialise_lifted(ecode)?;
        }
        if let Some(ecode_ssa) = self.ecode_ssa {
            transaction.materialise_lifted(ecode_ssa)?;
        }
        Ok(())
    }

    fn admit_references(
        &mut self,
        transaction: &mut ProjectTransaction<'_>,
    ) -> Result<(), ProjectError> {
        if let Some(references) = self.pcode_references.take() {
            transaction.replace_derived_references(
                references.coverage,
                ReferenceKind::Data,
                references.references,
            )?;
        }
        Ok(())
    }

    fn publish_one<T>(&mut self, queries: &QueryEngine) -> Option<Arc<T>>
    where
        T: GeneratedIl,
    {
        let ir = Arc::new(T::take(self)?);
        queries.insert_lifted(ir.metadata().function(), ir.clone());
        Some(ir)
    }

    fn publish(mut self, queries: &QueryEngine) {
        self.publish_one::<PCodeIr>(queries);
        self.publish_one::<ECodeIr>(queries);
        self.publish_one::<ECodeSsaIr>(queries);
    }
}

impl Worker {
    pub(super) fn new(
        config: AnalysisEngineConfig,
        project: Arc<RwLock<Project>>,
        queries: QueryEngine,
        poison: Arc<OnceLock<String>>,
        cancellation: CancellationToken,
        progress: Progress,
        metrics: EngineMetrics,
    ) -> Result<Self, EngineError> {
        let mut analysers = Vec::new();
        let project_read = project.read();
        for provider in registry::iter::<AnalyserProvider>() {
            let analyser = provider.build(&project_read)?;
            if analyser.can_analyse(&project_read) {
                analysers.push(ScheduledAnalyser::new(analyser));
            }
        }
        drop(project_read);

        let mut order = (0..analysers.len()).collect::<Vec<_>>();
        order.sort_by_key(|&index| analysers[index].analyser().name());
        for (rank, index) in order.into_iter().enumerate() {
            analysers[index].set_order(rank as u32);
        }
        let analyser_count = analysers.len();
        let coverage = project
            .write()
            .coverage_mut()
            .configure(
                analysers
                    .iter()
                    .map(|state| (state.analyser().name(), state.phase())),
            )
            .into_reconfiguration();

        let revision = project.read().revision();
        let mut worker = Self {
            analysers,
            config,
            pending_diagnostics: PendingDiagnostics::default(),
            cancellation,
            poison,
            progress,
            queries,
            project,
            queue: AnalysisWorkQueue::with_analysers(analyser_count),
            dependencies: DependencyIndex::with_analysers(analyser_count),
            recent_changes: RecentChanges::new(revision),
            metrics,
            subscribers: Vec::new(),
        };

        worker.apply_coverage_reconfiguration(&coverage);
        worker.schedule_uncovered_hints();

        Ok(worker)
    }

    fn apply_coverage_reconfiguration(
        &mut self,
        reconfiguration: &coverage::CoverageReconfiguration,
    ) {
        let invalidated = reconfiguration.invalidated();
        if !invalidated.is_empty() {
            self.pending_diagnostics.defer(
                ProblemScope::for_regions(invalidated),
                ProblemKind::AnalysisCoverageInvalidated,
            );
            for analyser in reconfiguration.analysers() {
                tracing::warn!("invalidating persisted analysis coverage for {analyser}");
            }
        }

        let revision = self.project.read().revision();
        let provenance = ChangeProvenance::of(ChangeSource::engine("coverage configuration"));
        for reanalysis in reconfiguration.reanalysis() {
            let Some(index) = self
                .analysers
                .iter()
                .position(|state| state.analyser().name() == reanalysis.analyser())
            else {
                continue;
            };
            self.schedule_analyser(
                index,
                reanalysis.regions(),
                ChangeKinds::empty(),
                revision,
                &provenance,
            );
        }
    }

    fn cancel_pending_work(&mut self) {
        self.queue.clear();
        for analyser in &mut self.analysers {
            analyser.clear_claimed();
        }
        self.cancellation.clear();
        self.progress.clear_message();
    }

    fn reject_pending(rx: &Receiver<Intake>, message: &str) {
        loop {
            match rx.try_recv() {
                Ok(Intake::CreateMapping { reply, .. }) => {
                    let _ = reply.send(Err(EngineError::Poisoned(message.to_owned())));
                }
                Ok(Intake::CreateSpace(reply)) => {
                    let _ = reply.send(Err(EngineError::Poisoned(message.to_owned())));
                }
                Ok(Intake::Updates { reply, .. }) => {
                    let _ = reply.send(Err(EngineError::Poisoned(message.to_owned())));
                }
                Ok(Intake::EnsureLifted { reply, .. }) => {
                    let _ = reply.send(Err(EngineError::Poisoned(message.to_owned())));
                }
                Ok(Intake::GenerateLifted { reply, .. }) => {
                    let _ = reply.send(Err(EngineError::Poisoned(message.to_owned())));
                }
                Ok(Intake::Analyse(reply)) => {
                    let _ = reply.send(Err(EngineError::Poisoned(message.to_owned())));
                }
                Ok(
                    Intake::Cancel
                    | Intake::Direct { .. }
                    | Intake::Shutdown
                    | Intake::Subscribe(_),
                ) => {}
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
            }
        }
    }

    pub(super) fn run(mut self, rx: Receiver<Intake>) {
        let mut deferred = None;

        loop {
            let message = match deferred.take() {
                Some(message) => message,
                None => match rx.recv() {
                    Ok(message) => message,
                    Err(_) => break,
                },
            };

            match message {
                Intake::Cancel => {
                    self.cancel_pending_work();
                }
                Intake::CreateMapping { builder, reply } => {
                    let result = self
                        .drain_or_handle_cancelled()
                        .and_then(|()| self.create_mapping(builder));
                    let _ = reply.send(result);
                }
                Intake::CreateSpace(reply) => {
                    let result = self
                        .drain_or_handle_cancelled()
                        .and_then(|()| self.create_space());
                    let _ = reply.send(result);
                }
                Intake::Direct { kind, regions } => {
                    self.route_requested(kind, &regions);
                    loop {
                        match rx.try_recv() {
                            Ok(Intake::Direct { kind, regions }) => {
                                self.route_requested(kind, &regions);
                            }
                            Ok(message) => {
                                deferred = Some(message);
                                break;
                            }
                            Err(TryRecvError::Empty) => break,
                            Err(TryRecvError::Disconnected) => {
                                deferred = Some(Intake::Shutdown);
                                break;
                            }
                        }
                    }
                }

                Intake::EnsureLifted {
                    function,
                    level,
                    reply,
                } => {
                    let result = self
                        .drain_or_handle_cancelled()
                        .and_then(|()| self.ensure_lifted(function, level));
                    let _ = reply.send(result);
                }
                Intake::GenerateLifted {
                    function,
                    level,
                    reply,
                } => {
                    let result = self
                        .drain_or_handle_cancelled()
                        .and_then(|()| self.generate_lifted(function, level));
                    let _ = reply.send(result);
                }
                Intake::Updates { updates, reply } => {
                    let result = self
                        .drain_or_handle_cancelled()
                        .and_then(|()| self.apply_updates(updates));
                    let _ = reply.send(result);
                }
                Intake::Analyse(reply) => {
                    let result = self.drain_or_handle_cancelled();
                    let _ = reply.send(result);
                }
                Intake::Shutdown => {
                    if let Err(error) = self.drain_or_handle_cancelled() {
                        let message = error.to_string();
                        let _ = self.poison.set(message);
                        self.queries.mark_dead();
                    }
                    break;
                }
                Intake::Subscribe(subscriber) => {
                    self.subscribe(subscriber);
                }
            }

            if let Err(error) = self.drain_or_handle_cancelled() {
                let message = match &error {
                    EngineError::Poisoned(message) => message.clone(),
                    _ => error.to_string(),
                };
                let _ = self.poison.set(message.clone());
                self.queries.mark_dead();
                Self::reject_pending(&rx, &message);
                break;
            }
        }
    }

    fn drain_or_handle_cancelled(&mut self) -> Result<(), EngineError> {
        match self.drain() {
            Ok(()) => Ok(()),
            Err(error) if self.handle_analysis_cancelled(&error) => {
                self.cancel_pending_work();
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn handle_analysis_cancelled(&mut self, error: &EngineError) -> bool {
        if matches!(error, EngineError::Analysis(AnalysisError::Cancelled(_))) {
            self.cancellation.clear();
            true
        } else {
            false
        }
    }

    fn poison_and_stop(&self, message: String) -> EngineError {
        let _ = self.poison.set(message.clone());
        self.queries.mark_dead();
        EngineError::Poisoned(message)
    }

    fn drain(&mut self) -> Result<(), EngineError> {
        if let Some(message) = self.poison.get() {
            return Err(EngineError::Poisoned(message.clone()));
        }

        let mut completion_pending = false;
        let mut completion_rounds = 0usize;

        loop {
            loop {
                let batch = self.queue.pop_batch(WORK_SLICE_BYTES, WORK_BATCH_ITEMS);
                let degradations = self.queue.take_degradations();
                self.defer_degradations(degradations);
                if !batch.is_empty() {
                    completion_pending = true;
                    self.run_work_batch(batch)?;
                    continue;
                }

                break;
            }

            if completion_pending {
                completion_pending = false;
                self.run_completion_hooks()?;
                if !self.queue.is_empty() {
                    completion_rounds += 1;
                    if completion_rounds > MAX_COMPLETION_ROUNDS {
                        return Err(
                            self.poison_and_stop("completion hooks did not converge".to_owned())
                        );
                    }
                    continue;
                }
            }

            if !self.pending_diagnostics.is_empty() {
                self.flush_deferred_problems()?;
                if !self.queue.is_empty() || !self.pending_diagnostics.is_empty() {
                    continue;
                }
            }

            return Ok(());
        }
    }

    fn route_changes(&mut self, changes: &ChangeSet) {
        let revision = changes.revision();
        let provenance = changes.provenance();

        let mut retract = AddressRangeSet::new();
        let mut triggered = BTreeMap::<ChangeKinds, AddressRangeSet>::new();
        let mut by_kind = BTreeMap::<ChangeKinds, AddressRangeSet>::new();

        for record in changes.records() {
            let kind = record.kind();
            let affected = record.ranges();

            if Self::invalidates_bytes(record) {
                for range in &affected {
                    retract.insert_range(*range);
                }
            }

            if kind.is_empty() {
                continue;
            }

            let regions = by_kind.entry(kind).or_default();
            for range in &affected {
                regions.insert_range(*range);
            }

            let regions = triggered.entry(kind).or_default();
            match record {
                ChangeRecord::FunctionAdded { entry, .. }
                | ChangeRecord::FunctionChanged { entry, .. }
                | ChangeRecord::FunctionRemoved { entry, .. } => {
                    regions.insert(*entry);
                }
                _ => {
                    for range in affected {
                        regions.insert_range(range);
                    }
                }
            }
        }

        if !retract.is_empty() {
            self.cancel_phases(&retract, RETRACTED_BY_BYTE_CHANGE);
            self.retract_coverage(&retract);
        }

        for (kind, regions) in triggered {
            self.route_direct(kind, &regions, revision, provenance);
        }

        for (kind, regions) in by_kind {
            self.route_dependencies(kind, &regions, provenance, revision);
        }
    }

    fn route_dependencies(
        &mut self,
        kind: ChangeKinds,
        changed: &AddressRangeSet,
        provenance: &ChangeProvenance,
        revision: Revision,
    ) {
        if kind.is_empty() {
            return;
        }

        let scope = (!changed.is_empty()).then_some(changed);

        for index in 0..self.analysers.len() {
            let state = &self.analysers[index];
            let self_produced = provenance.contains(state.analyser().name())
                && state.analyser().produces().contains(kind);
            if self_produced {
                continue;
            }

            let invalidated = self.dependencies.invalidated(index, kind, scope);
            if invalidated.is_empty() {
                continue;
            }

            if invalidated.has_addressless() {
                self.metrics.record_dependency_reschedule();
                self.schedule_analyser(index, &AddressRangeSet::new(), kind, revision, provenance);
            }
            if !invalidated.regions().is_empty() {
                self.metrics.record_dependency_reschedule();
                self.schedule_analyser(index, invalidated.regions(), kind, revision, provenance);
            }
        }
    }

    fn route_direct(
        &mut self,
        kind: ChangeKinds,
        regions: &AddressRangeSet,
        revision: Revision,
        provenance: &ChangeProvenance,
    ) {
        for index in 0..self.analysers.len() {
            let state = &self.analysers[index];
            let self_produced = provenance.contains(state.analyser().name())
                && state.analyser().produces().contains(kind);
            if self_produced || !state.triggers().intersects(kind) {
                continue;
            }
            self.schedule_analyser(index, regions, kind, revision, provenance);
        }
    }

    fn route_requested(&mut self, kind: ChangeKinds, regions: &AddressRangeSet) {
        let revision = self.project.read().revision();
        let provenance = ChangeProvenance::of(ChangeSource::engine("schedule"));
        self.route_direct(kind, regions, revision, &provenance);
    }

    fn schedule_uncovered_hints(&mut self) {
        let mut regions = AddressRangeSet::new();
        let project = self.project.read();
        let revision = project.revision();

        if let Some(entry) = project.entry_point() {
            regions.insert(entry);
        }

        for (_, symbol) in project
            .symbols()
            .iter_by_address()
            .filter(|(_, symbol)| symbol.is_function())
        {
            regions.insert(symbol.address());
        }

        for hint in project.segments().function_hints() {
            regions.insert(hint);
        }

        let pending = self
            .analysers
            .iter()
            .enumerate()
            .filter(|(_, state)| state.triggers().intersects(ChangeKinds::SEGMENT_MAPPED))
            .filter_map(|(index, state)| {
                let regions = project
                    .coverage()
                    .gaps_for(state.analyser().name(), &regions);
                (!regions.is_empty()).then_some((index, regions))
            })
            .collect::<SmallVec<[_; 4]>>();
        drop(project);

        let provenance = ChangeProvenance::of(ChangeSource::engine("startup"));
        for (index, regions) in pending {
            self.schedule_analyser(
                index,
                &regions,
                ChangeKinds::SEGMENT_MAPPED,
                revision,
                &provenance,
            );
        }
    }

    fn invalidates_bytes(record: &ChangeRecord) -> bool {
        matches!(
            record,
            ChangeRecord::BytesWritten { .. } | ChangeRecord::SegmentUnmapped { .. }
        )
    }

    fn schedule_analyser(
        &mut self,
        index: usize,
        regions: &AddressRangeSet,
        kind: ChangeKinds,
        revision: Revision,
        provenance: &ChangeProvenance,
    ) {
        let state = &self.analysers[index];
        let degradations = self.queue.schedule(
            index,
            state.order(),
            state.phase(),
            state.priority(),
            regions,
            |range| WorkCause::new(range, kind, revision).with_provenance(provenance.clone()),
        );
        self.defer_degradations(degradations);
    }

    fn mark_covered(&mut self, index: usize, phase: AnalysisPhase, regions: &AddressRangeSet) {
        let state = &mut self.analysers[index];
        for range in regions.ranges() {
            state.claim(range);
        }

        if state.analyser().has_pending_work() || self.queue.has_pending_for(index) {
            return;
        }

        let claimed = self.analysers[index].take_claimed();
        if claimed.is_empty() {
            return;
        }

        let contended = self.analysers.iter().enumerate().any(|(other, state)| {
            other != index && state.phase() == phase && self.queue.has_pending_for(other)
        });

        let claimed = if contended {
            let mut narrowed = claimed;
            for (other, state) in self.analysers.iter().enumerate() {
                if other != index && state.phase() == phase {
                    narrowed = narrowed.difference(&self.queue.pending_for(other));
                }
            }
            narrowed
        } else {
            claimed
        };

        if claimed.is_empty() {
            return;
        }

        let mut project = self.project.write();
        let analyser = self.analysers[index].analyser().name();
        for range in claimed.ranges() {
            project.coverage_mut().mark(analyser, phase, range);
        }
    }

    fn cancel_phases(&mut self, region: &AddressRangeSet, phases: &[AnalysisPhase]) {
        let degradations = self.queue.cancel(phases, region);
        self.defer_degradations(degradations);

        for state in &mut self.analysers {
            if phases.contains(&state.phase()) {
                for range in region.ranges() {
                    state.retract_claimed(range);
                }
            }
        }
    }

    fn retract_coverage(&mut self, region: &AddressRangeSet) {
        if region.is_empty() {
            return;
        }

        let mut project = self.project.write();
        for range in region.ranges() {
            project.coverage_mut().clear(range);
        }
    }

    fn defer_degradations(&mut self, degradations: DegradationReport) {
        for degradation in degradations {
            let kind = match degradation.kind() {
                Degradation::CausesMerged => {
                    self.metrics.record_causes_merged();
                    ProblemKind::WorkCausesMerged
                }
                Degradation::RangesCollapsed => {
                    self.metrics.record_ranges_collapsed();
                    ProblemKind::PendingWorkCollapsed
                }
            };
            self.pending_diagnostics.defer(degradation.scope(), kind);
        }
    }

    fn defer_read_set_collapse(&mut self, regions: &AddressRangeSet) {
        self.metrics.record_read_set_collapsed();
        self.pending_diagnostics.defer(
            ProblemScope::for_regions(regions),
            ProblemKind::ReadSetCollapsed,
        );
    }

    fn flush_deferred_problems(&mut self) -> Result<(), EngineError> {
        let result = self
            .with_transaction(ChangeSource::engine("analysis diagnostics"), |_, _| {
                Ok::<(), Infallible>(())
            })?;
        match result {
            TransactionResult::Committed { .. } => Ok(()),
            TransactionResult::Rejected(error) => match error {},
        }
    }

    fn with_transaction<T, E>(
        &mut self,
        source: ChangeSource,
        operation: impl FnOnce(&mut Self, &mut ProjectTransaction<'_>) -> Result<T, E>,
    ) -> Result<TransactionResult<T, E>, EngineError> {
        let query_write = self.queries.write_guard();
        let project_lock = self.project.clone();
        let mut project = project_lock.write();
        let mut transaction = project.transaction(source);
        transaction.set_worker_limit(self.config.worker_limit());

        let deferred_problems = self
            .pending_diagnostics
            .iter()
            .collect::<SmallVec<[_; 8]>>();
        for (scope, kind) in &deferred_problems {
            transaction.add_scoped_problem(*scope, *kind)?;
        }

        match operation(self, &mut transaction) {
            Ok(value) => {
                let reads = transaction.take_reads();
                let reads_collapsed = transaction.reads_collapsed();
                let changes = transaction.commit()?;
                self.pending_diagnostics.acknowledge(&deferred_problems);
                if !changes.is_empty() {
                    self.begin_publish(&changes);
                }
                drop(project);
                drop(query_write);
                if !changes.is_empty() {
                    self.finish_publish(&changes)?;
                }
                Ok(TransactionResult::Committed {
                    value,
                    changes,
                    reads,
                    reads_collapsed,
                })
            }
            Err(error) => {
                if let Err(rejection_error) = transaction.reject() {
                    project.abandon_persistence();
                    return Err(self.poison_and_stop(rejection_error.to_string()));
                }
                drop(project);
                drop(query_write);
                Ok(TransactionResult::Rejected(error))
            }
        }
    }

    fn run_work_batch(&mut self, batch: WorkBatch) -> Result<(), EngineError> {
        let Some(first) = batch.first() else {
            return Ok(());
        };

        let index = first.analyser();
        let phase = first.phase();
        self.metrics.record_dispatch(batch.len());

        let mut regions = AddressRangeSet::new();
        let mut causes = SmallVec::<[WorkCause; 4]>::new();
        let continuation = first.is_continuation();
        for item in &batch {
            debug_assert_eq!(item.is_continuation(), continuation);
            if let Some(range) = item.range() {
                regions.insert_range(range);
            }
            for cause in item.causes() {
                if !causes.contains(cause) {
                    causes.push(cause.clone());
                }
            }
        }

        self.dispatch(index, phase, regions, causes, continuation, batch)
    }

    fn admit_analysis(
        &mut self,
        name: &'static str,
        production: AnalysisProduction,
    ) -> Result<AnalysisAdmissionResult, EngineError> {
        if let Some(conflict) = self
            .recent_changes
            .conflict(production.base, &production.reads)
        {
            match conflict {
                AdmissionConflict::InputsChanged => self.metrics.record_admission_conflict(),
                AdmissionConflict::ResynchronisationRequired => {
                    self.metrics.record_admission_resynchronisation();
                }
            }
            return Ok(AnalysisAdmissionResult::Conflict);
        }

        let AnalysisProduction {
            outcome,
            reads,
            reads_collapsed,
            updates,
            ..
        } = production;
        let result =
            self.with_transaction(ChangeSource::analysis(name), move |_, transaction| {
                transaction.absorb_reads(&reads);
                ProjectUpdate::apply_all(updates, transaction)
                    .map_err(|error| AnalysisError::pass_failed(name, error))?;
                Ok::<_, AnalysisError>(outcome)
            })?;

        Ok(match result {
            TransactionResult::Committed {
                value,
                reads,
                reads_collapsed: admission_reads_collapsed,
                ..
            } => AnalysisAdmissionResult::Committed(AnalysisAdmission {
                outcome: value,
                reads,
                reads_collapsed: reads_collapsed || admission_reads_collapsed,
            }),
            TransactionResult::Rejected(error) => AnalysisAdmissionResult::Rejected(error),
        })
    }

    fn dispatch(
        &mut self,
        index: usize,
        phase: AnalysisPhase,
        regions: AddressRangeSet,
        causes: SmallVec<[WorkCause; 4]>,
        continuation: bool,
        batch: WorkBatch,
    ) -> Result<(), EngineError> {
        let name = self.analysers[index].analyser().name();
        self.progress.reset();
        let cx = AnalysisContext::new(self.cancellation.child(), self.progress.clone())
            .with_worker_limit(self.config.worker_limit())
            .with_work(phase, causes, continuation);

        let production = {
            let project = self.project.read();
            let base = project.revision();
            let view = ProjectView::new(&project);
            let mut updates = Vec::new();
            let analysis =
                self.analysers[index]
                    .analyser_mut()
                    .analyse(&view, &regions, &cx, &mut updates);
            let reads_collapsed = view.collapsed();
            let reads = view.into_reads();
            AnalysisProduction::from_analysis(base, analysis, reads, reads_collapsed, updates)
        };
        let production = match production {
            Ok(production) => production,
            Err(error) => return self.handle_dispatch_failure(index, batch, error),
        };
        match self.admit_analysis(name, production)? {
            AnalysisAdmissionResult::Committed(AnalysisAdmission {
                outcome: Ok(()),
                reads,
                reads_collapsed,
            }) => {
                self.dependencies.record(index, &regions, reads);
                if reads_collapsed {
                    self.defer_read_set_collapse(&regions);
                }
                if phase != AnalysisPhase::Retract {
                    self.mark_covered(index, phase, &regions);
                }
                if self.analysers[index].analyser().has_pending_work() {
                    let degradations = self.queue.requeue_continuation(batch);
                    self.defer_degradations(degradations);
                }
                self.progress.clear_message();
                Ok(())
            }
            AnalysisAdmissionResult::Committed(AnalysisAdmission {
                outcome: Err(cancelled),
                ..
            }) => {
                self.progress.clear_message();
                Err(AnalysisError::Cancelled(cancelled).into())
            }
            AnalysisAdmissionResult::Conflict => self.handle_admission_conflict(batch),
            AnalysisAdmissionResult::Rejected(error) => {
                self.handle_dispatch_failure(index, batch, error)
            }
        }
    }

    fn handle_admission_conflict(&mut self, batch: WorkBatch) -> Result<(), EngineError> {
        for item in batch {
            let degradations = self.queue.requeue(item);
            self.defer_degradations(degradations);
        }
        self.progress.clear_message();
        Ok(())
    }

    fn handle_dispatch_failure(
        &mut self,
        index: usize,
        batch: WorkBatch,
        error: AnalysisError,
    ) -> Result<(), EngineError> {
        let name = self.analysers[index].analyser().name();
        let bound = self.analysers[index].max_attempts();
        tracing::warn!("analyser {name} failed: {error}");

        for mut item in batch {
            item.record_attempt();

            if usize::from(item.attempts()) >= bound {
                self.metrics.record_retry_exhausted();
                self.pending_diagnostics.defer(
                    item.range()
                        .map(ProblemScope::Range)
                        .unwrap_or(ProblemScope::Global),
                    ProblemKind::RetryBudgetExhausted,
                );
                continue;
            }

            self.metrics.record_retry();
            let degradations = self.queue.requeue(item);
            self.defer_degradations(degradations);
        }

        self.progress.clear_message();
        Ok(())
    }

    fn run_completion_hooks(&mut self) -> Result<(), EngineError> {
        for index in 0..self.analysers.len() {
            self.run_completion_hook(index)?;
        }

        Ok(())
    }

    fn run_completion_hook(&mut self, index: usize) -> Result<(), EngineError> {
        let name = self.analysers[index].analyser().name();
        self.progress.reset();
        for _ in 0..MAX_COMPLETION_ROUNDS {
            let cx = AnalysisContext::new(self.cancellation.child(), self.progress.clone())
                .with_worker_limit(self.config.worker_limit());
            let production = {
                let project = self.project.read();
                let base = project.revision();
                let view = ProjectView::new(&project);
                let mut updates = Vec::new();
                let analysis =
                    self.analysers[index]
                        .analyser_mut()
                        .analysis_ended(&view, &cx, &mut updates);
                let reads_collapsed = view.collapsed();
                let reads = view.into_reads();
                AnalysisProduction::from_analysis(base, analysis, reads, reads_collapsed, updates)
            };
            let production = match production {
                Ok(production) => production,
                Err(error) => {
                    tracing::warn!("analyser {name} completion failed: {error}");
                    self.progress.clear_message();
                    return Err(error.into());
                }
            };

            return match self.admit_analysis(name, production)? {
                AnalysisAdmissionResult::Committed(AnalysisAdmission {
                    outcome: Ok(()),
                    reads_collapsed,
                    ..
                }) => {
                    if reads_collapsed {
                        self.defer_read_set_collapse(&AddressRangeSet::new());
                    }
                    self.progress.clear_message();
                    Ok(())
                }
                AnalysisAdmissionResult::Committed(AnalysisAdmission {
                    outcome: Err(cancelled),
                    ..
                }) => {
                    self.progress.clear_message();
                    Err(AnalysisError::Cancelled(cancelled).into())
                }
                AnalysisAdmissionResult::Conflict => continue,
                AnalysisAdmissionResult::Rejected(error) => {
                    tracing::warn!("analyser {name} completion failed: {error}");
                    self.progress.clear_message();
                    Err(error.into())
                }
            };
        }

        self.progress.clear_message();
        Err(self.poison_and_stop(format!(
            "analyser {name} completion admission did not converge"
        )))
    }

    fn apply_updates(
        &mut self,
        updates: impl IntoIterator<Item = ProjectUpdate>,
    ) -> Result<ChangeSet, EngineError> {
        match self.with_transaction(ChangeSource::engine("update"), |_, transaction| {
            ProjectUpdate::apply_all(updates, transaction)?;
            Ok::<(), ProjectError>(())
        })? {
            TransactionResult::Committed { changes, .. } => Ok(changes),
            TransactionResult::Rejected(error) => Err(error.into()),
        }
    }

    fn ensure_lifted(
        &mut self,
        function: FunctionId,
        level: IlLevel,
    ) -> Result<ChangeSet, EngineError> {
        let cancellation = self.cancellation.child();
        let prepared =
            self.prepare_lifted(function, level, LiftedLookup::Persisted, &cancellation)?;
        let result = self
            .with_transaction(ChangeSource::engine("ensure IR"), move |_, transaction| {
                prepared.admit(transaction)
            })?;

        match result {
            TransactionResult::Committed { changes, .. } => Ok(changes),
            TransactionResult::Rejected(error) => Err(error.into()),
        }
    }

    fn generate_lifted(
        &mut self,
        function: FunctionId,
        level: IlLevel,
    ) -> Result<Option<Arc<dyn Any + Send + Sync>>, EngineError> {
        match level {
            IlLevel::PCode => self.generate::<PCodeIr>(function),
            IlLevel::ECode => self.generate::<ECodeIr>(function),
            IlLevel::ECodeSsa => self.generate::<ECodeSsaIr>(function),
        }
    }

    fn generate<T>(
        &mut self,
        function: FunctionId,
    ) -> Result<Option<Arc<dyn Any + Send + Sync>>, EngineError>
    where
        T: GeneratedIl,
    {
        let mut prepared = self.prepare_generated_lifted(function, T::LEVEL)?;
        let generated = prepared.publish_one::<T>(&self.queries);
        prepared.publish(&self.queries);
        match generated {
            Some(ir) => Ok(Some(ir)),
            None => Ok(self
                .current_query_lifted::<T>(function)?
                .map(|ir| ir as Arc<dyn Any + Send + Sync>)),
        }
    }

    fn prepare_generated_lifted(
        &mut self,
        function: FunctionId,
        level: IlLevel,
    ) -> Result<PreparedLiftedArtefacts, EngineError> {
        let cancellation = self.cancellation.child();
        let mut prepared =
            self.prepare_lifted(function, level, LiftedLookup::Current, &cancellation)?;
        if prepared.pcode_references.is_none() {
            return Ok(prepared);
        }

        let result = self.with_transaction(
            ChangeSource::engine("generated PCode references"),
            |_, transaction| prepared.admit_references(transaction),
        )?;
        match result {
            TransactionResult::Committed { .. } => Ok(prepared),
            TransactionResult::Rejected(error) => Err(error.into()),
        }
    }

    fn prepare_lifted(
        &self,
        function: FunctionId,
        level: IlLevel,
        lookup: LiftedLookup,
        cancellation: &CancellationToken,
    ) -> Result<PreparedLiftedArtefacts, EngineError> {
        cancellation.check().map_err(ProjectError::from)?;
        if function.is_invalid() {
            return Err(
                ProjectError::from(IlError::missing_artefact(function, IlLevel::PCode)).into(),
            );
        }

        let project = self.project.read();
        let view = ProjectView::new(&project);
        let revision = project.semantic_revision();
        let existing_pcode = self
            .queries
            .current_lifted::<PCodeIr>(&project, function, lookup)?;
        let existing_ecode = self
            .queries
            .current_lifted::<ECodeIr>(&project, function, lookup)?;
        let existing_ecode_ssa = self
            .queries
            .current_lifted::<ECodeSsaIr>(&project, function, lookup)?;
        let build_ecode = level >= IlLevel::ECode && existing_ecode.is_none();
        let build_pcode = (level == IlLevel::PCode || build_ecode) && existing_pcode.is_none();
        let build_ecode_ssa = level == IlLevel::ECodeSsa && existing_ecode_ssa.is_none();
        let mut prepared = PreparedLiftedArtefacts::default();

        if build_pcode {
            let mut canonicaliser = PCodeCanonicaliser::default();
            let pcode = canonicaliser
                .build_function(PCodeFunctionInput::new(
                    view.language(),
                    view.functions(),
                    view.blocks(),
                    view.segments(),
                    function,
                    revision,
                    cancellation,
                ))
                .map_err(ProjectError::from)?;
            if cfg!(debug_assertions)
                && let Err(error) = pcode.verify()
            {
                panic!("canonicalised pcode for {function:?} fails verification: {error}");
            }

            let mut coverage = AddressRangeSet::new();
            pcode.reference_coverage_into(&mut coverage);
            if let Some(function) = view.functions().get_by_id(function) {
                view.blocks()
                    .coverage_into(function.blocks().map(|(_, block)| block), &mut coverage);
            }
            prepared.pcode_references = Some(PreparedDerivedReferences {
                coverage,
                references: pcode.data_references().collect(),
            });
            prepared.pcode = Some(pcode);
        }

        if build_ecode {
            let source = prepared
                .pcode
                .as_ref()
                .or(existing_pcode.as_deref())
                .ok_or_else(|| IlError::missing_artefact(function, IlLevel::PCode))
                .map_err(ProjectError::from)?;
            let mut transform = PCodeToECode::default();
            let ecode = transform
                .transform(source, view.arch(), view.platform(), cancellation)
                .map_err(ProjectError::from)?;
            if cfg!(debug_assertions) {
                ecode
                    .verify()
                    .expect("transformed ecode fails verification");
            }
            prepared.ecode = Some(ecode);
        }

        if build_ecode_ssa {
            let source = prepared
                .ecode
                .as_ref()
                .or(existing_ecode.as_deref())
                .ok_or_else(|| IlError::missing_artefact(function, IlLevel::ECode))
                .map_err(ProjectError::from)?;
            let mut transform = ECodeToSsa::default();
            prepared.ecode_ssa = Some(
                transform
                    .transform_optimised(source, cancellation)
                    .map_err(ProjectError::from)?,
            );
        }

        Ok(prepared)
    }

    fn current_query_lifted<T>(&self, function: FunctionId) -> Result<Option<Arc<T>>, EngineError>
    where
        T: IlArtefact + QueryCachedIl,
    {
        let project = self.project.read();
        self.queries
            .current_lifted(&project, function, LiftedLookup::Current)
            .map_err(EngineError::from)
    }

    fn create_mapping(
        &mut self,
        builder: SegmentMappingBuilder,
    ) -> Result<MappingCreationResult, EngineError> {
        match self.with_transaction(ChangeSource::engine("update"), |_, transaction| {
            transaction.create_mapping(builder)
        })? {
            TransactionResult::Committed {
                value: mapping,
                changes,
                ..
            } => Ok(MappingCreationResult::new(mapping, changes)),
            TransactionResult::Rejected(error) => Err(error.into()),
        }
    }

    fn create_space(&mut self) -> Result<SpaceCreationResult, EngineError> {
        match self.with_transaction(ChangeSource::engine("update"), |_, transaction| {
            transaction.create_space()
        })? {
            TransactionResult::Committed {
                value: space,
                changes,
                ..
            } => Ok(SpaceCreationResult::new(space, changes)),
            TransactionResult::Rejected(error) => Err(error.into()),
        }
    }

    fn begin_publish(&mut self, changes: &ChangeSet) {
        debug_assert!(!changes.is_empty());

        self.recent_changes.record(changes);
        if changes.contains(ChangeKinds::RESYNCHRONISE) {
            self.pending_diagnostics
                .defer(ProblemScope::Global, ProblemKind::ChangeIndexCollapsed);
        }
        if self.queries.apply_changes(changes) {
            self.pending_diagnostics
                .defer(ProblemScope::Global, ProblemKind::ChangeIndexCollapsed);
        }
    }

    fn finish_publish(&mut self, changes: &ChangeSet) -> Result<(), EngineError> {
        let mut resync = None;
        self.subscribers
            .retain(|subscriber| subscriber.materialise(changes, &mut resync));
        self.route_changes(changes);
        Ok(())
    }

    fn subscribe(&mut self, subscriber: Subscriber) {
        let revision = self.project.read().revision();

        if revision != Revision::default() {
            let resynchronisation = Arc::new(
                ChangeSet::with_records(revision, [ChangeRecord::Resynchronise { to: revision }])
                    .with_provenance(ChangeSource::engine("subscription")),
            );
            if !subscriber.resync(resynchronisation) {
                return;
            }
        }

        self.subscribers.push(subscriber);
    }
}

#[cfg(test)]
mod test {
    use super::{AdmissionConflict, PendingDiagnostics, RecentChanges};
    use crate::engine::ReadSet;
    use crate::engine::change::{
        ChangeKinds, ChangeRecord, ChangeSet, MAX_DETAILED_CHANGE_RECORDS, Revision,
    };
    use crate::ir::{Address, AddressRange, ProblemKind, ProblemScope};
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn pending_diagnostics_are_bounded_by_kind() {
        let first = AddressSpaceId::from(0u8);
        let second = AddressSpaceId::from(1u8);
        let mut pending = PendingDiagnostics::default();

        pending.defer(
            ProblemScope::Range(AddressRange::new(first, 0x1000u64.into(), 0x1fffu64.into())),
            ProblemKind::PendingWorkCollapsed,
        );
        pending.defer(
            ProblemScope::Range(AddressRange::new(
                second,
                0x1000u64.into(),
                0x1fffu64.into(),
            )),
            ProblemKind::PendingWorkCollapsed,
        );
        pending.defer(
            ProblemScope::AddressSpace(first),
            ProblemKind::WorkCausesMerged,
        );

        let diagnostics = pending.iter().collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 2);
        assert!(diagnostics.contains(&(ProblemScope::Global, ProblemKind::PendingWorkCollapsed)));
        assert!(diagnostics.contains(&(
            ProblemScope::AddressSpace(first),
            ProblemKind::WorkCausesMerged
        )));
    }

    #[test]
    fn recent_changes_detect_only_observed_conflicts() {
        let space = AddressSpaceId::from(0u8);
        let mut window = RecentChanges::new(Revision::new(0));
        let changes = ChangeSet::with_records(
            Revision::new(1),
            [ChangeRecord::BytesWritten {
                range: AddressRange::new(space, 0x1000u64.into(), 0x1fffu64.into()),
            }],
        );
        window.record(&changes);

        let mut overlapping = ReadSet::new();
        overlapping.record(
            ChangeKinds::BYTES_WRITTEN,
            AddressRange::new(space, 0x1800u64.into(), 0x18ffu64.into()),
        );
        assert_eq!(
            window.conflict(Revision::new(0), &overlapping),
            Some(AdmissionConflict::InputsChanged)
        );

        let mut elsewhere = ReadSet::new();
        elsewhere.record(
            ChangeKinds::BYTES_WRITTEN,
            AddressRange::new(space, 0x3000u64.into(), 0x30ffu64.into()),
        );
        assert_eq!(window.conflict(Revision::new(0), &elsewhere), None);
    }

    #[test]
    fn oversized_change_sets_bound_the_admission_window() {
        let space = AddressSpaceId::from(0u8);
        let records = (0..=MAX_DETAILED_CHANGE_RECORDS)
            .map(|index| ChangeRecord::BytesWritten {
                range: AddressRange::point(Address::new(space, index as u64)),
            })
            .collect::<Vec<_>>();
        let mut window = RecentChanges::new(Revision::new(0));
        window.record(&ChangeSet::with_records(Revision::new(1), records));

        assert_eq!(
            window.conflict(Revision::new(0), &ReadSet::new()),
            Some(AdmissionConflict::ResynchronisationRequired)
        );
        assert_eq!(window.conflict(Revision::new(1), &ReadSet::new()), None);
    }
}
