use std::any::Any;
use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::sync::{Arc, OnceLock};

use flume::{Receiver, Sender, TryRecvError};
use parking_lot::RwLock;
use smallvec::SmallVec;

use super::scheduler::{
    AnalyserId, AnalyserOrder, AnalysisWorkQueue, Degradation, DegradationReport, IlAnalysisInputs,
    ScheduledAnalyser, WORK_SLICE_BYTES, WorkBatch,
};
use super::subscription::Subscriber;
use super::update::{MappingCreationResult, ProjectUpdate, SpaceCreationResult};
use super::view::DependencyIndex;
use super::{
    AnalyserProvider, AnalysisContext, AnalysisEngineConfig, EngineError, EngineMetrics,
    MAX_COMPLETION_ROUNDS, ProjectView, RETRACTED_BY_BYTE_CHANGE, WORK_BATCH_ITEMS, WorkCause,
};
use crate::analysis::AnalysisError;
use crate::analysis::control::{CancellationToken, Cancelled, Progress};
use crate::extension;
use crate::il::common::{IlError, IlFormId, IlGenerationContext, IlSubject};
use crate::il::registry::{GeneratedArtefact, IlGenerationSession, IlRegistry};
use crate::ir::{AddressRangeSet, FunctionId, ProblemKind, ProblemScope};
use crate::project::{
    AnalysisPhase, ChangeKinds, ChangeProvenance, ChangeRecord, ChangeSet, ChangeSource,
    CoverageReconfiguration, MAX_DETAILED_CHANGE_RECORDS, Project, ProjectError,
    ProjectTransaction, ReadSet,
};
use crate::queries::{IlLookup, QueryEngine};
use crate::storage::segments::mapping::SegmentMappingBuilder;
use crate::types::Revision;

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
        form: IlFormId,
        reply: Sender<Result<ChangeSet, EngineError>>,
    },
    GenerateLifted {
        function: FunctionId,
        form: IlFormId,
        reply: Sender<Result<Option<Arc<dyn Any + Send + Sync>>, EngineError>>,
    },
    Shutdown,
    Subscribe(Subscriber),
    Updates {
        source: ChangeSource,
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

pub(crate) struct Worker {
    analysers: Vec<ScheduledAnalyser>,
    config: AnalysisEngineConfig,
    pending_diagnostics: PendingDiagnostics,
    cancellation: CancellationToken,
    poison: Arc<OnceLock<String>>,
    progress: Progress,
    project: Arc<RwLock<Project>>,
    queries: QueryEngine,
    generation: IlGenerationSession,
    il_inputs: Option<IlAnalysisInputs>,
    registry: Arc<IlRegistry>,
    queue: AnalysisWorkQueue,
    dependencies: DependencyIndex,
    recent_changes: RecentChanges,
    metrics: EngineMetrics,
    subscribers: Vec<Subscriber>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmissionConflict {
    InputsChanged,
    ResynchronisationRequired,
}

struct RecentChanges {
    changes: VecDeque<ChangeSet>,
    floor: Revision,
    latest: Revision,
    records: usize,
}

impl RecentChanges {
    fn new(revision: Revision) -> Self {
        Self {
            changes: VecDeque::new(),
            floor: revision,
            latest: revision,
            records: 0,
        }
    }

    fn record(&mut self, changes: &ChangeSet) {
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

    fn conflict(&self, base: Revision, reads: &ReadSet) -> Option<AdmissionConflict> {
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
struct PendingDiagnostics {
    scopes: BTreeMap<ProblemKind, ProblemScope>,
}

impl PendingDiagnostics {
    fn defer(&mut self, scope: ProblemScope, kind: ProblemKind) {
        self.scopes
            .entry(kind)
            .and_modify(|existing| *existing = existing.covering(scope))
            .or_insert(scope);
    }

    fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }

    fn iter(&self) -> impl Iterator<Item = (ProblemScope, ProblemKind)> + '_ {
        self.scopes.iter().map(|(&kind, &scope)| (scope, kind))
    }

    fn acknowledge(&mut self, diagnostics: &[(ProblemScope, ProblemKind)]) {
        for (_, kind) in diagnostics {
            self.scopes.remove(kind);
        }
    }
}

#[derive(Default)]
struct PreparedLiftedArtefacts {
    artefacts: Vec<GeneratedArtefact>,
}

impl PreparedLiftedArtefacts {
    fn new(artefacts: Vec<GeneratedArtefact>) -> Self {
        Self { artefacts }
    }

    fn admit(self, transaction: &mut ProjectTransaction<'_>) -> Result<(), ProjectError> {
        for artefact in self.artefacts {
            let form = artefact.form().clone();
            transaction.materialise_erased(&form, artefact.into_value())?;
        }
        Ok(())
    }
}

impl Worker {
    pub(crate) fn new(
        config: AnalysisEngineConfig,
        project: Arc<RwLock<Project>>,
        queries: QueryEngine,
        poison: Arc<OnceLock<String>>,
        cancellation: CancellationToken,
        progress: Progress,
        metrics: EngineMetrics,
    ) -> Result<Self, EngineError> {
        let registry = config.registry_handle();
        let mut analysers = Vec::new();
        let project_read = project.read();
        for provider in extension::iter::<AnalyserProvider>() {
            let analyser = provider.build(&project_read)?;
            if analyser.can_analyse(&project_read) {
                let id = AnalyserId::new(analysers.len());
                analysers.push(ScheduledAnalyser::new(id, analyser, provider.il_input()));
            }
        }
        drop(project_read);

        let mut order = analysers
            .iter()
            .map(ScheduledAnalyser::id)
            .collect::<Vec<_>>();
        order.sort_by_key(|id| analysers[id.index()].analyser().name());
        for (rank, id) in order.into_iter().enumerate() {
            let rank = u32::try_from(rank).expect("number of analysers must fit in u32");
            analysers[id.index()].set_order(AnalyserOrder::new(rank));
        }
        let analyser_count = analysers.len();
        let coverage = project
            .write()
            .coverage_mut()
            .configure(
                analysers
                    .iter()
                    .filter(|state| state.il_input().is_none())
                    .map(|state| (state.analyser().name(), state.phase())),
            )
            .into_reconfiguration();

        let revision = project.read().revision();
        let generation = IlGenerationSession::new(&registry);
        let mut worker = Self {
            analysers,
            config,
            pending_diagnostics: PendingDiagnostics::default(),
            cancellation,
            poison,
            progress,
            queries,
            generation,
            il_inputs: None,
            registry,
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

    fn apply_coverage_reconfiguration(&mut self, reconfiguration: &CoverageReconfiguration) {
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
            let Some(id) = self
                .analysers
                .iter()
                .find(|state| state.analyser().name() == reanalysis.analyser())
                .map(ScheduledAnalyser::id)
            else {
                continue;
            };
            self.schedule_analyser(
                id,
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

    pub(crate) fn run(mut self, rx: Receiver<Intake>) {
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
                    form,
                    reply,
                } => {
                    let result = self
                        .drain_or_handle_cancelled()
                        .and_then(|()| self.ensure_lifted(function, &form));
                    let _ = reply.send(result);
                }
                Intake::GenerateLifted {
                    function,
                    form,
                    reply,
                } => {
                    let result = self
                        .drain_or_handle_cancelled()
                        .and_then(|()| self.generate_lifted(function, &form));
                    let _ = reply.send(result);
                }
                Intake::Updates {
                    source,
                    updates,
                    reply,
                } => {
                    let result = self
                        .drain_or_handle_cancelled()
                        .and_then(|()| self.apply_updates(source, updates));
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

        for id in (0..self.analysers.len()).map(AnalyserId::new) {
            let state = &self.analysers[id.index()];
            let self_produced = provenance.contains(state.analyser().name())
                && state.analyser().produces().contains(kind);
            if self_produced {
                continue;
            }

            let invalidated = self.dependencies.invalidated(id, kind, scope);
            if invalidated.is_empty() {
                continue;
            }

            if invalidated.has_addressless() {
                self.metrics.record_dependency_reschedule();
                self.schedule_analyser(id, &AddressRangeSet::new(), kind, revision, provenance);
            }
            if !invalidated.regions().is_empty() {
                self.metrics.record_dependency_reschedule();
                self.schedule_analyser(id, invalidated.regions(), kind, revision, provenance);
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
        for id in (0..self.analysers.len()).map(AnalyserId::new) {
            let state = &self.analysers[id.index()];
            let self_produced = provenance.contains(state.analyser().name())
                && state.analyser().produces().contains(kind);
            if self_produced || !state.triggers().intersects(kind) {
                continue;
            }
            self.schedule_analyser(id, regions, kind, revision, provenance);
        }
    }

    fn route_requested(&mut self, kind: ChangeKinds, regions: &AddressRangeSet) {
        let revision = self.project.read().revision();
        let provenance = ChangeProvenance::of(ChangeSource::engine("schedule"));
        self.route_direct(kind, regions, revision, &provenance);
    }

    fn schedule_il_analysers(&mut self, function: FunctionId) {
        let inputs = self
            .il_inputs
            .as_ref()
            .expect("generated IL scheduling requires prepared inputs");
        let analysers = self
            .analysers
            .iter()
            .filter_map(|analyser| {
                analyser
                    .il_input()
                    .is_some_and(|form| inputs.contains(form))
                    .then_some(analyser.id())
            })
            .collect::<SmallVec<[_; 4]>>();
        if analysers.is_empty() {
            return;
        }

        let mut regions = AddressRangeSet::new();
        let project = self.project.read();
        let function_body = project
            .functions()
            .get_by_id(function)
            .expect("generated IL must belong to a current function");
        project
            .blocks()
            .coverage_into(function_body.blocks().map(|(_, block)| block), &mut regions);
        if regions.is_empty() {
            regions.insert(function_body.entry());
        }
        let revision = project.revision();
        drop(project);

        let provenance = ChangeProvenance::of(ChangeSource::engine("generated IL"));
        for id in analysers {
            self.schedule_analyser(id, &regions, ChangeKinds::empty(), revision, &provenance);
        }
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
            .filter(|state| state.triggers().intersects(ChangeKinds::SEGMENT_MAPPED))
            .filter_map(|state| {
                let regions = project
                    .coverage()
                    .gaps_for(state.analyser().name(), &regions);
                (!regions.is_empty()).then_some((state.id(), regions))
            })
            .collect::<SmallVec<[_; 4]>>();
        drop(project);

        let provenance = ChangeProvenance::of(ChangeSource::engine("startup"));
        for (id, regions) in pending {
            self.schedule_analyser(
                id,
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
        id: AnalyserId,
        regions: &AddressRangeSet,
        kind: ChangeKinds,
        revision: Revision,
        provenance: &ChangeProvenance,
    ) {
        let state = &self.analysers[id.index()];
        let degradations = self.queue.schedule(
            id,
            state.order(),
            state.phase(),
            state.priority(),
            regions,
            |range| WorkCause::new(range, kind, revision).with_provenance(provenance.clone()),
        );
        self.defer_degradations(degradations);
    }

    fn mark_covered(&mut self, id: AnalyserId, phase: AnalysisPhase, regions: &AddressRangeSet) {
        let state = &mut self.analysers[id.index()];
        if state.il_input().is_some() {
            return;
        }
        for range in regions.ranges() {
            state.claim(range);
        }

        if state.analyser().has_pending_work() || self.queue.has_pending_for(id) {
            return;
        }

        let claimed = self.analysers[id.index()].take_claimed();
        if claimed.is_empty() {
            return;
        }

        let contended = self.analysers.iter().any(|state| {
            state.id() != id && state.phase() == phase && self.queue.has_pending_for(state.id())
        });

        let claimed = if contended {
            let mut narrowed = claimed;
            for state in &self.analysers {
                if state.id() != id && state.phase() == phase {
                    narrowed = narrowed.difference(&self.queue.pending_for(state.id()));
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
        let analyser = self.analysers[id.index()].analyser().name();
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
        let query_publication = self.queries.begin_publication();
        let project_lock = self.project.clone();
        let mut project = project_lock.write();
        let mut transaction = project.transaction_with_registry(source, self.registry.clone());

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
                drop(query_publication);
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
                drop(query_publication);
                Ok(TransactionResult::Rejected(error))
            }
        }
    }

    fn run_work_batch(&mut self, batch: WorkBatch) -> Result<(), EngineError> {
        let Some(first) = batch.first() else {
            return Ok(());
        };

        let id = first.analyser();
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

        self.dispatch(id, phase, regions, causes, continuation, batch)
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
        id: AnalyserId,
        phase: AnalysisPhase,
        regions: AddressRangeSet,
        causes: SmallVec<[WorkCause; 4]>,
        continuation: bool,
        batch: WorkBatch,
    ) -> Result<(), EngineError> {
        let name = self.analysers[id.index()].analyser().name();
        self.progress.reset();
        let cx = AnalysisContext::new(self.cancellation.child(), self.progress.clone())
            .with_worker_limit(self.config.worker_limit())
            .with_work(phase, causes, continuation);

        let production = {
            let project = self.project.read();
            let base = project.revision();
            let view = match self.il_inputs.as_ref() {
                Some(inputs) => ProjectView::with_il_inputs(&project, &self.registry, inputs),
                None => ProjectView::with_registry(&project, &self.registry),
            };
            let mut updates = Vec::new();
            let analysis = self.analysers[id.index()].analyser_mut().analyse(
                &view,
                &regions,
                &cx,
                &mut updates,
            );
            let reads_collapsed = view.collapsed();
            let reads = view.into_reads();
            AnalysisProduction::from_analysis(base, analysis, reads, reads_collapsed, updates)
        };
        let production = match production {
            Ok(production) => production,
            Err(error) => return self.handle_dispatch_failure(id, batch, error),
        };
        match self.admit_analysis(name, production)? {
            AnalysisAdmissionResult::Committed(AnalysisAdmission {
                outcome: Ok(()),
                reads,
                reads_collapsed,
            }) => {
                self.dependencies.record(id, &regions, reads);
                if reads_collapsed {
                    self.defer_read_set_collapse(&regions);
                }
                if phase != AnalysisPhase::Retract {
                    self.mark_covered(id, phase, &regions);
                }
                if self.analysers[id.index()].analyser().has_pending_work() {
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
                self.handle_dispatch_failure(id, batch, error)
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
        id: AnalyserId,
        batch: WorkBatch,
        error: AnalysisError,
    ) -> Result<(), EngineError> {
        let name = self.analysers[id.index()].analyser().name();
        let bound = self.analysers[id.index()].max_attempts();
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
        for id in (0..self.analysers.len()).map(AnalyserId::new) {
            self.run_completion_hook(id)?;
        }

        Ok(())
    }

    fn run_completion_hook(&mut self, id: AnalyserId) -> Result<(), EngineError> {
        let name = self.analysers[id.index()].analyser().name();
        self.progress.reset();
        for _ in 0..MAX_COMPLETION_ROUNDS {
            let cx = AnalysisContext::new(self.cancellation.child(), self.progress.clone())
                .with_worker_limit(self.config.worker_limit());
            let production = {
                let project = self.project.read();
                let base = project.revision();
                let view = match self.il_inputs.as_ref() {
                    Some(inputs) => ProjectView::with_il_inputs(&project, &self.registry, inputs),
                    None => ProjectView::with_registry(&project, &self.registry),
                };
                let mut updates = Vec::new();
                let analysis = self.analysers[id.index()].analyser_mut().analysis_ended(
                    &view,
                    &cx,
                    &mut updates,
                );
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
        source: ChangeSource,
        updates: impl IntoIterator<Item = ProjectUpdate>,
    ) -> Result<ChangeSet, EngineError> {
        match self.with_transaction(source, |_, transaction| {
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
        form: &IlFormId,
    ) -> Result<ChangeSet, EngineError> {
        let cancellation = self.cancellation.child();
        let prepared = self.prepare_lifted(function, form, IlLookup::Persisted, &cancellation)?;
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
        form: &IlFormId,
    ) -> Result<Option<Arc<dyn Any + Send + Sync>>, EngineError> {
        let prepared = self.prepare_generated_lifted(function, form)?;
        if prepared.artefacts.is_empty() {
            let project = self.project.read();
            return self
                .queries
                .lookup_lifted_erased(&project, function, form, IlLookup::Current)
                .map_err(EngineError::from);
        }

        let inputs = IlAnalysisInputs::new(function, prepared.artefacts);
        let generated = inputs.requested(form);
        self.il_inputs = Some(inputs);
        self.schedule_il_analysers(function);
        let admission = self.drain();
        let inputs = self
            .il_inputs
            .take()
            .expect("generated IL analysis owns its prepared inputs");
        admission?;

        for artefact in inputs.into_artefacts() {
            let form = artefact.form().clone();
            self.queries
                .insert_lifted_erased(function, &form, artefact.into_artefact())?;
        }

        match generated {
            Some(generated) => Ok(Some(generated)),
            None => {
                let project = self.project.read();
                self.queries
                    .lookup_lifted_erased(&project, function, form, IlLookup::Current)
                    .map_err(EngineError::from)
            }
        }
    }

    fn prepare_generated_lifted(
        &mut self,
        function: FunctionId,
        form: &IlFormId,
    ) -> Result<PreparedLiftedArtefacts, EngineError> {
        let cancellation = self.cancellation.child();
        self.prepare_lifted(function, form, IlLookup::Current, &cancellation)
    }

    fn prepare_lifted(
        &mut self,
        function: FunctionId,
        form: &IlFormId,
        lookup: IlLookup,
        cancellation: &CancellationToken,
    ) -> Result<PreparedLiftedArtefacts, EngineError> {
        cancellation.check().map_err(ProjectError::from)?;
        let registry = self.registry.clone();
        let path = registry.canonical_path(form);
        if function.is_invalid() {
            let root = path.first().unwrap_or(form).clone();
            return Err(ProjectError::from(IlError::missing_artefact(function, root)).into());
        }

        let project = self.project.read();
        let view = ProjectView::with_registry(&project, &registry);
        let context = IlGenerationContext::new(
            IlSubject::Admitted(function),
            view.arch(),
            view.platform(),
            view.functions(),
            view.blocks(),
            view.segments(),
            project.semantic_revision(),
        );

        let existing = path
            .iter()
            .map(|step| {
                self.queries
                    .lookup_lifted_erased(&project, function, step, lookup)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let generated = self
            .generation
            .generate(&registry, form, existing, &context, cancellation)
            .map_err(ProjectError::from)?;

        Ok(PreparedLiftedArtefacts::new(generated.into_artefacts()))
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
    use crate::ir::{Address, AddressRange, ProblemKind, ProblemScope};
    use crate::project::{
        ChangeKinds, ChangeRecord, ChangeSet, MAX_DETAILED_CHANGE_RECORDS, ReadSet,
    };
    use crate::storage::segments::space::AddressSpaceId;
    use crate::types::Revision;

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
