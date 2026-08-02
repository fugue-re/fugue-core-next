use std::cell::Cell;
use std::cmp::Ordering;
use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, OnceLock};
use std::thread::{Builder, JoinHandle};

use flume::{Receiver, RecvError, Selector, Sender, TryRecvError};
use parking_lot::RwLock;
use smallvec::SmallVec;
use thiserror::Error;

use self::change::{ChangeFilter, ChangeKinds, ChangeProvenance, ChangeSet, Revision};
use crate::analysis::AnalysisError;
use crate::analysis::control::{CancellationToken, Progress};
use crate::il::common::IlLevel;
use crate::ir::{
    Address, AddressRange, AddressRangeSet, FunctionId, IncompleteFunction, Reference,
    ReferenceOrigin, ReferenceTarget, Switch, SymbolEntry, SymbolIndex,
};
use crate::project::{Project, ProjectError};
use crate::queries::{QueryEngine, QueryReader};
use crate::registry::{self, Registration};
use crate::storage::segments::mapping::{SegmentMappingBuilder, SegmentMappingId};
use crate::storage::segments::space::AddressSpaceId;

pub mod change;

pub(crate) mod coverage;
pub use coverage::AnalysisCoverage;

pub(crate) mod metrics;
pub use metrics::{EngineMetrics, EngineMetricsSnapshot};

mod scheduler;

mod subscription;
pub(crate) use subscription::Subscriber;
pub use subscription::{Subscription, SubscriptionBuilder};

pub(crate) mod view;
pub use view::{ProjectView, ReadSet};

mod update;
pub use update::{
    BytePatch, FunctionPatch, FunctionPropertiesUpdate, FunctionRemoval, MappingCreationResult,
    MappingMetadataUpdate, MappingPlacement, MappingPlacementMode, MappingPriorityUpdate,
    MappingRemap, MappingRemoval, MappingResize, ProblemPatch, ProjectUpdate, ReferenceRemoval,
    SpaceCreationResult, SwitchPatch, SymbolPatch, SymbolRemoval,
};

mod worker;
pub(crate) use worker::Intake;
use worker::Worker;

const DEFAULT_CHANNEL_CAPACITY: usize = 1024;
const DEFAULT_INSN_CACHE_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_LIFTED_CACHE_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_SUBSCRIPTION_CAPACITY: usize = 1024;
pub(crate) const DEFAULT_WORK_ITEM_MAX_ATTEMPTS: usize = 3;
const MAX_COMPLETION_ROUNDS: usize = 256;
const RETRACTED_BY_BYTE_CHANGE: &[AnalysisPhase] =
    &[AnalysisPhase::Decode, AnalysisPhase::Partition];
const WORK_BATCH_ITEMS: usize = 1024;

thread_local! {
    static ON_ANALYSIS_THREAD: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn on_analysis_thread() -> bool {
    ON_ANALYSIS_THREAD.with(Cell::get)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkCause {
    range: Option<AddressRange>,
    kind: ChangeKinds,
    provenance: ChangeProvenance,
    revision: Revision,
}

impl WorkCause {
    pub fn new(
        range: impl Into<Option<AddressRange>>,
        kind: ChangeKinds,
        revision: Revision,
    ) -> Self {
        Self {
            range: range.into(),
            kind,
            provenance: ChangeProvenance::empty(),
            revision,
        }
    }

    pub fn with_provenance(mut self, provenance: ChangeProvenance) -> Self {
        self.set_provenance(provenance);
        self
    }

    pub fn set_provenance(&mut self, provenance: ChangeProvenance) {
        self.provenance = provenance;
    }

    pub fn range(&self) -> Option<AddressRange> {
        self.range
    }

    pub fn kind(&self) -> ChangeKinds {
        self.kind
    }

    pub fn provenance(&self) -> &ChangeProvenance {
        &self.provenance
    }

    pub fn revision(&self) -> Revision {
        self.revision
    }

    pub(crate) fn coarsen(&mut self, other: &WorkCause) {
        self.range = match (self.range, other.range) {
            (Some(left), Some(right)) if left.space() == right.space() => Some(AddressRange::new(
                left.space(),
                left.start().min(right.start()),
                left.end().max(right.end()),
            )),
            (left, right) if left == right => left,
            _ => None,
        };
        self.kind |= other.kind;
        self.provenance.merge(&other.provenance);
        if other.revision > self.revision {
            self.revision = other.revision;
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[repr(u8)]
#[allow(unknown_lints, sorted_enum_variants)]
pub enum AnalysisPhase {
    Retract,
    #[default]
    Decode,
    Partition,
    Derive,
    Propagate,
    Identify,
}

impl AnalysisPhase {
    pub const ALL: [AnalysisPhase; 6] = [
        AnalysisPhase::Retract,
        AnalysisPhase::Decode,
        AnalysisPhase::Partition,
        AnalysisPhase::Derive,
        AnalysisPhase::Propagate,
        AnalysisPhase::Identify,
    ];

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Retract => "retract",
            Self::Decode => "decode",
            Self::Partition => "partition",
            Self::Derive => "derive",
            Self::Propagate => "propagate",
            Self::Identify => "identify",
        }
    }
}

impl Display for AnalysisPhase {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Priority(i32);

impl Priority {
    pub const DISCOVERY: Self = Self(0);
    pub const ENRICHMENT: Self = Self(1_000);

    pub const fn new(value: i32) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> i32 {
        self.0
    }
}

impl Default for Priority {
    fn default() -> Self {
        Self::DISCOVERY
    }
}

impl Display for Priority {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisEngineConfig {
    channel_capacity: usize,
    insn_cache_bytes: usize,
    lifted_cache_bytes: usize,
    worker_limit: usize,
}

impl Default for AnalysisEngineConfig {
    fn default() -> Self {
        Self {
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
            insn_cache_bytes: DEFAULT_INSN_CACHE_BYTES,
            lifted_cache_bytes: DEFAULT_LIFTED_CACHE_BYTES,
            worker_limit: 1,
        }
    }
}

impl AnalysisEngineConfig {
    pub fn channel_capacity(&self) -> usize {
        self.channel_capacity
    }

    pub fn set_channel_capacity(&mut self, capacity: usize) {
        self.channel_capacity = capacity;
    }

    pub fn with_channel_capacity(mut self, capacity: usize) -> Self {
        self.set_channel_capacity(capacity);
        self
    }

    pub fn insn_cache_bytes(&self) -> usize {
        self.insn_cache_bytes
    }

    pub fn set_insn_cache_bytes(&mut self, bytes: usize) {
        self.insn_cache_bytes = bytes;
    }

    pub fn with_insn_cache_bytes(mut self, bytes: usize) -> Self {
        self.set_insn_cache_bytes(bytes);
        self
    }

    pub fn lifted_cache_bytes(&self) -> usize {
        self.lifted_cache_bytes
    }

    pub fn set_lifted_cache_bytes(&mut self, bytes: usize) {
        self.lifted_cache_bytes = bytes;
    }

    pub fn with_lifted_cache_bytes(mut self, bytes: usize) -> Self {
        self.set_lifted_cache_bytes(bytes);
        self
    }

    pub fn worker_limit(&self) -> usize {
        self.worker_limit
    }

    pub fn set_worker_limit(&mut self, limit: usize) {
        self.worker_limit = limit.max(1);
    }

    pub fn with_worker_limit(mut self, limit: usize) -> Self {
        self.set_worker_limit(limit);
        self
    }
}

#[derive(Clone)]
pub struct AnalysisContext {
    cancellation: CancellationToken,
    causes: SmallVec<[WorkCause; 4]>,
    continuation: bool,
    phase: AnalysisPhase,
    progress: Progress,
    worker_limit: usize,
}

impl Default for AnalysisContext {
    fn default() -> Self {
        Self::new(CancellationToken::default(), Progress::default())
    }
}

impl AnalysisContext {
    pub fn new(cancellation: CancellationToken, progress: Progress) -> Self {
        Self {
            cancellation,
            causes: SmallVec::new(),
            continuation: false,
            phase: AnalysisPhase::default(),
            progress,
            worker_limit: 1,
        }
    }

    fn with_worker_limit(mut self, limit: usize) -> Self {
        self.worker_limit = limit.max(1);
        self
    }

    fn with_work(
        mut self,
        phase: AnalysisPhase,
        causes: impl IntoIterator<Item = WorkCause>,
        continuation: bool,
    ) -> Self {
        self.causes.extend(causes);
        self.continuation = continuation;
        self.phase = phase;
        self
    }

    pub fn causes(&self) -> &[WorkCause] {
        &self.causes
    }

    pub fn phase(&self) -> AnalysisPhase {
        self.phase
    }

    pub fn is_continuation(&self) -> bool {
        self.continuation
    }

    pub fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    pub fn progress(&self) -> &Progress {
        &self.progress
    }

    pub fn worker_limit(&self) -> usize {
        self.worker_limit
    }
}

pub trait Analyser: Send {
    fn name(&self) -> &'static str;

    fn triggers(&self) -> ChangeKinds;

    fn phase(&self) -> AnalysisPhase {
        AnalysisPhase::default()
    }

    fn priority(&self) -> Priority {
        Priority::default()
    }

    fn can_analyse(&self, project: &Project) -> bool;

    fn analyse(
        &mut self,
        project: &ProjectView<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError>;

    fn produces(&self) -> ChangeKinds {
        ChangeKinds::empty()
    }

    fn analysis_ended(
        &mut self,
        project: &ProjectView<'_>,
        cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        let _ = project;
        let _ = cx;
        let _ = updates;
        Ok(())
    }

    fn has_pending_work(&self) -> bool {
        false
    }

    fn max_attempts(&self) -> usize {
        DEFAULT_WORK_ITEM_MAX_ATTEMPTS
    }
}

type AnalyserBuildFn = fn(&Project) -> Result<Box<dyn Analyser>, AnalysisError>;

pub struct AnalyserProvider {
    build: AnalyserBuildFn,
    name: &'static str,
}

impl AnalyserProvider {
    pub const fn new(name: &'static str, build: AnalyserBuildFn) -> Self {
        Self { build, name }
    }

    pub fn build(&self, project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
        (self.build)(project)
    }
}

impl Registration for AnalyserProvider {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl PartialEq for AnalyserProvider {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for AnalyserProvider {}

impl PartialOrd for AnalyserProvider {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AnalyserProvider {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name.cmp(other.name)
    }
}

registry::collect!(AnalyserProvider);

#[derive(Debug, Error)]
pub enum EngineError {
    #[error(transparent)]
    Analysis(#[from] AnalysisError),
    #[error("analysis engine poisoned: {0}")]
    Poisoned(String),
    #[error(transparent)]
    Project(#[from] ProjectError),
    #[error("analysis engine stopped")]
    Stopped,
    #[error("subscription has no pending changes")]
    SubscriptionEmpty,
    #[error("subscription receive timed out")]
    SubscriptionTimeout,
}

pub struct AnalysisEngine {
    cancellation: CancellationToken,
    handle: Option<JoinHandle<()>>,
    metrics: EngineMetrics,
    poison: Arc<OnceLock<String>>,
    query_reader: QueryReader,
    tx: Sender<Intake>,
    worker_done: Receiver<()>,
}

impl AnalysisEngine {
    pub fn new(project: Project) -> Result<Self, EngineError> {
        Self::with_config(project, AnalysisEngineConfig::default())
    }

    pub fn with_config(
        project: Project,
        config: AnalysisEngineConfig,
    ) -> Result<Self, EngineError> {
        let channel_capacity = config.channel_capacity();
        let (tx, rx) = flume::bounded(channel_capacity);
        let (worker_done_tx, worker_done) = flume::bounded(1);
        let cancellation = CancellationToken::default();
        let poison = Arc::new(OnceLock::new());
        let progress = Progress::default();
        let project = Arc::new(RwLock::new(project));
        let queries = QueryEngine::new(
            project.clone(),
            config.insn_cache_bytes(),
            config.lifted_cache_bytes(),
        );
        let query_reader = queries.reader().with_intake(tx.clone());
        let worker_cancellation = cancellation.clone();
        let worker_poison = poison.clone();
        let worker_state_poison = poison.clone();
        let worker_progress = progress.clone();
        let metrics = EngineMetrics::new();
        let worker_metrics = metrics.clone();
        let handle = Builder::new()
            .name("fugue-analysis".to_owned())
            .spawn(move || {
                ON_ANALYSIS_THREAD.with(|flag| flag.set(true));
                let worker = Worker::new(
                    config,
                    project,
                    queries,
                    worker_state_poison,
                    worker_cancellation,
                    worker_progress,
                    worker_metrics,
                );
                match worker {
                    Ok(worker) => worker.run(rx),
                    Err(error) => {
                        let _ = worker_poison.set(error.to_string());
                    }
                }
                let _ = worker_done_tx.send(());
            })
            .map_err(|error| EngineError::Poisoned(error.to_string()))?;

        Ok(Self {
            cancellation,
            handle: Some(handle),
            metrics,
            poison,
            query_reader,
            tx,
            worker_done,
        })
    }

    pub fn schedule_ranges(
        &self,
        kind: ChangeKinds,
        regions: AddressRangeSet,
    ) -> Result<(), EngineError> {
        self.poison_check()?;
        self.tx
            .send(Intake::Direct { kind, regions })
            .map_err(|_| EngineError::Stopped)
    }

    pub fn apply_update(&self, update: ProjectUpdate) -> Result<ChangeSet, EngineError> {
        self.apply_update_batch(SmallVec::from_buf([update]))
    }

    pub fn apply_updates(&self, updates: Vec<ProjectUpdate>) -> Result<ChangeSet, EngineError> {
        self.apply_update_batch(SmallVec::from_vec(updates))
    }

    fn apply_update_batch(
        &self,
        updates: SmallVec<[ProjectUpdate; 1]>,
    ) -> Result<ChangeSet, EngineError> {
        self.poison_check()?;

        let (reply_tx, reply_rx) = flume::bounded(1);
        self.tx
            .send(Intake::Updates {
                updates,
                reply: reply_tx,
            })
            .map_err(|_| EngineError::Stopped)?;

        self.receive_reply(reply_rx)
    }

    pub fn write_bytes(
        &self,
        address: Address,
        bytes: impl Into<Arc<[u8]>>,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::write_bytes(address, bytes))
    }

    pub fn add_symbol(
        &self,
        index: SymbolIndex,
        entry: SymbolEntry,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::add_symbol(index, entry))
    }

    pub fn add_function(&self, function: IncompleteFunction) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::add_function(function))
    }

    pub fn add_reference(&self, reference: Reference) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::add_reference(reference))
    }

    pub fn remove_reference(
        &self,
        from: Address,
        target: ReferenceTarget,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::remove_reference(from, target))
    }

    pub fn add_switch(&self, switch: Switch) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::add_switch(switch))
    }

    pub fn remove_switch(&self, branch: impl Into<Address>) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::remove_switch(branch))
    }

    pub fn add_mapping_to_space(
        &self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::add_mapping_to_space(space, mapping))
    }

    pub fn add_mapping_to_space_bottom(
        &self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::add_mapping_to_space_bottom(space, mapping))
    }

    pub fn add_mapping_to_space_top(
        &self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::add_mapping_to_space_top(space, mapping))
    }

    pub fn create_mapping(
        &self,
        builder: SegmentMappingBuilder,
    ) -> Result<MappingCreationResult, EngineError> {
        self.poison_check()?;

        let (reply_tx, reply_rx) = flume::bounded(1);
        self.tx
            .send(Intake::CreateMapping {
                builder,
                reply: reply_tx,
            })
            .map_err(|_| EngineError::Stopped)?;

        self.receive_reply(reply_rx)
    }

    pub fn create_space(&self) -> Result<SpaceCreationResult, EngineError> {
        self.poison_check()?;

        let (reply_tx, reply_rx) = flume::bounded(1);
        self.tx
            .send(Intake::CreateSpace(reply_tx))
            .map_err(|_| EngineError::Stopped)?;

        self.receive_reply(reply_rx)
    }

    pub fn deprioritise_mapping(
        &self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::deprioritise_mapping(space, mapping))
    }

    pub fn prioritise_mapping(
        &self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::prioritise_mapping(space, mapping))
    }

    pub fn remove_function(&self, entry: Address) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::RemoveFunction(
            FunctionRemoval::new(entry).with_origin(ReferenceOrigin::Asserted),
        ))
    }

    pub fn remove_function_by_id(&self, id: FunctionId) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::RemoveFunction(
            FunctionRemoval::by_id(id).with_origin(ReferenceOrigin::Asserted),
        ))
    }

    pub fn remap_mapping(
        &self,
        mapping: SegmentMappingId,
        start: Address,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::remap_mapping(mapping, start))
    }

    pub fn remove_mapping(&self, mapping: SegmentMappingId) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::remove_mapping(mapping))
    }

    pub fn remove_symbol(&self, index: SymbolIndex) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::remove_symbol(index))
    }

    pub fn resize_mapping(
        &self,
        mapping: SegmentMappingId,
        size: u64,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::resize_mapping(mapping, size))
    }

    pub fn update_mapping_metadata(
        &self,
        update: MappingMetadataUpdate,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::update_mapping_metadata(update))
    }

    pub fn ensure_lifted(
        &self,
        function: FunctionId,
        level: IlLevel,
    ) -> Result<ChangeSet, EngineError> {
        self.poison_check()?;

        let (reply_tx, reply_rx) = flume::bounded(1);
        self.tx
            .send(Intake::EnsureLifted {
                function,
                level,
                reply: reply_tx,
            })
            .map_err(|_| EngineError::Stopped)?;

        self.receive_reply(reply_rx)
    }

    pub fn analyse(&self) -> Result<(), EngineError> {
        self.poison_check()?;

        let (reply_tx, reply_rx) = flume::bounded(1);
        self.tx
            .send(Intake::Analyse(reply_tx))
            .map_err(|_| EngineError::Stopped)?;

        self.receive_reply(reply_rx)
    }

    pub fn metrics(&self) -> EngineMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn query_reader(&self) -> Result<QueryReader, EngineError> {
        self.poison_check()?;
        Ok(self.query_reader.clone())
    }

    pub fn cancel(&self) -> Result<(), EngineError> {
        self.poison_check()?;
        self.cancellation.cancel();
        self.tx
            .send(Intake::Cancel)
            .map_err(|_| EngineError::Stopped)
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn subscribe(&self) -> SubscriptionBuilder<'_> {
        SubscriptionBuilder::new(self)
    }

    fn open_subscription(
        &self,
        filter: ChangeFilter,
        capacity: usize,
    ) -> Result<Subscription, EngineError> {
        self.poison_check()?;

        let (tx, rx) = flume::bounded(capacity.max(1));
        self.tx
            .send(Intake::Subscribe(Subscriber::new(tx, rx.clone(), filter)))
            .map_err(|_| EngineError::Stopped)?;

        Ok(Subscription::new(rx))
    }

    pub fn poison_check(&self) -> Result<(), EngineError> {
        if let Some(message) = self.poison.get() {
            return Err(EngineError::Poisoned(message.clone()));
        }
        if !matches!(self.worker_done.try_recv(), Err(TryRecvError::Empty))
            || self.tx.is_disconnected()
            || !self.query_reader.is_active()
            || self.handle.as_ref().is_some_and(JoinHandle::is_finished)
        {
            return Err(EngineError::Stopped);
        }
        Ok(())
    }

    fn receive_reply<T>(&self, reply: Receiver<Result<T, EngineError>>) -> Result<T, EngineError> {
        enum WorkerReply<T> {
            Reply(Result<Result<T, EngineError>, RecvError>),
            Stopped,
        }

        match Selector::new()
            .recv(&reply, WorkerReply::Reply)
            .recv(&self.worker_done, |_| WorkerReply::Stopped)
            .wait()
        {
            WorkerReply::Reply(reply) => reply.map_err(|_| EngineError::Stopped)?,
            WorkerReply::Stopped => Err(EngineError::Stopped),
        }
    }
}

impl Drop for AnalysisEngine {
    fn drop(&mut self) {
        let _ = self.tx.send(Intake::Shutdown);

        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
