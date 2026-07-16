use std::cmp::Ordering;
use std::collections::{BTreeMap, VecDeque};
use std::fmt::{self, Display, Formatter};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, OnceLock};
use std::thread::{Builder, JoinHandle};
use std::time::{Duration, Instant};

use flume::{Receiver, RecvTimeoutError, Sender, TryRecvError, TrySendError};
use parking_lot::RwLock;
use smol_str::SmolStr;
use thiserror::Error;

use self::change::{
    ChangeCategory, ChangeFilter, ChangeKinds, ChangeRecord, ChangeSet, ChangeSource, Revision,
};
use crate::analysis::AnalysisError;
use crate::analysis::control::{CancellationToken, Progress};
use crate::analysis::function::recovery::PartialFunction;
use crate::il::common::{IlError, IlLevel};
use crate::ir::{
    Address, AddressRangeSet, FunctionId, RawAddressRangeSet, Reference, ReferenceTarget,
    SymbolEntry, SymbolIndex,
};
use crate::project::{Project, ProjectError, ProjectTransaction};
use crate::queries::{QueryEngine, QueryReader};
use crate::registry::{self, Registration};
use crate::storage::segments::mapping::{
    SegmentMappingBuilder, SegmentMappingFlags, SegmentMappingId, SegmentMappingKind,
    SegmentMappingProvenance,
};
use crate::storage::segments::space::AddressSpaceId;

const DEFAULT_CHANNEL_CAPACITY: usize = 1024;
const DEFAULT_SUBSCRIPTION_CAPACITY: usize = 1024;
const MAX_PENDING_REGION_RANGES: usize = 4096;
const IDLE_PERSIST_INTERVAL: Duration = Duration::from_millis(250);
pub const DEFAULT_ANALYSER_MAX_FAILURES: usize = 3;

pub mod change;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistencePolicy {
    Manual,
    OnIdle,
    OnCommit,
}

impl PersistencePolicy {
    pub fn for_project(project: &Project) -> Self {
        if project.storage().entities.is_transient() {
            Self::Manual
        } else {
            Self::OnIdle
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Trigger {
    BytesMapped,
    BytesWritten,
    FunctionAdded,
    FunctionChanged,
    FunctionRemoved,
    SegmentMapped,
    SegmentUnmapped,
    SymbolAdded,
    SymbolRemoved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Priority(i32);

impl Priority {
    pub const DISCOVERY: Self = Self(0);
    pub const DERIVED: Self = Self(1_000);

    pub const fn new(value: i32) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> i32 {
        self.0
    }

    pub const fn before(&self) -> Self {
        Self(self.0 - 1)
    }

    pub const fn after(&self) -> Self {
        Self(self.0 + 1)
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

#[derive(Clone, Default)]
pub struct AnalysisCx {
    cancellation: CancellationToken,
    progress: Progress,
}

impl AnalysisCx {
    pub fn new(cancellation: CancellationToken, progress: Progress) -> Self {
        Self {
            cancellation,
            progress,
        }
    }

    pub fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    pub fn progress(&self) -> &Progress {
        &self.progress
    }
}

pub trait Analyser: Send {
    fn name(&self) -> &'static str;

    fn triggers(&self) -> &'static [Trigger];

    fn priority(&self) -> Priority {
        Priority::default()
    }

    fn enabled_by_default(&self, project: &Project) -> bool {
        let _ = project;
        true
    }

    fn can_analyse(&self, project: &Project) -> bool;

    fn analyse(
        &mut self,
        transaction: &mut ProjectTransaction<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisCx,
    ) -> Result<(), AnalysisError>;

    fn analysis_ended(
        &mut self,
        transaction: &mut ProjectTransaction<'_>,
        cx: &AnalysisCx,
    ) -> Result<(), AnalysisError> {
        let _ = transaction;
        let _ = cx;
        Ok(())
    }

    fn has_pending_work(&self) -> bool {
        false
    }

    fn max_failures(&self) -> usize {
        DEFAULT_ANALYSER_MAX_FAILURES
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
    #[error("project persistence failed: {0}")]
    Persistence(#[source] ProjectError),
    #[error("analysis engine poisoned: {0}")]
    Poisoned(String),
    #[error(transparent)]
    Project(#[from] ProjectError),
    #[error("analysis engine stopped")]
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisMessageKind {
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisMessage {
    analyser: &'static str,
    kind: AnalysisMessageKind,
    message: String,
}

impl AnalysisMessage {
    pub fn new(
        analyser: &'static str,
        kind: AnalysisMessageKind,
        message: impl Into<String>,
    ) -> Self {
        Self {
            analyser,
            kind,
            message: message.into(),
        }
    }

    pub fn analyser(&self) -> &'static str {
        self.analyser
    }

    pub fn kind(&self) -> AnalysisMessageKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytePatch {
    address: Address,
    bytes: Arc<[u8]>,
}

impl BytePatch {
    pub fn new(address: impl Into<Address>, bytes: impl Into<Arc<[u8]>>) -> Self {
        Self {
            address: address.into(),
            bytes: bytes.into(),
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionPatch {
    function: PartialFunction,
}

impl FunctionPatch {
    pub fn new(function: PartialFunction) -> Self {
        Self { function }
    }

    pub fn function(&self) -> &PartialFunction {
        &self.function
    }

    fn into_function(self) -> PartialFunction {
        self.function
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolPatch {
    index: SymbolIndex,
    entry: SymbolEntry,
}

impl SymbolPatch {
    pub fn new(index: SymbolIndex, entry: SymbolEntry) -> Self {
        Self { index, entry }
    }

    pub fn index(&self) -> SymbolIndex {
        self.index
    }

    pub fn entry(&self) -> &SymbolEntry {
        &self.entry
    }

    fn into_parts(self) -> (SymbolIndex, SymbolEntry) {
        (self.index, self.entry)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FunctionRemovalTarget {
    Address(Address),
    Id(FunctionId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionRemoval {
    target: FunctionRemovalTarget,
}

impl FunctionRemoval {
    pub fn new(entry: impl Into<Address>) -> Self {
        Self {
            target: FunctionRemovalTarget::Address(entry.into()),
        }
    }

    pub fn by_id(id: FunctionId) -> Self {
        Self {
            target: FunctionRemovalTarget::Id(id),
        }
    }

    pub fn entry(&self) -> Option<Address> {
        match self.target {
            FunctionRemovalTarget::Address(entry) => Some(entry),
            FunctionRemovalTarget::Id(_) => None,
        }
    }

    pub fn id(&self) -> Option<FunctionId> {
        match self.target {
            FunctionRemovalTarget::Address(_) => None,
            FunctionRemovalTarget::Id(id) => Some(id),
        }
    }

    fn apply(self, transaction: &mut ProjectTransaction<'_>) -> Result<(), ProjectError> {
        match self.target {
            FunctionRemovalTarget::Address(entry) => {
                transaction.remove_function(entry)?;
            }
            FunctionRemovalTarget::Id(id) => {
                transaction.remove_function_by_id(id)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolRemoval {
    index: SymbolIndex,
}

impl SymbolRemoval {
    pub fn new(index: SymbolIndex) -> Self {
        Self { index }
    }

    pub fn index(&self) -> SymbolIndex {
        self.index
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceRemoval {
    from: Address,
    target: ReferenceTarget,
}

impl ReferenceRemoval {
    pub fn new(from: Address, target: ReferenceTarget) -> Self {
        Self { from, target }
    }

    pub fn from(&self) -> Address {
        self.from
    }

    pub fn target(&self) -> ReferenceTarget {
        self.target
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingPlacementMode {
    Bottom,
    Default,
    Top,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingPlacement {
    mapping: SegmentMappingId,
    mode: MappingPlacementMode,
    space: AddressSpaceId,
}

impl MappingPlacement {
    pub fn new(
        space: AddressSpaceId,
        mapping: SegmentMappingId,
        mode: MappingPlacementMode,
    ) -> Self {
        Self {
            mapping,
            mode,
            space,
        }
    }

    pub fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }

    pub fn mode(&self) -> MappingPlacementMode {
        self.mode
    }

    pub fn space(&self) -> AddressSpaceId {
        self.space
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingPriorityUpdate {
    mapping: SegmentMappingId,
    space: AddressSpaceId,
}

impl MappingPriorityUpdate {
    pub fn new(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self { mapping, space }
    }

    pub fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }

    pub fn space(&self) -> AddressSpaceId {
        self.space
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingMetadataUpdate {
    flags: SegmentMappingFlags,
    kind: SegmentMappingKind,
    mapping: SegmentMappingId,
    provenance: SegmentMappingProvenance,
}

impl MappingMetadataUpdate {
    pub fn new(mapping: SegmentMappingId) -> Self {
        Self {
            flags: SegmentMappingFlags::default(),
            kind: SegmentMappingKind::default(),
            mapping,
            provenance: SegmentMappingProvenance::default(),
        }
    }

    pub fn flags(&self) -> SegmentMappingFlags {
        self.flags
    }

    pub fn kind(&self) -> SegmentMappingKind {
        self.kind
    }

    pub fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }

    pub fn provenance(&self) -> SegmentMappingProvenance {
        self.provenance
    }

    pub fn set_flags(&mut self, flags: SegmentMappingFlags) {
        self.flags = flags;
    }

    pub fn set_kind(&mut self, kind: SegmentMappingKind) {
        self.kind = kind;
    }

    pub fn set_provenance(&mut self, provenance: SegmentMappingProvenance) {
        self.provenance = provenance;
    }

    pub fn with_flags(mut self, flags: SegmentMappingFlags) -> Self {
        self.set_flags(flags);
        self
    }

    pub fn with_kind(mut self, kind: SegmentMappingKind) -> Self {
        self.set_kind(kind);
        self
    }

    pub fn with_provenance(mut self, provenance: SegmentMappingProvenance) -> Self {
        self.set_provenance(provenance);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingRemap {
    mapping: SegmentMappingId,
    start: Address,
}

impl MappingRemap {
    pub fn new(mapping: SegmentMappingId, start: impl Into<Address>) -> Self {
        Self {
            mapping,
            start: start.into(),
        }
    }

    pub fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }

    pub fn start(&self) -> Address {
        self.start
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingRemoval {
    mapping: SegmentMappingId,
}

impl MappingRemoval {
    pub fn new(mapping: SegmentMappingId) -> Self {
        Self { mapping }
    }

    pub fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingResize {
    mapping: SegmentMappingId,
    size: u64,
}

impl MappingResize {
    pub fn new(mapping: SegmentMappingId, size: u64) -> Self {
        Self { mapping, size }
    }

    pub fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingCreationResult {
    changes: ChangeSet,
    mapping: SegmentMappingId,
}

impl MappingCreationResult {
    pub fn new(mapping: SegmentMappingId, changes: ChangeSet) -> Self {
        Self { changes, mapping }
    }

    pub fn changes(&self) -> &ChangeSet {
        &self.changes
    }

    pub fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }

    pub fn into_parts(self) -> (SegmentMappingId, ChangeSet) {
        (self.mapping, self.changes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceCreationResult {
    changes: ChangeSet,
    space: AddressSpaceId,
}

impl SpaceCreationResult {
    pub fn new(space: AddressSpaceId, changes: ChangeSet) -> Self {
        Self { changes, space }
    }

    pub fn changes(&self) -> &ChangeSet {
        &self.changes
    }

    pub fn space(&self) -> AddressSpaceId {
        self.space
    }

    pub fn into_parts(self) -> (AddressSpaceId, ChangeSet) {
        (self.space, self.changes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectUpdate {
    AddFunction(FunctionPatch),
    AddMappingToSpace(MappingPlacement),
    AddReference(Reference),
    DeprioritiseMapping(MappingPriorityUpdate),
    InsertSymbol(SymbolPatch),
    PrioritiseMapping(MappingPriorityUpdate),
    RemapMapping(MappingRemap),
    RemoveFunction(FunctionRemoval),
    RemoveMapping(MappingRemoval),
    RemoveReference(ReferenceRemoval),
    RemoveSymbol(SymbolRemoval),
    ResizeMapping(MappingResize),
    UpdateMappingMetadata(MappingMetadataUpdate),
    WriteBytes(BytePatch),
}

impl ProjectUpdate {
    pub fn add_function(function: PartialFunction) -> Self {
        Self::AddFunction(FunctionPatch::new(function))
    }

    pub fn add_mapping_to_space(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self::AddMappingToSpace(MappingPlacement::new(
            space,
            mapping,
            MappingPlacementMode::Default,
        ))
    }

    pub fn add_mapping_to_space_bottom(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self::AddMappingToSpace(MappingPlacement::new(
            space,
            mapping,
            MappingPlacementMode::Bottom,
        ))
    }

    pub fn add_mapping_to_space_top(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self::AddMappingToSpace(MappingPlacement::new(
            space,
            mapping,
            MappingPlacementMode::Top,
        ))
    }

    pub fn deprioritise_mapping(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self::DeprioritiseMapping(MappingPriorityUpdate::new(space, mapping))
    }

    pub fn insert_symbol(index: SymbolIndex, entry: SymbolEntry) -> Self {
        Self::InsertSymbol(SymbolPatch::new(index, entry))
    }

    pub fn prioritise_mapping(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self::PrioritiseMapping(MappingPriorityUpdate::new(space, mapping))
    }

    pub fn remap_mapping(mapping: SegmentMappingId, start: impl Into<Address>) -> Self {
        Self::RemapMapping(MappingRemap::new(mapping, start))
    }

    pub fn remove_function(entry: impl Into<Address>) -> Self {
        Self::RemoveFunction(FunctionRemoval::new(entry))
    }

    pub fn remove_function_by_id(id: FunctionId) -> Self {
        Self::RemoveFunction(FunctionRemoval::by_id(id))
    }

    pub fn remove_mapping(mapping: SegmentMappingId) -> Self {
        Self::RemoveMapping(MappingRemoval::new(mapping))
    }

    pub fn add_reference(reference: Reference) -> Self {
        Self::AddReference(reference)
    }

    pub fn remove_reference(from: Address, target: ReferenceTarget) -> Self {
        Self::RemoveReference(ReferenceRemoval::new(from, target))
    }

    pub fn remove_symbol(index: SymbolIndex) -> Self {
        Self::RemoveSymbol(SymbolRemoval::new(index))
    }

    pub fn resize_mapping(mapping: SegmentMappingId, size: u64) -> Self {
        Self::ResizeMapping(MappingResize::new(mapping, size))
    }

    pub fn update_mapping_metadata(update: MappingMetadataUpdate) -> Self {
        Self::UpdateMappingMetadata(update)
    }

    pub fn write_bytes(address: impl Into<Address>, bytes: impl Into<Arc<[u8]>>) -> Self {
        Self::WriteBytes(BytePatch::new(address, bytes))
    }

    fn apply(self, transaction: &mut ProjectTransaction<'_>) -> Result<(), ProjectError> {
        match self {
            Self::AddFunction(patch) => {
                transaction.add_function(patch.into_function())?;
                Ok(())
            }
            Self::AddMappingToSpace(placement) => match placement.mode() {
                MappingPlacementMode::Bottom => {
                    transaction.add_mapping_to_space_bottom(placement.space(), placement.mapping())
                }
                MappingPlacementMode::Default => {
                    transaction.add_mapping_to_space(placement.space(), placement.mapping())
                }
                MappingPlacementMode::Top => {
                    transaction.add_mapping_to_space_top(placement.space(), placement.mapping())
                }
            },
            Self::DeprioritiseMapping(priority) => {
                transaction.deprioritise_mapping(priority.space(), priority.mapping())
            }
            Self::AddReference(reference) => {
                transaction.add_reference(reference)?;
                Ok(())
            }
            Self::InsertSymbol(patch) => {
                let (index, entry) = patch.into_parts();
                transaction.insert_symbol(index, entry);
                Ok(())
            }
            Self::PrioritiseMapping(priority) => {
                transaction.prioritise_mapping(priority.space(), priority.mapping())
            }
            Self::RemapMapping(remap) => transaction.remap_mapping(remap.mapping(), remap.start()),
            Self::RemoveFunction(removal) => removal.apply(transaction),
            Self::RemoveMapping(removal) => transaction.remove_mapping(removal.mapping()),
            Self::RemoveReference(removal) => {
                transaction.remove_reference(removal.from(), removal.target())?;
                Ok(())
            }
            Self::RemoveSymbol(removal) => {
                transaction.remove_symbol_by_index(removal.index());
                Ok(())
            }
            Self::ResizeMapping(resize) => {
                transaction.resize_mapping(resize.mapping(), resize.size())
            }
            Self::UpdateMappingMetadata(update) => transaction.update_mapping_metadata(
                update.mapping(),
                update.kind(),
                update.provenance(),
                update.flags(),
            ),
            Self::WriteBytes(patch) => transaction.write_bytes(patch.address(), patch.bytes()),
        }
    }
}

pub(crate) enum Intake {
    Cancel,
    CreateMapping {
        builder: SegmentMappingBuilder,
        reply: Sender<Result<MappingCreationResult, EngineError>>,
    },
    CreateSpace(Sender<Result<SpaceCreationResult, EngineError>>),
    Direct {
        regions: AddressRangeSet,
        trigger: Trigger,
    },
    EnsureLifted {
        function: FunctionId,
        level: IlLevel,
        reply: Sender<Result<ChangeSet, EngineError>>,
    },
    FlushDerivedReferences {
        function: FunctionId,
        reply: Sender<Result<ChangeSet, EngineError>>,
    },
    Update {
        update: ProjectUpdate,
        reply: Sender<Result<ChangeSet, EngineError>>,
    },
    Flush(Sender<Result<(), EngineError>>),
    Save(Sender<Result<(), EngineError>>),
    Shutdown,
    Subscribe(Subscriber),
}

struct WorkerStartup {
    project: Arc<RwLock<Project>>,
    queries: QueryEngine,
    persistence_policy: PersistencePolicy,
    messages: Arc<RwLock<Vec<AnalysisMessage>>>,
    poison: Arc<OnceLock<String>>,
    cancellation: CancellationToken,
    progress: Progress,
    rx: Receiver<Intake>,
}

impl WorkerStartup {
    fn run(self) -> Result<(), EngineError> {
        let worker = Worker::new(
            self.project,
            self.queries,
            self.persistence_policy,
            self.messages,
            self.poison,
            self.cancellation,
            self.progress,
        )?;
        worker.run(self.rx);
        Ok(())
    }
}

struct AnalyserState {
    analyser: Box<dyn Analyser>,
    consecutive_failures: usize,
    disabled: bool,
    max_failures: usize,
    pending: AddressRangeSet,
    priority: Priority,
    scheduled: bool,
    triggers: &'static [Trigger],
}

pub(crate) struct Subscriber {
    rx: Receiver<Arc<ChangeSet>>,
    tx: Sender<Arc<ChangeSet>>,
    filter: ChangeFilter,
}

impl Subscriber {
    fn new(tx: Sender<Arc<ChangeSet>>, rx: Receiver<Arc<ChangeSet>>, filter: ChangeFilter) -> Self {
        Self { rx, tx, filter }
    }

    fn materialise(&self, changes: &Arc<ChangeSet>, resync: &Arc<ChangeSet>) -> bool {
        let scoped = match changes.scoped_to(&self.filter) {
            Some(scoped) => Arc::new(scoped),
            None => return true,
        };

        match self.tx.try_send(scoped) {
            Ok(()) => true,
            Err(TrySendError::Disconnected(_)) => false,
            Err(TrySendError::Full(_)) => self.resync(resync.clone()),
        }
    }

    fn resync(&self, changes: Arc<ChangeSet>) -> bool {
        loop {
            match self.rx.try_recv() {
                Ok(_) => {}
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return false,
            }
        }

        self.tx.try_send(changes).is_ok()
    }
}

impl AnalyserState {
    fn new(analyser: Box<dyn Analyser>) -> Self {
        let max_failures = analyser.max_failures();
        let priority = analyser.priority();
        let triggers = analyser.triggers();

        Self {
            analyser,
            consecutive_failures: 0,
            disabled: false,
            max_failures,
            pending: AddressRangeSet::new(),
            priority,
            scheduled: false,
            triggers,
        }
    }

    fn add_pending(&mut self, regions: &AddressRangeSet) {
        self.pending = self.pending.union(regions);
        if self.pending.range_count() > MAX_PENDING_REGION_RANGES {
            self.pending = self.pending.spanning_ranges();
        }
    }

    fn take_pending(&mut self) -> AddressRangeSet {
        self.scheduled = false;
        std::mem::take(&mut self.pending)
    }

    fn clear(&mut self) {
        self.pending = AddressRangeSet::new();
        self.scheduled = false;
    }

    fn disable(&mut self) {
        self.disabled = true;
        self.clear();
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
    }

    fn record_failure(&mut self) -> bool {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= self.max_failures {
            self.disable();
            true
        } else {
            false
        }
    }

    fn schedule(&mut self, index: usize, regions: &AddressRangeSet, queue: &mut AnalysisQueue) {
        if self.disabled {
            return;
        }

        self.add_pending(regions);
        if self.scheduled {
            return;
        }

        self.scheduled = true;
        queue.schedule(self.priority, index);
    }

    fn schedule_resume(&mut self, index: usize, queue: &mut AnalysisQueue) {
        if self.disabled || self.scheduled {
            return;
        }

        self.scheduled = true;
        queue.schedule(self.priority, index);
    }
}

#[derive(Default)]
struct AnalysisQueue {
    priorities: BTreeMap<Priority, VecDeque<usize>>,
}

impl AnalysisQueue {
    fn schedule(&mut self, priority: Priority, index: usize) {
        self.priorities
            .entry(priority)
            .or_default()
            .push_back(index);
    }

    fn pop_next(&mut self) -> Option<usize> {
        let priority = *self.priorities.keys().next()?;
        let queue = self.priorities.get_mut(&priority)?;
        let index = queue.pop_front();

        if queue.is_empty() {
            self.priorities.remove(&priority);
        }

        index
    }

    fn clear(&mut self) {
        self.priorities.clear();
    }

    fn is_empty(&self) -> bool {
        self.priorities.is_empty()
    }
}

pub struct AnalysisEngine {
    cancellation: CancellationToken,
    handle: Option<JoinHandle<()>>,
    messages: Arc<RwLock<Vec<AnalysisMessage>>>,
    poison: Arc<OnceLock<String>>,
    progress: Progress,
    query_reader: QueryReader,
    tx: Sender<Intake>,
}

impl AnalysisEngine {
    pub fn new(project: Project) -> Result<Self, EngineError> {
        Self::with_capacity(project, DEFAULT_CHANNEL_CAPACITY)
    }

    pub fn with_capacity(project: Project, channel_capacity: usize) -> Result<Self, EngineError> {
        let persistence_policy = PersistencePolicy::for_project(&project);
        Self::with_capacity_and_policy(project, channel_capacity, persistence_policy)
    }

    pub fn with_policy(
        project: Project,
        persistence_policy: PersistencePolicy,
    ) -> Result<Self, EngineError> {
        Self::with_capacity_and_policy(project, DEFAULT_CHANNEL_CAPACITY, persistence_policy)
    }

    pub fn with_capacity_and_policy(
        project: Project,
        channel_capacity: usize,
        persistence_policy: PersistencePolicy,
    ) -> Result<Self, EngineError> {
        let (tx, rx) = flume::bounded(channel_capacity);
        let cancellation = CancellationToken::default();
        let messages = Arc::new(RwLock::new(Vec::new()));
        let poison = Arc::new(OnceLock::new());
        let progress = Progress::default();
        let project = Arc::new(RwLock::new(project));
        let queries = QueryEngine::new(project.clone());
        let query_reader = queries.reader().with_intake(tx.clone());
        let worker_cancellation = cancellation.clone();
        let worker_messages = messages.clone();
        let worker_poison = poison.clone();
        let worker_state_poison = poison.clone();
        let worker_progress = progress.clone();
        let handle = Builder::new()
            .name("fugue-analysis".to_owned())
            .spawn(move || {
                let startup = WorkerStartup {
                    project,
                    queries,
                    persistence_policy,
                    messages: worker_messages,
                    poison: worker_state_poison,
                    cancellation: worker_cancellation,
                    progress: worker_progress,
                    rx,
                };
                match catch_unwind(AssertUnwindSafe(|| startup.run())) {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        let _ = worker_poison.set(error.to_string());
                    }
                    Err(payload) => {
                        let _ = worker_poison.set(Worker::panic_message(payload.as_ref()));
                    }
                }
            })
            .map_err(|error| EngineError::Poisoned(error.to_string()))?;

        Ok(Self {
            cancellation,
            handle: Some(handle),
            messages,
            poison,
            progress,
            query_reader,
            tx,
        })
    }

    pub fn schedule(
        &self,
        trigger: Trigger,
        regions: RawAddressRangeSet,
    ) -> Result<(), EngineError> {
        let mut mapped = AddressRangeSet::new();
        for range in regions.ranges() {
            mapped.insert_raw_range(AddressSpaceId::default(), range);
        }

        self.schedule_ranges(trigger, mapped)
    }

    pub fn schedule_ranges(
        &self,
        trigger: Trigger,
        regions: AddressRangeSet,
    ) -> Result<(), EngineError> {
        self.poison_check()?;
        self.tx
            .send(Intake::Direct { trigger, regions })
            .map_err(|_| EngineError::Stopped)
    }

    pub fn apply_update(&self, update: ProjectUpdate) -> Result<ChangeSet, EngineError> {
        self.poison_check()?;

        let (reply_tx, reply_rx) = flume::bounded(1);
        self.tx
            .send(Intake::Update {
                update,
                reply: reply_tx,
            })
            .map_err(|_| EngineError::Stopped)?;

        reply_rx.recv().map_err(|_| EngineError::Stopped)?
    }

    pub fn write_bytes(
        &self,
        address: Address,
        bytes: impl Into<Arc<[u8]>>,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::write_bytes(address, bytes))
    }

    pub fn insert_symbol(
        &self,
        index: SymbolIndex,
        entry: SymbolEntry,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::insert_symbol(index, entry))
    }

    pub fn add_function(&self, function: PartialFunction) -> Result<ChangeSet, EngineError> {
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

    pub fn create_mapping_from_builder(
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

        reply_rx.recv().map_err(|_| EngineError::Stopped)?
    }

    pub fn create_space(&self) -> Result<SpaceCreationResult, EngineError> {
        self.poison_check()?;

        let (reply_tx, reply_rx) = flume::bounded(1);
        self.tx
            .send(Intake::CreateSpace(reply_tx))
            .map_err(|_| EngineError::Stopped)?;

        reply_rx.recv().map_err(|_| EngineError::Stopped)?
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
        self.apply_update(ProjectUpdate::remove_function(entry))
    }

    pub fn remove_function_by_id(&self, id: FunctionId) -> Result<ChangeSet, EngineError> {
        self.apply_update(ProjectUpdate::remove_function_by_id(id))
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

        reply_rx.recv().map_err(|_| EngineError::Stopped)?
    }

    pub fn flush_derived_references(&self, function: FunctionId) -> Result<ChangeSet, EngineError> {
        self.poison_check()?;

        let (reply_tx, reply_rx) = flume::bounded(1);
        self.tx
            .send(Intake::FlushDerivedReferences {
                function,
                reply: reply_tx,
            })
            .map_err(|_| EngineError::Stopped)?;

        reply_rx.recv().map_err(|_| EngineError::Stopped)?
    }

    pub fn wait_until_idle(&self) -> Result<(), EngineError> {
        self.poison_check()?;

        let (reply_tx, reply_rx) = flume::bounded(1);
        self.tx
            .send(Intake::Flush(reply_tx))
            .map_err(|_| EngineError::Stopped)?;

        reply_rx.recv().map_err(|_| EngineError::Stopped)?
    }

    pub fn save(&self) -> Result<(), EngineError> {
        self.poison_check()?;

        let (reply_tx, reply_rx) = flume::bounded(1);
        self.tx
            .send(Intake::Save(reply_tx))
            .map_err(|_| EngineError::Stopped)?;

        reply_rx.recv().map_err(|_| EngineError::Stopped)?
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

    pub fn take_run_log(&self) -> Vec<AnalysisMessage> {
        std::mem::take(&mut *self.messages.write())
    }

    pub fn progress(&self) -> Progress {
        self.progress.clone()
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

        Ok(Subscription { rx })
    }

    pub fn poison_check(&self) -> Result<(), EngineError> {
        match self.poison.get() {
            Some(message) => Err(EngineError::Poisoned(message.clone())),
            None => Ok(()),
        }
    }
}

pub struct SubscriptionBuilder<'a> {
    engine: &'a AnalysisEngine,
    filter: ChangeFilter,
    capacity: usize,
}

impl<'a> SubscriptionBuilder<'a> {
    fn new(engine: &'a AnalysisEngine) -> Self {
        Self {
            engine,
            filter: ChangeFilter::new(),
            capacity: DEFAULT_SUBSCRIPTION_CAPACITY,
        }
    }

    pub fn kinds(mut self, kinds: ChangeKinds) -> Self {
        self.filter = self.filter.with_kinds(kinds);
        self
    }

    pub fn region(mut self, region: AddressRangeSet) -> Self {
        self.filter = self.filter.with_region(region);
        self
    }

    pub fn category(mut self, category: ChangeCategory) -> Self {
        self.filter = self.filter.with_category(category);
        self
    }

    pub fn source_label(mut self, label: impl Into<SmolStr>) -> Self {
        self.filter = self.filter.with_source_label(label);
        self
    }

    pub fn capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    pub fn build(self) -> Result<Subscription, EngineError> {
        self.engine.open_subscription(self.filter, self.capacity)
    }
}

pub struct Subscription {
    rx: Receiver<Arc<ChangeSet>>,
}

impl Subscription {
    pub fn recv(&self) -> Result<Arc<ChangeSet>, EngineError> {
        self.rx.recv().map_err(|_| EngineError::Stopped)
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<Arc<ChangeSet>, RecvTimeoutError> {
        self.rx.recv_timeout(timeout)
    }

    pub fn try_recv(&self) -> Result<Arc<ChangeSet>, TryRecvError> {
        self.rx.try_recv()
    }

    pub fn iter(&self) -> impl Iterator<Item = Arc<ChangeSet>> + '_ {
        self.rx.iter()
    }

    pub fn try_iter(&self) -> impl Iterator<Item = Arc<ChangeSet>> + '_ {
        self.rx.try_iter()
    }

    pub fn drain(&self) -> Option<ChangeSet> {
        let mut merged = None::<ChangeSet>;
        for changes in self.rx.try_iter() {
            match merged.as_mut() {
                Some(batch) => batch.merge(&changes),
                None => merged = Some((*changes).clone()),
            }
        }
        merged
    }

    pub fn recv_batch(&self) -> Result<ChangeSet, EngineError> {
        let mut batch = (*self.recv()?).clone();
        if let Some(rest) = self.drain() {
            batch.merge(&rest);
        }
        Ok(batch)
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

struct Worker {
    analysers: Vec<AnalyserState>,
    cancellation: CancellationToken,
    dirty_revision: Option<Revision>,
    last_checkpoint: Option<Instant>,
    messages: Arc<RwLock<Vec<AnalysisMessage>>>,
    persistence_policy: PersistencePolicy,
    poison: Arc<OnceLock<String>>,
    progress: Progress,
    project: Arc<RwLock<Project>>,
    queries: QueryEngine,
    queue: AnalysisQueue,
    subscribers: Vec<Subscriber>,
}

impl Worker {
    fn new(
        project: Arc<RwLock<Project>>,
        queries: QueryEngine,
        persistence_policy: PersistencePolicy,
        messages: Arc<RwLock<Vec<AnalysisMessage>>>,
        poison: Arc<OnceLock<String>>,
        cancellation: CancellationToken,
        progress: Progress,
    ) -> Result<Self, EngineError> {
        let mut analysers = Vec::new();
        let project_read = project.read();
        for provider in registry::iter::<AnalyserProvider>() {
            let analyser = provider.build(&project_read)?;
            if analyser.enabled_by_default(&project_read) && analyser.can_analyse(&project_read) {
                analysers.push(AnalyserState::new(analyser));
            }
        }
        drop(project_read);

        let mut worker = Self {
            analysers,
            cancellation,
            dirty_revision: None,
            last_checkpoint: None,
            messages,
            persistence_policy,
            poison,
            progress,
            queries,
            project,
            queue: AnalysisQueue::default(),
            subscribers: Vec::new(),
        };

        worker.seed_existing_hints();

        Ok(worker)
    }

    fn record_message(
        &mut self,
        analyser: &'static str,
        kind: AnalysisMessageKind,
        message: impl Into<String>,
    ) {
        self.messages
            .write()
            .push(AnalysisMessage::new(analyser, kind, message));
    }

    fn cancel_pending_work(&mut self) {
        self.queue.clear();
        for analyser in &mut self.analysers {
            analyser.clear();
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
                Ok(Intake::Update { reply, .. }) => {
                    let _ = reply.send(Err(EngineError::Poisoned(message.to_owned())));
                }
                Ok(Intake::EnsureLifted { reply, .. }) => {
                    let _ = reply.send(Err(EngineError::Poisoned(message.to_owned())));
                }
                Ok(Intake::FlushDerivedReferences { reply, .. }) => {
                    let _ = reply.send(Err(EngineError::Poisoned(message.to_owned())));
                }
                Ok(Intake::Flush(reply)) | Ok(Intake::Save(reply)) => {
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

    fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
        payload
            .downcast_ref::<&str>()
            .map(|message| (*message).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "analysis worker panicked".to_owned())
    }

    fn run(mut self, rx: Receiver<Intake>) {
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
                        .and_then(|()| self.create_mapping_from_builder(builder));
                    let _ = reply.send(result);
                }
                Intake::CreateSpace(reply) => {
                    let result = self
                        .drain_or_handle_cancelled()
                        .and_then(|()| self.create_space());
                    let _ = reply.send(result);
                }
                Intake::Direct { regions, trigger } => {
                    self.route_direct(trigger, &regions);
                    loop {
                        match rx.try_recv() {
                            Ok(Intake::Direct { regions, trigger }) => {
                                self.route_direct(trigger, &regions);
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
                Intake::FlushDerivedReferences { function, reply } => {
                    let result = self
                        .drain_or_handle_cancelled()
                        .and_then(|()| self.flush_derived_references(function));
                    let _ = reply.send(result);
                }
                Intake::Update { update, reply } => {
                    let result = self
                        .drain_or_handle_cancelled()
                        .and_then(|()| self.apply_update(update));
                    let _ = reply.send(result);
                }
                Intake::Flush(reply) => {
                    let result = self.drain_or_handle_cancelled().and_then(|()| {
                        if self.persistence_policy == PersistencePolicy::OnIdle {
                            self.persist_dirty()
                        } else {
                            Ok(())
                        }
                    });
                    let _ = reply.send(result);
                }
                Intake::Save(reply) => {
                    let result = self
                        .drain_or_handle_cancelled()
                        .and_then(|()| self.save_checkpoint());
                    let _ = reply.send(result);
                }
                Intake::Shutdown => break,
                Intake::Subscribe(subscriber) => {
                    self.subscribe(subscriber);
                }
            }

            if let Err(error) = self.drain_or_handle_cancelled() {
                if matches!(error, EngineError::Persistence(_)) {
                    tracing::warn!("analysis engine checkpoint failed: {error}");
                    continue;
                }
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

        let mut completion_ran = false;

        loop {
            let mut ran_analyser = false;

            while let Some(index) = self.queue.pop_next() {
                ran_analyser = true;
                self.run_analyser(index)?;
            }

            if !ran_analyser {
                if !completion_ran {
                    completion_ran = true;
                    self.run_completion_hooks()?;
                    if !self.queue.is_empty() {
                        continue;
                    }
                }

                if self.persistence_policy == PersistencePolicy::OnIdle {
                    self.persist_dirty_debounced()?;
                }
                return Ok(());
            }
        }
    }

    fn route_changes(&mut self, changes: &ChangeSet) {
        for record in changes.records() {
            self.route_record(record);
        }
    }

    fn route_direct(&mut self, trigger: Trigger, regions: &AddressRangeSet) {
        for index in 0..self.analysers.len() {
            if self.analysers[index].triggers.contains(&trigger) {
                self.schedule_analyser(index, regions);
            }
        }
    }

    fn seed_existing_hints(&mut self) {
        let mut regions = AddressRangeSet::new();
        let project = self.project.read();

        if let Some(entry) = project.entry() {
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
        drop(project);

        if !regions.is_empty() {
            self.route_direct(Trigger::BytesMapped, &regions);
        }
    }

    fn route_record(&mut self, record: &ChangeRecord) {
        match record {
            ChangeRecord::BytesWritten { range } => {
                let mut regions = AddressRangeSet::new();
                regions.insert_range(*range);
                self.route_direct(Trigger::BytesWritten, &regions);
            }
            ChangeRecord::FunctionAdded { entry, .. } => {
                let mut regions = AddressRangeSet::new();
                regions.insert(*entry);
                self.route_direct(Trigger::FunctionAdded, &regions);
            }
            ChangeRecord::FunctionChanged { entry, .. } => {
                let mut regions = AddressRangeSet::new();
                regions.insert(*entry);
                self.route_direct(Trigger::FunctionChanged, &regions);
            }
            ChangeRecord::FunctionRemoved { entry, .. } => {
                let mut regions = AddressRangeSet::new();
                regions.insert(*entry);
                self.route_direct(Trigger::FunctionRemoved, &regions);
            }
            ChangeRecord::Restored { .. } => {}
            ChangeRecord::SegmentMapped { range, .. } => {
                let mut regions = AddressRangeSet::new();
                regions.insert_range(*range);
                self.route_direct(Trigger::BytesMapped, &regions);
                self.route_direct(Trigger::SegmentMapped, &regions);
            }
            ChangeRecord::SegmentMappingCreated { .. } => {}
            ChangeRecord::SegmentMappingChanged { .. } => {}
            ChangeRecord::SegmentUnmapped { range, .. } => {
                let mut regions = AddressRangeSet::new();
                regions.insert_range(*range);
                self.route_direct(Trigger::SegmentUnmapped, &regions);
            }
            ChangeRecord::SpaceCreated { .. } => {}
            ChangeRecord::SymbolAdded { address, .. } => {
                let mut regions = AddressRangeSet::new();
                regions.insert(*address);
                self.route_direct(Trigger::SymbolAdded, &regions);
            }
            ChangeRecord::SymbolRemoved { address, .. } => {
                let mut regions = AddressRangeSet::new();
                regions.insert(*address);
                self.route_direct(Trigger::SymbolRemoved, &regions);
            }
            ChangeRecord::ReferenceAdded { .. }
            | ChangeRecord::ReferenceRemoved { .. }
            | ChangeRecord::ReferencesChanged { .. }
            | ChangeRecord::LiftedMaterialised { .. }
            | ChangeRecord::LiftedRemoved { .. } => {}
        }
    }

    fn schedule_analyser(&mut self, index: usize, regions: &AddressRangeSet) {
        self.analysers[index].schedule(index, regions, &mut self.queue);
    }

    fn run_analyser(&mut self, index: usize) -> Result<(), EngineError> {
        if self.analysers[index].disabled {
            self.analysers[index].clear();
            return Ok(());
        }

        let regions = self.analysers[index].take_pending();
        let name = self.analysers[index].analyser.name();
        self.progress.reset();
        let cx = AnalysisCx::new(self.cancellation.child(), self.progress.clone());
        let query_write = self.queries.write_guard();
        let project_lock = self.project.clone();
        let mut project = project_lock.write();
        let mut transaction = project.transaction(ChangeSource::analysis(
            self.analysers[index].analyser.name(),
        ));

        // Catch only to poison and stop; the engine never resumes after a panic.
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.analysers[index]
                .analyser
                .analyse(&mut transaction, &regions, &cx)
        }));

        match result {
            Ok(Ok(())) => {
                let changes = transaction.commit()?;
                if !changes.is_empty() {
                    self.begin_publish(&changes);
                }
                drop(project);
                drop(query_write);
                self.analysers[index].record_success();
                if !changes.is_empty() {
                    self.finish_publish(changes)?;
                }
                if self.analysers[index].analyser.has_pending_work() {
                    self.analysers[index].schedule_resume(index, &mut self.queue);
                }
                self.progress.clear_message();
                Ok(())
            }
            Ok(Err(AnalysisError::Cancelled(cancelled))) => {
                let changes = transaction.commit()?;
                if !changes.is_empty() {
                    self.begin_publish(&changes);
                }
                drop(project);
                drop(query_write);
                if !changes.is_empty() {
                    self.finish_publish(changes)?;
                }
                self.progress.clear_message();
                Err(AnalysisError::Cancelled(cancelled).into())
            }
            Ok(Err(error)) => {
                if let Err(rollback_error) = transaction.rollback() {
                    return Err(self.poison_and_stop(rollback_error.to_string()));
                }
                drop(project);
                drop(query_write);
                tracing::warn!("analyser {name} failed: {error}");
                let disabled = self.analysers[index].record_failure();
                self.record_message(name, AnalysisMessageKind::Error, error.to_string());
                if disabled {
                    tracing::warn!("analyser {name} disabled after repeated failures");
                }
                self.progress.clear_message();
                Ok(())
            }
            Err(payload) => {
                let poisoned = self.poison_and_stop(Self::panic_message(payload.as_ref()));
                if let Err(error) = transaction.rollback() {
                    tracing::error!("failed to roll back transaction after panic: {error}");
                }
                project.abandon_persistence();
                drop(project);
                drop(query_write);
                self.progress.clear_message();
                Err(poisoned)
            }
        }
    }

    fn run_completion_hooks(&mut self) -> Result<(), EngineError> {
        for index in 0..self.analysers.len() {
            if self.analysers[index].disabled {
                continue;
            }

            self.run_completion_hook(index)?;
        }

        Ok(())
    }

    fn run_completion_hook(&mut self, index: usize) -> Result<(), EngineError> {
        let name = self.analysers[index].analyser.name();
        self.progress.reset();
        let cx = AnalysisCx::new(self.cancellation.child(), self.progress.clone());
        let query_write = self.queries.write_guard();
        let project_lock = self.project.clone();
        let mut project = project_lock.write();
        let mut transaction =
            project.transaction(ChangeSource::analysis(format!("{name} completion")));

        // Catch only to poison and stop; the engine never resumes after a panic.
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.analysers[index]
                .analyser
                .analysis_ended(&mut transaction, &cx)
        }));

        match result {
            Ok(Ok(())) => {
                let changes = transaction.commit()?;
                if !changes.is_empty() {
                    self.begin_publish(&changes);
                }
                drop(project);
                drop(query_write);
                if !changes.is_empty() {
                    self.finish_publish(changes)?;
                }
                self.progress.clear_message();
                Ok(())
            }
            Ok(Err(AnalysisError::Cancelled(cancelled))) => {
                let changes = transaction.commit()?;
                if !changes.is_empty() {
                    self.begin_publish(&changes);
                }
                drop(project);
                drop(query_write);
                if !changes.is_empty() {
                    self.finish_publish(changes)?;
                }
                self.progress.clear_message();
                Err(AnalysisError::Cancelled(cancelled).into())
            }
            Ok(Err(error)) => {
                if let Err(rollback_error) = transaction.rollback() {
                    return Err(self.poison_and_stop(rollback_error.to_string()));
                }
                drop(project);
                drop(query_write);
                tracing::warn!("analyser {name} completion failed: {error}");
                let disabled = self.analysers[index].record_failure();
                self.record_message(name, AnalysisMessageKind::Error, error.to_string());
                if disabled {
                    tracing::warn!("analyser {name} disabled after repeated failures");
                }
                self.progress.clear_message();
                Ok(())
            }
            Err(payload) => {
                let poisoned = self.poison_and_stop(Self::panic_message(payload.as_ref()));
                if let Err(error) = transaction.rollback() {
                    tracing::error!("failed to roll back transaction after panic: {error}");
                }
                project.abandon_persistence();
                drop(project);
                drop(query_write);
                self.progress.clear_message();
                Err(poisoned)
            }
        }
    }

    fn apply_update(&mut self, update: ProjectUpdate) -> Result<ChangeSet, EngineError> {
        let query_write = self.queries.write_guard();
        let project_lock = self.project.clone();
        let mut project = project_lock.write();
        let mut transaction = project.transaction(ChangeSource::agent("update"));
        let result = update.apply(&mut transaction);

        match result {
            Ok(()) => {
                let changes = transaction.commit()?;
                if !changes.is_empty() {
                    self.begin_publish(&changes);
                }
                drop(project);
                drop(query_write);

                if !changes.is_empty() {
                    self.finish_publish(changes.clone())?;
                }

                Ok(changes)
            }
            Err(error) => {
                if let Err(rollback_error) = transaction.rollback() {
                    return Err(self.poison_and_stop(rollback_error.to_string()));
                }
                Err(error.into())
            }
        }
    }

    fn ensure_lifted(
        &mut self,
        function: FunctionId,
        level: IlLevel,
    ) -> Result<ChangeSet, EngineError> {
        let query_write = self.queries.write_guard();
        let project_lock = self.project.clone();
        let mut project = project_lock.write();
        let mut transaction = project.transaction(ChangeSource::agent("ensure IR"));
        let cancellation = self.cancellation.child();
        let result = transaction.ensure_lifted(function, level, &cancellation);

        match result {
            Ok(_) => {
                let changes = transaction.commit()?;
                let present = match level {
                    IlLevel::PCode => project.pcode(function)?.is_some(),
                    IlLevel::ECode => project.ecode(function)?.is_some(),
                    IlLevel::ECodeSsa => project.ecode_ssa(function)?.is_some(),
                };

                if !present {
                    return Err(
                        ProjectError::from(IlError::missing_artefact(function, level)).into(),
                    );
                }

                if !changes.is_empty() {
                    self.begin_publish(&changes);
                }
                drop(project);
                drop(query_write);

                if !changes.is_empty() {
                    self.finish_publish(changes.clone())?;
                }

                Ok(changes)
            }
            Err(error) => {
                if let Err(rollback_error) = transaction.rollback() {
                    return Err(self.poison_and_stop(rollback_error.to_string()));
                }
                Err(error.into())
            }
        }
    }

    fn flush_derived_references(&mut self, function: FunctionId) -> Result<ChangeSet, EngineError> {
        let query_write = self.queries.write_guard();
        let project_lock = self.project.clone();
        let mut project = project_lock.write();
        let mut transaction = project.transaction(ChangeSource::agent("flush IR references"));

        match transaction.flush_derived_references(function) {
            Ok(_) => {
                let changes = transaction.commit()?;
                if !changes.is_empty() {
                    self.begin_publish(&changes);
                }
                drop(project);
                drop(query_write);

                if !changes.is_empty() {
                    self.finish_publish(changes.clone())?;
                }

                Ok(changes)
            }
            Err(error) => {
                if let Err(rollback_error) = transaction.rollback() {
                    return Err(self.poison_and_stop(rollback_error.to_string()));
                }
                Err(error.into())
            }
        }
    }

    fn create_mapping_from_builder(
        &mut self,
        builder: SegmentMappingBuilder,
    ) -> Result<MappingCreationResult, EngineError> {
        let query_write = self.queries.write_guard();
        let project_lock = self.project.clone();
        let mut project = project_lock.write();
        let mut transaction = project.transaction(ChangeSource::agent("update"));
        let result = transaction.create_mapping_from_builder(builder);

        match result {
            Ok(mapping) => {
                let changes = transaction.commit()?;
                if !changes.is_empty() {
                    self.begin_publish(&changes);
                }
                drop(project);
                drop(query_write);

                if !changes.is_empty() {
                    self.finish_publish(changes.clone())?;
                }

                Ok(MappingCreationResult::new(mapping, changes))
            }
            Err(error) => {
                if let Err(rollback_error) = transaction.rollback() {
                    return Err(self.poison_and_stop(rollback_error.to_string()));
                }
                Err(error.into())
            }
        }
    }

    fn create_space(&mut self) -> Result<SpaceCreationResult, EngineError> {
        let query_write = self.queries.write_guard();
        let project_lock = self.project.clone();
        let mut project = project_lock.write();
        let mut transaction = project.transaction(ChangeSource::agent("update"));
        let result = transaction.create_space();

        match result {
            Ok(space) => {
                let changes = transaction.commit()?;
                if !changes.is_empty() {
                    self.begin_publish(&changes);
                }
                drop(project);
                drop(query_write);

                if !changes.is_empty() {
                    self.finish_publish(changes.clone())?;
                }

                Ok(SpaceCreationResult::new(space, changes))
            }
            Err(error) => {
                if let Err(rollback_error) = transaction.rollback() {
                    return Err(self.poison_and_stop(rollback_error.to_string()));
                }
                Err(error.into())
            }
        }
    }

    fn begin_publish(&mut self, changes: &ChangeSet) {
        debug_assert!(!changes.is_empty());
        self.mark_dirty(changes.revision());
        self.queries.apply_changes(changes);
    }

    fn finish_publish(&mut self, changes: ChangeSet) -> Result<(), EngineError> {
        let resync = Arc::new(
            ChangeSet::with_records(
                changes.revision(),
                [ChangeRecord::Restored {
                    to: changes.revision(),
                }],
            )
            .attributed_to(ChangeSource::engine("resync")),
        );
        let changes = Arc::new(changes);
        self.subscribers
            .retain(|subscriber| subscriber.materialise(&changes, &resync));
        self.route_changes(&changes);
        if self.persistence_policy == PersistencePolicy::OnCommit {
            self.persist_dirty()?;
        }
        Ok(())
    }

    fn mark_dirty(&mut self, revision: Revision) {
        if self.dirty_revision.is_none() {
            self.dirty_revision = Some(revision);
        }
    }

    fn persist_dirty(&mut self) -> Result<(), EngineError> {
        if self.dirty_revision.is_none() {
            return Ok(());
        }

        self.save_checkpoint()
    }

    fn persist_dirty_debounced(&mut self) -> Result<(), EngineError> {
        if self
            .last_checkpoint
            .is_some_and(|last| last.elapsed() < IDLE_PERSIST_INTERVAL)
        {
            return Ok(());
        }

        self.persist_dirty()
    }

    fn save_checkpoint(&mut self) -> Result<(), EngineError> {
        if let Err(error) = self.project.write().save() {
            if error.is_write_back_poisoned() {
                let message = error.to_string();
                let _ = self.poison.set(message.clone());
                return Err(EngineError::Poisoned(message));
            }

            return Err(EngineError::Persistence(error));
        }

        self.dirty_revision = None;
        self.last_checkpoint = Some(Instant::now());
        Ok(())
    }

    fn subscribe(&mut self, subscriber: Subscriber) {
        let project = self.project.read();
        let restored_revision = project.restored_revision().map(|_| project.revision());
        drop(project);

        if let Some(revision) = restored_revision {
            let restored = Arc::new(
                ChangeSet::with_records(revision, [ChangeRecord::Restored { to: revision }])
                    .attributed_to(ChangeSource::engine("restore")),
            );
            if !subscriber.materialise(&restored, &restored) {
                return;
            }
        }

        self.subscribers.push(subscriber);
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::change::{ChangeFilter, ChangeRecord, ChangeSet, Revision};
    use super::{
        Analyser, AnalyserState, AnalysisCx, AnalysisQueue, Priority, Subscriber, Trigger,
    };
    use crate::analysis::AnalysisError;
    use crate::ir::{Address, AddressRangeSet};
    use crate::project::{Project, ProjectTransaction};
    use crate::storage::segments::space::AddressSpaceId;

    struct QueueTestAnalyser;

    impl Analyser for QueueTestAnalyser {
        fn name(&self) -> &'static str {
            "queue-test"
        }

        fn triggers(&self) -> &'static [Trigger] {
            &[Trigger::BytesMapped]
        }

        fn priority(&self) -> Priority {
            Priority::DISCOVERY
        }

        fn can_analyse(&self, project: &Project) -> bool {
            let _ = project;
            true
        }

        fn analyse(
            &mut self,
            transaction: &mut ProjectTransaction<'_>,
            regions: &AddressRangeSet,
            cx: &AnalysisCx,
        ) -> Result<(), AnalysisError> {
            let _ = transaction;
            let _ = regions;
            let _ = cx;
            Ok(())
        }
    }

    #[test]
    fn test_repeated_schedules_coalesce_queue_entry() {
        let mut state = AnalyserState::new(Box::new(QueueTestAnalyser));
        let mut queue = AnalysisQueue::default();

        for offset in 0..10_000u64 {
            let mut regions = AddressRangeSet::new();
            regions.insert(Address::in_default_space(offset));
            state.schedule(7, &regions, &mut queue);
        }

        assert_eq!(queue.pop_next(), Some(7));
        assert_eq!(queue.pop_next(), None);

        let pending = state.take_pending();
        assert!(pending.contains(Address::in_default_space(0u64)));
        assert!(pending.contains(Address::in_default_space(9_999u64)));

        let mut regions = AddressRangeSet::new();
        regions.insert(Address::in_default_space(10_000u64));
        state.schedule(7, &regions, &mut queue);

        assert_eq!(queue.pop_next(), Some(7));
        assert_eq!(queue.pop_next(), None);
    }

    #[test]
    fn test_pending_regions_preserve_address_space() {
        let mut state = AnalyserState::new(Box::new(QueueTestAnalyser));
        let mut queue = AnalysisQueue::default();
        let space = AddressSpaceId::from(7u8);
        let address = Address::new(space, 0x1000u64);
        let mut regions = AddressRangeSet::new();

        regions.insert(address);
        state.schedule(3, &regions, &mut queue);

        assert!(state.take_pending().contains(address));
    }

    #[test]
    fn test_lagged_subscriber_receives_resync_change() -> Result<(), Box<dyn std::error::Error>> {
        let (tx, rx) = flume::bounded(1);
        let subscriber = Subscriber::new(tx, rx.clone(), ChangeFilter::new());
        let first = Arc::new(ChangeSet::with_records(
            Revision::new(1),
            [ChangeRecord::SpaceCreated {
                space: AddressSpaceId::from(0u8),
            }],
        ));
        let second = Arc::new(ChangeSet::with_records(
            Revision::new(2),
            [ChangeRecord::SpaceCreated {
                space: AddressSpaceId::from(0u8),
            }],
        ));
        let resync = Arc::new(ChangeSet::with_records(
            Revision::new(2),
            [ChangeRecord::Restored {
                to: Revision::new(2),
            }],
        ));

        assert!(subscriber.materialise(&first, &resync));
        assert!(subscriber.materialise(&second, &resync));

        let delivered = rx.try_recv()?;
        assert_eq!(&*delivered, &*resync);
        assert!(rx.try_recv().is_err());

        Ok(())
    }
}
