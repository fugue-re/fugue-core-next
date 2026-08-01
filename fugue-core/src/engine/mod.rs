use std::cell::Cell;
use std::cmp::Ordering;
use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, OnceLock};
use std::thread::{Builder, JoinHandle};
use std::time::Duration;

use flume::{Receiver, Selector, Sender, TryRecvError, TrySendError};
use parking_lot::RwLock;
use smallvec::SmallVec;
use smol_str::SmolStr;
use thiserror::Error;

use self::change::{
    ChangeCategory, ChangeFilter, ChangeKinds, ChangeProvenance, ChangeRecord, ChangeSet,
    ChangeSource, MAX_DETAILED_CHANGE_RECORDS, Revision,
};
use crate::analysis::AnalysisError;
use crate::analysis::control::{CancellationToken, Progress};
use crate::il::common::{IlArtefact, IlError, IlLevel};
use crate::il::ecode::ssa::{ECodeSsaIr, ECodeToSsa};
use crate::il::ecode::{ECodeIr, PCodeToECode};
use crate::il::pcode::{PCodeCanonicaliser, PCodeIr};
use crate::ir::{
    Address, AddressRange, AddressRangeSet, FunctionId, FunctionProperties, IncompleteFunction,
    ProblemKind, ProblemScope, Reference, ReferenceKind, ReferenceTarget, Switch, SymbolEntry,
    SymbolIndex,
};
use crate::project::{Project, ProjectError, ProjectTransaction};
use crate::queries::{QueryEngine, QueryReader};
use crate::registry::{self, Registration};
use crate::storage::segments::mapping::{
    SegmentMappingBuilder, SegmentMappingFlags, SegmentMappingId, SegmentMappingKind,
    SegmentMappingProvenance,
};
use crate::storage::segments::space::AddressSpaceId;

thread_local! {
    static ON_ANALYSIS_THREAD: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn on_analysis_thread() -> bool {
    ON_ANALYSIS_THREAD.with(Cell::get)
}

const DEFAULT_CHANNEL_CAPACITY: usize = 1024;
const DEFAULT_SUBSCRIPTION_CAPACITY: usize = 1024;
const RETRACTED_BY_BYTE_CHANGE: &[AnalysisPhase] =
    &[AnalysisPhase::Decode, AnalysisPhase::Partition];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(unknown_lints, sorted_enum_variants)]
pub(crate) enum Degradation {
    CausesMerged,
    RangesCollapsed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DegradationEvent {
    kind: Degradation,
    scope: ProblemScope,
}

impl DegradationEvent {
    fn new(kind: Degradation, scope: ProblemScope) -> Self {
        Self { kind, scope }
    }
}

#[derive(Debug, Default)]
pub(crate) struct DegradationReport {
    events: SmallVec<[DegradationEvent; 2]>,
}

impl DegradationReport {
    fn push(&mut self, event: DegradationEvent) {
        if let Some(existing) = self
            .events
            .iter_mut()
            .find(|existing| existing.kind == event.kind)
        {
            existing.scope = existing.scope.covering(event.scope);
        } else {
            self.events.push(event);
        }
    }

    fn extend(&mut self, other: Self) {
        for event in other.events {
            self.push(event);
        }
    }
}

impl IntoIterator for DegradationReport {
    type IntoIter = smallvec::IntoIter<[DegradationEvent; 2]>;
    type Item = DegradationEvent;

    fn into_iter(self) -> Self::IntoIter {
        self.events.into_iter()
    }
}
const WORK_BATCH_ITEMS: usize = 1024;
const MAX_COMPLETION_ROUNDS: usize = 256;
pub const DEFAULT_WORK_ITEM_MAX_ATTEMPTS: usize = 3;

pub mod change;

pub(crate) mod coverage;
pub use coverage::AnalysisCoverage;

pub mod metrics;
pub use metrics::{EngineMetrics, EngineMetricsSnapshot};

mod scheduler;
use scheduler::{AnalysisWorkQueue, ScheduledAnalyser, WORK_SLICE_BYTES, WorkBatch};

pub(crate) mod view;
pub(crate) use view::DependencyIndex;
pub use view::{ProjectView, ReadSet};

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
        self.provenance = provenance;
        self
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
    worker_limit: usize,
}

impl Default for AnalysisEngineConfig {
    fn default() -> Self {
        Self {
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
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
    function: IncompleteFunction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionPropertiesUpdate {
    entry: Address,
    properties: FunctionProperties,
}

impl FunctionPropertiesUpdate {
    pub fn new(entry: impl Into<Address>, properties: FunctionProperties) -> Self {
        Self {
            entry: entry.into(),
            properties,
        }
    }

    pub fn entry(&self) -> Address {
        self.entry
    }

    pub fn properties(&self) -> FunctionProperties {
        self.properties
    }
}

impl FunctionPatch {
    pub fn new(function: IncompleteFunction) -> Self {
        Self { function }
    }

    pub fn function(&self) -> &IncompleteFunction {
        &self.function
    }

    fn into_function(self) -> IncompleteFunction {
        self.function
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolPatch {
    index: SymbolIndex,
    entry: SymbolEntry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchPatch {
    asserted: bool,
    switch: Switch,
}

impl SwitchPatch {
    pub fn new(switch: Switch) -> Self {
        Self {
            asserted: true,
            switch,
        }
    }

    fn derived(switch: Switch) -> Self {
        Self {
            asserted: false,
            switch,
        }
    }

    pub fn switch(&self) -> &Switch {
        &self.switch
    }

    fn into_parts(self) -> (Switch, bool) {
        (self.switch, self.asserted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProblemPatch {
    address: Address,
    kind: ProblemKind,
}

impl ProblemPatch {
    pub fn new(address: impl Into<Address>, kind: ProblemKind) -> Self {
        Self {
            address: address.into(),
            kind,
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn kind(&self) -> ProblemKind {
        self.kind
    }
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
    AddSwitch(SwitchPatch),
    DeprioritiseMapping(MappingPriorityUpdate),
    InsertSymbol(SymbolPatch),
    InsertProblem(ProblemPatch),
    PrioritiseMapping(MappingPriorityUpdate),
    RemapMapping(MappingRemap),
    RemoveFunction(FunctionRemoval),
    RemoveMapping(MappingRemoval),
    RemoveReference(ReferenceRemoval),
    RemoveSwitch(Address),
    RemoveSymbol(SymbolRemoval),
    ResizeMapping(MappingResize),
    SetFunctionProperties(FunctionPropertiesUpdate),
    UpdateMappingMetadata(MappingMetadataUpdate),
    WriteBytes(BytePatch),
}

impl ProjectUpdate {
    pub fn add_function(function: IncompleteFunction) -> Self {
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

    pub fn add_symbol(index: SymbolIndex, entry: SymbolEntry) -> Self {
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

    pub fn add_switch(switch: Switch) -> Self {
        Self::AddSwitch(SwitchPatch::new(switch))
    }

    pub(crate) fn add_derived_switch(switch: Switch) -> Self {
        Self::AddSwitch(SwitchPatch::derived(switch))
    }

    pub fn insert_problem(address: impl Into<Address>, kind: ProblemKind) -> Self {
        Self::InsertProblem(ProblemPatch::new(address, kind))
    }

    pub fn set_function_properties(
        entry: impl Into<Address>,
        properties: FunctionProperties,
    ) -> Self {
        Self::SetFunctionProperties(FunctionPropertiesUpdate::new(entry, properties))
    }

    pub fn remove_switch(branch: impl Into<Address>) -> Self {
        Self::RemoveSwitch(branch.into())
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

    pub(crate) fn apply(
        self,
        transaction: &mut ProjectTransaction<'_>,
    ) -> Result<(), ProjectError> {
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
            Self::AddSwitch(patch) => {
                let (mut switch, asserted) = patch.into_parts();
                if asserted {
                    switch.mark_override();
                }
                let branch = switch.branch();
                transaction.add_switch(branch, move |id, _| switch.with_id(id))?;
                Ok(())
            }
            Self::InsertSymbol(patch) => {
                let (index, entry) = patch.into_parts();
                transaction.add_symbol(index, entry)?;
                Ok(())
            }
            Self::InsertProblem(problem) => {
                transaction.insert_problem(problem.address(), problem.kind())
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
            Self::RemoveSwitch(branch) => {
                transaction.remove_switch(branch)?;
                Ok(())
            }
            Self::RemoveSymbol(removal) => {
                transaction.remove_symbol_by_index(removal.index())?;
                Ok(())
            }
            Self::ResizeMapping(resize) => {
                transaction.resize_mapping(resize.mapping(), resize.size())
            }
            Self::SetFunctionProperties(update) => {
                transaction.set_function_properties(update.entry(), update.properties())?;
                Ok(())
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

    pub(crate) fn apply_all(
        updates: impl IntoIterator<Item = Self>,
        transaction: &mut ProjectTransaction<'_>,
    ) -> Result<(), ProjectError> {
        let mut functions = Vec::new();

        for update in updates {
            let update = match update {
                Self::AddFunction(patch) => {
                    functions.push(patch.into_function());
                    continue;
                }
                update => update,
            };

            if !functions.is_empty() {
                transaction.add_functions(functions.drain(..))?;
            }
            update.apply(transaction)?;
        }

        if !functions.is_empty() {
            transaction.add_functions(functions)?;
        }

        Ok(())
    }
}

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

struct WorkerStartup {
    config: AnalysisEngineConfig,
    project: Arc<RwLock<Project>>,
    queries: QueryEngine,
    poison: Arc<OnceLock<String>>,
    cancellation: CancellationToken,
    progress: Progress,
    metrics: EngineMetrics,
    rx: Receiver<Intake>,
}

impl WorkerStartup {
    fn run(self) -> Result<(), EngineError> {
        let worker = Worker::new(
            self.config,
            self.project,
            self.queries,
            self.poison,
            self.cancellation,
            self.progress,
            self.metrics,
        )?;
        worker.run(self.rx);
        Ok(())
    }
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

    fn materialise(&self, changes: &ChangeSet, resync: &mut Option<Arc<ChangeSet>>) -> bool {
        if self.tx.receiver_count() == 1 {
            return false;
        }
        if changes.len() > MAX_DETAILED_CHANGE_RECORDS {
            return self.resync(Self::resynchronisation(changes, resync));
        }

        let scoped = match changes.scoped_to(&self.filter) {
            Some(scoped) => Arc::new(scoped),
            None => return true,
        };

        match self.tx.try_send(scoped) {
            Ok(()) => true,
            Err(TrySendError::Disconnected(_)) => false,
            Err(TrySendError::Full(_)) => self.resync(Self::resynchronisation(changes, resync)),
        }
    }

    fn resynchronisation(
        changes: &ChangeSet,
        resync: &mut Option<Arc<ChangeSet>>,
    ) -> Arc<ChangeSet> {
        resync
            .get_or_insert_with(|| {
                Arc::new(
                    ChangeSet::with_records(
                        changes.revision(),
                        [ChangeRecord::Resynchronise {
                            to: changes.revision(),
                        }],
                    )
                    .with_provenance(ChangeSource::engine("resynchronisation")),
                )
            })
            .clone()
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

    pub fn with_capacity(project: Project, channel_capacity: usize) -> Result<Self, EngineError> {
        Self::with_config(
            project,
            AnalysisEngineConfig::default().with_channel_capacity(channel_capacity),
        )
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
        let queries = QueryEngine::new(project.clone());
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
                let startup = WorkerStartup {
                    config,
                    project,
                    queries,
                    poison: worker_state_poison,
                    cancellation: worker_cancellation,
                    progress: worker_progress,
                    metrics: worker_metrics,
                    rx,
                };
                if let Err(error) = startup.run() {
                    let _ = worker_poison.set(error.to_string());
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

        Ok(Subscription { rx })
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
            Reply(Result<Result<T, EngineError>, flume::RecvError>),
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

    pub fn with_kinds(mut self, kinds: ChangeKinds) -> Self {
        self.filter = self.filter.with_kinds(kinds);
        self
    }

    pub fn with_region(mut self, region: AddressRangeSet) -> Self {
        self.filter = self.filter.with_region(region);
        self
    }

    pub fn with_category(mut self, category: ChangeCategory) -> Self {
        self.filter = self.filter.with_category(category);
        self
    }

    pub fn with_source_label(mut self, label: impl Into<SmolStr>) -> Self {
        self.filter = self.filter.with_source_label(label);
        self
    }

    pub fn with_capacity(mut self, capacity: usize) -> Self {
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

    pub fn recv_timeout(&self, timeout: Duration) -> Result<Arc<ChangeSet>, EngineError> {
        self.rx.recv_timeout(timeout).map_err(|error| match error {
            flume::RecvTimeoutError::Disconnected => EngineError::Stopped,
            flume::RecvTimeoutError::Timeout => EngineError::SubscriptionTimeout,
        })
    }

    pub fn try_recv(&self) -> Result<Arc<ChangeSet>, EngineError> {
        self.rx.try_recv().map_err(|error| match error {
            TryRecvError::Disconnected => EngineError::Stopped,
            TryRecvError::Empty => EngineError::SubscriptionEmpty,
        })
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
    pcode: Option<PCodeIr>,
    ecode: Option<ECodeIr>,
    ecode_ssa: Option<ECodeSsaIr>,
    pcode_references: Option<PreparedDerivedReferences>,
}

struct PreparedDerivedReferences {
    coverage: AddressRangeSet,
    references: Vec<Reference>,
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
}

impl Worker {
    fn new(
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
        let provenance = ChangeProvenance::of(ChangeSource::agent("schedule"));
        self.route_direct(kind, regions, revision, &provenance);
    }

    fn schedule_uncovered_hints(&mut self) {
        let mut regions = AddressRangeSet::new();
        let project = self.project.read();
        let revision = project.revision();

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
            let kind = match degradation.kind {
                Degradation::CausesMerged => {
                    self.metrics.record_causes_merged();
                    ProblemKind::WorkCausesMerged
                }
                Degradation::RangesCollapsed => {
                    self.metrics.record_ranges_collapsed();
                    ProblemKind::PendingWorkCollapsed
                }
            };
            self.pending_diagnostics.defer(degradation.scope, kind);
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
            transaction.insert_scoped_problem(*scope, *kind)?;
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

        let (base, analysis, reads, reads_collapsed, updates) = {
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
            (base, analysis, reads, reads_collapsed, updates)
        };
        let value = match analysis {
            Ok(()) => Ok(()),
            Err(AnalysisError::Cancelled(cancelled)) => Err(cancelled),
            Err(error) => return self.handle_dispatch_failure(index, batch, error),
        };
        if let Some(conflict) = self.recent_changes.conflict(base, &reads) {
            return self.handle_admission_conflict(batch, conflict);
        }
        let result =
            self.with_transaction(ChangeSource::analysis(name), move |_, transaction| {
                transaction.absorb_reads(&reads);
                ProjectUpdate::apply_all(updates, transaction)
                    .map_err(|error| AnalysisError::pass_failed(name, error))?;
                Ok::<_, AnalysisError>(value)
            })?;
        match result {
            TransactionResult::Committed {
                value: Ok(()),
                reads,
                reads_collapsed: admission_reads_collapsed,
                ..
            } => {
                self.dependencies.record(index, &regions, reads);
                if reads_collapsed || admission_reads_collapsed {
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
            TransactionResult::Committed {
                value: Err(cancelled),
                ..
            } => {
                self.progress.clear_message();
                Err(AnalysisError::Cancelled(cancelled).into())
            }
            TransactionResult::Rejected(error) => self.handle_dispatch_failure(index, batch, error),
        }
    }

    fn handle_admission_conflict(
        &mut self,
        batch: WorkBatch,
        conflict: AdmissionConflict,
    ) -> Result<(), EngineError> {
        match conflict {
            AdmissionConflict::InputsChanged => self.metrics.record_admission_conflict(),
            AdmissionConflict::ResynchronisationRequired => {
                self.metrics.record_admission_resynchronisation();
            }
        }
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
            let (base, analysis, reads, reads_collapsed, updates) = {
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
                (base, analysis, reads, reads_collapsed, updates)
            };
            let value = match analysis {
                Ok(()) => Ok(()),
                Err(AnalysisError::Cancelled(cancelled)) => Err(cancelled),
                Err(error) => {
                    tracing::warn!("analyser {name} completion failed: {error}");
                    self.progress.clear_message();
                    return Err(error.into());
                }
            };
            if let Some(conflict) = self.recent_changes.conflict(base, &reads) {
                match conflict {
                    AdmissionConflict::InputsChanged => self.metrics.record_admission_conflict(),
                    AdmissionConflict::ResynchronisationRequired => {
                        self.metrics.record_admission_resynchronisation();
                    }
                }
                continue;
            }

            let result =
                self.with_transaction(ChangeSource::analysis(name), move |_, transaction| {
                    transaction.absorb_reads(&reads);
                    ProjectUpdate::apply_all(updates, transaction)
                        .map_err(|error| AnalysisError::pass_failed(name, error))?;
                    Ok::<_, AnalysisError>(value)
                })?;

            return match result {
                TransactionResult::Committed {
                    value: Ok(()),
                    reads_collapsed: admission_reads_collapsed,
                    ..
                } => {
                    if reads_collapsed || admission_reads_collapsed {
                        self.defer_read_set_collapse(&AddressRangeSet::new());
                    }
                    self.progress.clear_message();
                    Ok(())
                }
                TransactionResult::Committed {
                    value: Err(cancelled),
                    ..
                } => {
                    self.progress.clear_message();
                    Err(AnalysisError::Cancelled(cancelled).into())
                }
                TransactionResult::Rejected(error) => {
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
        match self.with_transaction(ChangeSource::agent("update"), |_, transaction| {
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
        let prepared = self.prepare_lifted(function, level, &cancellation)?;
        let result = self
            .with_transaction(ChangeSource::agent("ensure IR"), move |_, transaction| {
                prepared.admit(transaction)
            })?;

        match result {
            TransactionResult::Committed { changes, .. } => Ok(changes),
            TransactionResult::Rejected(error) => Err(error.into()),
        }
    }

    fn prepare_lifted(
        &self,
        function: FunctionId,
        level: IlLevel,
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
        let existing_pcode = Self::current_lifted::<PCodeIr>(&project, function)?;
        let existing_ecode = Self::current_lifted::<ECodeIr>(&project, function)?;
        let existing_ecode_ssa = Self::current_lifted::<ECodeSsaIr>(&project, function)?;
        let build_ecode = level >= IlLevel::ECode && existing_ecode.is_none();
        let build_pcode = (level == IlLevel::PCode || build_ecode) && existing_pcode.is_none();
        let build_ecode_ssa = level == IlLevel::ECodeSsa && existing_ecode_ssa.is_none();
        let mut prepared = PreparedLiftedArtefacts::default();

        if build_pcode {
            let mut canonicaliser = PCodeCanonicaliser::default();
            let pcode = canonicaliser
                .build_function(
                    view.language(),
                    view.functions(),
                    view.blocks(),
                    view.segments(),
                    function,
                    revision,
                    cancellation,
                )
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
                .or(existing_pcode.as_ref())
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
                .or(existing_ecode.as_ref())
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

    fn current_lifted<T>(project: &Project, function: FunctionId) -> Result<Option<T>, ProjectError>
    where
        T: IlArtefact,
    {
        match project.lifted::<T>(function) {
            Ok(artefact) => Ok(artefact),
            Err(ProjectError::Il(
                IlError::SchemaMismatch { .. } | IlError::StaleArtefact { .. },
            )) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn create_mapping(
        &mut self,
        builder: SegmentMappingBuilder,
    ) -> Result<MappingCreationResult, EngineError> {
        match self.with_transaction(ChangeSource::agent("update"), |_, transaction| {
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
        match self.with_transaction(ChangeSource::agent("update"), |_, transaction| {
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
    use std::sync::Arc;

    use super::change::{ChangeFilter, ChangeKinds, ChangeRecord, ChangeSet, Revision};
    use super::{
        AdmissionConflict, Degradation, MAX_DETAILED_CHANGE_RECORDS, ReadSet, RecentChanges,
        Subscriber,
    };
    use crate::ir::{Address, AddressRange, ProblemKind, ProblemScope};
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn degradation_reports_are_bounded_by_kind_and_coarsen_scope() {
        let first = AddressSpaceId::from(0u8);
        let second = AddressSpaceId::from(1u8);
        let mut report = super::DegradationReport::default();

        report.push(super::DegradationEvent::new(
            Degradation::CausesMerged,
            ProblemScope::Range(AddressRange::new(first, 0x1000u64.into(), 0x1fffu64.into())),
        ));
        report.push(super::DegradationEvent::new(
            Degradation::CausesMerged,
            ProblemScope::Range(AddressRange::new(first, 0x3000u64.into(), 0x3fffu64.into())),
        ));
        report.push(super::DegradationEvent::new(
            Degradation::CausesMerged,
            ProblemScope::Range(AddressRange::new(
                second,
                0x1000u64.into(),
                0x1fffu64.into(),
            )),
        ));
        report.push(super::DegradationEvent::new(
            Degradation::RangesCollapsed,
            ProblemScope::AddressSpace(first),
        ));

        let events = report.into_iter().collect::<Vec<_>>();
        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|event| {
            event.kind == Degradation::CausesMerged && event.scope == ProblemScope::Global
        }));
        assert!(events.iter().any(|event| {
            event.kind == Degradation::RangesCollapsed
                && event.scope == ProblemScope::AddressSpace(first)
        }));
    }

    #[test]
    fn pending_diagnostics_are_bounded_by_kind() {
        let first = AddressSpaceId::from(0u8);
        let second = AddressSpaceId::from(1u8);
        let mut pending = super::PendingDiagnostics::default();

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

        assert!(window.changes.is_empty());
        assert_eq!(window.records, 0);
        assert_eq!(
            window.conflict(Revision::new(0), &ReadSet::new()),
            Some(AdmissionConflict::ResynchronisationRequired)
        );
        assert_eq!(window.conflict(Revision::new(1), &ReadSet::new()), None);
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
        let mut resync = None;

        assert!(subscriber.materialise(&first, &mut resync));
        assert!(subscriber.materialise(&second, &mut resync));

        let delivered = rx.try_recv()?;
        assert_eq!(&*delivered, &*resync.expect("resync must be materialised"));
        assert!(rx.try_recv().is_err());

        Ok(())
    }

    #[test]
    fn oversized_publication_delivers_one_resynchronisation_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let (tx, rx) = flume::bounded(1);
        let subscriber = Subscriber::new(tx, rx.clone(), ChangeFilter::new());
        let records = (0..=MAX_DETAILED_CHANGE_RECORDS)
            .map(|index| ChangeRecord::BytesWritten {
                range: AddressRange::point(Address::from(index as u64)),
            })
            .collect::<Vec<_>>();
        let changes = ChangeSet::with_records(Revision::new(1), records);
        let mut resynchronisation = None;

        assert!(subscriber.materialise(&changes, &mut resynchronisation));

        let delivered = rx.try_recv()?;
        assert_eq!(
            delivered.records(),
            &[ChangeRecord::Resynchronise {
                to: Revision::new(1)
            }]
        );
        assert_eq!(delivered.provenance().sources().count(), 1);

        Ok(())
    }

    #[test]
    fn dropped_subscription_is_pruned_despite_internal_receiver() {
        let (tx, rx) = flume::bounded(1);
        let subscriber = Subscriber::new(tx, rx.clone(), ChangeFilter::new());
        drop(rx);
        let changes = Arc::new(ChangeSet::new(Revision::new(1)));
        assert!(!subscriber.materialise(&changes, &mut None));
    }
}
