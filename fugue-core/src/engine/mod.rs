use std::cmp::Ordering;
use std::collections::{BTreeMap, VecDeque};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, OnceLock};
use std::thread::{Builder, JoinHandle};

use flume::{Receiver, Sender, TryRecvError, TrySendError};
use parking_lot::RwLock;
use thiserror::Error;

use self::change::{ChangeRecord, ChangeSet};
use crate::analysis::AnalysisError;
use crate::analysis::control::{CancellationToken, Progress};
use crate::analysis::function::recovery::PartialFunction;
use crate::ir::{Address, AddressRangeSet, RawAddressRangeSet, SymbolEntry, SymbolIndex};
use crate::project::{Project, ProjectError, ProjectTransaction};
use crate::queries::{QueryEngine, QueryReader};
use crate::registry::{self, Registration};
use crate::storage::segments::mapping::{
    SegmentMappingBuilder, SegmentMappingFlags, SegmentMappingId, SegmentMappingKind,
    SegmentMappingProvenance,
};
use crate::storage::segments::space::AddressSpaceId;

const DEFAULT_CHANNEL_CAPACITY: usize = 1024;
const MAX_PENDING_REGION_RANGES: usize = 4096;

pub mod change;

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
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
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

    fn trigger(&self) -> Trigger;

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
pub struct FunctionRemoval {
    entry: Address,
}

impl FunctionRemoval {
    pub fn new(entry: impl Into<Address>) -> Self {
        Self {
            entry: entry.into(),
        }
    }

    pub fn entry(&self) -> Address {
        self.entry
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
pub struct MappingPriorityEdit {
    mapping: SegmentMappingId,
    space: AddressSpaceId,
}

impl MappingPriorityEdit {
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
pub enum ProjectEdit {
    AddFunction(FunctionPatch),
    AddMappingToSpace(MappingPlacement),
    DeprioritiseMapping(MappingPriorityEdit),
    InsertSymbol(SymbolPatch),
    PrioritiseMapping(MappingPriorityEdit),
    RemapMapping(MappingRemap),
    RemoveFunction(FunctionRemoval),
    RemoveMapping(MappingRemoval),
    RemoveSymbol(SymbolRemoval),
    ResizeMapping(MappingResize),
    UpdateMappingMetadata(MappingMetadataUpdate),
    WriteBytes(BytePatch),
}

impl ProjectEdit {
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
        Self::DeprioritiseMapping(MappingPriorityEdit::new(space, mapping))
    }

    pub fn insert_symbol(index: SymbolIndex, entry: SymbolEntry) -> Self {
        Self::InsertSymbol(SymbolPatch::new(index, entry))
    }

    pub fn prioritise_mapping(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self::PrioritiseMapping(MappingPriorityEdit::new(space, mapping))
    }

    pub fn remap_mapping(mapping: SegmentMappingId, start: impl Into<Address>) -> Self {
        Self::RemapMapping(MappingRemap::new(mapping, start))
    }

    pub fn remove_function(entry: impl Into<Address>) -> Self {
        Self::RemoveFunction(FunctionRemoval::new(entry))
    }

    pub fn remove_mapping(mapping: SegmentMappingId) -> Self {
        Self::RemoveMapping(MappingRemoval::new(mapping))
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
            Self::InsertSymbol(patch) => {
                let (index, entry) = patch.into_parts();
                transaction.insert_symbol(index, entry);
                Ok(())
            }
            Self::PrioritiseMapping(priority) => {
                transaction.prioritise_mapping(priority.space(), priority.mapping())
            }
            Self::RemapMapping(remap) => transaction.remap_mapping(remap.mapping(), remap.start()),
            Self::RemoveFunction(removal) => {
                transaction.remove_function(removal.entry());
                Ok(())
            }
            Self::RemoveMapping(removal) => transaction.remove_mapping(removal.mapping()),
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

enum Intake {
    Cancel,
    Changes(ChangeSet),
    CreateMapping {
        builder: SegmentMappingBuilder,
        reply: Sender<Result<MappingCreationResult, EngineError>>,
    },
    CreateSpace(Sender<Result<SpaceCreationResult, EngineError>>),
    Direct {
        regions: AddressRangeSet,
        trigger: Trigger,
    },
    Edit {
        edit: ProjectEdit,
        reply: Sender<Result<ChangeSet, EngineError>>,
    },
    Flush(Sender<Result<(), EngineError>>),
    Save(Sender<Result<(), EngineError>>),
    Shutdown,
    Subscribe(Subscriber),
}

struct AnalyserState {
    analyser: Box<dyn Analyser>,
    pending: AddressRangeSet,
    priority: Priority,
    scheduled: bool,
    trigger: Trigger,
}

struct Subscriber {
    rx: Receiver<Arc<ChangeSet>>,
    tx: Sender<Arc<ChangeSet>>,
}

impl Subscriber {
    fn new(tx: Sender<Arc<ChangeSet>>, rx: Receiver<Arc<ChangeSet>>) -> Self {
        Self { rx, tx }
    }

    fn publish(&self, changes: Arc<ChangeSet>, resync: Arc<ChangeSet>) -> bool {
        match self.tx.try_send(changes) {
            Ok(()) => true,
            Err(TrySendError::Disconnected(_)) => false,
            Err(TrySendError::Full(_)) => self.resync(resync),
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
        let priority = analyser.priority();
        let trigger = analyser.trigger();

        Self {
            analyser,
            pending: AddressRangeSet::new(),
            priority,
            scheduled: false,
            trigger,
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

    fn schedule(&mut self, index: usize, regions: &AddressRangeSet, queue: &mut AnalysisQueue) {
        self.add_pending(regions);
        if self.scheduled {
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

    fn is_empty(&self) -> bool {
        self.priorities.is_empty()
    }
}

pub struct AnalysisEngine {
    cancellation: CancellationToken,
    handle: Option<JoinHandle<()>>,
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
        let (tx, rx) = flume::bounded(channel_capacity);
        let cancellation = CancellationToken::default();
        let poison = Arc::new(OnceLock::new());
        let progress = Progress::default();
        let project = Arc::new(RwLock::new(project));
        let queries = QueryEngine::new(project.clone());
        let query_reader = queries.reader();
        let worker_cancellation = cancellation.clone();
        let worker_poison = poison.clone();
        let worker_state_poison = poison.clone();
        let worker_progress = progress.clone();
        let handle = Builder::new()
            .name("fugue-analysis".to_owned())
            .spawn(move || {
                match catch_unwind(AssertUnwindSafe(|| {
                    let worker = Worker::new(
                        project,
                        queries,
                        worker_state_poison,
                        worker_cancellation,
                        worker_progress,
                    )?;
                    worker.run(rx);
                    Ok::<(), EngineError>(())
                })) {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        let _ = worker_poison.set(error.to_string());
                    }
                    Err(payload) => {
                        let message = payload
                            .downcast_ref::<&str>()
                            .map(|message| (*message).to_owned())
                            .or_else(|| payload.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "analysis worker panicked".to_owned());
                        let _ = worker_poison.set(message);
                    }
                }
            })
            .map_err(|error| EngineError::Poisoned(error.to_string()))?;

        Ok(Self {
            cancellation,
            handle: Some(handle),
            poison,
            progress,
            query_reader,
            tx,
        })
    }

    pub fn send_changes(&self, changes: ChangeSet) -> Result<(), EngineError> {
        self.poison_check()?;
        self.tx
            .send(Intake::Changes(changes))
            .map_err(|_| EngineError::Stopped)
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

    pub fn apply_edit(&self, edit: ProjectEdit) -> Result<ChangeSet, EngineError> {
        self.poison_check()?;

        let (reply_tx, reply_rx) = flume::bounded(1);
        self.tx
            .send(Intake::Edit {
                edit,
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
        self.apply_edit(ProjectEdit::write_bytes(address, bytes))
    }

    pub fn insert_symbol(
        &self,
        index: SymbolIndex,
        entry: SymbolEntry,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_edit(ProjectEdit::insert_symbol(index, entry))
    }

    pub fn add_function(&self, function: PartialFunction) -> Result<ChangeSet, EngineError> {
        self.apply_edit(ProjectEdit::add_function(function))
    }

    pub fn add_mapping_to_space(
        &self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_edit(ProjectEdit::add_mapping_to_space(space, mapping))
    }

    pub fn add_mapping_to_space_bottom(
        &self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_edit(ProjectEdit::add_mapping_to_space_bottom(space, mapping))
    }

    pub fn add_mapping_to_space_top(
        &self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_edit(ProjectEdit::add_mapping_to_space_top(space, mapping))
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
        self.apply_edit(ProjectEdit::deprioritise_mapping(space, mapping))
    }

    pub fn prioritise_mapping(
        &self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_edit(ProjectEdit::prioritise_mapping(space, mapping))
    }

    pub fn remove_function(&self, entry: Address) -> Result<ChangeSet, EngineError> {
        self.apply_edit(ProjectEdit::remove_function(entry))
    }

    pub fn remap_mapping(
        &self,
        mapping: SegmentMappingId,
        start: Address,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_edit(ProjectEdit::remap_mapping(mapping, start))
    }

    pub fn remove_mapping(&self, mapping: SegmentMappingId) -> Result<ChangeSet, EngineError> {
        self.apply_edit(ProjectEdit::remove_mapping(mapping))
    }

    pub fn remove_symbol(&self, index: SymbolIndex) -> Result<ChangeSet, EngineError> {
        self.apply_edit(ProjectEdit::remove_symbol(index))
    }

    pub fn resize_mapping(
        &self,
        mapping: SegmentMappingId,
        size: u64,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_edit(ProjectEdit::resize_mapping(mapping, size))
    }

    pub fn update_mapping_metadata(
        &self,
        update: MappingMetadataUpdate,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_edit(ProjectEdit::update_mapping_metadata(update))
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

    pub fn progress(&self) -> Progress {
        self.progress.clone()
    }

    pub fn subscribe(&self, capacity: usize) -> Result<Receiver<Arc<ChangeSet>>, EngineError> {
        self.poison_check()?;

        let (tx, rx) = flume::bounded(capacity.max(1));
        self.tx
            .send(Intake::Subscribe(Subscriber::new(tx, rx.clone())))
            .map_err(|_| EngineError::Stopped)?;

        Ok(rx)
    }

    pub fn poison_check(&self) -> Result<(), EngineError> {
        match self.poison.get() {
            Some(message) => Err(EngineError::Poisoned(message.clone())),
            None => Ok(()),
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

struct Worker {
    analysers: Vec<AnalyserState>,
    cancellation: CancellationToken,
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

    fn run(mut self, rx: Receiver<Intake>) {
        loop {
            let message = match rx.recv() {
                Ok(message) => message,
                Err(_) => break,
            };

            match message {
                Intake::Cancel => {
                    if self.queue.is_empty() {
                        self.cancellation.clear();
                    }
                }
                Intake::Changes(changes) => {
                    if !changes.is_empty() {
                        self.publish(changes);
                    }
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
                Intake::Direct { regions, trigger } => self.route_direct(trigger, &regions),
                Intake::Edit { edit, reply } => {
                    let result = self
                        .drain_or_handle_cancelled()
                        .and_then(|()| self.apply_edit(edit));
                    let _ = reply.send(result);
                }
                Intake::Flush(reply) => {
                    let _ = reply.send(self.drain_or_handle_cancelled());
                }
                Intake::Save(reply) => {
                    let result = self
                        .drain_or_handle_cancelled()
                        .and_then(|()| self.project.write().save().map_err(EngineError::from));
                    let _ = reply.send(result);
                }
                Intake::Shutdown => break,
                Intake::Subscribe(subscriber) => {
                    self.subscribers.push(subscriber);
                }
            }

            if let Err(error) = self.drain_or_handle_cancelled() {
                let _ = self.poison.set(error.to_string());
            }
        }
    }

    fn drain_or_handle_cancelled(&mut self) -> Result<(), EngineError> {
        match self.drain() {
            Ok(()) => {
                self.cancellation.clear();
                Ok(())
            }
            Err(error) if self.handle_analysis_cancelled(&error) => Ok(()),
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

    fn drain(&mut self) -> Result<(), EngineError> {
        while let Some(index) = self.queue.pop_next() {
            self.run_analyser(index)?;
        }

        Ok(())
    }

    fn route_changes(&mut self, changes: &ChangeSet) {
        for record in changes.records() {
            self.route_record(record);
        }
    }

    fn route_direct(&mut self, trigger: Trigger, regions: &AddressRangeSet) {
        for index in 0..self.analysers.len() {
            if self.analysers[index].trigger == trigger {
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
            ChangeRecord::BytesWritten { space, range } => {
                let mut regions = AddressRangeSet::new();
                regions.insert_raw_range(*space, range.0..=range.1);
                self.route_direct(Trigger::BytesWritten, &regions);
            }
            ChangeRecord::FunctionAdded { entry } => {
                let mut regions = AddressRangeSet::new();
                regions.insert(*entry);
                self.route_direct(Trigger::FunctionAdded, &regions);
            }
            ChangeRecord::FunctionChanged { entry, .. } => {
                let mut regions = AddressRangeSet::new();
                regions.insert(*entry);
                self.route_direct(Trigger::FunctionChanged, &regions);
            }
            ChangeRecord::FunctionRemoved { entry } => {
                let mut regions = AddressRangeSet::new();
                regions.insert(*entry);
                self.route_direct(Trigger::FunctionRemoved, &regions);
            }
            ChangeRecord::Restored { .. } => {}
            ChangeRecord::SegmentMapped { space, range, .. } => {
                let mut regions = AddressRangeSet::new();
                regions.insert_raw_range(*space, range.0..=range.1);
                self.route_direct(Trigger::BytesMapped, &regions);
                self.route_direct(Trigger::SegmentMapped, &regions);
            }
            ChangeRecord::SegmentMappingCreated { .. } => {}
            ChangeRecord::SegmentMappingChanged { .. } => {}
            ChangeRecord::SegmentUnmapped { space, range, .. } => {
                let mut regions = AddressRangeSet::new();
                regions.insert_raw_range(*space, range.0..=range.1);
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
        }
    }

    fn schedule_analyser(&mut self, index: usize, regions: &AddressRangeSet) {
        self.analysers[index].schedule(index, regions, &mut self.queue);
    }

    fn run_analyser(&mut self, index: usize) -> Result<(), EngineError> {
        let regions = self.analysers[index].take_pending();
        self.progress.reset();
        let cx = AnalysisCx::new(self.cancellation.clone(), self.progress.clone());
        let mut project = self.project.write();
        let mut transaction = project.transaction(self.analysers[index].analyser.name());

        let result = self.analysers[index]
            .analyser
            .analyse(&mut transaction, &regions, &cx);

        let changes = transaction.commit();
        drop(project);
        if !changes.is_empty() {
            self.publish(changes);
        }
        self.progress.clear_message();

        result.map_err(EngineError::from)
    }

    fn apply_edit(&mut self, edit: ProjectEdit) -> Result<ChangeSet, EngineError> {
        let mut project = self.project.write();
        let mut transaction = project.transaction("edit");
        let result = edit.apply(&mut transaction);
        let changes = transaction.commit();
        drop(project);

        if !changes.is_empty() {
            self.publish(changes.clone());
        }

        result.map(|()| changes).map_err(EngineError::from)
    }

    fn create_mapping_from_builder(
        &mut self,
        builder: SegmentMappingBuilder,
    ) -> Result<MappingCreationResult, EngineError> {
        let mut project = self.project.write();
        let mut transaction = project.transaction("edit");
        let result = transaction.create_mapping_from_builder(builder);
        let changes = transaction.commit();
        drop(project);

        if !changes.is_empty() {
            self.publish(changes.clone());
        }

        result
            .map(|mapping| MappingCreationResult::new(mapping, changes))
            .map_err(EngineError::from)
    }

    fn create_space(&mut self) -> Result<SpaceCreationResult, EngineError> {
        let mut project = self.project.write();
        let mut transaction = project.transaction("edit");
        let result = transaction.create_space();
        let changes = transaction.commit();
        drop(project);

        if !changes.is_empty() {
            self.publish(changes.clone());
        }

        result
            .map(|space| SpaceCreationResult::new(space, changes))
            .map_err(EngineError::from)
    }

    fn publish(&mut self, changes: ChangeSet) {
        self.queries.apply_changes(&changes);
        let resync = Arc::new(ChangeSet::with_records(
            changes.revision(),
            [ChangeRecord::Restored {
                to: changes.revision(),
            }],
        ));
        let changes = Arc::new(changes);
        self.subscribers
            .retain(|subscriber| subscriber.publish(changes.clone(), resync.clone()));
        self.route_changes(&changes);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::change::{ChangeRecord, ChangeSet, Revision};
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

        fn trigger(&self) -> Trigger {
            Trigger::BytesMapped
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
        let subscriber = Subscriber::new(tx, rx.clone());
        let first = Arc::new(ChangeSet::new(Revision::new(1)));
        let second = Arc::new(ChangeSet::new(Revision::new(2)));
        let resync = Arc::new(ChangeSet::with_records(
            Revision::new(2),
            [ChangeRecord::Restored {
                to: Revision::new(2),
            }],
        ));

        assert!(subscriber.publish(first, resync.clone()));
        assert!(subscriber.publish(second, resync.clone()));

        let delivered = rx.try_recv()?;
        assert_eq!(&*delivered, &*resync);
        assert!(rx.try_recv().is_err());

        Ok(())
    }
}
