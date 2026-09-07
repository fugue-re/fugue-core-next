use std::any::{TypeId, type_name};
use std::cmp::Ordering;
use std::fmt::{self, Display, Formatter};
use std::mem;
use std::sync::{Arc, OnceLock};
use std::thread::{Builder, JoinHandle};

use change::ChangeFilter;
use downcast_rs::{Downcast, impl_downcast};
use flume::{Receiver, RecvError, Selector, Sender, TryRecvError};
use parking_lot::RwLock;
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;
use smol_str::SmolStr;
use thiserror::Error;
use update::ProjectUpdate;
use worker::Worker;

use crate::analysis::AnalysisError;
use crate::extension::{self, Registration};
use crate::il::common::{IlAnalyser, IlArtefact, IlFormId};
use crate::il::registry::IlRegistry;
use crate::ir::{
    Address, AddressRange, AddressRangeSet, FunctionId, IncompleteFunction, Reference,
    ReferenceTarget, Switch, SymbolEntry, SymbolIndex,
};
use crate::project::{
    AnalysisPhase, ChangeKinds, ChangeProvenance, ChangeSet, ChangeSource, Project, ProjectError,
};
use crate::queries::{QueryEngine, QueryReader};
use crate::storage::segments::mapping::{SegmentMappingBuilder, SegmentMappingId};
use crate::storage::segments::space::AddressSpaceId;
use crate::types::Revision;

pub mod change;
pub(crate) mod metrics;
mod scheduler;
mod subscription;
mod update;
pub(crate) mod view;
mod worker;

pub use metrics::{EngineMetrics, EngineMetricsSnapshot};
pub(crate) use subscription::Subscriber;
pub use subscription::{Subscription, SubscriptionBuilder};
pub use update::{
    MappingCreationResult, MappingMetadataUpdate, ProjectUpdates, SpaceCreationResult,
};
pub use view::ProjectView;
pub(crate) use worker::Intake;

const DEFAULT_CHANNEL_CAPACITY: usize = 1024;
const DEFAULT_LIFTED_CACHE_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_SUBSCRIPTION_CAPACITY: usize = 1024;
pub(crate) const DEFAULT_WORK_ITEM_MAX_ATTEMPTS: usize = 3;
const MAX_COMPLETION_ROUNDS: usize = 256;
const RETRACTED_BY_BYTE_CHANGE: &[AnalysisPhase] =
    &[AnalysisPhase::Decode, AnalysisPhase::Partition];
const WORK_BATCH_ITEMS: usize = 1024;

pub trait AnalysisData: Downcast + Send {
    #[doc(hidden)]
    fn delegated(&self) -> Option<&dyn AnalysisData> {
        None
    }

    #[doc(hidden)]
    fn delegated_mut(&mut self) -> Option<&mut dyn AnalysisData> {
        None
    }
}

impl_downcast!(AnalysisData);

#[derive(Debug, Error)]
pub enum AnalysisDataError {
    #[error("multiple analysis data values expose `{0}`")]
    Ambiguous(&'static str),
    #[error("analysis data not found: `{0}`")]
    Missing(&'static str),
}

impl AnalysisDataError {
    fn ambiguous<T>() -> Self {
        Self::Ambiguous(type_name::<T>())
    }

    fn missing<T>() -> Self {
        Self::Missing(type_name::<T>())
    }
}

#[derive(Default)]
pub struct AnalysisDataStore {
    entries: FxHashMap<TypeId, Box<dyn AnalysisData>>,
}

impl AnalysisDataStore {
    pub fn get<T>(&self) -> Result<Option<&T>, AnalysisDataError>
    where
        T: AnalysisData,
    {
        let Some(root) = self.root_for::<T>()? else {
            return Ok(None);
        };
        let mut data = self
            .entries
            .get(&root)
            .expect("analysis data root must remain installed")
            .as_ref();

        loop {
            if data.is::<T>() {
                return Ok(data.downcast_ref::<T>());
            }
            data = data
                .delegated()
                .expect("selected analysis data root must expose the requested type");
        }
    }

    pub fn get_mut<T>(&mut self) -> Result<Option<&mut T>, AnalysisDataError>
    where
        T: AnalysisData,
    {
        let Some(root) = self.root_for::<T>()? else {
            return Ok(None);
        };
        let mut data = self
            .entries
            .get_mut(&root)
            .expect("analysis data root must remain installed")
            .as_mut();

        loop {
            if data.is::<T>() {
                return Ok(data.downcast_mut::<T>());
            }
            data = data
                .delegated_mut()
                .expect("selected analysis data root must expose the requested type");
        }
    }

    pub fn require<T>(&self) -> Result<&T, AnalysisDataError>
    where
        T: AnalysisData,
    {
        self.get::<T>()?.ok_or_else(AnalysisDataError::missing::<T>)
    }

    pub fn require_mut<T>(&mut self) -> Result<&mut T, AnalysisDataError>
    where
        T: AnalysisData,
    {
        self.get_mut::<T>()?
            .ok_or_else(AnalysisDataError::missing::<T>)
    }

    pub(crate) fn set(&mut self, root: TypeId, value: Box<dyn AnalysisData>) {
        self.entries.insert(root, value);
    }

    fn root_for<T>(&self) -> Result<Option<TypeId>, AnalysisDataError>
    where
        T: AnalysisData,
    {
        let mut selected = None;

        for (root, data) in &self.entries {
            if !Self::exposes::<T>(data.as_ref()) {
                continue;
            }
            if selected.is_some() {
                return Err(AnalysisDataError::ambiguous::<T>());
            }
            selected = Some(*root);
        }

        Ok(selected)
    }

    fn exposes<T>(mut data: &dyn AnalysisData) -> bool
    where
        T: AnalysisData,
    {
        loop {
            if data.is::<T>() {
                return true;
            }
            let Some(delegated) = data.delegated() else {
                return false;
            };
            data = delegated;
        }
    }
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

#[derive(Debug, Clone)]
pub struct AnalysisEngineConfig {
    analyser_names: FxHashMap<SmolStr, bool>,
    analyser_types: FxHashMap<TypeId, AnalyserTypeSelection>,
    analysers_enabled: bool,
    channel_capacity: usize,
    lifted_cache_bytes: usize,
    registry: Arc<IlRegistry>,
    worker_limit: usize,
}

#[derive(Debug, Clone, Copy)]
struct AnalyserTypeSelection {
    enabled: bool,
    type_name: &'static str,
}

impl Default for AnalysisEngineConfig {
    fn default() -> Self {
        Self {
            analyser_names: FxHashMap::default(),
            analyser_types: FxHashMap::default(),
            analysers_enabled: true,
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
            lifted_cache_bytes: DEFAULT_LIFTED_CACHE_BYTES,
            registry: IlRegistry::standard().clone(),
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

    pub fn registry(&self) -> &IlRegistry {
        &self.registry
    }

    pub fn set_registry(&mut self, registry: impl Into<Arc<IlRegistry>>) {
        self.registry = registry.into();
    }

    pub fn with_registry(mut self, registry: impl Into<Arc<IlRegistry>>) -> Self {
        self.set_registry(registry);
        self
    }

    fn set_analyser_enabled<T: 'static>(&mut self, enabled: bool) {
        self.analyser_types.insert(
            TypeId::of::<T>(),
            AnalyserTypeSelection {
                enabled,
                type_name: type_name::<T>(),
            },
        );
    }

    fn registry_handle(&self) -> Arc<IlRegistry> {
        self.registry.clone()
    }

    fn analyser_enabled(&self, provider: &AnalyserProvider) -> bool {
        self.analyser_names
            .get(provider.name())
            .copied()
            .or_else(|| {
                self.analyser_types
                    .get(&provider.type_id())
                    .map(|selection| selection.enabled)
            })
            .unwrap_or(self.analysers_enabled)
    }

    pub fn disable_all_analysers(&mut self) {
        self.analyser_names.clear();
        self.analyser_types.clear();
        self.analysers_enabled = false;
    }

    pub fn disable_analyser<T: 'static>(&mut self) {
        self.set_analyser_enabled::<T>(false);
    }

    pub fn disable_named_analyser(&mut self, name: impl Into<SmolStr>) {
        self.analyser_names.insert(name.into(), false);
    }

    pub fn enable_all_analysers(&mut self) {
        self.analyser_names.clear();
        self.analyser_types.clear();
        self.analysers_enabled = true;
    }

    pub fn enable_analyser<T: 'static>(&mut self) {
        self.set_analyser_enabled::<T>(true);
    }

    pub fn enable_named_analyser(&mut self, name: impl Into<SmolStr>) {
        self.analyser_names.insert(name.into(), true);
    }

    fn validate_analysers(&self) -> Result<(), EngineError> {
        let mut names = FxHashSet::default();
        let mut types = FxHashSet::default();

        for provider in extension::iter::<AnalyserProvider>() {
            if !names.insert(provider.name()) {
                return Err(EngineError::DuplicateAnalyserName(provider.name()));
            }
            types.insert(provider.type_id());
        }

        if let Some(selection) = self
            .analyser_types
            .iter()
            .find_map(|(id, selection)| (!types.contains(id)).then_some(selection))
        {
            return Err(EngineError::UnregisteredAnalyserType(selection.type_name));
        }

        if let Some(name) = self
            .analyser_names
            .keys()
            .find(|name| !names.contains(name.as_str()))
        {
            return Err(EngineError::UnregisteredAnalyserName(String::from(
                name.as_str(),
            )));
        }

        Ok(())
    }
}

pub struct AnalysisContext<'a, 'p> {
    pub project: ProjectView<'p>,
    pub updates: ProjectUpdates,
    pub analysis_data: &'a mut AnalysisDataStore,
    causes: SmallVec<[WorkCause; 4]>,
    continuation: bool,
    phase: AnalysisPhase,
    regions: &'a AddressRangeSet,
    worker_limit: usize,
}

impl<'a, 'p> AnalysisContext<'a, 'p> {
    pub fn causes(&self) -> &[WorkCause] {
        &self.causes
    }

    pub fn phase(&self) -> AnalysisPhase {
        self.phase
    }

    pub fn is_continuation(&self) -> bool {
        self.continuation
    }

    pub fn regions(&self) -> &'a AddressRangeSet {
        self.regions
    }

    pub fn worker_limit(&self) -> usize {
        self.worker_limit
    }

    pub fn with_project<R>(
        &mut self,
        project: &mut ProjectView<'p>,
        operation: impl FnOnce(&mut Self) -> R,
    ) -> R {
        mem::swap(&mut self.project, project);
        let result = operation(self);
        mem::swap(&mut self.project, project);
        result
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

    fn analyse(&mut self, context: &mut AnalysisContext<'_, '_>) -> Result<(), AnalysisError>;

    fn produces(&self) -> ChangeKinds {
        ChangeKinds::empty()
    }

    fn analysis_ended(
        &mut self,
        context: &mut AnalysisContext<'_, '_>,
    ) -> Result<(), AnalysisError> {
        let _ = context;
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
    il_input: Option<IlFormId>,
    name: &'static str,
    type_id: TypeId,
}

impl AnalyserProvider {
    pub const fn new<T: Analyser + 'static>(name: &'static str, build: AnalyserBuildFn) -> Self {
        Self {
            build,
            il_input: None,
            name,
            type_id: TypeId::of::<T>(),
        }
    }

    pub const fn for_il<A: IlAnalyser>() -> Self {
        Self {
            build: Self::build_il_analyser::<A>,
            il_input: Some(A::Input::FORM),
            name: A::NAME,
            type_id: TypeId::of::<A>(),
        }
    }

    pub(crate) fn il_input(&self) -> Option<IlFormId> {
        self.il_input.clone()
    }

    pub(crate) fn type_id(&self) -> TypeId {
        self.type_id
    }

    pub fn create(&self, project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
        (self.build)(project)
    }

    fn build_il_analyser<A: IlAnalyser>(
        project: &Project,
    ) -> Result<Box<dyn Analyser>, AnalysisError> {
        Ok(Box::new(scheduler::IlAnalyserAdapter::new(A::build(
            project,
        )?)))
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

extension::collect!(AnalyserProvider);

#[derive(Debug, Error)]
pub enum EngineError {
    #[error(transparent)]
    Analysis(#[from] AnalysisError),
    #[error("duplicate registered analyser name: `{0}`")]
    DuplicateAnalyserName(&'static str),
    #[error("analysis engine poisoned: {0}")]
    Poisoned(String),
    #[error(transparent)]
    Project(#[from] ProjectError),
    #[error("project is retained by a live query reader or project handle")]
    ProjectRetained,
    #[error("analysis engine stopped")]
    Stopped,
    #[error("subscription has no pending changes")]
    SubscriptionEmpty,
    #[error("subscription receive timed out")]
    SubscriptionTimeout,
    #[error("analyser name is not registered: `{0}`")]
    UnregisteredAnalyserName(String),
    #[error("analyser type is not registered: `{0}`")]
    UnregisteredAnalyserType(&'static str),
}

pub struct AnalysisEngine {
    handle: Option<JoinHandle<()>>,
    metrics: EngineMetrics,
    poison: Arc<OnceLock<String>>,
    query_reader: Option<QueryReader>,
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
        config.validate_analysers()?;
        let channel_capacity = config.channel_capacity();
        let (tx, rx) = flume::bounded(channel_capacity);
        let (worker_done_tx, worker_done) = flume::bounded(1);
        let poison = Arc::new(OnceLock::new());
        let project = Arc::new(RwLock::new(project));
        let registry = config.registry_handle();
        let queries = QueryEngine::new(
            project.clone(),
            registry.clone(),
            config.lifted_cache_bytes(),
        );
        let query_reader = queries.reader(tx.clone());
        let worker_poison = poison.clone();
        let worker_state_poison = poison.clone();
        let metrics = EngineMetrics::new();
        let worker_metrics = metrics.clone();
        let handle = Builder::new()
            .name("fugue-analysis".to_owned())
            .spawn(move || {
                let worker = Worker::new(
                    config,
                    project,
                    queries,
                    worker_state_poison,
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
            handle: Some(handle),
            metrics,
            poison,
            query_reader: Some(query_reader),
            tx,
            worker_done,
        })
    }

    pub fn metrics(&self) -> EngineMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn set_data<T>(&self, value: T) -> Result<(), EngineError>
    where
        T: AnalysisData,
    {
        self.poison_check()?;

        let (reply_tx, reply_rx) = flume::bounded(1);
        self.tx
            .send(Intake::SetData {
                data: Box::new(value),
                root: TypeId::of::<T>(),
                reply: reply_tx,
            })
            .map_err(|_| EngineError::Stopped)?;

        self.receive_reply(reply_rx)
    }

    pub fn with_data<T>(self, value: T) -> Result<Self, EngineError>
    where
        T: AnalysisData,
    {
        self.set_data(value)?;
        Ok(self)
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

    fn apply_update(
        &self,
        source: impl Into<ChangeSource>,
        update: ProjectUpdate,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_updates(source, ProjectUpdates::from(update))
    }

    pub fn apply_updates(
        &self,
        source: impl Into<ChangeSource>,
        updates: ProjectUpdates,
    ) -> Result<ChangeSet, EngineError> {
        self.poison_check()?;

        let (reply_tx, reply_rx) = flume::bounded(1);
        self.tx
            .send(Intake::Updates {
                source: source.into(),
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
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::write_bytes(address, bytes),
        )
    }

    pub fn add_symbol(
        &self,
        index: SymbolIndex,
        entry: SymbolEntry,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::add_symbol(index, entry),
        )
    }

    pub fn add_function(&self, function: IncompleteFunction) -> Result<ChangeSet, EngineError> {
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::add_function(function),
        )
    }

    pub fn add_reference(&self, reference: Reference) -> Result<ChangeSet, EngineError> {
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::add_reference(reference),
        )
    }

    pub fn remove_reference(
        &self,
        from: Address,
        target: ReferenceTarget,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::remove_reference(from, target),
        )
    }

    pub fn add_switch(&self, switch: Switch) -> Result<ChangeSet, EngineError> {
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::add_switch(switch),
        )
    }

    pub fn remove_switch(&self, branch: impl Into<Address>) -> Result<ChangeSet, EngineError> {
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::remove_switch(branch),
        )
    }

    pub fn add_mapping_to_space(
        &self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::add_mapping_to_space(space, mapping),
        )
    }

    pub fn add_mapping_to_space_bottom(
        &self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::add_mapping_to_space_bottom(space, mapping),
        )
    }

    pub fn add_mapping_to_space_top(
        &self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::add_mapping_to_space_top(space, mapping),
        )
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
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::deprioritise_mapping(space, mapping),
        )
    }

    pub fn prioritise_mapping(
        &self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::prioritise_mapping(space, mapping),
        )
    }

    pub fn remove_function(&self, entry: Address) -> Result<ChangeSet, EngineError> {
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::remove_asserted_function(entry),
        )
    }

    pub fn remove_function_by_id(&self, id: FunctionId) -> Result<ChangeSet, EngineError> {
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::remove_asserted_function_by_id(id),
        )
    }

    pub fn remap_mapping(
        &self,
        mapping: SegmentMappingId,
        start: Address,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::remap_mapping(mapping, start),
        )
    }

    pub fn remove_mapping(&self, mapping: SegmentMappingId) -> Result<ChangeSet, EngineError> {
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::remove_mapping(mapping),
        )
    }

    pub fn remove_symbol(&self, index: SymbolIndex) -> Result<ChangeSet, EngineError> {
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::remove_symbol(index),
        )
    }

    pub fn resize_mapping(
        &self,
        mapping: SegmentMappingId,
        size: u64,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::resize_mapping(mapping, size),
        )
    }

    pub fn update_mapping_metadata(
        &self,
        update: MappingMetadataUpdate,
    ) -> Result<ChangeSet, EngineError> {
        self.apply_update(
            ChangeSource::engine("update"),
            ProjectUpdate::update_mapping_metadata(update),
        )
    }

    pub fn ensure_lifted(
        &self,
        function: FunctionId,
        form: IlFormId,
    ) -> Result<ChangeSet, EngineError> {
        self.poison_check()?;

        let (reply_tx, reply_rx) = flume::bounded(1);
        self.tx
            .send(Intake::EnsureLifted {
                function,
                form,
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

    pub fn query_reader(&self) -> Result<QueryReader, EngineError> {
        self.poison_check()?;
        self.query_reader
            .as_ref()
            .cloned()
            .ok_or(EngineError::Stopped)
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
            || !self
                .query_reader
                .as_ref()
                .is_some_and(QueryReader::is_active)
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

    fn shutdown(&mut self) -> Result<(), EngineError> {
        if let Some(reader) = &self.query_reader {
            reader.mark_dead();
        }
        let _ = self.tx.send(Intake::Shutdown);

        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .map_err(|_| EngineError::Poisoned("analysis worker panicked".to_owned()))?;
        }

        if let Some(message) = self.poison.get() {
            return Err(EngineError::Poisoned(message.clone()));
        }
        Ok(())
    }

    pub fn into_project(mut self) -> Result<Project, EngineError> {
        self.shutdown()?;

        let project = self
            .query_reader
            .take()
            .ok_or(EngineError::Stopped)?
            .into_project();
        Arc::try_unwrap(project)
            .map(RwLock::into_inner)
            .map_err(|_| EngineError::ProjectRetained)
    }
}

impl Drop for AnalysisEngine {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
