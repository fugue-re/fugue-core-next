use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Debug;
use std::ops::Bound;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, LazyLock, Mutex};
use std::time::Duration;
use std::{io, iter, thread};

use bytes::Bytes;
use fallible_iterator::{FallibleIterator, convert};
use fugue_core::analysis::AnalysisError;
use fugue_core::analysis::control::Cancelled;
use fugue_core::analysis::function::{
    FunctionRecovery, FunctionRecoveryCommitContext, FunctionRecoveryCommitHook,
    FunctionRecoveryError, FunctionRecoveryExtension,
};
use fugue_core::analysis::switch::SwitchRecovery;
use fugue_core::arch::Arch;
use fugue_core::engine::change::{ChangeCategory, ChangeKinds, ChangeRecord};
use fugue_core::engine::{
    Analyser, AnalyserProvider, AnalysisContext, AnalysisEngine, EngineError,
    MappingMetadataUpdate, Priority, ProjectUpdate, ProjectView, Subscription,
};
use fugue_core::extension::{self, Registration};
use fugue_core::il::common::{IlArtefact, IlError};
use fugue_core::il::ecode::ECodeIr;
use fugue_core::il::ecode::ssa::ECodeSsaIr;
use fugue_core::il::pcode::PCodeIr;
use fugue_core::ir::{
    Address, AddressRange, AddressRangeSet, AddressTable, AddressWithContext, Endian, FlowKind,
    ProblemKind, ProblemScope, RawAddress, Reference, ReferenceOrigin, ReferenceProperties,
    ReferenceTarget, SegmentProperties, Switch, SwitchCase, SwitchId, SwitchModel, SymbolEntry,
    SymbolIndex, SymbolProperties, SymbolTableSelector,
};
use fugue_core::lifter::{ContextSet, resolve_language};
use fugue_core::loader::{
    ImageAddress, ImageBacking, ImageBank, ImageBankHandle, ImageLayout, ImageSegment,
    ImageSegmentContents, ImageSegmentContentsIterator, ImageSegmentIterator, ImageSpace,
    ImageSpaceHandle, Loadable, LoadableAnalysers, LoadableMetadata, Loader, LoaderError,
};
use fugue_core::project::{Project, ProjectError};
use fugue_core::queries::{CallEdge, MappingRow, QueryError, QueryPage, SymbolRow};
use fugue_core::storage::{
    BufferedEntityWriter, DEFAULT_SPACE_ID, ENTITY_PROJECT_REVISION_ID, EntityBytesAsIterator,
    EntityBytesIterator, EntityBytesReadTransaction, EntityBytesWriteTransaction,
    EntityKeyBytesIterator, EntityStorage, EntityStorageError, EntityStorageProvider,
    EntityStorageProviderFromLoadable, EntityStorageWriteTransaction, InMemoryEntityStorage,
    InMemorySegmentStorage, PERSISTENT, ProjectEntity, SegmentMappingBuilder, SegmentMappingFlags,
    SegmentMappingKind, SegmentMappingProvenance, SegmentStorage, StorageContainer,
    StoragePersistence, StorageProvider, StorageProviderError, TransientStorageProvider,
};
#[cfg(feature = "sqlite")]
use fugue_core::storage::{
    DefaultPersistentSegmentStorage, PersistentStorageProvider, SqliteEntityStorage,
};
#[cfg(feature = "sqlite")]
use fugue_core::types::ATTRIBUTE_PROJECT_PATH;
use fugue_core::types::{AttributeMap, BytesOrSlice};

mod common;

use common::{one_block_function, writable_address};

const EXPECTED_DEFAULT_WORK_ITEM_MAX_ATTEMPTS: usize = 3;
const TEST_ANALYSER_ATTR: &str = "fugue.test.engine-analyser";
const TEST_CHUNKED_RECOVERY_ATTR: &str = "fugue.test.chunked-recovery";
const TEST_SWITCH_RECOVERY_ATTR: &str = "fugue.test.switch-recovery";
const TEST_WORK_SLICE_BYTES: u64 = 1 << 20;

#[cfg(feature = "sqlite")]
type SqliteProjectProvider =
    PersistentStorageProvider<SqliteEntityStorage<PERSISTENT>, DefaultPersistentSegmentStorage>;

static COMPLETION_ANALYSE_COUNT: AtomicUsize = AtomicUsize::new(0);
static COMPLETION_END_COUNT: AtomicUsize = AtomicUsize::new(0);
static FAIL_ENTITY_COMMITS: AtomicBool = AtomicBool::new(false);
static FAILING_ANALYSER_RUNS: AtomicUsize = AtomicUsize::new(0);
static FAILING_ANALYSER_TEST_LOCK: Mutex<()> = Mutex::new(());
static FAIL_ENTITY_REMOVES: AtomicBool = AtomicBool::new(false);
static PROJECT_REVISION_KEY: LazyLock<Bytes> = LazyLock::new(|| {
    ENTITY_PROJECT_REVISION_ID
        .key_for(&ProjectEntity::Revision)
        .into()
});
static PROJECT_REVISION_INSERTS: AtomicUsize = AtomicUsize::new(0);
static STAGED_FAILURE_TEST_LOCK: Mutex<()> = Mutex::new(());
static STORM_ANALYSER_RUNS: AtomicUsize = AtomicUsize::new(0);

#[derive(Default)]
struct FailingEntityStorage {
    inner: InMemoryEntityStorage,
}

struct DeferredFunctionCommit {
    entry: Address,
}

impl FunctionRecoveryCommitHook for DeferredFunctionCommit {
    fn should_commit(
        &self,
        project: &ProjectView<'_>,
        context: &FunctionRecoveryCommitContext,
    ) -> Result<bool, FunctionRecoveryError> {
        let _ = project;
        Ok(context.function().entry() != self.entry)
    }
}

struct FailingEntityWriter<'a> {
    inner: BufferedEntityWriter<'a, FailingEntityStorage>,
}

impl EntityStorageWriteTransaction for FailingEntityWriter<'_> {
    fn insert(&mut self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        self.inner.insert(key, value)
    }

    fn remove(&mut self, key: &[u8]) -> Result<(), EntityStorageError> {
        self.inner.remove(key)
    }

    fn commit(self: Box<Self>) -> Result<(), EntityStorageError> {
        if FAIL_ENTITY_COMMITS.load(Ordering::SeqCst) {
            return Err(EntityStorageError::backing(io::Error::other(
                "injected entity transaction failure",
            )));
        }

        Box::new(self.inner).commit()
    }
}

impl EntityStorageProviderFromLoadable for FailingEntityStorage {
    fn from_loadable(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self {
            inner: InMemoryEntityStorage::from_loadable(loadable, attributes)?,
        })
    }
}

impl EntityStorageProvider for FailingEntityStorage {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        self.inner.get(key)
    }

    fn get_as<F, T>(&self, key: &[u8], f: F) -> Result<Option<T>, EntityStorageError>
    where
        F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
    {
        self.inner.get_as(key, f)
    }

    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        if key == PROJECT_REVISION_KEY.as_ref() {
            PROJECT_REVISION_INSERTS.fetch_add(1, Ordering::SeqCst);
        }

        self.inner.insert(key, value)
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        if FAIL_ENTITY_REMOVES.load(Ordering::SeqCst) {
            return Err(EntityStorageError::backing(io::Error::other(
                "injected entity removal failure",
            )));
        }

        self.inner.remove(key)
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        self.inner.contains(key)
    }

    fn iter_prefix_keys(
        &self,
        prefix: &[u8],
    ) -> Result<EntityKeyBytesIterator<'_>, EntityStorageError> {
        self.inner.iter_prefix_keys(prefix)
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        self.inner.iter_prefix(prefix)
    }

    fn iter_range(
        &self,
        prefix: &[u8],
        start: Bound<&[u8]>,
    ) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        self.inner.iter_range(prefix, start)
    }

    fn iter_prefix_as<'a, F, T>(
        &'a self,
        prefix: &[u8],
        f: F,
    ) -> Result<EntityBytesAsIterator<'a, T>, EntityStorageError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<T, EntityStorageError> + 'a,
        T: 'a,
    {
        self.inner.iter_prefix_as(prefix, f)
    }

    fn read_transaction(&self) -> Result<EntityBytesReadTransaction, EntityStorageError> {
        Err(EntityStorageError::unsupported_with(
            "failing storage does not support read transactions",
        ))
    }

    fn write_transaction(&self) -> Result<EntityBytesWriteTransaction, EntityStorageError> {
        Ok(Box::new(FailingEntityWriter {
            inner: BufferedEntityWriter::new(self),
        }))
    }

    fn persistence(&self) -> StoragePersistence {
        PERSISTENT
    }
}

struct FailingStorageProvider;

impl StorageProvider for FailingStorageProvider {
    fn from_loadable(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<StorageContainer, StorageProviderError> {
        FAIL_ENTITY_REMOVES.store(false, Ordering::SeqCst);
        FAIL_ENTITY_COMMITS.store(false, Ordering::SeqCst);
        PROJECT_REVISION_INSERTS.store(0, Ordering::SeqCst);

        let entities =
            EntityStorage::new(FailingEntityStorage::from_loadable(loadable, attributes)?);
        let (segments, image_resolution) =
            SegmentStorage::from_loadable::<InMemorySegmentStorage>(loadable, attributes)?
                .into_parts();

        Ok(StorageContainer::from_parts(entities, segments)?
            .with_image_resolution(image_resolution))
    }

    fn from_storage(
        path: impl AsRef<Path>,
        attributes: &mut AttributeMap,
    ) -> Result<StorageContainer, StorageProviderError> {
        let _ = path;
        let _ = attributes;
        Err(StorageProviderError::NotAStandaloneProject)
    }
}

struct FailingTestAnalyser {
    mode: &'static str,
}

impl FailingTestAnalyser {
    fn new(mode: &'static str) -> Self {
        Self { mode }
    }
}

impl Analyser for FailingTestAnalyser {
    fn name(&self) -> &'static str {
        self.mode
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::BYTES_WRITTEN
    }

    fn can_analyse(&self, project: &Project) -> bool {
        project
            .attributes()
            .get_attr::<String>(TEST_ANALYSER_ATTR)
            .as_deref()
            == Some(self.mode)
    }

    fn analyse(
        &mut self,
        project: &ProjectView<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        let _ = project;
        let _ = cx;
        FAILING_ANALYSER_RUNS.fetch_add(1, Ordering::SeqCst);

        if self.mode == "mutating-error"
            && let Some(address) = regions.ranges().next().map(|range| range.start_address())
        {
            updates.push(ProjectUpdate::add_symbol(
                SymbolIndex::new(SymbolTableSelector::new(251), 0),
                SymbolEntry::new(
                    address,
                    "rolled_back_symbol",
                    SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
                ),
            ));
        }

        Err(AnalysisError::pass_failed(
            self.mode,
            io::Error::other("test analyser failed"),
        ))
    }
}

struct PanickingTestAnalyser;

impl Analyser for PanickingTestAnalyser {
    fn name(&self) -> &'static str {
        "panicking-test"
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::BYTES_WRITTEN | ChangeKinds::SYMBOL_ADDED
    }

    fn can_analyse(&self, project: &Project) -> bool {
        project
            .attributes()
            .get_attr::<String>(TEST_ANALYSER_ATTR)
            .as_deref()
            == Some(self.name())
    }

    fn analyse(
        &mut self,
        project: &ProjectView<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        let _ = project;
        let _ = cx;
        if let Some(address) = regions.ranges().next().map(|range| range.start_address()) {
            updates.push(ProjectUpdate::add_symbol(
                SymbolIndex::new(SymbolTableSelector::new(252), 0),
                SymbolEntry::new(
                    address,
                    "panicked_torn_symbol",
                    SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
                ),
            ));
            let target = address
                .checked_add(0x100u64)
                .expect("torn reference target");
            updates.push(ProjectUpdate::add_reference(Reference::data(
                address,
                target,
                ReferenceProperties::READ,
            )));
        }
        panic!("test analyser panic");
    }
}

struct CompletionTestAnalyser {
    address: Option<Address>,
    completed: bool,
}

impl CompletionTestAnalyser {
    fn new() -> Self {
        Self {
            address: None,
            completed: false,
        }
    }
}

impl Analyser for CompletionTestAnalyser {
    fn name(&self) -> &'static str {
        "completion-test"
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::BYTES_WRITTEN
    }

    fn can_analyse(&self, project: &Project) -> bool {
        project
            .attributes()
            .get_attr::<String>(TEST_ANALYSER_ATTR)
            .as_deref()
            == Some(self.name())
    }

    fn analyse(
        &mut self,
        project: &ProjectView<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        let _ = project;
        let _ = updates;
        let _ = cx;
        COMPLETION_ANALYSE_COUNT.fetch_add(1, Ordering::SeqCst);
        self.address = regions.ranges().next().map(|range| range.start_address());
        Ok(())
    }

    fn analysis_ended(
        &mut self,
        project: &ProjectView<'_>,
        cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        let _ = project;
        let _ = cx;
        let Some(address) = self.address.take() else {
            return Ok(());
        };
        COMPLETION_END_COUNT.fetch_add(1, Ordering::SeqCst);

        if self.completed {
            return Ok(());
        }

        self.completed = true;
        updates.push(ProjectUpdate::add_symbol(
            SymbolIndex::new(SymbolTableSelector::new(252), 1),
            SymbolEntry::new(
                address,
                "completion_symbol",
                SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
            ),
        ));
        Ok(())
    }
}

struct PanickingCompletionTestAnalyser;

impl Analyser for PanickingCompletionTestAnalyser {
    fn name(&self) -> &'static str {
        "completion-panic-test"
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::BYTES_WRITTEN
    }

    fn can_analyse(&self, project: &Project) -> bool {
        project
            .attributes()
            .get_attr::<String>(TEST_ANALYSER_ATTR)
            .as_deref()
            == Some(self.name())
    }

    fn analyse(
        &mut self,
        project: &ProjectView<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        let _ = project;
        let _ = updates;
        let _ = regions;
        let _ = cx;
        Ok(())
    }

    fn analysis_ended(
        &mut self,
        project: &ProjectView<'_>,
        cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        let _ = project;
        let _ = updates;
        let _ = cx;
        panic!("test completion panic");
    }
}

struct DerivedSymbolAnalyser {
    next_index: usize,
}

impl DerivedSymbolAnalyser {
    fn new() -> Self {
        Self { next_index: 0 }
    }
}

impl Analyser for DerivedSymbolAnalyser {
    fn name(&self) -> &'static str {
        "derived-symbol"
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::FUNCTION_ADDED
    }

    fn priority(&self) -> Priority {
        Priority::ENRICHMENT
    }

    fn can_analyse(&self, project: &Project) -> bool {
        project
            .attributes()
            .get_attr::<String>(TEST_ANALYSER_ATTR)
            .as_deref()
            == Some(self.name())
    }

    fn analyse(
        &mut self,
        project: &ProjectView<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        let _ = project;
        let _ = cx;

        for range in regions.ranges() {
            let address = range.start_address();
            updates.push(ProjectUpdate::add_symbol(
                SymbolIndex::new(SymbolTableSelector::new(253), self.next_index),
                SymbolEntry::new(
                    address,
                    "derived_function",
                    SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
                ),
            ));
            self.next_index += 1;
        }

        Ok(())
    }
}

struct StormTestAnalyser;

impl Analyser for StormTestAnalyser {
    fn name(&self) -> &'static str {
        "storm-test"
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::BYTES_WRITTEN
    }

    fn can_analyse(&self, project: &Project) -> bool {
        project
            .attributes()
            .get_attr::<String>(TEST_ANALYSER_ATTR)
            .as_deref()
            == Some(self.name())
    }

    fn analyse(
        &mut self,
        project: &ProjectView<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        let _ = project;
        let _ = cx;
        STORM_ANALYSER_RUNS.fetch_add(1, Ordering::SeqCst);

        let Some(address) = regions.ranges().next().map(|range| range.start_address()) else {
            return Ok(());
        };

        updates.push(ProjectUpdate::add_symbol(
            SymbolIndex::new(SymbolTableSelector::new(250), 0),
            SymbolEntry::new(
                address,
                "storm_symbol",
                SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
            ),
        ));
        Ok(())
    }
}

struct CancellingTestAnalyser;

impl Analyser for CancellingTestAnalyser {
    fn name(&self) -> &'static str {
        "cancelling-test"
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::BYTES_WRITTEN
    }

    fn can_analyse(&self, project: &Project) -> bool {
        project
            .attributes()
            .get_attr::<String>(TEST_ANALYSER_ATTR)
            .as_deref()
            == Some(self.name())
    }

    fn analyse(
        &mut self,
        project: &ProjectView<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        let _ = project;
        let _ = cx;
        let Some(address) = regions.ranges().next().map(|range| range.start_address()) else {
            return Err(Cancelled.into());
        };

        updates.push(ProjectUpdate::add_symbol(
            SymbolIndex::new(SymbolTableSelector::new(248), 0),
            SymbolEntry::new(
                address,
                "cancel_committed_symbol",
                SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
            ),
        ));

        Err(Cancelled.into())
    }
}

struct CancellationFollowUpAnalyser;

impl Analyser for CancellationFollowUpAnalyser {
    fn name(&self) -> &'static str {
        "cancellation-follow-up"
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::SYMBOL_ADDED
    }

    fn priority(&self) -> Priority {
        Priority::ENRICHMENT
    }

    fn can_analyse(&self, project: &Project) -> bool {
        project
            .attributes()
            .get_attr::<String>(TEST_ANALYSER_ATTR)
            .as_deref()
            == Some("cancelling-test")
    }

    fn analyse(
        &mut self,
        project: &ProjectView<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        let _ = project;
        let _ = cx;
        let Some(address) = regions.ranges().next().map(|range| range.start_address()) else {
            return Ok(());
        };

        updates.push(ProjectUpdate::add_symbol(
            SymbolIndex::new(SymbolTableSelector::new(248), 1),
            SymbolEntry::new(
                address,
                "cancel_followup_symbol",
                SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
            ),
        ));

        Ok(())
    }
}

fn build_error_analyser(_project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
    Ok(Box::new(FailingTestAnalyser::new("error-test")))
}

fn build_mutating_error_analyser(_project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
    Ok(Box::new(FailingTestAnalyser::new("mutating-error")))
}

fn build_panicking_analyser(_project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
    Ok(Box::new(PanickingTestAnalyser))
}

fn build_completion_analyser(_project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
    Ok(Box::new(CompletionTestAnalyser::new()))
}

fn build_completion_panic_analyser(_project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
    Ok(Box::new(PanickingCompletionTestAnalyser))
}

fn build_derived_symbol_analyser(_project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
    Ok(Box::new(DerivedSymbolAnalyser::new()))
}

fn build_storm_analyser(_project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
    Ok(Box::new(StormTestAnalyser))
}

fn build_cancelling_analyser(_project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
    Ok(Box::new(CancellingTestAnalyser))
}

fn build_cancellation_follow_up_analyser(
    _project: &Project,
) -> Result<Box<dyn Analyser>, AnalysisError> {
    Ok(Box::new(CancellationFollowUpAnalyser))
}

fn configure_test_recovery(
    project: &Project,
    recovery: &mut FunctionRecovery,
) -> Result<(), AnalysisError> {
    if project
        .attributes()
        .get_attr::<bool>(TEST_CHUNKED_RECOVERY_ATTR)
        .unwrap_or(false)
    {
        recovery.set_chunk_function_limit(Some(1));
        recovery.set_chunk_candidate_limit(Some(1));
    }
    if project
        .attributes()
        .get_attr::<bool>(TEST_SWITCH_RECOVERY_ATTR)
        .unwrap_or(false)
    {
        recovery.add_builder_post_structuring_pass("switch-recovery", SwitchRecovery::new());
    }

    Ok(())
}

extension::submit! {
    AnalyserProvider::new("error-test", build_error_analyser)
}

extension::submit! {
    AnalyserProvider::new("mutating-error", build_mutating_error_analyser)
}

extension::submit! {
    AnalyserProvider::new("panicking-test", build_panicking_analyser)
}

extension::submit! {
    AnalyserProvider::new("completion-test", build_completion_analyser)
}

extension::submit! {
    AnalyserProvider::new("completion-panic-test", build_completion_panic_analyser)
}

extension::submit! {
    AnalyserProvider::new("derived-symbol", build_derived_symbol_analyser)
}

extension::submit! {
    AnalyserProvider::new("storm-test", build_storm_analyser)
}

extension::submit! {
    AnalyserProvider::new("cancelling-test", build_cancelling_analyser)
}

extension::submit! {
    AnalyserProvider::new("cancellation-follow-up", build_cancellation_follow_up_analyser)
}

extension::submit! {
    FunctionRecoveryExtension::new("test-recovery", configure_test_recovery)
}

fn project_with_test_analyser(mode: &'static str) -> Result<Project, Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut attributes = AttributeMap::new();
    attributes.set_attr(TEST_ANALYSER_ATTR, mode);
    Ok(Project::new_with_provider::<TransientStorageProvider>(
        &loader, attributes,
    )?)
}

fn project_with_writable_address() -> Result<(Project, Address), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let address = writable_address(&project, 0x20)?;
    Ok((project, address))
}

fn trigger_test_analyser(engine: &AnalysisEngine, address: Address) -> Result<(), Box<dyn Error>> {
    let mut regions = AddressRangeSet::new();
    regions.insert(address);
    engine.schedule_ranges(ChangeKinds::BYTES_WRITTEN, regions)?;
    engine.analyse()?;
    Ok(())
}

fn consume_initial_resynchronisation(
    subscription: &Subscription,
    revision: fugue_core::types::Revision,
) -> Result<(), Box<dyn Error>> {
    let changes = subscription.recv_timeout(Duration::from_secs(1))?;
    assert_eq!(changes.revision(), revision);
    assert_eq!(
        changes.records(),
        &[ChangeRecord::Resynchronise { to: revision }]
    );
    Ok(())
}

fn assert_strict_cursor_pages<T, F>(mut next_page: F) -> Result<Vec<T>, Box<dyn Error>>
where
    T: Copy + Ord + Debug,
    F: FnMut(Option<T>) -> Result<QueryPage<T>, QueryError>,
{
    let mut cursor = None;
    let mut records = Vec::new();

    loop {
        let page = next_page(cursor)?;
        assert!(page.entries().len() <= 1);

        for record in page.entries().iter().copied() {
            if let Some(previous) = records.last() {
                assert!(record > *previous, "page order did not advance");
            }
            records.push(record);
        }

        let Some(next_cursor) = page.next_cursor().copied() else {
            break;
        };

        if let Some(current) = cursor {
            assert!(next_cursor > current, "cursor did not advance");
        }
        cursor = Some(next_cursor);
    }

    Ok(records)
}

#[test]
fn test_engine_startup_reaches_imperative_entry() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;

    let mut imperative = Project::new_transient(&loader)?;
    let Some(entry) = imperative.entry_point() else {
        return Err(io::Error::other("fixture entry missing").into());
    };
    let mut recovery = loader.analysers().function_recovery()?;
    recovery.add_candidate(entry);
    recovery.analyse(&mut imperative)?;

    let imperative_functions = imperative.functions().addresses().collect::<BTreeSet<_>>();
    assert!(imperative_functions.contains(&entry));

    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;
    let changes = engine.subscribe().with_capacity(4096).build()?;
    engine.analyse()?;
    let reader = engine.query_reader()?;
    let mut engine_functions = BTreeSet::new();
    let function_spaces = imperative_functions
        .iter()
        .map(|address| address.space())
        .collect::<BTreeSet<_>>();
    for space in function_spaces {
        let mut cursor = None::<Address>;
        loop {
            let page = reader.function_page(space, cursor, 128)?;
            engine_functions.extend(page.entries().iter().copied());

            let Some(next_cursor) = page.next_cursor().copied() else {
                break;
            };
            cursor = Some(next_cursor);
        }
    }
    let mut journal_functions = BTreeSet::new();

    for changes in changes.try_iter() {
        for record in changes.records() {
            match record {
                ChangeRecord::FunctionAdded { entry, .. } => {
                    journal_functions.insert(*entry);
                }
                ChangeRecord::FunctionRemoved { entry, .. } => {
                    journal_functions.remove(entry);
                }
                ChangeRecord::Resynchronise { .. } => {
                    return Err(io::Error::other("subscriber was forced to resync").into());
                }
                _ => {}
            }
        }
    }

    let flow_graph = reader
        .flow_targets(entry)?
        .ok_or_else(|| io::Error::other("fixture entry flow graph missing"))?;
    let expected_callees = flow_graph
        .targets()
        .iter()
        .filter(|target| target.kind().is_call())
        .map(|target| target.to())
        .collect::<BTreeSet<_>>();
    let callees = reader
        .callee_page(entry, None, 4096)?
        .entries()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let call_edges = reader
        .call_edge_page(None, 4096)?
        .entries()
        .iter()
        .filter(|edge| edge.source() == entry)
        .map(|edge| edge.target())
        .collect::<BTreeSet<_>>();

    assert_eq!(callees, expected_callees);
    assert_eq!(call_edges, expected_callees);
    assert_eq!(engine_functions, imperative_functions);
    assert_eq!(journal_functions, engine_functions);

    Ok(())
}

#[test]
fn test_query_pages_advance_from_cursor() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    let reader = engine.query_reader()?;

    let functions = assert_strict_cursor_pages::<Address, _>(|cursor| {
        reader.function_page(DEFAULT_SPACE_ID, cursor, 1)
    })?;
    assert!(!functions.is_empty());

    let symbols =
        assert_strict_cursor_pages::<SymbolRow, _>(|cursor| reader.symbol_page(cursor, 1))?;
    assert!(!symbols.is_empty());

    let mappings = assert_strict_cursor_pages::<MappingRow, _>(|cursor| {
        reader.mapping_page(DEFAULT_SPACE_ID, cursor, 1)
    })?;
    assert!(!mappings.is_empty());

    Ok(())
}

#[test]
fn test_symbol_pages_handle_shared_address_boundaries() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;
    let address = Address::in_default_space(0x7fff_1234u64);
    let inserted = [
        SymbolEntry::new(address, "z_page_boundary", SymbolProperties::LOCAL),
        SymbolEntry::new(address, "a_page_boundary", SymbolProperties::EXTERN),
        SymbolEntry::new(
            address,
            "m_page_boundary",
            SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
        ),
    ];

    engine.analyse()?;
    for (index, symbol) in inserted.iter().cloned().enumerate() {
        engine.add_symbol(
            SymbolIndex::new(SymbolTableSelector::new(247), index),
            symbol,
        )?;
    }

    let reader = engine.query_reader()?;
    let mut expected = inserted
        .iter()
        .map(|entry| SymbolRow::new(entry.address(), entry.symbol(), entry.properties()))
        .collect::<Vec<_>>();
    expected.sort();

    let symbols_at = assert_strict_cursor_pages::<SymbolRow, _>(|cursor| {
        reader.symbol_page_at(address, cursor, 1)
    })?;
    assert_eq!(symbols_at, expected);

    let symbol_page =
        assert_strict_cursor_pages::<SymbolRow, _>(|cursor| reader.symbol_page(cursor, 1))?;
    let shared_address = symbol_page
        .into_iter()
        .filter(|record| record.address() == address)
        .collect::<Vec<_>>();
    assert_eq!(shared_address, expected);

    Ok(())
}

#[test]
fn test_mapping_pages_handle_overlaid_start_boundaries() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let view = project
        .segments()
        .iter_views(DEFAULT_SPACE_ID)?
        .find(|view| view.size() > 1)
        .ok_or_else(|| io::Error::other("fixture mapping missing"))?;
    let mapping = project
        .segments()
        .mapping(view.mapping_ref().mapping_id())
        .ok_or_else(|| io::Error::other("fixture mapping metadata missing"))?;
    let shared_start = mapping
        .start()
        .checked_add(mapping.size() + 0x4000)
        .ok_or_else(|| io::Error::other("fixture mapping cannot form shared-start page"))?;
    let mapping_offset = mapping.offset();
    let provider_id = mapping.provider_id();
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;

    let first = engine
        .create_mapping(
            SegmentMappingBuilder::new(shared_start, 1, mapping_offset, provider_id)
                .with_properties(SegmentProperties::PERM_READ)
                .with_name("z_page_boundary_mapping"),
        )?
        .mapping();
    let second = engine
        .create_mapping(
            SegmentMappingBuilder::new(shared_start, 1, mapping_offset, provider_id)
                .with_properties(SegmentProperties::PERM_READ | SegmentProperties::PERM_WRITE)
                .with_name("a_page_boundary_mapping"),
        )?
        .mapping();
    let third = engine
        .create_mapping(
            SegmentMappingBuilder::new(shared_start, 1, mapping_offset, provider_id)
                .with_properties(SegmentProperties::PERM_EXECUTE)
                .with_name("m_page_boundary_mapping"),
        )?
        .mapping();

    engine.add_mapping_to_space_top(DEFAULT_SPACE_ID, first)?;
    engine.add_mapping_to_space_top(DEFAULT_SPACE_ID, second)?;
    engine.add_mapping_to_space_top(DEFAULT_SPACE_ID, third)?;

    let _ = (first, second);
    let reader = engine.query_reader()?;

    let mappings = assert_strict_cursor_pages::<MappingRow, _>(|cursor| {
        reader.mapping_page(DEFAULT_SPACE_ID, cursor, 1)
    })?;
    let shared_start_records = mappings
        .into_iter()
        .filter(|record| record.start() == shared_start)
        .collect::<Vec<_>>();
    assert_eq!(shared_start_records.len(), 1);
    assert_eq!(shared_start_records[0].mapping(), third);

    Ok(())
}

#[test]
fn test_byte_chunked_function_recovery_converges() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut unchunked_project = Project::new_transient(&loader)?;
    let mut chunked_project = Project::new_transient(&loader)?;
    let mut unchunked = FunctionRecovery::new();
    let mut chunked = FunctionRecovery::new();
    let mut extensions = extension::iter::<FunctionRecoveryExtension>().collect::<Vec<_>>();
    extensions.sort_unstable_by_key(|extension| (extension.priority(), extension.name()));
    for extension in extensions {
        extension.apply(&unchunked_project, &mut unchunked)?;
        extension.apply(&chunked_project, &mut chunked)?;
    }

    chunked.set_chunk_output_byte_limit(Some(1));

    unchunked.analyse(&mut unchunked_project)?;

    let mut chunks = 0usize;
    loop {
        chunks += 1;
        assert!(
            chunks <= 4096,
            "chunked recovery did not consume its queued candidates"
        );
        chunked.analyse(&mut chunked_project)?;

        if !Analyser::has_pending_work(&chunked) {
            break;
        }
    }
    assert!(chunks > 1, "the chunk limit did not yield partial work");

    let unchunked_functions = unchunked_project
        .functions()
        .addresses()
        .collect::<BTreeSet<_>>();
    let chunked_functions = chunked_project
        .functions()
        .addresses()
        .collect::<BTreeSet<_>>();
    let function_blocks = |project: &Project| {
        project
            .functions()
            .iter()
            .map(|function| {
                (
                    function.entry(),
                    function
                        .blocks()
                        .map(|(address, _)| address)
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };

    assert_eq!(chunked_functions, unchunked_functions);

    let chunked_blocks = function_blocks(&chunked_project);
    let unchunked_blocks = function_blocks(&unchunked_project);
    let difference = chunked_blocks.iter().find_map(|(&entry, blocks)| {
        let unchunked = unchunked_blocks.get(&entry)?;
        if blocks == unchunked {
            return None;
        }
        let chunked_only = blocks
            .iter()
            .find(|address| unchunked.binary_search(address).is_err())
            .copied();
        let unchunked_only = unchunked
            .iter()
            .find(|address| blocks.binary_search(address).is_err())
            .copied();
        Some((
            entry,
            blocks.len(),
            unchunked.len(),
            chunked_only,
            chunked_only.is_some_and(|address| chunked_functions.contains(&address)),
            unchunked_only,
            unchunked_only.is_some_and(|address| unchunked_functions.contains(&address)),
        ))
    });
    assert!(
        difference.is_none(),
        "chunked recovery differs at {difference:?}"
    );

    Ok(())
}

#[test]
fn test_recovery_requires_executable_cause_start() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut project = Project::new_transient(&loader)?;
    let view = project
        .segments()
        .iter_views(DEFAULT_SPACE_ID)?
        .find(|view| view.properties().is_writable() && view.size() >= 2)
        .ok_or_else(|| io::Error::other("fixture writable mapping missing"))?;
    let mapping = project
        .segments()
        .mapping(view.mapping_ref().mapping_id())
        .ok_or_else(|| io::Error::other("fixture mapping metadata missing"))?;
    let boundary = Address::in_default_space(0x7000_0000u64);
    let data = boundary
        .checked_add(0x1000u64)
        .ok_or_else(|| io::Error::other("test data address overflow"))?;
    let provider_id = mapping.provider_id();
    let provider_offset = mapping.to_offset(view.start());

    {
        let mut transaction = project.transaction("test");
        let executable = transaction.create_mapping(
            SegmentMappingBuilder::new(boundary, 1, provider_offset, provider_id).with_properties(
                SegmentProperties::PERM_READ
                    | SegmentProperties::PERM_WRITE
                    | SegmentProperties::PERM_EXECUTE,
            ),
        )?;
        let non_executable = transaction.create_mapping(
            SegmentMappingBuilder::new(data, 1, provider_offset + 1, provider_id)
                .with_properties(SegmentProperties::PERM_READ | SegmentProperties::PERM_WRITE),
        )?;
        transaction.add_mapping_to_space_top(DEFAULT_SPACE_ID, executable)?;
        transaction.add_mapping_to_space_top(DEFAULT_SPACE_ID, non_executable)?;
        transaction.commit()?;
    }
    {
        let mut transaction = project.transaction("test");
        transaction.write_bytes(boundary, &[0xc3])?;
        transaction.write_bytes(data, &[0xc3])?;
        transaction.commit()?;
    }

    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;
    assert!(engine.query_reader()?.function_id_at(boundary)?.is_none());
    assert!(engine.query_reader()?.function_id_at(data)?.is_none());

    let mut boundary_region = AddressRangeSet::new();
    boundary_region.insert_range(AddressRange::new(
        DEFAULT_SPACE_ID,
        boundary.raw_address() - TEST_WORK_SLICE_BYTES,
        boundary.raw_address(),
    ));
    engine.schedule_ranges(ChangeKinds::BYTES_WRITTEN, boundary_region)?;
    engine.analyse()?;
    assert!(engine.query_reader()?.function_id_at(boundary)?.is_none());

    let mut data_region = AddressRangeSet::new();
    data_region.insert(data);
    engine.schedule_ranges(ChangeKinds::BYTES_WRITTEN, data_region)?;
    engine.analyse()?;
    assert!(engine.query_reader()?.function_id_at(data)?.is_none());

    Ok(())
}

#[test]
fn test_function_boundary_retraction_reconciles_callers() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut project = Project::new_transient(&loader)?;
    let mut recovery = FunctionRecovery::new();
    recovery.analyse(&mut project)?;

    let (caller, source, target) = project
        .functions()
        .iter()
        .find_map(|function| {
            function
                .flow_targets(project.blocks())
                .find(|target| {
                    target.kind() == FlowKind::TailCallBranch
                        && project
                            .segments()
                            .view_containing(target.from())
                            .is_ok_and(|view| view.contains(target.to()))
                })
                .map(|target| (function.entry(), target.from(), target.to()))
        })
        .ok_or_else(|| io::Error::other("no recovered tail-call boundary"))?;
    let function = project
        .functions()
        .get_by_address(caller)
        .ok_or_else(|| io::Error::other("tail-call owner missing"))?;
    assert_eq!(
        function
            .flow_targets(project.blocks())
            .filter(|flow| flow.from() == source && flow.to() == target)
            .map(|flow| flow.kind())
            .collect::<Vec<_>>(),
        vec![FlowKind::TailCallBranch],
    );
    drop(function);

    {
        let mut transaction = project.transaction("test");
        assert!(transaction.remove_function(target, ReferenceOrigin::Derived)?);
        transaction.commit()?;
    }
    assert!(project.functions().get_by_address(target).is_none());
    recovery.set_commit_hook(DeferredFunctionCommit { entry: target });
    recovery.config_mut().enable_commit_pending_functions(false);
    recovery.add_candidate(target);
    recovery.analyse(&mut project)?;

    assert!(project.functions().get_by_address(target).is_none());
    let function = project
        .functions()
        .get_by_address(caller)
        .ok_or_else(|| io::Error::other("caller removed during boundary reconciliation"))?;
    assert!(function.blocks_at(target).next().is_some());
    assert!(
        !function
            .flow_targets(project.blocks())
            .any(|flow| flow.kind() == FlowKind::TailCallBranch && flow.to() == target)
    );
    drop(function);

    recovery.config_mut().enable_commit_pending_functions(true);
    recovery.analyse(&mut project)?;

    assert!(project.functions().get_by_address(target).is_some());
    let function = project
        .functions()
        .get_by_address(caller)
        .ok_or_else(|| io::Error::other("caller missing after boundary restoration"))?;
    assert_eq!(
        function
            .flow_targets(project.blocks())
            .filter(|flow| flow.from() == source && flow.to() == target)
            .map(|flow| flow.kind())
            .collect::<Vec<_>>(),
        vec![FlowKind::TailCallBranch],
    );

    Ok(())
}

#[test]
fn test_function_boundary_addition_splits_containing_block() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut project = Project::new_transient(&loader)?;
    let mut recovery = FunctionRecovery::new();
    recovery.analyse(&mut project)?;
    let mut disassembler = project.arch().disassembler();
    let mut lifter = project.lifter();

    let (owner, boundary) = project
        .functions()
        .iter()
        .find_map(|function| {
            function.blocks().find_map(|(_, id)| {
                let block = project.blocks().get_by_id(id)?;
                block.context().apply(block.address(), lifter.context_mut());
                let view = project.segments().view_containing(block.address()).ok()?;
                let bytes = view.bytes_from(block.address())?;
                let bytes = bytes.as_contiguous()?;
                let first = disassembler
                    .disassemble(block.address(), bytes, lifter.context_mut())
                    .ok()?;
                let boundary = first.next_address();
                if boundary >= block.next_address() {
                    return None;
                }
                (project.functions().get_by_address(boundary).is_none())
                    .then_some((function.entry(), boundary))
            })
        })
        .ok_or_else(|| io::Error::other("no block contains a usable interior boundary"))?;

    recovery.add_candidate(boundary);
    recovery.analyse(&mut project)?;

    assert!(project.functions().get_by_address(boundary).is_some());
    let owner = project
        .functions()
        .get_by_address(owner)
        .ok_or_else(|| io::Error::other("containing function removed during reconciliation"))?;
    assert!(!owner.blocks().any(|(_, id)| {
        project
            .blocks()
            .get_by_id(id)
            .is_some_and(|block| block.range().contains(&boundary))
    }));

    Ok(())
}

#[test]
fn test_function_recovery_bounds_candidate_instructions() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut project = Project::new_transient(&loader)?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let mut recovery = FunctionRecovery::new();
    let config = recovery.config_mut();
    config.enable_segment_function_hints(false);
    config.enable_symbol_table_function_hints(false);
    config.set_max_function_insns(1);

    recovery.analyse(&mut project)?;

    assert!(project.functions().is_empty());
    assert!(
        project
            .problems()
            .get(entry, ProblemKind::FunctionTooLarge)
            .is_some()
    );

    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn test_chunked_function_recovery_converges_after_reopen() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("chunked-recovery.fdbz");
    let fixture = "tests/ls.elf";
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path);
    let mut project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        fixture,
        attributes.clone(),
    )?;
    let mut recovery = FunctionRecovery::new();
    let config = recovery.config_mut();
    config.enable_segment_function_hints(false);
    config.enable_symbol_table_function_hints(false);
    recovery.set_chunk_function_limit(Some(1));

    recovery.analyse(&mut project)?;
    assert!(Analyser::has_pending_work(&recovery));
    let partial_function_count = project.functions().len();
    assert!(partial_function_count > 0);
    drop(project);

    let mut reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        fixture, attributes,
    )?;
    let mut resumed = FunctionRecovery::new();
    let config = resumed.config_mut();
    config.enable_segment_function_hints(false);
    config.enable_symbol_table_function_hints(false);
    resumed.analyse(&mut reopened)?;
    assert!(!Analyser::has_pending_work(&resumed));

    let loader = Loader::from_file(fixture)?;
    let mut clean = Project::new_transient(&loader)?;
    let mut clean_recovery = FunctionRecovery::new();
    let config = clean_recovery.config_mut();
    config.enable_segment_function_hints(false);
    config.enable_symbol_table_function_hints(false);
    clean_recovery.analyse(&mut clean)?;

    assert!(clean.functions().len() > 1);
    assert!(partial_function_count < clean.functions().len());
    let reopened_functions = reopened.functions().addresses().collect::<BTreeSet<_>>();
    let clean_functions = clean.functions().addresses().collect::<BTreeSet<_>>();
    let missing = clean_functions
        .difference(&reopened_functions)
        .take(8)
        .copied()
        .collect::<Vec<_>>();
    let unexpected = reopened_functions
        .difference(&clean_functions)
        .take(8)
        .copied()
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty() && unexpected.is_empty(),
        "resumed recovery diverged: {} reopened functions, {} clean functions, \
         first missing {missing:?}, first unexpected {unexpected:?}",
        reopened_functions.len(),
        clean_functions.len(),
    );

    Ok(())
}

#[test]
fn test_reader_observes_progress_during_chunked_function_recovery() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut attributes = AttributeMap::new();
    attributes.set_attr(TEST_CHUNKED_RECOVERY_ATTR, true);
    let project = Project::new_with_provider::<TransientStorageProvider>(&loader, attributes)?;
    let engine = AnalysisEngine::new(project)?;
    let reader = engine.query_reader()?;
    let running = Arc::new(AtomicBool::new(true));
    let started = Arc::new(Barrier::new(2));
    let observed = Arc::new(Mutex::new(Vec::new()));

    thread::scope(|scope| -> Result<(), Box<dyn Error>> {
        let reader_running = running.clone();
        let reader_started = started.clone();
        let observed = observed.clone();
        let handle = scope.spawn(move || -> Result<(), QueryError> {
            reader_started.wait();
            let mut last = None;
            while reader_running.load(Ordering::Acquire) {
                let revision = reader.revision()?;
                if last != Some(revision) {
                    observed
                        .lock()
                        .expect("observed revisions lock poisoned")
                        .push(revision);
                    last = Some(revision);
                }
                thread::yield_now();
            }
            Ok(())
        });

        started.wait();
        engine.analyse()?;
        running.store(false, Ordering::Release);
        handle
            .join()
            .map_err(|_| io::Error::other("reader thread panicked"))??;

        Ok(())
    })?;

    let observed = observed.lock().expect("observed revisions lock poisoned");
    assert!(
        observed.len() >= 2,
        "reader did not observe multiple committed revisions during chunked recovery: {observed:?}"
    );

    Ok(())
}

#[test]
fn test_query_reader_reports_stopped_after_engine_drop() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;
    let reader = engine.query_reader()?;

    engine.analyse()?;
    assert!(reader.revision().is_ok());

    drop(engine);

    assert!(matches!(reader.revision(), Err(QueryError::Stopped)));

    Ok(())
}

#[test]
fn test_query_readers_remain_available_during_concurrent_analysis() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;

    let reader = engine.query_reader()?;
    let baseline_revision = reader.revision()?;
    let running = Arc::new(AtomicBool::new(true));
    let start = Arc::new(Barrier::new(5));

    thread::scope(|scope| -> Result<(), Box<dyn Error>> {
        let mut readers = Vec::new();
        for _ in 0..4 {
            let reader = reader.clone();
            let running = running.clone();
            let start = start.clone();
            readers.push(scope.spawn(move || -> Result<(), QueryError> {
                start.wait();
                let mut last = reader.revision()?;
                while running.load(Ordering::Acquire) {
                    let revision = reader.revision()?;
                    assert!(revision >= last);
                    last = revision;
                    let page = reader.function_page(DEFAULT_SPACE_ID, None, 16)?;
                    assert!(page.entries().len() <= 16);
                }
                Ok(())
            }));
        }

        start.wait();
        for index in 0..64 {
            let address = Address::in_default_space(0x7100_0000u64 + index as u64);
            let symbol = SymbolEntry::new(
                address,
                format!("concurrent_query_symbol_{index}"),
                SymbolProperties::LOCAL,
            );
            engine.add_symbol(
                SymbolIndex::new(SymbolTableSelector::new(246), index),
                symbol,
            )?;
        }
        running.store(false, Ordering::Release);

        for reader in readers {
            reader
                .join()
                .map_err(|_| io::Error::other("reader thread panicked"))??;
        }

        Ok(())
    })?;

    assert!(reader.revision()? > baseline_revision);

    Ok(())
}

#[test]
fn test_engine_startup_uses_segment_function_hints() -> Result<(), Box<dyn Error>> {
    struct HintLoader {
        arch: Arch,
        attributes: AttributeMap,
        layout: ImageLayout,
        metadata: LoadableMetadata,
    }

    impl Loadable for HintLoader {
        fn attributes(&self) -> &AttributeMap {
            &self.attributes
        }

        fn attributes_mut(&mut self) -> &mut AttributeMap {
            &mut self.attributes
        }

        fn metadata(&self) -> &LoadableMetadata {
            &self.metadata
        }

        fn architecture(&self) -> Arch {
            self.arch.clone()
        }

        fn image_layout(&self) -> &ImageLayout {
            &self.layout
        }

        fn image_segments<'a>(
            &'a self,
        ) -> impl FallibleIterator<Item = ImageSegment<'a>, Error = LoaderError> + 'a {
            let segment = ImageSegment::new(
                "hint",
                ImageAddress::in_default_space(0x1000u64),
                1,
                SegmentProperties::PERM_ALL,
            )
            .with_backing(ImageBacking::in_default_bank(0u64));

            Box::new(convert(iter::once(Ok(segment)))) as ImageSegmentIterator<'a>
        }

        fn image_contents<'a>(
            &'a self,
        ) -> impl FallibleIterator<Item = ImageSegmentContents<'a>, Error = LoaderError> + 'a
        {
            let mut contents = ImageSegmentContents::new(0x1000u64, Endian::Little, vec![0xc3u8]);
            contents.add_function_hint(0x1000u64);

            Box::new(convert(iter::once(Ok(contents)))) as ImageSegmentContentsIterator<'a>
        }
    }

    let layout = ImageLayout::new(
        vec![ImageBank::new(
            ImageBankHandle::default(),
            RawAddress::from(0x1000u64)..=RawAddress::from(0x1000u64),
        )],
        vec![ImageSpace::base(ImageSpaceHandle::default())],
    );
    let loader = HintLoader {
        arch: Arch::new(resolve_language("x86:LE:64")?),
        attributes: AttributeMap::new(),
        layout,
        metadata: LoadableMetadata::new([0xc3u8], "hint-loader"),
    };
    let project = Project::new_transient(&loader)?;

    assert!(project.entry_point().is_none());

    let hint = Address::in_default_space(0x1000u64);
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;
    let reader = engine.query_reader()?;

    assert!(
        reader
            .function_page(DEFAULT_SPACE_ID, None, 16)?
            .entries()
            .contains(&hint)
    );

    Ok(())
}

#[test]
fn test_function_recovery_cancel_before_seeding_leaves_project_unchanged()
-> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut project = Project::new_transient(&loader)?;
    let revision = project.revision();
    let mut recovery = loader.analysers().function_recovery()?;
    let cancellation = recovery.cancellation_token();

    cancellation.cancel();
    recovery.set_cancellation_token(cancellation);

    let error = recovery
        .analyse(&mut project)
        .expect_err("cancelled recovery should fail");

    assert!(matches!(error, AnalysisError::Cancelled(_)));
    assert_eq!(project.revision(), revision);
    assert!(project.functions().is_empty());

    Ok(())
}

#[test]
fn test_engine_write_bytes_materialises_change() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let address = writable_address(&project, 1)?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    let reader = engine.query_reader()?;
    let revision = reader.revision()?;
    let changes = engine.subscribe().with_capacity(16).build()?;
    consume_initial_resynchronisation(&changes, revision)?;

    let written = engine.write_bytes(address, [0xcc])?;

    assert!(written.revision() > revision);
    assert!(written.records().contains(&ChangeRecord::BytesWritten {
        range: AddressRange::new(
            address.space(),
            address.raw_address(),
            address.raw_address()
        ),
    }));

    let delivered = changes.recv_timeout(Duration::from_secs(1))?;
    assert_eq!(&*delivered, &written);

    Ok(())
}

#[test]
fn test_engine_applies_update_batch_in_one_revision() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?
        + 0x10_0000u64;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;
    let revision = engine.query_reader()?.revision()?;

    let changes = engine.apply_updates(vec![
        ProjectUpdate::add_function(one_block_function(entry, 1)),
        ProjectUpdate::add_function(one_block_function(entry + 0x10u64, 1)),
    ])?;

    assert_eq!(
        changes
            .records()
            .iter()
            .filter(|record| matches!(record, ChangeRecord::FunctionAdded { .. }))
            .count(),
        2
    );
    assert_eq!(changes.revision().value(), revision.value() + 1);
    engine.analyse()?;

    Ok(())
}

#[test]
fn test_oversized_update_batch_resynchronises_and_records_degradation() -> Result<(), Box<dyn Error>>
{
    let project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let updates = (0..8193)
        .map(|index| {
            ProjectUpdate::add_problem(
                Address::in_default_space(0x1000_0000u64 + index as u64),
                ProblemKind::DecodeFailed,
            )
        })
        .collect::<Vec<_>>();
    let changes = engine.apply_updates(updates)?;
    assert_eq!(
        changes.records(),
        [ChangeRecord::Resynchronise {
            to: changes.revision()
        }]
    );

    engine.analyse()?;
    let diagnostic = engine
        .query_reader()?
        .problems()
        .find_map(|row| match row {
            Ok(row)
                if row.kind() == ProblemKind::ChangeIndexCollapsed
                    && row.scope() == ProblemScope::Global =>
            {
                Some(Ok(()))
            }
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .transpose()?;
    assert!(
        diagnostic.is_some(),
        "collapsing transaction change detail must remain observable"
    );

    Ok(())
}

#[test]
fn test_engine_ensure_lifted_materialises_requested_chain() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let function = {
        let reader = engine.query_reader()?;
        reader
            .function_id_at(entry)?
            .ok_or_else(|| io::Error::other("function ID missing after add"))?
    };

    let ensured = engine.ensure_lifted(function, PCodeIr::FORM)?;
    assert!(
        ensured
            .records()
            .contains(&ChangeRecord::LiftedMaterialised {
                function,
                form: PCodeIr::FORM,
            })
    );
    assert!(!ensured.records().iter().any(|record| matches!(
        record,
        ChangeRecord::LiftedMaterialised { form, .. }
            if form == &ECodeIr::FORM || form == &ECodeSsaIr::FORM
    )));

    let ensured = engine.ensure_lifted(function, ECodeSsaIr::FORM)?;

    for form in [ECodeIr::FORM, ECodeSsaIr::FORM] {
        assert!(
            ensured
                .records()
                .contains(&ChangeRecord::LiftedMaterialised { function, form })
        );
    }
    assert!(
        !ensured
            .records()
            .contains(&ChangeRecord::LiftedMaterialised {
                function,
                form: PCodeIr::FORM,
            })
    );

    let reader = engine.query_reader()?;
    assert!(reader.ecode(function)?.is_some());
    let ssa = reader
        .ecode_ssa(function)?
        .ok_or_else(|| io::Error::other("LIR SSA missing after ensure_lifted"))?;
    assert_eq!(ssa.metadata().function(), function);

    let ensured = engine.ensure_lifted(function, ECodeSsaIr::FORM)?;
    assert!(ensured.records().is_empty());

    Ok(())
}

#[test]
fn test_engine_ensure_lifted_cancelled_is_rejected_without_materialising()
-> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let reader = engine.query_reader()?;
    let function = reader
        .function_id_at(entry)?
        .ok_or_else(|| io::Error::other("function ID missing after add"))?;
    let revision = reader.revision()?;

    let cancellation = engine.cancellation_token();
    cancellation.cancel();

    assert!(matches!(
        engine.ensure_lifted(function, ECodeSsaIr::FORM),
        Err(EngineError::Project(ProjectError::Il(IlError::Cancelled)))
    ));

    let reader = engine.query_reader()?;
    assert_eq!(reader.revision()?, revision);
    let snapshot = reader.project()?;
    assert!(snapshot.pcode(function)?.is_none());
    assert!(snapshot.ecode(function)?.is_none());
    assert!(snapshot.ecode_ssa(function)?.is_none());
    drop(snapshot);

    cancellation.clear();
    let ensured = engine.ensure_lifted(function, ECodeSsaIr::FORM)?;
    for form in [PCodeIr::FORM, ECodeIr::FORM, ECodeSsaIr::FORM] {
        assert!(
            ensured
                .records()
                .contains(&ChangeRecord::LiftedMaterialised { function, form })
        );
    }
    assert!(engine.query_reader()?.ecode_ssa(function)?.is_some());

    Ok(())
}

#[test]
fn test_query_reader_lifted_reads_build_on_miss() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let reader = engine.query_reader()?;
    let function = reader
        .function_id_at(entry)?
        .ok_or_else(|| io::Error::other("function ID missing after add"))?;

    assert!(reader.project()?.pcode(function)?.is_none());

    assert!(reader.pcode(function)?.is_some());
    assert!(reader.project()?.pcode(function)?.is_none());

    assert!(reader.ecode_ssa(function)?.is_some());
    assert!(reader.project()?.ecode(function)?.is_none());
    assert!(reader.project()?.ecode_ssa(function)?.is_none());

    Ok(())
}

#[test]
fn engine_pcode_materialisation_is_idempotent() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let function = {
        let reader = engine.query_reader()?;
        reader
            .function_id_at(entry)?
            .ok_or_else(|| io::Error::other("function ID missing after add"))?
    };

    engine.ensure_lifted(function, PCodeIr::FORM)?;
    let changes = engine.ensure_lifted(function, PCodeIr::FORM)?;
    assert!(!changes.records().iter().any(|record| matches!(
        record,
        ChangeRecord::LiftedMaterialised { .. } | ChangeRecord::ReferencesChanged { .. }
    )));

    Ok(())
}

#[test]
fn test_engine_partial_write_rolls_back_without_materialising() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let address = project
        .segments()
        .iter_views(DEFAULT_SPACE_ID)?
        .filter(|view| view.properties().is_writable())
        .max_by_key(|view| view.last())
        .map(|view| view.last())
        .ok_or_else(|| io::Error::other("fixture writable segment missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    let changes = engine.subscribe().with_capacity(16).build()?;
    consume_initial_resynchronisation(&changes, engine.query_reader()?.revision()?)?;

    assert!(engine.write_bytes(address, [0xcc, 0xdd]).is_err());
    assert!(changes.recv_timeout(Duration::from_millis(100)).is_err());

    Ok(())
}

#[test]
fn test_engine_symbol_edits_materialise_changes() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    let reader = engine.query_reader()?;
    let revision = reader.revision()?;
    let changes = engine.subscribe().with_capacity(16).build()?;
    consume_initial_resynchronisation(&changes, revision)?;
    let index = SymbolIndex::new(SymbolTableSelector::new(250), 0);
    let symbol = SymbolEntry::new(
        entry,
        "engine_symbol_edit",
        SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
    );

    let inserted = engine.add_symbol(index, symbol.clone())?;

    assert!(inserted.revision() > revision);
    assert!(inserted.records().contains(&ChangeRecord::SymbolAdded {
        address: entry,
        symbol: symbol.symbol(),
    }));
    assert_eq!(&*changes.recv_timeout(Duration::from_secs(1))?, &inserted);
    assert!(
        reader
            .symbol_page_at(entry, None, 16)?
            .entries()
            .iter()
            .any(|record| record.symbol() == symbol.symbol())
    );

    let removed = engine.remove_symbol(index)?;

    assert!(removed.revision() > inserted.revision());
    assert!(removed.records().contains(&ChangeRecord::SymbolRemoved {
        address: entry,
        symbol: symbol.symbol(),
    }));
    assert_eq!(&*changes.recv_timeout(Duration::from_secs(1))?, &removed);
    assert!(
        !reader
            .symbol_page_at(entry, None, 16)?
            .entries()
            .iter()
            .any(|record| record.symbol() == symbol.symbol())
    );

    Ok(())
}

#[test]
fn test_engine_symbol_replacement_materialises_removed_and_added() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let old_entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let new_entry = old_entry
        .checked_add(0x40u64)
        .ok_or_else(|| io::Error::other("replacement symbol address overflow"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    let index = SymbolIndex::new(SymbolTableSelector::new(245), 0);
    let old_symbol = SymbolEntry::new(
        old_entry,
        "engine_symbol_replace_old",
        SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
    );
    let new_symbol = SymbolEntry::new(
        new_entry,
        "engine_symbol_replace_new",
        SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
    );

    engine.add_symbol(index, old_symbol.clone())?;
    let replaced = engine.add_symbol(index, new_symbol.clone())?;

    assert!(replaced.records().contains(&ChangeRecord::SymbolRemoved {
        address: old_entry,
        symbol: old_symbol.symbol(),
    }));
    assert!(replaced.records().contains(&ChangeRecord::SymbolAdded {
        address: new_entry,
        symbol: new_symbol.symbol(),
    }));

    let reader = engine.query_reader()?;
    assert!(
        !reader
            .symbol_page_at(old_entry, None, 16)?
            .entries()
            .iter()
            .any(|record| record.symbol() == old_symbol.symbol())
    );
    assert!(
        reader
            .symbol_page_at(new_entry, None, 16)?
            .entries()
            .iter()
            .any(|record| record.symbol() == new_symbol.symbol())
    );

    Ok(())
}

#[test]
fn test_engine_remove_function_updates_queries() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    let reader = engine.query_reader()?;
    let changes = engine.subscribe().with_capacity(16).build()?;
    consume_initial_resynchronisation(&changes, reader.revision()?)?;
    assert!(reader.flow_targets(entry)?.is_some());

    let removed = engine.remove_function(entry)?;

    assert!(removed.records().iter().any(|record| matches!(
        record,
        ChangeRecord::FunctionRemoved { entry: removed_entry, .. } if *removed_entry == entry
    )));
    assert_eq!(&*changes.recv_timeout(Duration::from_secs(1))?, &removed);
    assert!(reader.flow_targets(entry)?.is_none());
    assert!(
        !reader
            .function_page(DEFAULT_SPACE_ID, None, 4096)?
            .entries()
            .contains(&entry)
    );
    assert!(reader.callee_page(entry, None, 4096)?.entries().is_empty());
    assert!(
        !reader
            .call_edge_page(None, 4096)?
            .entries()
            .iter()
            .any(|edge| edge.source() == entry)
    );

    let added = engine.add_function(one_block_function(entry, 1))?;

    assert!(added.records().iter().any(|record| matches!(
        record,
        ChangeRecord::FunctionAdded { entry: added_entry, .. } if *added_entry == entry
    )));
    assert_eq!(&*changes.recv_timeout(Duration::from_secs(1))?, &added);
    assert!(reader.flow_targets(entry)?.is_some());
    assert!(
        reader
            .function_page(DEFAULT_SPACE_ID, None, 4096)?
            .entries()
            .contains(&entry)
    );
    assert!(reader.callee_page(entry, None, 4096)?.entries().is_empty());

    Ok(())
}

#[test]
fn test_removing_callee_preserves_dangling_caller_edge() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    let reader = engine.query_reader()?;

    let functions = assert_strict_cursor_pages::<Address, _>(|cursor| {
        reader.function_page(DEFAULT_SPACE_ID, cursor, 1)
    })?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let edges =
        assert_strict_cursor_pages::<CallEdge, _>(|cursor| reader.call_edge_page(cursor, 1))?;
    let edge = edges
        .iter()
        .copied()
        .find(|edge| {
            edge.source() != edge.target()
                && functions.contains(&edge.source())
                && functions.contains(&edge.target())
        })
        .ok_or_else(|| io::Error::other("fixture has no live non-recursive call edge"))?;

    let removed = engine.remove_function(edge.target())?;

    assert!(removed.records().iter().any(|record| matches!(
        record,
        ChangeRecord::FunctionRemoved { entry, .. } if *entry == edge.target()
    )));
    engine.analyse()?;

    let functions_after = assert_strict_cursor_pages::<Address, _>(|cursor| {
        reader.function_page(DEFAULT_SPACE_ID, cursor, 1)
    })?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let callers_after =
        assert_strict_cursor_pages(|cursor| reader.caller_page(edge.target(), cursor, 1))?;
    let edges_after =
        assert_strict_cursor_pages::<CallEdge, _>(|cursor| reader.call_edge_page(cursor, 1))?;

    assert!(!functions_after.contains(&edge.target()));
    assert!(callers_after.contains(&edge.source()));
    assert!(edges_after.contains(&edge));

    Ok(())
}

#[test]
fn test_engine_mapping_edits_materialise_changes() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let view = project
        .segments()
        .iter_views(DEFAULT_SPACE_ID)?
        .find(|view| view.size() > 1)
        .ok_or_else(|| io::Error::other("fixture mapping missing"))?;
    let mapping_id = view.mapping_ref().mapping_id();
    let mapping = project
        .segments()
        .mapping(mapping_id)
        .ok_or_else(|| io::Error::other("fixture mapping metadata missing"))?;
    let mapping_offset = mapping.offset();
    let mapping_properties = mapping.properties();
    let provider_id = mapping.provider_id();
    let old_start = mapping.start();
    let old_size = mapping.size();
    let old_range = (mapping.start().raw_address(), mapping.last().raw_address());
    let new_start = old_start
        .checked_add(old_size + 0x1000)
        .ok_or_else(|| io::Error::other("fixture mapping cannot be safely remapped"))?;
    let remapped_last = new_start
        .checked_add(old_size - 1)
        .ok_or_else(|| io::Error::other("fixture mapping cannot be safely remapped"))?;
    let remapped_range = (new_start.raw_address(), remapped_last.raw_address());
    let resized_size = old_size - 1;
    let resized_last = new_start
        .checked_add(resized_size - 1)
        .ok_or_else(|| io::Error::other("fixture mapping cannot be safely resized"))?;
    let resized_range = (new_start.raw_address(), resized_last.raw_address());
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    let reader = engine.query_reader()?;
    let changes = engine.subscribe().with_capacity(16).build()?;
    consume_initial_resynchronisation(&changes, reader.revision()?)?;
    assert!(
        reader
            .mapping_page(DEFAULT_SPACE_ID, None, 4096)?
            .entries()
            .iter()
            .any(|record| record.mapping() == mapping_id)
    );

    let created_start = old_start
        .checked_add(old_size + 0x2000)
        .ok_or_else(|| io::Error::other("fixture mapping cannot be safely duplicated"))?;
    let created = engine.create_mapping(
        SegmentMappingBuilder::new(created_start, 1, mapping_offset, provider_id)
            .with_properties(mapping_properties)
            .with_name("engine-created"),
    )?;
    let created_id = created.mapping();

    assert!(
        created
            .changes()
            .records()
            .contains(&ChangeRecord::SegmentMappingCreated {
                mapping: created_id
            })
    );
    assert!(
        !reader
            .mapping_page(DEFAULT_SPACE_ID, None, 4096)?
            .entries()
            .iter()
            .any(|record| record.mapping() == created_id)
    );

    let created_space = engine.create_space()?;
    let extra_space = created_space.space();

    assert!(
        created_space
            .changes()
            .records()
            .contains(&ChangeRecord::SpaceCreated { space: extra_space })
    );

    let placed = engine.add_mapping_to_space(extra_space, created_id)?;

    assert!(placed.records().contains(&ChangeRecord::SegmentMapped {
        mapping: created_id,
        range: AddressRange::new(
            extra_space,
            created_start.raw_address(),
            created_start.raw_address(),
        ),
    }));
    assert!(
        reader
            .mapping_page(extra_space, None, 4096)?
            .entries()
            .iter()
            .any(|record| record.mapping() == created_id)
    );

    let metadata = engine.update_mapping_metadata(
        MappingMetadataUpdate::new(created_id)
            .with_kind(SegmentMappingKind::Mmap)
            .with_provenance(SegmentMappingProvenance::Synthetic)
            .with_flags(SegmentMappingFlags::PRIVATE),
    )?;

    assert!(
        metadata
            .records()
            .contains(&ChangeRecord::SegmentMappingChanged {
                mapping: created_id
            })
    );

    let remapped = engine.remap_mapping(mapping_id, new_start)?;

    assert!(remapped.records().contains(&ChangeRecord::SegmentUnmapped {
        mapping: mapping_id,
        range: AddressRange::new(DEFAULT_SPACE_ID, old_range.0, old_range.1),
    }));
    assert!(remapped.records().contains(&ChangeRecord::SegmentMapped {
        mapping: mapping_id,
        range: AddressRange::new(DEFAULT_SPACE_ID, remapped_range.0, remapped_range.1),
    }));
    let mut delivered = false;
    for _ in 0..16 {
        if *changes.recv_timeout(Duration::from_secs(1))? == remapped {
            delivered = true;
            break;
        }
    }
    assert!(delivered);
    let remapped_record = reader
        .mapping_page(DEFAULT_SPACE_ID, None, 4096)?
        .entries()
        .iter()
        .find(|record| record.mapping() == mapping_id)
        .copied()
        .ok_or_else(|| io::Error::other("remapped mapping missing"))?;
    assert_eq!(remapped_record.start(), new_start);

    let resized = engine.resize_mapping(mapping_id, resized_size)?;

    assert!(resized.records().contains(&ChangeRecord::SegmentUnmapped {
        mapping: mapping_id,
        range: AddressRange::new(DEFAULT_SPACE_ID, remapped_range.0, remapped_range.1),
    }));
    assert!(resized.records().contains(&ChangeRecord::SegmentMapped {
        mapping: mapping_id,
        range: AddressRange::new(DEFAULT_SPACE_ID, resized_range.0, resized_range.1),
    }));
    let mut delivered = false;
    for _ in 0..16 {
        if *changes.recv_timeout(Duration::from_secs(1))? == resized {
            delivered = true;
            break;
        }
    }
    assert!(delivered);
    let resized_record = reader
        .mapping_page(DEFAULT_SPACE_ID, None, 4096)?
        .entries()
        .iter()
        .find(|record| record.mapping() == mapping_id)
        .copied()
        .ok_or_else(|| io::Error::other("resized mapping missing"))?;
    assert_eq!(resized_record.size(), resized_size);

    let removed = engine.remove_mapping(mapping_id)?;

    assert!(removed.records().contains(&ChangeRecord::SegmentUnmapped {
        mapping: mapping_id,
        range: AddressRange::new(DEFAULT_SPACE_ID, resized_range.0, resized_range.1),
    }));
    let mut delivered = false;
    for _ in 0..16 {
        if *changes.recv_timeout(Duration::from_secs(1))? == removed {
            delivered = true;
            break;
        }
    }
    assert!(delivered);
    assert!(
        !reader
            .mapping_page(DEFAULT_SPACE_ID, None, 4096)?
            .entries()
            .iter()
            .any(|record| record.mapping() == mapping_id)
    );

    Ok(())
}

#[test]
fn test_cancel_between_analyses_does_not_poison_future_work() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    engine.cancel()?;
    engine.analyse()?;

    assert!(!engine.cancellation_token().is_cancelled());

    Ok(())
}

#[test]
fn test_cancelling_analyser_commits_partial_progress_and_clears_followup()
-> Result<(), Box<dyn Error>> {
    let project = project_with_test_analyser("cancelling-test")?;
    let address = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    trigger_test_analyser(&engine, address)?;

    let reader = engine.query_reader()?;
    let symbols = reader.symbol_page_at(address, None, 4096)?;
    assert!(
        symbols
            .entries()
            .iter()
            .any(|record| record.symbol().as_str() == "cancel_committed_symbol")
    );
    assert!(
        symbols
            .entries()
            .iter()
            .all(|record| record.symbol().as_str() != "cancel_followup_symbol")
    );
    assert!(!engine.cancellation_token().is_cancelled());

    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn test_drop_persists_revision_and_reopen_sends_resynchronisation() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("engine.fdbz");
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path.clone());

    let project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes.clone(),
    )?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;
    let revision = engine.query_reader()?.revision()?;
    assert!(revision > Default::default());
    drop(engine);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes,
    )?;
    assert_eq!(reopened.revision(), revision);

    let engine = AnalysisEngine::new(reopened)?;
    let changes = engine.subscribe().with_capacity(1).build()?;
    let resynchronisation = changes.recv_timeout(Duration::from_secs(1))?;

    assert_eq!(resynchronisation.revision(), revision);
    assert_eq!(
        resynchronisation.records(),
        &[ChangeRecord::Resynchronise { to: revision }]
    );

    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn test_drop_reopen_queries_persisted_state_and_single_resynchronisation()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("engine-saved-state.fdbz");
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path.clone());

    let project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes.clone(),
    )?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    let reader = engine.query_reader()?;
    let symbol = SymbolEntry::new(
        entry,
        "saved_engine_symbol",
        SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
    );
    let symbol_name = symbol.symbol();
    let inserted = engine.add_symbol(SymbolIndex::new(SymbolTableSelector::new(254), 0), symbol)?;

    assert!(inserted.records().contains(&ChangeRecord::SymbolAdded {
        address: entry,
        symbol: symbol_name,
    }));
    assert!(
        reader
            .symbol_page_at(entry, None, 4096)?
            .entries()
            .iter()
            .any(|record| record.symbol() == symbol_name)
    );

    let revision = reader.revision()?;
    drop(reader);
    drop(engine);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes,
    )?;
    assert_eq!(reopened.revision(), revision);

    let engine = AnalysisEngine::new(reopened)?;
    let changes = engine.subscribe().with_capacity(2).build()?;
    let resynchronisation = changes.recv_timeout(Duration::from_secs(1))?;

    assert_eq!(resynchronisation.revision(), revision);
    assert_eq!(
        resynchronisation.records(),
        &[ChangeRecord::Resynchronise { to: revision }]
    );
    assert!(changes.recv_timeout(Duration::from_millis(100)).is_err());
    assert!(
        engine
            .query_reader()?
            .symbol_page_at(entry, None, 4096)?
            .entries()
            .iter()
            .any(|record| record.symbol() == symbol_name)
    );

    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn test_drop_reopen_reads_explicitly_materialised_lifted() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("engine-il-artefacts.fdbz");
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path.clone());

    let project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes.clone(),
    )?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    let reader = engine.query_reader()?;
    let function = reader
        .function_id_at(entry)?
        .ok_or_else(|| io::Error::other("function ID missing after add"))?;

    engine.ensure_lifted(function, ECodeSsaIr::FORM)?;
    let pcode = reader
        .pcode(function)?
        .ok_or_else(|| io::Error::other("PCode IR missing after ensure_lifted"))?;
    let ecode = reader
        .ecode(function)?
        .ok_or_else(|| io::Error::other("LIR missing after ensure_lifted"))?;
    let ssa = reader
        .ecode_ssa(function)?
        .ok_or_else(|| io::Error::other("LIR SSA missing after ensure_lifted"))?;
    let revision = reader.revision()?;

    drop(reader);
    drop(engine);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes,
    )?;
    assert_eq!(reopened.revision(), revision);

    let engine = AnalysisEngine::new(reopened)?;
    let reader = engine.query_reader()?;
    let function = reader
        .function_id_at(entry)?
        .ok_or_else(|| io::Error::other("reopened function ID missing"))?;

    let snapshot = reader.project()?;
    assert_eq!(snapshot.pcode(function)?.as_ref(), Some(&*pcode));
    assert_eq!(snapshot.ecode(function)?.as_ref(), Some(&*ecode));
    assert_eq!(snapshot.ecode_ssa(function)?.as_ref(), Some(&*ssa));

    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn test_drop_reopen_regenerates_query_views_without_persisting() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("engine-generated-views.fdbz");
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path);

    let project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes.clone(),
    )?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let mut reader = engine.query_reader()?;
    let function = reader
        .function_id_at(entry)?
        .ok_or_else(|| io::Error::other("function ID missing after analysis"))?;
    let block = reader
        .project()?
        .functions()
        .get_by_id(function)
        .and_then(|function| function.blocks().next().map(|(_, block)| block))
        .ok_or_else(|| io::Error::other("function block missing after analysis"))?;
    let insns = reader
        .insns(block)?
        .ok_or_else(|| io::Error::other("generated insns missing"))?;
    let pcode = reader
        .pcode(function)?
        .ok_or_else(|| io::Error::other("generated PCode missing"))?;
    let ecode_ssa = reader
        .ecode_ssa(function)?
        .ok_or_else(|| io::Error::other("generated ECode SSA missing"))?;
    let revision = reader.revision()?;
    let snapshot = reader.project()?;
    assert!(snapshot.pcode(function)?.is_none());
    assert!(snapshot.ecode(function)?.is_none());
    assert!(snapshot.ecode_ssa(function)?.is_none());
    drop(snapshot);
    drop(reader);
    drop(engine);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes,
    )?;
    assert_eq!(reopened.revision(), revision);
    assert!(reopened.pcode(function)?.is_none());
    assert!(reopened.ecode(function)?.is_none());
    assert!(reopened.ecode_ssa(function)?.is_none());

    let engine = AnalysisEngine::new(reopened)?;
    let mut reader = engine.query_reader()?;
    assert_eq!(reader.insns(block)?.as_deref(), Some(insns.as_ref()));
    assert_eq!(reader.pcode(function)?.as_deref(), Some(pcode.as_ref()));
    assert_eq!(
        reader.ecode_ssa(function)?.as_deref(),
        Some(ecode_ssa.as_ref())
    );
    let snapshot = reader.project()?;
    assert!(snapshot.pcode(function)?.is_none());
    assert!(snapshot.ecode(function)?.is_none());
    assert!(snapshot.ecode_ssa(function)?.is_none());

    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn test_drop_persists_update() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("engine-on-commit.fdbz");
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path.clone());

    let project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes.clone(),
    )?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    let symbol = SymbolEntry::new(
        entry,
        "on_commit_symbol",
        SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
    );
    let symbol_name = symbol.symbol();
    let inserted = engine.add_symbol(SymbolIndex::new(SymbolTableSelector::new(254), 1), symbol)?;
    let revision = inserted.revision();
    drop(engine);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes,
    )?;
    assert_eq!(reopened.revision(), revision);

    let engine = AnalysisEngine::new(reopened)?;
    assert!(
        engine
            .query_reader()?
            .symbol_page_at(entry, None, 4096)?
            .entries()
            .iter()
            .any(|record| record.symbol() == symbol_name)
    );

    Ok(())
}

#[test]
fn test_analyser_error_does_not_poison_engine() -> Result<(), Box<dyn Error>> {
    let _guard = FAILING_ANALYSER_TEST_LOCK
        .lock()
        .map_err(|_| io::Error::other("failing analyser test lock poisoned"))?;
    FAILING_ANALYSER_RUNS.store(0, Ordering::SeqCst);
    let project = project_with_test_analyser("error-test")?;
    let address = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    trigger_test_analyser(&engine, address)?;

    assert_eq!(
        FAILING_ANALYSER_RUNS.load(Ordering::SeqCst),
        EXPECTED_DEFAULT_WORK_ITEM_MAX_ATTEMPTS,
        "a failing region must be retried to the failure bound, not silently dropped"
    );
    engine.poison_check()?;

    Ok(())
}

#[test]
fn test_retry_exhaustion_does_not_disable_analyser() -> Result<(), Box<dyn Error>> {
    let _guard = FAILING_ANALYSER_TEST_LOCK
        .lock()
        .map_err(|_| io::Error::other("failing analyser test lock poisoned"))?;
    FAILING_ANALYSER_RUNS.store(0, Ordering::SeqCst);
    let project = project_with_test_analyser("error-test")?;
    let address = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    trigger_test_analyser(&engine, address)?;

    assert_eq!(
        FAILING_ANALYSER_RUNS.load(Ordering::SeqCst),
        EXPECTED_DEFAULT_WORK_ITEM_MAX_ATTEMPTS,
        "one trigger retries its own item to the bound"
    );

    trigger_test_analyser(&engine, address)?;
    assert_eq!(
        FAILING_ANALYSER_RUNS.load(Ordering::SeqCst),
        EXPECTED_DEFAULT_WORK_ITEM_MAX_ATTEMPTS * 2,
        "exhausting one item must not disable unrelated future work"
    );

    Ok(())
}

#[test]
fn test_panicking_analyser_is_fatal() -> Result<(), Box<dyn Error>> {
    let project = project_with_test_analyser("panicking-test")?;
    let address = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    let mut regions = AddressRangeSet::new();
    regions.insert(address);
    engine.schedule_ranges(ChangeKinds::BYTES_WRITTEN, regions)?;

    let result = engine.analyse();
    assert!(
        matches!(result, Err(EngineError::Stopped)),
        "a panicking analyser terminates the worker rather than being caught"
    );
    assert!(matches!(
        engine.add_symbol(
            SymbolIndex::new(SymbolTableSelector::new(249), 0),
            SymbolEntry::new(
                address,
                "after_panic_symbol",
                SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
            ),
        ),
        Err(EngineError::Stopped)
    ));

    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn test_panicking_analyser_does_not_persist_torn_state() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("engine-panic-torn.fdbz");
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path.clone());
    attributes.set_attr(TEST_ANALYSER_ATTR, "panicking-test");

    let project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes.clone(),
    )?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    let mut regions = AddressRangeSet::new();
    regions.insert(entry);
    engine.schedule_ranges(ChangeKinds::BYTES_WRITTEN, regions)?;

    assert!(matches!(engine.analyse(), Err(EngineError::Stopped)));
    drop(engine);

    let mut reopen_attributes = AttributeMap::new();
    reopen_attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path);
    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        reopen_attributes,
    )?;
    assert!(
        reopened
            .symbols()
            .get_first("panicked_torn_symbol")
            .is_none()
    );

    let torn_target = entry
        .checked_add(0x100u64)
        .ok_or_else(|| io::Error::other("torn reference target overflow"))?;
    let reopened_engine = AnalysisEngine::new(reopened)?;
    reopened_engine.analyse()?;
    let reader = reopened_engine.query_reader()?;
    let torn_reference = reader
        .outgoing_references(entry)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|reference| reference.target().address() == Some(torn_target));
    assert!(torn_reference.is_none());

    Ok(())
}

#[test]
fn test_panicking_completion_hook_is_fatal() -> Result<(), Box<dyn Error>> {
    let project = project_with_test_analyser("completion-panic-test")?;
    let engine = AnalysisEngine::new(project)?;

    let result = engine.analyse();
    assert!(
        matches!(result, Err(EngineError::Stopped)),
        "a panicking completion hook terminates the worker rather than being caught"
    );
    assert!(matches!(engine.query_reader(), Err(EngineError::Stopped)));

    Ok(())
}

#[test]
fn test_completion_hook_runs_once_after_drain() -> Result<(), Box<dyn Error>> {
    let project = project_with_test_analyser("completion-test")?;
    let address = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    let reader = engine.query_reader()?;

    engine.analyse()?;
    COMPLETION_ANALYSE_COUNT.store(0, Ordering::SeqCst);
    COMPLETION_END_COUNT.store(0, Ordering::SeqCst);
    trigger_test_analyser(&engine, address)?;

    let symbols = reader.symbol_page_at(address, None, 4096)?;
    assert_eq!(
        symbols
            .entries()
            .iter()
            .filter(|symbol| symbol.symbol().as_str() == "completion_symbol")
            .count(),
        1
    );
    assert_eq!(COMPLETION_END_COUNT.load(Ordering::SeqCst), 1);

    Ok(())
}

#[test]
fn test_derived_analyser_runs_after_function_discovery() -> Result<(), Box<dyn Error>> {
    let project = project_with_test_analyser("derived-symbol")?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    let changes = engine.subscribe().with_capacity(4096).build()?;

    engine.analyse()?;
    let reader = engine.query_reader()?;
    let symbols = reader.symbol_page_at(entry, None, 4096)?;

    assert!(
        symbols
            .entries()
            .iter()
            .any(|symbol| symbol.symbol().as_str() == "derived_function")
    );

    let journal = changes.try_iter().collect::<Vec<_>>();
    let first_function_revision = journal.iter().position(|changes| {
        changes
            .records()
            .iter()
            .any(|record| matches!(record, ChangeRecord::FunctionAdded { .. }))
    });
    let first_symbol_revision = journal.iter().position(|changes| {
        changes.records().iter().any(|record| {
            matches!(
                record,
                ChangeRecord::SymbolAdded { symbol, .. }
                    if symbol.as_str() == "derived_function"
            )
        })
    });

    assert!(matches!(
        (first_function_revision, first_symbol_revision),
        (Some(function), Some(symbol)) if function < symbol
    ));

    Ok(())
}

#[test]
fn test_engine_storm_regions_coalesce_to_single_analyser_task() -> Result<(), Box<dyn Error>> {
    let run_scenario = |storm: bool| -> Result<(usize, Vec<SymbolRow>), Box<dyn Error>> {
        STORM_ANALYSER_RUNS.store(0, Ordering::SeqCst);

        let project = project_with_test_analyser("storm-test")?;
        let entry = project
            .entry_point()
            .ok_or_else(|| io::Error::other("fixture entry missing"))?;
        let engine = AnalysisEngine::new(project)?;

        engine.analyse()?;

        if storm {
            for offset in 0..512u64 {
                let end = entry
                    .raw_address()
                    .checked_add(RawAddress::from(offset))
                    .ok_or_else(|| io::Error::other("fixture entry cannot form storm range"))?;
                let mut regions = AddressRangeSet::new();
                regions.insert_raw_range(entry.space(), entry.raw_address()..=end);
                engine.schedule_ranges(ChangeKinds::BYTES_WRITTEN, regions)?;
            }
        } else {
            let mut regions = AddressRangeSet::new();
            regions.insert(entry);
            engine.schedule_ranges(ChangeKinds::BYTES_WRITTEN, regions)?;
        }

        engine.analyse()?;

        let symbols = engine
            .query_reader()?
            .symbol_page_at(entry, None, 4096)?
            .entries()
            .iter()
            .copied()
            .filter(|symbol| symbol.symbol().as_str() == "storm_symbol")
            .collect::<Vec<_>>();

        Ok((STORM_ANALYSER_RUNS.load(Ordering::SeqCst), symbols))
    };

    let (calm_runs, calm_symbols) = run_scenario(false)?;
    let (storm_runs, storm_symbols) = run_scenario(true)?;

    assert_eq!(calm_runs, 1);
    assert!(
        (1..512).contains(&storm_runs),
        "storm sends should coalesce far below the send count, got {storm_runs}"
    );
    assert_eq!(storm_symbols, calm_symbols);
    assert_eq!(storm_symbols.len(), 1);

    Ok(())
}

#[test]
fn test_analyser_error_is_rejected_without_materialising_records() -> Result<(), Box<dyn Error>> {
    let _guard = FAILING_ANALYSER_TEST_LOCK
        .lock()
        .map_err(|_| io::Error::other("failing analyser test lock poisoned"))?;
    FAILING_ANALYSER_RUNS.store(0, Ordering::SeqCst);
    let project = project_with_test_analyser("mutating-error")?;
    let address = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    let revision = engine.query_reader()?.revision()?;
    let changes = engine
        .subscribe()
        .with_kinds(ChangeKinds::PROBLEM_RECORDED)
        .with_capacity(16)
        .build()?;
    consume_initial_resynchronisation(&changes, revision)?;
    trigger_test_analyser(&engine, address)?;

    assert!(
        engine
            .query_reader()?
            .symbol_page_at(address, None, 4096)?
            .entries()
            .iter()
            .all(|record| record.symbol().as_str() != "rolled_back_symbol"),
        "the analyser's own mutations must not survive its failure"
    );
    while let Ok(published) = changes.recv_timeout(Duration::from_millis(100)) {
        assert!(
            published
                .records()
                .iter()
                .all(|record| matches!(record, ChangeRecord::ProblemRecorded { .. })),
            "the only change a failed analyser may publish is its own diagnostic"
        );
    }
    assert_eq!(
        FAILING_ANALYSER_RUNS.load(Ordering::SeqCst),
        EXPECTED_DEFAULT_WORK_ITEM_MAX_ATTEMPTS,
        "every retry must be rejected without materialising records"
    );
    engine.poison_check()?;

    Ok(())
}

#[test]
fn test_failed_analyser_needs_no_entity_rollback() -> Result<(), Box<dyn Error>> {
    let _staging_guard = STAGED_FAILURE_TEST_LOCK
        .lock()
        .map_err(|_| io::Error::other("staged failure test lock poisoned"))?;
    let _analyser_guard = FAILING_ANALYSER_TEST_LOCK
        .lock()
        .map_err(|_| io::Error::other("failing analyser test lock poisoned"))?;
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut attributes = AttributeMap::new();
    attributes.set_attr(TEST_ANALYSER_ATTR, "mutating-error");
    let mut project = Project::new_with_provider::<FailingStorageProvider>(&loader, attributes)?;
    let address = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let mut transaction = project.transaction("rejection failure test");
    transaction.add_function(one_block_function(address, 1))?;
    transaction.commit()?;
    let engine = AnalysisEngine::new(project)?;

    engine.analyse()?;
    FAIL_ENTITY_REMOVES.store(true, Ordering::SeqCst);
    let mut regions = AddressRangeSet::new();
    regions.insert(address);
    engine.schedule_ranges(ChangeKinds::BYTES_WRITTEN, regions)?;
    let result = engine.analyse();
    FAIL_ENTITY_REMOVES.store(false, Ordering::SeqCst);

    result?;
    assert!(
        engine
            .query_reader()?
            .symbol_page_at(address, None, 4096)?
            .entries()
            .iter()
            .all(|record| record.symbol().as_str() != "rolled_back_symbol"),
        "failed analyser output must be discarded before touching entity storage"
    );
    engine.poison_check()?;

    PROJECT_REVISION_INSERTS.store(0, Ordering::SeqCst);
    drop(engine);
    assert!(
        PROJECT_REVISION_INSERTS.load(Ordering::SeqCst) > 0,
        "a discarded stage must not abandon persistence"
    );

    Ok(())
}

#[test]
fn test_failed_storage_admission_keeps_revision_and_tables_unchanged() -> Result<(), Box<dyn Error>>
{
    let _staging_guard = STAGED_FAILURE_TEST_LOCK
        .lock()
        .map_err(|_| io::Error::other("staged failure test lock poisoned"))?;
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut project =
        Project::new_with_provider::<FailingStorageProvider>(&loader, AttributeMap::new())?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?
        .checked_add(0x4000_0000u64)
        .ok_or_else(|| io::Error::other("synthetic function address overflow"))?;
    let revision = project.revision();

    FAIL_ENTITY_COMMITS.store(true, Ordering::SeqCst);
    let mut transaction = project.transaction("storage failure test");
    transaction.add_function(one_block_function(entry, 1))?;
    let result = transaction.commit();
    FAIL_ENTITY_COMMITS.store(false, Ordering::SeqCst);

    assert!(result.is_err());
    assert_eq!(project.revision(), revision);
    assert!(project.functions().get_by_address(entry).is_none());

    Ok(())
}

#[test]
fn test_subscription_kind_filter_wakes_only_on_matching_kinds() -> Result<(), Box<dyn Error>> {
    let (project, address) = project_with_writable_address()?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let symbols = engine
        .subscribe()
        .with_kinds(ChangeKinds::SYMBOLS)
        .with_capacity(16)
        .build()?;
    consume_initial_resynchronisation(&symbols, engine.query_reader()?.revision()?)?;

    engine.write_bytes(address, [0xccu8])?;
    assert!(symbols.recv_timeout(Duration::from_millis(100)).is_err());

    engine.add_symbol(
        SymbolIndex::new(SymbolTableSelector::new(200), 0),
        SymbolEntry::new(address, "scoped_symbol", SymbolProperties::LOCAL),
    )?;
    let delivered = symbols.recv_timeout(Duration::from_secs(1))?;
    assert!(delivered.contains(ChangeKinds::SYMBOL_ADDED));

    Ok(())
}

#[test]
fn test_subscription_region_filter_wakes_only_inside_region() -> Result<(), Box<dyn Error>> {
    let (project, address) = project_with_writable_address()?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let mut region = AddressRangeSet::new();
    region.insert_range(AddressRange::new(
        address.space(),
        address.raw_address(),
        address.raw_address(),
    ));
    let outside = address + 8u64;

    let inside_region = engine
        .subscribe()
        .with_kinds(ChangeKinds::BYTES_WRITTEN | ChangeKinds::SPACE_CREATED)
        .with_region(region)
        .with_capacity(16)
        .build()?;
    consume_initial_resynchronisation(&inside_region, engine.query_reader()?.revision()?)?;

    engine.write_bytes(outside, [0xccu8])?;
    assert!(
        inside_region
            .recv_timeout(Duration::from_millis(100))
            .is_err()
    );

    engine.write_bytes(address, [0xccu8])?;
    let delivered = inside_region.recv_timeout(Duration::from_secs(1))?;
    assert!(delivered.contains(ChangeKinds::BYTES_WRITTEN));

    engine.create_space()?;
    let global = inside_region.recv_timeout(Duration::from_secs(1))?;
    assert!(global.contains(ChangeKinds::SPACE_CREATED));

    Ok(())
}

#[test]
fn test_subscription_drain_coalesces_commit_burst() -> Result<(), Box<dyn Error>> {
    let (project, address) = project_with_writable_address()?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let symbols = engine
        .subscribe()
        .with_kinds(ChangeKinds::SYMBOLS)
        .with_capacity(16)
        .build()?;
    consume_initial_resynchronisation(&symbols, engine.query_reader()?.revision()?)?;

    for index in 0..8usize {
        engine.add_symbol(
            SymbolIndex::new(SymbolTableSelector::new(210), index),
            SymbolEntry::new(
                address + index as u64,
                "burst_symbol",
                SymbolProperties::LOCAL,
            ),
        )?;
    }
    engine.analyse()?;

    let batch = symbols.drain_merged().ok_or("burst produced no batch")?;
    assert!(batch.contains(ChangeKinds::SYMBOL_ADDED));
    assert_eq!(
        batch
            .records()
            .iter()
            .filter(|record| record.kind() == ChangeKinds::SYMBOL_ADDED)
            .count(),
        8
    );
    assert!(symbols.drain_merged().is_none());

    Ok(())
}

#[test]
fn test_subscription_recv_batch_merges_queued_changes() -> Result<(), Box<dyn Error>> {
    let (project, address) = project_with_writable_address()?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let symbols = engine
        .subscribe()
        .with_kinds(ChangeKinds::SYMBOLS)
        .with_capacity(16)
        .build()?;
    consume_initial_resynchronisation(&symbols, engine.query_reader()?.revision()?)?;

    for index in 0..4usize {
        engine.add_symbol(
            SymbolIndex::new(SymbolTableSelector::new(211), index),
            SymbolEntry::new(
                address + index as u64,
                "batch_symbol",
                SymbolProperties::LOCAL,
            ),
        )?;
    }
    engine.analyse()?;

    let burst = symbols.recv_batch()?;
    assert_eq!(
        burst
            .records()
            .iter()
            .filter(|record| record.kind() == ChangeKinds::SYMBOL_ADDED)
            .count(),
        4
    );

    engine.add_symbol(
        SymbolIndex::new(SymbolTableSelector::new(211), 4),
        SymbolEntry::new(address + 4u64, "batch_symbol", SymbolProperties::LOCAL),
    )?;
    engine.analyse()?;

    let single = symbols.recv_batch()?;
    assert_eq!(
        single
            .records()
            .iter()
            .filter(|record| record.kind() == ChangeKinds::SYMBOL_ADDED)
            .count(),
        1
    );
    assert!(single.revision() > burst.revision());

    Ok(())
}

#[test]
fn test_subscription_changes_carry_provenance() -> Result<(), Box<dyn Error>> {
    let project = project_with_test_analyser("derived-symbol")?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    let changes = engine.subscribe().with_capacity(4096).build()?;

    engine.analyse()?;

    let journal = changes.try_iter().collect::<Vec<_>>();
    assert!(journal.iter().any(|changes| {
        changes.provenance().contains("function-recovery")
            && changes.provenance().includes(ChangeCategory::Analysis)
            && changes.contains(ChangeKinds::FUNCTION_ADDED)
    }));
    assert!(journal.iter().any(|changes| {
        changes.provenance().contains("derived-symbol")
            && changes.records().iter().any(|record| {
                matches!(
                    record,
                    ChangeRecord::SymbolAdded { symbol, .. }
                        if symbol.as_str() == "derived_function"
                )
            })
    }));

    engine.add_symbol(
        SymbolIndex::new(SymbolTableSelector::new(212), 0),
        SymbolEntry::new(entry, "provenance_symbol", SymbolProperties::LOCAL),
    )?;
    engine.analyse()?;

    let update = changes
        .drain_merged()
        .ok_or("update produced no provenance batch")?;
    assert!(update.provenance().contains("update"));
    assert!(update.provenance().includes(ChangeCategory::Engine));
    assert!(!update.provenance().includes(ChangeCategory::Agent));

    Ok(())
}

#[test]
fn test_subscription_source_filter_selects_actor() -> Result<(), Box<dyn Error>> {
    let project = project_with_test_analyser("derived-symbol")?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let analysis_only = engine
        .subscribe()
        .with_kinds(ChangeKinds::SYMBOLS)
        .with_category(ChangeCategory::Analysis)
        .with_capacity(4096)
        .build()?;
    let user_only = engine
        .subscribe()
        .with_kinds(ChangeKinds::SYMBOLS)
        .with_category(ChangeCategory::Engine)
        .with_capacity(4096)
        .build()?;
    let derived_only = engine
        .subscribe()
        .with_source_label("derived-symbol")
        .with_capacity(4096)
        .build()?;
    let revision = engine.query_reader()?.revision()?;
    consume_initial_resynchronisation(&analysis_only, revision)?;
    consume_initial_resynchronisation(&user_only, revision)?;
    consume_initial_resynchronisation(&derived_only, revision)?;

    engine.add_symbol(
        SymbolIndex::new(SymbolTableSelector::new(213), 0),
        SymbolEntry::new(entry, "actor_symbol", SymbolProperties::LOCAL),
    )?;
    engine.analyse()?;

    let user_batch = user_only
        .drain_merged()
        .ok_or("user subscription missed the update")?;
    assert!(user_batch.provenance().contains("update"));
    assert!(analysis_only.drain_merged().is_none());
    assert!(derived_only.drain_merged().is_none());

    let target = entry + 0x40u64;
    engine.add_function(one_block_function(target, 1))?;
    engine.analyse()?;

    let analysis_batch = analysis_only
        .drain_merged()
        .ok_or("analysis subscription missed analyser symbols")?;
    assert!(analysis_batch.provenance().contains("derived-symbol"));
    assert!(!analysis_batch.provenance().includes(ChangeCategory::Agent));

    let derived_batch = derived_only
        .drain_merged()
        .ok_or("label subscription missed analyser changes")?;
    assert!(derived_batch.provenance().contains("derived-symbol"));
    assert_eq!(derived_batch.provenance().sources().count(), 1);

    assert!(user_only.drain_merged().is_none());

    Ok(())
}

#[test]
fn test_query_reader_symbol_iterator_equals_cursor_walk() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;
    let reader = engine.query_reader()?;

    let walked = reader.symbols().collect::<Result<Vec<_>, _>>()?;

    let mut cursor = None;
    let mut manual = Vec::new();
    loop {
        let page = reader.symbol_page(cursor, 256)?;
        manual.extend(page.entries().iter().copied());
        let Some(next) = page.next_cursor().copied() else {
            break;
        };
        cursor = Some(next);
    }

    assert_eq!(walked, manual);
    assert!(!walked.is_empty());

    Ok(())
}

#[test]
fn test_query_readers_serve_multiple_concurrent_clients() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let reader = engine.query_reader()?;
    let entries = reader
        .functions(DEFAULT_SPACE_ID)
        .take(32)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(!entries.is_empty());

    thread::scope(|scope| -> Result<(), Box<dyn Error>> {
        let handles = (0..8)
            .map(|_| {
                let reader = reader.clone();
                let entries = entries.clone();
                scope.spawn(move || -> Result<(), QueryError> {
                    let anywhere = AddressRangeSet::new();
                    for _ in 0..200 {
                        for entry in &entries {
                            reader.flow_targets(*entry)?;
                            reader.latest_change(ChangeKinds::all(), &anywhere)?;
                        }
                    }
                    Ok(())
                })
            })
            .collect::<Vec<_>>();

        for handle in handles {
            handle
                .join()
                .map_err(|_| io::Error::other("client thread panicked"))??;
        }
        Ok(())
    })?;

    let first = reader.flow_targets(entries[0])?.ok_or("entry missing")?;
    let second = reader.flow_targets(entries[0])?.ok_or("entry missing")?;
    assert!(Arc::ptr_eq(&first, &second));

    Ok(())
}

#[test]
fn test_engine_recovers_derived_references() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;
    let reader = engine.query_reader()?;

    let edge = reader
        .call_edge_page(None, 4096)?
        .entries()
        .iter()
        .copied()
        .next()
        .ok_or_else(|| io::Error::other("no call edges recovered"))?;
    let callee = edge.target();

    let incoming = reader
        .incoming_references(callee)
        .collect::<Result<Vec<_>, _>>()?;
    let call_reference = incoming
        .iter()
        .find(|reference| reference.is_call())
        .ok_or_else(|| {
            let flow_targets = reader
                .flow_targets(edge.source())
                .ok()
                .flatten()
                .map(|targets| targets.targets().to_vec());
            io::Error::other(format!(
                "no incoming call reference for {edge:?}; incoming={incoming:?}; \
                 flow_targets={flow_targets:?}",
            ))
        })?;
    assert!(call_reference.origin().is_derived());
    assert_eq!(call_reference.target().address(), Some(callee));

    let outgoing = reader
        .outgoing_references(call_reference.from())
        .collect::<Result<Vec<_>, _>>()?;
    assert!(
        outgoing
            .iter()
            .any(|reference| reference.target().address() == Some(callee) && reference.is_call())
    );

    Ok(())
}

#[test]
fn test_engine_recovers_and_persists_switches() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut attributes = AttributeMap::new();
    attributes.set_attr(TEST_SWITCH_RECOVERY_ATTR, true);
    let project = Project::new_with_provider::<TransientStorageProvider>(&loader, attributes)?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let reader = engine.query_reader()?;
    let switches = reader.switches().collect::<Result<Vec<_>, _>>()?;
    assert!(
        !switches.is_empty(),
        "recovered switches must persist in the switch table"
    );
    for (branch, cases) in [
        (0x4f55u64, 277usize),
        (0x6efd, 73),
        (0x10612, 5),
        (0x12116, 54),
        (0x149dd, 123),
    ] {
        let switch = switches
            .iter()
            .find(|record| record.branch() == Address::from(branch))
            .ok_or_else(|| io::Error::other(format!("switch missing at {branch:#x}")))?;
        assert_eq!(
            switch.case_count(),
            cases,
            "switch at {branch:#x}: model={:?}, properties={:?}, confidence={}, default={}",
            switch.switch().model(),
            switch.switch().properties(),
            switch.confidence(),
            switch.has_default(),
        );
    }
    let record = switches
        .iter()
        .find(|record| record.case_count() >= 2)
        .ok_or_else(|| io::Error::other("no multi-case switch recovered from ls.elf"))?;
    let switch = record.switch();
    let project = reader.project()?;
    let exact = project
        .functions()
        .get_by_address(record.branch())
        .map(|function| function.id());
    let owners = project
        .functions()
        .iter()
        .filter(|function| {
            function.blocks().any(|(_, block)| {
                project
                    .blocks()
                    .get_by_id(block)
                    .is_some_and(|block| block.address_range().contains_address(record.branch()))
            })
        })
        .map(|function| function.id())
        .collect::<Vec<_>>();
    if switch.function().is_invalid() {
        assert!(exact.is_none() && owners.len() != 1);
    } else {
        assert!(
            exact == Some(switch.function())
                || (exact.is_none() && owners.as_slice() == [switch.function()])
        );
    }
    drop(project);
    let table = switch
        .model()
        .table()
        .ok_or_else(|| io::Error::other("recovered switch has no table"))?;
    assert!(
        table.address().offset() != 0,
        "recovered table must have a real address"
    );

    let outgoing = reader
        .outgoing_references(record.branch())
        .collect::<Result<Vec<_>, _>>()?;
    for case in switch.cases() {
        let target = case.target().address();
        assert!(
            outgoing.iter().any(|reference| {
                reference.is_flow() && reference.target().address() == Some(target)
            }),
            "case target {target} must be integrated as a flow reference from the branch"
        );
    }

    assert!(
        switches.iter().any(|record| record.has_default()),
        "a guarded switch must recover a default case"
    );

    Ok(())
}

#[test]
fn test_engine_recovers_arm_inline_switches() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/libipmi.so")?;
    let mut attributes = AttributeMap::new();
    attributes.set_attr(TEST_SWITCH_RECOVERY_ATTR, true);
    let project = Project::new_with_provider::<TransientStorageProvider>(&loader, attributes)?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let reader = engine.query_reader()?;
    let switches = reader.switches().collect::<Result<Vec<_>, _>>()?;
    let switch_addresses = switches
        .iter()
        .map(|record| record.branch().raw_address())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        switch_addresses.len(),
        94,
        "unexpected ARM switch branches: {switch_addresses:#x?}"
    );

    let branch = Address::from(0x3bec0u64);
    let record = switches
        .iter()
        .find(|record| record.branch() == branch)
        .ok_or_else(|| io::Error::other("ARM inline switch missing"))?;
    let switch = record.switch();
    let SwitchModel::InlineBranchTable(table) = switch.model() else {
        return Err(io::Error::other("ARM switch has the wrong model").into());
    };
    assert_eq!(table.address(), Address::from(0x3bec8u64));
    assert_eq!(table.element_size(), 4);
    assert_eq!(table.element_count(), 4);
    assert_eq!(
        switch
            .cases()
            .iter()
            .flat_map(|case| case.labels())
            .map(|label| label.value())
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3],
    );
    assert_eq!(
        switch
            .cases()
            .iter()
            .map(|case| case.target().address())
            .collect::<Vec<_>>(),
        vec![
            Address::from(0x3bf28u64),
            Address::from(0x3bf28u64),
            Address::from(0x3bed8u64),
            Address::from(0x3bed8u64),
        ],
    );
    assert_eq!(
        switch.default_case().map(|case| case.target().address()),
        Some(Address::from(0x3bf78u64)),
    );

    for (address, count) in [
        (0x46df4u64, 33usize),
        (0x489c8, 6),
        (0x53d98, 8),
        (0xe1e5c, 4),
    ] {
        let recovered = switches
            .iter()
            .find(|record| record.branch() == Address::from(address))
            .ok_or_else(|| io::Error::other(format!("ARM switch missing at {address:#x}")))?;
        assert_eq!(recovered.case_count(), count);
    }

    let outgoing = reader
        .outgoing_references(branch)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(outgoing.iter().all(|reference| {
        !reference.is_data() || reference.target().address() != Some(table.address())
    }));

    let function_entry = Address::from(0x3be5cu64);
    let function_id = {
        let project = reader.project()?;
        let function = project
            .functions()
            .get_by_address(function_entry)
            .ok_or_else(|| io::Error::other("ARM fixture function missing"))?;
        for (_, block_id) in function.blocks() {
            let block = project
                .blocks()
                .get_by_id(block_id)
                .ok_or_else(|| io::Error::other("ARM fixture block missing"))?;
            assert!(!(0x3c318..0x3c330).contains(&block.address().offset()));
            assert!(block.last_address().offset() < 0x3c318 || block.address().offset() >= 0x3c330);
        }
        function.id()
    };

    assert!(reader.pcode(function_id)?.is_some());
    assert!(reader.ecode(function_id)?.is_some());
    assert!(reader.ecode_ssa(function_id)?.is_some());

    Ok(())
}

#[test]
fn test_engine_add_and_remove_switch_round_trips() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;
    let reader = engine.query_reader()?;
    let baseline = reader.revision()?;

    let table = entry + 0x400u64;
    let mut switch = Switch::new(
        SwitchId::default(),
        entry,
        SwitchModel::Absolute(AddressTable::new(table, 4).with_element_count(2)),
    );
    for offset in [0x40u64, 0x80] {
        switch.add_case(SwitchCase::new(AddressWithContext::new(
            entry + offset,
            ContextSet::default(),
        )));
    }
    let changes = engine.add_switch(switch)?;
    assert!(changes.contains(ChangeKinds::SWITCH_ADDED));
    assert!(changes.contains(ChangeKinds::REFERENCES));

    let mut branch_region = AddressRangeSet::new();
    branch_region.insert(entry);
    assert!(reader.changed_since(baseline, ChangeKinds::SWITCHES, &branch_region)?);
    assert!(reader.changed_since(baseline, ChangeKinds::REFERENCES, &branch_region)?);

    let record = reader
        .switch_at(entry)?
        .ok_or_else(|| io::Error::other("switch missing after add"))?;
    assert!(record.switch().is_override());
    assert!(matches!(record.switch().model(), SwitchModel::Absolute(_)));
    assert!(
        !record.switch().function().is_invalid(),
        "owning function should be resolved from the branch"
    );

    let outgoing = reader
        .outgoing_references(entry)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(
        outgoing
            .iter()
            .any(|reference| reference.is_data() && reference.target().address() == Some(table)),
        "table should gain a derived data reference"
    );
    for offset in [0x40u64, 0x80] {
        assert!(
            outgoing.iter().any(|reference| {
                reference.is_flow() && reference.target().address() == Some(entry + offset)
            }),
            "case target should gain a derived flow reference"
        );
    }

    let removed = engine.remove_switch(entry)?;
    assert!(removed.contains(ChangeKinds::SWITCH_REMOVED));
    assert!(removed.contains(ChangeKinds::REFERENCES));
    assert!(reader.switch_at(entry)?.is_none());

    Ok(())
}

#[test]
fn test_engine_asserted_reference_round_trips() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let to = entry + 0x40u64;
    let changes = engine.add_reference(Reference::data(entry, to, ReferenceProperties::READ))?;
    assert!(changes.contains(ChangeKinds::REFERENCE_ADDED));

    let outgoing = engine
        .query_reader()?
        .outgoing_references(entry)
        .collect::<Result<Vec<_>, _>>()?;
    let asserted = outgoing
        .iter()
        .find(|reference| reference.target().address() == Some(to))
        .ok_or_else(|| io::Error::other("asserted reference missing"))?;
    assert!(asserted.is_read());
    assert!(asserted.origin().is_asserted());

    engine.add_reference(Reference::data(entry, to, ReferenceProperties::WRITE))?;
    let merged = engine
        .query_reader()?
        .incoming_reference_page(to, None, 64)?
        .entries()
        .iter()
        .copied()
        .find(|reference| reference.from() == entry)
        .ok_or_else(|| io::Error::other("merged reference missing"))?;
    assert!(merged.is_read());
    assert!(merged.is_write());

    engine.remove_reference(entry, ReferenceTarget::from(to))?;
    let after = engine
        .query_reader()?
        .outgoing_references(entry)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(
        after
            .iter()
            .all(|reference| reference.target().address() != Some(to))
    );

    Ok(())
}
