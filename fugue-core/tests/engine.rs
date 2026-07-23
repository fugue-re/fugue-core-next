use std::cell::RefCell;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::Debug;
use std::ops::Bound;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;
use std::{io, iter, thread};

use bytes::Bytes;
use fallible_iterator::{FallibleIterator, convert};
use fugue_core::analysis::control::Cancelled;
use fugue_core::analysis::function::recovery::{FunctionRecovery, FunctionRecoveryExtension};
use fugue_core::analysis::switch::SwitchRecovery;
use fugue_core::analysis::{AnalysisError, AnalysisPass};
use fugue_core::arch::Arch;
use fugue_core::engine::change::{ChangeCategory, ChangeKinds, ChangeRecord, Revision};
use fugue_core::engine::{
    Analyser, AnalyserProvider, AnalysisCx, AnalysisEngine, AnalysisMessageKind,
    DEFAULT_ANALYSER_MAX_FAILURES, EngineError, MappingMetadataUpdate, PersistencePolicy, Priority,
    Trigger,
};
use fugue_core::il::common::{IlError, IlLevel};
use fugue_core::ir::{
    Address, AddressRange, AddressRangeSet, AddressTable, AddressWithContext, Endian,
    IncompleteCodeBlock, IncompleteFunction, RawAddress, Reference, ReferenceProperties,
    ReferenceTarget, SegmentProperties, Switch, SwitchCase, SwitchId, SwitchModel, SymbolEntry,
    SymbolIndex, SymbolProperties, SymbolTableSelector,
};
use fugue_core::lifter::{ContextSet, resolve_language};
use fugue_core::loader::{
    ImageAddress, ImageBacking, ImageBank, ImageBankHandle, ImageLayout, ImageSegment,
    ImageSegmentContents, ImageSegmentContentsIterator, ImageSegmentIterator, ImageSpace,
    ImageSpaceHandle, Loadable, LoadableAnalysers, LoadableMetadata, Loader, LoaderError,
};
use fugue_core::project::{Project, ProjectError, ProjectTransaction};
use fugue_core::queries::{CallEdge, MappingRecord, QueryError, QueryPage, SymbolRecord};
use fugue_core::registry;
#[cfg(feature = "sqlite")]
use fugue_core::storage::PersistentStorageProvider;
#[cfg(feature = "sqlite")]
use fugue_core::storage::entities::SqliteEntityStorage;
use fugue_core::storage::entities::{
    EntityBytesAsIterator, EntityBytesBulkInserter, EntityBytesIterator,
    EntityBytesTransactionalReader, EntityBytesTransactionalWriter, EntityKeyBytesIterator,
    EntityStorageProvider, EntityStorageProviderFromLoadable, EntityStorageTransactionalReader,
    EntityStorageTransactionalWriter, InMemoryEntityStorage,
};
#[cfg(feature = "sqlite")]
use fugue_core::storage::segments::DefaultPersistentSegmentStorage;
use fugue_core::storage::segments::mapping::{
    SegmentMappingBuilder, SegmentMappingFlags, SegmentMappingKind, SegmentMappingProvenance,
};
use fugue_core::storage::segments::{DEFAULT_SPACE_ID, InMemorySegmentStorage};
use fugue_core::storage::{
    EntityStorage, EntityStorageError, PERSISTENT, SegmentStorage, StorageContainer,
    StoragePersistence, StorageProvider, StorageProviderError,
};
#[cfg(feature = "sqlite")]
use fugue_core::types::attributes::ATTRIBUTE_PROJECT_PATH;
use fugue_core::types::{AttributeMap, BytesOrSlice};

const PROJECT_REVISION_KEY: &[u8] = &[0, 12, 6];
const TEST_ANALYSER_ATTR: &str = "fugue.test.engine-analyser";
const TEST_CHUNKED_RECOVERY_ATTR: &str = "fugue.test.chunked-recovery";
const TEST_SWITCH_RECOVERY_ATTR: &str = "fugue.test.switch-recovery";

#[cfg(feature = "sqlite")]
type SqliteProjectProvider =
    PersistentStorageProvider<SqliteEntityStorage<PERSISTENT>, DefaultPersistentSegmentStorage>;

static COMPLETION_ANALYSE_COUNT: AtomicUsize = AtomicUsize::new(0);
static COMPLETION_END_COUNT: AtomicUsize = AtomicUsize::new(0);
static FAIL_ENTITY_INSERTS: AtomicBool = AtomicBool::new(false);
static SAVE_FAILURE_TEST_LOCK: Mutex<()> = Mutex::new(());
static STORM_ANALYSER_RUNS: AtomicUsize = AtomicUsize::new(0);

#[derive(Default)]
struct FailingSaveEntityStorage {
    inner: InMemoryEntityStorage,
}

enum FailingSaveWrite {
    Insert(Bytes, Bytes),
    Remove(Bytes),
}

struct FailingSaveTransaction<'a> {
    storage: &'a FailingSaveEntityStorage,
    writes: RefCell<Vec<FailingSaveWrite>>,
}

impl<'a> FailingSaveTransaction<'a> {
    fn new(storage: &'a FailingSaveEntityStorage) -> Self {
        Self {
            storage,
            writes: RefCell::new(Vec::new()),
        }
    }
}

impl<'a> EntityStorageTransactionalReader<'a> for FailingSaveTransaction<'a> {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        self.storage.get(key)
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        self.storage.contains(key)
    }
}

impl<'a> EntityStorageTransactionalWriter<'a> for FailingSaveTransaction<'a> {
    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        self.writes.borrow_mut().push(FailingSaveWrite::Insert(
            Bytes::copy_from_slice(key),
            value.into_bytes(),
        ));
        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        self.writes
            .borrow_mut()
            .push(FailingSaveWrite::Remove(Bytes::copy_from_slice(key)));
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<(), EntityStorageError> {
        for write in self.writes.into_inner() {
            match write {
                FailingSaveWrite::Insert(key, value) => {
                    self.storage
                        .insert(key.as_ref(), BytesOrSlice::from(value))?;
                }
                FailingSaveWrite::Remove(key) => {
                    self.storage.remove(key.as_ref())?;
                }
            }
        }

        Ok(())
    }
}

impl EntityStorageProviderFromLoadable for FailingSaveEntityStorage {
    fn from_loadable(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self {
            inner: InMemoryEntityStorage::from_loadable(loadable, attributes)?,
        })
    }
}

impl EntityStorageProvider for FailingSaveEntityStorage {
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
        if FAIL_ENTITY_INSERTS.load(Ordering::SeqCst) && key == PROJECT_REVISION_KEY {
            return Err(EntityStorageError::backing(io::Error::other(
                "injected save failure",
            )));
        }

        self.inner.insert(key, value)
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
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

    fn scan_range(
        &self,
        prefix: &[u8],
        start: Bound<&[u8]>,
    ) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        self.inner.scan_range(prefix, start)
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

    fn bulk_inserter(&self) -> Result<EntityBytesBulkInserter, EntityStorageError> {
        self.inner.bulk_inserter()
    }

    fn transactional_reader(&self) -> Result<EntityBytesTransactionalReader, EntityStorageError> {
        Ok(Box::new(FailingSaveTransaction::new(self)))
    }

    fn transactional_writer(&self) -> Result<EntityBytesTransactionalWriter, EntityStorageError> {
        Ok(Box::new(FailingSaveTransaction::new(self)))
    }

    fn persistence(&self) -> StoragePersistence {
        PERSISTENT
    }
}

struct FailingSaveStorageProvider;

impl StorageProvider for FailingSaveStorageProvider {
    fn from_loadable(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<StorageContainer, StorageProviderError> {
        FAIL_ENTITY_INSERTS.store(false, Ordering::SeqCst);

        let entities = EntityStorage::new(FailingSaveEntityStorage::from_loadable(
            loadable, attributes,
        )?);
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

    fn triggers(&self) -> &'static [Trigger] {
        &[Trigger::BytesWritten]
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
        transaction: &mut ProjectTransaction<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisCx,
    ) -> Result<(), AnalysisError> {
        let _ = cx;

        if self.mode == "mutating-error"
            && let Some(address) = regions.ranges().next().map(|range| range.start_address())
        {
            transaction.insert_symbol(
                SymbolIndex::new(SymbolTableSelector::new(251), 0),
                SymbolEntry::new(
                    address,
                    "rolled_back_symbol",
                    SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
                ),
            );
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

    fn triggers(&self) -> &'static [Trigger] {
        &[Trigger::BytesWritten, Trigger::SymbolAdded]
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
        transaction: &mut ProjectTransaction<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisCx,
    ) -> Result<(), AnalysisError> {
        let _ = cx;
        if let Some(address) = regions.ranges().next().map(|range| range.start_address()) {
            transaction.insert_symbol(
                SymbolIndex::new(SymbolTableSelector::new(252), 0),
                SymbolEntry::new(
                    address,
                    "panicked_torn_symbol",
                    SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
                ),
            );
            let target = address
                .checked_add(0x100u64)
                .expect("torn reference target");
            transaction
                .add_reference(Reference::data(address, target, ReferenceProperties::READ))
                .expect("torn reference asserted");
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

    fn triggers(&self) -> &'static [Trigger] {
        &[Trigger::BytesWritten]
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
        transaction: &mut ProjectTransaction<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisCx,
    ) -> Result<(), AnalysisError> {
        let _ = transaction;
        let _ = cx;
        COMPLETION_ANALYSE_COUNT.fetch_add(1, Ordering::SeqCst);
        self.address = regions.ranges().next().map(|range| range.start_address());
        Ok(())
    }

    fn analysis_ended(
        &mut self,
        transaction: &mut ProjectTransaction<'_>,
        cx: &AnalysisCx,
    ) -> Result<(), AnalysisError> {
        let _ = cx;
        let Some(address) = self.address.take() else {
            return Ok(());
        };
        COMPLETION_END_COUNT.fetch_add(1, Ordering::SeqCst);

        if self.completed {
            return Ok(());
        }

        self.completed = true;
        transaction.insert_symbol(
            SymbolIndex::new(SymbolTableSelector::new(252), 1),
            SymbolEntry::new(
                address,
                "completion_symbol",
                SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
            ),
        );
        Ok(())
    }
}

struct PanickingCompletionTestAnalyser;

impl Analyser for PanickingCompletionTestAnalyser {
    fn name(&self) -> &'static str {
        "completion-panic-test"
    }

    fn triggers(&self) -> &'static [Trigger] {
        &[Trigger::BytesWritten]
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
        transaction: &mut ProjectTransaction<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisCx,
    ) -> Result<(), AnalysisError> {
        let _ = transaction;
        let _ = regions;
        let _ = cx;
        Ok(())
    }

    fn analysis_ended(
        &mut self,
        transaction: &mut ProjectTransaction<'_>,
        cx: &AnalysisCx,
    ) -> Result<(), AnalysisError> {
        let _ = transaction;
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

    fn triggers(&self) -> &'static [Trigger] {
        &[Trigger::FunctionAdded]
    }

    fn priority(&self) -> Priority {
        Priority::DERIVED
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
        transaction: &mut ProjectTransaction<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisCx,
    ) -> Result<(), AnalysisError> {
        let _ = cx;

        for range in regions.ranges() {
            let address = range.start_address();
            transaction.insert_symbol(
                SymbolIndex::new(SymbolTableSelector::new(253), self.next_index),
                SymbolEntry::new(
                    address,
                    "derived_function",
                    SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
                ),
            );
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

    fn triggers(&self) -> &'static [Trigger] {
        &[Trigger::BytesWritten]
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
        transaction: &mut ProjectTransaction<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisCx,
    ) -> Result<(), AnalysisError> {
        let _ = cx;
        STORM_ANALYSER_RUNS.fetch_add(1, Ordering::SeqCst);

        let Some(address) = regions.ranges().next().map(|range| range.start_address()) else {
            return Ok(());
        };

        transaction.insert_symbol(
            SymbolIndex::new(SymbolTableSelector::new(250), 0),
            SymbolEntry::new(
                address,
                "storm_symbol",
                SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
            ),
        );
        Ok(())
    }
}

struct CancellingTestAnalyser;

impl Analyser for CancellingTestAnalyser {
    fn name(&self) -> &'static str {
        "cancelling-test"
    }

    fn triggers(&self) -> &'static [Trigger] {
        &[Trigger::BytesWritten]
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
        transaction: &mut ProjectTransaction<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisCx,
    ) -> Result<(), AnalysisError> {
        let _ = cx;
        let Some(address) = regions.ranges().next().map(|range| range.start_address()) else {
            return Err(Cancelled.into());
        };

        transaction.insert_symbol(
            SymbolIndex::new(SymbolTableSelector::new(248), 0),
            SymbolEntry::new(
                address,
                "cancel_committed_symbol",
                SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
            ),
        );

        Err(Cancelled.into())
    }
}

struct CancellationFollowUpAnalyser;

impl Analyser for CancellationFollowUpAnalyser {
    fn name(&self) -> &'static str {
        "cancellation-follow-up"
    }

    fn triggers(&self) -> &'static [Trigger] {
        &[Trigger::SymbolAdded]
    }

    fn priority(&self) -> Priority {
        Priority::DERIVED
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
        transaction: &mut ProjectTransaction<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisCx,
    ) -> Result<(), AnalysisError> {
        let _ = cx;
        let Some(address) = regions.ranges().next().map(|range| range.start_address()) else {
            return Ok(());
        };

        transaction.insert_symbol(
            SymbolIndex::new(SymbolTableSelector::new(248), 1),
            SymbolEntry::new(
                address,
                "cancel_followup_symbol",
                SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
            ),
        );

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

registry::submit! {
    AnalyserProvider::new("error-test", build_error_analyser)
}

registry::submit! {
    AnalyserProvider::new("mutating-error", build_mutating_error_analyser)
}

registry::submit! {
    AnalyserProvider::new("panicking-test", build_panicking_analyser)
}

registry::submit! {
    AnalyserProvider::new("completion-test", build_completion_analyser)
}

registry::submit! {
    AnalyserProvider::new("completion-panic-test", build_completion_panic_analyser)
}

registry::submit! {
    AnalyserProvider::new("derived-symbol", build_derived_symbol_analyser)
}

registry::submit! {
    AnalyserProvider::new("storm-test", build_storm_analyser)
}

registry::submit! {
    AnalyserProvider::new("cancelling-test", build_cancelling_analyser)
}

registry::submit! {
    AnalyserProvider::new("cancellation-follow-up", build_cancellation_follow_up_analyser)
}

registry::submit! {
    FunctionRecoveryExtension::new("test-recovery", configure_test_recovery)
}

fn project_with_test_analyser(mode: &'static str) -> Result<Project, Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut attributes = AttributeMap::new();
    attributes.set_attr(TEST_ANALYSER_ATTR, mode);
    Ok(Project::new_transient_with(&loader, attributes)?)
}

fn project_with_writable_address() -> Result<(Project, Address), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let address = project
        .segments()
        .iter_views(DEFAULT_SPACE_ID)?
        .find(|view| view.properties().is_writable() && view.size() >= 0x20)
        .map(|view| view.start())
        .ok_or_else(|| io::Error::other("fixture writable segment missing"))?;
    Ok((project, address))
}

fn trigger_test_analyser(engine: &AnalysisEngine, address: Address) -> Result<(), Box<dyn Error>> {
    let mut regions = AddressRangeSet::new();
    regions.insert(address);
    engine.schedule_ranges(Trigger::BytesWritten, regions)?;
    engine.wait_until_idle()?;
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
    let Some(entry) = imperative.entry() else {
        return Err(io::Error::other("fixture entry missing").into());
    };
    let mut recovery = loader.analysers().function_recovery()?;
    recovery.add_candidate(entry);
    AnalysisPass::analyse(&mut recovery, &mut imperative)?;

    let imperative_functions = imperative.functions().addresses().collect::<BTreeSet<_>>();
    assert!(imperative_functions.contains(&entry));

    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;
    let changes = engine.subscribe().capacity(4096).build()?;
    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;
    let mut engine_functions = BTreeSet::new();
    let function_spaces = imperative_functions
        .iter()
        .map(|address| address.space())
        .collect::<BTreeSet<_>>();
    for space in function_spaces {
        let mut cursor = None::<Address>;
        loop {
            let page =
                reader.function_page(space, cursor.map(|address| address.raw_address()), 128)?;
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
                ChangeRecord::Restored { .. } => {
                    return Err(io::Error::other("subscriber was forced to resync").into());
                }
                _ => {}
            }
        }
    }

    let flow_graph = reader
        .flow_graph(entry)?
        .ok_or_else(|| io::Error::other("fixture entry flow graph missing"))?;
    let expected_callees = flow_graph
        .targets()
        .iter()
        .filter(|target| target.kind().is_call())
        .map(|target| target.to())
        .collect::<BTreeSet<_>>();
    let callees = reader
        .callees_of(entry, None, 4096)?
        .entries()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let call_edges = reader
        .call_edges(None, 4096)?
        .entries()
        .iter()
        .filter(|edge| edge.caller() == entry)
        .map(|edge| edge.callee())
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

    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;

    let functions = assert_strict_cursor_pages::<Address, _>(|cursor| {
        reader.function_page(
            DEFAULT_SPACE_ID,
            cursor.map(|address| address.raw_address()),
            1,
        )
    })?;
    assert!(!functions.is_empty());

    let symbols =
        assert_strict_cursor_pages::<SymbolRecord, _>(|cursor| reader.symbol_page(cursor, 1))?;
    assert!(!symbols.is_empty());

    let mappings = assert_strict_cursor_pages::<MappingRecord, _>(|cursor| {
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

    engine.wait_until_idle()?;
    for (index, symbol) in inserted.iter().cloned().enumerate() {
        engine.insert_symbol(
            SymbolIndex::new(SymbolTableSelector::new(247), index),
            symbol,
        )?;
    }

    let reader = engine.query_reader()?;
    let mut expected = inserted
        .iter()
        .map(|entry| SymbolRecord::new(entry.address(), entry.symbol(), entry.properties()))
        .collect::<Vec<_>>();
    expected.sort();

    let symbols_at = assert_strict_cursor_pages::<SymbolRecord, _>(|cursor| {
        reader.symbols_at(address, cursor, 1)
    })?;
    assert_eq!(symbols_at, expected);

    let symbol_page =
        assert_strict_cursor_pages::<SymbolRecord, _>(|cursor| reader.symbol_page(cursor, 1))?;
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

    engine.wait_until_idle()?;

    let first = engine
        .create_mapping_from_builder(
            SegmentMappingBuilder::new(shared_start, 1, mapping_offset, provider_id)
                .with_properties(SegmentProperties::PERM_READ)
                .with_name("z_page_boundary_mapping"),
        )?
        .mapping();
    let second = engine
        .create_mapping_from_builder(
            SegmentMappingBuilder::new(shared_start, 1, mapping_offset, provider_id)
                .with_properties(SegmentProperties::PERM_READ | SegmentProperties::PERM_WRITE)
                .with_name("a_page_boundary_mapping"),
        )?
        .mapping();
    let third = engine
        .create_mapping_from_builder(
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

    let mappings = assert_strict_cursor_pages::<MappingRecord, _>(|cursor| {
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
fn test_chunked_function_recovery_converges() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut unchunked_project = Project::new_transient(&loader)?;
    let mut chunked_project = Project::new_transient(&loader)?;
    let mut unchunked = FunctionRecovery::new();
    let mut chunked = FunctionRecovery::new();

    chunked.set_chunk_function_limit(Some(1));

    let mut transaction = unchunked_project.transaction("unchunked recovery");
    unchunked.analyse_transaction(&mut transaction)?;
    transaction.commit()?;

    let mut regions = AddressRangeSet::new();
    if let Some(entry) = chunked_project.entry() {
        regions.insert(entry);
    }

    loop {
        let mut transaction = chunked_project.transaction("chunked recovery");
        Analyser::analyse(
            &mut chunked,
            &mut transaction,
            &regions,
            &AnalysisCx::default(),
        )?;
        transaction.commit()?;

        if !Analyser::has_pending_work(&chunked) {
            break;
        }

        regions = AddressRangeSet::new();
    }

    let unchunked_functions = unchunked_project
        .functions()
        .addresses()
        .collect::<BTreeSet<_>>();
    let chunked_functions = chunked_project
        .functions()
        .addresses()
        .collect::<BTreeSet<_>>();

    assert_eq!(chunked_functions, unchunked_functions);

    Ok(())
}

#[test]
fn test_reader_observes_progress_during_chunked_function_recovery() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut attributes = AttributeMap::new();
    attributes.set_attr(TEST_CHUNKED_RECOVERY_ATTR, true);
    let project = Project::new_transient_with(&loader, attributes)?;
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
        engine.wait_until_idle()?;
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

    engine.wait_until_idle()?;
    assert!(reader.revision().is_ok());

    drop(engine);

    assert_eq!(reader.revision(), Err(QueryError::Stopped));

    Ok(())
}

#[test]
fn test_query_readers_block_until_idle_during_concurrent_updates() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;

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
            engine.insert_symbol(
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

    assert!(project.entry().is_none());

    let hint = Address::in_default_space(0x1000u64);
    let engine = AnalysisEngine::new(project)?;
    engine.wait_until_idle()?;
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

    let error = AnalysisPass::analyse(&mut recovery, &mut project)
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
    let address = project
        .segments()
        .iter_views(DEFAULT_SPACE_ID)?
        .find(|view| view.properties().is_writable())
        .map(|view| view.start())
        .ok_or_else(|| io::Error::other("fixture writable segment missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;
    let revision = reader.revision()?;
    let changes = engine.subscribe().capacity(16).build()?;

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
fn test_engine_ensure_lifted_materialises_requested_chain() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.wait_until_idle()?;

    let mut incomplete = IncompleteFunction::new(entry);
    incomplete.push_block(IncompleteCodeBlock::new(
        entry,
        1,
        Vec::new(),
        Default::default(),
    ));
    engine.add_function(incomplete)?;
    engine.wait_until_idle()?;
    let function = {
        let reader = engine.query_reader()?;
        reader
            .function_at(entry)?
            .ok_or_else(|| io::Error::other("function ID missing after add"))?
    };

    let ensured = engine.ensure_lifted(function, IlLevel::ECodeSsa)?;

    for level in [IlLevel::PCode, IlLevel::ECode, IlLevel::ECodeSsa] {
        assert!(
            ensured
                .records()
                .contains(&ChangeRecord::LiftedMaterialised { function, level })
        );
    }

    let reader = engine.query_reader()?;
    assert!(reader.ecode(function)?.is_some());
    let ssa = reader
        .ecode_ssa(function)?
        .ok_or_else(|| io::Error::other("LIR SSA missing after ensure_lifted"))?;
    assert_eq!(ssa.header().function(), function);

    let ensured = engine.ensure_lifted(function, IlLevel::ECodeSsa)?;
    assert!(ensured.records().is_empty());

    Ok(())
}

#[test]
fn test_engine_ensure_lifted_cancelled_rolls_back_without_materialising()
-> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.wait_until_idle()?;

    let mut incomplete = IncompleteFunction::new(entry);
    incomplete.push_block(IncompleteCodeBlock::new(
        entry,
        1,
        Vec::new(),
        Default::default(),
    ));
    engine.add_function(incomplete)?;
    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;
    let function = reader
        .function_at(entry)?
        .ok_or_else(|| io::Error::other("function ID missing after add"))?;
    let revision = reader.revision()?;

    let cancellation = engine.cancellation_token();
    cancellation.cancel();

    assert!(matches!(
        engine.ensure_lifted(function, IlLevel::ECodeSsa),
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
    let ensured = engine.ensure_lifted(function, IlLevel::ECodeSsa)?;
    assert!(
        ensured
            .records()
            .contains(&ChangeRecord::LiftedMaterialised {
                function,
                level: IlLevel::PCode,
            })
    );
    assert!(engine.query_reader()?.ecode_ssa(function)?.is_some());

    Ok(())
}

#[test]
fn test_query_reader_lifted_reads_build_on_miss() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.wait_until_idle()?;

    let mut incomplete = IncompleteFunction::new(entry);
    incomplete.push_block(IncompleteCodeBlock::new(
        entry,
        1,
        Vec::new(),
        Default::default(),
    ));
    engine.add_function(incomplete)?;
    engine.wait_until_idle()?;

    let reader = engine.query_reader()?;
    let function = reader
        .function_at(entry)?
        .ok_or_else(|| io::Error::other("function ID missing after add"))?;

    assert!(reader.project()?.pcode(function)?.is_none());

    assert!(reader.pcode(function)?.is_some());
    assert!(reader.project()?.pcode(function)?.is_some());

    assert!(reader.ecode_ssa(function)?.is_some());
    assert!(reader.project()?.ecode(function)?.is_some());
    assert!(reader.project()?.ecode_ssa(function)?.is_some());

    Ok(())
}

#[test]
fn test_engine_flush_derived_references_is_idempotent() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.wait_until_idle()?;

    let mut incomplete = IncompleteFunction::new(entry);
    incomplete.push_block(IncompleteCodeBlock::new(
        entry,
        1,
        Vec::new(),
        Default::default(),
    ));
    engine.add_function(incomplete)?;
    engine.wait_until_idle()?;
    let function = {
        let reader = engine.query_reader()?;
        reader
            .function_at(entry)?
            .ok_or_else(|| io::Error::other("function ID missing after add"))?
    };

    engine.ensure_lifted(function, IlLevel::PCode)?;
    engine.flush_derived_references(function)?;
    let changes = engine.flush_derived_references(function)?;
    assert!(
        !changes
            .records()
            .iter()
            .any(|record| matches!(record, ChangeRecord::ReferencesChanged { .. }))
    );

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

    engine.wait_until_idle()?;
    let changes = engine.subscribe().capacity(16).build()?;

    assert!(engine.write_bytes(address, [0xcc, 0xdd]).is_err());
    assert!(changes.recv_timeout(Duration::from_millis(100)).is_err());

    Ok(())
}

#[test]
fn test_engine_symbol_edits_materialise_changes() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;
    let revision = reader.revision()?;
    let changes = engine.subscribe().capacity(16).build()?;
    let index = SymbolIndex::new(SymbolTableSelector::new(250), 0);
    let symbol = SymbolEntry::new(
        entry,
        "engine_symbol_edit",
        SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
    );

    let inserted = engine.insert_symbol(index, symbol.clone())?;

    assert!(inserted.revision() > revision);
    assert!(inserted.records().contains(&ChangeRecord::SymbolAdded {
        address: entry,
        symbol: symbol.symbol(),
    }));
    assert_eq!(&*changes.recv_timeout(Duration::from_secs(1))?, &inserted);
    assert!(
        reader
            .symbols_at(entry, None, 16)?
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
            .symbols_at(entry, None, 16)?
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
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let new_entry = old_entry
        .checked_add(0x40u64)
        .ok_or_else(|| io::Error::other("replacement symbol address overflow"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;
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

    engine.insert_symbol(index, old_symbol.clone())?;
    let replaced = engine.insert_symbol(index, new_symbol.clone())?;

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
            .symbols_at(old_entry, None, 16)?
            .entries()
            .iter()
            .any(|record| record.symbol() == old_symbol.symbol())
    );
    assert!(
        reader
            .symbols_at(new_entry, None, 16)?
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
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;
    let changes = engine.subscribe().capacity(16).build()?;
    assert!(reader.flow_graph(entry)?.is_some());

    let removed = engine.remove_function(entry)?;

    assert!(removed.records().iter().any(|record| matches!(
        record,
        ChangeRecord::FunctionRemoved { entry: removed_entry, .. } if *removed_entry == entry
    )));
    assert_eq!(&*changes.recv_timeout(Duration::from_secs(1))?, &removed);
    assert!(reader.flow_graph(entry)?.is_none());
    assert!(
        !reader
            .function_page(DEFAULT_SPACE_ID, None, 4096)?
            .entries()
            .contains(&entry)
    );
    assert!(reader.callees_of(entry, None, 4096)?.entries().is_empty());
    assert!(
        !reader
            .call_edges(None, 4096)?
            .entries()
            .iter()
            .any(|edge| edge.caller() == entry)
    );

    let mut function = IncompleteFunction::new(entry);
    function.push_block(IncompleteCodeBlock::new(
        entry,
        1,
        Vec::new(),
        Default::default(),
    ));
    let added = engine.add_function(function)?;

    assert!(added.records().iter().any(|record| matches!(
        record,
        ChangeRecord::FunctionAdded { entry: added_entry, .. } if *added_entry == entry
    )));
    assert_eq!(&*changes.recv_timeout(Duration::from_secs(1))?, &added);
    assert!(reader.flow_graph(entry)?.is_some());
    assert!(
        reader
            .function_page(DEFAULT_SPACE_ID, None, 4096)?
            .entries()
            .contains(&entry)
    );
    assert!(reader.callees_of(entry, None, 4096)?.entries().is_empty());

    Ok(())
}

#[test]
fn test_removing_callee_preserves_dangling_caller_edge() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;

    let functions = assert_strict_cursor_pages::<Address, _>(|cursor| {
        reader.function_page(
            DEFAULT_SPACE_ID,
            cursor.map(|address| address.raw_address()),
            1,
        )
    })?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let edges = assert_strict_cursor_pages::<CallEdge, _>(|cursor| reader.call_edges(cursor, 1))?;
    let edge = edges
        .iter()
        .copied()
        .find(|edge| {
            edge.caller() != edge.callee()
                && functions.contains(&edge.caller())
                && functions.contains(&edge.callee())
        })
        .ok_or_else(|| io::Error::other("fixture has no live non-recursive call edge"))?;

    let removed = engine.remove_function(edge.callee())?;

    assert!(removed.records().iter().any(|record| matches!(
        record,
        ChangeRecord::FunctionRemoved { entry, .. } if *entry == edge.callee()
    )));
    engine.wait_until_idle()?;

    let functions_after = assert_strict_cursor_pages::<Address, _>(|cursor| {
        reader.function_page(
            DEFAULT_SPACE_ID,
            cursor.map(|address| address.raw_address()),
            1,
        )
    })?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let callers_after =
        assert_strict_cursor_pages(|cursor| reader.callers_of(edge.callee(), cursor, 1))?;
    let edges_after =
        assert_strict_cursor_pages::<CallEdge, _>(|cursor| reader.call_edges(cursor, 1))?;

    assert!(!functions_after.contains(&edge.callee()));
    assert!(callers_after.contains(&edge.caller()));
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

    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;
    let changes = engine.subscribe().capacity(16).build()?;
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
    let created = engine.create_mapping_from_builder(
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
fn test_idle_cancel_does_not_poison_future_work() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;
    engine.cancel()?;
    engine.wait_until_idle()?;
    engine.save()?;

    assert!(!engine.cancellation_token().is_cancelled());

    Ok(())
}

#[test]
fn test_cancelling_analyser_commits_partial_progress_and_clears_followup()
-> Result<(), Box<dyn Error>> {
    let project = project_with_test_analyser("cancelling-test")?;
    let address = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;
    trigger_test_analyser(&engine, address)?;

    let reader = engine.query_reader()?;
    let symbols = reader.symbols_at(address, None, 4096)?;
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
    engine.save()?;

    Ok(())
}

#[test]
fn test_engine_constructors_accept_explicit_persistence_policy() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::with_policy(project, PersistencePolicy::Manual)?;

    engine.wait_until_idle()?;
    engine.save()?;

    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::with_capacity_and_policy(project, 8, PersistencePolicy::OnCommit)?;

    engine.wait_until_idle()?;

    Ok(())
}

#[test]
fn test_manual_save_failure_reaches_caller_and_can_retry() -> Result<(), Box<dyn Error>> {
    let _guard = SAVE_FAILURE_TEST_LOCK
        .lock()
        .map_err(|_| io::Error::other("save failure test lock poisoned"))?;
    FAIL_ENTITY_INSERTS.store(false, Ordering::SeqCst);
    let loader = Loader::from_file("tests/ls.elf")?;
    let project =
        Project::new_with_provider::<FailingSaveStorageProvider>(&loader, AttributeMap::new())?;
    let engine = AnalysisEngine::with_policy(project, PersistencePolicy::Manual)?;

    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;
    let created = engine.create_space()?;
    let revision = created.changes().revision();
    assert!(revision > Default::default());

    FAIL_ENTITY_INSERTS.store(true, Ordering::SeqCst);
    let error = engine
        .save()
        .expect_err("injected save failure should reach caller");
    FAIL_ENTITY_INSERTS.store(false, Ordering::SeqCst);

    assert!(matches!(error, EngineError::Persistence(_)));
    assert_eq!(reader.revision()?, revision);
    engine.save()?;

    Ok(())
}

#[test]
fn test_on_idle_save_failure_reaches_caller_and_can_retry() -> Result<(), Box<dyn Error>> {
    let _guard = SAVE_FAILURE_TEST_LOCK
        .lock()
        .map_err(|_| io::Error::other("save failure test lock poisoned"))?;
    FAIL_ENTITY_INSERTS.store(false, Ordering::SeqCst);
    let loader = Loader::from_file("tests/ls.elf")?;
    let project =
        Project::new_with_provider::<FailingSaveStorageProvider>(&loader, AttributeMap::new())?;
    let engine = AnalysisEngine::with_policy(project, PersistencePolicy::OnIdle)?;

    engine.wait_until_idle()?;

    FAIL_ENTITY_INSERTS.store(true, Ordering::SeqCst);
    let created = engine.create_space()?;
    assert!(created.changes().revision() > Revision::default());
    let error = engine
        .wait_until_idle()
        .expect_err("injected on-idle save failure should reach caller");
    FAIL_ENTITY_INSERTS.store(false, Ordering::SeqCst);

    assert!(matches!(error, EngineError::Persistence(_)));
    let reader = engine.query_reader()?;
    let _ = reader.revision()?;

    engine.wait_until_idle()?;
    let _ = reader.revision()?;

    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn test_on_idle_persists_revision_and_reopen_sends_restored() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("engine.fdbz");
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path.clone());

    let project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes.clone(),
    )?;
    let engine = AnalysisEngine::with_policy(project, PersistencePolicy::OnIdle)?;
    engine.wait_until_idle()?;
    let revision = engine.query_reader()?.revision()?;
    assert!(revision > Default::default());
    drop(engine);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes,
    )?;
    assert_eq!(reopened.revision(), revision);

    let engine = AnalysisEngine::with_policy(reopened, PersistencePolicy::Manual)?;
    let changes = engine.subscribe().capacity(1).build()?;
    let restored = changes.recv_timeout(Duration::from_secs(1))?;

    assert_eq!(restored.revision(), revision);
    assert_eq!(
        restored.records(),
        &[ChangeRecord::Restored { to: revision }]
    );

    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn test_manual_save_reopen_queries_saved_state_and_single_restored() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("engine-saved-state.fdbz");
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path.clone());

    let project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes.clone(),
    )?;
    let entry = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::with_policy(project, PersistencePolicy::Manual)?;

    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;
    let symbol = SymbolEntry::new(
        entry,
        "saved_engine_symbol",
        SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
    );
    let symbol_name = symbol.symbol();
    let inserted =
        engine.insert_symbol(SymbolIndex::new(SymbolTableSelector::new(254), 0), symbol)?;

    assert!(inserted.records().contains(&ChangeRecord::SymbolAdded {
        address: entry,
        symbol: symbol_name,
    }));
    assert!(
        reader
            .symbols_at(entry, None, 4096)?
            .entries()
            .iter()
            .any(|record| record.symbol() == symbol_name)
    );

    engine.save()?;
    let revision = reader.revision()?;
    drop(reader);
    drop(engine);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes,
    )?;
    assert_eq!(reopened.revision(), revision);

    let engine = AnalysisEngine::with_policy(reopened, PersistencePolicy::Manual)?;
    let changes = engine.subscribe().capacity(2).build()?;
    let restored = changes.recv_timeout(Duration::from_secs(1))?;

    assert_eq!(restored.revision(), revision);
    assert_eq!(
        restored.records(),
        &[ChangeRecord::Restored { to: revision }]
    );
    assert!(changes.recv_timeout(Duration::from_millis(100)).is_err());
    assert!(
        engine
            .query_reader()?
            .symbols_at(entry, None, 4096)?
            .entries()
            .iter()
            .any(|record| record.symbol() == symbol_name)
    );

    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn test_manual_save_reopen_reads_lifted() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("engine-il-artefacts.fdbz");
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path.clone());

    let project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes.clone(),
    )?;
    let entry = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::with_policy(project, PersistencePolicy::Manual)?;

    engine.wait_until_idle()?;
    let mut function = IncompleteFunction::new(entry);
    function.push_block(IncompleteCodeBlock::new(
        entry,
        1,
        Vec::new(),
        Default::default(),
    ));
    engine.add_function(function)?;
    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;
    let function = reader
        .function_at(entry)?
        .ok_or_else(|| io::Error::other("function ID missing after add"))?;

    engine.ensure_lifted(function, IlLevel::ECodeSsa)?;
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

    engine.save()?;
    drop(reader);
    drop(engine);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes,
    )?;
    assert_eq!(reopened.revision(), revision);

    let engine = AnalysisEngine::with_policy(reopened, PersistencePolicy::Manual)?;
    let reader = engine.query_reader()?;
    let function = reader
        .function_at(entry)?
        .ok_or_else(|| io::Error::other("reopened function ID missing"))?;

    let snapshot = reader.project()?;
    assert_eq!(snapshot.pcode(function)?.as_ref(), Some(&*pcode));
    assert_eq!(snapshot.ecode(function)?.as_ref(), Some(&*ecode));
    assert_eq!(snapshot.ecode_ssa(function)?.as_ref(), Some(&*ssa));

    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn test_on_commit_persists_update_before_result_returns() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("engine-on-commit.fdbz");
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path.clone());

    let project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes.clone(),
    )?;
    let entry = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::with_policy(project, PersistencePolicy::OnCommit)?;

    engine.wait_until_idle()?;
    let symbol = SymbolEntry::new(
        entry,
        "on_commit_symbol",
        SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
    );
    let symbol_name = symbol.symbol();
    let inserted =
        engine.insert_symbol(SymbolIndex::new(SymbolTableSelector::new(254), 1), symbol)?;
    let revision = inserted.revision();
    drop(engine);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes,
    )?;
    assert_eq!(reopened.revision(), revision);

    let engine = AnalysisEngine::with_policy(reopened, PersistencePolicy::Manual)?;
    assert!(
        engine
            .query_reader()?
            .symbols_at(entry, None, 4096)?
            .entries()
            .iter()
            .any(|record| record.symbol() == symbol_name)
    );

    Ok(())
}

#[test]
fn test_analyser_error_is_logged_without_poisoning_engine() -> Result<(), Box<dyn Error>> {
    let project = project_with_test_analyser("error-test")?;
    let address = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;
    trigger_test_analyser(&engine, address)?;
    engine.save()?;

    let messages = engine.take_run_log();
    assert!(messages.iter().any(|message| {
        message.analyser() == "error-test" && message.kind() == AnalysisMessageKind::Error
    }));

    Ok(())
}

#[test]
fn test_repeated_analyser_errors_disable_analyser() -> Result<(), Box<dyn Error>> {
    let project = project_with_test_analyser("error-test")?;
    let address = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;
    for _ in 0..DEFAULT_ANALYSER_MAX_FAILURES {
        trigger_test_analyser(&engine, address)?;
    }

    let messages = engine.take_run_log();
    assert_eq!(
        messages
            .iter()
            .filter(|message| {
                message.analyser() == "error-test" && message.kind() == AnalysisMessageKind::Error
            })
            .count(),
        DEFAULT_ANALYSER_MAX_FAILURES
    );

    trigger_test_analyser(&engine, address)?;
    assert!(engine.take_run_log().is_empty());

    Ok(())
}

#[test]
fn test_panicking_analyser_is_fatal() -> Result<(), Box<dyn Error>> {
    let project = project_with_test_analyser("panicking-test")?;
    let address = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;
    let mut regions = AddressRangeSet::new();
    regions.insert(address);
    engine.schedule_ranges(Trigger::BytesWritten, regions)?;

    let result = engine.wait_until_idle();
    assert!(matches!(
        result,
        Err(EngineError::Poisoned(_)) | Err(EngineError::Stopped)
    ));
    assert!(matches!(
        engine.poison_check(),
        Err(EngineError::Poisoned(message)) if message.contains("test analyser panic")
    ));
    assert!(matches!(
        engine.insert_symbol(
            SymbolIndex::new(SymbolTableSelector::new(249), 0),
            SymbolEntry::new(
                address,
                "after_panic_symbol",
                SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
            ),
        ),
        Err(EngineError::Poisoned(_))
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
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::with_policy(project, PersistencePolicy::OnIdle)?;

    engine.wait_until_idle()?;
    let mut regions = AddressRangeSet::new();
    regions.insert(entry);
    engine.schedule_ranges(Trigger::BytesWritten, regions)?;

    assert!(matches!(
        engine.wait_until_idle(),
        Err(EngineError::Poisoned(_)) | Err(EngineError::Stopped)
    ));
    assert!(matches!(
        engine.poison_check(),
        Err(EngineError::Poisoned(_))
    ));
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
    reopened_engine.wait_until_idle()?;
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

    let result = engine.wait_until_idle();
    assert!(matches!(
        result,
        Err(EngineError::Poisoned(_)) | Err(EngineError::Stopped)
    ));
    assert!(matches!(
        engine.poison_check(),
        Err(EngineError::Poisoned(message)) if message.contains("test completion panic")
    ));
    assert!(matches!(engine.save(), Err(EngineError::Poisoned(_))));

    Ok(())
}

#[test]
fn test_completion_hook_runs_once_after_drain() -> Result<(), Box<dyn Error>> {
    let project = project_with_test_analyser("completion-test")?;
    let address = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    let reader = engine.query_reader()?;

    engine.wait_until_idle()?;
    COMPLETION_ANALYSE_COUNT.store(0, Ordering::SeqCst);
    COMPLETION_END_COUNT.store(0, Ordering::SeqCst);
    trigger_test_analyser(&engine, address)?;

    let symbols = reader.symbols_at(address, None, 4096)?;
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
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    let changes = engine.subscribe().capacity(4096).build()?;

    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;
    let symbols = reader.symbols_at(entry, None, 4096)?;

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
    let run_scenario = |storm: bool| -> Result<(usize, Vec<SymbolRecord>), Box<dyn Error>> {
        STORM_ANALYSER_RUNS.store(0, Ordering::SeqCst);

        let project = project_with_test_analyser("storm-test")?;
        let entry = project
            .entry()
            .ok_or_else(|| io::Error::other("fixture entry missing"))?;
        let engine = AnalysisEngine::new(project)?;

        engine.wait_until_idle()?;

        if storm {
            for offset in 0..512u64 {
                let end = entry
                    .raw_address()
                    .checked_add(RawAddress::from(offset))
                    .ok_or_else(|| io::Error::other("fixture entry cannot form storm range"))?;
                let mut regions = AddressRangeSet::new();
                regions.insert_raw_range(entry.space(), entry.raw_address()..=end);
                engine.schedule_ranges(Trigger::BytesWritten, regions)?;
            }
        } else {
            let mut regions = AddressRangeSet::new();
            regions.insert(entry);
            engine.schedule_ranges(Trigger::BytesWritten, regions)?;
        }

        engine.wait_until_idle()?;

        let symbols = engine
            .query_reader()?
            .symbols_at(entry, None, 4096)?
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
fn test_analyser_error_rolls_back_without_materialising_records() -> Result<(), Box<dyn Error>> {
    let project = project_with_test_analyser("mutating-error")?;
    let address = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;
    let revision = engine.query_reader()?.revision()?;
    let changes = engine.subscribe().capacity(16).build()?;
    trigger_test_analyser(&engine, address)?;

    assert_eq!(engine.query_reader()?.revision()?, revision);
    assert!(
        engine
            .query_reader()?
            .symbols_at(address, None, 4096)?
            .entries()
            .iter()
            .all(|record| record.symbol().as_str() != "rolled_back_symbol")
    );
    assert!(changes.recv_timeout(Duration::from_millis(100)).is_err());
    assert!(engine.take_run_log().iter().any(|message| {
        message.analyser() == "mutating-error" && message.kind() == AnalysisMessageKind::Error
    }));

    Ok(())
}

#[test]
fn test_subscription_kind_filter_wakes_only_on_matching_kinds() -> Result<(), Box<dyn Error>> {
    let (project, address) = project_with_writable_address()?;
    let engine = AnalysisEngine::new(project)?;
    engine.wait_until_idle()?;

    let symbols = engine
        .subscribe()
        .kinds(ChangeKinds::SYMBOLS)
        .capacity(16)
        .build()?;

    engine.write_bytes(address, [0xccu8])?;
    assert!(symbols.recv_timeout(Duration::from_millis(100)).is_err());

    engine.insert_symbol(
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
    engine.wait_until_idle()?;

    let mut region = AddressRangeSet::new();
    region.insert_range(AddressRange::new(
        address.space(),
        address.raw_address(),
        address.raw_address(),
    ));
    let outside = address + 8u64;

    let inside_region = engine
        .subscribe()
        .kinds(ChangeKinds::BYTES_WRITTEN | ChangeKinds::SPACE_CREATED)
        .region(region)
        .capacity(16)
        .build()?;

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
    engine.wait_until_idle()?;

    let symbols = engine
        .subscribe()
        .kinds(ChangeKinds::SYMBOLS)
        .capacity(16)
        .build()?;

    for index in 0..8usize {
        engine.insert_symbol(
            SymbolIndex::new(SymbolTableSelector::new(210), index),
            SymbolEntry::new(
                address + index as u64,
                "burst_symbol",
                SymbolProperties::LOCAL,
            ),
        )?;
    }
    engine.wait_until_idle()?;

    let batch = symbols.drain().ok_or("burst produced no batch")?;
    assert!(batch.contains(ChangeKinds::SYMBOL_ADDED));
    assert_eq!(batch.records_matching(ChangeKinds::SYMBOL_ADDED).count(), 8);
    assert!(symbols.drain().is_none());

    Ok(())
}

#[test]
fn test_subscription_recv_batch_merges_queued_changes() -> Result<(), Box<dyn Error>> {
    let (project, address) = project_with_writable_address()?;
    let engine = AnalysisEngine::new(project)?;
    engine.wait_until_idle()?;

    let symbols = engine
        .subscribe()
        .kinds(ChangeKinds::SYMBOLS)
        .capacity(16)
        .build()?;

    for index in 0..4usize {
        engine.insert_symbol(
            SymbolIndex::new(SymbolTableSelector::new(211), index),
            SymbolEntry::new(
                address + index as u64,
                "batch_symbol",
                SymbolProperties::LOCAL,
            ),
        )?;
    }
    engine.wait_until_idle()?;

    let burst = symbols.recv_batch()?;
    assert_eq!(burst.records_matching(ChangeKinds::SYMBOL_ADDED).count(), 4);

    engine.insert_symbol(
        SymbolIndex::new(SymbolTableSelector::new(211), 4),
        SymbolEntry::new(address + 4u64, "batch_symbol", SymbolProperties::LOCAL),
    )?;
    engine.wait_until_idle()?;

    let single = symbols.recv_batch()?;
    assert_eq!(
        single.records_matching(ChangeKinds::SYMBOL_ADDED).count(),
        1
    );
    assert!(single.revision() > burst.revision());

    Ok(())
}

#[test]
fn test_subscription_changes_carry_provenance() -> Result<(), Box<dyn Error>> {
    let project = project_with_test_analyser("derived-symbol")?;
    let entry = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    let changes = engine.subscribe().capacity(4096).build()?;

    engine.wait_until_idle()?;

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

    engine.insert_symbol(
        SymbolIndex::new(SymbolTableSelector::new(212), 0),
        SymbolEntry::new(entry, "provenance_symbol", SymbolProperties::LOCAL),
    )?;
    engine.wait_until_idle()?;

    let update = changes
        .drain()
        .ok_or("update produced no provenance batch")?;
    assert!(update.provenance().contains("update"));
    assert!(update.provenance().includes(ChangeCategory::Agent));
    assert!(!update.provenance().includes(ChangeCategory::Engine));

    Ok(())
}

#[test]
fn test_subscription_source_filter_selects_actor() -> Result<(), Box<dyn Error>> {
    let project = project_with_test_analyser("derived-symbol")?;
    let entry = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.wait_until_idle()?;

    let analysis_only = engine
        .subscribe()
        .kinds(ChangeKinds::SYMBOLS)
        .category(ChangeCategory::Analysis)
        .capacity(4096)
        .build()?;
    let user_only = engine
        .subscribe()
        .kinds(ChangeKinds::SYMBOLS)
        .category(ChangeCategory::Agent)
        .capacity(4096)
        .build()?;
    let derived_only = engine
        .subscribe()
        .source_label("derived-symbol")
        .capacity(4096)
        .build()?;

    engine.insert_symbol(
        SymbolIndex::new(SymbolTableSelector::new(213), 0),
        SymbolEntry::new(entry, "actor_symbol", SymbolProperties::LOCAL),
    )?;
    engine.wait_until_idle()?;

    let user_batch = user_only
        .drain()
        .ok_or("user subscription missed the update")?;
    assert!(user_batch.provenance().contains("update"));
    assert!(analysis_only.drain().is_none());
    assert!(derived_only.drain().is_none());

    let target = entry + 0x40u64;
    let mut function = IncompleteFunction::new(target);
    function.push_block(IncompleteCodeBlock::new(
        target,
        1,
        Vec::new(),
        Default::default(),
    ));
    engine.add_function(function)?;
    engine.wait_until_idle()?;

    let analysis_batch = analysis_only
        .drain()
        .ok_or("analysis subscription missed analyser symbols")?;
    assert!(analysis_batch.provenance().contains("derived-symbol"));
    assert!(!analysis_batch.provenance().includes(ChangeCategory::Agent));

    let derived_batch = derived_only
        .drain()
        .ok_or("label subscription missed analyser changes")?;
    assert!(derived_batch.provenance().contains("derived-symbol"));
    assert_eq!(derived_batch.provenance().sources().count(), 1);

    assert!(user_only.drain().is_none());

    Ok(())
}

#[test]
fn test_query_reader_symbol_iterator_equals_cursor_walk() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;
    engine.wait_until_idle()?;
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
    engine.wait_until_idle()?;

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
                            reader.flow_graph(*entry)?;
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

    let first = reader.flow_graph(entries[0])?.ok_or("entry missing")?;
    let second = reader.flow_graph(entries[0])?.ok_or("entry missing")?;
    assert!(Arc::ptr_eq(&first, &second));

    Ok(())
}

#[test]
fn test_engine_recovers_derived_references() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;
    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;

    let callee = reader
        .call_edges(None, 4096)?
        .entries()
        .iter()
        .map(|edge| edge.callee())
        .next()
        .ok_or_else(|| io::Error::other("no call edges recovered"))?;

    let incoming = reader
        .incoming_references(callee)
        .collect::<Result<Vec<_>, _>>()?;
    let call_reference = incoming
        .iter()
        .find(|reference| reference.is_call())
        .ok_or_else(|| io::Error::other("no incoming call reference at callee"))?;
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
    let project = Project::new_transient_with(&loader, attributes)?;
    let engine = AnalysisEngine::new(project)?;
    engine.wait_until_idle()?;

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
            "switch at {branch:#x}: model={:?}, evidence={:?}, confidence={}, default={}",
            switch.switch().model(),
            switch.switch().evidence(),
            switch.confidence(),
            switch.has_default(),
        );
    }
    let record = switches
        .iter()
        .find(|record| record.case_count() >= 2)
        .ok_or_else(|| io::Error::other("no multi-case switch recovered from ls.elf"))?;
    let switch = record.switch();

    assert!(
        !switch.function().is_invalid(),
        "recovered switch must resolve its owning function"
    );
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
    let project = Project::new_transient_with(&loader, attributes)?;
    let engine = AnalysisEngine::new(project)?;
    engine.wait_until_idle()?;

    let reader = engine.query_reader()?;
    let switches = reader.switches().collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        switches
            .iter()
            .map(|record| record.branch().raw_address())
            .collect::<BTreeSet<_>>()
            .len(),
        94
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

    for (address, count) in [(0x46df4u64, 33usize), (0x489c8, 6), (0x53d98, 8)] {
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
            assert!(block.instructions().iter().all(|instruction| {
                !(0x3c318..0x3c330).contains(&instruction.address().offset())
            }));
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
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.wait_until_idle()?;

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
    switch.mark_override();

    let changes = engine.add_switch(switch)?;
    assert!(changes.contains(ChangeKinds::SWITCH_ADDED));

    let record = engine
        .query_reader()?
        .switch_at(entry)?
        .ok_or_else(|| io::Error::other("switch missing after add"))?;
    assert!(record.switch().is_override());
    assert!(matches!(record.switch().model(), SwitchModel::Absolute(_)));
    assert!(
        !record.switch().function().is_invalid(),
        "owning function should be resolved from the branch"
    );

    let outgoing = engine
        .query_reader()?
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
    assert!(engine.query_reader()?.switch_at(entry)?.is_none());

    Ok(())
}

#[test]
fn test_engine_asserted_reference_round_trips() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.wait_until_idle()?;

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
        .references_to(to, None, 64)?
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
