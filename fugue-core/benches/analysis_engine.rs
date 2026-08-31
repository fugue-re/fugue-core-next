use std::alloc::{GlobalAlloc, Layout, System};
use std::error::Error;
use std::hint::black_box;
use std::ops::Bound;
#[cfg(feature = "sqlite")]
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use fugue_core::analysis::control::CancellationToken;
#[cfg(feature = "sqlite")]
use fugue_core::attributes;
use fugue_core::engine::{AnalysisEngine, ProjectUpdate, ProjectView};
use fugue_core::il::common::{
    IlBlockId, IlBlockProperties, IlDominance, IlDominanceEvent, IlEdgeKinds, IlGraphBuilder,
    IlIndexRange,
};
use fugue_core::il::ecode::{ECodeIr, ECodeOpcode};
use fugue_core::il::mcode::ECodeToMCode;
use fugue_core::ir::{
    Address, AddressRange, AddressRangeSet, IncompleteCodeBlock, IncompleteFunction, Reference,
    ReferenceProperties, SymbolEntry, SymbolIndex, SymbolProperties, SymbolTableSelector,
};
use fugue_core::loader::{Loadable, Loader};
use fugue_core::project::{ChangeKinds, ChangeSource, Project};
use fugue_core::queries::{Dependency, QueryReader, Term};
#[cfg(feature = "sqlite")]
use fugue_core::storage::DefaultPersistentEntityStorage;
#[cfg(feature = "sqlite")]
use fugue_core::storage::DefaultPersistentSegmentStorage;
#[cfg(feature = "sqlite")]
use fugue_core::storage::PersistentStorageProvider;
use fugue_core::storage::{
    BufferedEntityWriter, DEFAULT_SPACE_ID, EntityBytesReadTransaction,
    EntityBytesWriteTransaction, EntityStorage, EntityStorageError, EntityStorageProvider,
    EntityStorageProviderFromLoadable, InMemoryEntityStorage, InMemorySegmentStorage, PERSISTENT,
    SegmentProperties, SegmentStorage, StorageContainer, StoragePersistence, StorageProvider,
    StorageProviderError,
};
#[cfg(feature = "sqlite")]
use fugue_core::types::ATTRIBUTE_PROJECT_PATH;
use fugue_core::types::{AttributeMap, BytesOrSlice};
const SYNTHETIC_SYMBOLS: usize = 1024;
const SYNTHETIC_FUNCTIONS: usize = 256;
const LARGE_FUNCTION_BLOCKS: usize = 4096;
const DOMINANCE_BRANCHES: usize = 512;
const DOMINANCE_LIVE_DOMAINS: usize = 256;
const PAGE_LIMIT: usize = 64;
const QUERY_REPETITIONS: usize = 128;
const REPRESENTATIVE_FIXTURE: &str = "tests/libipmi.so";
const REPEATED_FUNCTION_REPLACEMENTS: usize = 8193;
const SEGMENT_MAPPING_REMOVALS: usize = 4096;
const SEGMENT_MAPPING_SIZE: u64 = 0x1000;

struct MeasuringAllocator;

static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static ENTITY_READS: AtomicU64 = AtomicU64::new(0);
static ENTITY_WRITES: AtomicU64 = AtomicU64::new(0);
static LIVE_BYTES: AtomicU64 = AtomicU64::new(0);
static PEAK_LIVE_BYTES: AtomicU64 = AtomicU64::new(0);

#[global_allocator]
static ALLOCATOR: MeasuringAllocator = MeasuringAllocator;

impl MeasuringAllocator {
    fn grow(size: usize) {
        let live = LIVE_BYTES.fetch_add(size as u64, Ordering::Relaxed) + size as u64;
        PEAK_LIVE_BYTES.fetch_max(live, Ordering::Relaxed);
    }

    fn shrink(size: usize) {
        LIVE_BYTES.fetch_sub(size as u64, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for MeasuringAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let allocation = unsafe { System.alloc(layout) };
        if !allocation.is_null() {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            ALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            Self::grow(layout.size());
        }
        allocation
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let allocation = unsafe { System.alloc_zeroed(layout) };
        if !allocation.is_null() {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            ALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            Self::grow(layout.size());
        }
        allocation
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        Self::shrink(layout.size());
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let allocation = unsafe { System.realloc(pointer, layout, size) };
        if !allocation.is_null() {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            ALLOCATED_BYTES.fetch_add(size as u64, Ordering::Relaxed);
            if size >= layout.size() {
                Self::grow(size - layout.size());
            } else {
                Self::shrink(layout.size() - size);
            }
        }
        allocation
    }
}

#[derive(Clone, Copy)]
struct AllocationSnapshot {
    allocations: u64,
    bytes: u64,
    live_bytes: u64,
    peak_live_bytes: u64,
}

impl AllocationSnapshot {
    fn begin() -> Self {
        let live_bytes = LIVE_BYTES.load(Ordering::Relaxed);
        PEAK_LIVE_BYTES.store(live_bytes, Ordering::Relaxed);
        Self {
            allocations: ALLOCATIONS.load(Ordering::Relaxed),
            bytes: ALLOCATED_BYTES.load(Ordering::Relaxed),
            live_bytes,
            peak_live_bytes: live_bytes,
        }
    }

    fn capture() -> Self {
        Self {
            allocations: ALLOCATIONS.load(Ordering::Relaxed),
            bytes: ALLOCATED_BYTES.load(Ordering::Relaxed),
            live_bytes: LIVE_BYTES.load(Ordering::Relaxed),
            peak_live_bytes: PEAK_LIVE_BYTES.load(Ordering::Relaxed),
        }
    }

    fn since(self, previous: Self) -> Self {
        Self {
            allocations: self.allocations.saturating_sub(previous.allocations),
            bytes: self.bytes.saturating_sub(previous.bytes),
            live_bytes: self.live_bytes.saturating_sub(previous.live_bytes),
            peak_live_bytes: self.peak_live_bytes.saturating_sub(previous.live_bytes),
        }
    }
}

#[derive(Clone, Copy)]
struct EntityAccessSnapshot {
    reads: u64,
    writes: u64,
}

impl EntityAccessSnapshot {
    fn capture() -> Self {
        Self {
            reads: ENTITY_READS.load(Ordering::Relaxed),
            writes: ENTITY_WRITES.load(Ordering::Relaxed),
        }
    }

    fn since(self, previous: Self) -> Self {
        Self {
            reads: self.reads.saturating_sub(previous.reads),
            writes: self.writes.saturating_sub(previous.writes),
        }
    }
}

#[derive(Default)]
struct CountingEntityStorage {
    inner: InMemoryEntityStorage,
}

impl EntityStorageProviderFromLoadable for CountingEntityStorage {
    fn from_loadable(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self {
            inner: InMemoryEntityStorage::from_loadable(loadable, attributes)?,
        })
    }
}

impl EntityStorageProvider for CountingEntityStorage {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        ENTITY_READS.fetch_add(1, Ordering::Relaxed);
        self.inner.get(key)
    }

    fn get_as<F, T>(&self, key: &[u8], f: F) -> Result<Option<T>, EntityStorageError>
    where
        F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
    {
        ENTITY_READS.fetch_add(1, Ordering::Relaxed);
        self.inner.get_as(key, f)
    }

    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        ENTITY_WRITES.fetch_add(1, Ordering::Relaxed);
        self.inner.insert(key, value)
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        ENTITY_WRITES.fetch_add(1, Ordering::Relaxed);
        self.inner.remove(key)
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        ENTITY_READS.fetch_add(1, Ordering::Relaxed);
        self.inner.contains(key)
    }

    fn iter_prefix_keys(
        &self,
        prefix: &[u8],
    ) -> Result<
        Box<dyn Iterator<Item = Result<BytesOrSlice<'_>, EntityStorageError>> + '_>,
        EntityStorageError,
    > {
        ENTITY_READS.fetch_add(1, Ordering::Relaxed);
        self.inner.iter_prefix_keys(prefix)
    }

    fn iter_prefix(
        &self,
        prefix: &[u8],
    ) -> Result<
        Box<
            dyn Iterator<Item = Result<(BytesOrSlice<'_>, BytesOrSlice<'_>), EntityStorageError>>
                + '_,
        >,
        EntityStorageError,
    > {
        ENTITY_READS.fetch_add(1, Ordering::Relaxed);
        self.inner.iter_prefix(prefix)
    }

    fn iter_range(
        &self,
        prefix: &[u8],
        start: Bound<&[u8]>,
    ) -> Result<
        Box<
            dyn Iterator<Item = Result<(BytesOrSlice<'_>, BytesOrSlice<'_>), EntityStorageError>>
                + '_,
        >,
        EntityStorageError,
    > {
        ENTITY_READS.fetch_add(1, Ordering::Relaxed);
        self.inner.iter_range(prefix, start)
    }

    fn iter_prefix_as<'a, F, T>(
        &'a self,
        prefix: &[u8],
        f: F,
    ) -> Result<Box<dyn Iterator<Item = Result<T, EntityStorageError>> + 'a>, EntityStorageError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<T, EntityStorageError> + 'a,
        T: 'a,
    {
        ENTITY_READS.fetch_add(1, Ordering::Relaxed);
        self.inner.iter_prefix_as(prefix, f)
    }

    fn read_transaction(&self) -> Result<EntityBytesReadTransaction<'_>, EntityStorageError> {
        Err(EntityStorageError::unsupported_with(
            "counting storage does not support read transactions",
        ))
    }

    fn write_transaction(&self) -> Result<EntityBytesWriteTransaction<'_>, EntityStorageError> {
        Ok(Box::new(BufferedEntityWriter::new(self)))
    }

    fn persistence(&self) -> StoragePersistence {
        PERSISTENT
    }
}

struct CountingStorageProvider;

impl StorageProvider for CountingStorageProvider {
    fn from_loadable(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<StorageContainer, StorageProviderError> {
        let entities =
            EntityStorage::new(CountingEntityStorage::from_loadable(loadable, attributes)?);
        let (segments, image_resolution) =
            SegmentStorage::from_loadable::<InMemorySegmentStorage>(loadable, attributes)?
                .into_parts();
        Ok(StorageContainer::from_parts(entities, segments)?
            .with_image_resolution(image_resolution))
    }

    fn from_storage(
        path: impl AsRef<std::path::Path>,
        attributes: &mut AttributeMap,
    ) -> Result<StorageContainer, StorageProviderError> {
        let _ = path;
        let _ = attributes;
        Err(StorageProviderError::NotAStandaloneProject)
    }
}

struct BenchResult {
    allocated_bytes: u64,
    allocations: u64,
    entity_reads: u64,
    entity_writes: u64,
    name: &'static str,
    elapsed: Duration,
    items: usize,
    p50_latency: Option<Duration>,
    p99_latency: Option<Duration>,
    peak_live_bytes: u64,
    retained_bytes: u64,
    rss_kib: Option<u64>,
}

struct BenchmarkRenameState {
    values: Vec<u64>,
    undo: Vec<(usize, u64)>,
}

impl BenchmarkRenameState {
    fn new(domains: usize) -> Self {
        Self {
            values: vec![0; domains],
            undo: Vec::new(),
        }
    }

    fn checkpoint(&self) -> usize {
        self.undo.len()
    }

    fn rename_for(&mut self, block: IlBlockId) {
        for (index, value) in self.values.iter_mut().enumerate() {
            self.undo.push((index, *value));
            *value = block.index() as u64 + 1;
        }
    }

    fn rollback(&mut self, checkpoint: usize) {
        while self.undo.len() > checkpoint {
            let (index, value) = self
                .undo
                .pop()
                .expect("a benchmark checkpoint is within the undo log");
            self.values[index] = value;
        }
    }

    fn checksum(&self) -> u64 {
        self.values.iter().copied().sum()
    }
}

impl BenchResult {
    fn new(
        name: &'static str,
        elapsed: Duration,
        items: usize,
        allocations: AllocationSnapshot,
        entities: EntityAccessSnapshot,
    ) -> Self {
        Self {
            allocated_bytes: allocations.bytes,
            allocations: allocations.allocations,
            entity_reads: entities.reads,
            entity_writes: entities.writes,
            name,
            elapsed,
            items,
            p50_latency: None,
            p99_latency: None,
            peak_live_bytes: allocations.peak_live_bytes,
            retained_bytes: allocations.live_bytes,
            rss_kib: current_rss_kib(),
        }
    }

    fn with_latencies(
        name: &'static str,
        elapsed: Duration,
        items: usize,
        samples: &[Duration],
        allocations: AllocationSnapshot,
        entities: EntityAccessSnapshot,
    ) -> Self {
        Self {
            allocated_bytes: allocations.bytes,
            allocations: allocations.allocations,
            entity_reads: entities.reads,
            entity_writes: entities.writes,
            name,
            elapsed,
            items,
            p50_latency: percentile(samples, 50),
            p99_latency: percentile(samples, 99),
            peak_live_bytes: allocations.peak_live_bytes,
            retained_bytes: allocations.live_bytes,
            rss_kib: current_rss_kib(),
        }
    }

    fn print(&self) {
        let rss = self
            .rss_kib
            .map(|rss| rss.to_string())
            .unwrap_or_else(|| "unknown".to_owned());
        let p50 = self
            .p50_latency
            .map(|latency| latency.as_nanos().to_string())
            .unwrap_or_else(|| "none".to_owned());
        let p99 = self
            .p99_latency
            .map(|latency| latency.as_nanos().to_string())
            .unwrap_or_else(|| "none".to_owned());
        println!(
            "bench={},elapsed_ns={},items={},allocations={},allocated_bytes={},peak_live_bytes={},retained_bytes={},entity_reads={},entity_writes={},p50_latency_ns={p50},p99_latency_ns={p99},rss_kib={rss}",
            self.name,
            self.elapsed.as_nanos(),
            self.items,
            self.allocations,
            self.allocated_bytes,
            self.peak_live_bytes,
            self.retained_bytes,
            self.entity_reads,
            self.entity_writes,
        );
    }
}

fn percentile(samples: &[Duration], percentile: usize) -> Option<Duration> {
    if samples.is_empty() {
        return None;
    }

    let mut samples = samples.to_vec();
    samples.sort_unstable();
    let index = ((samples.len() - 1) * percentile) / 100;
    samples.get(index).copied()
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/ls.elf")
}

fn load_project() -> Result<Project, Box<dyn Error>> {
    let loader = Loader::from_file(fixture_path())?;
    Ok(Project::new_transient(&loader)?)
}

fn load_counting_project() -> Result<Project, Box<dyn Error>> {
    let loader = Loader::from_file(fixture_path())?;
    Ok(Project::new_with_provider::<CountingStorageProvider>(
        &loader,
        AttributeMap::new(),
    )?)
}

fn load_engine() -> Result<(AnalysisEngine, Address), Box<dyn Error>> {
    let project = load_project()?;
    let entry = project
        .entry_point()
        .ok_or_else(|| std::io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;
    Ok((engine, entry))
}

fn measure<T, F>(name: &'static str, f: F) -> Result<(BenchResult, T), Box<dyn Error>>
where
    F: FnOnce() -> Result<(T, usize), Box<dyn Error>>,
{
    let allocations = AllocationSnapshot::begin();
    let entities = EntityAccessSnapshot::capture();
    let start = Instant::now();
    let (value, items) = f()?;
    let allocations = AllocationSnapshot::capture().since(allocations);
    let entities = EntityAccessSnapshot::capture().since(entities);
    Ok((
        BenchResult::new(name, start.elapsed(), items, allocations, entities),
        value,
    ))
}

fn measure_repeated<T, F>(name: &'static str, mut f: F) -> Result<(BenchResult, T), Box<dyn Error>>
where
    F: FnMut() -> Result<(T, usize), Box<dyn Error>>,
{
    let allocations = AllocationSnapshot::begin();
    let entities = EntityAccessSnapshot::capture();
    let start = Instant::now();
    let (mut value, mut items) = f()?;
    for _ in 1..QUERY_REPETITIONS {
        let (next, next_items) = f()?;
        value = next;
        items += next_items;
    }
    let allocations = AllocationSnapshot::capture().since(allocations);
    let entities = EntityAccessSnapshot::capture().since(entities);
    Ok((
        BenchResult::new(name, start.elapsed(), items, allocations, entities),
        value,
    ))
}

fn current_rss_kib() -> Option<u64> {
    let pid = std::process::id().to_string();
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", pid.as_str()])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    String::from_utf8(output.stdout)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

fn add_symbols(
    engine: &AnalysisEngine,
    entry: Address,
    count: usize,
) -> Result<(), Box<dyn Error>> {
    for index in 0..count {
        let address = entry
            .checked_add(index as u64)
            .ok_or_else(|| std::io::Error::other("synthetic symbol address overflow"))?;
        let symbol = format!("bench_symbol_{index}");
        engine.add_symbol(
            SymbolIndex::new(SymbolTableSelector::new(240), index),
            SymbolEntry::new(address, symbol, SymbolProperties::LOCAL),
        )?;
    }

    engine.analyse()?;
    Ok(())
}

fn add_empty_function(engine: &AnalysisEngine, entry: Address) -> Result<(), Box<dyn Error>> {
    let mut function = IncompleteFunction::new(entry);
    function.push_block(IncompleteCodeBlock::new(
        entry,
        1,
        Vec::new(),
        Default::default(),
    ));
    engine.add_function(function)?;
    Ok(())
}

fn function_updates(base: Address, count: usize) -> Result<Vec<ProjectUpdate>, Box<dyn Error>> {
    let mut updates = Vec::with_capacity(count);
    for index in 0..count {
        let entry = base
            .checked_add(index as u64)
            .ok_or_else(|| std::io::Error::other("synthetic function address overflow"))?;
        let mut function = IncompleteFunction::new(entry);
        function.push_block(IncompleteCodeBlock::new(
            entry,
            1,
            Vec::new(),
            Default::default(),
        ));
        updates.push(ProjectUpdate::add_function(function));
    }
    Ok(updates)
}

fn large_function(
    entry: Address,
    blocks: usize,
    changed_from: usize,
) -> Result<IncompleteFunction, Box<dyn Error>> {
    let mut function = IncompleteFunction::new(entry);
    for index in 0..blocks {
        let address = entry
            .checked_add((index as u64) * 0x10)
            .ok_or_else(|| std::io::Error::other("synthetic block address overflow"))?;
        let length = if index >= changed_from { 2 } else { 1 };
        function.push_block(IncompleteCodeBlock::new(
            address,
            length,
            Vec::new(),
            Default::default(),
        ));
    }
    Ok(function)
}

fn page_symbols(reader: &QueryReader) -> Result<usize, Box<dyn Error>> {
    let mut cursor = None;
    let mut count = 0usize;

    loop {
        let page = reader.symbol_page(cursor, PAGE_LIMIT)?;
        count += page.entries().len();

        let Some(next) = page.next_cursor().copied() else {
            return Ok(count);
        };

        cursor = Some(next);
    }
}

fn page_mappings(reader: &QueryReader) -> Result<usize, Box<dyn Error>> {
    let mut cursor = None;
    let mut count = 0usize;

    loop {
        let page = reader.mapping_page(DEFAULT_SPACE_ID, cursor, PAGE_LIMIT)?;
        count += page.entries().len();

        let Some(next) = page.next_cursor().copied() else {
            return Ok(count);
        };

        cursor = Some(next);
    }
}

fn page_call_edges(reader: &QueryReader) -> Result<usize, Box<dyn Error>> {
    let mut cursor = None;
    let mut count = 0usize;

    loop {
        let page = reader.call_edge_page(cursor, PAGE_LIMIT)?;
        count += page.entries().len();

        let Some(next) = page.next_cursor().copied() else {
            return Ok(count);
        };

        cursor = Some(next);
    }
}

fn bench_initial_analysis(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (result, engine) = measure("initial_analysis_startup", || {
        let project = load_project()?;
        let engine = AnalysisEngine::new(project)?;
        engine.analyse()?;
        Ok((engine, 1))
    })?;

    let reader = engine.query_reader()?;
    black_box(reader.revision()?);
    results.push(result);
    Ok(())
}

fn bench_representative_analysis(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (load, project) = measure("representative_project_load", || {
        let loader = Loader::from_file(REPRESENTATIVE_FIXTURE)?;
        let project = Project::new_transient(&loader)?;
        Ok((project, 1))
    })?;
    results.push(load);

    let (result, engine) = measure("representative_arm_analysis", || {
        let engine = AnalysisEngine::new(project)?;
        engine.analyse()?;
        Ok((engine, 1))
    })?;

    let entry = engine
        .query_reader()?
        .project()?
        .entry_point()
        .ok_or_else(|| std::io::Error::other("representative fixture entry missing"))?;
    black_box(engine.query_reader()?.revision()?);
    results.push(result);

    let batch_base = Address::new(entry.space(), 0xf000_0000u64);
    let (output, updates) = measure("representative_function_batch_output", || {
        let updates = function_updates(batch_base, SYNTHETIC_FUNCTIONS)?;
        Ok((updates, SYNTHETIC_FUNCTIONS))
    })?;
    results.push(output);

    let (admission, _) = measure("representative_function_batch_admission", || {
        engine.apply_updates(ChangeSource::engine("benchmark"), updates)?;
        Ok(((), SYNTHETIC_FUNCTIONS))
    })?;
    results.push(admission);
    engine.analyse()?;
    Ok(())
}

fn branch_heavy_dominance() -> Result<(IlDominance, IlBlockId), Box<dyn Error>> {
    let mut builder = IlGraphBuilder::new();
    let entry = builder.push_block(IlIndexRange::EMPTY, IlBlockProperties::ENTRY)?;
    for _ in 0..DOMINANCE_BRANCHES {
        let child = builder.push_block(IlIndexRange::EMPTY, IlBlockProperties::EXIT)?;
        builder.add_successor(entry, child, IlEdgeKinds::UNCONDITIONAL)?;
    }
    let graph = builder.build(0)?;
    Ok((
        IlDominance::from_blocks(graph.blocks(), graph.successors(), entry),
        entry,
    ))
}

fn bench_dominance_traversal(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (dominance, entry) = branch_heavy_dominance()?;
    let (rollback, checksum) = measure("dominance_branch_rollback", || {
        let mut state = BenchmarkRenameState::new(DOMINANCE_LIVE_DOMAINS);
        let mut checkpoints = Vec::new();
        for event in dominance.events_from(entry) {
            match event {
                IlDominanceEvent::Enter(block) => {
                    checkpoints.push(state.checkpoint());
                    state.rename_for(block);
                }
                IlDominanceEvent::Exit(_) => {
                    state.rollback(
                        checkpoints
                            .pop()
                            .expect("each dominance exit follows a matching entry"),
                    );
                }
            }
        }
        Ok((state.checksum(), DOMINANCE_BRANCHES))
    })?;
    black_box(checksum);
    results.push(rollback);

    let (cloned, checksum) = measure("dominance_branch_clone_reference", || {
        let mut stack = vec![(entry, vec![0u64; DOMINANCE_LIVE_DOMAINS])];
        let mut checksum = 0u64;
        while let Some((block, mut state)) = stack.pop() {
            state.fill(block.index() as u64 + 1);
            checksum = checksum.wrapping_add(state.iter().copied().sum::<u64>());
            for child in dominance.children_for(block).iter().rev() {
                stack.push((*child, state.clone()));
            }
        }
        Ok((checksum, DOMINANCE_BRANCHES))
    })?;
    black_box(checksum);
    results.push(cloned);
    Ok(())
}

fn bench_call_heavy_mcode(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (engine, _) = load_engine()?;
    let reader = engine.query_reader()?;
    let project = reader.project()?;
    let arch = project.arch().clone();
    let platform = project.platform().clone();
    let functions = project
        .functions()
        .iter()
        .map(|function| function.id())
        .collect::<Vec<_>>();
    drop(project);

    let mut selected = None;
    for function in functions {
        let Some(source) = reader.lifted::<ECodeIr>(function)? else {
            continue;
        };
        let calls = source
            .ops()
            .iter()
            .filter(|operation| {
                matches!(
                    operation.opcode(),
                    ECodeOpcode::Call | ECodeOpcode::CallIndirect
                )
            })
            .count();
        if selected
            .as_ref()
            .is_none_or(|(_, selected_calls)| calls > *selected_calls)
        {
            selected = Some((source, calls));
        }
    }
    let (source, calls) = selected
        .filter(|(_, calls)| *calls != 0)
        .ok_or_else(|| std::io::Error::other("fixture contains no ECode calls"))?;
    let mut transformer = ECodeToMCode::default();
    black_box(transformer.transform(
        &source,
        &arch,
        &platform,
        None,
        &CancellationToken::default(),
    )?);

    let (result, mcode) = measure("mcode_call_heavy_transform", || {
        let mcode = transformer.transform(
            &source,
            &arch,
            &platform,
            None,
            &CancellationToken::default(),
        )?;
        Ok((mcode, calls))
    })?;
    black_box(mcode);
    results.push(result);
    Ok(())
}

fn bench_repeated_flow_targets(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (engine, entry) = load_engine()?;
    let reader = engine.query_reader()?;
    let disjoint_entry = entry
        .checked_add(0x30_000u64)
        .ok_or_else(|| std::io::Error::other("disjoint function address overflow"))?;

    black_box(reader.flow_targets(entry)?);
    let (hit, _) = measure_repeated("repeated_flow_targets_query_hit", || {
        black_box(reader.flow_targets(entry)?);
        Ok(((), 1))
    })?;
    results.push(hit);

    add_empty_function(&engine, entry)?;
    engine.analyse()?;
    let (after_same_entry, _) = measure("flow_targets_after_same_entry_edit", || {
        black_box(reader.flow_targets(entry)?);
        Ok(((), 1))
    })?;
    results.push(after_same_entry);

    add_empty_function(&engine, disjoint_entry)?;
    engine.analyse()?;
    let (after_disjoint_range, _) =
        measure_repeated("flow_targets_after_disjoint_range_edit", || {
            black_box(reader.flow_targets(entry)?);
            Ok(((), 1))
        })?;
    results.push(after_disjoint_range);

    engine.add_symbol(
        SymbolIndex::new(SymbolTableSelector::new(241), 0),
        SymbolEntry::new(entry, "bench_unrelated_symbol", SymbolProperties::LOCAL),
    )?;
    engine.analyse()?;

    let (after_unrelated_kind, _) =
        measure_repeated("flow_targets_after_unrelated_kind_edit", || {
            black_box(reader.flow_targets(entry)?);
            Ok(((), 1))
        })?;
    results.push(after_unrelated_kind);
    Ok(())
}

fn bench_page_scans(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (engine, entry) = load_engine()?;
    add_symbols(&engine, entry, SYNTHETIC_SYMBOLS)?;
    let reader = engine.query_reader()?;

    let (symbols, _) = measure_repeated("symbol_page_scan", || {
        let count = page_symbols(&reader)?;
        Ok(((), count))
    })?;
    results.push(symbols);

    let (mappings, _) = measure_repeated("mapping_page_scan", || {
        let count = page_mappings(&reader)?;
        Ok(((), count))
    })?;
    results.push(mappings);
    Ok(())
}

fn bench_call_graph_pages(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (engine, entry) = load_engine()?;
    let reader = engine.query_reader()?;

    let (edges, edge_count) = measure_repeated("call_graph_page_scan", || {
        let count = page_call_edges(&reader)?;
        Ok((count, count))
    })?;
    results.push(edges);

    let (callees, _) = measure_repeated("call_graph_callees_page", || {
        let page = reader.callee_page(entry, None, PAGE_LIMIT)?;
        Ok(((), page.entries().len()))
    })?;
    results.push(callees);

    if edge_count > 0 {
        let first = reader
            .call_edge_page(None, 1)?
            .entries()
            .first()
            .copied()
            .ok_or_else(|| std::io::Error::other("call edge disappeared"))?;
        let (callers, _) = measure_repeated("call_graph_callers_page", || {
            let page = reader.caller_page(first.target(), None, PAGE_LIMIT)?;
            Ok(((), page.entries().len()))
        })?;
        results.push(callers);
    }

    Ok(())
}

fn bench_single_function_edit(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (engine, entry) = load_engine()?;
    let reader = engine.query_reader()?;
    let new_entry = entry
        .checked_add(0x10_000u64)
        .ok_or_else(|| std::io::Error::other("synthetic function address overflow"))?;

    let (edit, _) = measure("single_function_edit", || {
        add_empty_function(&engine, new_entry)?;
        engine.analyse()?;
        Ok(((), 1))
    })?;
    results.push(edit);

    let (related, _) = measure("single_function_edit_related_query", || {
        black_box(reader.flow_targets(new_entry)?);
        Ok(((), 1))
    })?;
    results.push(related);

    let (unrelated, _) = measure_repeated("single_function_edit_unrelated_query", || {
        black_box(reader.symbol_page(None, PAGE_LIMIT)?);
        Ok(((), PAGE_LIMIT))
    })?;
    results.push(unrelated);
    Ok(())
}

fn bench_large_function_replacement(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let entry = Address::from(0x1000_0000u64);

    let mut repeated_project = load_counting_project()?;
    let (repeated, _) = measure("repeated_function_replacement_one_admission", || {
        let mut transaction =
            repeated_project.transaction("repeated function replacement benchmark");
        for _ in 0..REPEATED_FUNCTION_REPLACEMENTS {
            transaction.add_function(large_function(entry, 1, 1)?)?;
        }
        black_box(transaction.commit()?);
        Ok(((), REPEATED_FUNCTION_REPLACEMENTS))
    })?;
    results.push(repeated);

    let mut insertion_project = load_counting_project()?;
    let (insertion, _) = measure("large_function_insert", || {
        let function = large_function(entry, LARGE_FUNCTION_BLOCKS, LARGE_FUNCTION_BLOCKS)?;
        let mut transaction = insertion_project.transaction("large function insertion benchmark");
        transaction.add_function(function)?;
        transaction.commit()?;
        Ok(((), LARGE_FUNCTION_BLOCKS))
    })?;
    results.push(insertion);

    let mut replacement_project = load_counting_project()?;
    let mut transaction = replacement_project.transaction("large function replacement baseline");
    transaction.add_function(large_function(
        entry,
        LARGE_FUNCTION_BLOCKS,
        LARGE_FUNCTION_BLOCKS,
    )?)?;
    transaction.commit()?;
    let (replacement, _) = measure("large_function_replace", || {
        let function = large_function(entry, LARGE_FUNCTION_BLOCKS, 0)?;
        let mut transaction =
            replacement_project.transaction("large function replacement benchmark");
        transaction.add_function(function)?;
        transaction.commit()?;
        Ok(((), LARGE_FUNCTION_BLOCKS))
    })?;
    results.push(replacement);

    let mut shared_project = load_counting_project()?;
    let mut transaction = shared_project.transaction("shared function replacement baseline");
    transaction.add_function(large_function(
        entry,
        LARGE_FUNCTION_BLOCKS,
        LARGE_FUNCTION_BLOCKS,
    )?)?;
    transaction.commit()?;
    let changed_from = LARGE_FUNCTION_BLOCKS - (LARGE_FUNCTION_BLOCKS / 100).max(1);
    let (mostly_shared, _) = measure("large_function_replace_mostly_shared", || {
        let function = large_function(entry, LARGE_FUNCTION_BLOCKS, changed_from)?;
        let mut transaction = shared_project.transaction("shared function replacement benchmark");
        transaction.add_function(function)?;
        transaction.commit()?;
        Ok(((), LARGE_FUNCTION_BLOCKS))
    })?;
    results.push(mostly_shared);

    Ok(())
}

fn writable_region(reader: &QueryReader) -> Result<(Address, u64), Box<dyn Error>> {
    let mut cursor = None;

    loop {
        let page = reader.mapping_page(DEFAULT_SPACE_ID, cursor, PAGE_LIMIT)?;
        if let Some(record) = page
            .entries()
            .iter()
            .find(|record| record.properties().is_writable() && record.size() >= 0x1000)
        {
            return Ok((record.start(), record.size()));
        }

        let Some(next) = page.next_cursor().copied() else {
            return Err(std::io::Error::other("no writable mapping in fixture").into());
        };
        cursor = Some(next);
    }
}

fn bench_byte_writes(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (engine, _) = load_engine()?;
    let reader = engine.query_reader()?;
    let (address, available) = writable_region(&reader)?;

    let (small_write, _) = measure("byte_write_small_range_publication", || {
        engine.write_bytes(address, vec![0u8; 4])?;
        engine.analyse()?;
        Ok(((), 1))
    })?;
    results.push(small_write);

    let large_len = available.min(64 * 1024) as usize;
    let (large_write, _) = measure("byte_write_large_range_publication", || {
        engine.write_bytes(address, vec![0u8; large_len])?;
        engine.analyse()?;
        Ok(((), large_len))
    })?;
    results.push(large_write);
    Ok(())
}

fn bench_mapping_changes(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let mapping_count = u64::try_from(SEGMENT_MAPPING_REMOVALS)?;
    let provider_size = usize::try_from(mapping_count * SEGMENT_MAPPING_SIZE)?;
    let mut storage = SegmentStorage::empty();
    let provider = storage.open_provider(
        InMemorySegmentStorage::with_size(provider_size),
        SegmentProperties::PERM_ALL,
    );

    let (insertion, _) = measure("segment_mapping_insertion", || {
        for index in 0..mapping_count {
            let offset = index * SEGMENT_MAPPING_SIZE;
            let mapping = storage.create_mapping(
                provider,
                0x1000u64 + offset,
                SEGMENT_MAPPING_SIZE,
                offset,
                SegmentProperties::PERM_ALL,
            )?;
            storage.add_mapping_to_space(DEFAULT_SPACE_ID, mapping)?;
        }
        Ok(((), SEGMENT_MAPPING_REMOVALS))
    })?;
    results.push(insertion);

    let (removal, _) = measure("segment_mapping_provider_removal", || {
        storage.close_provider(provider)?;
        Ok(((), SEGMENT_MAPPING_REMOVALS))
    })?;
    results.push(removal);
    Ok(())
}

fn bench_latest_change(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (engine, _) = load_engine()?;
    let reader = engine.query_reader()?;
    let (address, available) = writable_region(&reader)?;

    let mut region = AddressRangeSet::new();
    region.insert_range(AddressRange::new(
        address.space(),
        address.raw_address(),
        address.raw_address() + 0xfffu64,
    ));

    let (small, _) = measure_repeated("latest_change_small_region", || {
        black_box(reader.latest_change(ChangeKinds::all(), &region)?);
        Ok(((), 1))
    })?;
    results.push(small);

    let stride = (available / 4096).max(8);
    for index in 0..4096u64 {
        let scatter = address
            .checked_add((index * stride) % available.saturating_sub(4))
            .ok_or_else(|| std::io::Error::other("scatter write address overflow"))?;
        engine.write_bytes(scatter, vec![0u8; 4])?;
    }
    engine.analyse()?;

    let (scattered, _) = measure_repeated("latest_change_after_many_scattered_writes", || {
        black_box(reader.latest_change(ChangeKinds::all(), &region)?);
        Ok(((), 1))
    })?;
    results.push(scattered);
    Ok(())
}

fn bench_reader_latency(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (engine, entry) = load_engine()?;
    let reader = engine.query_reader()?;
    let allocations = AllocationSnapshot::begin();
    let entities = EntityAccessSnapshot::capture();
    let start = Instant::now();
    let mut samples = Vec::new();

    thread::scope(|scope| -> Result<(), Box<dyn Error>> {
        let writer = scope.spawn(|| -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
            for index in 0..128usize {
                let address = entry
                    .checked_add(index as u64)
                    .ok_or_else(|| std::io::Error::other("latency symbol address overflow"))?;
                engine.add_symbol(
                    SymbolIndex::new(SymbolTableSelector::new(242), index),
                    SymbolEntry::new(address, "bench_latency_symbol", SymbolProperties::LOCAL),
                )?;
            }
            Ok(())
        });

        for _ in 0..128usize {
            let query_start = Instant::now();
            black_box(reader.symbol_page(None, PAGE_LIMIT)?);
            samples.push(query_start.elapsed());
        }

        writer
            .join()
            .map_err(|_| std::io::Error::other("writer thread panicked"))?
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(())
    })?;

    engine.analyse()?;
    results.push(BenchResult::with_latencies(
        "reader_latency_during_write_batch",
        start.elapsed(),
        samples.len(),
        &samples,
        AllocationSnapshot::capture().since(allocations),
        EntityAccessSnapshot::capture().since(entities),
    ));
    Ok(())
}

fn bench_index_maintenance(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (separate_engine, separate_entry) = load_engine()?;
    let separate_base = separate_entry
        .checked_add(0x20_000u64)
        .ok_or_else(|| std::io::Error::other("synthetic function base overflow"))?;

    let (separate, _) = measure("function_separate_admission", || {
        for index in 0..SYNTHETIC_FUNCTIONS {
            let function_entry = separate_base
                .checked_add(index as u64)
                .ok_or_else(|| std::io::Error::other("synthetic function address overflow"))?;
            add_empty_function(&separate_engine, function_entry)?;
        }
        separate_engine.analyse()?;
        Ok(((), SYNTHETIC_FUNCTIONS))
    })?;
    results.push(separate);

    let (engine, entry) = load_engine()?;
    let base = entry
        .checked_add(0x20_000u64)
        .ok_or_else(|| std::io::Error::other("synthetic function base overflow"))?;

    let (result, _) = measure("function_batch_admission", || {
        let updates = function_updates(base, SYNTHETIC_FUNCTIONS)?;
        engine.apply_updates(ChangeSource::engine("benchmark"), updates)?;
        engine.analyse()?;
        Ok(((), SYNTHETIC_FUNCTIONS))
    })?;
    results.push(result);
    Ok(())
}

fn bench_cached_derived(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (engine, entry) = load_engine()?;
    let reader = engine.query_reader()?;

    let mut region = AddressRangeSet::new();
    region.insert_range(AddressRange::new(
        entry.space(),
        entry.raw_address(),
        entry.raw_address() + 0xffffu64,
    ));

    let probe = entry;
    let compute = move |view: &ProjectView<'_>| Ok(view.function_at(probe).is_some() as usize);
    let mut term = Term::new(Dependency::on(ChangeKinds::FUNCTIONS).within(region));
    black_box(term.evaluate(&reader, compute)?);

    let (hit, _) = measure_repeated("cached_derived_hit", || {
        black_box(term.evaluate(&reader, compute)?);
        Ok(((), 1))
    })?;
    results.push(hit);

    let new_entry = entry
        .checked_add(0x40u64)
        .ok_or_else(|| std::io::Error::other("cached derived function address overflow"))?;
    add_empty_function(&engine, new_entry)?;

    let (recompute, _) = measure("cached_derived_recompute", || {
        black_box(term.evaluate(&reader, compute)?);
        Ok(((), 1))
    })?;
    results.push(recompute);
    Ok(())
}

fn bench_multi_client(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (engine, entry) = load_engine()?;
    let reader = engine.query_reader()?;
    black_box(reader.flow_targets(entry)?);

    let mut region = AddressRangeSet::new();
    region.insert_range(AddressRange::new(
        entry.space(),
        entry.raw_address(),
        entry.raw_address() + 0xffffu64,
    ));

    let client_count = 8usize;
    let queries_per_client = 512usize;

    let (result, _) = measure("multi_client_flow_targets_and_latest_change", || {
        thread::scope(|scope| -> Result<(), Box<dyn Error>> {
            let mut clients = Vec::new();
            for _ in 0..client_count {
                let reader = reader.clone();
                let region = region.clone();
                clients.push(scope.spawn(
                    move || -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
                        for _ in 0..queries_per_client {
                            black_box(
                                reader
                                    .flow_targets(entry)
                                    .map_err(|error| std::io::Error::other(error.to_string()))?,
                            );
                            black_box(
                                reader
                                    .latest_change(ChangeKinds::all(), &region)
                                    .map_err(|error| std::io::Error::other(error.to_string()))?,
                            );
                        }
                        Ok(())
                    },
                ));
            }

            for client in clients {
                client
                    .join()
                    .map_err(|_| std::io::Error::other("client thread panicked"))?
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
            }
            Ok(())
        })?;
        Ok(((), client_count * queries_per_client))
    })?;
    results.push(result);
    Ok(())
}

const HOT_TARGET_REFERENCES: usize = 8192;

fn bench_reference_hot_target(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (engine, entry) = load_engine()?;
    let hot_target = entry
        .checked_add(0x10_0000u64)
        .ok_or_else(|| std::io::Error::other("hot target address overflow"))?;

    let (insert, _) = measure("reference_bulk_assert", || {
        for index in 0..HOT_TARGET_REFERENCES {
            let from = entry
                .checked_add(0x20_0000 + index as u64 * 0x10)
                .ok_or_else(|| std::io::Error::other("reference source address overflow"))?;
            engine.add_reference(Reference::data(from, hot_target, ReferenceProperties::READ))?;
        }
        engine.analyse()?;
        Ok(((), HOT_TARGET_REFERENCES))
    })?;
    results.push(insert);

    let reader = engine.query_reader()?;

    let (first_page, _) = measure_repeated("reference_hot_target_first_page", || {
        let page = reader.incoming_reference_page(hot_target, None, PAGE_LIMIT)?;
        Ok(((), page.entries().len()))
    })?;
    results.push(first_page);

    let (full_walk, _) = measure_repeated("reference_hot_target_full_walk", || {
        let mut count = 0usize;
        for result in reader.incoming_references(hot_target) {
            black_box(result?);
            count += 1;
        }
        Ok(((), count))
    })?;
    results.push(full_walk);

    Ok(())
}

#[cfg(feature = "sqlite")]
const SCALE_REFERENCES: usize = 1_048_576;
#[cfg(feature = "sqlite")]
const SCALE_HOT_REFERENCES: usize = 65_536;
#[cfg(feature = "sqlite")]
const SCALE_REFERENCE_BATCH: usize = 8192;

#[cfg(feature = "sqlite")]
fn load_persistent_project(project_path: &Path) -> Result<(Project, Address), Box<dyn Error>> {
    let project_path = project_path
        .to_str()
        .ok_or_else(|| std::io::Error::other("project path is not valid UTF-8"))?;
    let project = Project::from_file_with_provider_and_attributes::<
        PersistentStorageProvider<DefaultPersistentEntityStorage, DefaultPersistentSegmentStorage>,
    >(
        fixture_path(),
        attributes![ATTRIBUTE_PROJECT_PATH => project_path],
    )?;
    let entry = project
        .entry_point()
        .ok_or_else(|| std::io::Error::other("fixture entry missing"))?;
    Ok((project, entry))
}

#[cfg(feature = "sqlite")]
fn bench_reference_million_scale(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let (mut project, entry) = load_persistent_project(&dir.path().join("scale.fdbz"))?;
    let hot_target = entry
        .checked_add(0x10_0000u64)
        .ok_or_else(|| std::io::Error::other("hot target address overflow"))?;

    let (insert, _) = measure("reference_scale_bulk_assert", || {
        for start in (0..SCALE_REFERENCES).step_by(SCALE_REFERENCE_BATCH) {
            let mut transaction = project.transaction("benchmark reference batch");
            for index in start..(start + SCALE_REFERENCE_BATCH).min(SCALE_REFERENCES) {
                let from = entry
                    .checked_add(0x100_0000 + index as u64 * 0x10)
                    .ok_or_else(|| std::io::Error::other("reference source address overflow"))?;
                let target = if index < SCALE_HOT_REFERENCES {
                    hot_target
                } else {
                    entry
                        .checked_add(0x2000_0000 + index as u64 * 0x10)
                        .ok_or_else(|| std::io::Error::other("reference target address overflow"))?
                };
                transaction.add_reference(Reference::data(
                    from,
                    target,
                    ReferenceProperties::READ,
                ))?;
            }
            transaction.commit()?;
        }
        Ok(((), SCALE_REFERENCES))
    })?;
    results.push(insert);

    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;
    let reader = engine.query_reader()?;

    let (first_page, _) = measure_repeated("reference_scale_hot_first_page", || {
        let page = reader.incoming_reference_page(hot_target, None, PAGE_LIMIT)?;
        Ok(((), page.entries().len()))
    })?;
    results.push(first_page);

    let (full_walk, _) = measure_repeated("reference_scale_hot_full_walk", || {
        let mut count = 0usize;
        for result in reader.incoming_references(hot_target) {
            black_box(result?);
            count += 1;
        }
        Ok(((), count))
    })?;
    results.push(full_walk);

    let spread_target = entry
        .checked_add(0x2000_0000 + (SCALE_REFERENCES as u64 - 1) * 0x10)
        .ok_or_else(|| std::io::Error::other("spread target address overflow"))?;
    let (spread_page, _) = measure_repeated("reference_scale_spread_first_page", || {
        let page = reader.incoming_reference_page(spread_target, None, PAGE_LIMIT)?;
        Ok(((), page.entries().len()))
    })?;
    results.push(spread_page);

    let spread_from = entry
        .checked_add(0x100_0000 + (SCALE_REFERENCES as u64 - 1) * 0x10)
        .ok_or_else(|| std::io::Error::other("spread source address overflow"))?;
    let (outgoing_page, _) = measure_repeated("reference_scale_outgoing_page", || {
        let page = reader.outgoing_reference_page(spread_from, None, PAGE_LIMIT)?;
        Ok(((), page.entries().len()))
    })?;
    results.push(outgoing_page);

    Ok(())
}

fn selected_group(selected: Option<&str>, group: &str) -> bool {
    selected.is_none_or(|selected| selected == group)
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut results = Vec::new();
    let selected = std::env::args()
        .skip(1)
        .find(|argument| argument != "--bench");

    if selected_group(selected.as_deref(), "analysis") {
        bench_initial_analysis(&mut results)?;
    }
    if selected_group(selected.as_deref(), "representative") {
        bench_representative_analysis(&mut results)?;
    }
    if selected_group(selected.as_deref(), "il") {
        bench_dominance_traversal(&mut results)?;
        bench_call_heavy_mcode(&mut results)?;
    }
    if selected_group(selected.as_deref(), "queries") {
        bench_repeated_flow_targets(&mut results)?;
        bench_page_scans(&mut results)?;
        bench_call_graph_pages(&mut results)?;
        bench_cached_derived(&mut results)?;
    }
    if selected_group(selected.as_deref(), "functions") {
        bench_single_function_edit(&mut results)?;
        bench_large_function_replacement(&mut results)?;
        bench_index_maintenance(&mut results)?;
    }
    if selected_group(selected.as_deref(), "changes") {
        bench_byte_writes(&mut results)?;
        bench_mapping_changes(&mut results)?;
        bench_latest_change(&mut results)?;
    }
    if selected_group(selected.as_deref(), "concurrency") {
        bench_reader_latency(&mut results)?;
        bench_multi_client(&mut results)?;
    }
    if selected_group(selected.as_deref(), "references") {
        bench_reference_hot_target(&mut results)?;
        #[cfg(feature = "sqlite")]
        bench_reference_million_scale(&mut results)?;
    }

    for result in results {
        result.print();
    }

    Ok(())
}
