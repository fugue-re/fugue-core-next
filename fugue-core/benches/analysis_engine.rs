use std::error::Error;
use std::hint::black_box;
#[cfg(feature = "sqlite")]
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(feature = "sqlite")]
use fugue_core::attributes;
use fugue_core::engine::AnalysisEngine;
use fugue_core::engine::change::ChangeKinds;
use fugue_core::ir::{
    Address, AddressRange, AddressRangeSet, IncompleteCodeBlock, IncompleteFunction, Reference,
    ReferenceProperties, SymbolEntry, SymbolIndex, SymbolProperties, SymbolTableSelector,
};
use fugue_core::loader::Loader;
use fugue_core::project::Project;
use fugue_core::queries::{Cached, Dependency, QueryReader};
use fugue_core::storage::DEFAULT_SPACE_ID;
#[cfg(feature = "sqlite")]
use fugue_core::storage::DefaultPersistentEntityStorage;
#[cfg(feature = "sqlite")]
use fugue_core::storage::DefaultPersistentSegmentStorage;
#[cfg(feature = "sqlite")]
use fugue_core::storage::PersistentStorageProvider;
#[cfg(feature = "sqlite")]
use fugue_core::types::ATTRIBUTE_PROJECT_PATH;
const SYNTHETIC_SYMBOLS: usize = 1024;
const SYNTHETIC_FUNCTIONS: usize = 256;
const PAGE_LIMIT: usize = 64;
const QUERY_REPETITIONS: usize = 128;

struct BenchResult {
    name: &'static str,
    elapsed: Duration,
    items: usize,
    p50_latency: Option<Duration>,
    p99_latency: Option<Duration>,
    rss_kib: Option<u64>,
}

impl BenchResult {
    fn new(name: &'static str, elapsed: Duration, items: usize) -> Self {
        Self {
            name,
            elapsed,
            items,
            p50_latency: None,
            p99_latency: None,
            rss_kib: current_rss_kib(),
        }
    }

    fn with_latencies(
        name: &'static str,
        elapsed: Duration,
        items: usize,
        samples: &[Duration],
    ) -> Self {
        Self {
            name,
            elapsed,
            items,
            p50_latency: percentile(samples, 50),
            p99_latency: percentile(samples, 99),
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
            "bench={},elapsed_ns={},items={},p50_latency_ns={p50},p99_latency_ns={p99},rss_kib={rss}",
            self.name,
            self.elapsed.as_nanos(),
            self.items,
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

fn load_engine() -> Result<(AnalysisEngine, Address), Box<dyn Error>> {
    let project = load_project()?;
    let entry = project
        .entry()
        .ok_or_else(|| std::io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.wait_until_idle()?;
    Ok((engine, entry))
}

fn measure<T, F>(name: &'static str, f: F) -> Result<(BenchResult, T), Box<dyn Error>>
where
    F: FnOnce() -> Result<(T, usize), Box<dyn Error>>,
{
    let start = Instant::now();
    let (value, items) = f()?;
    Ok((BenchResult::new(name, start.elapsed(), items), value))
}

fn measure_repeated<T, F>(name: &'static str, mut f: F) -> Result<(BenchResult, T), Box<dyn Error>>
where
    F: FnMut() -> Result<(T, usize), Box<dyn Error>>,
{
    let start = Instant::now();
    let (mut value, mut items) = f()?;
    for _ in 1..QUERY_REPETITIONS {
        let (next, next_items) = f()?;
        value = next;
        items += next_items;
    }
    Ok((BenchResult::new(name, start.elapsed(), items), value))
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

    engine.wait_until_idle()?;
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
        engine.wait_until_idle()?;
        Ok((engine, 1))
    })?;

    let reader = engine.query_reader()?;
    black_box(reader.revision()?);
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
    engine.wait_until_idle()?;
    let (after_same_entry, _) = measure("flow_targets_after_same_entry_edit", || {
        black_box(reader.flow_targets(entry)?);
        Ok(((), 1))
    })?;
    results.push(after_same_entry);

    add_empty_function(&engine, disjoint_entry)?;
    engine.wait_until_idle()?;
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
    engine.wait_until_idle()?;

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
        engine.wait_until_idle()?;
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
        engine.wait_until_idle()?;
        Ok(((), 1))
    })?;
    results.push(small_write);

    let large_len = available.min(64 * 1024) as usize;
    let (large_write, _) = measure("byte_write_large_range_publication", || {
        engine.write_bytes(address, vec![0u8; large_len])?;
        engine.wait_until_idle()?;
        Ok(((), large_len))
    })?;
    results.push(large_write);
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
    engine.wait_until_idle()?;

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

    engine.wait_until_idle()?;
    results.push(BenchResult::with_latencies(
        "reader_latency_during_write_batch",
        start.elapsed(),
        samples.len(),
        &samples,
    ));
    Ok(())
}

fn bench_index_maintenance(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (engine, entry) = load_engine()?;
    let base = entry
        .checked_add(0x20_000u64)
        .ok_or_else(|| std::io::Error::other("synthetic function base overflow"))?;

    let (result, _) = measure("call_graph_index_maintenance_per_function", || {
        for index in 0..SYNTHETIC_FUNCTIONS {
            let function_entry = base
                .checked_add(index as u64)
                .ok_or_else(|| std::io::Error::other("synthetic function address overflow"))?;
            add_empty_function(&engine, function_entry)?;
        }
        engine.wait_until_idle()?;
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

    let compute = |reader: &QueryReader| {
        reader
            .symbol_page(None, PAGE_LIMIT)
            .map(|page| page.entries().len())
    };
    let mut cached = Cached::new(Dependency::on(ChangeKinds::FUNCTIONS).within(region));
    black_box(cached.get(&reader, compute)?);

    let (hit, _) = measure_repeated("cached_derived_hit", || {
        black_box(cached.get(&reader, compute)?);
        Ok(((), 1))
    })?;
    results.push(hit);

    let new_entry = entry
        .checked_add(0x40u64)
        .ok_or_else(|| std::io::Error::other("cached derived function address overflow"))?;
    add_empty_function(&engine, new_entry)?;

    let (recompute, _) = measure("cached_derived_recompute", || {
        black_box(cached.get(&reader, compute)?);
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
        engine.wait_until_idle()?;
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
        .entry()
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
    engine.wait_until_idle()?;
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

fn main() -> Result<(), Box<dyn Error>> {
    let mut results = Vec::new();

    bench_initial_analysis(&mut results)?;
    bench_repeated_flow_targets(&mut results)?;
    bench_page_scans(&mut results)?;
    bench_call_graph_pages(&mut results)?;
    bench_single_function_edit(&mut results)?;
    bench_byte_writes(&mut results)?;
    bench_latest_change(&mut results)?;
    bench_reader_latency(&mut results)?;
    bench_index_maintenance(&mut results)?;
    bench_cached_derived(&mut results)?;
    bench_multi_client(&mut results)?;
    bench_reference_hot_target(&mut results)?;
    #[cfg(feature = "sqlite")]
    bench_reference_million_scale(&mut results)?;

    for result in results {
        result.print();
    }

    Ok(())
}
