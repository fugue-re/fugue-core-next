use std::error::Error;
use std::hash::{Hash, Hasher};
use std::hint::black_box;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use fugue_core::analysis::function::recovery::{PartialCodeBlock, PartialFunction};
use fugue_core::engine::AnalysisEngine;
use fugue_core::engine::change::ChangeKinds;
use fugue_core::ir::{
    Address, AddressRange, AddressRangeSet, SymbolEntry, SymbolIndex, SymbolProperties,
    SymbolTableSelector,
};
use fugue_core::loader::Loader;
use fugue_core::project::Project;
use fugue_core::queries::QueryReader;
use fugue_core::storage::segments::DEFAULT_SPACE_ID;
use rustc_hash::FxHasher;

const SYNTHETIC_SYMBOLS: usize = 1024;
const SYNTHETIC_FUNCTIONS: usize = 256;
const STAMP_BUCKETS: usize = 256;
const RANGE_STAMP_BUCKET_BITS: u32 = 12;
const RANGE_STAMP_BUCKETS: usize = 512;
const PAGE_LIMIT: usize = 64;

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

fn run_query<T>(
    query: impl FnOnce() -> Result<T, fugue_core::queries::QueryError>,
) -> Result<T, Box<dyn Error>> {
    Ok(query()?)
}

fn stamp_bucket(address: Address) -> usize {
    let mut hasher = FxHasher::default();
    (address.space().index(), address.offset()).hash(&mut hasher);
    (hasher.finish() as usize) % STAMP_BUCKETS
}

fn range_slot(address: Address) -> usize {
    let mut hasher = FxHasher::default();
    (
        address.space().index(),
        address.offset() >> RANGE_STAMP_BUCKET_BITS,
    )
        .hash(&mut hasher);
    (hasher.finish() as usize) % RANGE_STAMP_BUCKETS
}

fn find_bucket_peer(entry: Address, same_bucket: bool) -> Result<Address, Box<dyn Error>> {
    if same_bucket {
        let window = 1u64 << RANGE_STAMP_BUCKET_BITS;
        let delta = if entry.offset() % window < window / 2 {
            0x10u64
        } else {
            return Ok(Address::new(entry.space(), entry.offset() - 0x10));
        };
        return entry
            .checked_add(delta)
            .ok_or_else(|| std::io::Error::other("bucket peer address overflow").into());
    }

    let entry_slot = range_slot(entry);
    let entry_bucket = stamp_bucket(entry);
    let base = entry
        .checked_add(0x30_000u64)
        .ok_or_else(|| std::io::Error::other("bucket peer base address overflow"))?;

    for step in 0..(RANGE_STAMP_BUCKETS * 128) {
        let candidate = base
            .checked_add((step as u64) << RANGE_STAMP_BUCKET_BITS)
            .ok_or_else(|| std::io::Error::other("bucket peer address overflow"))?;
        if range_slot(candidate) != entry_slot && stamp_bucket(candidate) != entry_bucket {
            return Ok(candidate);
        }
    }

    Err(std::io::Error::other("bucket peer not found").into())
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
        engine.insert_symbol(
            SymbolIndex::new(SymbolTableSelector::new(240), index),
            SymbolEntry::new(address, symbol, SymbolProperties::LOCAL),
        )?;
    }

    engine.wait_until_idle()?;
    Ok(())
}

fn add_empty_function(engine: &AnalysisEngine, entry: Address) -> Result<(), Box<dyn Error>> {
    let mut function = PartialFunction::new(entry);
    function.push_block(PartialCodeBlock::new(
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
        let page = run_query(|| reader.symbol_page(cursor, PAGE_LIMIT))?;
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
        let page = run_query(|| reader.mapping_page(DEFAULT_SPACE_ID, cursor, PAGE_LIMIT))?;
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
        let page = run_query(|| reader.call_edges(cursor, PAGE_LIMIT))?;
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
    black_box(run_query(|| reader.revision())?);
    results.push(result);
    Ok(())
}

fn bench_repeated_flow_graph(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (engine, entry) = load_engine()?;
    let reader = engine.query_reader()?;
    let same_bucket = find_bucket_peer(entry, true)?;
    let different_bucket = find_bucket_peer(entry, false)?;

    black_box(run_query(|| reader.flow_graph(entry))?);
    let (hit, _) = measure("repeated_flow_graph_query_hit", || {
        black_box(run_query(|| reader.flow_graph(entry))?);
        Ok(((), 1))
    })?;
    results.push(hit);

    add_empty_function(&engine, same_bucket)?;
    engine.wait_until_idle()?;
    let (after_same_bucket, _) =
        measure("repeated_flow_graph_query_after_same_bucket_edit", || {
            black_box(run_query(|| reader.flow_graph(entry))?);
            Ok(((), 1))
        })?;
    results.push(after_same_bucket);

    add_empty_function(&engine, different_bucket)?;
    engine.wait_until_idle()?;
    let (after_different_bucket, _) = measure(
        "repeated_flow_graph_query_after_different_bucket_edit",
        || {
            black_box(run_query(|| reader.flow_graph(entry))?);
            Ok(((), 1))
        },
    )?;
    results.push(after_different_bucket);

    engine.insert_symbol(
        SymbolIndex::new(SymbolTableSelector::new(241), 0),
        SymbolEntry::new(entry, "bench_unrelated_symbol", SymbolProperties::LOCAL),
    )?;
    engine.wait_until_idle()?;

    let (after_edit, _) = measure("repeated_flow_graph_query_after_unrelated_edit", || {
        black_box(run_query(|| reader.flow_graph(entry))?);
        Ok(((), 1))
    })?;
    results.push(after_edit);
    Ok(())
}

fn bench_page_scans(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (engine, entry) = load_engine()?;
    add_symbols(&engine, entry, SYNTHETIC_SYMBOLS)?;
    let reader = engine.query_reader()?;

    let (symbols, _) = measure("symbol_page_scan", || {
        let count = page_symbols(&reader)?;
        Ok(((), count))
    })?;
    results.push(symbols);

    let (mappings, _) = measure("mapping_page_scan", || {
        let count = page_mappings(&reader)?;
        Ok(((), count))
    })?;
    results.push(mappings);
    Ok(())
}

fn bench_call_graph_pages(results: &mut Vec<BenchResult>) -> Result<(), Box<dyn Error>> {
    let (engine, entry) = load_engine()?;
    let reader = engine.query_reader()?;

    let (edges, edge_count) = measure("call_graph_page_scan", || {
        let count = page_call_edges(&reader)?;
        Ok((count, count))
    })?;
    results.push(edges);

    let (callees, _) = measure("call_graph_callees_page", || {
        let page = run_query(|| reader.callees_of(entry, None, PAGE_LIMIT))?;
        Ok(((), page.entries().len()))
    })?;
    results.push(callees);

    if edge_count > 0 {
        let first = run_query(|| reader.call_edges(None, 1))?
            .entries()
            .first()
            .copied()
            .ok_or_else(|| std::io::Error::other("call edge disappeared"))?;
        let (callers, _) = measure("call_graph_callers_page", || {
            let page = run_query(|| reader.callers_of(first.callee(), None, PAGE_LIMIT))?;
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
        black_box(run_query(|| reader.flow_graph(new_entry))?);
        Ok(((), 1))
    })?;
    results.push(related);

    let (unrelated, _) = measure("single_function_edit_unrelated_query", || {
        black_box(run_query(|| reader.symbol_page(None, PAGE_LIMIT))?);
        Ok(((), PAGE_LIMIT))
    })?;
    results.push(unrelated);
    Ok(())
}

fn writable_region(reader: &QueryReader) -> Result<(Address, u64), Box<dyn Error>> {
    let mut cursor = None;

    loop {
        let page = run_query(|| reader.mapping_page(DEFAULT_SPACE_ID, cursor, PAGE_LIMIT))?;
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
    let (address, _) = writable_region(&reader)?;

    let mut region = AddressRangeSet::new();
    region.insert_range(AddressRange::new(
        address.space(),
        address.raw_address(),
        address.raw_address() + 0xfffu64,
    ));

    let (small, _) = measure("latest_change_small_region", || {
        black_box(run_query(|| {
            reader.latest_change(ChangeKinds::all(), &region)
        })?);
        Ok(((), 1))
    })?;
    results.push(small);

    for index in 0..4096u64 {
        let scatter = address
            .checked_add(0x10_000 + index * 0x400)
            .ok_or_else(|| std::io::Error::other("scatter write address overflow"))?;
        engine.write_bytes(scatter, vec![0u8; 4])?;
    }
    engine.wait_until_idle()?;

    let (scattered, _) = measure("latest_change_after_many_scattered_writes", || {
        black_box(run_query(|| {
            reader.latest_change(ChangeKinds::all(), &region)
        })?);
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
                engine.insert_symbol(
                    SymbolIndex::new(SymbolTableSelector::new(242), index),
                    SymbolEntry::new(address, "bench_latency_symbol", SymbolProperties::LOCAL),
                )?;
            }
            Ok(())
        });

        for _ in 0..128usize {
            let query_start = Instant::now();
            black_box(run_query(|| reader.symbol_page(None, PAGE_LIMIT))?);
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

fn main() -> Result<(), Box<dyn Error>> {
    let mut results = Vec::new();

    bench_initial_analysis(&mut results)?;
    bench_repeated_flow_graph(&mut results)?;
    bench_page_scans(&mut results)?;
    bench_call_graph_pages(&mut results)?;
    bench_single_function_edit(&mut results)?;
    bench_byte_writes(&mut results)?;
    bench_latest_change(&mut results)?;
    bench_reader_latency(&mut results)?;
    bench_index_maintenance(&mut results)?;

    for result in results {
        result.print();
    }

    Ok(())
}
