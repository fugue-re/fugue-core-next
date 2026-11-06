# Memory-mapped segment storage

## Provider layout

`storage/segments/provider/memmap/mod.rs` implements
`MemoryMappedSegmentStorage`; `memmap/packed.rs` implements
`PackedMemoryMappedSegmentStorage`. Both use the existing segment-provider API.
Banks, loader layout, address spaces and analysis lifecycle are unchanged.

The providers share `MemoryMappedSegmentStorageError` and the backing filename
constants defined in `memmap/mod.rs`. Their metadata representations are separate:
Packed saves physical file offsets as well as logical extents. Backing allocation,
read/write paths and packing algorithms remain separate.

Ordinary image storage retains its selected provider. Newly constructed storage
defaults to Packed for persistent synthetic backing and InMemory for transient
synthetic backing. Synthetic provider creation remains lazy: rejecting a staged
mapping opens no provider.

The synthetic mapping builders are constructed in their direct and staged
creation methods. `mappings()` and checked `pending_provider_id(offset)` provide
staging access without exposing storage fields. `open_synthetic_provider` owns
provider registration and growth. Append placement remains the maximum mapping
backing end, including applicable staged mappings, rather than provider capacity.

## Synthetic provider selection

Set `ATTRIBUTE_SEGMENT_STORAGE_SYNTHETIC_PROVIDER` in the project's `AttributeMap`
to a registered provider's `STABLE_TAG` to override the synthetic backing default.
The attribute key is `storage.segments.synthetic_provider`; it does not change
the image provider selected by the storage type.

The selection is stored as `synthetic_provider_tag` in segment-storage metadata,
including before the first synthetic mapping exists. Reopened projects retain
that saved selection rather than applying a different creation attribute.
Unknown tags are rejected during project creation and when reading saved
segment-storage metadata, before opening any provider. Backing creation remains
lazy. A supplied project path is retained for transient storage too, so a
file-backed synthetic provider can use it without making the project persistent.

## Bounds and staged writes

Buffer lengths widen from `usize` to `u64` without a fallible conversion. Bounds
checks use checked inclusive-end arithmetic rather than constructing and
discarding address ranges. Empty read/write buffers remain no-ops; synthetic
mappings must be non-empty.

`AddressRange::size()` returns `Option<u64>`: `Some(0)` for empty ranges, the
exact length for representable ranges, and `None` for the full address-space span
whose length is `2^64`. `SegmentSubMapping::size()` follows the same contract,
including submappings expanded through their public endpoint methods.

Mapping construction and metadata loading reject zero or unrepresentable sizes.
Validated mappings and their bounded storage views retain their `u64` size
accessors. Work scheduling splits full-space ranges to fit the requested budget
instead of treating an unrepresentable length as an invalid range.

Staged writes limit each chunk to the remaining source bytes before narrowing its
length to `usize`. This is not partial-write acceptance: all destinations must
validate before any bytes from that request enter the staged writes. An unmapped
or unwritable suffix rejects the request without staging its valid prefix.

## Ordinary mmap backing

The logical size is independent of mapped file sizes. Written data is held in
provider-private backing files ordered by logical base. A forward gap greater
than **4 MiB (4 × 1024 × 1024 bytes)** starts another backing. The threshold is a
storage policy, not an ELF, PE or Mach-O guarantee, and does not cap contiguous
file size.

Contiguous writes grow a backing. Writes before an existing backing can create
a preceding backing without relocating existing bytes. Filling a gap does not
merge existing backing files. Views crossing files can therefore contain several
chunks; callers can gather them with `SegmentView::read_into`.

A read within the sole backing copies directly from its mmap, without an extent
lookup. Multiple backings require coarse-range selection. Written-range tracking
still distinguishes view data from holes. Logical growth does not allocate an
entire address span; shrinking removes data beyond the new end.

Live backing files are anonymous files in the provider directory. `flush` flushes
the live maps. Persistent drop writes the canonical packed data file and metadata;
reopening reconstructs small-gap clusters. The existing `PackMetadata` and
`PackExtent` on-disk layout is unchanged. There is no background or periodic
writer.

## Packed backing

Packed retains the append-oriented physical layout of the preceding
implementation, with logical extents indexing the mmap. Its registration tags
are `packed-memory-mapped-persistent` and `packed-memory-mapped-transient`;
ordinary mmap tags are unchanged.

`view_bytes_from` uses one predecessor lookup. `read_bytes` fills only holes,
rather than zeroing bytes that will immediately be overwritten. Packed still
pays extent-translation costs on reads; it is not the ordinary image mmap backend.

Persistent Packed `flush()` synchronises the backing and directly writes metadata
describing the live logical size, allocation end and each extent's logical offset,
length and physical file offset. Reopening restores that layout without assuming
the data has been compacted. An extent is eligible for append extension only if it
reaches the saved allocation end, including after shrink/regrow.

Close-time compaction, adjacent-extent coalescing and file truncation remain in
place. Close saves metadata describing the compacted positions. The private Packed
metadata format changes; no compatibility reader or temporary-file publication
is introduced. Transient flush behaviour and ordinary mmap storage are unchanged.

## Verification

No permanent tests were added. Existing release-mode checks passed:

- 55 storage/segment unit tests.
- Five SQLite segment-persistence integration tests, including distant image
  segments, synthetic mapping reopen, and rejected staging without a provider.

Temporary real-provider probes exercised both implementations with a 16 TiB
logical span, out-of-order and overlapping writes, chunked view gathering,
flush/drop/reopen, and shrink/regrow. An ordinary-provider probe also checked the
4 MiB threshold and a bridging write without merging existing backings. Its
maximum resident set size was 41,615,360 bytes, including probe buffers.

Packed appended 16,384 blocks of 4 KiB (64 MiB), then reopened and checked sampled
blocks. The measured append/resize loop took 17.0 ms in one smoke run; this is not
a comparative performance claim.

### Initial performance measurements

Matched original-flat and revised binaries were built with the bench profile and
SQLite feature. The baseline uses the preserved working tree with the original
HEAD mmap implementation and its manifest dependency restored. Other pre-existing
fixes were retained in both variants.

Twelve alternating runs per variant through `storage_timing mmap` gave these
medians (milliseconds):

| Fixture    | Stage            | Original flat | Revised ordinary mmap |
| ---------- | ---------------- | ------------: | --------------------: |
| ls.elf     | Project creation |         0.671 |                 1.111 |
| ls.elf     | Analysis         |        11.209 |                10.951 |
| libipmi.so | Project creation |         7.703 |                 7.907 |
| libipmi.so | Analysis         |       185.673 |               170.439 |

Recovered counts matched: 400 functions / 4,357 blocks for ls.elf; 4,403 functions /
37,305 blocks for libipmi.so. Analysis timings were noisy: libipmi.so ranged from
157–254 ms in the original and 156–286 ms in the revision. These measurements do
not establish an analysis speedup. The ls.elf creation cost increased.

One-million-operation read probes, repeated twelve times, measured these median
nanoseconds per operation:

| Layout      | Operation        | Original flat | Revised ordinary | Packed |
| ----------- | ---------------- | ------------: | ---------------: | -----: |
| Contiguous  | Read 16 bytes    |          3.43 |             4.57 |  18.37 |
| Contiguous  | View from offset |          9.33 |            10.56 |   6.98 |
| Small holes | Read 16 bytes    |          3.50 |             5.12 |  29.32 |
| Small holes | View from offset |         17.14 |            19.94 |  12.80 |

These initial measurements showed per-call overhead despite a no-search
single-backing path. The byte-read follow-up below addresses that path; view and
creation costs remain separate.

The pre-change snapshot, comparison sources/binaries and raw measurements are
preserved outside temporary storage under:

`/Users/slt/Projects/fugue-v0.3/fugue-core/.git/rollback-backups/fix-gap-testing/storage-rework-O7kVQmJr/`

The runtime-mappings design and checklist were left unchanged.

### Byte-read hot/cold split

The single-backing `read_bytes` path now obtains a checked mmap slice and copies
directly. Partial reads, unmapped holes and multiple backings use the existing
fallback, moved unchanged into the private, non-inlined
`read_bytes_from_backings` method. The caller marks that branch with
`std::hint::cold_path`. No state, allocations, unsafe code or public API were
added; backing placement and growth policy are unchanged.

On ARM64, keeping traversal in the same function made the ordinary path save
twelve registers. The split reduces that to four, matching the original flat
reader. Trial changes to view construction did not provide a consistent benefit
and were removed.

Temporary probes cover a nonzero backing base, mapped spare capacity, holes,
partial and empty reads, shrink/regrow and reopen. The 16 TiB sparse lifecycle
and exact 4 MiB gap-threshold probes also pass.

The pre-optimisation working tree is preserved in `storage-shared-jSbPtZ/tree`.
Concurrent engine/recovery edits made comparisons against the older analysis
binaries unmatched. The final end-to-end control and optimised source trees
therefore differ only in `provider/memmap/mod.rs`; those trees and their build
outputs are isolated in `mmap-read-comparison-fsUwLe/` beside the earlier backups.

The final isolated comparison rebuilt each variant after clearing only
`fugue-core` outputs in its private target directory. Distinct binary checksums
are recorded. An earlier shared-target attempt produced identical binaries and
was discarded.

Twenty-four alternating read-probe runs, one million operations each, gave these
median nanoseconds per operation:

| Layout      | Operation        | Before split | After split |
| ----------- | ---------------- | -----------: | ----------: |
| Contiguous  | Read 16 bytes    |         4.15 |        3.03 |
| Small holes | Read 16 bytes    |         4.18 |        3.06 |
| Contiguous  | View from offset |         8.70 |        8.69 |
| Small holes | View from offset |        16.35 |       16.29 |

Byte reads improved by approximately 27%, returning to the original flat reader's
approximately 3 ns in the earlier same-host comparison. Views remain unchanged;
their residual overhead against the original flat provider is not resolved here.

Sixteen alternating real-image runs per variant gave median analysis times of
30.726 → 30.475 ms for ls.elf and 149.275 → 149.134 ms for libipmi.so. Recovery
counts and dispatch counts matched (400 functions / 4,357 blocks / 3 dispatches;
4,403 functions / 37,305 blocks / 11 dispatches, respectively). This establishes
no meaningful end-to-end speedup; it isolates the byte-read improvement without
attributing concurrent engine changes to the provider.

Raw final results are `read-isolated-comparison.json` and
`analysis-isolated-comparison.json` in `mmap-read-comparison-fsUwLe/`.

Final verification on the frozen optimised tree passed all 55 existing
storage/segment unit tests and all five SQLite segment-persistence integration
tests. No permanent tests were added. Dylint was not run.

### Provider-selection verification

After adding the configuration attribute, the existing release-mode library,
engine, project-transaction, reservation, segment-persistence and switch-query
suites passed: 677 tests, with 29 ignored.

A temporary executable verified default and explicitly selected persistent
providers, conflicting reopen attributes before first synthetic use, synthetic
byte persistence, unknown-provider rejection and public space reservations.
The analysis executable completed on `ls.elf` with 400 functions, 4,357 blocks and
zero problems. The temporary executable was removed; no permanent tests were added.

The bounds cleanup passed the same six release-mode suites: 677 tests passed,
29 remained ignored. A temporary executable verified writes across adjacent
mappings, short writes, and rejection of unmapped or unwritable suffixes without
staging a prefix, even when the transaction subsequently commits. It also checked
empty buffers, overflowing requests, the last address, and inverted or
unrepresentable mapping lengths. These scenarios ran on the host; no 32-bit
target was executed.

The analysis-engine benchmark built successfully. The analysis executable again
completed on `ls.elf` with 400 functions, 4,357 blocks and zero problems.

The optional range-size migration passed 682 existing release-mode tests across
eight suites, with 29 ignored. Temporary smoke checks covered empty and full-space
ranges, maximum representable lengths, expanded submappings and mapping rejection.
The private scheduler was exercised with a full-space range: a zero budget left it
queued, and a `u64::MAX` budget produced a representable slice followed by the last
address. Both temporary verification hooks were removed; no permanent tests were
added.

### Pre-commit recovery and switch review

Three review fixes were measured against a source snapshot taken immediately
before these fixes, not against HEAD or the older benchmark figures above:

- Candidate retraction removes the reanalysis marker inside the existing queue
  traversal, only when discarding that candidate. No second traversal or new
  allocation is introduced.
- Ranged dependency causes retain their full range when finding affected
  functions. Singleton ranges keep the existing point lookup.
- Persistent switch preparation retains the previous coverage for publication.
  Publication removes only the replaced or removed switch ID from each covered
  interval, independently of whether its old entity remains cached. Other
  switches sharing the interval remain indexed. Transient publication retains
  its existing behaviour.

The comparison used separate frozen release libraries and executables, built
with `--features sqlite`, on aarch64 macOS with rustc 1.97.1. Each workload ran
two warm-up pairs followed by 16 measured pairs, alternating before/after order.
The external probes used `opt-level=3`. The following figures are medians:

| Workload | Before | After | Change |
| --- | ---: | ---: | ---: |
| Retract all 1,024 queued candidates | 6.79 µs | 8.75 µs | +28.8% |
| Retract all 16,384 queued candidates | 104.24 µs | 132.65 µs | +27.2% |
| Retract half of 16,384 candidates | 110.57 µs | 131.53 µs | +19.0% |
| Retract none of 16,384 candidates | 19.18 µs | 18.97 µs | −1.1% |
| Point-attributed dependency update and analysis | 6.213 ms | 6.213 ms | <0.1% |
| Ranged dependency update and analysis | 108.19 µs | 145.86 µs | +34.8% |
| Persistent switch add, normal cache | 18.50 µs/op | 16.04 µs/op | −13.3% |
| Persistent switch remove, normal cache | 16.97 µs/op | 17.10 µs/op | +0.8% |
| Persistent switch move, normal cache | 20.92 µs/op | 20.92 µs/op | <0.1% |
| Persistent switch shrink, normal cache | 17.80 µs/op | 17.82 µs/op | +0.1% |
| Persistent switch add, one-byte cache | 17.31 µs/op | 15.11 µs/op | −12.7% |
| Persistent switch remove, one-byte cache | 24.18 µs/op | 22.80 µs/op | −5.7% |
| Persistent switch move, one-byte cache | 27.09 µs/op | 25.03 µs/op | −7.6% |
| Persistent switch shrink, one-byte cache | 24.20 µs/op | 22.00 µs/op | −9.1% |
| `ls.elf` analysis | 7.299 ms | 7.372 ms | +1.0% |
| `libipmi.so` analysis | 128.554 ms | 129.368 ms | +0.6% |

Retraction pays for one hash-set removal per discarded candidate: about 28.4 µs
extra for 16,384 removals in this workload. The ranged baseline skips required
analysis: only 160 of 320 resulting graphs were correct, versus 320 of 320 after
the fix. Its additional 37.7 µs per update is therefore not a comparison of two
correct implementations. Both point-path variants passed all 640 graph checks.

Switch timings include staging, preparation and commit of a 256-operation
transaction, divided by 256; project creation and subsequent correctness checks
are outside the timer. The normal cache is 8 MiB. Checks covered shared case
targets, identical and partially overlapping table coverage, removal, movement
and shrinking. All 1,088 measured switch checks passed after the fix; the baseline
passed 816. Median peak process RSS for the combined switch workload changed
from 48.09 to 48.41 MiB. This is a process-level measurement, not an allocation
count for retained coverage.

End-to-end timing interquartile ranges overlap: `ls.elf` was 7.216–7.334 ms before
and 7.240–7.404 ms after; `libipmi.so` was 125.039–129.808 ms before and
126.700–130.783 ms after. Median peak RSS was 48.95 → 48.89 MiB for `ls.elf` and
133.56 → 133.02 MiB for `libipmi.so`. All runs retained the same function, block,
dispatch and problem counts: 400/4,357/3/0 and 4,403/37,305/11/1 respectively.
The existing `libipmi.so` problem remains present in both variants.

The existing release-mode library, engine, project-transaction, reservation,
segment-persistence, switch-query, switch-entity, work-model and global-work
suites passed: 686 tests, with 29 ignored. No permanent tests or repository
benchmark scaffolding were added. The source snapshot, frozen binaries, external
probes, raw samples, quartiles and correctness totals are retained under
`rollback-backups/fix-gap-testing/review-bench-K0D95J/` in the common Git directory.
The runtime-mappings documents were not changed.

### Rejected compact prepared switch coverage experiment

This experiment was reverted after review: its peak-memory saving did not
justify the larger inline records and measured CPU cost. Prepared records again
retain `AddressRangeSet`; the cache-independent publication correctness fix is
preserved. The measurements below describe the rejected experiment.

The experiment retained normalised coverage as `SmallVec<[AddressRange; 2]>`.
It still constructed a temporary set, then dropped it after collecting its
ranges. Index insertion and normalisation were unchanged. Transient removal
continued to iterate its temporary set directly.

The comparison below uses the correct pre-compaction implementation as its
baseline, not the earlier cache-dependent publication implementation. A counting
Rust global allocator measured three runs of each 256-operation transaction.
Instrumentation was confined to external executables and was not used for timing
comparisons. It counts requested Rust allocation sizes, not allocator metadata,
SQLite's native allocations or resident pages.

| Normal-cache transaction | Baseline peak live heap growth | Compact peak live heap growth |
| --- | ---: | ---: |
| Add 256 switches | 637.00 KiB | 637.56 KiB |
| Move 256 switch tables | 782.34 KiB | 646.34 KiB |
| Shrink 256 switch tables | 550.34 KiB | 414.34 KiB |
| Remove 256 switches | 475.45 KiB | 339.45 KiB |

Replacement/removal peak live Rust heap fell by 136 KiB per batch, or 544 bytes
per affected switch. This is a reduction in temporary retained memory, not in
the long-lived index. Allocation count is not reduced: coverage calculation
still allocates the temporary trees.

The field itself grows from 24 to 64 bytes. An external layout probe with the
same record fields measured 256 versus 296 bytes per record. Its isolated
256-record retention measurement changed from 210 to 74 KiB for one or two
normalised ranges, while total requested bytes increased by 10 KiB. Empty
coverage also pays the larger inline record cost. With three ranges, as in
disjoint two-level switch tables, SmallVec spills: the probe retained 98 KiB
instead of 210 KiB and incurred one additional allocation per record. Its
allocation count was 769 versus 513, including the record vector. No range-count
limit or alternate normalisation algorithm was introduced.

Uninstrumented release comparisons used two warm-up pairs and 16 measured pairs
with alternating execution order. The single-table transaction medians were:

| Operation | Normal cache, baseline → compact | One-byte cache, baseline → compact |
| --- | ---: | ---: |
| Add | 16.19 → 16.26 µs/op | 15.23 → 15.27 µs/op |
| Remove | 17.20 → 17.32 µs/op | 22.76 → 23.18 µs/op |
| Move | 21.10 → 21.19 µs/op | 25.13 → 25.38 µs/op |
| Shrink | 17.92 → 18.52 µs/op | 22.08 → 22.35 µs/op |

This is not a demonstrated CPU improvement: observed median increases were
0.3–3.3%, at most 0.60 µs per operation. The two-level spill workload ranged from
0.7% faster to 1.9% slower. Median process peak RSS changed from 48.40 to
48.18 MiB for the single-table workload and 49.24 to 49.16 MiB for two-level
tables. These process measurements are distinct from the allocator measurements.

End-to-end analysis medians were 7.587 → 7.580 ms for `ls.elf` and
129.455 → 127.938 ms for `libipmi.so`, with overlapping interquartile ranges and
unchanged result counts. Process peak RSS was mixed: 48.89 → 48.91 MiB and
133.21 → 134.42 MiB respectively. Both fixtures produced zero switches, so these
runs do not exercise retained previous switch coverage.

All 1,088 single-table and 1,856 two-level measured switch checks passed in each
variant, including identical and overlapping shared tables, removal, movement,
shrinking and shared target references. The same nine existing release suites
passed again: 686 tests, 29 ignored. No permanent tests or repository probe
scaffolding were added. Source snapshots, frozen binaries, external probes,
allocation records and timing samples are retained under
`rollback-backups/fix-gap-testing/coverage-compact-rpTFyY/` in the common Git
directory. ID-only block lookup and ranged-update profiling remain proposals;
neither was implemented as part of this change.

### ID-only overlaps and recovery profiling

Compact switch coverage was reverted without reverting the correctness fixes.
The retained production optimisation provides a public
`CodeBlockTable::get_ids_overlapping` iterator and uses it in
`FunctionTable::overlaps`. Persistent lookup reuses its existing ID collection
without fetching block entities; transient lookup streams index IDs without
boxing. Entity-returning overlaps and point lookups keep their behaviour. No
new index, cache or dependency mechanism was introduced.

The correct baseline and ID-only version used frozen release binaries with
SQLite enabled. Each workload had two warm-up pairs and 16 measured pairs,
alternating execution order. Lookup medians, in microseconds per query:

| Backend and range | Correct baseline | ID-only | Change |
| --- | ---: | ---: | ---: |
| Transient, 64 bytes | 0.292 | 0.242 | −17.3% |
| Transient, 1,024 bytes | 2.046 | 1.875 | −8.4% |
| Transient, 4,096 bytes | 7.779 | 7.206 | −7.4% |
| Persistent, normal cache, 64 bytes | 51.614 | 51.778 | +0.3% |
| Persistent, normal cache, 4,096 bytes | 665.190 | 663.181 | −0.3% |
| Persistent, one-byte block cache, 64 bytes | 59.434 | 52.155 | −12.2% |
| Persistent, one-byte block cache, 1,024 bytes | 257.633 | 181.290 | −29.6% |
| Persistent, one-byte block cache, 4,096 bytes | 1,016.129 | 662.027 | −34.8% |

Normal block cache capacity was 8 MiB. The one-byte configuration forces the
block-fetch miss path; it is not a representative cache-hit ratio. Transient
queries used 128 function entries and 1,000 repetitions; persistent queries used
32 entries and 20 repetitions. Compare variants within each workload, not the
absolute times across backends with different sample sets. Every sampled range
was checked against entity-returning overlap results outside the timer.

Three separate allocator-instrumented runs per backend measured one fewer Rust
allocation and 328 fewer requested bytes per transient range query. For a
64-byte range, mean requests fell from 3 allocations/337 bytes to 2/9 bytes.
Normal-cache persistent queries avoided approximately two allocations and
120 bytes each. With the one-byte cache and 4,096-byte ranges, requests fell
from approximately 2,905 allocations/169,032 bytes to 2,344/98,887 bytes per
query. These count Rust allocation requests, not native allocator traffic or
retained memory; instrumented runs were not used for latency comparisons.

The optimisation did not demonstrate an end-to-end latency improvement.
The 200-cycle range workload measured 126.31 → 127.31 µs per update, with
overlapping interquartile ranges. Point updates remained 6.214 ms.
`ls.elf` analysis was 7.369 → 7.367 ms and `libipmi.so` was
129.225 → 130.689 ms, also with overlapping interquartile ranges and unchanged
results. Process peak RSS did not demonstrate an improvement either:
48.88 → 48.89 MiB and 133.05 → 134.58 MiB respectively. The `libipmi.so` RSS
interquartile ranges were 132.42–135.83 and 134.42–135.80 MiB.

#### Isolated recovery attribution

Profiling was confined to separate source snapshots. No profiling module,
timers, counters or recovery-behaviour changes were added to production.
Nested timers report exclusive worker time separately from inclusive time and
parallel task elapsed time. The measured workload used serial candidate
execution; parallel task time was zero.

A common driver ran four update warm-ups and 200 measured updates per process.
Six variants ran two warm-up rounds and 16 measured rounds. Uninstrumented
original recovery took 96.09 µs/update but produced only 1,600 correct graphs
out of 3,200. Correct recovery took 135.34 µs/update and ID-only took 135.48;
both produced 3,200/3,200 correct graphs. The approximately 39.25 µs correctness
cost remains. These driver figures must not be compared as a speedup against
the different warm-up/cycle arrangements of earlier workloads.

The original-recovery instrumented diagnostic substitutes the original recovery
source into otherwise correct layers. It is a known-incorrect reference, not an
acceptable implementation. Instrumented latencies were 96.07 µs for that
reference, 134.73 for correct recovery and 134.53 for ID-only. Instrumentation
and code-generation differences mean these timings are diagnostic, not a precise
measurement of timer overhead.

Selected exclusive profile medians, in microseconds per update:

| Component | Original recovery diagnostic | Correct recovery | ID-only |
| --- | ---: | ---: | ---: |
| Recovery coverage setup | 29.25 | 29.10 | 29.15 |
| Recovery context construction | 10.92 | 20.49 | 20.53 |
| Setup boundary refresh | 2.67 | 4.68 | 4.59 |
| Region lookup and enqueue | 0.03 | 1.01 | 0.90 |
| Candidate selection, excluding execution | 5.52 | 12.66 | 12.37 |
| Serial candidate execution | 0.00 | 3.93 | 3.86 |
| Update staging | 3.78 | 10.10 | 10.13 |
| Transaction commit | 2.94 | 5.63 | 5.58 |

Work counts were identical across all 16 runs of each profiling variant.
Original recovery submitted no candidates during the measured replay. Correct
and ID-only recovery each submitted, recovered and committed the caller and
indirect reader once per update. Both used two dispatches and constructed two
recovery contexts per update, versus one each for original recovery. Candidate
execution occurred in one batch per update. There were no duplicate reanalysis
enqueues, retries, admission conflicts or recovery failures. Successful
transaction counts include empty completion-hook transactions, not just
change-producing commits.

The lookup optimisation saves roughly 0.11 µs in the profiled lookup/enqueue
portion; it does not address the approximately 39 µs total difference.
Coverage setup and repeated context construction are the larger next
investigation targets. Their lifecycle and discovery semantics were not changed.

The release build and ten existing suites passed: 695 tests, 29 ignored.
Measured range and point graph checks passed 3,200/3,200 and 640/640 respectively
in each correct uninstrumented variant. No permanent tests were added.
Snapshots, exact compiler invocations, frozen binaries, external probes and
raw results are retained under
`rollback-backups/fix-gap-testing/range-profile-GXwuTC/` in the common Git
directory. Runtime-mappings documents remain unchanged.

Persistent switch removal now removes its index entry only after the backing
write succeeds. A subsequent release build and isolated failure-injection probe
confirmed that a failed deletion preserves ID, branch and coverage lookups, and
that a successful retry removes the switch both immediately and after reopen.
Asserted-switch retention and function membership are unchanged.

### Dependency-attribution trial and provider configuration

The dependency trial extends the existing scheduled regions with function entries
from committed `FunctionAdded` and body-change records before associating the
batch's read set. Coverage accounting still uses the original scheduled regions.
Resynchronisation conservatively includes all current function entries; global
work remains global. Recovery and IR APIs are unchanged.

This fixes the unhinted transitive reader, but its update cost is not accepted.
Release measurements used two warm-up pairs and sixteen alternating measured
pairs, with identical provider-configuration fixes in both binaries:

| Scenario | Baseline median | Trial median | Difference |
| --- | ---: | ---: | ---: |
| Range update | 129.07 us | 130.65 us | +1.2% |
| Already-correct point update | 6.296 ms | 7.202 ms | +14.4% |
| Unhinted reader update | 121.97 us, incorrect | 7.001 ms, correct | Not equivalent work |
| `ls.elf` initial analysis | 7.643 ms | 7.670 ms | +0.4% |
| `libipmi.so` initial analysis | 131.993 ms | 133.802 ms | +1.4% |

All 3,200 range and 640 point updates per variant were correct. The unhinted
baseline retained a stale target and passed only 1,600 of 3,200 cycles; the trial
passed all 3,200. Initial graph counts agreed between variants.

A separate input-revision probe explains the broader recovery: each hinted
pointer update changed 299 existing functions in the baseline and 402 in the
trial. The unhinted baseline changed 298 functions on the first update and none
on the following three; the trial changed 402 on every update. The shared batch
read set now reaches discovered functions, but also causes their recovery when
another function's input changes.

Median point-update process peak RSS increased by 584 KiB. The newly correct
unhinted workload increased by 8.87 MiB; this comparison includes the additional
recovery work. Separate allocator-instrumented runs, five alternating pairs per
fixture, measured additional retained requested Rust heap of approximately
12.7 KiB for `ls.elf` and 99.4 KiB for `libipmi.so` after initial analysis.
These heap figures exclude mappings, native allocations and allocator overhead;
instrumented timings were not used for the timing comparison.

Configuration smoke checks confirmed that an unknown synthetic-provider tag
fails at creation, a valid saved configuration reopens, and an unknown saved tag
fails at reopen. A transient project with a supplied path successfully staged
and committed a file-backed synthetic mapping. Five existing release test suites
passed with 72 tests passed and four ignored. No permanent tests were added.

The persistent-provider flush redesign remains unimplemented. It would change
backing-file lifetime, saved layout, flush/reopen and cleanup in both providers,
including their private persisted format; it is not a small validation fix.

The complete pre-change source snapshot, original library, frozen baseline and
trial binaries, probe sources, commands and raw results are retained under
`rollback-backups/fix-gap-testing/dependency-admission-Sl1kjp/` in the common Git
directory. Runtime-mappings documents remain unchanged.

### Packed live metadata persistence

An external release-mode probe reproduced successful flush followed by failed
reopen before this fix. The same probe now passes out-of-order writes,
flush/reopen without destructors, shrink/regrow with further writes, empty
storage, and metadata-write failure followed by retry. Compacted close/reopen
preserved the expected bytes and produced exact backing lengths of eight and
eleven bytes in the successive write scenarios.

Nine existing Packed unit tests, five segment-persistence integration tests and
two reservation tests passed. No permanent tests were added. Source snapshot,
baseline library, external probe and before/after results are retained under
`rollback-backups/fix-gap-testing/packed-metadata-0m3fbpyp/` in the common Git
directory. Whole-project exit handling and the dependency-attribution trial
are unchanged.
