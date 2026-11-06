# Runtime mappings implementation checklist

Contract: [01-design.md](01-design.md). The explicit dependency pass has been rolled back and its contract withdrawn; §10.3 is the agreed model and is implemented. Earlier provider/runtime work is preserved. Thunk-target recovery optimisation and a parallel worker pool are outside this work.

Check an item only after its implementation or validation evidence is recorded here. Use existing tests and temporary real-fixture probes; add no permanent tests. Run `cargo house-style check` on every touched scope.

## 1. Engine matching (§10.3)

- [x] `TRACKED_DEPENDENCY_KINDS = ChangeKinds::all() − (SEGMENTS | ADDRESS_SPACE_CREATED)` in `engine/mod.rs`; `route_changes` excludes other kinds from dependency routing; `ReadSet::conflicts_with` takes the same set for admission.
- [x] `ProjectView::read_bytes` records `BYTES_WRITTEN` only. `segments()` on `ProjectView` and `ProjectTransaction` unchanged.
- [x] `invalidates_bytes` → `retracts`, covering `BytesWritten`, `SegmentUnmapped`, `SegmentMapped`, `SegmentMappingChanged`; `RETRACTED_BY_BYTE_CHANGE` → `PHASES_CANCELLED_BY_RETRACTION`.
- [x] `Analyser::retract(&mut self, regions: &AddressRangeSet)` with a no-op default, called with the retract set from `route_changes`, with the batch regions on admission conflict or rejection, and on an analyser error.
- [x] `ReadSet` overflow collapses a kind to the whole ranges of its observed spaces instead of an unbounded read.
- [x] `DependencyIndex::record` merges a continuation's reads with the sets previously recorded for its regions; entries are `DependencyReadSet` (identity equality) keyed by `RawAddress`; regionless reads, work and invalidation are `global`.

## 2. Location rule (§10.3–10.4)

- [x] Switches: `Switch::coverage_into`, `SwitchIndex` coverage index, `SwitchTable::overlaps` and `staged_overlaps`, owners retired from `invalidate_functions_in_range`.
- [x] Pointer slots: `ProjectView::add_dependency(kinds, range)` (public; `read_bytes` without the read); the function builder and thunk pass declare the slot with `BYTES_WRITTEN` after their cached read. No slot field on instructions, blocks or functions and no new reference path.
- [x] Function recovery implements `retract`: drop pending functions and candidates intersecting the regions and clear continuation coverage and context. No revisions, dependency sets or budgets in recovery.
- [x] Function recovery re-recovers functions containing `BYTES_WRITTEN` dependency cause ranges; other kinds reach it through `triggers()`. Attribution is batch-wide (§10.4).
- [x] The transaction infers no reads for staged function coverage or switch tables; the location rule covers them (§10.6).

## 3. Change records (§10.5)

- [x] `prepare_write` projects each provider chunk through every committed or staged mapping on that provider into its placements; `PreparedSegmentWriteRecords::range()` → `ranges()`; `write_bytes` retires functions and emits `BytesWritten` per range.
- [x] No new record kinds, payloads or visibility fields; hidden placements of an aliasing mapping are included.
- [ ] Deferred, not in this pass: `ChangeIndex` spatial handling of `SegmentMappingChanged`; `Dependency::covers` same-kind union.

## 4. Existing synthetic-space surface (§2–9, §11–13)

- [x] Preserve agreed names and provider-descriptor access; no storage renames or exposed backing offsets. The only storage change is the placement projection in `prepare_write`.
- [x] Transient and persistent engine APIs, named base/overlay lookup, lazy provider creation, append/growth, removal and reload: covered by the existing `fugue-core` suites, which pass on the final tree.
- [x] `fugue-python`, `fugue-workbench` and `fugue-core-idalib` pass `cargo check` against the final core; no binding surface changed.
- [x] Unsuccessful transactions leave no provider file, space or identifier gap; repeated analyses reuse names/mappings: existing suites, unchanged behaviour.

## 5. Behaviour and performance acceptance (§10.7, §13–14)

- [x] Existing suites with `sqlite`, Clippy and house-style after integration; no new permanent tests.
- [x] Temporary probes: pointer-slot write re-recovers the reader (§14.4); unrelated space and mapping creation does not dependency-reschedule recovery (§14.4); switch-table write retires the function (§12); a write through the original placement of a writable mapping aliased into a second base space emitted `BytesWritten` in both spaces and retired the function at the alias placement; 1,100 disjoint `BYTES_WRITTEN` reads in one space collapsed to that space, still matching a change in a gap there and not a change in another space. Not exercised: a placement change over a pending function between dispatches (needs mid-analysis interleaving the engine API does not expose), materialised-IL and cached-`Term` recomputation at the alias, and permission/shadow/reveal changes beyond the existing suites.
- [x] Baseline frozen and compared with repeated interleaved `bench`-profile builds, identical fixtures and instrumentation (§14.4): `ls.elf` +0.8%, `libipmi.so` +1.3%, quartiles overlapping, memory unchanged.
- [ ] Separate measurement of admission, routing and analyser execution for the §10.7 workload list; §14.4 reports whole-run figures and the dependency-reschedule and dispatch counts only.
- [x] §12 and §14 updated; temporary probes removed.

## Evidence

- Implementation baseline: working tree on `fd0447f`; historical acceptance and failures remain in design §14 until superseded.
- Thunk-target recovery is retained unchanged in both baseline and revised measurements.
- Rollback restored 36 Rust files and both documents from the pre-implementation working-tree snapshot; eleven restored files already contained pre-pass changes against HEAD, preserved across 24 files. Persistent backups: `/Users/slt/Projects/fugue-v0.3/fugue-core/.git/rollback-backups/fix-gap-testing/runtime-dependencies-pBunbu/` (`baseline/` and `before-rollback.tar.gz`). Do not remove.
- Switch-table location: temporary `ls.elf` probe (function with an `Absolute` table at `entry + 0x100`, outside its coverage): `overlaps` returned exactly that switch for a one-byte range in the table and nothing for an unrelated address; a write at `entry + 0x300` retired nothing; a write at `table + 3` retired the function and switch and emitted `FunctionRemoved`.
- Engine model: final-tree measurements and probe results are in design §14.4. The pre-pass snapshot predates concurrent storage work and was not used as the performance baseline; the baseline was the final tree with only this pass's hunks removed.
- Gates on the final tree: full `fugue-core` suite with `sqlite` (library and all integration suites), Clippy clean in touched files, `cargo house-style check` clean on `engine`, `queries`, `ir/switch`, `ir/function/table`, `ir/address.rs`, `project/transaction`, `project/read.rs`, `analysis/function/recovery`, `analysis/thunk`, `storage/segments/mod.rs`, `storage/segments/staging.rs` and `tests/global_work.rs`, apart from the pre-existing findings in `metrics.rs`, `recovery/analysis.rs:147`, `thunk/mod.rs` and `queries/cache.rs` (`clear_lifted` order).
