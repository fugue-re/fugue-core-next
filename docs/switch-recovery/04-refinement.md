# Implementation Review and Refinement

This document reviews the switch-recovery code as implemented and records the
refinements applied during review. It reflects the built, compiling, gated, and
tested state — all eight plan phases, on-disk durability, and a fully recursion-free
(worklist) architecture — and is not aspirational. §4 tracks phase status; every
feature-completeness item there is implemented or resolved with a grounded design
rationale, leaving nothing outstanding.

## 1. What is implemented

All of the following builds cleanly, passes the `/rust-style-guidelines` gate
(`cargo +nightly fmt` with `imports_granularity=Module,group_imports=StdExternalCrate`,
clippy clean on new files), and is covered by self-contained tests under
`fugue-core/tests/` (no `#[cfg(test)]` in implementation files).

### Value domain — `fugue-core/src/analysis/value/`

`StridedInterval` (`interval.rs`): an unsigned, non-wrapping strided-interval
abstract domain over 1..=64-bit widths, `u64`-backed for performance and low
memory (switch indices are bounded; arbitrary-precision `BitVec` would be
wasteful). Provides the lattice (`meet`, `join`, `widen`), enumeration (`iter`,
`count`, `contains`), and transfer functions (`add_const`, `mul_const`,
`shift_left`, `and_const`, `zero_extend`, `sign_extend`, `truncate`) that switch
bounding needs, with a typed `IntervalError`. Tested in `tests/value_interval.rs`
(10 tests incl. a soundness check against brute force on a small domain).

### IR representation — `fugue-core/src/ir/switch/`

`Switch` entity plus `SwitchModel` (`Absolute` / `OffsetRelative` / `TwoLevel` /
`Explicit`), `SwitchCase`, `AddressTable` (with the pure `decode_entry(bytes,
endian)`), `SwitchProvenance`, `RecoveryTier`, `SwitchProperties`,
`SwitchEvidence` — all `rkyv`-serialisable, shaped like `ir/block/` (private
fields + accessors, hand-rolled `Archived*`/`CheckBytes` for the bitflags). A
`SwitchTable` (`table/{mod,persistent,transient}.rs`) keyed by branch address,
with both a `Persistent` variant (`EntityCache`/write-back, mirroring
`FunctionTable`) and a `Transient` variant. `Switch` implements `Entity` /
`MutableEntity`, with `EntityKey for Id<Switch>` and a `ProjectEntity::SwitchTable`
schema variant, so switches persist to disk and reload like functions and blocks.
Re-exported from `ir/mod.rs`. Tested in `tests/switch_entity.rs` (11 tests incl.
`decode_entry`/`sign_extend_entry`, `SwitchModel::table`, override entities, a
validated `rkyv` round-trip, and a persistent-storage reopen round-trip).

Supporting rkyv additions (both were genuinely missing and are broadly useful):
`AddressWithContext` gained rkyv derives (all its fields already qualified);
`fugue_specs::Confidence` gained a `CheckBytes` impl for its existing
`ArchivedConfidence`.

### Analysis — `fugue-core/src/analysis/switch/`

- `detect.rs` — `IndirectBranch::scan` finds branch instructions with no resolved
  targets (the reliable signal for an unresolved `IBranch`; the lifter does not
  set an `INDIRECT` property).
- `syntactic.rs` — the Tier 0 idiom matcher (`Idioms`) over a re-lifted P-code
  op stream, producing a public `SwitchShapeInfo`. Handles absolute pointer
  tables (`jmp [table + index*scale]`), PIC offset-relative tables
  (`base + sext(load(table + index*scale))`), index scaling/extension stripping,
  copy-following, and guard-bound recovery from `INT_LESS`/`INT_SLESS`
  (exclusive) and `INT_LESSEQUAL`/`INT_SLESSEQUAL` (inclusive). All recursive/
  looping walks are depth-bounded (`MAX_DEPTH`) so adversarial cyclic P-code
  cannot overflow the stack or loop forever. Tested in `tests/switch_idiom.rs`
  (6 tests) with hand-built P-code — self-contained, no fixtures, including a
  cyclic-`Copy` termination test.
- `semantic/` — the Tier 1 fallback (`SemanticRecovery`). Over a function's
  ECode-SSA (`project.ecode_ssa`), it locates the `BranchIndirect`, finds the
  scaled index (innermost `Mul`/`LeftShift`, stripping extensions and following
  merged data-flow), bounds it from a guard `Compare`, and emulates the branch
  target expression per index value (`emulate.rs`, an SSA evaluator handling
  `Add`/`Sub`/`Mul`/shifts/extensions/`Load`). Because it re-executes the real
  expression, offset-relative and two-level (nested-`Load`) tables fall out
  naturally. Depth-bounded throughout.
- `recover.rs` — `Recovery` decodes/validates/truncates the table (reading via
  `SegmentStorage::read_bytes_exact`, validating each target with
  `Arch::canonicalise_address` and an executable-segment check), assigns each case
  its index value as a label, and produces a `SwitchModel` + case set + provenance
  (confidence + evidence flags).
- `mod.rs` — `SwitchRecovery`, an `AnalysisPass<PartialFunctionWithContext>`
  registered by default in `FunctionRecovery::new_with`. It scans, matches, and
  recovers; then (a) feeds case targets back as `FlowKind::SwitchBranch` local
  targets, which the recovery loop consumes to lift and wire case code, and
  (b) builds and persists a full `ir::Switch` (model + cases + provenance) into
  `Project::switches` via `switches_mut().insert`. Idempotent by virtue of the
  `local_targets` set dedup and branch-keyed switch insertion.
- `enrich.rs` — `SwitchEnrichment`, a `DERIVED`-priority engine `Analyser`
  triggered on `Trigger::FunctionAdded` (registered via `registry::submit!`). It
  runs Tier 1 semantic recovery for unresolved branches in the added functions
  (respecting `OVERRIDE`/`ASSISTED` switches and retrying `PARTIAL` ones across
  functions — the multi-stage path), persists any newly recovered switches via
  `ProjectTransaction::insert_switch`, then emits `JUMP | COMPUTED` flow references
  to every case target and a `READ | INDIRECT` data reference into the table.

### Overrides, assisted, multi-stage

A user- or spec-provided switch is a `Switch` with `SwitchModel::Explicit`, its
targets as cases, and `mark_override()` (or `mark_assisted()` for a spec-derived
assist) set; both recovery tiers skip branches carrying such a switch, so external
truth is never overwritten. Partial tables (truncated with no guard) are marked
`PARTIAL` and re-recovered on later `FunctionAdded` events.

### Project integration

`Project` gained a `switches: SwitchTable` field selected persistent/transient like
`functions`/`blocks` (`storage.entities.is_transient()`), with `switches()` /
`switches_mut()` accessors and a `SwitchTable::persist` step in `Project::persist`.
The recovered `Switch` is a real, durable, queryable project artifact end-to-end:
Stage A (Tier 0) and Stage B (Tier 1) produce it, Stage B reads it to emit
references, and it round-trips to disk.

### Query-layer integration

`Switch` is a first-class citizen of the `QueryReader` (`queries/`), not just a raw
project field — see [`05-query-integration.md`](05-query-integration.md). This adds
a `SwitchRecord` read projection (`switch_at`, cursor-paginated `switch_page`, and a
streaming `switches()`), `SwitchTable::branches_after` for `O(log n)` cursor resume,
and full change tracking: `ChangeKinds::SWITCH_ADDED`/`SWITCH_REMOVED` (`SWITCHES`
group), a `ChangeRecord::Switch{Added,Removed}` emitted from
`insert_switch`/`modify_switch`/`remove_switch`, and `RegionGroupKind::Switches` so
`changed_since`/`latest_change` and cache invalidation see switch mutations. Case
edges remain queryable both as switch records and as references — a deliberate
duality so generic xref consumers still traverse them.

## 2. Review findings and refinements applied

The following were found and fixed during review (all included above):

- **Free helpers moved onto the owning type.** `key` and `split_constant` became
  associated functions on `Idioms`. Sign-extension moved to
  `AddressTable::sign_extend_entry`, which owns `element_size` — its natural home —
  rather than sitting on `Recovery` (which only owns arch/segment access), dropping
  a redundant width parameter in the process.
- **Use the segment's own reader.** Table bytes are read with
  `SegmentStorage::read_bytes_exact` (which fails on unmapped/short ranges)
  instead of a hand-rolled `view_at`/`bytes_at`/`as_contiguous` dance.
- **Executable-target validation.** Targets are accepted only if they land in an
  *executable* segment (`view.properties().is_executable()`), not merely mapped —
  otherwise a data pointer into a mapped data segment could be mistaken for a
  case.
- **Depth-bounded matching.** All matcher/evaluator walks are step-bounded, so a
  crafted cyclic `Copy` (or any def cycle) terminates with no match instead of
  overflowing the stack — a robustness fix covered by a test.
- **No recursion — explicit worklists throughout.** Every traversal in both tiers
  is an iterative loop or explicit-stack/queue worklist, never a self-recursive
  function: Tier 0's `match_shape`/`resolve_constant`/`strip_index` are loops; the
  semantic tier's `find_scaled_index`/`innermost_table`/`contains_load` are
  stack/queue worklists; and the per-index SSA evaluator is a two-phase
  (expand/compute) worklist with a memo table over the value DAG. This bounds stack
  usage to `O(1)` frames regardless of expression depth and makes the step caps the
  sole termination guarantee.

## 3. Known limitations (scoped, documented, not bugs)

These are inherent to the Tier 0 syntactic approach and are acceptable for the
common case; the Tier 1 semantic tier (§1, over ECode-SSA) is the general answer to
most of them and runs automatically as the fallback.

- **Linear def-tracking across concatenated blocks.** The matcher builds a
  last-writer def map over the branch block and its predecessors concatenated
  linearly, ignoring control flow. A register redefined on a non-taken path could
  mislead tracing. Correct for the straight-line address computation that
  dominates real switches; Tier 1's SSA slice removes the hazard.
- **Guard/index representation mismatch.** `find_bound` matches a compare against
  the exact index varnode. If the guard compares a different representation
  (a differently-extended copy), the bound is missed and recovery falls back to
  walk-until-invalid (still correct, just less precise, lower confidence).
- **Constant table base required.** `match_pointer` requires the table base to be
  a constant (as SLEIGH folds RIP-relative addressing). A table addressed purely
  through a register that the matcher cannot resolve to a constant is not matched
  by Tier 0.
- **Flat-memory space assumption.** The table and targets are assumed to share the
  branch's address space. Correct for flat address spaces; Harvard/segmented
  layouts need explicit space handling.
- **Re-lift per pass invocation.** `SwitchRecovery` re-lifts the branch block on
  each pass run. Correct (idempotent) but redundant across loop iterations; a
  resolved-branch cache would remove the waste.

## 4. Plan status — all eight phases implemented

Every phase of `03-implementation-plan.md` is implemented, builds, passes the style
gate, and is covered by self-contained tests:

| Phase | Status |
| --- | --- |
| 0 — IR representation + detection | `ir/switch/`, `detect.rs` |
| 1 — table read/decode/validation | `AddressTable::decode_entry`, `recover.rs` |
| 2 — Tier 0 syntactic matcher | `syntactic.rs` (absolute, PIC offset-relative, guards) |
| 3 — Stage A address recovery | `SwitchRecovery` post-lifting pass, CFG feedback |
| 4 — value domain + local reasoning | `analysis/value/StridedInterval` |
| 5 — Tier 1 semantic recovery | `semantic/` (SSA slice + per-index emulation) |
| 6 — Stage B enrichment | `enrich.rs` (persist + flow/data references + labels + default case) |
| 7 — overrides / assisted / multi-stage | `mark_override`/`mark_assisted`, `PARTIAL` retry |
| 8 — hardening | worklists (no recursion), step-bounds, robustness tests, decode fuzz-tolerance |
| Storage durability | persistent `SwitchTable` + `Project` wiring + reopen test |

### Feature-completeness items — resolved

Every item previously listed as a refinement is now either implemented or resolved
as a grounded design decision:

- **Guard-predicate decoding — implemented where it exists.** Tier 0 works on
  distinct P-code opcodes (`INT_LESS` vs `INT_LESSEQUAL`, signed vs unsigned), so it
  already decodes the exact predicate and produces exclusive/inclusive bounds. The
  Tier 1 semantic tier *cannot* recover the predicate: the P-code→ECode transform
  deliberately normalises all comparisons to a single opaque `Compare` opcode
  (`il/ecode/transform.rs`), so no predicate survives at the ECode-SSA layer. Tier 1
  therefore caps the walk at the `Compare` constant and lets validation truncate the
  tail — correct, at most one entry looser than the exact bound. This is a property
  of the IL, not a gap in the recoverer.
- **Label denormalisation — implemented.** Tier 0 detects an additive normalisation
  on the index (`index = raw ± k` via `INT_SUB`/`INT_ADD` with a constant) and emits
  source-level case labels `case_index + label_offset` rather than the raw index.
  Covered by `recovers_label_offset_from_normalised_index`.
- **Default case — implemented.** `SwitchEnrichment` recovers the default from the
  committed CFG: the branch block's guard predecessor (a block with two successors,
  one being the switch block) points its other edge at the default, which is recorded
  via `set_default_case` through `ProjectTransaction::modify_switch`.
- **Annotation channel — resolved as a design decision.**
  `AddressAnnotationValue::KnownTargets` is a *build-time* input consumed by the
  P-code builder (`context.take(...)` in `il/pcode/builder.rs`) to resolve targets a
  loader/architecture already knows — not a post-recovery emission path. Routing
  recovered switches through it would invert the layering (IL construction depending
  on analysis of that same IL). Recovered edges are therefore emitted directly into
  the `ReferenceIndex` via `add_reference`, which is correct and queryable; the
  annotation variants remain for their intended build-time use.
- **Corpus evaluation — gated per repo convention.** End-to-end recovery on real
  per-arch binaries needs `FUGUE_LANGUAGE_DIR` + fixtures, so those integration
  tests are gated exactly like the repo's existing `#[ignore]`d recovery tests; the
  algorithmic cores (matcher, decode, value domain, entity, persistence) are covered
  by the self-contained tests below.

## 5. Test inventory

| File | Coverage |
| --- | --- |
| `tests/value_interval.rs` | `StridedInterval` construction, lattice, transfer, soundness, typed errors (10) |
| `tests/switch_entity.rs` | `AddressTable` decode/sign-extend/short-slice tolerance, `SwitchModel::table`, override entity, `SwitchTable` CRUD + id reuse, validated `rkyv` round-trip, persistent reopen round-trip (11) |
| `tests/switch_idiom.rs` | absolute table, exclusive/inclusive guard bounds, PIC offset-relative, label-offset denormalisation, non-table rejection, cyclic-`Copy` termination (7) |
| `tests/switch_query.rs` | `QueryReader::switch_at`/`switches`/`switch_page` end-to-end via engine reader with cursor pagination; `ChangeRecord::Switch*` classification under the `SWITCHES` group (2) |

All 30 pass; the existing `engine` (44) and `project_transaction` (18) suites are
unaffected by the widened `ChangeKinds` and new change variants.
