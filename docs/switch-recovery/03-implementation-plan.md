# Implementation Plan

Phased delivery of switch-case recovery per the [architecture](02-architecture.md).
Each phase is independently reviewable, lands behind tests, and leaves the tree
building. Phases are ordered so that value is delivered early (common tables
resolve after Phase 3) and the heavier semantic machinery is added only where the
syntactic tier falls short.

## Guiding constraints

- **Layering.** The lifter stays oblivious to analysis results: `Insn` keeps
  emitting `Unresolved` for `IBranch`; CFG edges arrive via local targets
  (Stage A) and reference derivation from `KnownTargets` (Stage B).
- **Cheap hot path.** Tier 0 must resolve common tables without SSA or emulation.
  Tier 1 and local SSA are built only when Tier 0 fails.
- **Idempotent + re-entrant.** Stage A runs repeatedly per function as the loop
  re-drives; it must skip already-resolved branches and converge.
- **No new magic thresholds as hard gates.** Bounds/validation feed
  `Confidence`; only clearly-invalid entries are hard-rejected.
- Follow repo conventions throughout: named structs over tuples, methods over free
  functions (prefer a static method on an existing type to a local `fn`), `rkyv`
  for on-disk records, `Address`/`RawAddress` idioms, lazy iteration (no
  collect-then-reiterate), no trivial helpers, no code comments, typed errors, and
  invariants enforced by visibility rather than defensive checks.

## Phase gate (enforced at every phase boundary)

No phase is complete — and the next must not begin — until **both** its **Exit**
criteria and this style gate are green. The gate is the `/rust-style-guidelines`
skill run against the phase's diff, treated as a blocking review: a violation fails
the phase exactly as a failing test does. The mechanical portion can be driven by
the `rust-style-lint` skill / `rust-lint` agent, with `/rust-style-guidelines` as
the authoritative spec. A phase's `**Gate:**` line below calls out what tends to
bite in that phase; the full checklist applies every time:

- **Formatting.** `cargo fmt -- --config
  imports_granularity=Module,group_imports=StdExternalCrate` produces no changes.
  Imports grouped std → external → crate with blank lines between groups; one
  module path per `use` (no nested `{}` spanning modules).
- **British spelling for every identifier** (`analyse`, `serialise`,
  `canonicalise`, `normalise`, `materialise`), consistent with the existing
  `canonicalise_address`.
- **No `pub` fields.** Every struct field is private with fluent accessors/mutators
  (`fn element_size(&self) -> u8`, `fn set_element_size(&mut self, to: u8)`).
- **Typed errors only.** `thiserror` enums with many specific variants (never one
  catch-all); **no stringly-typed errors** — no `Err(String)`, no `Box<dyn Error>`
  or `anyhow`-style opaque strings in library code. Messages lower-case except a
  leading proper noun/acronym (`"table entry unavailable: …"`, `"I/O error: …"`).
- **Borrowed over owned parameters:** `impl AsRef<[u8]>`/`&[u8]` not `&Vec<u8>`;
  `&Path` not `&PathBuf`; `&str`/`impl AsRef<str>` not `&String`. `to_owned`, not
  `to_string`, on `&str`.
- **`?` over `.unwrap()`/`.expect()`.**
- **No let-binding type annotations** — turbofish or inference
  (`let cases = Vec::new();`, not `let cases: Vec<SwitchCase> = Vec::new();`).
- **Inline format args:** `format!("{branch}")`, not `format!("{}", branch)`.
- **No emojis; self-explanatory names; zero code comments** (repo convention); one
  word per concept (`size`, not `len`/`length`).
- **No convenience methods that presume an implementation path** (don't add
  `read_entry` alongside a `read_entries` you're implementing).
- **No stray free functions.** If behaviour can be a method, it is one — an
  associated/static method on an existing type, or a method in the common location
  that already owns that concern. A local free function appears only when the
  behaviour genuinely belongs to no type; even then, prefer a static method on the
  most relevant existing type over a bare `fn`.
- **No excessively defensive code.** Do not add runtime checks for invariants the
  module already guarantees. Enforce library-internal invariants with visibility
  (`pub(crate)`/private constructors and fields) and the type system — make invalid
  states unrepresentable — rather than re-validating them at each call.
- **Names follow existing conventions and never force rename-on-import.** A new
  type/trait must not collide with an in-scope name such that a call site needs
  `as` renaming or path-qualification to disambiguate; check the crate before
  naming, and avoid bare names that shadow language concepts (`Slice`, `Table`,
  `Value`) — qualify them (`BranchSlice`, `AddressTable`).
- **Comments never reference the plan.** No `// Phase 3`, `// see
  02-architecture.md`, or milestone/PathMeld-style pointers in code; the code reads
  clearly on its own (the repo convention is zero code comments regardless).
- **Module layout:** `mod.rs` for modules with submodules, `name.rs` for leaves;
  no new-style module paths.

Plus the repo memory conventions already listed under Guiding constraints (structs
not tuples, methods over free functions, lazy iteration, `rkyv` on-disk, no trivial
helpers, `usize` only at physical slice indices).

## Phase 0 — Scaffolding and data model

**Goal:** the durable `ir` representation and detection exist; nothing wires yet.

- `ir/switch/mod.rs`: `Switch`, `SwitchId`, `SwitchProperties` (bitflags),
  `SwitchModel`, `SwitchCase`, `AddressTable`, `SwitchProvenance`, `RecoveryTier`,
  `SwitchEvidence` — shaped exactly like `ir/block/mod.rs` (rkyv derive, private
  fields + accessors/mutators, hand-rolled `ArchivedSwitchProperties`).
- `ir/switch/table/{mod.rs, persistent.rs, transient.rs}`: `SwitchTable` enum +
  `SwitchTableError`, mirroring `ir/block/table/`. `ir/mod.rs` re-exports beside
  `block`/`function`.
- `storage/schema.rs`: `ENTITY_SWITCH`.
- `analysis/switch/detect.rs`: `IndirectBranch::scan(function) -> impl
  Iterator<Item = IndirectBranch>` (a static method on the type it yields) scanning
  for `Op::IBranch`/`ICall` via the structured function's `UNRESOLVED` blocks and
  `InsnTarget::Unresolved`.
- `analysis/switch/mod.rs`: empty `SwitchRecovery` (Stage A) and
  `SwitchEnrichment` (Stage B) shells plus a `SwitchConfig`.

**Tests:** `Switch` rkyv round-trips through `SwitchTable` (in-memory backend);
`IndirectBranch::scan` finds the indirect branch in hand-lifted snippets (x86
`jmp rax`, ARM `bx r0`).

**Exit:** types compile, the `ir::Switch` representation persists/reloads,
detection covered, no behaviour change.

**Gate:** style gate green on the new `ir/switch/` representation and detection;
confirm `ir/switch/` matches the `ir/block/` form (accessors not `pub` fields,
British spelling, typed `SwitchTableError`) before Phase 1 builds on them.

## Phase 1 — Table reading, decoding, validation

**Goal:** given a `SwitchModel` and an index range, populate an `ir::Switch` with
validated cases. Split along the layering boundary: the ir type decodes its own
layout; the analysis fetches bytes and resolves addresses.

- `ir/switch/mod.rs`: `AddressTable::decode_entry(&self, bytes: &[u8]) ->
  RawAddress` — pure decode over a byte slice (element size, `endian`, `shift`,
  sign/zero extend); no `Project` dependency, so `ir` stays free of segment/arch
  deps.
- `analysis/switch/recover.rs`: a `Recovery<'a>` context holding `&Project`
  (segments + arch), with methods (no free functions):
  - resolve one entry: fetch `element_size` bytes via `view_at`/`bytes_at`, call
    `AddressTable::decode_entry`, add `base` for offset tables, then
    `Arch::canonicalise_address_with` to validate and derive the `ContextSet`
    (Thumb decode) → `SwitchCase`.
  - walk-and-validate: from entry 0, resolve each entry into the in-progress
    `ir::Switch`'s `cases`, stopping on the first invalid entry and setting
    `SwitchProperties::TRUNCATED` + `SwitchEvidence::Truncated` — mutating the
    `Switch` under construction rather than returning a side structure.

**Tests:** decode against a small in-memory segment fixture holding a known table
(absolute and offset-relative); truncation stops at an unmapped entry; Thumb-bit
targets canonicalise with the right context. Use real segment storage, not
hand-crafted byte blobs where a fixture binary is available.

**Exit:** table decoding is correct and endianness/mode-aware in isolation.

**Gate:** style gate green; table-reading failures are specific `thiserror`
variants with lower-case messages; segment/byte parameters are borrowed types
(`&[u8]`/`impl AsRef<[u8]>`), and reads propagate with `?`.

## Phase 2 — Tier 0 idiom matcher

**Goal:** recover model + local bound for the common idioms, no SSA.

- `analysis/switch/syntactic/mod.rs`: `IdiomMatcher` — a tree matcher over the
  ECode target expression of a `BranchIndirect`, with typed holes producing a
  `SwitchModel` + the `index` sub-expression.
- `analysis/switch/syntactic/patterns.rs`: the initial pattern set (x86/x86-64
  absolute + PIC offset, ARM/Thumb `tbb`/`tbh`/`ldr pc`, AArch64 `adr+ldr+add+br`,
  MIPS absolute + GOT-relative).
- Local bound scan: find `cmp index, N` + conditional branch in the branch block
  and its immediate dominator; yield a bounded or unbounded index.

**Dependency note:** Tier 0 needs the branch's ECode expression. Post-commit
(Stage B) this is `project.ecode(fid)`. Pre-commit (Stage A) requires lifting the
partial function's relevant block(s) to ECode; wire that in Phase 4. Until then,
exercise Tier 0 through Stage B / unit fixtures.

**Tests:** each pattern matches its target expression and extracts
`table`/`stride`/`base`/`signed`; a non-table indirect branch (`bx lr`) matches
nothing.

**Exit:** Tier 0 turns a matched idiom + bound into validated targets end-to-end
(Tier 0 → Phase 1), verified on fixtures.

**Gate:** style gate green; idiom patterns expose no `pub` fields; the matcher
returns `Result` propagated with `?`; pattern data lives in `patterns.rs` as a leaf
module (no new-style module paths).

## Phase 3 — Stage A: address recovery in the loop

**Goal:** common tables resolve during function recovery; case code gets lifted.

- `analysis/switch/mod.rs`: `SwitchRecovery` implements
  `AnalysisPass<PartialFunctionWithContext>` — for each detected branch not already
  resolved, run Tier 0; on success it builds an in-progress `ir::Switch` and emits
  its edges itself (emitting targets is the pass's own responsibility, not a
  separate module): `context_mut().add_local_target(branch, case,
  FlowKind::SwitchBranch)` for intra-function cases, `add_candidate_with_context`
  for foreign targets, and `TailCallBranch` for the single-foreign-target tail-call
  case. It stashes the in-progress `ir::Switch` on the partial function and records
  the branch as resolved.
- Register in `FunctionRecovery` construction via
  `add_builder_post_lifting_pass("switch-recovery", …)`.
- Clear `CodeBlockProperties::UNRESOLVED` once a branch has edges.

**Tests:** an integration test (mirroring `fugue-core/tests/engine.rs`) recovers a
function containing an x86 jump-table switch and asserts the case blocks are
lifted and wired as `SwitchBranch` successors; re-running is idempotent (no
duplicate edges); a switch whose cases are separate functions surfaces them as
candidates.

**Exit:** the load-bearing outcome — Tier-0-recoverable switches produce a
complete CFG through the existing recovery loop.

**Gate:** style gate green across the `FunctionRecovery` integration; the pass
touches existing files, so run the gate over those diffs too and match their import
grouping and error-type conventions rather than introducing a parallel style.

## Phase 4 — Local SSA for Stage A; value domain foundation

**Goal:** Stage A can recover tables Tier 0 cannot, and the reusable value domain
exists.

- `analysis/value/strided.rs`: `StridedInterval` over `BitVec` widths — lattice
  (join/meet/widen) + transfer functions for `Add`, `Sub`, `Mul`-const,
  `LeftShift`, `And`-mask, `ZeroExtend`, `SignExtend`; `Load` ⇒ top.
- `analysis/value/solver.rs`: bounded worklist solver over an ECode-SSA function
  computing an interval per value, applying guard constraints on conditional
  edges, with a widening iteration cap.
- Stage A local SSA: lift the partial function to ECode then ECode-SSA in-memory
  (existing `ECodeToSsa`) when Tier 0 fails, so Tier 1 has an SSA source
  pre-commit.

**Tests:** interval transfer functions and widening (unit); solver bounds a loop
index; solver derives `[0, N]` for a guarded switch index. Property test: interval
ops are sound over-approximations against brute-forced small-width value sets.

**Exit:** the value domain is a standalone, tested building block; Stage A has an
SSA source for Tier 1.

**Gate:** style gate green; the value domain defines specific `thiserror` error
types (no catch-all), uses turbofish/inference over let-binding annotations
throughout the solver, and keeps transfer functions as methods on the interval
type rather than free functions.

## Phase 5 — Tier 1 semantic recovery

**Goal:** back-slice → bound → emulate recovers offset/scaled/two-level tables and
merged-dataflow cases.

- `analysis/switch/semantic/slice.rs`: backward slice / path meld from the
  `BranchIndirect` value over ECode-SSA, producing the common spine + ordered ops;
  prune/point rules per the architecture.
- `analysis/switch/semantic/bounds.rs`: pick the smallest-range spine value as the
  normalized index using the value domain; pull guard conditions back through
  condition ops to constrain it.
- `analysis/switch/semantic/emulate.rs`: straight-line ECode evaluator over the
  slice; per index, evaluate to a target; record `Load`s as `AddressTable`
  observations and collapse contiguous same-size reads; abort on branch/call/
  unavailable memory (drop index, lower confidence).
- `SwitchRecovery`/`SwitchEnrichment`: fall through to Tier 1 when Tier 0 misses.

**Tests:** recover an offset-relative (PIC) table and a two-level table via
emulation on fixtures; a diamond/merged-path switch melds to one spine; an
unbounded-but-walkable table truncates by validation. Compare recovered targets
against ground truth extracted with the IDA MCP tools on the same fixture where
available.

**Exit:** the general fallback matches Ghidra's coverage on the standard table
shapes.

**Gate:** style gate green; slice/bound/emulate helpers are methods on their types,
not free functions, and no trivial single-use helpers are extracted; iteration over
indices and slice ops stays lazy (no collect-then-reiterate).

## Phase 6 — Stage B enrichment: labels, default, references, persistence

**Goal:** committed functions get labels, typing, references, and a persisted
`ir::Switch`.

- `analysis/switch/labels.rs`: denormalise the index (bounded reversible ops) and
  reverse-evaluate each target's index to case labels, filling the in-progress
  `ir::Switch`; identify the default from the guard's out-of-range edge;
  reversibility limits feed confidence.
- Persistence reuses the transaction API — no new module: `SwitchEnrichment`
  persists the completed `ir::Switch` via `ProjectTransaction::insert_switch`
  (added in Phase 0 alongside `switches()` / `ENTITY_SWITCH`), matching
  `add_function`.
- References reuse the existing derivation path: `SwitchEnrichment` emits
  `AddressAnnotationValue::KnownTargets`/`ComputedSpace` on the branch P-code op,
  and the extension to `il/pcode/builder.rs` + `project.rs`
  `replace_ir_derived_references` turns `KnownTargets` into `JUMP | COMPUTED` flow
  refs and constant DATA refs into the table bytes (beside `Insn::flow_references`
  and `PCodeIr::data_references`).
- `SwitchEnrichment` implements `Analyser` (`Trigger::FunctionAdded`,
  `Priority::DERIVED`); register via `registry::submit!{ AnalyserProvider::new(…) }`.

**Tests:** references from the branch to each case exist post-commit with
`COMPUTED`; the `ir::Switch` entity persists and reloads through `SwitchTable`
(SQLite + MDBX backends, per `tests/engine.rs`); labels match known case values;
the table's DATA refs are marked constant.

**Exit:** switch information is complete, queryable, and durable.

**Gate:** style gate green; the `ir::Switch` record is `rkyv`-derived over private
fields with accessors (no hand-rolled byte packing), matching `ir::CodeBlock`; the
annotation/reference derivation uses inline format args and borrowed parameters.

## Phase 7 — Overrides, spec-assisted models, cross-function multi-stage

**Goal:** cover the hard tail and cross-function completion.

- Override intake (annotation/API) → validation + labelling, bypassing detection.
- Spec-assisted idioms via `fugue-specs`/`.cspec` producing
  `SwitchModel::Explicit`.
- Stage B multi-stage: on `FunctionAdded`, re-examine partial tables whose new
  case code now reveals more entries or a foreign target set; extend and re-emit.

**Tests:** a user override resolves an otherwise-unrecoverable branch; a
spec-assisted idiom fixture resolves; a two-stage table (entries in a second
function) completes across two `FunctionAdded` cycles.

**Exit:** parity with the reference tools' override/assist paths plus graceful
partial completion.

**Gate:** style gate green on override/assist intake; spec-derived identifiers keep
British spelling and consistent vocabulary with the rest of the feature.

## Phase 8 — Hardening and evaluation

- Corpus evaluation across arches (x86-64, ARM/Thumb, AArch64, MIPS) using the
  local test binaries and, where present, IDA-derived ground truth via the MCP
  tools. Track recall/precision per tier and per arch.
- Fuzz table reading against malformed/short segments (no panics, bounded work).
- Tune confidence weighting from corpus results; document residual gaps.
- Benchmarks: ensure Tier 0 adds negligible cost to `FunctionRecovery` and Tier 1
  fires only on the tail (`benches/analysis_engine.rs`).

**Gate:** final `/rust-style-guidelines` sweep across the entire feature — every
module under `analysis/switch/` and `analysis/value/` plus the touched existing
files — must be clean before merge, with `cargo fmt --check` (Module granularity,
`StdExternalCrate` grouping) passing tree-wide.

## Dependency graph

```
Phase 0 ─┬─► Phase 1 ─► Phase 2 ─► Phase 3   (common tables resolve)
         │
         └─► Phase 4 (value domain + local SSA) ─► Phase 5 (Tier 1)
                                                       │
Phase 3, 5 ──────────────────────────────────────────┴─► Phase 6 ─► Phase 7 ─► Phase 8
```

Phases 1–3 deliver the high-value common case with no SSA. Phase 4 is the one
substantial new primitive (the value domain), reusable beyond switches. Phases
5–7 add generality; Phase 8 hardens.

## Test strategy notes

- Prefer **real binaries** and the real executable/object API for fixtures (per
  repo convention); derive addresses from the loaded image rather than hard-coding.
  Reuse the `tests/` fixtures and `FUGUE_LANGUAGE_DIR`-gated pattern already used
  by recovery tests; add small switch-heavy fixtures per arch.
- Where ground truth helps, cross-check recovered tables against IDA via the `ida`
  MCP tools (`decompile`, `xrefs_from`, `get_bytes`) on the same binary.
- Unit-test the value domain with property tests (soundness vs. brute force on
  small widths) since it underpins bound correctness.
- Integration-test through the real `AnalysisEngine` (as `tests/engine.rs` does),
  asserting CFG edges, references, and the persisted entity across storage
  backends.

## Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Pre-commit local SSA cost in the hot loop | Build it only when Tier 0 misses; Tier 0 covers the common case without SSA |
| Value-domain imprecision ⇒ oversized ranges | Rely on table-walk validation to terminate; cap widening; record low confidence and defer to Stage B |
| Emulation aborts (branch/call on path, unmapped table) | Drop the offending index, keep the valid prefix, lower confidence — never fail the whole function |
| Re-drive non-convergence | Strict idempotency: resolved-branch set on the partial function; targets are a set |
| Mode-bit (Thumb) errors | Decode/validate via `canonicalise_address_with`; carry `ContextSet` on every `SwitchCase` |
| Storage schema churn | MVP allows no back-compat; add `ENTITY_SWITCH` directly |
