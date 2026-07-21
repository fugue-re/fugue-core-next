# Switch Recovery — Outstanding Work & Validation Log

This is the source of truth for the rework. Every item has a **validation** command
or check that must pass before its status becomes DONE. Status is never DONE on
assertion alone — only after the recorded validation passes. Updated as work
proceeds.

Legend: `TODO` · `WIP` · `DONE` (validation passed) · `BLOCKED`.

## Design decision: value representation boundary

- **ECode / ECode-SSA IL storage stays `(u64 immediate, u32 width)`.** P-code
  immediates originate as `u64` (`Varnode::constant(u64, size)`), so this is
  lossless at the source; converting IL *storage* to `BitVec` would be
  framework-wide churn (rkyv archived forms, all builders/transforms/tests) for no
  correctness gain. Rejected.
- **The IL exposes width-correct `BitVec` at its query boundary** — e.g.
  `ECodeSsaOp::constant() -> Option<BitVec>` — so consumers never rebuild values by
  hand from `(u64, width)`.
- **The value domain (`StridedInterval`) is `BitVec`-native** (bounds + stride are
  `BitVec` at the index width) — answers review #21.
- **The switch analysis computes entirely in `BitVec`**, seeded from the IL's
  `BitVec` accessors and from `AddressTable::decode_entry -> BitVec`.
- Addresses remain `Address` / `RawAddress`; a `BitVec` target is lowered to
  `RawAddress` only at the validated-target boundary.

## A. Review comments (round 3)

| # | Location | Issue | Fix | Validation | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | enrich.rs `SwitchEnrichment` | vague/misleading name | rename `SwitchAnalyser`, registered `switch-analysis` | grep: no `SwitchEnrichment`; builds | DONE |
| 2 | detect.rs `IndirectBranch` pub + generic | not pub, better name | `pub(crate) IndirectBranchSite` | grep: no `pub struct IndirectBranch`; not in crate pub API | DONE |
| 3 | model.rs `SwitchConfig` | → `SwitchRecoveryConfig` | rename | grep: no `SwitchConfig` | DONE |
| 4 | model.rs `TargetValidator` | → `SwitchTarget…` | rename `SwitchTargetResolver` | grep: no `TargetValidator` | DONE |
| 5 | model.rs `maps_executable` | one-use helper; `view_at` already ensures `contains` | inline; drop `contains` check | grep: no `maps_executable`; no `.contains(` in resolve | DONE |
| 6 | recover.rs `Idioms` | not self-describing | rename `SwitchIdiomMatcher` | grep: no `Idioms` | DONE |
| 7 | recover.rs entry addr `+` | wrapping not checked | `checked_mul`/`checked_add`, break on overflow | code review + build | DONE |
| 8 | emulate.rs `Evaluator` | poorly named | rename `SwitchEmulator` | grep: no `Evaluator` | DONE |
| 9 | emulate.rs `new` arg order | inconsistent | standardise `(ssa, arch, segments, …)` | matrix check below | DONE |
| 10 | emulate.rs LHS type annotations | forbidden | turbofish/inference everywhere | grep: no `let …: T =` in switch | DONE |
| 11 | emulate.rs `evaluate`/`compute` | bad API names | `emulate`/`apply` | grep | DONE |
| 12 | semantic `TableShape` | → `SwitchTableShape` / distinct | rename `TableLayout` | grep: single def | DONE |
| 13 | semantic `SemanticRecovery` | naming consistency w/ syntactic | tiers as parallel dirs | tree parity | DONE |
| 14 | semantic `constant` | belongs on op | `ECodeSsaOp::constant()` | grep: method on op | DONE |
| 15 | semantic `strip_copies` | belongs on IL | `ECodeSsaIr::skip_copies` | grep | DONE |
| 16 | semantic `non_constant_operand` | belongs on IL | `ECodeSsaIr::sole_non_constant_operand` | grep | DONE |
| 17 | semantic `branch_target` | belongs on IL | `ECodeSsaIr::indirect_branch_input` | grep | DONE |
| 18 | syntactic module | bad naming, u64, VarKey mess | rename types, RawAddress, `VarnodeKey` newtype | grep: no `VarKey`, no raw table `u64` | DONE |
| 19 | syntactic `Idioms` | not descriptive | (same as #6) | — | DONE |
| 20 | syntactic `HashMap` | use FxHashMap | `FxHashMap` | grep: no `std…HashMap` in switch | DONE |
| 21 | value/interval.rs | should work with BitVec | make `StridedInterval` BitVec-based | grep: BitVec fields; tests pass | DONE |

## B. Value domain — the core integration gap (was unfinished)

The value domain was designed (Phase 4 / architecture §10) to bound+stride the
switch index, but was never wired in — the semantic tier used an ad-hoc
`guard_bound`. This is the main unfinished work.

| Item | Validation | Status |
| --- | --- | --- |
| B1 `StridedInterval` uses `BitVec` bounds/stride | tests pass; fields are `BitVec` | DONE |
| B2 index value-set solver over SSA (guards, mask, stride) | unit test on hand-built SSA or via seam | DONE |
| B3 semantic tier drives enumeration from the interval (replaces `guard_bound` + `0..limit`) | grep: `StridedInterval` used in `semantic/`; recovery still works | DONE |
| B4 value domain is actually referenced by non-test code | grep: `StridedInterval` outside `analysis/value/` and tests | DONE |

## C. Global gates (must pass at end of every work session)

| Gate | Command | Last result |
| --- | --- | --- |
| workspace build | `cargo build` | PASS (all crates incl. fugue, fugue-python, idalib) |
| fmt | `cargo +nightly fmt -p fugue-core --check` | PASS (clean) |
| clippy (changed files) | `cargo clippy -p fugue-core --tests` filtered | PASS (only pre-existing `ECodeSsaIr::new` 9-arg note) |
| no LHS type annotations | grep in `analysis/switch` + `analysis/value` | PASS (none) |
| no `std` HashMap in switch | `grep HashMap analysis/switch` | PASS (FxHashMap only) |
| value domain used | `grep StridedInterval src` | PASS (semantic/mod.rs:45,250,252,254) |
| old type names gone | grep `SwitchConfig\|TargetValidator\|Idioms\|Evaluator\|SwitchEnrichment\|IndirectBranch\b` | PASS (none) |
| full test suite | `cargo test -p fugue-core` | PASS (360 passed, 0 failed, 28 ignored) |

## E. ECode lowering correctness (framework-wide; user-requested "fix it all")

`transform.rs::expression_opcode` collapses distinct P-code ops into a few ECode
ops, and `ECodeExpr`/`ECodeSsaOp` carry no predicate discriminator (the `immediate`
field is the P-code op's own immediate, blindly forwarded — meaningless for
comparisons/logic). Every distinct-semantics P-code op must get a distinct ECode
opcode. Losses found (all "the same bug"):

| Loss | Current sink | Fix |
| --- | --- | --- |
| all comparisons (eq/ne/lt/le, signed, int/float) | `Compare` | split: `IntEqual/IntNotEqual/IntLess/IntSignedLess/IntLessEqual/IntSignedLessEqual` + `FloatEqual/FloatNotEqual/FloatLess/FloatLessEqual` |
| `IntAnd/IntOr/IntXor` (+ `BoolAnd/BoolOr/BoolXor`) | `Bool` | `And/Or/Xor` (bool logical merges into bitwise — non-lossy on 1-bit, matches existing `Not`←`IntNot`+`BoolNot` precedent); drop `Bool` |
| float arith vs int arith | `Add/Sub/Mul/UnsignedDiv/Negate` | distinct `FloatAdd/FloatSub/FloatMul/FloatDiv/FloatNegate` |
| `IntCarry` vs `IntSignedCarry` | `Carry` | `Carry` (unsigned) + `SignedCarry`; `Borrow`→`SignedBorrow` (only signed exists) |
| `FloatAbs/Sqrt/Ceiling/Floor/Round/IsNan/ToInt/ToFloat`, `IntToFloat` | `IntrinsicResult` | distinct float unary/convert opcodes; `IntrinsicResult` keeps only `UserOp` |

| Item | Validation | Status |
| --- | --- | --- |
| E1 `ECodeExprOpcode` faithful (mnemonic, fixed_operand_count, requires_address_space) | builds; 1 variant per distinct P-code expr op | DONE |
| E2 `ECodeSsaOpcode` faithful (mnemonic, from_expression 1:1, from_statement, requires_memory_domain) | builds | DONE |
| E3 `transform.rs::expression_opcode` 1:1, no collapse | builds; unit test IntAnd→And, IntEq→IntEqual, FloatAdd→FloatAdd | DONE |
| E4 bump ECODE + ECODE_SSA schema versions | verify() accepts new, rejects old | DONE |
| E5 fix every consumer (format/display, emulator, exhaustive matches) | full build clean (exhaustive matches surface all) | DONE |
| E6 emulator handles `And/Or/Xor` (masks now recoverable) | `emulates_bitwise_mask` + `emulates_absolute_table_load` | DONE |
| E7 index solver bounds via `And`-mask | (not wired) | DEFERRED |

**E7 note (honest):** the solver (`index_interval`/`guard_upper_bound`) bounds the
index from guard comparisons and the index *width* only — it does **not** interpret
an `And`-mask on the index as a bound. The emulator now handles `And/Or/Xor` when
they appear in the *address computation* (E6), but mask-as-index-bound is not
implemented. It is unnecessary for correctness (guards + width give a sound bound
and every enumerated target is validated), so it is deferred, not done.

## Bonus fix found during test-writing

`SwitchEmulator::emulate` previously did `defining_operation(value)?`, which aborted
the whole emulation when it reached a `Load`'s memory-domain operand (no defining
operation). That meant the semantic tier never actually emulated a table `Load` —
a latent bug in the original untested code. Now opaque inputs are skipped;
`emulates_absolute_table_load` covers it.

## Test coverage (evidence)

- Value domain (`StridedInterval`, `BitVec`-native): `tests/value_interval.rs` — 9 tests.
- Syntactic matcher (`SwitchIdiomMatcher`): `tests/switch_idiom.rs` — 8 tests
  (absolute, offset-relative, guard bound incl. inclusive, label offset, rejects,
  cyclic termination).
- IL lowering fidelity: `ecode/transform.rs::distinct_pcode_ops_do_not_collapse`
  (IntAnd→And, IntEq→IntEqual, FloatAdd→FloatAdd, IntCarry vs IntSignedCarry, …).
- Emulator (`SwitchEmulator`): `emulates_absolute_table_load` (real in-memory table
  via `Load`) + `emulates_bitwise_mask` (`And`).
- Known gap: no end-to-end `SemanticRecovery`/`SwitchAnalyser` test over a real
  lifted binary (needs a compiled jump-table fixture). The tier's pieces (matcher,
  emulator, value domain, IL fidelity) are unit-covered; the wiring is build-checked.

## F. Reconciliation (round 4) — one analysis, machinery-named modules

The two switch analyses were confusingly two types (`SwitchRecovery` pass +
`SwitchAnalyser` engine analyser) in vaguely-named modules (`enrich`, `syntactic`,
`semantic`). Reconciled into a single `SwitchRecovery` that implements both framework
hooks — `AnalysisPass` (the in-function-recovery tier, P-code idiom matching) and
`Analyser` (the post-commit engine tier, SSA data-flow). Modules are now named for
their machinery, not a tier adjective:

| Module | Contents |
| --- | --- |
| `mod.rs` | the `SwitchRecovery` orchestrator: both trait impls, `recover_syntactic`, default-case + reference enrichment, registration |
| `matcher.rs` | `SwitchIdiomMatcher` — matches P-code instruction idioms |
| `dataflow.rs` | `recover_semantic` — analyses SSA data-flow of the branch target: back-slice to the index, bound the index (value domain), evaluate the target expression per index value |
| `detect.rs` | `IndirectBranchSite` — finds indirect branches |
| `model.rs` | config, `RecoveredSwitch`, `SwitchTargetResolver` |

There is no "SSA emulation": `dataflow::evaluate_target` concretely evaluates the
back-sliced target data-flow expression for a given index value (constant-folds the
slice), reading table bytes through `Load`. It is expression evaluation over the
SSA slice, not a machine emulator.

### Round-4 review fixes
- schema versions reverted to `1` (no release, no migration).
- `ECodeSsaIr::skip_copies` → `underlying_value` (self-describing).
- boolean logic no longer erased: distinct `BoolAnd/BoolOr/BoolXor/BoolNot` ECode
  opcodes, separate from bitwise `And/Or/Xor/Not`.
- `SwitchRecord`: derives structural `PartialEq/Eq` (was branch-only `Eq`+`Ord`,
  which the cursor never used — `switch_page` keys on `record.branch()`); `From<&Switch>`.
- `VarnodeKey`: `From<&Varnode>` (was `::of`). It is a P-code varnode location
  (lifter space index + offset), **not** an `Address` — varnodes live in register /
  unique / constant spaces, which are not memory addresses.
- `SwitchShapeInfo::bound` is `Option<BitVec>`; `element_size` is `u32` (also on
  `AddressTable`); `ECodeSsaIr::first_non_constant_operand`.
- `StridedInterval` is a flat enum (`Empty(u32)` / `Interval { lo, hi, stride }`).
- E7 done: `StridedInterval::masked` + `dataflow::index_mask` bound the index from a
  contiguous `& mask` (exact), meeting with the width and guard bounds.

## G. Round 5 — structural rework to match `function/recovery/` conventions

Stopped surgical patching and matched the peer analysis layout exactly
(`function/recovery/`: config+error at module root, driver in `analysis.rs`,
machinery in role files). Final `analysis/switch/` layout:

| File | Contents |
| --- | --- |
| `mod.rs` | re-exports + `SwitchRecoveryConfig` (getters/setters/`with_*` builders) + `RecoveredSwitch` + `SwitchTargetResolver` |
| `analysis.rs` | the `SwitchRecovery` driver: both framework hooks, syntactic entry, enrichment |
| `matcher.rs` | `SwitchIdiomMatcher` — P-code idiom strategy (+ `SwitchShapeInfo`, `OffsetBase`) |
| `slice.rs` | `SwitchSliceEvaluator` — back-slices the branch target and evaluates the slice per index |

- **`SwitchDataflow` → `SwitchSliceEvaluator`** (`dataflow.rs` → `slice.rs`): it is
  not fixpoint data-flow analysis; it back-slices the indirect branch target through
  the SSA and concretely evaluates that slice for each feasible index. Named for what
  it does.
- **Opt-in pass** (review): the Tier-0 pass is no longer hardcoded in
  `FunctionRecovery::new_with`; it registers a `FunctionRecoveryExtension`
  (`build_analyser` applies it, like the ELF loader patterns), so the bare
  constructor is clean.
- **`detect.rs` deleted**: `IndirectBranchSite` → `PartialFunction::indirect_branches()`
  returning `impl Iterator<Item = (usize, Address)>`.
- **Reuse PartialFunction's lifting**: `lift_block_ops` → `PartialFunction::lift_block_flow`,
  using the same segment-window lifting as `lift_block` (not a bespoke buffer). The raw
  ops genuinely aren't retained (`Insn` drops them), so re-lifting via
  `resolve_insn_flow_into` is unavoidable — but it now lives on the owning type and
  shares its byte-fetch.
- **`Varnode` is the matcher's map key directly** (no `VarnodeKey` newtype). It is a
  lifter varnode location (register / unique / constant space + offset + size), not a
  memory `Address`.
- **`OffsetBase { address, signed }`**: signedness now lives inside the offset base, so
  an absolute table cannot carry a meaningless `signed` flag.

### IR-entity cleanups (review)
- `RecoveryTier` enum removed entirely; `tier` dropped from `SwitchProvenance`,
  `RecoveredSwitch::into_switch`, `SwitchRecord`. It recorded which tier found the
  switch but drove no decision — confidence + evidence already capture quality.
- `SwitchCase` labels are `CaseLabel` (a newtype), not bare `u64`.
- `AddressTable::byte_span` → `size`; `decode_entry` is now `pub(crate)`.
  - Known coverage loss: the 3 `decode_entry_*` integration tests were removed (an
    external test crate can no longer call the now-internal method); decode logic is
    exercised transitively through syntactic recovery. No in-`src` `#[cfg(test)]` was
    added (per the standing rule).
- No release yet, so the ECode schema versions stay `1` (no migration).

## H. Round 6

- `CaseLabel` → `SwitchCaseLabel`.
- `PartialFunction::lift_block_flow` removed. The block P-code is now gathered
  **inline in the Tier-0 pass using the existing `Lifter`** (`resolve_insn_flow_into`),
  not a wrapper method on the core type.

### Re-lifting in the pass is fine — but gated on unresolved indirect branches

Decision: re-lifting inside the Tier-0 pass is acceptable (a partial function may need
arbitrary transformation in a pass), because the pass runs **before** the P-code IL is
built (`builder.rs:560`) and `Insn` drops the raw `PCodeOp`s — so idiom matching must
re-lift via `Lifter::resolve_insn_flow_into`. The rule is: **don't lift every function
— only functions with unresolved indirect branches.** Both tiers now gate on this:

- **Tier-0 pass**: `state.function().indirect_branches()` is a cheap scan of block
  terminators (no lifting); `if branches.is_empty() { return }` runs first, so the
  block re-lift only happens for functions with ≥1 unresolved indirect branch.
- **Semantic tier**: gated on `CodeBlock::has_unresolved()` before loading
  `ecode_ssa`, so the SSA is not loaded/scanned for functions with no unresolved
  control flow (unless retrying a partial switch).

## I. ECode-SSA constant folding (option B)

Enables in-IL constant folding on ECode-SSA without widening every op or requiring
`BitVec` to be rkyv-serialisable.

- **Wide-constant storage (option B).** `ECodeSsaIr` gained a `constants: Vec<u8>`
  side-pool (rkyv-native; added via a `with_constants` build-step so `new()`'s
  signature is untouched — 9 callers unchanged). A `Constant` op encodes its value by
  width: `width <= 64` → `immediate` holds the value inline (unchanged, lossless for
  P-code literals); `width > 64` → `immediate` is a byte offset into `constants`, and
  the value occupies `width.div_ceil(8)` little-endian bytes. `ECodeSsaOp::constant`
  takes the pool; `ECodeSsaIr::constant_value` threads it through. Op struct size is
  unchanged, so the `size_of::<ECodeSsaOp>() <= 64` invariant still holds.
- **The transform.** `ECodeSsaIr::fold_constants(&mut self)` — a forward pass computes
  a `value → BitVec` map (folding any op whose operands are all known constants),
  then a rewrite pass replaces each folded op with a `Constant` (interning wide
  results into the pool). Sound and conservative: an op is folded only when every
  operand is already known constant, so processing in index order can miss some
  cross-block folds but never produces a wrong value.
- **Shared evaluator.** The pure arithmetic/bitwise/shift/extend semantics now live on
  `ECodeSsaOpcode::evaluate(width, &[BitVec])`, used by both the folder and the switch
  slice evaluator (which previously duplicated the arithmetic; it now only adds
  `Constant`/`Load` on top).
- **Test:** `fold_constants_materialises_wide_result_in_pool` folds `ZeroExtend` of a
  64-bit constant into a **128-bit** constant, stores it in the pool, and round-trips
  it back through `constant_value` — proving the wide path. (In-crate, since the SSA
  builder is `pub(crate)`; there is no way to construct SSA input from `tests/`.)
- **Not auto-wired.** `fold_constants` is an available capability (like `dominance()`,
  `uses()`, `liveness()`), not run by default — wiring it into the SSA pipeline is a
  separate policy decision, since it rewrites the IL every consumer sees.

## J. Dead code elimination — stage 1 (mark-and-sweep)

`ECodeSsaIr::eliminate_dead_code(&mut self)` — a standard SSA mark-and-sweep:

- **Roots** = operations with side effects (`ECodeSsaOpcode::has_side_effect`: `Store`,
  `Intrinsic`/`IntrinsicResult`, all branch/call/return flow, `Trap`) plus the
  operations that define values passed as **edge arguments** (block-parameter inputs on
  CFG edges). Everything else is pure and removable if unused.
- **Propagate** backward: a live op keeps its operands' defining ops live (worklist to a
  fixpoint). Block-argument values are never swept (block args aren't operations).
- **Sweep**: each non-live op is neutralised in place to `Undefined` (0 operands, no
  side effect, result value + width kept) via `ECodeSsaOp::make_undefined`. This is the
  same in-place style as `fold_constants`, so it's rkyv-safe and leaves every index,
  block op-range, and span untouched. `verify()` still passes (an `Undefined` op has no
  operands, so no use/dominance constraints; live ops only ever reference live values).

This is deliberately the *logical* elimination — op/value arrays don't shrink yet.
Complements folding: after `fold_constants` turns a computation into a `Constant`, its
operands become unused and DCE neutralises them.

Test: `eliminate_dead_code_neutralises_unused_operations` (a live constant kept, a dead
`Copy` neutralised, `verify()` clean).

### Stage 2 — the compacting pass

`ECodeSsaIr::compact(&mut self)` physically removes dead operations and rebuilds every
index-referenced array. The liveness (`live_operations()`) is shared with
`eliminate_dead_code`, so `compact` is self-contained (it recomputes liveness; running
it after stage 1 or standalone both work, and it correctly keeps genuine `Undefined`
value-producers whose results are used).

Rebuild, driven by two prefix-sum maps — `operation_index` (old op → new op) and
`value_index` (old value → new value):
- **values**: keep block-argument values + results of live ops; `definition_index`
  remapped (op index for results, arg index unchanged for block args).
- **operations + value_operands**: emit live ops in order; each op's `operands` slice is
  remapped and re-pooled, `results` range remapped. Live ops only reference live values,
  so every operand survives the value map.
- **block_arguments / edge_argument_values**: value ids remapped (order preserved, so
  block-arg definition indices stay valid).
- **source/parent spans**: `destination` op-ranges remapped, spans with no surviving op
  dropped. `first_pcode_index`/`pcode_count` (source provenance) and parent `source`
  ranges reference other arrays and are kept as-is. Contiguity holds because compaction
  preserves order and spans/blocks partition the op array.
- **graph blocks**: operation ranges remapped; successors/predecessors/properties kept.
- `edge_arguments`, `memory_domains`, `constants` unchanged.

Order preservation means dominance is preserved, so `verify()` passes on the result.

Tests: `compact_removes_dead_operations_and_remaps_indices` (dead `Copy` dropped, op/value
counts shrink, `verify()` clean, the surviving `Add`'s operands still resolve to their
constants) and `fold_then_compact_collapses_constant_expression` (fold turns `c1+c2` into
`Constant(12)`, then compact removes the now-dead `c1`/`c2` — 4 ops → 2).

## K. Fixpoint analyses (round 7) — "production ready, not toy demonstrations"

User challenge: *are the analyses proper fixpoint analyses?* Audit of every analysis the
switch work introduced, and what was done:

| Analysis | Before | After |
|---|---|---|
| Liveness (`ECodeSsaLiveness`) | iterative `while changed` fixpoint | unchanged — already a proper fixpoint |
| Dominance (`solve_immediate_dominators`) | iterative `while changed` fixpoint | unchanged — already a proper fixpoint |
| Dead-code (`live_operations`) | worklist to fixed point (seeds side-effecting + edge-arg uses, propagates backward through operands) | unchanged — already a proper fixpoint |
| `fold_constants` | O(n²) full-rescan loop until no new constant | **sparse def-use worklist** (`ECodeSsaUses`): seed all ops, on fold push only the result's users. Same fixpoint, linear in edges |
| Index value-range | ad-hoc one-shot backward walk (`index_interval`/`index_mask`) — a *toy* | **real forward abstract-interpretation fixpoint** (`StridedIntervals`) |

### `StridedIntervals` — forward strided-interval fixpoint

New module `il/ecode/ssa/intervals.rs` (IR-specific analysis, lives beside `liveness`/
`def_use`, not with the general analyses). Consumes the reusable `StridedInterval` abstract
domain, which stays general in `analysis/value/strided.rs`. Sparse fixpoint over the SSA
value graph (one `StridedInterval` per value), mirroring the house style of
`ECodeSsaLiveness`:

- **Init** every value to `Empty` (⊥).
- **Transfer** for operation results: per-opcode over operand intervals — `Constant`→single,
  `Add`/`Sub`/`Mul`/`LeftShift`/`And`/`Copy`/`ZeroExtend`/`SignExtend`/`Truncate` via new
  `StridedInterval` domain methods; anything unmodelled → `full` (⊤). All transfers are
  overflow-sound (a sum/scale/truncate that would wrap saturates to `full`).
- **Join** at block arguments (phis): a block-argument value's interval is the `join` of its
  incoming edge-argument sources, computed from a predecessor-edge map.
- **Widening** on every block-argument recompute (`widen` pushes growing bounds to 0 / max),
  which is what makes loop-carried values terminate — the sole cycles in SSA value
  dependencies pass through a block argument, so widening there guarantees convergence.
- **Worklist**: revisit an operation's result when an operand changes (via `ECodeSsaUses`),
  and revisit a block argument when one of its edge sources changes (via an inverted
  source map, since edge arguments are not operation operands).

New `StridedInterval` lattice/transfer ops: `join`, `widen`, `cast_to`, `zero_extend`,
`sign_extend`, `truncate`, `add`, `sub`, `mul`, `shift_left`, `and` (+ private `as_single`,
`scale`).

`SwitchSliceEvaluator` now builds `StridedIntervals` once per function and reads the index's
interval from it; `index_mask` is deleted (subsumed by the `And` transfer). `guard_bound`
stays as an explicit path-sensitive refinement layered on the fixpoint result — SSA without
pi/sigma nodes cannot attach a branch-guard narrowing to a value inside the fixpoint itself,
so this is kept honest and separate rather than faked into the lattice.

Tests: `masking_bounds_an_unknown_index`, `arithmetic_propagates_through_operations`,
`loop_carried_value_widens_to_termination` (in-crate SSA construction, proves the loop
fixpoint terminates via widening) + 15 pure-domain tests in `tests/value_interval.rs`
(join/widen/add/sub/mul/shl/and/zext/sext/truncate, incl. overflow-saturation cases).

### project.rs review comments (round-6 leftovers)

- Comment 1 (separation of concerns): switch table loading reused `block_cache_bytes`. Gave
  switches their own `ATTRIBUTE_SWITCH_CACHE_SIZE` / `DEFAULT_SWITCH_CACHE_BYTES`. The
  deeper "change model" point: `SwitchAdded`/`SwitchRemoved` is the intended derived-change
  vocabulary (switches are a first-class authored entity per the approved design);
  `modify_switch` emitting `SwitchAdded` is the correct "re-read at branch" signal, not a
  defect. No speculative rewrite.
- Comment 2 (naming): `switches()` / `switches_mut()` matches the `blocks()` / `functions()`
  / `symbols()` accessor + `_mut` pattern. No change.

### Naming and layout (round 8)

Unify the two recovery tiers on the technique they use, and move the IR-specific analysis
into the IR module tree:

- `analysis/switch/matcher.rs` → `analysis/switch/idiom.rs` — the syntactic tier is now the
  `idiom` module, pairing with the semantic `slice` module (both named after the technique;
  types `SwitchIdiomMatcher` / `SwitchSliceEvaluator` unchanged). `tests/switch_matcher.rs`
  → `tests/switch_idiom.rs`.
- `analysis/value/interval.rs` → `analysis/value/strided.rs`; the reusable abstract domain
  `StridedInterval` stays here (general, not IR-specific).
- `analysis/value/intervals.rs` (`ValueIntervals`) → `il/ecode/ssa/intervals.rs`
  (`StridedIntervals`) — the fixpoint runs on `ECodeSsaIr`, so it belongs with the other
  IR-specific analyses (`liveness`, `def_use`), re-exported from `il::ecode::ssa`. The
  reusable part (the domain) was already separate, so nothing else needed splitting out.

### Review round 9 — Tier-0 lifting via shared machinery; hot-path allocations

- Comment 2 (duplicated lifting): the Tier-0 pass hand-rolled per-insn
  `segments.read_bytes` into a fixed 32-byte buffer + `resolve_insn_flow_into`. That did a
  segment lookup per instruction, failed near segment ends / for instructions needing more
  than 32 bytes, and ignored the block's lifting context. `Insn` drops its P-code ops at
  construction (only targets/properties/length survive), so a re-lift is unavoidable — the
  fix is sharing, not avoiding: new `PartialFunction::lift_block_operations` sits beside
  `lift_block`, uses the same segment-view pattern (one `view_at` per block, full remaining
  contiguous window), applies the block's recorded `ContextSet` before lifting (as recovery
  itself does), and drives the shared `Translator` via a new `Translator::lift_into`
  passthrough. Per-insn lift failures truncate that insn's partial output and continue
  (best-effort op stream for the matcher). The switch pass now just calls it per
  predecessor + branch block.
- Comment 1 (needless collect): the `sources` Vec is gone — `lift_block_operations` takes
  `&self`, so the pass iterates `block.predecessors().iter().copied().chain([block_index])`
  directly while holding the block borrow.
- Comment 3 (hot-path Vecs): `ops` hoisted out of the branch loop (cleared per branch);
  `predecessors` hoisted out of the switch loop (clear + extend per switch); the
  `successors` collect eliminated entirely — the two successor ids are destructured from
  the guard's iterator in an inner scope (guard dropped before the next table read, keeping
  the two-guards-alive discipline), zero allocation.

Gates (C): `cargo +nightly fmt` clean; `cargo clippy -p fugue-core --lib --tests` — no new
warnings on touched files; `cargo test -p fugue-core` — all pass (276 lib + 44 + 18 + 6 + 7
+ 2 + 26 across suites, 0 failures); `cargo build` — workspace clean.

## L. Segment-read hot loops (round 10) — cached-view `SegmentReader`

`SegmentStorage::read_bytes` / `view_at` resolve the containing mapping every call
(`find_containing` over the space) — there is no fast-path cache of the last segment read.
The recursive-descent lifter in the function analyser already avoids this by holding one
`SegmentMappingView` and only refreshing it on `!view.contains(addr)`. Several analysis hot
loops re-resolved per read instead. Encapsulated that pattern and applied it everywhere.

New `storage/segments/reader.rs`: `SegmentReader` wraps `&SegmentStorage` + a cached
`SegmentMappingView`; `view(addr)` refreshes only when the cache is stale (`!is_valid`) or
does not contain `addr`; `read_bytes` / `read_bytes_exact` delegate to the cached view.
Re-exported at `storage::segments::SegmentReader` and `storage::SegmentReader`. (Named
`SegmentReader`, not `Cursor` — it does random-access reads with a segment cache; "cursor"
implies an advancing read position, which this is not.)

Converted hot loops:
- **`PCodeCanonicaliser::build_function`** (`il/pcode/transform.rs`) — the hottest: a
  `read_bytes` per instruction of every block of every function during IL construction. Now
  one `SegmentReader` across the whole function; consecutive instructions/blocks in the same
  segment reuse the resolved view.
- **`SwitchRecovery` Tier-0** (`analysis/switch/analysis.rs`) — `recover_syntactic`'s table
  entry loop reads via a reader; `lift_block_operations` now takes `&mut SegmentReader`
  (signature changed from `&SegmentStorage`) so the branch block + all predecessors reuse
  one view.
- **`SwitchSliceEvaluator`** (`analysis/switch/slice.rs`) — `load_entry` threads a reader
  down through `evaluate_target` / `apply`; table-entry and two-level loads in the case loop
  reuse the view.
- **`SwitchTargetResolver`** (`analysis/switch/mod.rs`) — held a bare `&SegmentStorage` and
  called `view_at` per case for the executable check; now owns a `SegmentReader` and
  `resolve(&mut self)` reuses it.
- **`FunctionRecoveryPatternMatcher::for_each_segment`** (`analysis/function/recovery/patterns.rs`)
  — it hand-rolled the exact cache (`&mut Option<SegmentMappingView>` threaded from
  `analyse_space`, refresh on `!contains`). Replaced with `&mut SegmentReader`, deleting the
  manual reuse/insert branch — DRY onto the shared abstraction.

Left as-is (already correct — hold-and-refresh, not per-read resolution): the function
analyser (`builder.rs`) and `PartialFunction::lift_block` / `lift_all_blocks`. `lift_insn`
has no callers and is a single instruction, not a loop.

Single instructions cannot straddle a segment boundary, so the reader's within-view read
(vs. the old cross-mapping gap-filling `read_bytes`) is behaviour-preserving for every
converted site.

Gates: `cargo +nightly fmt` clean; clippy — no new warnings on touched files;
`cargo test -p fugue-core` all pass (276 lib + 44 + 18 + 6 + 7 + 2 + 26, 0 failures);
`cargo build` workspace clean.

## M. Segment property fast path (round 11)

Property checks went through `view_at()`, which pays the mapping lookup, a **provider**
lookup, and full `SegmentMappingView` construction — all waste for a metadata query. The
storage already had metadata-only queries that stop at `find_containing`
(`contains_segment` / `space_contains_segment`) but no properties analogue.

- New `SegmentStorage::segment_properties` / `space_segment_properties`, mirroring the
  `contains_segment` pair: space lookup → `find_containing` → mapping lookup → mapping-ref
  validity check → `SegmentProperties`. No provider lookup, no view construction; `None`
  for unmapped or stale.
- New `SegmentReader::properties(addr)` for consumers with locality: serves from the cached
  view (a miss populates the cache via `view()`, so subsequent same-segment queries are
  ~free, and the cache stays coherent for byte reads).
- `SwitchTargetResolver::resolve` now uses `reader.properties(address)` for the
  executable check instead of pulling a full view.

Other property-check sites audited and left alone: `analysis.rs` builds its executable
range set from `iter_views` (bulk enumeration, once per space); `queries`' `MappingRecord`
summarises views it already holds; the `project.rs` fixture helper is test-only.

Test: `test_segment_properties_fast_path` (two mappings with distinct permissions;
asserts exact properties inside each and `None` outside).

Gates: fmt clean; clippy — 0 errors, no new warnings on touched files;
`cargo test -p fugue-core` all pass (now 277 lib + 44 + 18 + 6 + 7 + 2 + 26);
`cargo build` workspace clean.

## D. Process rule

Do not report "done" to the user without every A/B item at DONE and every C gate
green, with the evidence recorded above. Previous premature "done" claims
(rounds 1–5) are the reason this log exists.
