# Switch Recovery — Refinement Plan

Review of the `feature/switch-case-recovery` branch (base `feature/dialects`) against
`docs/switch-recovery/01..07` and the surrounding fugue-core conventions. Findings were
produced by three focused passes (entity/persistence, analysis tiers, IL/value layer) and
every load-bearing claim was re-verified in code. Scope intentionally spills past this
branch where the review surfaced a real pre-existing issue.

Priorities: **P0** correctness/soundness (wrong results persisted, unsound analysis, silent
data loss); **P1** completeness gaps (specced-but-absent, half-wired lifecycle); **P2**
optimisation/scaling; **P3** hygiene (naming, dead code, house-style).

Legend for evidence: `file:line` is where the issue lives; "spec §" points at
`docs/switch-recovery/`.

---

## P0 — Correctness & soundness

### P0.1 Recovered references are persisted as user-asserted facts
`analysis/switch/analysis.rs:392-407` builds jump/data references
`.with_origin(ReferenceOrigin::Derived)`, but `ProjectTransaction::add_reference`
(`project.rs:690`) unconditionally does `reference.with_origin(ReferenceOrigin::Asserted)`.
The `Derived` origin is dead code; every recovered switch reference is stored as an
authoritative user assertion, and the merge path (`project.rs:695-710`) then treats it as
such. Asserted references also survive the derived-reference cleanup that runs on
re-analysis, so they leak.
**Fix:** add a transaction path that preserves a caller-supplied origin (or route these
through the same derived-reference insertion function recovery uses), and store them as
`Derived` so `flush_derived_references` can replace them.

### P0.2 Semantic recovery is inert — targets never integrated, branch stays unresolved
The `Analyser` tier inserts the `Switch` entity and references but never feeds case targets
back into the CFG. Tier-0 calls `add_local_target` (`analysis.rs:286-292`); the semantic
tier has no equivalent, and the engine's change router has an **empty arm** for
`ChangeRecord::SwitchAdded | SwitchRemoved` (`engine/mod.rs:1858-1864`). So a semantically
recovered switch resolves nothing: `has_unresolved()` stays true, the block CFG is never
extended with case targets, and the `unresolved` gate (`analysis.rs:193-198`) re-selects the
same function every run (reloads SSA, rebuilds the evaluator, then skips the branch at
`analysis.rs:214-218` because a non-partial switch now exists). The recovery is inert
metadata.
**Fix:** route `SwitchAdded` to a `FunctionChanged`-style trigger (or have the switch
Analyser request re-recovery of the owning function) so case targets are integrated and the
unresolved gate closes.

### P0.3 Guard bound detection is unsound in both tiers
Spec §7.3 (`02-architecture.md`) requires guards to come from *dominating conditional
branches whose condition constrains a spine value*, pulled back through inverse transfer
functions. Neither tier does this:
- **Semantic** (`slice.rs:276-304`): `guard_bound` scans **every** operation in the
  function and takes the first `IntLess`-family comparison whose LHS strips to the index,
  with no dominance check and no branch-polarity check. A comparison on the same SSA value
  on a sibling/unrelated path narrows `index_interval` (`slice.rs:266-272`), silently
  dropping valid cases — and the switch is then stored complete, `GUARD_FOUND`,
  `somewhat_certain`.
- **Tier-0** (`analysis.rs:249-262` + `idiom.rs:243-268`): all predecessors' P-code streams
  plus the branch block are concatenated into one linear `ops` Vec. `guard_bound` picks the
  first comparison from *either* predecessor; with two guard blocks (`cmp x,10` / `cmp
  x,100`) the smaller bound caps `entry_limit` and cases are dropped, stored non-truncated.
**Fix:** accept only a comparison whose conditional branch dominates the indirect branch and
whose taken/fallthrough polarity actually constrains the path into the switch; otherwise
treat as unguarded. This is the documented `analyzeGuards` + `CircleRange::pullBack` step —
implement it once as an inverse-transfer pull-back in the value domain (ties into P0.9 and
the domain's missing guard refinement).

### P0.4 Tier-0 concatenates mutually-exclusive predecessor streams
`analysis.rs:249-262` concatenates the op streams of *all* predecessors + the branch block
and hands them to `SwitchIdiomMatcher` as straight-line code. The matcher's `defs` is
last-write-wins (`idiom.rs:76-80`) and `defining_operation` (`idiom.rs:100-102`) ignores use
position, so: (a) a use can resolve to a def appearing *after* it (register redefined
post-load); (b) ops from two mutually-exclusive predecessors get stitched into a phantom
idiom; (c) the wrong result rewrites the CFG via `add_local_target`.
**Fix:** run the matcher once per `predecessor + branch-block` path, validate/intersect
results; make `defs` position-aware (nearest def strictly before the use index).

### P0.5 `widen()` is not an upper bound of its inputs
`analysis/value/strided.rs:184-221`: when the new lower bound undercuts the old (`lo`
rebased to 0) but strides are equal, the old stride is kept while the phase anchor moves.
`widen({12,20,s8}, {4,12,20,s8})` → `range(0,20,8)` = `{0,8,16}`, which **excludes 12 and
20** (members of both inputs; `range()` re-rounds `hi` down from the new `lo`). Reachable
from the phi update at `intervals.rs:41` with 3+ predecessors depending on worklist order;
the fixpoint then converges on an interval that omits real index values.
**Fix:** when bounds are rebased, recompute stride as `gcd(s1, s2, l1−lo, l2−lo)` (with zero
handling), or degrade stride to 1 whenever `lo`/`hi` is rebased.

### P0.6 `sign_extend()` stores sign-flagged BitVecs into the unsigned lattice
`strided.rs:244-257`: `signed_cast` sets the BitVec sign flag (`fugue-bv` `signed().cast`),
and `BitVec::Ord` orders by `is_negative()`. Sign-extending an all-negative interval
produces flagged bounds that poison later `join`/`meet`: a mixed-sign comparison makes
`0xFFFF < 0`, so `join` yields `Interval{lo:0xFF80, hi:0}` (slips past the `lo>hi` guard),
whose `contains()` excludes real members. The domain is an unsigned lattice; the flag must
never be stored.
**Fix:** `.signed_cast(width).unsigned()` for `lo`/`hi` in `sign_extend` (stride already
uses `unsigned_cast`). The straddle guard itself is fine (`min_value_with(bits, true)` does
not set the flag).

### P0.8 Switch entity has no rollback and no lifecycle cleanup
Two related defects that together make the switch table drift out of sync with reality:
- **No revert** (`project.rs:724-748`): `insert_switch`/`modify_switch`/`remove_switch`
  mutate `project.switches` and push change records but capture no revert; there is no
  `switch_reverts` field and `rollback()` (`project.rs:1253-1280`) never restores switches.
  Every peer captures a revert (`FunctionTableRevert`, `ReferenceRevert`,
  `SymbolTableRevert`). This is reachable: an analyser error after an insert rolls back
  (`engine/mod.rs:1927-1930`) but leaves the switch, which the persistent cache has already
  staged for flush.
- **No stale removal** (`project.rs:743`): `remove_switch` has no production caller —
  `ChangeRecord::SwitchRemoved` is never emitted outside tests. When a function is removed or
  re-analysed, `remove_function_by_id` cleans call edges, derived references, blocks and IR,
  but switches at branch addresses inside it persist forever, and a stale non-partial switch
  actively blocks re-recovery (`analysis.rs:214-217`).
**Fix:** add `SwitchTableRevert` (mirroring `FunctionTableRevert` with an allocation
checkpoint) pushed from the three mutators and restored in `rollback()`; and in
`remove_function_by_id`/the body-changed path, remove/invalidate switches whose branch falls
in the affected block ranges (emitting `SwitchRemoved`), analogous to
`replace_derived_of_kind`.

### P0.9 `TwoLevel` model is a placeholder storing one table twice
`slice.rs:88-95` builds `SwitchModel::TwoLevel { outer: table.clone(), inner: table }` with
the same table; `table_layout` (`slice.rs:172-215`) only ever finds one load. Compounded by
`SwitchModel::table()` (`ir/switch/mod.rs:184-191`) returning only `outer` for `TwoLevel`, so
the inner table is unreachable and gets no derived reference. The persisted model is wrong
for any consumer.
**Fix:** either compute both layouts (track the second `table_address` hit along the nested
load chain) or emit `Absolute` for the single level actually recovered; expose all tables
via `tables(&self) -> impl Iterator<Item = &AddressTable>` and derive one reference per
table.

### P0.10 Property flag deserialize wipes all flags on one unknown bit
`ir/switch/mod.rs:343,384`: `SwitchProperties::from_bits(..).unwrap_or(NONE)` and the same
for `SwitchEvidence` — a single unknown bit silently clears **all** flags on read. Peers use
`from_bits_truncate` (`ir/symbol/mod.rs:280`, `ir/segment.rs:62`), which keeps known bits.
**Fix:** `from_bits_truncate(self.0.to_native())` for both.

---

## P1 — Completeness gaps

### P1.1 Optimisation pipeline is never run in production
`fold_constants`, `eliminate_dead_code`, `compact` (`ssa/builder.rs`) have **zero**
production callers — `ensure_ecode_ssa` (`project.rs:499-501`) runs `ECodeToSsa.transform`
then `materialise_lifted` only. Switch recovery builds `StridedIntervals` over raw,
unfolded, dead-op-laden SSA, and persisted SSA carries the dead code.
**Fix:** wire `fold_constants(); eliminate_dead_code(); compact();` into `ensure_ecode_ssa`
before `materialise_lifted`, gated behind the production verifier (P1.9).

### P1.2 Semantic tier drops case labels
`slice.rs:66-74` pushes `SwitchCase::new(destination)` and discards `value` — the concrete
index assignment in scope — while Tier-0 records `SwitchCaseLabel` (`analysis.rs:89-93`).
Consumers get labelled cases from one tier and unlabelled from the other.
**Fix:** `case.add_label(SwitchCaseLabel::new(value.to_u64()?))` with the same normalisation
offset Tier-0 applies.

### P1.3 Constant folding does not cross phis, and `evaluate` covers 15/68 opcodes
- `fold_constants` (`ssa/builder.rs:171-188`) only inserts operation results into `folded`;
  `BlockArgument` values never enter it, so constants never flow through control-flow joins
  even when all incoming edge arguments fold to the same constant.
- `ECodeSsaOpcode::evaluate` (`ssa/mod.rs:358-376`) implements 15 opcodes; all six
  comparisons, div/rem, the bool ops, carries, `CountOnes`/`CountLeadingZeros`,
  `Extract`/`Insert` are missing, so a `ConditionalBranch` on a comparison of two constants
  never folds and statically-dead arms are never pruned.
**Fix:** add phi-constant propagation (needs the edge-argument use index, P1.7); fill in the
pure integer opcodes (`fugue-bv` already has comparisons, div/rem, carries).

### P1.4 DCE/compact keep dead phis and their feeders
`live_operations` (`ssa/builder.rs:388-395`) roots *all* `edge_argument_values`, and
`compact` keeps every `BlockArgument` and only remaps (never drops) edge arguments. A dead
loop counter `i = phi(0, i+1)` keeps its phi, `Add`, and seed constant forever.
**Fix:** phi-aware liveness over (live op ↔ live block-arg ↔ live edge-arg slot), and make
`compact` delete dead block-argument slots plus the positional edge-argument entries across
all predecessor edges in sync. ~100-150 lines; do together with P1.3/P1.7.

### P1.5 Liveness ignores edge-argument uses (latent soundness bug)
`liveness.rs:87-109`: `collect_operation_uses` counts only operation operands. A value whose
only consumer is a phi on an outgoing edge is live-out of no block. No production consumer
today (`ir.liveness()` call sites are test-only), so latent — but it will silently bite the
first real consumer.
**Fix:** per edge P→S, add `arguments_for_edge(edge)` values to `block_use[P]` when not
defined in P, and union them into `live_out[P]`.

### P1.6 Instruction re-lifting must hand the lifter a view, not a fixed-size read
Instruction decode needs readahead (delay slots, prefixes, variable-length ISAs), so a
fixed `insn.len()` read can fail to decode. `PCodeCanonicaliser::build_function`
(`il/pcode/transform.rs:72-78`) reads exactly `insn.len()` bytes into a buffer and lifts
from that — no readahead. `lift_block_operations` already does the right thing (lifts from a
segment-view window via `bytes_from(...).as_contiguous()`).
**Fix:** re-lift from a segment view window (to end of the contiguous segment) rather than a
fixed buffer. `SegmentReader::view(addr)` already returns the `SegmentMappingView` needed;
add a helper that yields the readahead window and switch the canonicaliser to it. (This
supersedes the earlier "use `read_bytes_exact` for instruction bytes" note — exact-size is
wrong for decode.)

### P1.7 Edge-argument uses are missing from `ECodeSsaUses`, worked around three ways
`def_use.rs:35-71` excludes edge-argument uses. `StridedIntervals` builds its own
`block_argument_sources`/`dependents` maps; liveness compensates not at all (P1.5); folding
would need the same for P1.3.
**Fix:** add a shared phi-sources index (`block argument → feeder values per edge`) as a
method on `ECodeSsaIr`, consumed by intervals, liveness, and folding — or extend
`ECodeSsaUses` with edge-argument use records.

### P1.8 Semantic tier fails silently at phi boundaries; back-slice is not the specced meld
Spec §7.2 specifies a PathMeld-style back-slice that prunes at block arguments with no
single reaching def and keeps the common spine. `evaluate_target` (`slice.rs:317-350`)
instead pops values with no defining operation without seeding the memo, so any slice
crossing a phi yields zero cases with no evidence recorded.
**Fix:** resolve single-source block arguments through their unique feeder; record a
"slice not closed" trace distinct from "no idiom". Longer term, restructure toward the
documented `slice`/`bounds`/`emulate` split (currently collapsed into one `slice.rs` under
`analysis/switch/`, not the specced `analysis/switch/semantic/`).

### P1.9 No production verifier for the IL
`verify()` and its pcode/ecode siblings live in `#[cfg(test)] mod test`
(`ssa/builder.rs:716`), so the new mutators (`fold_constants`, `eliminate_dead_code`,
`compact`, `replace_with_constant`, `make_undefined`) are never checked outside tests and
`materialise_lifted` persists mutated IL unverified. verify also never bound-checks wide
`Constant` immediates against the pool nor operand widths against `op.width()`.
**Fix:** hoist verify out of the test module (debug-assert- or feature-gated), add
pool-bounds and operand-width checks, and run it after the pass pipeline (P1.1).

### P1.10 Retried switches outside the trigger region skip defaults and references
When `retry_partials` is set, `recover_semantic` recovers switches for functions outside
`regions`, but the default-case loop (`analysis.rs:336`) and reference loop
(`analysis.rs:386-388`) still filter by `regions` — retried switches get an improved case
list but no default and no references.
**Fix:** drive the default/reference passes from the set of branches actually touched this
run, not from `regions` alone.

### P1.11 Default-case heuristic overrides user assertions and misfires
`analysis.rs:332-381`: applies to every switch without a default including `is_override()`/
`is_assisted()` ones (a user-authored switch silently gains a heuristic default with
`HAS_DEFAULT` set permanently); accepts the first two-successor predecessor without checking
it tests the switch index (a loop header yields the loop exit as a bogus default).
**Fix:** skip override/assisted switches; validate the predecessor guards the index; extract
`discover_defaults`/`emit_references` methods out of `Analyser::analyse` (see P3.6).

### P1.12 Unguarded Tier-0 result permanently blocks the stronger semantic tier
The semantic tier only revisits branches whose switch `is_partial()`
(`analysis.rs:214-218`), but Tier-0 can never produce a partial switch: `truncated` requires
`shape.bound()` Some, which forces `guarded = true`, and `is_partial = TRUNCATED &&
!GUARD_FOUND` (`mod.rs:132-135`). So an unguarded, `somewhat_uncertain` Tier-0 run-length
walk permanently blocks semantic analysis on that branch.
**Fix:** mark unguarded Tier-0 results partial, or widen the retry condition to include
low-confidence/unguarded switches.

### P1.13 Client/engine surface: switches are read-only, override workflow unreachable
`engine/mod.rs` has no `ProjectUpdate` variant for switches and no `AnalysisEngine`
add/remove methods (peers have `add_reference`/`remove_reference`). Clients can read
switches but never insert/override/remove one — yet `SwitchProperties::OVERRIDE`/`ASSISTED`
exist specifically for user assertions and recovery honours them. The override workflow is
unreachable end-to-end. The `SwitchTable` wrapper also exposes only panicking accessors
(`get_by_id`/`modify_by_id`/`remove_by_id` via `into_fatal()`); the fallible `try_*`
variants exist on the persistent table but are not surfaced (peers surface them).
**Fix:** add `ProjectUpdate::{AddSwitch, RemoveSwitch}` + `AnalysisEngine` methods delegating
to the transaction API; surface the `try_*` accessors on `SwitchTable`.

### P1.14 Dead capability paths with no producer
`decode_entry`'s shift handling (`analysis.rs:130-141`) is unreachable — both tiers always
build `AddressTable` with `shift = 0` and no idiom recovers a scaled entry (ARM `tbb`/`tbh`
`base + entry*2`). `SwitchProperties::TRUNCATED`/`mark_truncated` and evidence flags
`TABLE_IN_READ_ONLY`/`TARGETS_ALIGNED` are never produced, even though the segment reader
needed for `TABLE_IN_READ_ONLY` is in hand. Tier-0 also discards the load's address space
and reads from `branch.space()` (`analysis.rs:58-77`), whereas the semantic tier honours it
(`slice.rs:391`) — wrong space on architectures with non-default table spaces.
**Fix:** either wire these up (tbb/tbh shift recovery, read-only/alignment evidence, load
space threading) or delete the dead paths and document the deferral.

---

## P2 — Optimisation & scaling

### P2.1 One partial switch triggers a whole-project SSA scan, permanently
`analysis.rs:187-204`: `retry_partials = any partial switch in the project` disables both
the regions gate and the unresolved-blocks gate, so one partial switch makes every
`FunctionAdded` load and build `StridedIntervals` for **every** function
(`project.ecode_ssa` deserialises per call). A partial switch that stays partial (the common
case) makes this a permanent tax.
**Fix:** derive the retry set from the partial switches' branch→function mapping and revisit
only those functions; skip retry when the bytes feeding a partial switch are unchanged.

### P2.2 `StridedIntervals` built over the whole function, before candidate check
`SwitchSliceEvaluator::new` (`slice.rs:44`) runs the full-function interval fixpoint in the
constructor, before confirming any surviving `BranchIndirect` candidate, and the evaluator
only ever consults the single index's interval.
**Fix:** hoist the candidate/skip checks before constructing the evaluator; compute the
interval on demand for the index's backward slice.

### P2.3 Per-case re-evaluation and allocation in the emulator
`evaluate_target` (`slice.rs:306-351`) allocates a fresh memo + stack per case (up to 4096),
re-evaluating index-independent subvalues per case; `load_entry` allocates a `Vec` per load
per case.
**Fix:** evaluate the index-independent portion once into a base memo and clone/layer per
case; hoist a reusable read buffer.

### P2.4 Unbounded DAG walks without a visited set
`scaled_index`/`table_layout`/`contains_load` (`slice.rs:124-238`) traverse the SSA def DAG
with no visited set — shared subexpressions re-expand per path, bounded only by
`walk_step_limit` (2^20).
**Fix:** add an `FxHashSet` of visited value ids to each walk.

### P2.5 Liveness allocates `Vec<Vec<bool>>` churn per iteration
`liveness.rs:21-43` uses four dense `Vec<Vec<bool>>` (blocks×values) plus a per-block
`clone()` and a fresh `vec![false; value_count]` every fixpoint iteration.
**Fix:** packed `u64` bitset rows with two reused scratch rows (word-wise OR).

### P2.6 Hot maps keyed by dense indices should be Vecs
`fold_constants` `folded: FxHashMap<usize, BitVec>` (`builder.rs:158`) and
`intervals.rs:79` map keyed by dense value index → use `Vec<Option<_>>`; reuse a scratch
operand buffer per op visit.

### P2.7 Constants pool grows on repeated folding
`fold_constants` rebuilds an empty `interned` map each call while `self.constants` persists,
so a second fold re-appends byte-identical wide constants; `compact` never GCs orphaned pool
bytes (`builder.rs:197,240`). Latent (passes unwired).
**Fix:** seed `interned` from the pool; trim the pool during `compact`.

---

## P3 — Hygiene, naming, structure

- **P3.1 Value-domain precision nits (sound but loose):** `and(single, single)` returns
  `masked` instead of `single(a&b)` (`strided.rs:340`); interval transfer degrades `Or`,
  `Xor`, `LogicalRightShift`, `ArithmeticRightShift`, div/rem, `Extract`, `Load` to `full`
  (`intervals.rs:122-135`) — add at least constant-shift and constant-or.
- **P3.2 Domain encapsulation:** `StridedInterval` variants/fields are fully public
  (`strided.rs:4-11`), so `Interval` can be built bypassing `range()` normalisation that
  `iter`/`count`/`contains` rely on — hide behind the smart constructors.
- **P3.3 Vocabulary:** value domain says `bits`, SSA layer says `width` for the same concept
  — align on `width`. Two tiers carry three vocabularies (modules `idiom`/`slice`, methods
  `recover_syntactic`/`recover_semantic`, types `SwitchIdiomMatcher`/`SwitchSliceEvaluator`)
  — pick one axis. `peel_depth` vs `walk_step_limit` are the same traversal-cap concept.
- **P3.4 `has_side_effect` misnamed:** includes `IntrinsicResult` (a pure projection) because
  it actually means "not DCE-removable" (`ssa/mod.rs:342-356`) — rename to `is_dce_root` /
  split purity from removability before a reordering consumer is misled.
- **P3.5 Methods over free fns / structs over tuples:** `intervals.rs:67`
  `block_argument_sources(&self, body)` never uses `self` and is pure IR structure — move
  onto `ECodeSsaIr`. `idiom.rs:198` `match_loaded_offset` returns a 4-tuple with an
  anonymous bool; `slice.rs:240` `table_address` returns `(RawAddress, bool)` — use named
  structs (`MatchedTable`, `TableAddress { address, nested }`).
- **P3.6 Separation of concerns:** the default-case heuristic and reference pass sit inline
  in `Analyser::analyse` while recovery lives in `recover_semantic`; Tier-0's table walk
  (`recover_syntactic`, `decode_entry`, `relative_target`, near-duplicate `confidence`/
  `evidence`) lives on `SwitchRecovery` in `analysis.rs` while the semantic equivalent lives
  in `SwitchSliceEvaluator`. Move Tier-0's walk into `idiom.rs` (or a dedicated evaluator);
  extract `discover_defaults`/`emit_references`.
- **P3.7 Needless defensive / silent swallowing:** `lift_block_operations` returns a
  `Result` whose only error is unreachable (caller already resolved the block) and is
  discarded with `let _ =` (`analysis.rs:256-261`); `let _ = switches_mut().insert(...)`
  (`analysis.rs:294-296`) swallows `SwitchTableError`. Make `lift_block_operations`
  infallible; route the insert through the transaction (P0.8) and propagate the error.
- **P3.8 `ECodeSsaOp::constant` abstraction leak:** it is `pub` but takes the pool as an
  argument and `ECodeSsaIr` exposes no pool accessor, so no external caller can use it
  correctly (`ssa/mod.rs:453-464`) — make it `pub(crate)`; `ECodeSsaIr::constant_value` is
  the public API.
- **P3.9 Duplicated default state:** `Switch` keeps both a `default: Option<SwitchCase>`
  field and a `HAS_DEFAULT` flag (`ir/switch/mod.rs:104-155`) — make `has_default()` return
  `self.default.is_some()` and drop the flag.
- **P3.10 Dead/foot-gun API:** `Switch::with_id`/`set_model`/`case_mut` are unused and
  `with_id` lets a caller desync id from slot (`ir/switch/mod.rs:63-98`) — delete until a
  consumer exists.
- **P3.11 Query hygiene:** `switch_page` eagerly collects (`queries/read.rs:182-193`) — keep
  lazy like `symbol_page`; `SwitchRecord` duplicates `branch` and is a heavyweight clone-only
  paging cursor (`queries/mod.rs:209-243`) — page on an `Address`. `branches_after` uses
  fully-qualified `std::ops::Bound` (`table/persistent.rs:178`, `transient.rs:133`) — import
  it.
- **P3.12 Naming vs peers:** transaction mutator `insert_switch` vs the dominant `add_`
  verb (`add_function`, `add_reference`) — rename to `add_switch`; keep table-level `insert`.
- **P3.13 Bottom/unknown conflation:** a feederless block argument stays `Empty` forever and
  propagates bottom through transfers (`intervals.rs:35-44`) — use `full(width)` for
  feederless arguments. Latent (entry reads currently materialise as `Undefined`→`full`).
- **P3.14 `AddressTable` ergonomics:** `new(address, element_size, element_count, shift)` has
  two adjacent transposable `u32`s with trailing-zero literals at both call sites — prefer
  `new(address, element_size)` + `with_element_count`/`with_shift`, and add
  `entry_address(index)`/`range()` so `analysis.rs:69-73` stops hand-rolling the arithmetic.
- **P3.15 Test coverage:** no end-to-end recovery test against a real binary (all matcher
  tests hand-craft synthetic `PCodeOp` streams, `tests/switch_idiom.rs`); no test for the
  multi-predecessor concatenation path or for `SwitchSliceEvaluator`. Add at least one
  lifted-from-real-binary switch recovery test (a known switch in `ls.elf`/`libipmi.so`).

---

## Dialect mechanism — characterisation (the flagged "incomplete ECode dialect")

For planning, not a single fix. History: commit `6612aa9` introduced `il/common/dialect.rs`
(`DialectId {TEST, PCODE, LLIL, LLIL_SSA, MAPPED_MLIL, MLIL}` + an `llil` tree); commit
`9433ce7` deleted it and collapsed to three hard-wired levels —
`IlLevel {PCode → ECode → ECodeSsa}` with `parent()`/`descendants_from()`
(`il/common/artefact.rs:52-79`), the `IlArtefact` trait, the `ensure_lifted` chain
(`project.rs:419,461-504`), and engine gating (`engine/mod.rs:2090`).

The ECode lowering *was* many-to-one lossy on the base branch (all six int comparisons and
all float comparisons → one `Compare`; int and bool `And/Or/Xor` → one `Bool`; both carries →
`Carry`; every float op → an integer opcode). This branch completes the opcode **set** to 1:1
with p-code (floats included) because switch recovery needs real comparisons and masks. What
remains incomplete as a *mechanism*:

1. Three parallel hand-maintained opcode enums (`PCodeOpcode`, `ECodeExprOpcode`,
   `ECodeSsaOpcode`) with hand-written `name`/`operand_count`/`from_*` tables and no single
   source of truth — one new opcode touches ~6 large matches (and see P0.7/P3 on the
   append-numbering contortion in `expression.rs:28-31`).
2. Semantics live in three disconnected partial implementations —
   `ECodeSsaOpcode::evaluate` (15/68), `StridedIntervals::evaluate` (9/68), the ECode
   interpret path — with no shared per-dialect interpreter hook.
3. No production verifier per level (P1.9); no optimisation stage in the transform pipeline
   (P1.1).
4. Residual lossy edges: `UserOp → IntrinsicResult` (`transform.rs:280`) and
   `Subpiece → Extract` (`transform.rs:261`) where subpiece's byte-offset operand is
   implicit and unimplemented in every evaluator.
5. Schema versioning is not connected to dialect content (P0.7).

A future dialect refactor should target a single opcode source of truth with generated
name/arity/lowering tables and one interpreter trait per dialect, at which point
`evaluate`/interval-transfer/fold become one shared table rather than three.

---

## Suggested sequencing

1. **P0.5** (small, self-contained soundness fixes).
2. **P0.1 + P0.2 + P0.8** as one lifecycle workstream (origin, trigger routing, revert,
   stale removal) — they share the change-model plumbing.
3. **P0.3 + P0.4** guard soundness (both tiers) — implement the pull-back once (P1 domain
   guard refinement rides along).
4. **P1.1 + P1.9 + P1.3/P1.4/P1.7** IL pipeline + verifier + phi-aware analyses as one unit.
5. **P0.9 + P1.2 + P1.6 + P1.14** recovery-quality fixes.
6. **P2** scaling once correctness is settled.
7. **P3** hygiene, opportunistically alongside the above.
