# Architecture

How switch-case recovery integrates into Fugue. This document maps the design onto
the current code, defines the data model, describes the two-tier recovery pipeline
and its value-analysis dependency, and specifies every integration point.

All paths are relative to the repository root. Code sketches are illustrative and
follow the repo's conventions (named structs over tuples, methods over free
functions, `Address`/`RawAddress` idioms, `u64` for addresses and `usize` only at
physical slice indices, `rkyv` for on-disk structs).

## 1. Where recovery runs: two stages on the existing loop

Fugue's `FunctionRecovery`
(`fugue-core/src/analysis/function/recovery/analysis.rs`) already runs a
recursive-descent loop that lifts a function block-by-block and re-drives until no
new candidates or local targets appear (`builder.rs`, `analyse` at the
`self.candidates.is_empty() && self.local_targets.len() == num_local_targets`
check). Its stage-3 design note explicitly reserves the post-structuring point for
"resolve jump tables, indirect jumps, etc." We use two insertion points that
mirror Ghidra's split across two heritage passes:

### Stage A — address recovery (in-function, pre-commit)

Registered via `FunctionRecovery::add_builder_post_lifting_pass(name, pass)` as an
`AnalysisPass<PartialFunctionWithContext>` (`builder.rs:148`,
`analysis.rs:469`). It runs *after* a function's blocks are structured but *before*
the function is committed — the analog of Ghidra recovering addresses on a partial
clone during flow analysis.

At this point the pass has:

- `&mut Project` — read-only access to segments (`project.segments()`), the arch
  (`project.arch()`), and the lifter, for reading table bytes and validating
  targets.
- `&mut PartialFunctionWithContext` — the structured `PartialFunction` (its
  `insns`, `insn_map`, and blocks) and the `FunctionBuilderContext`.

It does **not** have project-cached ECode-SSA, because the function is not
committed. Stage A therefore builds any SSA it needs *locally* from the partial
function's P-code (see §5), or resolves the case entirely in Tier 0 without SSA.

What Stage A produces:

- For each resolved intra-function case target `t` from branch site `b`:
  `context_mut().add_local_target(b, t, FlowKind::SwitchBranch)`
  (`builder.rs:234`). The loop re-structures and re-lifts, so case code is
  discovered in the same function.
- For targets that are separate functions (switch-of-tail-calls):
  `context_mut().add_candidate_with_context(t, ctx)` — surfaced through
  `global_targets` for the discovery loop.
- An in-progress `ir::Switch` (labels/default unset; see §3) stashed on the partial
  function for Stage B to enrich, so the expensive work is not repeated.

Because the loop re-drives to a fixpoint, **partial tables complete for free**:
a table whose entries reach code that reveals a second indirect branch simply
gets picked up on a later iteration. This subsumes Ghidra's explicit multi-stage
restart for the common case. (A cross-*function* restart still needs Stage B; see
§8.)

**Idempotency.** The pass must not re-emit targets it already added. It records
resolved branch sites on the partial function and skips them on re-entry.

### Stage B — enrichment (post-commit, DERIVED)

Registered as an engine `Analyser` via
`registry::submit!{ AnalyserProvider::new("switch-recovery", …) }`
(`fugue-core/src/engine/mod.rs`), with `triggers() = [Trigger::FunctionAdded]` and
`priority() = Priority::DERIVED`. It runs after the function is committed, when
full ECode-SSA is available lazily through `project.ecode_ssa(fid)`
(`project.rs`). This is the analog of Ghidra's late `ActionSwitchNorm`.

Stage B, per committed function that contains an in-progress `ir::Switch`:

- Recovers **case labels** and the **default** case (reverse the index
  normalization — §7), using full SSA.
- Determines the **element kind** and lays down the table typing metadata.
- Emits persistent **references**: `add_reference(Reference)` with
  `ReferenceProperties::JUMP | COMPUTED` from the branch to each case, and DATA
  references into the table (§9).
- Persists the **`Switch` entity** into `SwitchTable` (§4).
- Emits `AddressAnnotationValue::KnownTargets` / `ComputedSpace` onto the P-code IR
  so the IL, the xref index, and consumers reflect the resolved edges (§9).

Splitting this way keeps the hot recovery loop cheap (Stage A does only what flow
discovery needs) and puts the SSA-heavy enrichment where SSA already exists.

```
FunctionRecovery loop (per function, to fixpoint)
  lift blocks ─► structure_blocks ─► [post-lifting passes]
                                       └─ Stage A: SwitchRecovery
                                            detect ▸ Tier0/Tier1 ▸ targets
                                            add_local_target(SwitchBranch) ──┐
  ◄──────────────── re-drive if new targets ───────────────────────────────┘
  commit function ─► FunctionAdded trigger
                       └─ Stage B: SwitchEnrichment (DERIVED analyser)
                            labels ▸ default ▸ typing ▸ references ▸ entity
```

## 2. Detection

Detection finds indirect branches that need resolution. In the P-code IR these are
`Op::IBranch` (`fugue-lifter-runtime/src/pcode.rs`, displays as `BRANCHIND`); in
`Insn::push_targets_for_operations` (`fugue-core/src/ir/insn.rs:176`) an `IBranch`
currently pushes a lone `InsnTarget::Unresolved` and creates no successor. In the
structured function these show up as blocks carrying
`CodeBlockProperties::UNRESOLVED` (`fugue-core/src/ir/block/mod.rs`).

`detect` yields, per unresolved branch, an `IndirectBranch { site, block, kind }`
where `kind` distinguishes `IBranch` (jump) from `ICall` (call). Calls are
in-scope too (`FlowKind::SwitchCall` exists) but jumps are the priority.

We deliberately do **not** try to recover every indirect branch as a table.
Detection is cheap; the pipeline decides table-vs-not, and a branch that resolves
to a single target (a tail call / thunk) is reported as such, not forced into a
one-entry table (avoiding Ghidra's thunk-misclassification corner).

## 3. Data model — a first-class `ir` representation

The recovered switch is a durable program representation, so it lives in `ir/`
alongside `CodeBlock`, `Function`, `Reference`, and `Symbol` — **not** in the
analysis crate — and takes the same shape as its siblings: an entity struct with
private fields + accessors, an `Id`, a `Properties` bitflags with the hand-rolled
`rkyv` archive impl the other entities use, and a collection under
`ir/switch/table/` (§4). It is produced by the analysis (§5–§7) exactly as a
`PartialFunction` produces a `Function`.

`fugue-core/src/ir/switch/mod.rs`:

```rust
#[derive(Debug, Clone, Default, PartialEq, Eq,
         rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Switch {
    id: SwitchId,
    branch: Address,              // the indirect branch instruction
    model: SwitchModel,           // how targets are computed from an index
    cases: Vec<SwitchCase>,       // concrete targets (labels filled by Stage B)
    default: Option<SwitchCase>,  // out-of-range destination, if a guard was found
    provenance: SwitchProvenance, // how it was recovered and how much we trust it
    properties: SwitchProperties,
}

pub struct SwitchCase {
    target: AddressWithContext,   // carries the context (e.g. Thumb mode) to decode it
    labels: SmallVec<[BitVec; 1]>,// case value(s); empty until Stage B
}

pub enum SwitchModel {
    Absolute(AddressTable),                                   // target = read(tab + i*stride)
    OffsetRelative { table: AddressTable, base: RawAddress, signed: bool },
    TwoLevel { outer: AddressTable, inner: AddressTable },    // table2[table1[i]]
    Explicit,                                                 // override / assisted: no table
}

pub struct AddressTable {
    address: Address,
    element_size: u8,   // bytes per entry: 1, 2, 4, 8
    element_count: u32, // recovered entry count (post-truncation)
    shift: u8,          // left shift applied to each raw entry (ARM Thumb tables)
}
// NB (as built): endianness is not stored on the table — it is an arch-wide
// property supplied to decode_entry (see 04-refinement.md).

pub struct SwitchProvenance {
    tier: RecoveryTier,       // Syntactic | Semantic | Override | Assisted | Trivial
    confidence: Confidence,   // reuses ir::AddressWithContext's Confidence
    evidence: SwitchEvidence, // bitflags: GuardFound, TableInReadOnly, TargetsAligned,
                              // TargetsInExecutable, ContiguousEntries, Truncated, …
}
```

`SwitchProperties` is a bitflags (`PARTIAL`, `TRUNCATED`, `HAS_DEFAULT`,
`ASSISTED`, `OVERRIDE`) with the same `Archived…`/`CheckBytes` impl pattern
`CodeBlockProperties` uses. All fields are private; every field has a fluent
accessor and, where mutated post-construction (labels, default, properties), a
mutator — matching `CodeBlock`. `SwitchId = Id<Switch>`.

There is **no separate analysis-side result type**: the recovery builds a `Switch`
directly (Stage A leaves `labels`/`default` empty and may set `PARTIAL`; Stage B
fills them). This mirrors `PartialFunction → Function` rather than introducing a
parallel `RecoveredSwitch` we would have to keep in sync. Confidence gates whether
a computed `Switch` is committed at all.

`Confidence`, `AddressWithContext`, `Address`, `RawAddress`, and `Endian` are all
re-exported from `ir` already (`fugue-core/src/ir/address.rs`, `cfg.rs`); `BitVec`
is `fugue-bv`. `RecoveryTier` and `SwitchEvidence` live here too, since provenance
is persisted with the entity.

**Why confidence, not thresholds.** Ghidra makes binary accept/reject calls at
`0xffff`, `0x10000`, `max_jumptable_size`, etc. We instead accumulate evidence into
a `Confidence`. Truncating a table at a suspicious entry becomes a confidence
penalty on the tail rather than a hard cut; a table in read-only memory whose
targets all land on aligned executable code scores high even if large; a table
recovered with no guard scores lower and may be held for Stage B confirmation.
Downstream recovery already understands `Confidence`, so low-confidence tables are
naturally treated conservatively.

## 4. The `SwitchTable` collection

The collection follows the `CodeBlock`/`CodeBlockTable`, `Function`/`FunctionTable`
form exactly: `fugue-core/src/ir/switch/table/{mod.rs, persistent.rs,
transient.rs}`, with `SwitchTable` an enum over `PersistentSwitchTable` /
`TransientSwitchTable` backed by `EntityStorage`, a typed `SwitchTableError`
(`thiserror`), `SwitchRef`/`SwitchMut`, and `SwitchIter`/`SwitchIterMut`. It
exposes the same surface as `CodeBlockTable`: `insert`, `get_by_id`,
`get_by_address`, `modify_by_id`, `remove_by_*`, and `try_*` fallible variants.

Neither IDA's `switch_info_t` nor Ghidra's in-decompiler `JumpTable` is a durable,
queryable project artifact; making `Switch` a normal `ir` entity gives every
consumer (queries, UI, other analyses, re-load) access to switch structure for
free.

- New entity id in `fugue-core/src/storage/schema.rs` (`ENTITY_SWITCH`), keyed by
  the branch `Address` (granular per-entity layout, per project convention — not a
  whole-table blob).
- On-disk record is the `rkyv`-derived `Switch` (per repo convention — no
  hand-rolled byte packing).
- Cross-referenced through the existing `ReferenceIndex`: flow refs from the branch
  to each case, DATA refs from the branch into the table bytes (§9).
- `Project` gains a `switches()` accessor mirroring `functions()`/`blocks()`;
  `ProjectTransaction` gains `insert_switch` / `remove_switch`, matching
  `add_function` / `insert_symbol`.

Because storage-format changes need no back-compat for existing projects in this
codebase, we add the schema entry directly.

## 5. Tier 0 — syntactic idiom matching

The fast path. It resolves the overwhelmingly common table idioms without SSA or
emulation, analogous to IDA's matcher but expressed declaratively over ECode
expression trees rather than as per-processor instruction templates.

**Why ECode.** SLEIGH lifts each architecture's switch instructions to uniform
P-code, which we raise to ECode expression trees
(`fugue-core/src/il/ecode/expression.rs`: `ECodeExprOpcode::{Load, Add, Mul,
LeftShift, ZeroExtend, SignExtend, …}`). A `jmp [tab + idx*4]` on x86 and an
`ldr pc, [pc, idx, lsl #2]` on ARM raise to structurally similar ECode. So a
single idiom pattern matches multiple encodings — eliminating IDA's per-processor
duplication.

**How it works.** Starting from the indirect branch statement
(`ECodeStmtOpcode::BranchIndirect`), Tier 0 takes the branch's target expression
and matches it against a set of `IdiomPattern`s. A pattern is a small tree matcher
with typed holes:

```rust
// target := Load(Add(Const(table), Mul(index, Const(stride))))   -- absolute table
// target := Add(Const(base), SignExtend(Load(Add(Const(table),
//                                    Mul(index, Const(stride))))))-- offset table
```

Bindings captured: `table` (an `Address`), `stride`/`element_size`, `index` (the
sub-expression), `base`, `shift`, and signedness (from `SignExtend` vs.
`ZeroExtend`). A matched pattern yields a `SwitchModel` plus the `index`
expression to bound.

Bounds for Tier 0 come from a *local* scan: within the branch's block and its
immediate dominator, look for a compare-and-conditional-branch that constrains
`index` (`cmp idx, N; ja default`). This is the common, cheap case; if the bound
is not found locally, Tier 0 emits a table with an *unbounded* index and hands off
to Tier 1 to bound it properly (rather than guessing).

Once model + bound are known, Tier 0 reads and decodes entries (§6) and validates
(§8). Patterns live as data in `fugue-core/src/analysis/switch/syntactic/patterns.rs`;
adding a compiler/arch idiom is adding a pattern, not code.

Coverage target for the initial pattern set:

- x86/x86-64: `jmp [tab + idx*sz]`, PIC `lea rax,[rip+tab]; movsxd rcx,[rax+idx*4];
  add rcx,rax; jmp rcx` (offset-relative), `jmp [tab + idx*8]`.
- ARM/Thumb: `tbb [pc, idx]` / `tbh [pc, idx, lsl #1]` (byte/halfword offset
  tables, `shift`/element-size encoded), `ldr pc, [pc, idx, lsl #2]`,
  `add pc, pc, idx, lsl #2`.
- AArch64: `adr x_, tab; ldr(sw) x_, [x_, idx, lsl #2]; add x_, x_, base; br x_`.
- MIPS: `sll t,idx,2; lw t,tab(t); jr t` (absolute), and the GOT/`.rodata`
  offset-relative variant.

## 6. Table reading and entry decoding

Shared by both tiers, split cleanly along the layering boundary: the *shape* knows
how to decode itself; the *analysis* fetches bytes and resolves addresses.

- **Decode is a method on `ir::AddressTable`.** As built,
  `AddressTable::decode_entry(&self, bytes: &[u8], endian: Endian) -> u64` reads
  `element_size` bytes at the given `endian` and applies `shift` (`raw << shift`) —
  a pure function of the table's layout and the byte slice, with no dependency on
  `Project`. Endianness is passed in rather than stored because it is an arch-wide
  property; sign-extension of signed offset entries is applied by the caller
  (`Recovery`) using the model's `signed` flag. This keeps `ir` free of
  segment/analysis dependencies.
- **The analysis supplies the bytes.** Recovery reads from segments
  (`project.segments().view_at(table_addr)` then `bytes_at`/`read_bytes`,
  `storage/segments/view.rs`) entry-by-entry — never materialising a large region
  (per repo convention) — and calls `decode_entry`. For offset-relative tables it
  then adds `base` per `SwitchModel::OffsetRelative`.
- **Validate + decode mode via `Arch::canonicalise_address`.** Per the codebase,
  `canonicalise_address` is a decoder: it clears the low bit, aligns, and
  validates against the cleared address — which simultaneously strips the ARM
  Thumb bit *and* tells us the target's mode. We use its result to (a) reject
  targets that do not canonicalize to mapped, aligned code, and (b) derive the
  `ContextSet` (Thumb vs. ARM) for the `SwitchCase`, using
  `canonicalise_address_with` to thread context. This replaces Ghidra's
  discard-bit-then-reconstruct-on-the-Java-side dance with a single designed step.

## 7. Tier 1 — semantic recovery

The general fallback, taken when Tier 0 does not match or leaves the index
unbounded. This is Ghidra's back-slice → bound → emulate pipeline, rebuilt on
Fugue's ECode-SSA and a clean value domain.

`fugue-core/src/analysis/switch/semantic/`.

### 7.1 SSA source

- **Stage B / post-commit:** use `project.ecode_ssa(fid)`
  (`fugue-core/src/il/ecode/ssa/`). Block-argument SSA (`ECodeSsaValueKind::{Operation,
  BlockArgument}`), with def-use (`ECodeSsaUses`), liveness, and
  dominance/frontier (`fugue-core/src/il/common/dominance.rs`). No phi nodes —
  block arguments play that role; the slice walks block-argument edges instead of
  MULTIEQUAL inputs.
- **Stage A / pre-commit:** the function is not committed, so build a *local*
  ECode-SSA from the `PartialFunction`'s P-code via the existing `ECodeToSsa`
  transform over the partial CFG. This is bounded (one function) and only built
  when Tier 0 fails, keeping the common path cheap. Alternatively Stage A can
  defer a hard indirect branch to Stage B by leaving the block `UNRESOLVED` and
  recording it — mirroring Ghidra's "recover later" — at the cost of the case
  code not being lifted until a re-drive. The plan builds local SSA (§ plan
  Phase 4) so Stage A is self-sufficient.

### 7.2 Back-slice (`slice.rs`) — the PathMeld analog

From the `BranchIndirect` target value, walk backward through defining operations,
collecting all data-flow paths to candidate index variables and keeping the ops
common to every path, in execution order. Pruning matches Ghidra's `isprune`
(stop at block arguments with no single reaching def, call results, constants) and
`ispoint` (a candidate is a non-constant, non-annotation, non-read-only value).
The result is a `BranchSlice { spine: Vec<SsaValue>, ops: Vec<SlicedOp> }` — the ordered
computation from index to branch input. Merged paths (a diamond, or an
unrolled-loop guard) intersect to their common spine, exactly as `PathMeld::meld`
does.

### 7.3 Bounds (`bounds.rs`) via the value domain

The normalized index is the spine value with the *smallest* value range. Ranges
come from the **strided-interval value domain** (§10), seeded from:

- Guard conditions: dominating conditional branches whose condition constrains a
  spine value. We pull the guard's boolean range back through the condition's
  operations (inverse transfer functions) to constrain the value — the general
  form of Ghidra's `analyzeGuards` + `CircleRange::pullBack`, but implemented once
  in the reusable domain.
- The value's own bit-pattern: trailing-zero bits of the known-zero mask give the
  stride (a scaled index); an `And` with a constant mask bounds the maximum.

If no bound is found, the index range is the full type range; the pipeline then
relies on the *table walk* (§8) to terminate, and records low confidence.

### 7.4 Materialize (`emulate.rs`) — emulate per index

For each value in the normalized index's range, execute the sliced op sequence to
produce a concrete target — Ghidra's `emulatePath`. The emulator is a tiny
straight-line ECode evaluator over the slice:

- Reads the current index value; evaluates each `SlicedOp` forward.
- `Load`s read from segments (§6), recording each as an `AddressTable` observation
  (the analog of `LoadTable`); contiguous same-size loads collapse into one table
  descriptor, which is how per-index single reads become "a table at X of N
  entries" — and how two-level tables yield two descriptors.
- Branch/call ops on the path abort emulation for that value (as in Ghidra); the
  index is dropped and confidence lowered.

Because this re-runs the real arithmetic, scaling, signedness, offset bases, and
nested tables are handled with no special cases — the key generality win we take
from Ghidra.

### 7.5 Labels and default (Stage B, `labels.rs`)

Walk forward from the normalized index through a bounded number of reversible ops
to the user-visible switch variable, then reverse-evaluate each recovered target's
index to its case value(s). The default is the guard's out-of-range edge. Values
that do not reverse get no label (the Ghidra `NO_LABEL` role). Unlike Ghidra we
express the reversibility limits as confidence inputs rather than hard `max*=1`
caps, so an unusual but real denormalization is recovered at lower confidence
rather than dropped.

## 8. Validation, truncation, and staging

Driven by `analysis/switch/recover.rs`, decoding through `ir::AddressTable` (§6).

Walk the table from entry 0, decoding and validating each entry (§6). Stop when an
entry fails to canonicalize to mapped executable code, points into the middle of a
known instruction, or hits a location that already has an unrelated symbol/xref —
the union of IDA's walk-and-stop and Ghidra's sanity check. Record the validated
count as `element_count` and mark `SwitchEvidence::Truncated` if we stopped early.

- A branch that resolves to exactly one target that is a distant/foreign address
  is reported as a **tail call**, not a one-entry table (rewrite as
  `FlowKind::TailCallBranch` / a `SwitchCall` candidate) — avoiding Ghidra's
  thunk-vs-table ambiguity.
- **Partial tables** (some entries reach not-yet-lifted code) are fine: Stage A
  emits the entries it validated; the recovery loop re-drives as case code is
  lifted, and a subsequent Stage A/B pass extends the table. Cross-function
  completion is Stage B's job (it re-examines on `FunctionAdded`).

## 9. Feeding results back into the CFG, IL, and references

There is no "wiring" grab-bag module. Feeding results back is not one concern; it
is three, each of which belongs to a mechanism that already exists. The recovery
passes call into those mechanisms rather than reimplementing them.

**Stage A → CFG (pre-commit).** Emitting edges is the pass's own job, not a
separate module: `SwitchRecovery` calls `context_mut().add_local_target(branch,
case, FlowKind::SwitchBranch)` for intra-function cases and
`add_candidate_with_context` for out-of-function targets. The builder's existing
`structure_blocks` consumes `local_targets` to cut blocks and wire successors, and
clears `CodeBlockProperties::UNRESOLVED` once the branch has edges — unchanged.

**Stage B → references (post-commit) — via the existing derivation path.**
References are already *derived* from the IL, not written ad hoc: `Project`'s
`replace_ir_derived_references` (`project.rs:246`) rebuilds a function's derived
references from its P-code, taking flow refs from `Insn::flow_references()` and data
refs from `PCodeIr::data_references()` (`il/pcode/builder.rs:137`). Switch targets
join that same path:

- Stage B emits `AddressAnnotationValue::KnownTargets(&[Address])` (and
  `ComputedSpace` where relevant) on the branch's P-code op through the existing
  annotation channel (`il/pcode/operation.rs`: `AddressAnnotation`,
  `PCodeAddressContext`). These variants exist but have no producer today — Stage B
  is the first producer.
- `PCodeIr::data_references` (renamed to reflect that it now derives flow as well
  as data references, or split so flow-from-annotations sits beside
  `Insn::flow_references`) turns a `KnownTargets`-annotated branch into
  `ReferenceProperties::JUMP | COMPUTED` flow refs per target;
  `ReferenceProperties::from_flow` already maps `SwitchBranch` correctly
  (`ir/reference.rs:141`). It also adds constant DATA refs into the table bytes
  (the analog of Ghidra's `markDataAsConstant`).

So the reference half is an *extension of existing derivation*, not new switch-
private plumbing.

**Stage B → entity persistence.** `SwitchEnrichment` fills the in-progress
`ir::Switch` (labels, default, properties) and persists it via
`ProjectTransaction::insert_switch` — the same shape as `add_function` /
`insert_symbol`. No bespoke module.

**`Insn` handling.** `Insn::push_targets_for_operations` keeps emitting
`Unresolved` for a bare `IBranch`; resolved edges come from the local-target path
(Stage A) and the derived-reference path (Stage B), not from re-interpreting the
lone P-code op. The lifter stays oblivious to analysis results (correct layering)
while the CFG still gets edges.

## 10. The value domain (a reusable building block)

Fugue has no value-set / abstract-interpretation layer today (confirmed: no VSA,
constant folding, strided intervals, or fixpoint framework in `fugue-core/src`).
Rather than build range math privately inside switch recovery (Ghidra's mistake,
which left `CircleRange` un-reusable), we add a small, general domain that switch
recovery consumes and other analyses can share.

`fugue-core/src/analysis/value/`:

- `interval.rs` — `StridedInterval` over `BitVec` widths: a set
  `{ lo, lo+stride, …, hi }` modulo `2^n`, with the standard lattice ops (join,
  meet, widen) and transfer functions for the ECode opcodes used in address
  computations (`Add`, `Sub`, `Mul`-by-constant, `LeftShift`, `And`-mask,
  `ZeroExtend`, `SignExtend`, `Load` ⇒ top). This is our replacement for
  Ghidra's `CircleRange`, kept independent of switch recovery.
- `solver.rs` — a bounded worklist/fixpoint solver over an ECode-SSA function that
  computes an interval per value, with guard constraints applied along
  conditional edges, and a widening cap for loops. This is the general form of
  Ghidra's value-set solver (the VSA reference), scoped to what switch bounds
  need first, but usable by future analyses (indexed load/store bounds, etc.).

Switch recovery depends on `analysis::value`; nothing in `analysis::value` depends
on switch recovery. Delivering it as a standalone layer is a deliberate scope
choice — it is the one genuinely missing primitive, and it is broadly useful.

## 11. Overrides and spec-assisted models

For the hard tail we support, unified behind the same `ir::Switch`:

- **Override** (Ghidra's `JumpBasicOverride`): a user- or script-provided target
  set, supplied through the annotation channel or a project API, that skips
  detection/bounds and goes straight to validation + labelling. The recovery still
  tries to recover an index variable so labels can be produced.
- **Assisted** (Ghidra's `JumpAssisted`): compiler/OS-specific idioms described in
  Fugue's spec crates (`fugue-specs`, `.cspec`), evaluated to targets. This is the
  hook for Visual-Studio-style or exception-table idioms that resist generic
  dataflow.

Both are `RecoveryTier` variants and produce `SwitchModel::Explicit`.

## 12. Module layout

The durable representation lives in `ir/` (shaped like `block/`); the analysis crate
holds only the machinery that *produces* it plus the reusable value domain.

```
fugue-core/src/ir/
  switch/                      # durable representation, parallels ir/block/
    mod.rs                     # Switch, SwitchId, SwitchProperties, SwitchCase,
                               #   SwitchModel, AddressTable, SwitchProvenance,
                               #   SwitchEvidence, RecoveryTier
    table/                     # collection, parallels ir/block/table/
      mod.rs                   # SwitchTable { Persistent, Transient }, SwitchTableError
      persistent.rs
      transient.rs

fugue-core/src/analysis/
  value/                       # reusable value domain (new building block)
    mod.rs
    interval.rs                # StridedInterval abstract domain
    solver.rs                  # bounded fixpoint solver over ECode-SSA
  switch/                      # recovery: produces ir::Switch, no durable types here
    mod.rs                     # SwitchRecovery (Stage A pass) + SwitchEnrichment
                               #   (Stage B analyser) + SwitchConfig + registration
    detect.rs                  # IndirectBranch::scan over unresolved branches
    recover.rs                 # tier dispatch; builds an ir::Switch; fills provenance
    syntactic/
      mod.rs                   # IdiomMatcher over ECode expression trees
      patterns.rs              # declarative idiom set (x86/arm/thumb/aarch64/mips)
    semantic/
      mod.rs                   # slice ▸ bound ▸ emulate driver
      slice.rs                 # backward slice / path meld over ECode-SSA
      bounds.rs                # guard + value-domain bounds for the index
      emulate.rs               # per-index straight-line ECode evaluator
    labels.rs                  # Stage B: fill labels + default (denormalisation)
```

Entry decoding is a method on `ir::AddressTable` (it knows its own layout —
element size, shift, endian); the analysis supplies bytes from segments and does
`Arch` canonicalisation (§6). Reference emission and entity persistence reuse the
existing derivation and transaction APIs (§9), so there is no `table.rs`,
`wiring.rs`, or `entity.rs` in the analysis crate.

Registration mirrors `FunctionRecovery`: Stage A via
`add_builder_post_lifting_pass` inside `FunctionRecovery` construction; Stage B via
`registry::submit!{ AnalyserProvider::new("switch-recovery", …) }`.

## 13. Integration-point checklist (existing code touched)

| File | Change |
| --- | --- |
| `ir/switch/` | **new** representation: `Switch`, `SwitchId`, `SwitchProperties`, `SwitchModel`, `SwitchCase`, `AddressTable`, `SwitchProvenance` |
| `ir/switch/table/` | **new** `SwitchTable` collection (persistent + transient), mirroring `ir/block/table/` |
| `ir/mod.rs` | (extend) `pub mod switch;` + re-exports beside `block`/`function`/`reference` |
| `analysis/function/recovery/analysis.rs` | register Stage A post-lifting pass |
| `analysis/function/recovery/builder.rs` | (consume) `add_local_target`, `add_candidate_with_context`, stash in-progress `ir::Switch` |
| `engine/mod.rs` | register Stage B `AnalyserProvider` (`FunctionAdded`, `DERIVED`) |
| `il/pcode/operation.rs` | (consume) `AddressAnnotationValue::KnownTargets/ComputedSpace` producer path |
| `il/pcode/builder.rs` | extend derivation to emit flow refs from `KnownTargets` (beside `data_references`) |
| `project.rs` | extend `replace_ir_derived_references`; add `switches()` accessor, `insert/remove_switch` on transaction |
| `ir/reference.rs` | (reuse) `ReferenceProperties::from_flow` for `SwitchBranch` |
| `ir/insn.rs` | leave `IBranch` ⇒ `Unresolved`; edges come from local targets / derived refs |
| `ir/block/mod.rs` | (consume/clear) `CodeBlockProperties::UNRESOLVED` |
| `storage/schema.rs` | add `ENTITY_SWITCH` |
| `arch/traits.rs` | (reuse) `canonicalise_address[_with]`, `endian` |
| `storage/segments/view.rs` | (reuse) `view_at`/`bytes_at`/`read_bytes` |

"(reuse)" means the API exists and is called as-is; "(consume)" means an existing
type gains its first producer/consumer; "(extend)" adds to an existing item;
"**new**" / unmarked means new code.
