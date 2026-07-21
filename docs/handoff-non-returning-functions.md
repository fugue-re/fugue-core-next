# Handoff: non-returning-function detection

## Goal

Stop function recovery over-extending across calls to functions that never return
(`abort`, `exit`, `__stack_chk_fail`, C++ `_Unwind_Resume`, Windows `ExitProcess`,
…). When a `call` targets a non-returning function, recovery must **not** follow the
post-call fall-through edge.

## Evidence / why it matters

On `fugue-core/tests/ls.elf`, two switches over-read because their containing
functions are grossly over-extended:

- `0x1282e`: IDA 11 cases, fugue **326** (recovered in a 419-block function).
- `0xb993`: IDA 7 cases, fugue **289** (recovered in a 429-block function; IDA's
  `sub_B910` is **15** blocks).

Root cause: the switch default cases jump into a cold section of `call _abort`
trampolines (`0x4d7f`–`0x6d03`, all `call _abort`). `abort` never returns, but
recovery adds the fall-through edge after each `call`, chaining through the whole
region and merging it into whatever function reaches it first. The polluted local
SSA then defeats guard matching (see the `switch-guard-pullback-and-cfg-fixes`
memory — the guard machinery itself is correct; this is purely a boundary problem).

### The PLT indirection (the crux)

`call _abort` at `0x4d7f` does **not** target the extern directly. It targets the
**PLT thunk** at `0x4750`:

```
0x4750  endbr64
0x4754  jmp  qword [rip + GOT:abort]     ; -> extern abort @ 0x24560
```

Facts established this session (via throwaway probes, since removed):

- The extern `abort` is a **symbol** at `0x24560` with `EXTERN | FUNCTION`
  (`is_extern() && is_function()`, `is_import()`), *not* a `Function` entity —
  externs are excluded from function recovery (`Segment::is_external()`).
- The PLT thunk `0x4750` **is** a recovered `Function`, but its `jmp [GOT]` is
  **unresolved**: no symbol, no callee edge, no reference. So nothing connects
  `0x4750 → abort`.
- The loader **already** resolves the GOT slot: the `R_X86_64_JUMP_SLOT` handler
  (`fugue-core/src/loader/elf/relocations/x86_64.rs`) writes `0x24560` into the GOT
  slot and marks a function hint there. The data to resolve the thunk exists; it is
  just never turned into a reference.

So `call abort` reaches `abort` through: call-site → PLT thunk (`Function`) →
extern (`symbol`). Both hops must be understood by the non-returning logic.

## Architecture (decided with the user)

Three constraints from the user:

1. **Initial seeding is a separate, opt-in analysis that runs before function
   recovery.** It must not be coupled to recovery — recovery only reads a shared
   marker, it never resolves names itself.
2. **Call-graph-level propagation is allowed at the end of each recovery cycle**
   (this part may be coupled to recovery).
3. **Shared state = the `NON_RETURNING` property** on symbols and functions (not a
   new project index). A call target is non-returning if the symbol *or* the
   function at that address is marked.

## What is already built (this session)

- **Extension-point registry** — `fugue-core/src/analysis/non_returning/`:
  - `mod.rs`: `NonReturningExterns { name, names }` registered via
    `registry::submit!` / collected via `registry::collect!`;
    `non_returning_extern_names()` unions all registered lists.
  - `posix.rs`: `POSIX_NON_RETURNING` (~57 names: `abort`, `exit`/`_exit`/`_Exit`,
    `__assert_fail`, `__stack_chk_fail`, `__fortify_fail`, `longjmp`/`siglongjmp`,
    `pthread_exit`, `__cxa_throw`, `_Unwind_Resume`, `_ZSt9terminatev`, …; includes
    with/without-leading-underscore and mangled variants, mirroring vulhunt).
  - `windows.rs`: `WINDOWS_NON_RETURNING` (~37 names: `ExitProcess`, `ExitThread`,
    `_CxxThrowException`, `RaiseException`, `KeBugCheckEx`, `__fastfail`,
    `_invalid_parameter_noinfo_noreturn`, …).
  - Unit test passes (`platform_lists_register_expected_names`).
- **`SymbolProperties::NON_RETURNING`** (`fugue-core/src/ir/symbol/mod.rs`): free
  `u8` bit `0b0010_0000` (no schema bump — still one `u8`). Accessors
  `SymbolProperties::is_non_returning`, `SymbolEntry::is_non_returning`,
  `SymbolEntry::mark_non_returning`.
- `FunctionProperties::NON_RETURNING` + `Function`/`PartialFunction`
  `is_non_returning`/`mark_non_returning` already existed (were dead code).
- Full lib suite green (322 tests).

Reference implementation to follow: vulhunt `bias-core`
(`src/cfg/non_returning.rs` core propagator, `src/posix/non_returning.rs`,
`src/windows/non_returning.rs`). Their model: `NonReturningFunctions =
Arc<BTreeSet<FunctionId>>`, a `NonReturningPropagator` trait extension point, and a
`PropagatedNonReturning<T>` worklist fixpoint over the call graph that converts
call edges into `TailCallBranch` and re-splits orphaned blocks.

## Remaining work (ordered)

### 1. `SymbolTable::mark_non_returning` (immediate blocker for seeding)

The unified `SymbolTable` enum (`fugue-core/src/ir/symbol/table/mod.rs`) exposes no
in-place mutation. The transient backend has `get_by_id_mut`; the persistent
backend needs read-modify-write (its entries go through the entity store `put`, cf.
the switch table's `insert` upsert in `table/persistent.rs`). Add:

```rust
pub fn mark_non_returning(&mut self, id: Id<Symbol>) -> bool
```

delegating to both backends. Prefer routing through `ProjectTransaction` for change
tracking if the seeding runs as an engine analysis (see step 2).

### 2. Seeding analysis (separate, opt-in, pre-recovery)

New analysis (e.g. `fugue-core/src/analysis/non_returning/seeding.rs`) implementing
`AnalysisPass`. Logic: for each name from `non_returning_extern_names()`, look it up
via `SymbolTable::get(name)` (name → symbols), and for each matching
`is_extern() && is_function()` symbol call `mark_non_returning`. O(names) lookups.

**Opt-in wiring**: do *not* auto-`submit!` it as an always-on analyser. Expose it so
a caller enables it explicitly (an engine/recovery config toggle, or a
`FunctionRecoveryExtension` gated on a config flag). Decide the toggle surface — the
existing engine analyser registration is `submit! { AnalyserProvider::new(...) }`
with `Trigger` + `Priority` (`fugue-core/src/engine/mod.rs`); a pre-recovery analysis
needs a higher `Priority` than `Priority::DISCOVERY` on `Trigger::BytesMapped`, or a
distinct trigger. Confirm the engine supports an opt-in analyser cleanly before
committing to a mechanism.

Unit test: load `ls.elf` transient, run seeding, assert the `abort` symbol at its
extern address `is_non_returning()`.

### 3. PLT/thunk reference resolution (dedicated analysis)

Resolve indirect `jmp/call [const-GOT-ptr]` to its extern and populate the missing
reference + call-graph edge, and `mark_thunk` the function. Approach (arch-generic):
build the thunk's local SSA (thunks are 1 block — cheap; reuse
`SwitchRecovery::build_local_ssa`), take the indirect-branch input; if it folds to
`Load(const_addr)`, read the (already relocated) pointer at `const_addr` from the
segment (`SegmentReader`) → target address; resolve the symbol there; emit a flow
reference (`FlowKind::TailCallBranch` — currently unused but defined in
`fugue-core/src/ir/cfg.rs`) so `CallGraphIndex::function_call_targets` picks it up
as a call edge. This is the "dedicated analysis to populate these references" the
user asked for; keep it separate from recovery.

Test: after this runs, `callees_of(0x4750)` includes `0x24560`; a reference
`0x4750 → 0x24560` exists.

### 4. Call-graph propagation (end of each recovery cycle)

Inter-function structuring pass
(`FunctionRecovery::add_inter_function_structuring_pass`, state
`FunctionStructuringContext` — exposes `pending_functions`,
`modify_pending_function`, `project.call_graph().callers/callees`). Worklist
fixpoint (vulhunt `PropagatedNonReturning`): a function is non-returning if it has
no return/indirect-jump blocks and every tail call targets a non-returning-or-
same-SCC function. Seed from step 2's symbols + step 3's thunk→extern edges. Mark
newly-proven functions `mark_non_returning` (function property). Run at the end of
each cycle so later cycles benefit.

### 5. Recovery suppression + re-split

- **Suppression** (`fugue-core/src/analysis/function/recovery/builder.rs`, lift loop
  ~369–398): when the lifted instruction `is_call()` and its `Global` (`InterSub`)
  target is non-returning (symbol- or function-marked), do **not** insert the
  `Fall` local target / candidate. This alone prevents `0x4d7f → 0x4d84` chaining
  *when the target is known non-returning at lift time*. Because a call has
  `has_fall() == true`, the `structure_blocks` fall-through loop
  (`ir.rs` ~585–599, added this session) must **also** skip the fall-through for a
  block whose terminating instruction is a non-returning call. Handle both, or the
  edge reappears.
- **Re-split**: functions over-extended in an earlier cycle (before their callee
  was proven non-returning) need the fall-through edge removed and the orphaned
  blocks re-recovered as new functions — vulhunt's `mark_non_returning_flows`. In
  fugue, rebuild the `PartialFunction` dropping the successor
  (`PartialCodeBlock::remove_successor`) and re-`add_function` (which recomputes CFG
  + call-graph edges), or emit new candidates for the orphaned entries.

### Ordering note

For lift-time suppression to catch the ls.elf case on the first pass, the PLT thunk
`0x4750` must be known non-returning *before* the function containing `0x4d7f` is
lifted. That requires steps 2+3 to seed thunk addresses ahead of recovery (thunk →
non-returning extern ⟹ thunk non-returning), *or* step 5's re-split to fix
functions over-extended before propagation caught up. Decide which during step 3:
if PLT resolution + seeding run fully pre-recovery, lift-time suppression suffices
and re-split is a safety net; otherwise re-split is required.

## Validation gates

- `ls.elf`: `0xb993` → **7** cases, `0x1282e` → **11** cases (currently 289/326);
  the other five switches unchanged (`0x10612`=5, `0x4f55`=277, `0x6efd`=73,
  `0x12116`=54, `0x149dd`=123).
- The function containing `0xb993` is bounded (~15 blocks, not 429).
- With seeding **off** (opt-in), behaviour is unchanged from today.
- New unit tests: registry (done), seeding marks `abort`, PLT resolution creates the
  thunk→extern edge, propagation marks a synthetic always-abort function.
- Real-binary regression test per the `no-handcrafted-binary-fixtures` memory.
- `cargo test -p fugue-core` green; **no committed debug**.

## Style gates (must pass review)

Follow the `rust-style-guidelines` skill exactly. Load-bearing here:

- Zero comments; self-explanatory names (project `no-code-comments` memory).
- British spelling (`analyse`, `initialise`, `recognise`).
- Accessors/mutators, no `pub` fields; return **named structs, not tuples**
  (`structs-not-tuples` memory); helpers as methods on the type
  (`methods-over-free-fns`).
- Import grouping stdlib / external / crate, one path per line, no nested module
  groups; `cargo fmt -- --config imports_granularity=Module,group_imports=StdExternalCrate`.
- No `let` type annotations; inline `format!` captures.
- `?` over `unwrap`/`expect`; `thiserror` specific variants; lower-case error
  messages.
- `cargo clippy -p fugue-core --all-targets` clean for touched files.
- Consult `import-types`, `no-trivial-helpers`, `consistent-vocabulary`,
  `use-rkyv-not-manual-bytes` memories.
- The seeding analysis and PLT resolution are **separate** modules; do not fold
  their logic into function recovery (explicit user constraint).

## Key files

- `fugue-core/src/analysis/non_returning/{mod,posix,windows}.rs` — registry +
  lists (built); add `seeding.rs`, and the PLT-resolution analysis (own module).
- `fugue-core/src/ir/symbol/mod.rs` — `SymbolProperties::NON_RETURNING` + accessors
  (built).
- `fugue-core/src/ir/symbol/table/mod.rs` — add `mark_non_returning`.
- `fugue-core/src/ir/function/mod.rs`, `.../recovery/ir.rs` —
  `FunctionProperties::NON_RETURNING`, `mark_non_returning` (exist, dead).
- `fugue-core/src/ir/cfg.rs` — `FlowKind::TailCallBranch` (exists, unused).
- `fugue-core/src/analysis/function/recovery/builder.rs` — lift loop (suppression
  point 1).
- `fugue-core/src/analysis/function/recovery/ir.rs` — `structure_blocks`
  fall-through loop (suppression point 2), `PartialCodeBlock::remove_successor`.
- `fugue-core/src/analysis/function/recovery/analysis.rs` — inter-function
  structuring pass hook (propagation), `FunctionRecoveryExtension` registration.
- `fugue-core/src/ir/call_graph.rs`, `fugue-core/src/queries/` — call graph +
  callers/callees.
- `fugue-core/src/loader/elf/relocations/x86_64.rs` — where the GOT slot is already
  resolved to the extern (source of truth for PLT resolution).
