# Handoff: ARM computed-PC switch recovery

## Goal

Recover ARM (and Thumb) computed-PC jump-table switches. These are the dominant
switch idiom on 32-bit ARM and are currently **not recovered at all** — our switch
recovery keys entirely on a data-table `Load`, which this family does not use.

## Evidence / ground truth

`fugue-core/tests/libipmi.so` is a 32-bit **ARM little-endian** shared library
(4613 functions). IDA finds **94 switches**; fugue recovers **0**.

Reproduce the IDA ground truth (IDA MCP, `run_script`):

```python
import ida_nalt, idautils, idc, ida_funcs
count = 0
for f in idautils.Functions():
    fn = ida_funcs.get_func(f)
    ea = fn.start_ea
    while ea < fn.end_ea and ea != idc.BADADDR:
        if ida_nalt.get_switch_info(ea):
            count += 1
        ea = idc.next_head(ea, fn.end_ea)
print(count)   # 94
```

Fugue count: load `libipmi.so` into a transient project, run the engine to idle,
and count `reader.switches()` — currently `0`.

## The idiom

The canonical form (libipmi `sub_3BE5C`, branch at `0x3bec0`):

```
0x3bebc  CMP     R8, #3               ; guard: R8 <= 3
0x3bec0  ADDLS   PC, PC, R8,LSL#2     ; predicated computed jump (LS = unsigned <=)
0x3bec4  B       def_3BEC0            ; default (executed when the ADD is NOT taken)
0x3bec8  B       loc_3BF28            ; case 0
0x3becc  B       loc_3BF28            ; case 1
0x3bed0  B       loc_3BED8            ; case 2
0x3bed4  B       loc_3BED8            ; case 3
```

Defining characteristics that separate this from the x86/`Load` family:

1. **The indirect branch is a write to `PC`** computed as `PC + index*4`. There is
   **no data-table `Load`** — the branch reads no memory.
2. **The "table" is inline code**: a run of `B target` instructions immediately
   after the `ADD`. Entry `i` lives at `add_addr + 8 + i*4` (ARM `PC` reads as the
   instruction address + 8) and *is itself a branch instruction*; the case target
   is that branch's target, not a pointer read from data.
3. **The guard is the predication condition on the `ADD`** (`LS`), fed by the
   preceding `CMP R8, #3`. When the predicate is false the `ADD` is a no-op and
   control falls through to the `B default` at `add_addr + 4`. So the default is
   the fall-through of the predicated computed jump, and the bound (`3`) comes from
   the `CMP` that set the flags the `ADDLS` tests.

### Related ARM/Thumb variants (in scope, secondary)

- `ADD PC, PC, Rn, LSL#2` (unconditional; guard is a separate preceding
  `CMP; Bxx default`) — same inline-`B`-table shape.
- `LDR PC, [PC, Rn, LSL#2]` — a *data* table of absolute code addresses. This one
  **does** have a `Load`, so the existing `Load`-based recovery is closest to
  working here; treat it as a second pattern, not the primary.
- Thumb-2 `TBB [PC, Rn]` / `TBH [PC, Rn, LSL#1]` — byte/halfword *offset* tables
  (target = `PC + 2*table[Rn]`). These have a `Load` of a byte/halfword and a
  scale; `docs/switch-recovery/02-architecture.md` §5 already lists them as a
  coverage target with `shift`/element-size encoded.

The Thumb-bit / mode handling for targets is already solved:
`Arch::canonicalise_address` clears the low bit, aligns, validates, and yields the
`ContextSet` (Thumb vs ARM) — see the `canonicalise-address-is-a-decoder` memory
and `docs/switch-recovery/02-architecture.md` §6. Reuse it for every recovered
case target; do **not** hand-strip the Thumb bit.

## Why the current recovery misses it

`fugue-core/src/analysis/switch/slice.rs`:

- `recover()` starts from `self.ssa.indirect_branch_input(branch)` and requires
  **both** `scaled_index(target)` and `table_layout(target)` to succeed.
- `table_layout()` walks the DAG looking for a `Load` whose pointer is
  `table_base + index*stride`. The computed-PC inline-`B` form has no `Load`, so
  `table_layout()` returns `None` and `recover()` bails with "no idiom".

So this needs a **new recognizer** for the "indirect branch target is
`PC + index*stride` into inline code" shape, plus an **inline-branch-table reader**
that decodes each entry by lifting the branch instruction there (instead of reading
a pointer from a data segment).

## Design

Keep it inside the existing two-tier switch framework
(`fugue-core/src/analysis/switch/`), alongside the x86 path — do not fork a
separate subsystem. Concretely:

1. **Computed-PC recognizer.** In the semantic evaluator (or a sibling of
   `scaled_index`/`table_layout`), recognize an indirect branch whose target ECode
   is `Add(pc_base, scale(index))` where `pc_base` is a **constant equal to the
   table base** (the address just past the `ADD`, accounting for the ARM `PC+8`
   pipeline offset that SLEIGH already encodes in the lifted `PC` value — verify
   against the lifted ECode rather than hard-coding `+8`). Extract `index` and
   `stride` (4 for `LSL#2`).

   - The `pc_base` constant should fold out of the ECode-SSA once constants are
     folded (`fold_constants` already runs in `build_local_ssa`). Confirm with a
     dump of the branch input's ECode for `0x3bec0` before writing the matcher.

2. **Inline-branch-table reader.** New table *shape*. Rather than
   `AddressTable::decode_entry` reading a pointer, decode entry `i` by lifting the
   instruction at `table_base + i*stride` and reading its (direct) branch target.
   Reuse the lifter/segment reader the recovery already holds. Stop at the first
   entry that does not decode to a direct branch to mapped, aligned code (this is
   also the natural table-end signal). Model this as a new `SwitchModel` variant
   (e.g. `SwitchModel::InlineBranchTable { base, stride }`) so the shape is
   explicit and persists — follow the existing `SwitchModel::{Absolute,
   OffsetRelative}` pattern in `fugue-core/src/ir/switch/`.

3. **Guard / bound.** The bound is the `CMP Rn, #N` feeding the predicated `ADD`.
   Two sub-cases:
   - **Predicated `ADDLS`**: the guard condition lives on the branch predicate
     itself. The value-domain guard pullback added this session
     (`find_guard`/`guard_interval` in `slice.rs`, see the
     `switch-guard-pullback-and-cfg-fixes` memory) evaluates ECode condition trees
     to an index interval — extend it to read the predicate that guards the
     computed-PC write, not only a separate `ConditionalBranch`. The flag inputs
     are the same primitive ECode comparisons.
   - **Separate `CMP; Bxx default`**: already handled by the existing
     dominating-guard search once the index matches.

4. **Case targets + context.** For each decoded target, run
   `Arch::canonicalise_address_with` to validate, strip the Thumb bit, and thread
   the `ContextSet` into the `SwitchCase` (Thumb vs ARM). Emit the default from the
   `B default` at `table_base` (the `ADD`-not-taken fall-through).

5. **References + persistence.** Emit the switch through the same path as the x86
   recovery (`SwitchRecovery` post-lifting pass → `add_pending_switch` →
   `commit_pending_function`), so targets become local flow targets and derived
   references, and the downgrade-guard (`switch_would_downgrade`) applies.

### Open questions to resolve first (before coding)

- Dump the lifted ECode-SSA for the branch at `0x3bec0` and confirm the target
  shape (`Add(const_base, index<<2)`) and how the `PC+8` offset appears. Write a
  throwaway test (load `libipmi.so`, build local SSA for `sub_3BE5C` via
  `SwitchRecovery::build_local_ssa`, print `indirect_branch_input` + its ECode
  tree) — remove it before finishing (no committed debug).
- Confirm how the predicated `ADDLS`/`B default` pair appears in ECode (is the
  `ADD PC` a `ConditionalBranch`, or a predicated write followed by an
  unconditional branch?). This determines the guard extraction in step 3.
- Decide the inline-table-end heuristic: first non-branch / first branch to
  unmapped code / bounded by the guard `N`. Prefer bounding by the guard `N` when
  present (exact), falling back to the decode-failure boundary.

## Implementation order

1. Diagnostic dump of `0x3bec0` ECode (throwaway) → lock down shapes.
2. `SwitchModel::InlineBranchTable` + `AddressTable`-adjacent inline reader.
3. Computed-PC recognizer feeding `recover()` (parallel to `scaled_index` +
   `table_layout`).
4. Guard extraction from the predicated computed-PC write.
5. Case decoding + Thumb/context via `canonicalise_address_with`.
6. `LDR PC,[PC,idx,LSL#2]` (data table) and `TBB`/`TBH` as follow-on patterns.

## Validation gates

- **Ground truth**: recovered switch count and per-switch case counts for
  `libipmi.so` must match IDA (`get_switch_info` `ncases`). Spot-check
  `0x3bec0` = 4 cases, and several of the 12 examples logged this session
  (`0x46df4` = 33, `0x53d98` = 8, `0x489c8` = 6, …).
- **Regression**: x86 `ls.elf` switch counts must be unchanged (the 5/7 that match
  IDA today: `0x10612`=5, `0x4f55`=277, `0x6efd`=73, `0x12116`=54, `0x149dd`=123).
- Add a real-binary regression test (`fugue-core/tests/`) that loads `libipmi.so`,
  runs the engine, and asserts a representative recovered switch's case count and
  targets. Follow the `no-handcrafted-binary-fixtures` memory: use the real object,
  derive addresses, imports at top, `tempfile` if a project file is needed.
- `cargo test -p fugue-core` fully green; **no committed `eprintln!`/debug**.

## Style gates (must pass review)

Follow the `rust-style-guidelines` skill exactly. The load-bearing ones here:

- Zero comments; self-explanatory code (project `no-code-comments` memory: no
  comments at all, no `# Safety` on non-public unsafe fns).
- British spelling for types/methods (`analyse`, `canonicalise`, `recognise`).
- Accessors/mutators, not `pub` fields (`structs-not-tuples`,
  `methods-over-free-fns` memories: return named structs not tuples; put helpers as
  methods on the type).
- Import order stdlib / external / crate, one path per `use` group, no nested
  module groups; format with
  `cargo fmt -- --config imports_granularity=Module,group_imports=StdExternalCrate`.
- No `let`-binding type annotations (turbofish or inference); inline `format!`
  captures (`format!("{name}")`).
- `?` over `unwrap`/`expect`; `thiserror` specific error variants; lower-case error
  messages.
- `cargo clippy -p fugue-core --all-targets` clean for touched files.
- Consult project memories: `lazy-not-eager`, `no-materialise-large-regions`
  (decode the inline table entry-by-entry, never materialise a region),
  `zero-copy-subslices`, `import-types`, `no-trivial-helpers`.

## Key files

- `fugue-core/src/analysis/switch/slice.rs` — `recover`, `scaled_index`,
  `table_layout`, `find_guard`/`guard_interval` (semantic tier; add the
  computed-PC recognizer + inline reader + predicated-guard extraction here).
- `fugue-core/src/analysis/switch/analysis.rs` — `SwitchRecovery` post-lifting
  pass, `build_local_ssa`, reconciliation/persistence.
- `fugue-core/src/ir/switch/` — `SwitchModel` (add `InlineBranchTable`),
  `AddressTable`, `SwitchCase`.
- `fugue-core/src/il/ecode/expression.rs` — ECode opcodes the matcher walks.
- `docs/switch-recovery/02-architecture.md` §5–6 — existing ARM/Thumb coverage
  targets and the `canonicalise_address`-as-decoder design.
