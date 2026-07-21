# Prior Approaches: IDA and Ghidra

This document summarizes how the two reference tools recover jump tables, compares
them, and records which ideas we adopt. It is background for the architecture in
[`02-architecture.md`](02-architecture.md).

## IDA: syntactic backward pattern matching

IDA's shared `jumptable.cc` is a backward pattern matcher driven by
processor-specific templates. The idiom that implements a switch is modeled as a
sequence of up to 16 *instruction slots*, numbered from slot 0 (the indirect
branch itself) backward through the data-dependency chain.

Key mechanics:

- **Dependency graph.** A `depends[]` array records, per slot, which earlier
  slots produce the registers it consumes; negative entries mark *optional*
  slots. A `roots[]` array lists the entry points of the dependency chains. The
  matcher matches slot 0 first, then traverses each root with `follow_tree()`.
- **Tolerant backward scan.** `follow_tree()` walks backward from a known slot to
  find the instruction for a dependency, tolerating: interleaved unrelated
  instructions, instruction rescheduling, cross-block fragments glued by
  unconditional branches, delay slots (MIPS/SPARC), and optional instructions
  (with full backtracking if an optional match causes a downstream failure).
- **Register spoiling.** When an intervening instruction overwrites a tracked
  register, that register role is marked "spoiled"; matching then requires the
  value to have been preserved. Spoil state is reset per dependency root and
  saved/restored per subtree.
- **MOV tracing.** Register-to-register moves are absorbed so a value can be
  followed across renames (`is_same()` compares against the moved-to operand).
- **Table types.** The matched pattern returns a type (`JT_FLAT32`,
  `JT_ARM_LDRB`, `JT_ARM_LDRH`, …) that tells the table reader how to decode
  entries: element size, shift, subtract-flag, offset base, and an ARM fixup that
  clears bit 0 (the Thumb bit).
- **Validation.** `check_and_create_flat_jump_table()` reads entries until one is
  undefined, hits a named/cross-referenced location, points outside mapped
  memory, or points into the middle of an instruction; it truncates there.

**Strengths.** Extremely fast; runs during disassembly, so targets are available
immediately. No SSA, no emulation. Handles the messy realities of real code
(reordering, interleaving, block splits, delay slots).

**Weaknesses.** Every idiom is hand-written C++ per processor (a virtual function
per slot). Coverage is only as good as the template set; novel compilers or
optimization levels need new templates. The backward scan is heuristic and can be
defeated by data flow it does not model (e.g. a bound computed through arithmetic
the template does not expect). Table typing is a small fixed enum.

## Ghidra: semantic recovery over SSA/P-code

Ghidra recovers tables in its decompiler, on SSA-form P-code, using a hierarchy of
*models*. The workhorse is `JumpBasic`.

Pipeline (per the reference documents):

1. **Back-slice — `PathMeld`.** From the `BRANCHIND` input, a depth-first backward
   walk (`findDeterminingVarnodes`) collects every data-flow path to a candidate
   switch variable and *melds* them, keeping the varnodes common to all paths (the
   "spine" of the address computation) in execution order.
2. **Guard / bounds analysis.** Walking up to two dominating `CBRANCH`es
   (`analyzeGuards`), each guard's condition is *pulled back* through up to two
   operations to constrain the switch variable. Constraints are expressed as
   `CircleRange`s — half-open intervals over `2^n` with a stride — computed with
   value-set analysis (`rangeutil.cc`, and the VSA reference). The *normalized*
   switch variable is the melded varnode with the *smallest* value range.
3. **Materialize — emulate per index.** For each value in the normalized range,
   `EmulateFunction::emulatePath` executes the melded op sequence (reading table
   bytes from the load image) to produce a concrete target address. Because this
   *re-runs the real arithmetic*, offset tables (`base + tab[i]`), tables of
   offsets, scaled/signed indices, and two-level tables all work with no special
   cases. Each `LOAD` is recorded as a `LoadTable`; contiguous same-size loads are
   collapsed into one table descriptor.
4. **Sanity + truncate.** Entries more than `0xffff` from entry 0 whose bytes are
   unavailable truncate the table to its valid prefix.
5. **Denormalize + labels.** Walk forward from the normalized variable through a
   bounded number of reversible ops (`maxaddsub`/`maxleftright`/`maxext`, each 1)
   to the user-visible switch variable, then reverse-emulate each target's index
   to a case label. Unreversible values (the default) get a `NO_LABEL` sentinel.
6. **Fold-in.** Rewrite the branch to read the switch variable directly (making the
   address computation dead) and disarm the guard CBRANCHes.

Model hierarchy, tried in order: `JumpAssisted` (spec-provided P-code script for
compiler-specific idioms), `JumpBasic`, `JumpBasic2` (a two-path model with a
constant default merged at a phi), `JumpBasicOverride` (user-provided table),
`JumpModelTrivial` (fall back to existing CFG edges).

**Staging and re-flow.** Address recovery happens *during flow analysis*, on a
throwaway *partial clone* of the function pushed through a reduced action pipeline
(the `"jumptable"` strategy) — because the real CFG is not finished yet. Recovered
targets seed new flow (`FlowInfo::generateOps` re-follows them), so case code gets
disassembled. Label recovery and fold-in run later, on the finished function
(`ActionSwitchNorm`). Tables discovered with only one reachable entry can request a
**multi-stage restart** to be retried once more flow is known. The Java analyzer
then re-runs the decompiler to read results and materialize program references,
disassembly, labels, and the table data type — including flowing the ARM `TMode`
(Thumb) context register to each case target.

**Strengths.** Model-agnostic arithmetic via emulation. Handles merged data flow
(diamonds, unrolled loop guards) via path melding. Partial-table + multi-stage
recovery grows tables as flow is discovered. Runs on a cheap partial SSA clone, so
it does not need full type/structure analysis to get addresses.

**Weaknesses.** Leans on guards: if the bound is missing, obfuscated, or not a
simple `CBRANCH` (e.g. an arithmetic clamp or a mask not expressed as `INT_AND`),
the range blows past `max_jumptable_size` and recovery fails or falls back to a
"assume non-negative" heuristic. Riddled with magic numbers (`0xffff` sanity gap,
`0x10000` positive-range threshold, table-size cap, thunk distance, tolerance 10,
early-fail depth 8, denormalization limits of 1). Emulation is fragile: any
branch on the address path, unavailable table memory, or un-injected `CALLOTHER`
aborts it. Mode-bit (Thumb) correctness is deferred to the Java side, which
discards then reconstructs it. Label recovery needs a reversible transform chain.

## Comparison

| Dimension | IDA | Ghidra |
| --- | --- | --- |
| Representation | Disassembly / instructions | SSA-form P-code |
| Detection | Backward idiom template match | Backward data-flow slice (PathMeld) |
| Bounds | Encoded in the template | Value-set analysis over guard CBRANCHes |
| Target materialization | Decode table entries by type | Emulate the sliced computation per index |
| Arch specificity | One template set per processor | Generic; arch quirks fall out of emulation |
| When it runs | During disassembly | During decompilation (partial SSA clone) |
| Cost | Very low | Moderate (partial SSA + emulation) |
| Offset / 2-level / scaled tables | Needs a matching template type | Automatic (emulation) |
| Merged / rescheduled data flow | Tolerated heuristically | Handled structurally (meld) |
| Failure mode | No template ⇒ miss | No guard ⇒ range explosion ⇒ miss |
| Robustness knobs | Template coverage | Magic thresholds |
| Case labels / default | Not the focus | Recovered via reverse emulation |
| Mode bit (Thumb) | ARM fixup clears bit 0 | Discarded, reconstructed on Java side |

## What we adopt, reject, and improve

**Adopt from IDA:**

- A fast first tier that resolves the common idioms without SSA or emulation.
- Backward, dependency-directed matching that tolerates interleaving.
- Table-entry decoding by *element kind* (absolute vs. offset-from-base, element
  size, shift/scale, signedness) and validation-by-walking with truncation.

**Adopt from Ghidra:**

- Semantic back-slice + bound + **emulate-per-index** as the general fallback, so
  offset/scaled/two-level tables need no bespoke handling.
- Bounds from guard conditions via a proper value-range domain.
- Staging: recover *addresses* early (feeding flow discovery), defer *labels and
  typing* to a later pass; support multi-stage completion of partial tables.
- Override and spec-assisted (`.cspec`-driven) models for the hard tail.

**Reject / replace:**

- IDA's per-processor C++ templates ⇒ replace with **declarative idioms over
  architecture-neutral ECode expression trees** (one idiom spans encodings).
- Ghidra's switch-private `CircleRange` and ad-hoc pull-backs ⇒ replace with a
  **reusable strided-interval abstract domain** that other analyses can share.
- Ghidra's binary accept/reject with magic thresholds ⇒ replace with a
  **confidence model**; thresholds become confidence penalties, not hard cutoffs.
- Ghidra's discard-then-reconstruct Thumb handling ⇒ **carry `ContextSet`** on
  case targets and decode/validate the mode bit with `Arch::canonicalise_address`.

**Improve:**

- Make the recovered switch a **first-class `ir` entity** (`ir::Switch`), persisted
  and queryable like `CodeBlock`/`Function`/`Reference` — not a decompiler-internal
  or database-side-table afterthought.
- Attach **provenance** (which tier, what evidence) to every recovered switch and
  case edge, so downstream recovery and the UI can reason about trust.

These decisions are realized in the architecture that follows.
