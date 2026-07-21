# Switch-Case / Jump-Table Recovery

Design and implementation plan for recovering the targets of computed (indirect)
branches that implement `switch` statements, and for wiring the recovered targets
back into Fugue's control-flow graph, references, and storage.

## Documents

1. [`01-approaches.md`](01-approaches.md) — how IDA and Ghidra each recover jump
   tables, a side-by-side comparison, and which ideas from each we adopt, reject,
   or improve on.
2. [`02-architecture.md`](02-architecture.md) — the architecture we build inside
   Fugue: staging, the two-tier recovery pipeline, the data model, the value
   analysis, and every integration point against the current code.
3. [`03-implementation-plan.md`](03-implementation-plan.md) — the phased plan:
   milestones, concrete modules and types, the test strategy, and a
   `/rust-style-guidelines` gate enforced at every phase boundary.
4. [`04-refinement.md`](04-refinement.md) — review of the implemented vertical
   slice: what is built and tested, the review fixes applied, known limitations,
   and the deferred plan work with rationale. Read this for the current state of
   the code; where it and the design docs disagree, it is authoritative.
5. [`05-query-integration.md`](05-query-integration.md) — making the recovered
   `Switch` a first-class citizen of the query layer (`QueryReader`): a
   `SwitchRecord` read surface, cursor pagination, and change tracking
   (`ChangeKinds::SWITCHES`), mirroring how symbols and references are wired.
6. [`06-type-and-naming-rework.md`](06-type-and-naming-rework.md) — the first type-
   correctness and naming rework. **Superseded by `07` where names disagree** (this
   round renamed the types again: `SwitchRecoveryConfig`, `SwitchTargetResolver`,
   `SwitchIdiomMatcher`, `SwitchEmulator`, `TableLayout`, `SwitchAnalyser`).
7. [`07-worklog.md`](07-worklog.md) — **the authoritative current state.** The
   second rework driven by a 21-comment review, the value-domain integration (the
   `BitVec`-native `StridedInterval` now actually bounds the index), and a
   framework-wide **ECode lowering-correctness fix**: the P-code→ECode transform was
   collapsing distinct P-code opcodes (all comparisons → `Compare`,
   `INT_AND/OR/XOR` → `Bool`, float arithmetic → integer) into a handful of lossy
   ECode opcodes. Every distinct-semantics op now gets a distinct opcode, so masked
   and bitwise address computations are recoverable. Read this for what is built,
   validated, and deferred.

## Executive summary

Two mature approaches exist, at opposite ends of a spectrum:

- **IDA** matches architecture-specific instruction *idioms* by walking backward
  from the indirect branch. It is fast and runs during disassembly, but each
  idiom is hand-written per processor and it degrades on rescheduled or merged
  data flow.
- **Ghidra** recovers tables *semantically* on SSA/P-code: it back-slices the
  branch input to a normalized index variable, bounds that index with value-set
  analysis over guard conditions, and then *emulates the sliced computation once
  per index* to materialize concrete targets. It is general (offset tables,
  two-level tables, scaling, signedness all fall out of emulation) but pays the
  cost of partial SSA construction and leans on brittle magic-number heuristics.

Fugue is already shaped for this feature — `FlowKind::SwitchBranch`,
`AddressAnnotationValue::KnownTargets`, `CodeBlockProperties::UNRESOLVED`, and a
recursive-descent recovery loop that re-drives to a fixpoint on newly discovered
targets all exist — but nothing produces or consumes them yet, and there is no
value-analysis layer.

**Our design combines both approaches in a single two-tier pipeline and improves
on each:**

- **Tier 0 (syntactic)** matches declarative idioms over Fugue's *architecture-
  neutral* ECode expression trees. Because SLEIGH already lifts each processor's
  instructions to uniform P-code, one idiom matches several encodings — so we get
  IDA's speed without IDA's per-processor duplication.
- **Tier 1 (semantic)** is the Ghidra path — back-slice, bound, emulate — but
  built on a clean, reusable **strided-interval value domain** (the VSA building
  block Fugue lacks) rather than switch-private range math.
- Results carry **confidence and provenance**, so brittle accept/reject cutoffs
  become graceful degradation.
- Recovered switches become a **first-class `ir` entity** (`ir::Switch`, alongside
  `CodeBlock`/`Function`/`Reference`), persisted and queryable like any other
  project artifact — something neither reference tool offers.
- Case targets carry **`ContextSet`** (e.g. ARM/Thumb mode) from the point of
  recovery, using `Arch::canonicalise_address` to both validate a target and
  decode its mode bit — instead of Ghidra's discard-then-reconstruct.

The recovery runs in two stages that mirror Ghidra's split across two heritage
passes, mapped onto Fugue's existing recovery loop:

- **Stage A — address recovery**, as a post-lifting pass inside function
  recovery, before the function is committed. It produces the target addresses
  and feeds them back into the loop as `SwitchBranch` edges so case code gets
  lifted. This is the load-bearing stage.
- **Stage B — enrichment**, as a `DERIVED` engine analyser after commit, when
  full project ECode-SSA is available. It recovers case labels and the default
  case, types the table data, emits persistent references, and stores the
  `ir::Switch` entity.

See [`02-architecture.md`](02-architecture.md) for the full design.
