# Type Correctness and Naming Rework

A review flagged the switch analysis as inconsistent and loosely typed. This
document records the rework that addressed it and the validation that now guards
against regression. It is authoritative where it disagrees with earlier docs.

## 1. Findings addressed

1. **Bare `u64` for addresses and decoded values.** Table addresses, bases,
   entries, and computed targets were plain `u64`, discarding width and address
   typing.
2. **Assumed 8-byte / 64-bit widths.** A hard `element_size > 8` cap, `1u64 <<
   bits` masking, and 64-bit arithmetic assumed pointer/element widths the target
   architecture does not guarantee.
3. **Hard-coded constants.** `MAX_MATCH_DEPTH = 64`, `MAX_DEPTH = 128`,
   `MAX_CASES = 4096`, and `ops.len()*4 + 32` step caps were scattered literals.
4. **Helpers on the wrong type.** `arity`/`is_supported` for an SSA opcode, a
   hand-rolled endian byte-fold, and hand-rolled sign-extend/mask sat inside the
   switch analysis instead of on the IL / `BitVec` / `fugue-bytes`.
5. **Cross-module naming drift.** The same concept had different names in
   different modules (`def` vs `defining_operation`, `find_bound` vs `guard_bound`),
   and two identical result types (`Recovered`, `SemanticSwitch`) coexisted.

## 2. What changed

### Width-correct values (`BitVec`, `RawAddress`, `Address`)

- `fugue-core` now depends on `fugue-bv`. Decoded table entries and every
  intermediate of the address computation are `BitVec`, carrying their bit width.
- `AddressTable::decode_entry(bytes, endian) -> BitVec` uses `BitVec::from_le_bytes`
  / `from_be_bytes` (no hand-rolled fold, no 8-byte cap — `BitVec` handles any
  width) and applies the table `shift` by widening first so no bits are lost.
- Sign/zero extension is `BitVec::signed_cast`/`unsigned_cast`; the bespoke
  `sign_extend_entry` and `mask` helpers are gone.
- `SwitchShapeInfo` carries `table: RawAddress` and `base: Option<RawAddress>`;
  the semantic tier's `TableShape` carries `address: RawAddress`. Widths come from
  `op.width()` / `Varnode::size()` — never assumed.
- Targets are validated and produced as `Address`/`AddressWithContext` by a single
  `TargetValidator` (§ below), which converts the final `BitVec` via `to_u64`,
  canonicalises through `Arch::canonicalise_address` (the authority on the real
  address-space width), and checks the target maps executable memory.

### Configuration (`SwitchConfig`)

All former literals are fields with getters/setters: `max_cases`,
`max_element_size`, `peel_depth` (def-chain peel bound), and `walk_step_limit`
(worklist termination backstop). One `SwitchConfig` threads through the Tier 0
pass, `SyntacticRecovery`, `SemanticRecovery`, and `SwitchEnrichment`.

### Helpers moved onto their owning types

- `ECodeSsaIr` gained `defining_operation(value)` and `value_width(value)`
  (alongside the existing `operation_operands(op)`). The evaluator and the semantic
  matcher both use these — the duplicated private navigation helpers are removed.
- `arity`/`is_supported` were deleted outright: an op already exposes its operands,
  and `compute` already returns `None` for an unsupported opcode.

### Unified result type and shared validation

- One `RecoveredSwitch { model, cases, confidence, evidence }` replaces the
  identical `Recovered`/`SemanticSwitch`. Its `into_switch(id, branch, tier)`
  centralises building the persisted `Switch` (both tiers and the Tier 0 pass used
  to duplicate that).
- `TargetValidator::resolve(&BitVec) -> Option<AddressWithContext>` centralises the
  canonicalise + executable-segment check both tiers previously duplicated.

### Consistent naming

- Recovery entry points: `SyntacticRecovery::recover` and
  `SemanticRecovery::recover` (were `Recovery`/`SemanticRecovery` with different
  shapes).
- Shared concepts share names: `defining_operation` (was `def` in Tier 0),
  `guard_bound` (was `find_bound` in Tier 0), `RecoveredSwitch`, `TargetValidator`.
- Genuinely different operations keep distinct names: `strip_copies` (peel
  copy/extend/truncate) vs `strip_index` (peel scaling to reach the index).

## 3. Naming-consistency validation (part of the gate)

A validation pass now builds a method-name matrix across the switch modules and
fails on shared-concept divergence. The current matrix:

| Concept | Name | Modules |
| --- | --- | --- |
| op defining a value | `defining_operation` | `ECodeSsaIr`, syntactic |
| operands of an op | `operation_operands` | `ECodeSsaIr` (both tiers) |
| value width | `value_width` | `ECodeSsaIr` |
| recovery entry | `recover` | `SyntacticRecovery`, `SemanticRecovery` |
| result | `RecoveredSwitch` | both tiers |
| target validation | `TargetValidator::resolve` | both tiers |
| guard bound | `guard_bound` | both tiers |
| confidence/evidence builders | `confidence`/`evidence` | both tiers |

Distinct-by-design (not divergence): `strip_copies` vs `strip_index`;
`SyntacticRecovery` works on `PCodeOp`, `SemanticRecovery` on `ECodeSsaIr`.

## 4. Verification

Library and all tests build clean; `cargo +nightly fmt` and clippy are clean on the
changed files (the one clippy note is the pre-existing `ECodeSsaIr::new`
arg-count). The full suite passes — 269 lib unit tests plus the switch/value/engine
integration suites — with no regression from the widened `ChangeKinds`, the new
`ECodeSsaIr` accessors, or the `fugue-bv` dependency.
