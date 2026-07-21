# Query-Layer Integration

The recovered `Switch` is a durable `ir` entity persisted in `Project::switches`,
but until now it had no presence in the **query layer** — the cached, paginated,
change-tracked read API (`QueryReader`) that consumers and UIs use. Switch case
edges were reachable only indirectly, as references (`references_from(branch)`).
This document specifies making `Switch` a first-class query citizen, mirroring how
symbols and references are already wired.

## 1. What the query layer provides (and how entities plug in)

`QueryReader` (`queries/mod.rs`) is the read façade over an `Arc<RwLock<Project>>`.
Every entity is exposed through the same three mechanisms:

- **Read surface.** `QueryReader::foo(...)` methods delegate to
  `ProjectRead::foo(...)` (`queries/read.rs`) under a query guard, returning either
  a `QueryPage<Record>` (cursor-paginated) or an `Arc<...>`. Streaming iterators are
  built with `Paged::new(...)` over the page method. Records are lightweight
  projections (`SymbolRecord`, `MappingRecord`, `CallEdge`) with an address key used
  as the pagination cursor.
- **Change tracking.** Transaction mutators push a `ChangeRecord`
  (`engine/change.rs`); each record maps to a `ChangeKinds` bit (`kind()`) and a set
  of `AddressRange`s (`ranges()`). The `ChangeIndex` (`queries/index.rs`) buckets
  those by `RegionGroupKind` so `QueryReader::latest_change`/`changed_since` answer
  "did any switch in this region change since revision R?" and the derived-query
  cache can invalidate precisely.
- **Pagination support.** The backing table exposes an address-ordered,
  cursor-resumable iterator (e.g. `FunctionTable::addresses_in_space_after`).

Switches currently plug into **none** of these.

## 2. Design

### 2.1 `SwitchRecord` (read projection)

A lightweight, `Clone`-able projection keyed by the branch address, mirroring
`SymbolRecord`:

```rust
pub struct SwitchRecord {
    branch: Address,
    switch: Switch,   // the full entity; Switch is Clone + self-contained
}
```

Accessors: `branch()`, `switch()`, plus conveniences `case_count()`, `tier()`,
`confidence()`, `has_default()`. Ordering and equality are **by branch address
only** (the unique key), so it is a valid pagination cursor — implemented by hand
because `Switch` itself is not `Ord`.

### 2.2 Read surface

- `ProjectRead::switch_at(branch) -> Option<SwitchRecord>` — direct lookup via
  `project.switches().get_by_branch`.
- `ProjectRead::switch_page(after, limit) -> QueryPage<SwitchRecord>` — iterate
  branches in address order from the cursor, project each, page with
  `Self::page(...)`.
- `QueryReader::switch_at` / `switch_page` — delegate via `with_project`, exactly
  like `symbol_page` / `symbols_at`.
- `QueryReader::switches() -> impl Iterator<Item = Result<SwitchRecord, _>>` —
  streaming walk via `Paged::new` over `switch_page` at `WALK_PAGE_LEN`.

### 2.3 Pagination support

`SwitchTable::branches_after(after: Option<Address>) -> impl Iterator<Item =
Address>` — a `BTreeMap::range` over the branch index on both the persistent and
transient variants (the index is already `BTreeMap<Address, SwitchId>`), so paging
resumes in `O(log n)` rather than rescanning from the start.

### 2.4 Change tracking

- **`ChangeKinds`** (`engine/change.rs`, a `u16` bitflags): add
  `SWITCH_ADDED = 0x4000`, `SWITCH_REMOVED = 0x8000`, and the group
  `SWITCHES = SWITCH_ADDED | SWITCH_REMOVED`.
- **`ChangeRecord`**: add `SwitchAdded { branch }` and `SwitchRemoved { branch }`.
  `kind()` maps them to the flags; `ranges()` returns `AddressRange::point(branch)`;
  they are excluded from `affects_lifted_inputs()` (a switch does not change the
  lifted-input surface). `SwitchAdded` covers both first insert and `modify_switch`
  (default/label fill), matching the symbol model's add/remove granularity.
- **Emission**: `ProjectTransaction::insert_switch` and `modify_switch` push
  `ChangeRecord::SwitchAdded { branch }`; a new `remove_switch` pushes
  `SwitchRemoved`. This mirrors `add_reference`/`insert_symbol`.
- **`RegionGroupKind::Switches`** (`queries/index.rs`) with
  `mask() == ChangeKinds::SWITCHES`, so switch changes are region-indexed for
  `latest_change`/`changed_since`.

### 2.5 The reference duality (intentional, retained)

Case edges remain queryable two ways, which is a feature, not redundancy:

- as **switch records** — `switch_at(branch)` returns the model, cases, labels,
  default, and provenance as one structured object; and
- as **references** — `references_from(branch)` returns the individual
  `JUMP | COMPUTED` edges, so generic xref/graph consumers that know nothing about
  switches still traverse them.

## 3. Files touched

| File | Change |
| --- | --- |
| `engine/change.rs` | `ChangeKinds::SWITCH_*` + `SWITCHES`; `ChangeRecord::Switch{Added,Removed}` + `kind`/`ranges`/`affects_lifted_inputs` |
| `queries/index.rs` | `RegionGroupKind::Switches` + mask mapping |
| `project.rs` | emit change records from `insert_switch`/`modify_switch`; add `remove_switch` |
| `ir/switch/table/*` | `branches_after` range iterator (enum + persistent + transient) |
| `queries/mod.rs` | `SwitchRecord`; `QueryReader::switch_at`/`switch_page`/`switches` |
| `queries/read.rs` | `ProjectRead::switch_at`/`switch_page` |

## 4. Test

A self-contained `tests/switch_query.rs`: build a transient project, insert a
couple of switches through a transaction, and assert `switch_at` returns the right
record, `switches()` walks them in branch order, and `changed_since(rev,
SWITCHES, region)` observes the insertion.
