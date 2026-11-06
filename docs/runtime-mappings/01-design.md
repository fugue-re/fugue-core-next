# Runtime address spaces and synthetic mappings

Status: implemented. The explicit dependency pass was rolled back and its
contract withdrawn in favour of the project- and engine-owned model in §10.3,
which is now in place; acceptance results are in §14.4.

How to add Ghidra-style memory blocks to a live project, from the engine API and
from analyses. The motivating case is a stack-string analysis that extracts
strings and stores them as bytes the rest of the system can read, reference and
display.

All paths are relative to the repository root. Code sketches show signatures
only; bodies are described in prose.

## 1. Model

| Ghidra                                                | fugue-core                                                        |
| ----------------------------------------------------- | ----------------------------------------------------------------- |
| block storage in the program database                 | one synthetic provider per project, owned by segment storage (§5) |
| `createInitializedBlock(name, start, bytes, overlay)` | `create_synthetic_mapping(start, bytes, properties)` (§7)         |
| overlay space                                         | an `AddressSpaceKind::Overlay { base }` address space             |
| overlay space name                                    | address spaces gain an optional name (§4)                         |

`AddressSpaceKind::Overlay { base }`, `SegmentStorage::overlay_spaces`,
`is_overlay_space` and `base_space` exist
(`fugue-core/src/storage/segments/space.rs`, `mod.rs`).
`SegmentMappingProvenance::Synthetic` already places a mapping at the bottom of a
space, so real bytes take precedence (`mod.rs:1210`, `staging.rs:335`).

Missing at the original HEAD baseline:

1. Overlay spaces can only be created at load time (`from_loadable`); runtime
   `create_space()` always creates an unnamed base space.
2. There is nowhere to put bytes that do not come from the image.
3. Analyses cannot create address spaces or mappings, and an analysis needs real
   addresses for a new block in the same result (to add references).

## 2. Requirements

- Placement is unrestricted: an existing base space at any address, a new base
  space, or a new overlay of any base space.
- Blocks can be created through the engine API and from analyses.
- Mappings stay provider-backed; there is no second way to back a mapping.
- Existing change records are reused, under the consistent names of §3.
- No identifier gaps: an analysis that finds nothing creates nothing, and a
  discarded or failed result leaves no trace.
- No special cases: synthetic mappings follow the same rules as loaded ones.

## 3. Vocabulary

The agreed vocabulary retains existing mapping and storage names. Only
address-space creation adopts the explicit address-space terminology below.

### 3.1 Change kinds and records

| At HEAD                                        | Agreed                                                        |
| ---------------------------------------------- | ------------------------------------------------------------- |
| `SPACE_CREATED` / `ChangeRecord::SpaceCreated` | `ADDRESS_SPACE_CREATED` / `ChangeRecord::AddressSpaceCreated` |

`SEGMENT_MAPPED` and `SEGMENT_UNMAPPED` keep their names. They record a range
becoming mapped or unmapped by a mapping, whichever operation caused it: adding
the mapping to a space, prioritising, deprioritising, remapping, resizing or
removing it. `SEGMENT_MAPPING_CREATED` and `SEGMENT_MAPPING_CHANGED` record
changes to the mapping itself.

### 3.2 Types

`SpaceCreationResult` becomes `AddressSpaceCreationResult`. The other names below
are retained, including the Python class name.

| Visibility | Agreed name                  | Where                          |
| ---------- | ---------------------------- | ------------------------------ |
| public     | `MappingCreationResult`      | `engine/update.rs`             |
| public     | `MappingMetadataUpdate`      | `engine/update.rs`             |
| public     | `AddressSpaceCreationResult` | `engine/update.rs`             |
| public     | `MappingEntity`              | `queries/entities.rs`          |
| private    | `MappingPlacementMode`       | `engine/update.rs`             |
| private    | `MappingPlacement`           | `engine/update.rs`             |
| private    | `MappingPriorityUpdate`      | `engine/update.rs`             |
| private    | `MappingRemap`               | `engine/update.rs`             |
| private    | `MappingRemoval`             | `engine/update.rs`             |
| private    | `MappingResize`              | `engine/update.rs`             |
| crate      | `MappingHint`                | `fugue-python/src/segments.rs` |

Outside the family, and unchanged: `BytesOrMapping` and `FileMapping` (operating
system file mappings), the `Image*` types (the loader's own layer), and the
`StorageProvider` types (project storage).

### 3.3 Implementation scope

Keep name and overlay-base validation in the operations that require it.
`SegmentStorage::synthetic_provider` returns the existing provider descriptor.
Backing placement belongs to mapping preparation, not provider lookup; staging
does not inspect storage fields.

In the memory-mapped provider, keep construction, growth and extent traversal
within their owning operations rather than adding `map`, `grow`, `append` or
`overlapping_extents` helpers. Shared backing lifecycle and checked offset
translation remain cohesive operations; no replacement wrapper layer is needed.

## 4. Address spaces

### 4.1 Names

`AddressSpace` gains an optional name, unique within a project, persisted in
`AddressSpaceMetadata`. Names are `String`, as mapping names are. Spaces created
at load time have none.

```rust
impl AddressSpace {
    pub fn name(&self) -> Option<&str>;
}

impl SegmentStorage {
    pub fn address_space_by_name(&self, name: impl AsRef<str>) -> Option<&AddressSpace>;
}
```

The lookup is `address_space_by_name` because `Language::space_by_name`
(`fugue-lifter-runtime`) already names SLEIGH spaces.

### 4.2 Creation

The same pair on every layer, following `AddressSpace::new(id)` /
`AddressSpace::new_with(id, kind)`. `create_space()` is unchanged.

```rust
impl SegmentStorage {
    pub fn create_space(&mut self) -> Result<AddressSpaceId, SegmentStorageError>;
    pub fn create_space_with(
        &mut self,
        name: impl Into<String>,
        kind: AddressSpaceKind,
    ) -> Result<AddressSpaceId, SegmentStorageError>;
}

impl ProjectTransaction<'_> {
    pub fn create_space(&mut self) -> Result<AddressSpaceId, ProjectError>;
    pub fn create_space_with(
        &mut self,
        name: impl Into<String>,
        kind: AddressSpaceKind,
    ) -> Result<AddressSpaceId, ProjectError>;
}

impl AnalysisEngine {
    pub fn create_space(&self) -> Result<AddressSpaceCreationResult, EngineError>;
    pub fn create_space_with(
        &self,
        name: impl Into<String>,
        kind: AddressSpaceKind,
    ) -> Result<AddressSpaceCreationResult, EngineError>;
}
```

Validation, on every layer: an overlay's base must exist and be a base space, and
the name must not already be in use (`SegmentStorageError::DuplicateAddressSpaceName`).

Staging records the name and kind of each space it creates
(`created_spaces: BTreeMap<AddressSpaceId, StagedAddressSpace>`). The engine adds
`Intake::CreateSpaceWith { name, kind, reply }` alongside `Intake::CreateSpace`.

## 5. The synthetic provider

### 5.1 Ownership

```rust
pub struct SegmentStorage {
    synthetic_provider: Option<SegmentStorageProviderId>,
}
```

- `None` until the first synthetic mapping is created, so a project that never
  makes one gets no provider and no file.
- Opened with the storage's default provider type: the type the storage was
  created with (`S::STABLE_TAG` in `from_loadable::<S>`), recorded privately and
  persisted in `SegmentStorageMetadata` with the provider identifier. Transient
  projects therefore get `InMemorySegmentStorage` and persistent projects the
  memory-mapped provider. The default provider type is not exposed.
- Constructed with the existing factory, `S::from_segment_range(id, range, attributes)`
  through the provider registry, after its identifier is allocated: the persistent
  provider places its file at `id.path_in(project_root)` (`provider/mod.rs:51`).
- The crate-private `synthetic_provider()` accessor returns
  `Option<&SegmentStorageDescriptor>`: `None` until the provider exists. It neither
  chooses a future identifier nor exposes an append offset.

### 5.2 Appending

- The next free offset is the furthest end of any mapping on the synthetic
  provider, derived from the mappings themselves; nothing extra is persisted.
- `SegmentStorage` prepares the backing placement in a `SegmentMappingBuilder`
  without opening or growing the provider. Direct creation and the first
  synthetic mapping in a transaction use this operation. Subsequent mappings use
  the transaction's private append cursor, accounting for created and resized
  staged mappings on the provider. No allocation state leaves the
  mapping-creation boundary.
- Within a transaction, staged synthetic mappings take offsets in order after
  that point. The provider is opened, grown and written when the transaction's
  segment changes are published, so a rejected transaction opens nothing, creates
  no file and writes nothing.
- Writes use the transaction's effective provider capacity: the larger of the
  committed size and any matching staged size. Existing permission and bounds
  checks are unchanged. This is segment-staging behaviour, not a separate
  analysis-engine lifecycle for synthetic mappings.
- An unrepresentable backing end or append range returns the existing invalid
  range error before opening, growing or writing backing storage. Ordinary
  mapping creation and resize rules are unchanged.
- Publication cannot fail, and a failure to open, grow or write the backing is
  fatal, as backing failures already are: a failed write through a memory mapping
  surfaces as `SIGBUS`. Recovery from such a failure is to rebuild the project
  from its source binary.
- Removing a synthetic mapping leaves its bytes in place. Reclaiming them is not
  part of this work.

### 5.3 Growth

Appending grows the provider's logical size with `resize`.

- `InMemorySegmentStorage` already implements `resize` by changing its logical
  size (`provider/memory.rs:200`).
- `MemoryMappedSegmentStorage` does not; it uses the trait default, which returns
  "resize not supported" (`provider/mod.rs:339`). After the rework of §6 its
  logical size is independent of its file, so `resize` only changes a number.

### 5.4 Reload

The provider is reopened through the registry like any other provider, and
`synthetic_provider` is restored from the metadata.

## 6. The memory-mapped provider

### 6.1 Problem

The ELF loader creates one default bank spanning the lowest to the highest loaded
address (`loader/elf/mod.rs:296-307`); only overlapping regions get banks of their
own. `MemoryMappedSegmentStorage` keeps a bank as one flat file as long as its
logical span, mapped in full: `with_size` extends the file with `set_len(size)`,
and loading re-extends it with `set_len(logical_size)` before moving the packed
extents back (`provider/memmap.rs`). A binary with very low and very high
addresses therefore needs a file and a mapping as large as the distance between
them, which fails beyond what the filesystem or the address space allows. The
same flat layout makes `resize`, which the synthetic provider needs, cost a
remap of the whole span.

`InMemorySegmentStorage` does not have this problem: its logical size is a
number, and its memory follows the bytes written.

### 6.2 Layout during a session

The file holds written extents back to back, as the on-disk format already does,
and the provider keeps an index from logical offset to file offset. The provider
is self-contained: the index and its logic live in `provider/memmap.rs` and share
no code with other providers.

```rust
pub struct MemoryMappedSegmentStorage<const PERSISTENCE: StoragePersistence> {
    backing: MmapMut,
    extents: BTreeMap<u64, MappedExtent>,
    file_end: u64,
    size: u64,
    project: PathBuf,
}

struct MappedExtent {
    size: u64,
    file_offset: u64,
}
```

`extents` is keyed by logical start. `file_end` is the end of the used part of
the file; the mapping may be longer. `size` is the logical size. `written` is
replaced by `extents`.

### 6.3 Reads and views

- `read_bytes` copies from each extent the range overlaps; holes read as zeros.
- `view_bytes` pushes one piece per overlapping extent, borrowed from the mapping;
  holes are left out, as now.
- `view_bytes_from` borrows from the offset to the end of the extent containing
  it, as now.

### 6.4 Writes

The provider merges writes exactly as `InMemorySegmentStorage` does: only writes
that touch or overlap are joined, gaps are never stored, and unwritten ranges are
reported as such, so the storage layer reads them as its fill byte.

- A write inside an extent is done in place.
- A write that touches or overlaps the end of the extent ending at `file_end`
  extends that extent in place.
- Any other write outside an extent becomes its own extent at `file_end`.
- Existing data is never moved during a session.
- The file grows by doubling and is mapped again. Growing takes `&mut`, so no
  view can be outstanding.

Loading writes each region's chunks in ascending order without overlap
(`ImageSegmentContents::into_writes`, `loader/image.rs:910-935`), so each region
becomes one contiguous extent, and synthetic blocks are appended whole. Only a
later write that touches an extent other than the last one in the file produces a
separate extent beside it, and a view across the two comes back in pieces until
the next save merges them.

### 6.5 Logical size

`size()` returns the logical size. `resize(new_size)` sets it; shrinking drops or
cuts the extents beyond the new size.

### 6.6 Saving and loading

- **Drop (persistent).** Compact the live extents to the start of the file in
  ascending logical order, merging extents that touch, truncate the file, and write
  `PackMetadata { logical_size, extents }`. The on-disk format is unchanged.
- **Load.** Map the file, read the metadata and rebuild the index, each extent's
  file offset being the running total of the sizes before it. Nothing is moved
  and the file is not extended to the logical size. The metadata stays until the
  next drop rewrites it.
- **Crash.** A persistent project is unpacked from its archive (`.fdbz`) to
  `.fdb` when it is opened, and archived again when it is closed. After a crash
  the leftover `.fdb` stops the project from opening; once it is removed, the
  project opens from its last archive. Nothing inside a provider has to survive a
  crash.
- **Transient.** The same layout; the file is deleted on drop.
- `from_segment_range`, when the file already exists, compares logical sizes.

`docs/packed-memmap-format.md` (in the main checkout) describes the current flat
layout during a session and is updated to match.

## 7. Synthetic mappings

One operation creates the mapping and places it, as Ghidra's
`createInitializedBlock` does. Argument order follows `write_bytes` (address, then
bytes) with properties last, as in `create_mapping`. Bytes are borrowed where they
are copied immediately and shared where they are held, as `write_bytes` already
does on each layer.

```rust
impl SegmentStorage {
    pub fn create_synthetic_mapping(
        &mut self,
        start: impl Into<Address>,
        bytes: &[u8],
        properties: SegmentProperties,
    ) -> Result<SegmentMappingId, SegmentStorageError>;
}

impl ProjectTransaction<'_> {
    pub fn create_synthetic_mapping(
        &mut self,
        start: impl Into<Address>,
        bytes: &[u8],
        properties: SegmentProperties,
    ) -> Result<SegmentMappingId, ProjectError>;
}

impl AnalysisEngine {
    pub fn create_synthetic_mapping(
        &self,
        start: impl Into<Address>,
        bytes: impl Into<Arc<[u8]>>,
        properties: SegmentProperties,
    ) -> Result<MappingCreationResult, EngineError>;
}

impl ProjectUpdates {
    pub fn create_synthetic_mapping(
        &mut self,
        start: impl Into<Address>,
        bytes: impl Into<Arc<[u8]>>,
        properties: SegmentProperties,
    );
}
```

It opens the synthetic provider if needed, appends the bytes, creates a mapping
over them with `Synthetic` provenance and the given properties, and adds it to the
space of `start`. The space must exist (or be created earlier in the same
transaction or result), `bytes` must not be empty, and the block must fit in the
space. Otherwise it fails like any other update; in a result, that rejects the
whole result.

Change records: `SegmentMappingCreated { mapping }`, then
`SegmentMapped { mapping, range }`. Opening the provider records nothing;
providers are only visible through mappings.

`create_mapping(builder)` and the other mapping operations are unchanged.
`Intake::CreateSyntheticMapping` is added for the engine.

## 8. Analyses

### 8.1 Finding or reserving an address space

An analysis looks its space up on the snapshot and, if it is not there, reserves
it. The reservation returns a real identifier immediately, without committing
anything.

```rust
impl AnalysisContext<'_, '_> {
    pub fn reserve_space(
        &mut self,
        name: impl Into<String>,
        kind: AddressSpaceKind,
    ) -> Result<AddressSpaceId, AnalysisError>;
}
```

- It is an error if the snapshot already has a space with that name; the analysis
  uses `address_space_by_name` for that case.
- The reservation is held in the result itself: it records the creation of the
  space in `self.updates` (`ProjectUpdates::reserve_space`), ahead of anything
  that uses it. Updates are applied in order, so the space exists by the time a
  synthetic mapping is added to it.
- The identifier is the snapshot's `pending_space_id(n)`, where `n` is the number
  of spaces the result has already reserved: the same numbering staging uses for
  the spaces a transaction creates. Reserving a name the result has already
  reserved returns the same identifier; a different kind is an error.
- Spaces reserved by analyses are always named, so a re-run finds them.
- A successful result containing only reservations publishes nothing: no spaces,
  address-space creation records or consumed identifiers.
- A result containing any non-reservation update applies all its reservations
  and updates atomically. Individual unused reservations are not pruned.

### 8.2 Updates

The analysis creates blocks with `ProjectUpdates::create_synthetic_mapping` (§7),
so it never needs a provider or mapping identifier. The reserved space is created
by a crate-private operation named after the transaction method it calls:

```rust
enum ProjectOperation {
    CreateSpace(ReservedAddressSpace),
    CreateSyntheticMapping(SyntheticSegmentMapping),
}
```

`CreateSpace` creates the space with its reserved identifier through the
crate-private `ProjectTransaction::create_space_with_id`, which staging validates
like any other space creation.

An analysis keeps no identifiers between runs: it looks its space up on each run,
and checks `contains_mapping(start)` on the snapshot before creating a block, as a
Ghidra analyser checks for an existing block. A reserved identifier is only valid
in the result that reserved it; if that result is discarded, the identifier goes
to the next space created.

### 8.3 Example: stack strings

```rust
let name = "stack-strings";
let space = match context.project.segments().address_space_by_name(name) {
    Some(space) => space.id(),
    None => context.reserve_space(name, AddressSpaceKind::Overlay { base: site.space() })?,
};
let start = Address::new(space, site.offset());

if !context.project.segments().contains_mapping(start) {
    context
        .updates
        .create_synthetic_mapping(start, bytes, SegmentProperties::PERM_READ);
    context.updates.add_reference(reference);
}
```

`site` is the instruction that builds the string, in a base space, and
`reference` runs from `site` to `start`. Placing each block at the site's address
in the overlay keeps the link to the code visible and gives the same addresses on
every run. Blocks do not collide while each string is no longer than the code
that builds it, as for strings built from immediates; an analysis that can produce
longer strings, or that scans overlay spaces, needs its own placement.

The analyser declares that it produces `SEGMENTS`, `ADDRESS_SPACE_CREATED` and
`REFERENCES`, so its own blocks do not re-run it (§10.2).

## 9. Reservations

A reservation is part of the result that holds it; there is no other reservation
state, and segment storage knows nothing about reservations.

- **Validity.** Execution and admission are currently serial, but correctness
  must rest on admission-time validation, not that scheduling assumption.
  Reservations are tentative until their whole result commits. With concurrent
  workers, two snapshots may select the same free identifier; one result can
  commit and the conflicting result must be recomputed from a current snapshot.
  Do not silently renumber addresses already embedded in references or other
  updates.
- **Release.** Discarded and failed results take their reservations with them.
  Successful reservation-only results are also no-ops. None creates a space or
  leaves an identifier gap. This is handled when applying the updates, without
  adding reservation state or changing the analysis-engine lifecycle.
- **Shared names.** Serial execution currently lets a later analysis see a
  committed space by name. Concurrent results may both observe an absent name.
  Admission must resolve that race atomically; the losing analysis retries its
  lookup against committed state. Speculative creation must not publish an empty
  space or leave an identifier gap.

## 10. Change records and re-runs

### 10.1 Records

| Operation                  | Record                                                                       | Kind                                        |
| -------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------- |
| create an address space    | `AddressSpaceCreated { space }`                                              | `ADDRESS_SPACE_CREATED`                     |
| create a synthetic mapping | `SegmentMappingCreated { mapping }`, then `SegmentMapped { mapping, range }` | `SEGMENT_MAPPING_CREATED`, `SEGMENT_MAPPED` |
| reference to a block       | `ReferenceAdded { … }`                                                       | `REFERENCE_ADDED`                           |

Analysers triggered by `SEGMENT_MAPPED` see new blocks as they see loaded
segments. Function recovery ignores non-executable mappings, so a read-only block
is never disassembled.

### 10.2 Why segment changes re-ran everything

The engine re-runs an analysis over a region when a change matches what it read
there (`engine/view.rs:96-131`, `engine/worker.rs:661-710`). Two mechanics
combined to produce the 13× result in §14.3:

1. `ProjectView::segments()` records an unbounded `SEGMENTS |
ADDRESS_SPACE_CREATED` read (`engine/view.rs:439-442`). Every analyser calls
   it, so `route_dependencies(SEGMENT_MAPPED, range)` matched every recorded
   region of every analyser.
2. `SegmentMappingCreated` and `AddressSpaceCreated` carry no ranges
   (`project/change.rs:380-384`), so they matched every bounded observer of
   their kind too (`project/read.rs:74`, `engine/view.rs:111`), including
   `read_bytes`, which recorded `BYTES_WRITTEN | SEGMENTS`.

The unbounded recording itself is needed: query terms rely on it, through
`Dependency::covers`, to be rejected when they read segments without declaring
`SEGMENTS` (`queries/term.rs:89`). The correction is in how the engine matches
change records against analysis reads, not in what the view records.

An earlier attempt replaced inference with analyser-published dependency sets.
It was rolled back: a complete declared set forced every analyser to re-record
its reads by hand, and retained-state validity forced revision bookkeeping into
function recovery. That contract is withdrawn. Ghidra, IDA and Binary Ninja
track no reads at all; each retires the facts located at a changed range and
re-queues producers over that range (Ghidra `AutoAnalysisManager`
subscriptions, IDA.md §"Reanalysis and invalidation", BINJA.md §"Cache
invalidation"). The model below is that one, with cross-address inputs made
explicit as located entities.

### 10.3 Model

Invalidation is owned by the project and the engine. Analysers neither record
reads nor declare dependencies; `Analyser::analyse`, `AnalysisContext`,
`ProjectUpdates` and storage APIs are unchanged.

**Location rule (transaction).** An automatic entity is retired when a change
intersects its location. Location is what the entity already stores:

| Entity    | Location                                         |
| --------- | ------------------------------------------------ |
| function  | block coverage                                   |
| switch    | branch and data tables (`Switch::coverage_into`) |
| problem   | scope                                            |
| reference | source and target                                |

Functions and problems already follow this rule
(`transaction/segment.rs:285`, `transaction/mod.rs:485`). Switches now do:
`SwitchTable::overlaps(range)` and the staged form
`SwitchTable::staged_overlaps(staging, range)` mirror the block and function
tables, and `invalidate_functions_in_range` retires the functions owning any
overlapping switch. Retirement is eager, per operation, not a commit-time sweep,
so a result staged later in the same transaction from the new inputs survives.

An input outside an entity's own range that no entity stores is declared
explicitly. `ProjectView::add_dependency(kinds, range)` records a read without
performing one; it is `read_bytes` without the bytes. Recovery declares the
pointer slot it reads to resolve an indirect branch or call target
(`function/recovery/builder.rs`, `thunk/mod.rs`) with `BYTES_WRITTEN` after its
cached read. A write to the slot then reaches recovery as a `Dependency` cause
over the batch regions (§10.4). Switch tables are already stored on the switch
and follow the location rule.

**Retraction (engine).** `BytesWritten`, `SegmentUnmapped`, `SegmentMapped` and
`SegmentMappingChanged` are retracting records (`retracts(record)` in
`engine/worker.rs`, today `invalidates_bytes` over the first two). Their ranges
cancel queued work in `PHASES_CANCELLED_BY_RETRACTION` (today
`RETRACTED_BY_BYTE_CHANGE`), retract persisted coverage, and are passed to
`Analyser::retract(&mut self, regions: &AddressRangeSet)`, a new hook with a
no-op default. Function recovery drops pending functions and its hint and
coverage snapshots intersecting the regions. The hook is also called with the
batch regions when a result is rejected at admission. Direct `triggers()` then
re-run the affected analysers over the retracted ranges, as they do now.

**Inferred reads (engine).** `ProjectView` keeps recording reads into
`DependencyIndex` as today, with two changes:

- `TRACKED_DEPENDENCY_KINDS = ChangeKinds::all() − (SEGMENTS |
ADDRESS_SPACE_CREATED)`, defined once in `engine/mod.rs`. `route_changes`
  excludes other kinds from dependency routing and `ReadSet::conflicts_with`
  takes the same set for admission, so routing and admission share one
  matching rule. An unbounded `SEGMENTS` read is recorded but never matched;
  rangeless records are inert.
- `read_bytes` records `BYTES_WRITTEN` only.

Byte writes therefore still reschedule bounded byte readers and still conflict
at admission. Mapping and space changes act only through the location rule,
retraction and direct triggers. An analyser interested in those kinds declares
them in `triggers()`; `route_direct` already dispatches rangeless records as
global work (`engine/worker.rs:632-644,719-727`), and `produces()` keeps
an analyser from re-triggering on its own spaces and mappings.

### 10.4 Where each input lives

| Input to a result                                                   | Owner                                                                                    |
| ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Instruction bytes and their mapping interpretation                  | function coverage; location rule and retraction                                          |
| Failed decode or missing bytes                                      | problem scope; `ChangeKinds::for_problem`                                                |
| Jump table bytes                                                    | switch data tables; location rule                                                        |
| Pointer slot of a resolved indirect target                          | explicit `add_dependency(BYTES_WRITTEN, slot)`; `Dependency` cause re-recovers the reader |
| Hints at a function's addresses                                     | immutable per mapping; a mapping change there is a placement record over the coverage    |
| Executable property of a call target outside the function           | discovery; `SEGMENT_MAPPED` direct trigger over the new placement                        |
| Discovery coverage (`spaces()`, `iter_views()`, `function_hints()`) | direct triggers; never a result dependency                                               |
| Names, address-space existence                                      | `triggers()` on `ADDRESS_SPACE_CREATED`; name races resolved by admission rejection (§9) |

Recovery coverage keeps its current semantics and storage vocabulary; linear
sweep still scans call targets only when boundary scanning across all coverage
spaces finds no candidates. Nothing forces an analyser to read through
`ProjectView::read_bytes`; the mapping cache and `bytes_from()` remain the
read path, and `bytes_from()` beyond a visible submapping needs no declaration
because the function's location, not its reads, governs retirement.

Recovery acts on `Dependency` causes of kind `BYTES_WRITTEN` only; symbols and
functions reach it through `triggers()`, and reacting to every kind re-recovered
batches on symbol edits. Attribution is batch-wide: a production's read set is
recorded against every region of its batch, so a write to a declared slot
re-recovers each function of that batch whose coverage contains a cause range.
In the `ls.elf` probe one slot write re-recovered 297 of 400 functions. Precise
attribution would need per-function read sets inside recovery and was not
taken.

### 10.5 Change records

One `ChangeSet`/`ChangeRecord` mechanism, existing kinds and payloads. The
placement meaning of `SegmentMapped` and `SegmentUnmapped` is unchanged;
remap and resize already emit old then new placements
(`transaction/segment.rs:135-170`); kind, provenance and flag changes emit
`SegmentMappingChanged` over all placements.

`write_bytes` emits one `BytesWritten` and one retirement per affected
placement, not only the requested virtual range. `prepare_write` already
resolves the write into provider chunks (`storage/segments/staging.rs:732-736`);
it also projects each chunk through every committed or staged mapping on that
provider into each of that mapping's placements, and
`PreparedSegmentWriteRecords::range()` becomes `ranges()`.
`ProjectTransaction::write_bytes` then retires functions and pushes
`BytesWritten` per range. Aliases only arise through the API (a mapping added
to two spaces, or a second mapping over an existing provider range): loaders
place each mapping once and synthetic mappings always append fresh bytes, and
an overlay space does not alias its base. Hidden placements of an aliasing
mapping are included; conservative invalidation of overlapping hidden mappings
remains acceptable, and no visibility-diff mechanism is added.

Retained admission history (`RecentChanges`) keeps its record budget; eviction
advances the floor and older results resynchronise. Collapse to `Resynchronise`
remains conservative.

Deferred, query side: `queries::ChangeIndex` treats `SegmentMappingChanged` as
a global watermark despite its ranges, and `Dependency::covers` requires one
clause per kind rather than unioning same-kind clauses. Both are small and
independent of this model; the per-placement `BytesWritten` records already
advance alias watermarks, which is what the cached-`Term` probe needed.

### 10.6 Retained analyser state

Retained work carries no revisions or dependency sets. Its validity is
maintained by retraction: a retracting change over a region discards pending
functions and hint or coverage snapshots there through `Analyser::retract`, and
an admission rejection discards them for the batch regions. A continuation
therefore never stages a pending function computed from since-changed inputs
(`function/recovery/analysis.rs:1584-1589` stages pending functions before
candidate analysis). Discovery coverage is already rebuilt on every
non-continuation dispatch.

`ReadSet` keeps its 1024-range limit per kind. On overflow a kind collapses to
the whole ranges of the spaces it observed rather than to an unbounded read, so
reads in one space never match changes in another. Negative observations are
preserved; nothing else changes in the type.

A continuation's read set is merged with the read sets previously recorded for
its regions, so reads from the dispatch that began the work survive when the
continuation's regions replace them. Entries are shared by identity across a
batch's regions (`DependencyReadSet`), so each previous set is merged once.

The transaction infers no reads for staged functions or switch tables. A byte
write there retires the entity through the location rule, and recovery is
triggered by `FUNCTION_REMOVED` and `BYTES_WRITTEN`; inferred reads duplicated
that at a 3.5% cost on `ls.elf` and were removed.

### 10.7 Acceptance of the revision

Use the existing suites and temporary real-fixture runtime probes; add no
permanent tests. Normal analysis must incur no measurable regression. Compare
repeated, interleaved baseline and revised runs under the Cargo `bench`
profile with identical fixtures and instrumentation, reporting variability; the
`dev`-profile numbers in §14.2 are not comparable.

- Empty-space creation and non-executable mappings in an unrelated space must
  not dependency-reschedule unchanged recovery. Direct `SEGMENT_MAPPED`
  scheduling over the new placement remains ordinary behaviour.
- A byte write to a switch table outside its function's coverage retires the
  function and switch; an unrelated write retires nothing (exercised, §12).
- A write to a declared pointer slot re-recovers the function that read it.
- A write through alias A retires a function and materialised IL at alias B,
  and a cached `Term` scoped to B recomputes.
- A placement change over a pending function's bytes between dispatches
  discards it; the continuation does not commit it.
- More than 1024 disjoint byte reads in one space do not match a change in
  another space.
- Compare normal recovery, a no-output analyser, references in an existing
  space, space creation alone, mappings alone and mappings with references.
  Separate admission, routing and analyser execution in the measurement.

Neither the 13× result nor the 138 ms ordering prototype is a target; residual
cost of the combined workload must be accounted for with no unexplained
unrelated recovery.

### 10.8 Multiple-worker compatibility

Agreed architecture: parallel computation with serial, authoritative admission
and commit; this work implements neither a worker pool nor concurrent project
mutation.

- Each job computes from a stable view at a known revision and returns owned
  updates; no shared mutable state crosses the result boundary.
- Admission validates the result's reads against `RecentChanges` and commits
  atomically. Unrelated intervening changes do not reject a result; relevant
  changes or exhausted history require recomputation.
- Ownership is the result's base revision and regions. A cancelled or
  superseded job cannot replace newer state because its base is stale.
- Rejection discards retained analyser state for the batch regions through
  `Analyser::retract`; database updates and speculative state are discarded
  together.
- `Analyser::analyse(&mut self, …)` keeps exclusive ownership of analyser state;
  parallelism must partition work or use independent instances.
- Reservations follow §9 at admission.
- With workers, a placement change landing between dispatch and admission does
  not conflict with the coverage read, because placement kinds are not tracked
  dependency kinds. Enabling workers requires placement records to conflict
  with bounded byte reads at admission; that is a one-line extension of the
  shared matching rule and is not made now.

## 11. Python bindings

The Python `Project` exposes `create_space_with`, `create_synthetic_mapping` and
`address_space_by_name` through its owned engine/query reader.
`AddressSpaceKind.Base()` and `AddressSpaceKind.Overlay(base=...)` select the space
kind; `SegmentProperties` supplies mapping permissions. `MappingHint` retains its
existing Python name.

## 12. Done already

`SegmentMappingFlags::OVERLAY_ENABLED`, left over from the write overlay removed
in `dcca97e`, has been deleted. The later flags moved down one bit:
`COMPRESSED = 0x0008`, `ENCRYPTED = 0x0010`, `LARGE_PAGE = 0x0020`.

The first-pass storage type renames have been removed. The original
`ProviderMetadata`, `MappingMetadata`, `SpacePriority`, `MappingPriority`,
`MappingPlacement`, `StagedMappingRecord`, `StagedMappingPlacementRecord` and
`CachedMapping` names are retained.

The first-pass `synthetic_end` and `synthetic_provider_id` helpers have been
removed. `SegmentStorage::synthetic_provider` only looks up an existing descriptor;
mapping preparation owns backing placement.
`validate_space_name` and `validate_overlay_base` have been inlined. The
memory-mapped provider's `map`, `grow`, `append` and `overlapping_extents` helpers
have also been removed. The existing `pending_space_id` API is unchanged.

The agreed engine, query and Python mapping names in §3 have been restored, along
with `SEGMENT_MAPPED` / `SegmentMapped` and `SEGMENT_UNMAPPED` / `SegmentUnmapped`.
Successful reservation-only results no longer publish empty spaces.

Switches carry their location: `Switch::coverage_into` covers the branch and
data tables, `SwitchIndex` keeps a per-space interval index built alongside the
branch index, `SwitchTable::overlaps(range)` and
`SwitchTable::staged_overlaps(staging, range)` mirror the block and function
tables, and `invalidate_functions_in_range` retires the owners of overlapping
switches. `FunctionTable::staged_by_switch_id` and
`FunctionTableStaging::by_switch` pair with `by_switch_mut`; the commit-time
sweep is `orphaned_switches`, and `house-style.toml` registers `orphaned` as
the IR term for entities left without an owning function. A temporary
`ls.elf` probe confirmed that a byte write into a switch table outside its
function's coverage retires the function and switch while an unrelated write
retires nothing; the full `fugue-core` suite with `sqlite` passed afterwards.

The §10.3 engine model is implemented. `TRACKED_DEPENDENCY_KINDS` is shared by
`route_changes` and `ReadSet::conflicts_with`; `read_bytes` records
`BYTES_WRITTEN` only; `retracts` covers the four placement records and
`PHASES_CANCELLED_BY_RETRACTION` names the cancelled phases;
`Analyser::retract` has a no-op default and is called from `route_changes`, on
admission conflict or rejection and on an analyser error. `ReadSet` overflow
collapses to the observed spaces. `ProjectView::add_dependency` replaces the
private read recorder, and recovery declares pointer slots with it in the
function builder and the thunk pass. `DependencyIndex::record` merges
continuation reads with the sets previously recorded for its regions, held by
identity as `DependencyReadSet` and keyed by `RawAddress`. Work, reads and
invalidation without regions are `global`, matching `ProblemScope::Global`;
`addressless` is gone. `write_bytes` retires and emits `BytesWritten` per
affected placement through `PreparedSegmentWriteRecords::ranges()`. Recovery
re-recovers functions containing `BYTES_WRITTEN` dependency causes and drops
pending functions and snapshots on `retract`. The pointer-slot reference path
from the rolled-back pass was removed completely: no slot field on
instructions, blocks or functions, and no `READ | INDIRECT` reference.

The cached `QueryReader::flow_targets` query, its `FlowTargets` aggregate and
its cache slot were removed as a separate clean-up: nothing outside
`fugue-core` used it, and the per-function edge list cost a second
invalidation path for what one pass over the function's blocks provides.

## 13. Tests

Use existing tests and temporary runtime checks; do not add tests. Real fixtures
only.

- **Memory-mapped provider.** Unit tests in `provider/memmap.rs`:
  - extents far apart (near 0 and near 2^47): create, write, read, view, drop and
    reopen succeed, and the file stays close to the written size;
  - a write touching the last extent extends it; one after a gap stays separate,
    and the gap reads as unwritten;
  - a write bridging two extents;
  - growing past the mapping's length, and `resize`.
- **Low and high addresses.** A binary with very low and very high loaded
  addresses in one bank loads, analyses, saves and reloads. The fixture is a small
  static ELF built with zig, with its code at the usual low addresses and one
  section placed near the top of the user address space with
  `-Wl,--section-start` (for example `0x7fff00000000`); the ELF loader puts both in
  its default bank. No sources are kept, and the test is checked to fail on the
  current provider before the rework.
- **Performance.** Timing, RSS and memory for load and recovery on `ls.elf` and
  `libipmi.so`, before and after the provider change; and the measurement of
  §10.2.
- **Engine API, transient.** On `ls.elf`, create a named overlay of the default
  space and a synthetic mapping in it; assert the change records, that
  `ProjectView` reads the bytes back, and that `address_space_by_name` finds the
  space.
- **Engine API, persistent.** The same on a persistent project after it has been
  loaded, with enough synthetic mappings to grow the provider past its first size,
  then close and reopen; assert the space (name and kind), every mapping and its
  bytes survive.
- **Rejected transaction.** Create a synthetic mapping in a transaction that is
  rejected; assert no provider is opened and no file is created.
- **Removal.** Remove a synthetic mapping, create another; assert the new one does
  not overwrite a live mapping's bytes.
- **Analysis.** A test analyser that reserves a space, creates a synthetic mapping
  and adds a reference in one result; assert the reference resolves to the block.
- **No gaps.** A test analyser whose result is discarded, and one that finds
  nothing; assert no space is created and the next space created takes the
  identifier the discarded result had reserved.
- **Shared names.** Two analysers using the same name; assert one space, the
  second finding the first's by name.
- **Re-runs.** Run the analysis twice; assert one space and one mapping per block.

## 14. Acceptance results

### 14.1 Correctness

- The full existing `fugue-core` suite with `sqlite` passed: 777 tests, 30 ignored.
  The Python extension built and `fugue-workbench` passed `cargo check`.
- Temporary runtime programs exercised persistent named overlays, growth through
  16, 4096, 65536 and 262144-byte blocks, rejection without creating backing,
  removal without overwriting live bytes, and appending after reopening the same
  synthetic provider.
- Packed-provider checks exercised reverse physical/logical ordering, bridging
  writes, holes, shrink/regrowth, zero-length reopen and a logical size of
  `u64::MAX`, with one byte at `u64::MAX - 1`.
- The existing distant-segments ELF failed to load on HEAD with “Cannot allocate
  memory”. The new implementation recovered its entry function, retained its
  bytes at `0x7fff00000000` through archive/reopen, and used an 800-byte live
  provider file.
- Both reproduced append bugs are fixed: backing-end arithmetic returns
  `InvalidAddressRange` instead of panicking, and appending after a staged resize
  no longer overlaps the resized mapping. Runtime checks covered resizing both
  committed and just-created mappings, and ordinary mapping creation before a
  synthetic append.
- Reservation-only success, ID reuse, mixed-result commits, reference-only
  commits, shared names and rejected results were exercised by the existing
  suites and temporary runtime programs.
- The Python runtime check passed named base/overlay creation and lookup,
  synthetic mapping creation, duplicate-name rejection and invalid overlay-base
  rejection. Its existing suite reported 12 passed, 1 skipped and 1 failed.
  `test_loader_attributes_are_converted_from_dict` fails on its expectation that
  the `address_space` loader attribute selects space 3. The same test failed with
  a separately built HEAD extension; this unrelated baseline failure is unchanged.
- The final targeted transaction, reservation and persistence suites passed all
  31 tests after the name-validation style correction.
- Clippy reported no diagnostics on the append fixes. Its name-validation
  `collapsible_if` warning was corrected. Four unrelated warnings in function
  recovery, the lifter, the persistent function table and the MIPS loader remain
  outside this work; the lint run was not warning-clean. Automatic fixes were
  inspected in a disposable copy rather than applied to unrelated source files.
- Package-scoped Dylint (`--no-deps`) completed with 504 warnings, including
  119 duplicates, in existing code. It reported no diagnostics in `staging.rs`
  or the changed append arithmetic. The run was not warning-clean; unrelated
  style changes were not applied.

No permanent tests were added during reconciliation. Temporary programs,
benchmark checkouts and generated Dylint build directories have been removed.

### 14.2 Provider measurements

Baseline: `fd0447f3175ab69d951ca5706429555ecf144ee8`. Both versions used the
same dependency lock versions, native arm64 macOS, the Cargo `dev` profile and
one analysis worker. Results are medians of three sequential runs, alternating
before/after order, using `storage_timing mmap`. RSS and peak memory footprint
come from `/usr/bin/time -l`; these are process-wide measurements, not provider
allocation counts or release-build performance claims.

| Fixture/version       | Loader ms | Project ms | Analysis ms | Peak RSS MiB | Peak footprint MiB |
| --------------------- | --------: | ---------: | ----------: | -----------: | -----------------: |
| `ls.elf`, HEAD        |      4.25 |       2.72 |       89.49 |        71.84 |              53.27 |
| `ls.elf`, current     |      4.18 |       3.38 |       91.16 |        71.84 |              53.30 |
| `libipmi.so`, HEAD    |     47.90 |      61.29 |     1600.67 |       149.80 |             128.75 |
| `libipmi.so`, current |     47.60 |      63.24 |     1623.86 |       148.44 |             127.69 |

Recovered counts were unchanged: 400 functions / 4357 blocks for `ls.elf`, and
4403 functions / 37305 blocks for `libipmi.so`. Dispatch counts were 3 and 11.
Geometric capacity growth makes the live files larger for these compact
fixtures: 149728 → 198994 bytes and 1539880 → 2272520 bytes. The sparse-address
benefit is demonstrated separately by the distant-segments fixture.

### 14.3 Synthetic-mapping re-analysis

On the current implementation, a temporary analyser created one read-only
one-byte mapping and reference per recovered function in a named base space.
The default analysis pipeline and one worker were used in both cases.

| `ls.elf` workload           | Analysis ms | Dispatches | Peak RSS MiB | Peak footprint MiB |
| --------------------------- | ----------: | ---------: | -----------: | -----------------: |
| Normal analysis             |       89.97 |          3 |        70.55 |              53.17 |
| With 400 synthetic mappings |     1167.73 |        599 |        72.22 |              54.75 |

These are three-run medians. The synthetic analyser ran once, all 400 mappings
were readable, and no function was created at their non-executable addresses.
The roughly 13× elapsed-time increase fails acceptance; it is not an accepted
cost of synthetic mappings.

Subsequent profiling separated a scheduler amplification from the broad
invalidation that initiates it. Address-first ordering interleaves fresh regional
work and pending continuations. Since a batch cannot mix these work kinds, the
combined workload made 297 fresh recovery calls and 297 continuation calls over
the original code. Those calls produced no updates and consumed roughly one
second. Recovery over the new non-executable mappings took about 3 ms.

An isolated prototype grouped fresh work before continuations within each phase.
Three-run medians on the same development-profile workload were:

| Workload                    | Current ms / dispatches | Ordering prototype ms / dispatches |
| --------------------------- | ----------------------: | ---------------------------------: |
| Normal analysis             |               90.38 / 3 |                          89.69 / 3 |
| 400 mappings and references |           1168.95 / 599 |                         138.17 / 6 |

Both combined runs processed 2388 work items with three dependency reschedules,
400 recovered functions, 400 new mappings and no retries. The prototype did not
remove invalidations. It has been removed; global queue ordering is unchanged.
Its remaining roughly 54% overhead is not an acceptance result.

The references-only control took about 97 ms when its address space already
existed, versus about 856 ms when its result also created the space, without
creating mappings. This isolates address-space creation as another source of
broad invalidation. These control values are individual runs, not medians.

A separate probe, with analysers disabled after initial recovery and the target
space already created, measured admission of 400 mappings and references at
16.60 ms (three-run median). This is not a complete attribution of the combined
workload's remaining overhead. Commit, publication, dependency matching and
analysis execution must be measured separately before acceptance.

### 14.4 Dependency model

Baseline: the same working tree with only the §10.3 engine, transaction and
recovery changes removed, so the concurrent storage work is on both sides.
Both sides were built with `--profile bench`, run interleaved in alternating
order with in-process repeats (`recovery_timing 1 30` for `ls.elf`, `1 5` for
`libipmi.so`), six rounds each.

| Fixture                   | Baseline ms (p25–p75) | Revised ms (p25–p75) | Dispatches / functions |
| ------------------------- | --------------------: | -------------------: | ---------------------: |
| `ls.elf` (n=180)          |      6.14 (6.09–6.21) |     6.19 (6.15–6.25) |                3 / 400 |
| `libipmi.so` (n=30)       |  117.93 (117.63–119.46) | 119.48 (118.90–121.36) |            11 / 4,403 |

Peak memory footprint is unchanged (`ls.elf` 43.0 versus 43.2 MiB; `libipmi.so`
within its 114–126 MiB run-to-run spread on both sides). Bisection on `ls.elf`
attributed 0.22 ms to the transaction's inferred coverage and table reads,
since removed, and 0.09 ms to the continuation merge, retained as a
correctness fix.

The §14.3 workload on the revised engine: 400 synthetic mappings and references
took 6 dispatches instead of 599, with 0 dependency reschedules instead of 599,
400 functions and 400 mappings. A temporary probe writing one byte into a
declared pointer slot produced 1 dependency reschedule, re-recovered the reader
(input revision 1 → 3) and, by batch attribution, 296 other functions of its
batch. A reaction to every dependency kind was rejected by the existing suite:
symbol edits re-recovered whole batches. The full `fugue-core` suite with
`sqlite`, Clippy and `cargo house-style check` on every touched scope passed
on the final tree.
