# Storage traits and capabilities plan

## Problem

`test_project` uses `DefaultTransientProjectStorageProvider`, but segment storage still attempts to persist segment metadata during project creation.

Current call path:

- `Project::<...>::from_file(...)` in `src/project.rs`
- `StorageContainer::from_loadable::<S::StorageProvider>(...)` in `src/project.rs`
- `TransientStorageProvider::from_loadable(...)` in `src/storage/mod.rs`
- `SegmentStorage::from_loadable::<InMemorySegmentStorage>(...)` in `src/storage/mod.rs`
- unconditional `storage.persist_storage(&project_path)?` in `src/storage/segments/mod.rs`

This is wrong for transient backends. The intended behaviour is:

- persistent backends: initialise and persist segment metadata
- transient backends: initialise in memory only, do not persist segment metadata

## Why this happens

The codebase currently expresses storage capability inconsistently.

### Entity storage already has a runtime persistence model

Entity storage exposes persistence explicitly:

- `EntityStorageProvider::persistence() -> StoragePersistence`
- `EntityStorage::persistence()`, `is_persistent()`, `is_transient()`
- `Project::persist()` checks `self.storage.entities.is_transient()` and skips persistence for transient entity storage

Relevant files:

- `src/storage/entities/mod.rs`
- `src/project.rs`

### Segment storage does not have the same model

Segment storage currently mixes three different concerns:

1. provider byte I/O (`SegmentStorageProvider`)
2. metadata serialisability / stable identity (`PersistableSegmentStorageProvider`, `stable_tag`)
3. reload-from-storage capability (`SegmentStorageProviderFromStorage`, registry `from_storage` presence)

Relevant files:

- `src/storage/segments/mod.rs`
- `src/storage/segments/provider/mod.rs`
- `src/storage/segments/provider/registry.rs`

Because these concerns are conflated, `SegmentStorage::from_loadable` does not have a direct way to ask the only question that matters here:

- is this segment storage transient or persistent?

Instead, it infers persistence indirectly from the existence of `ATTRIBUTE_PROJECT_PATH`, which is not the same thing.

## Current inconsistencies

### 1. Project path is treated as a persistence signal

In `src/storage/segments/mod.rs`, `SegmentStorage::from_loadable` persists metadata whenever `ATTRIBUTE_PROJECT_PATH` exists:

```rust
if let Some(project_path) = attributes.get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH) {
    storage.persist_storage(&project_path)?;
}
```

That attribute exists for both transient and persistent project creation paths. It is a location hint, not a persistence contract.

### 2. Segment provider traits blur persistence and loadability

`PersistableSegmentStorageProvider` currently means “has a stable tag”, not “must be persisted”.

At the same time, registry persistence is inferred via `from_storage.is_some()`:

- `SegmentStorageProviderRegistry::is_persistable()` really means “reloadable from stored metadata”

This naming hides the actual distinction between:

- backend lifetime: transient vs persistent
- serialisation capability: can metadata refer to this provider and later reconstruct it?

### 3. Segment storage metadata writing is all-or-nothing in behaviour, but not in type model

`persist_storage()` writes mappings for every provider, but filters the provider list through registry `is_persistable()`.

That means the current model can produce internally inconsistent metadata if transient/non-reloadable providers ever coexist with persisted mappings.

Even if current call sites mostly avoid mixed persistence, the abstraction allows an invalid state.

### 4. Provider byte flush is separate from metadata persistence, but the code does not make that boundary obvious

For example:

- `MemoryMappedSegmentStorage::flush()` flushes mapped bytes to its backing file
- `SegmentStorage::persist_storage()` writes `segment.storage.bin` metadata

These are different operations. The transient bug is about metadata persistence, not provider byte flush.

## Design goal

Adopt one explicit capability model across storage layers:

- persistence: transient vs persistent
- reloadability: can this provider be reconstructed from stored metadata?

The immediate behavioural rule should be:

- only persist segment metadata when the segment storage instance is persistent

## Recommended direction

### 1. Add runtime persistence to segment providers and `SegmentStorage`

Mirror the entity-storage design.

Add to `SegmentStorageProvider`:

```rust
fn persistence(&self) -> StoragePersistence {
    PERSISTENT
}
```

Transient providers override it to return `TRANSIENT`.

Then expose on `SegmentStorageDescriptor` and `SegmentStorage`:

- `SegmentStorageDescriptor::persistence()`
- `SegmentStorage::persistence()`
- `SegmentStorage::is_persistent()`
- `SegmentStorage::is_transient()`

For `SegmentStorage`, treat persistence as an invariant over the opened providers:

- if all providers are persistent, storage is persistent
- if all providers are transient, storage is transient
- mixed persistence should be rejected during provider registration/opening

Recommendation: reject mixed persistence. One storage instance should have one persistence mode.

Reason:

- the project design already thinks in terms of transient project backends vs persistent project backends
- mixed provider persistence makes metadata semantics ambiguous
- rejecting mixed mode keeps the abstraction honest and avoids invalid serialised state

### 2. Stop using `ATTRIBUTE_PROJECT_PATH` as the decision point

Change `SegmentStorage::from_loadable` to:

- initialise providers and mappings
- determine storage persistence from the providers
- persist metadata only if:
  - the storage is persistent, and
  - `ATTRIBUTE_PROJECT_PATH` exists

In other words, project path remains the destination, but persistence mode decides whether writing is allowed.

Conceptually:

```rust
if storage.is_persistent()
    && let Some(project_path) = attributes.get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH)
{
    storage.persist_storage(project_path)?;
}
```

That is the behavioural fix the test requires.

### 3. Rename the segment capability traits to match what they actually mean

The current names invite the bug.

Recommended split:

- keep `SegmentStorageProvider` for I/O and runtime persistence
- rename `PersistableSegmentStorageProvider` to something like `TaggedSegmentStorageProvider` or `RegisteredSegmentStorageProvider`
  - responsibility: provider has a stable tag for metadata
- keep `SegmentStorageProviderFromStorage` for reloadability
- rename registry `is_persistable()` to `is_reloadable()` or `supports_from_storage()`

This makes the mental model explicit:

- persistence answers whether we should write metadata at all
- reloadability answers whether written metadata can reconstruct the provider later

### 4. Make metadata persistence validate provider capabilities explicitly

`persist_storage()` should enforce its preconditions rather than silently filtering providers.

Recommended behaviour:

- if `SegmentStorage` is transient: return early without writing
- if `SegmentStorage` is persistent:
  - require every provider referenced by a mapping to be reloadable/tagged
  - fail loudly if a persistent storage contains a provider that cannot be reconstructed

Do not serialise partial provider metadata.

Reason:

- partial persistence creates a broken on-disk representation
- failure at persist time is preferable to silently writing unreadable project state

### 5. Keep byte flush separate from metadata persistence

Do not couple provider `flush()` with metadata persistence.

The two operations should remain distinct:

- provider flush: pushes provider-owned bytes to its backing medium
- metadata persist: writes `segment.storage.bin`

If a future persistent project persist flow wants stronger guarantees, it can orchestrate both explicitly, but they should not be conflated in the trait model.

## Proposed refactor outline

### Phase 1: capability model

1. Add `persistence()` to `SegmentStorageProvider`
2. Surface persistence on `SegmentStorageDescriptor`
3. Add `SegmentStorage::{persistence,is_persistent,is_transient}`
4. Enforce uniform persistence across providers in one `SegmentStorage`

### Phase 2: naming clean-up

1. Rename `PersistableSegmentStorageProvider`
2. Rename registry `is_persistable()` to `is_reloadable()` or equivalent
3. Audit call sites so persistence and reloadability are never treated as synonyms

### Phase 3: persistence behaviour

1. Gate `SegmentStorage::from_loadable` metadata write on `storage.is_persistent()`
2. Make `persist_storage()` a no-op for transient storage
3. Make `persist_storage()` validate that all mapped providers are reloadable

### Phase 4: project-level consistency

Consider whether `Project::persist()` should also become storage-symmetric:

- it already skips entity persistence for transient entity storage
- it should not assume segment metadata persistence happened earlier just because a project path exists

Even if no immediate project-level API change is required, the segment layer should expose enough truth for project-layer orchestration to remain coherent.

## Concrete acceptance criteria

The change is correct when all of the following are true:

1. `Project::<DefaultTransientProjectStorageProvider>::from_file("tests/ls.elf")` does not attempt to write segment metadata
2. transient segment storage with a project path no longer errors merely because metadata persistence was attempted
3. persistent segment storage still writes `segment.storage.bin`
4. loading a persisted project reconstructs providers only from metadata that fully describes all mapped providers
5. the code no longer uses project-path presence as a proxy for storage persistence
6. segment storage and entity storage expose persistence through parallel concepts

## Suggested tests

### Update existing regression target

- `src/project.rs::test_project`
  - assert transient project creation succeeds with default transient provider
  - optionally assert no segment metadata file is created when using transient storage with a project path

### Add segment-level tests

1. transient segment storage from loadable
   - create with `ATTRIBUTE_PROJECT_PATH`
   - verify success
   - verify `segment.storage.bin` is absent

2. persistent segment storage from loadable
   - create with `ATTRIBUTE_PROJECT_PATH`
   - verify `segment.storage.bin` is present

3. persistent storage with non-reloadable provider
   - verify persistence fails explicitly rather than writing partial metadata

4. persistence classification
   - verify in-memory provider reports transient
   - verify persistent memory-mapped provider reports persistent
   - verify transient memory-mapped provider reports transient

## Recommendation summary

Do not patch this with another special-case check at the call site.

Instead:

- give segment storage the same explicit runtime persistence model that entity storage already has
- separate persistence from reloadability in names and traits
- gate metadata writes on storage persistence, not on project-path presence
- reject mixed or partially serialisable provider states

This produces the intended behaviour for `test_project` and removes the trait/capability ambiguity that caused the bug in the first place.
