# Plan: Convert fugue-core from bincode to rkyv

## Overview

Convert the `fugue-core` crate (and `fugue-lifter-runtime`) from using bincode 2.x for serialization to rkyv 0.8.x for zero-copy deserialization.

## Current State Analysis

### Crates Using bincode

1. **fugue-core** (primary target)
   - Dependency: `bincode = { version = "2", features = ["serde"] }`
   - Uses bincode for entity storage serialization/deserialization
   - Many custom `Encode`/`Decode`/`BorrowDecode` implementations

2. **fugue-lifter-runtime**
   - Optional feature: `bincode = ["dep:bincode"]`
   - Uses `#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]`

### bincode Usage Patterns

1. **Simple derives**: `#[derive(Encode, Decode)]` on structs/enums
2. **Custom implementations**: Manual `Encode`, `Decode`, `BorrowDecode<'de, C>` for complex types
3. **API usage**: `bincode::encode_to_vec()`, `bincode::decode_from_slice()`

### Files with bincode Usage (fugue-core)

- `src/arch/mod.rs` - Architecture type serialization
- `src/ir/mod.rs` - IR types (custom implementations)
- `src/ir/address.rs` - Address type
- `src/ir/block/mod.rs` - CodeBlock (custom implementation)
- `src/ir/block/table.rs` - IndexedCodeBlockTable (custom for IntervalMap)
- `src/ir/function/mod.rs` - Function types (custom implementations)
- `src/ir/function/frame.rs` - Frame type
- `src/ir/function/table.rs` - Function table
- `src/ir/insn.rs` - Instruction types (custom implementations)
- `src/ir/location.rs` - Location type
- `src/ir/segment.rs` - Segment types (custom implementations)
- `src/ir/symbol.rs` - Symbol types (custom with serde::Compat)
- `src/lifter/mod.rs` - Lifter types (custom implementations)
- `src/loader/mod.rs` - Loader types
- `src/storage/entities/mod.rs` - Entity storage (encode/decode calls)
- `src/storage/entities/schema.rs` - Schema types
- `src/storage/segments/memmap.rs` - Memory-mapped segments
- `src/types/attributes.rs` - AttributeMap (custom implementations)

## rkyv 0.8 Migration Strategy

### Key Differences from bincode

| Aspect | bincode 2.x | rkyv 0.8 |
|--------|-------------|----------|
| Traits | `Encode`, `Decode`, `BorrowDecode` | `Archive`, `Serialize`, `Deserialize` |
| Result Type | Original type | `Archived<T>` (zero-copy view) |
| Serialization | `encode_to_vec()` | `rkyv::to_bytes::<Error>()` |
| Deserialization | `decode_from_slice()` | `rkyv::access::<T, Error>()` or `rkyv::from_bytes()` |
| Custom impl | Encoder/Decoder traits | `ArchiveWith`, `SerializeWith`, `DeserializeWith` |

### rkyv 0.8 Specifics

- Derives: `#[derive(Archive, Serialize, Deserialize)]`
- Optional validation with `bytecheck` feature
- `#[rkyv(...)]` attributes for customization

## Implementation Steps

### Phase 1: Update Dependencies

1. Update `fugue-core/Cargo.toml`:
   - Remove: `bincode = { version = "2", features = ["serde"] }`
   - Add: `rkyv = { version = "0.8", features = ["std", "bytecheck"] }`

2. Update `fugue-lifter-runtime/Cargo.toml`:
   - Replace bincode with rkyv feature flag

3. Update `fugue-lifter/Cargo.toml`:
   - Change feature flag from `bincode` to `rkyv`

### Phase 2: Create rkyv Wrapper Types/Helpers

Create a new module `src/types/rkyv_helpers.rs` with:
- Helper functions for encode/decode that match current API
- Custom archive implementations for types like `IntervalMap`, `FxHashMap`
- Type aliases for `ArchivedXxx` types

### Phase 3: Update Simple Types (Derive-only)

Convert simple types that only use `#[derive(Encode, Decode)]`:
- `src/ir/address.rs` - `Address`
- `src/ir/location.rs` - `Location`
- `src/ir/function/frame.rs` - Frame types
- `src/ir/function/table.rs` - Function table
- `src/storage/entities/schema.rs` - Schema types
- `src/loader/mod.rs` - Loader types

Pattern:
```rust
// Before:
#[derive(Encode, Decode)]
struct Foo { ... }

// After:
#[derive(Archive, Serialize, Deserialize)]
#[rkyv(derive(Debug, Clone))] // if needed
struct Foo { ... }
```

### Phase 4: Update Complex Types (Custom Implementations)

These require custom `Archive`/`Serialize`/`Deserialize` implementations:

1. **IndexedCodeBlockTable** (`src/ir/block/table.rs`)
   - Contains `IntervalMap<Address, IdSet<CodeBlock>>`
   - Need custom archive that serializes bounds as Vec of (Range, IdSet) pairs

2. **AttributeMap** (`src/types/attributes.rs`)
   - Contains `FxHashMap<String, serde_json::Value>`
   - Need to handle `serde_json::Value` recursively

3. **Symbol types** (`src/ir/symbol.rs`)
   - Uses `bincode::serde::Compat` for serde interop
   - Need `#[rkyv(with = ...)]` wrappers or custom implementations

4. **Instruction types** (`src/ir/insn.rs`)
   - Complex nested structures

5. **Segment types** (`src/ir/segment.rs`)
   - Multiple custom implementations

### Phase 5: Update Storage Layer

Modify `src/storage/entities/mod.rs`:
- Replace `bincode::encode_to_vec()` with `rkyv::to_bytes()`
- Replace `bincode::decode_from_slice()` with `rkyv::access()` or `rkyv::from_bytes()`
- Update error handling for rkyv errors

Modify `src/storage/segments/memmap.rs`:
- Update serialization for `MemoryMappedSegmentStorageMetadata`

### Phase 6: Update fugue-lifter-runtime

Convert types in:
- `src/partmap.rs`
- `src/pcode.rs`
- `src/context.rs`

Change feature flag from `bincode` to `rkyv`.

### Phase 7: Handle Archived Types in Public API

Since rkyv produces `Archived<T>` types, decide on API approach:
- **Option A**: Always deserialize to owned types (simpler, less efficient)
- **Option B**: Expose archived types in API (more complex, zero-copy benefits)

Recommendation: Start with Option A for compatibility, can optimize later.

## Critical Files to Modify

1. `fugue-core/Cargo.toml` - Dependencies
2. `fugue-lifter-runtime/Cargo.toml` - Dependencies
3. `fugue-lifter/Cargo.toml` - Feature flags
4. `fugue-core/src/storage/entities/mod.rs` - Storage layer encode/decode
5. `fugue-core/src/ir/block/table.rs` - IndexedCodeBlockTable
6. `fugue-core/src/types/attributes.rs` - AttributeMap
7. `fugue-core/src/ir/symbol.rs` - Symbol types
8. All IR types with custom implementations

## Risks and Considerations

1. **API Breaking Changes**: `Archived<T>` types may need different handling
2. **serde_json::Value**: Complex recursive type needs careful handling
3. **IntervalMap**: Third-party type without rkyv support - need wrapper
4. **Performance Testing**: Should verify zero-copy benefits are realized
5. **Feature Flags**: Need to update all crates that depend on the bincode feature

## Design Decisions (Confirmed)

1. **API Design**: Hybrid approach - provide both `get()` (owned) and `get_archived()` (zero-copy) methods
2. **Transition**: Full replacement - remove bincode entirely
3. **Scope**: fugue-core crate only (fugue-lifter-runtime bincode feature left unchanged)

---

## Detailed Implementation Plan

### Step 1: Update Cargo.toml Dependencies

**File: `fugue-core/Cargo.toml`**
```toml
# Remove:
bincode = { version = "2", features = ["serde"] }

# Add:
rkyv = { version = "0.8", features = ["std", "bytecheck", "alloc"] }
```

Also update `fugue-lifter` dependency to remove `bincode` feature requirement.

### Step 2: Convert Simple Types

**Pattern for simple derive replacement:**

```rust
// Before:
use bincode::{Decode, Encode};

#[derive(Debug, Clone, Encode, Decode)]
pub struct Foo { ... }

// After:
use rkyv::{Archive, Serialize, Deserialize};

#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
#[rkyv(derive(Debug, Clone))]  // derive on Archived type
pub struct Foo { ... }
```

**Files to convert (simple derives):**
1. `src/ir/address.rs` - Address
2. `src/ir/location.rs` - Location
3. `src/ir/function/frame.rs` - Frame types
4. `src/ir/function/table.rs` - IndexedFunctionTable
5. `src/storage/entities/schema.rs` - Entity schema types
6. `src/loader/mod.rs` - Loader types

### Step 4: Convert Complex Types with Custom Implementations

These require manual `Archive`/`Serialize`/`Deserialize` implementations:

#### 4a. AttributeMap (`src/types/attributes.rs`)

The `serde_json::Value` type needs special handling. Use rkyv's `with` attribute:

```rust
#[derive(Archive, Serialize, Deserialize)]
pub struct AttributeMap {
    #[rkyv(with = rkyv::with::AsVec)]  // serialize HashMap as Vec of pairs
    inner: FxHashMap<String, JsonValue>,
}

// JsonValue needs a custom archived representation
#[derive(Archive, Serialize, Deserialize)]
pub enum ArchivedJsonValue {
    Null,
    Bool(bool),
    Number(ArchivedJsonNumber),
    String(rkyv::string::ArchivedString),
    Array(rkyv::vec::ArchivedVec<ArchivedJsonValue>),
    Object(rkyv::collections::ArchivedHashMap<rkyv::string::ArchivedString, ArchivedJsonValue>),
}
```

#### 4b. IndexedCodeBlockTable (`src/ir/block/table.rs`)

`IntervalMap` has no rkyv support - need wrapper:

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct IndexedCodeBlockTable {
    // Serialize IntervalMap as a Vec of (Range, IdSet) pairs
    #[rkyv(with = IntervalMapWrapper)]
    bounds: IntervalMap<Address, IdSet<CodeBlock>>,
    blocks: Vec<CodeBlock>,
    free_ids: Vec<Id<CodeBlock>>,
}

// Custom wrapper that converts IntervalMap to/from Vec
struct IntervalMapWrapper;
```

#### 4c. Symbol Types (`src/ir/symbol.rs`)

Uses `bincode::serde::Compat` - replace with rkyv serde compat:

```rust
#[derive(Archive, Serialize, Deserialize)]
pub struct Symbol {
    #[rkyv(with = rkyv::with::AsString)]  // or custom serde wrapper
    name: SymbolName,
    // ...
}
```

#### 4d. Instruction Types (`src/ir/insn.rs`)

Complex nested structures - convert each nested type:

```rust
#[derive(Archive, Serialize, Deserialize)]
pub struct Instruction { ... }

#[derive(Archive, Serialize, Deserialize)]
pub struct InstructionMeta { ... }
```

#### 4e. Segment Types (`src/ir/segment.rs`)

Multiple types with custom impls:

```rust
#[derive(Archive, Serialize, Deserialize)]
pub struct Segment { ... }

#[derive(Archive, Serialize, Deserialize)]
pub struct SegmentKind { ... }
```

### Step 5: Update Entity Storage Layer

**File: `src/storage/entities/mod.rs`**

Replace bincode calls with rkyv:

```rust
// Before:
bincode::decode_from_slice::<E, _>(bytes.as_slice(), bincode::config::standard())

// After (owned):
rkyv::from_bytes::<E, rancor::Error>(bytes.as_slice())

// After (zero-copy):
rkyv::access::<ArchivedE, rancor::Error>(bytes.as_slice())
```

```rust
// Before:
bincode::encode_to_vec(entity, bincode::config::standard())

// After:
rkyv::to_bytes::<rancor::Error>(entity).map(|v| v.to_vec())
```

Add hybrid API methods:

```rust
impl EntityTransactionalReader<'a> {
    // Owned version (existing behavior)
    pub fn get<K: EntityKey, E: Entity>(&self, key: &K) -> Result<Option<E>, ...> {
        // ... use rkyv::from_bytes
    }

    // Zero-copy version (new)
    pub fn get_archived<K: EntityKey, E: Entity>(&self, key: &K)
        -> Result<Option<&E::Archived>, ...>
    {
        // ... use rkyv::access
    }
}
```

### Step 6: Update Memory-Mapped Segments

**File: `src/storage/segments/memmap.rs`**

Update `MemoryMappedSegmentStorageMetadata` serialization:

```rust
// Before:
bincode::decode_from_std_read::<MemoryMappedSegmentStorageMetadata, _, _>(...)
bincode::encode_into_std_write(&metadata, &mut file, bincode::config::standard())

// After:
let bytes = std::io::Read::read_to_end(&mut reader)?;
let metadata = rkyv::from_bytes::<MemoryMappedSegmentStorageMetadata, _>(&bytes)?;

let bytes = rkyv::to_bytes::<rancor::Error>(&metadata)?;
file.write_all(&bytes)?;
```

### Step 7: Update IR Types (mod.rs)

**File: `src/ir/mod.rs`**

Convert `Id<T>`, `IdSet<T>`, and other core IR types.

### Step 8: Update Lifter Module

**File: `src/lifter/mod.rs`**

Convert `Lifter` and `LifterContext` types.

### Step 9: Remove bincode Imports

Search and replace all `use bincode::*` imports with rkyv equivalents.

### Step 10: Update Tests

Update all tests that use bincode serialization to use rkyv.

---

## File Modification Order

1. `Cargo.toml` - Add rkyv, remove bincode
4. `src/ir/address.rs` - Simple type
5. `src/ir/location.rs` - Simple type
6. `src/ir/mod.rs` - Core IR types
7. `src/ir/block/mod.rs` - CodeBlock
8. `src/ir/block/table.rs` - IndexedCodeBlockTable (complex)
9. `src/ir/insn.rs` - Instruction types (complex)
10. `src/ir/segment.rs` - Segment types (complex)
11. `src/ir/symbol.rs` - Symbol types (complex)
12. `src/ir/function/frame.rs` - Frame
13. `src/ir/function/mod.rs` - Function
14. `src/ir/function/table.rs` - Function table
15. `src/types/attributes.rs` - AttributeMap (complex)
16. `src/arch/mod.rs` - Architecture types
17. `src/lifter/mod.rs` - Lifter types
18. `src/loader/mod.rs` - Loader types
19. `src/storage/entities/schema.rs` - Schema
20. `src/storage/entities/mod.rs` - Storage layer
21. `src/storage/segments/memmap.rs` - Memmap segments

---

## Estimated Complexity

| Category | Files | Complexity |
|----------|-------|------------|
| Simple derives | 8 | Low |
| Custom implementations | 6 | High |
| Storage layer | 2 | Medium |
| Other | 5 | Low-Medium |

Total: ~21 files to modify
