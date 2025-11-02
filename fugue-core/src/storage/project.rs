use crate::arch::Arch;
use crate::ir::SymbolTable;
use crate::storage::{EntityStorage, EntityStorageError};
use crate::types::AttributeMap;

// ProjectStorage provides a higher-level abstraction over EntityStorage, which is itself an
// abstraction over raw key-value storage. ProjectStorage focuses on project-specific data, and
// obtaining variations of core data structures, such as function and symbol tables, that are
// suitable for different workloads and available resources.
//
// The main reason for stacking these abstractions is to allow for experimentation, and to satisfy
// different use-cases, e.g., in-memory vs on-disk storage, different caching strategies, etc.,
// which can be swapped out without changing the higher-level logic that operates on these data
// structures.
pub trait ProjectStorage {
    fn architecture(&self, storage: &EntityStorage) -> Result<Option<Arch>, EntityStorageError>;

    fn attributes(&self, storage: &EntityStorage) -> Result<Option<AttributeMap>, EntityStorageError>;

    fn symbol_table(&self, storage: &EntityStorage) -> Result<SymbolTable, EntityStorageError>;
}
