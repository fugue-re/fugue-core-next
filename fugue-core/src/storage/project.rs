use std::marker::PhantomData;

use crate::arch::Arch;
use crate::ir::{IndexedFunctionTable, IndexedSymbolTable};
use crate::ir::traits::{FunctionTable, SymbolTable};
use crate::storage::entities::{
    DefaultFromEntityStorage, EntityStorageProviderFromStorage, ProjectEntity,
};
use crate::storage::segments::SegmentStorageProviderFromStorage;
use crate::storage::{
    EntityStorage, EntityStorageError, PersistentStorageProvider, StorageProvider,
    TransientStorageProvider,
};
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
    // type FunctionTable: Default;
    type SymbolTable: SymbolTable + DefaultFromEntityStorage + 'static;
    type FunctionTable: FunctionTable + DefaultFromEntityStorage + 'static;

    // NOTE: these are not configurable at the moment, but they could be in the future.
    fn architecture(storage: &EntityStorage) -> Result<Option<Arch>, EntityStorageError>;
    fn attributes(storage: &EntityStorage) -> Result<Option<AttributeMap>, EntityStorageError>;

    fn function_table(
        storage: &EntityStorage,
    ) -> Result<Option<Self::FunctionTable>, EntityStorageError>;

    fn symbol_table(
        storage: &EntityStorage,
    ) -> Result<Option<Self::SymbolTable>, EntityStorageError>;
}

pub struct DefaultProjectStorage;

impl ProjectStorage for DefaultProjectStorage {
    type SymbolTable = IndexedSymbolTable;
    type FunctionTable = IndexedFunctionTable;

    fn architecture(storage: &EntityStorage) -> Result<Option<Arch>, EntityStorageError> {
        storage.get(&ProjectEntity::Architecture)
    }

    fn attributes(storage: &EntityStorage) -> Result<Option<AttributeMap>, EntityStorageError> {
        storage.get(&ProjectEntity::Attributes)
    }

    fn function_table(
        storage: &EntityStorage,
    ) -> Result<Option<Self::FunctionTable>, EntityStorageError> {
        storage.get(&ProjectEntity::FunctionTable)
    }

    fn symbol_table(
        storage: &EntityStorage,
    ) -> Result<Option<Self::SymbolTable>, EntityStorageError> {
        storage.get(&ProjectEntity::SymbolTable)
    }
}

pub struct InMemoryProjectStorage;

impl ProjectStorage for InMemoryProjectStorage {
    type SymbolTable = IndexedSymbolTable;
    type FunctionTable = IndexedFunctionTable;

    fn architecture(_storage: &EntityStorage) -> Result<Option<Arch>, EntityStorageError> {
        Ok(None)
    }

    fn attributes(_storage: &EntityStorage) -> Result<Option<AttributeMap>, EntityStorageError> {
        Ok(None)
    }

    fn function_table(
        _storage: &EntityStorage,
    ) -> Result<Option<Self::FunctionTable>, EntityStorageError> {
        Ok(None)
    }

    fn symbol_table(
        _storage: &EntityStorage,
    ) -> Result<Option<Self::SymbolTable>, EntityStorageError> {
        Ok(None)
    }
}

pub trait ProjectStorageProvider {
    type ProjectStorage: ProjectStorage;
    type StorageProvider: StorageProvider;
}

pub struct DefaultTransientProjectStorageProvider;

impl ProjectStorageProvider for DefaultTransientProjectStorageProvider {
    type ProjectStorage = DefaultProjectStorage;
    type StorageProvider = TransientStorageProvider;
}

pub struct DefaultPersistentProjectStorageProvider<E, S>
where
    E: EntityStorageProviderFromStorage,
    S: SegmentStorageProviderFromStorage,
{
    _marker: PhantomData<(E, S)>,
}

impl<E, S> ProjectStorageProvider for DefaultPersistentProjectStorageProvider<E, S>
where
    E: EntityStorageProviderFromStorage,
    S: SegmentStorageProviderFromStorage,
{
    type ProjectStorage = DefaultProjectStorage;
    type StorageProvider = PersistentStorageProvider<E, S>;
}

pub struct InMemoryProvider;

impl ProjectStorageProvider for InMemoryProvider {
    type ProjectStorage = InMemoryProjectStorage;
    type StorageProvider = TransientStorageProvider;
}
