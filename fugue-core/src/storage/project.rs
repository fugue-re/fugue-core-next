use std::marker::PhantomData;

use crate::ir::block::table::IndexedCodeBlockTable;
use crate::ir::traits::{CodeBlockTable, FunctionTable, SymbolTable};
use crate::ir::{IndexedFunctionTable, IndexedSymbolTable};
use crate::storage::entities::EntityStorageProviderFromStorage;
use crate::storage::segments::SegmentStorageProviderFromStorage;
use crate::storage::{
    EntityStorage, EntityStorageError, PersistentStorageProvider, StorageProvider,
    TransientStorageProvider,
};

pub trait ProjectEntityFromStorage: Sized {
    fn from_entity_storage(storage: &EntityStorage) -> Result<Option<Self>, EntityStorageError>;
    fn default_from_entity_storage(storage: &EntityStorage) -> Result<Self, EntityStorageError>;
}

pub trait PersistableProjectEntity {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError>;
}

pub trait FundamentalProjectEntity:
    ProjectEntityFromStorage + PersistableProjectEntity + 'static
{
}

impl<T> FundamentalProjectEntity for T where
    T: ProjectEntityFromStorage + PersistableProjectEntity + 'static
{
}

// ProjectStorage provides a higher-level abstraction over EntityStorage, which is itself an
// abstraction over raw key-value storage. ProjectStorage focuses on project-specific data, and
// obtaining variations of core data structures, such as function and symbol tables, that are
// suitable for different workloads and available resources.
//
// The main reason for stacking these abstractions is to allow for experimentation, and to satisfy
// different use-cases, e.g., in-memory vs on-disk storage, different caching strategies, etc.,
// which can be swapped out without changing the higher-level logic that operates on these data
// structures.
//
pub trait ProjectStorage {
    type CodeBlockTable: CodeBlockTable + FundamentalProjectEntity;
    type FunctionTable: FunctionTable + FundamentalProjectEntity;
    type SymbolTable: SymbolTable + FundamentalProjectEntity;

    fn code_block_table(
        storage: &EntityStorage,
    ) -> Result<Option<Self::CodeBlockTable>, EntityStorageError> {
        Self::CodeBlockTable::from_entity_storage(storage)
    }

    fn function_table(
        storage: &EntityStorage,
    ) -> Result<Option<Self::FunctionTable>, EntityStorageError> {
        Self::FunctionTable::from_entity_storage(storage)
    }

    fn symbol_table(
        storage: &EntityStorage,
    ) -> Result<Option<Self::SymbolTable>, EntityStorageError> {
        Self::SymbolTable::from_entity_storage(storage)
    }
}

pub struct DefaultProjectStorage;

impl ProjectStorage for DefaultProjectStorage {
    type CodeBlockTable = IndexedCodeBlockTable;
    type FunctionTable = IndexedFunctionTable;
    type SymbolTable = IndexedSymbolTable;
}

pub struct InMemoryProjectStorage;

impl ProjectStorage for InMemoryProjectStorage {
    type CodeBlockTable = IndexedCodeBlockTable;
    type FunctionTable = IndexedFunctionTable;
    type SymbolTable = IndexedSymbolTable;

    fn code_block_table(
        _storage: &EntityStorage,
    ) -> Result<Option<Self::CodeBlockTable>, EntityStorageError> {
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
