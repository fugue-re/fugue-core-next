use crate::storage::{EntityStorage, EntityStorageError};

#[cfg(feature = "sqlite")]
pub mod sqlite;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteProvider;

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
