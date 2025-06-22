use thiserror::Error;

pub mod entities;
pub use entities::{
    DefaultPersistentEntityStorage, DefaultTransientEntityStorage, EntityStorage,
    EntityStorageError, EntityStorageProvider,
};

pub mod segments;
pub use segments::{
    DefaultPersistentSegmentStorage, DefaultTransientSegmentStorage, SegmentStorage,
    SegmentStorageError, SegmentStorageProvider,
};

use entities::{EntityStorageProviderFromLoadable, InMemoryEntityStorage};
use segments::{InMemorySegmentStorage, SegmentStorageProviderFromLoadable};

use crate::loader::Loadable;

#[derive(Debug, Error)]
pub enum StorageProviderError {
    #[error("failed to initialise entity storage: {0}")]
    EntityStorage(#[from] EntityStorageError),
    #[error("failed to initialise segment storage: {0}")]
    SegmentStorage(#[from] SegmentStorageError),
}

pub struct StorageContainer {
    pub(crate) entities: EntityStorage,
    pub(crate) segments: SegmentStorage,
    pub(crate) kind: StorageContainerKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageContainerKind {
    Transient,
    Persistent,
    PersistentPacked,
}

impl StorageContainerKind {
    pub fn is_persistent(self) -> bool {
        matches!(self, Self::Persistent | Self::PersistentPacked)
    }

    pub fn is_transient(self) -> bool {
        matches!(self, Self::Transient)
    }

    pub fn is_packed(self) -> bool {
        matches!(self, Self::PersistentPacked)
    }
}

impl StorageContainer {
    pub fn new<P>(loadable: &impl Loadable) -> Result<Self, StorageProviderError>
    where
        P: StorageProvider,
    {
        match P::KIND {
            StorageContainerKind::Transient | StorageContainerKind::Persistent => {
                P::from_loadable(loadable)
            }
            StorageContainerKind::PersistentPacked => {
                // TODO: perform unpacking, if necessary
                P::from_loadable(loadable)
            }
        }
    }

    pub fn from_parts<P: StorageProvider>(
        entities: EntityStorage,
        segments: SegmentStorage,
    ) -> Self {
        Self {
            entities,
            segments,
            kind: P::KIND,
        }
    }

    pub fn entities(&self) -> &EntityStorage {
        &self.entities
    }

    pub fn entities_mut(&mut self) -> &mut EntityStorage {
        &mut self.entities
    }

    pub fn segments(&self) -> &SegmentStorage {
        &self.segments
    }

    pub fn segments_mut(&mut self) -> &mut SegmentStorage {
        &mut self.segments
    }

    pub fn kind(&self) -> StorageContainerKind {
        self.kind
    }

    pub fn into_parts(self) -> (EntityStorage, SegmentStorage) {
        (self.entities, self.segments)
    }
}

pub trait StorageProvider {
    const KIND: StorageContainerKind;

    fn from_loadable(loadable: &impl Loadable) -> Result<StorageContainer, StorageProviderError>;
}

// This provider uses the default transient storage provider for both segments and entities.
pub struct TransientStorageProvider;

impl StorageProvider for TransientStorageProvider {
    const KIND: StorageContainerKind = StorageContainerKind::Transient;

    fn from_loadable(loadable: &impl Loadable) -> Result<StorageContainer, StorageProviderError> {
        let entities = EntityStorage::new(InMemoryEntityStorage::from_loadable(loadable)?);
        let segments = SegmentStorage::new(InMemorySegmentStorage::from_loadable(loadable)?);
        Ok(StorageContainer::from_parts::<Self>(entities, segments))
    }
}

// This provider uses the default transient storage provider for segments and default persistent
// storage provider for entities.
pub struct PersistentEntityStorageProvider;

impl StorageProvider for PersistentEntityStorageProvider {
    const KIND: StorageContainerKind = StorageContainerKind::Persistent;

    fn from_loadable(loadable: &impl Loadable) -> Result<StorageContainer, StorageProviderError> {
        let entities = EntityStorage::new(DefaultPersistentEntityStorage::from_loadable(loadable)?);
        let segments =
            SegmentStorage::new(DefaultTransientSegmentStorage::from_loadable(loadable)?);
        Ok(StorageContainer::from_parts::<Self>(entities, segments))
    }
}

// This provider uses the default persistent storage provider for both segments and entities.
pub struct PersistentStorageProvider;

impl StorageProvider for PersistentStorageProvider {
    const KIND: StorageContainerKind = StorageContainerKind::PersistentPacked;

    fn from_loadable(loadable: &impl Loadable) -> Result<StorageContainer, StorageProviderError> {
        let entities = EntityStorage::new(DefaultPersistentEntityStorage::from_loadable(loadable)?);
        let segments =
            SegmentStorage::new(DefaultTransientSegmentStorage::from_loadable(loadable)?);
        Ok(StorageContainer::from_parts::<Self>(entities, segments))
    }
}
