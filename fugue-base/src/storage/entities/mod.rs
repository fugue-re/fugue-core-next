use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub mod namespace;
pub use namespace::Namespace;

pub mod memory;
pub use memory::InMemoryStorage;

pub mod util;
pub use util::BytesOrSlice;

pub const ENTITY_KEY_SIZE: usize = 24;
pub const ENTITY_PREFIX_SIZE: usize = 16;

pub type EntityAddress = [u8; 8];
pub type EntityKeyPrefix = [u8; ENTITY_PREFIX_SIZE];
pub type EntityKey = [u8; ENTITY_KEY_SIZE];

#[derive(Debug, Error)]
pub enum StorageBackendError {
    #[error(transparent)]
    Backend(anyhow::Error),
    #[error("failed to decode entity: {0}")]
    Decode(anyhow::Error),
    #[error("failed to encode entity: {0}")]
    Encode(anyhow::Error),
    #[error("invalid key format")]
    InvalidKeyFormat,
    #[error("invalid key size")]
    InvalidKeySize,
}

impl StorageBackendError {
    pub fn encode<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        StorageBackendError::Encode(anyhow::anyhow!(err))
    }

    pub fn decode<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        StorageBackendError::Decode(anyhow::anyhow!(err))
    }

    pub fn backend<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        StorageBackendError::Backend(anyhow::anyhow!(err))
    }
}

pub trait Entity: Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync {
    const ID: Uuid;

    fn entity_type(&self) -> Uuid {
        Self::ID
    }
}

pub trait StorageBulkInserter<'a> {
    fn insert(&mut self, key: &[u8], value: BytesOrSlice<'a>) -> Result<(), StorageBackendError>;
    fn finish(self: Box<Self>) -> Result<(), StorageBackendError>;
}

pub type EntityIterator<'a> =
    Box<dyn Iterator<Item = Result<(EntityKey, BytesOrSlice<'a>), StorageBackendError>> + 'a>;

pub type EntityKeyIterator<'a> =
    Box<dyn Iterator<Item = Result<EntityKey, StorageBackendError>> + 'a>;

pub type EntityBulkInserter<'a> = Box<dyn StorageBulkInserter<'a> + 'a>;

pub trait StorageBackend: Send + Sync {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, StorageBackendError>;
    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), StorageBackendError>;
    fn remove(&self, key: &[u8]) -> Result<(), StorageBackendError>;
    fn contains(&self, key: &[u8]) -> Result<bool, StorageBackendError>;

    fn iter_prefix_keys(&self, prefix: &[u8])
        -> Result<EntityKeyIterator<'_>, StorageBackendError>;
    fn iter_prefix(&self, prefix: &[u8]) -> Result<EntityIterator<'_>, StorageBackendError>;

    fn bulk_inserter(&self) -> Result<EntityBulkInserter, StorageBackendError>;
}
