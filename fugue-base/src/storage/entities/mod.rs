use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub mod namespace;
pub use namespace::Namespace;

pub mod util;

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

pub(crate) const KEY_SIZE: usize = 24;
pub(crate) type EntityKeyPrefix = [u8; 16];
pub type EntityKey = [u8; KEY_SIZE];

pub trait Entity: Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync {
    const ID: Uuid;

    fn entity_type(&self) -> Uuid {
        Self::ID
    }
}

pub trait BulkInserter {
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StorageBackendError>;
    fn finish(self: Box<Self>) -> Result<(), StorageBackendError>;
}

// Storage backend trait
pub trait StorageBackend: Send + Sync {
    fn get(&self, key: &[u8]) -> Result<Option<Cow<'_, [u8]>>, StorageBackendError>;
    fn insert(&self, key: &[u8], value: &[u8]) -> Result<(), StorageBackendError>;
    fn delete(&self, key: &[u8]) -> Result<(), StorageBackendError>;
    fn exists(&self, key: &[u8]) -> Result<bool, StorageBackendError>;

    fn iter_keys(
        &self,
        prefix: &[u8],
    ) -> Result<
        Box<dyn Iterator<Item = Result<EntityKey, StorageBackendError>> + '_>,
        StorageBackendError,
    >;

    fn iter_prefix(
        &self,
        prefix: &[u8],
    ) -> Result<
        Box<dyn Iterator<Item = Result<(Cow<'_, [u8]>, Cow<'_, [u8]>), StorageBackendError>> + '_>,
        StorageBackendError,
    >;

    fn bulk_inserter(&self) -> Result<Box<dyn BulkInserter>, StorageBackendError>;
}

pub struct StorageKeyIterator<'a> {
    iter: Box<dyn Iterator<Item = Result<EntityKey, StorageBackendError>> + 'a>,
}

impl<'a> Iterator for StorageKeyIterator<'a> {
    type Item = Result<EntityKey, StorageBackendError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

pub struct StorageIterator<'a> {
    iter:
        Box<dyn Iterator<Item = Result<(Cow<'a, [u8]>, Cow<'a, [u8]>), StorageBackendError>> + 'a>,
}

impl<'a> Iterator for StorageIterator<'a> {
    type Item = Result<(Cow<'a, [u8]>, Cow<'a, [u8]>), StorageBackendError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}
