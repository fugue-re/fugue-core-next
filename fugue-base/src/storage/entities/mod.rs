use std::sync::Arc;

use bincode::{Decode, Encode};
use quick_cache::sync::Cache;
use thiserror::Error;
use uuid::Uuid;

pub mod namespace;
pub use namespace::Namespace;

pub mod memory;
pub use memory::InMemoryEntityStorage;

pub mod util;
pub use util::BytesOrSlice;
use util::{extract_address_from_key, make_key, make_type_prefix};

use crate::types::Address;

pub const ENTITY_KEY_SIZE: usize = 24;
pub const ENTITY_PREFIX_SIZE: usize = 16;

pub type EntityAddress = [u8; 8];
pub type EntityKeyPrefix = [u8; ENTITY_PREFIX_SIZE];
pub type EntityKey = [u8; ENTITY_KEY_SIZE];

#[derive(Debug, Error)]
pub enum EntityStorageBackendError {
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

impl EntityStorageBackendError {
    pub fn encode<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Encode(anyhow::anyhow!(err))
    }

    pub fn decode<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Decode(anyhow::anyhow!(err))
    }

    pub fn backend<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Backend(anyhow::anyhow!(err))
    }
}

pub trait Entity<Context = ()>: Encode + Decode<Context> + Clone + Send + Sync {
    const ID: Uuid;

    fn entity_type(&self) -> Uuid {
        Self::ID
    }
}

pub trait EntityStorageBulkInserter<'a> {
    fn insert(
        &mut self,
        key: &[u8],
        value: BytesOrSlice<'a>,
    ) -> Result<(), EntityStorageBackendError>;
    fn finish(self: Box<Self>) -> Result<(), EntityStorageBackendError>;
}

pub type EntityBytesIterator<'a> =
    Box<dyn Iterator<Item = Result<(EntityKey, BytesOrSlice<'a>), EntityStorageBackendError>> + 'a>;

pub type EntityKeyBytesIterator<'a> =
    Box<dyn Iterator<Item = Result<EntityKey, EntityStorageBackendError>> + 'a>;

pub type EntityIterator<'a, E> =
    Box<dyn Iterator<Item = Result<(Address, E), EntityStorageBackendError>> + 'a>;

pub type EntityKeyIterator<'a> =
    Box<dyn Iterator<Item = Result<Address, EntityStorageBackendError>> + 'a>;

pub type EntityBulkInserter<'a> = Box<dyn EntityStorageBulkInserter<'a> + 'a>;

pub trait EntityStorageBackend: Send + Sync {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageBackendError>;
    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageBackendError>;
    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageBackendError>;
    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageBackendError>;

    fn iter_prefix_keys(
        &self,
        prefix: &[u8],
    ) -> Result<EntityKeyBytesIterator<'_>, EntityStorageBackendError>;
    fn iter_prefix(
        &self,
        prefix: &[u8],
    ) -> Result<EntityBytesIterator<'_>, EntityStorageBackendError>;

    fn bulk_inserter(&self) -> Result<EntityBulkInserter, EntityStorageBackendError>;
}

pub struct EntityCache<T: Entity> {
    entities: Cache<Address, Arc<T>>,
    storage: EntityStorage,
}

impl<T> EntityCache<T>
where
    T: Entity,
{
    pub fn new(storage: EntityStorage, size: usize) -> Result<Self, EntityStorageBackendError> {
        Ok(Self {
            entities: Cache::new(size),
            storage,
        })
    }

    pub fn get(
        &self,
        address: impl Into<Address>,
    ) -> Result<Option<Arc<T>>, EntityStorageBackendError> {
        let address = address.into();

        if let Some(entity) = self.entities.get(&address) {
            return Ok(Some(entity.clone()));
        }

        if let Some(entity) = self.storage.get::<T>(address)? {
            let entity = Arc::new(entity);
            self.entities.insert(address, entity.clone());
            return Ok(Some(entity));
        }

        Ok(None)
    }

    pub fn contains(&self, address: impl Into<Address>) -> Result<bool, EntityStorageBackendError> {
        let address = address.into();

        if self.entities.contains_key(&address) {
            return Ok(true);
        }

        self.storage.contains::<T>(address)
    }

    pub fn insert(
        &self,
        address: impl Into<Address>,
        entity: T,
    ) -> Result<(), EntityStorageBackendError> {
        let address = address.into();

        self.storage.insert(address, &entity)?;
        self.entities.insert(address.clone(), Arc::new(entity));

        Ok(())
    }

    pub fn remove(&self, address: impl Into<Address>) -> Result<(), EntityStorageBackendError> {
        let address = address.into();

        self.storage.remove::<T>(address)?;
        self.entities.remove(&address);

        Ok(())
    }

    pub fn keys(&self) -> Result<EntityKeyIterator<'_>, EntityStorageBackendError> {
        self.storage.keys::<T>()
    }

    pub fn iter(&self) -> Result<EntityIterator<'_, Arc<T>>, EntityStorageBackendError> {
        // TODO: should we cache the elements in the iterator if the cache has capacity?
        let pfx = make_type_prefix(None, T::ID);
        self.storage.backend.iter_prefix(&pfx).map(|iter| {
            Box::new(iter.map(|result| {
                result.and_then(|(key, value)| {
                    let key = extract_address_from_key(&key)?;
                    if let Some(val) = self.entities.get(&key) {
                        return Ok((key, val));
                    }

                    let val = bincode::decode_from_slice::<T, _>(
                        value.as_slice(),
                        bincode::config::standard(),
                    )
                    .map(|(entity, _)| entity)
                    .map_err(EntityStorageBackendError::decode)?;

                    Ok((key, Arc::new(val)))
                })
            })) as EntityIterator<'_, Arc<T>>
        })
    }
}

#[derive(Clone)]
pub struct EntityStorage {
    backend: Arc<dyn EntityStorageBackend>,
}

impl EntityStorage {
    pub fn new(backend: impl EntityStorageBackend + 'static) -> Self {
        Self {
            backend: Arc::new(backend),
        }
    }

    pub fn get<E: Entity>(
        &self,
        address: impl Into<Address>,
    ) -> Result<Option<E>, EntityStorageBackendError> {
        let key = make_key(None, E::ID, address.into());
        let Some(val) = self.backend.get(&key)? else {
            return Ok(None);
        };

        bincode::decode_from_slice::<E, _>(val.as_slice(), bincode::config::standard())
            .map(|(entity, _)| Some(entity))
            .map_err(EntityStorageBackendError::decode)
    }

    pub fn insert<E: Entity>(
        &self,
        address: impl Into<Address>,
        entity: &E,
    ) -> Result<(), EntityStorageBackendError> {
        let key = make_key(None, E::ID, address.into());
        let encoded = bincode::encode_to_vec(entity, bincode::config::standard())
            .map_err(EntityStorageBackendError::encode)?;
        let encoded = BytesOrSlice::from(encoded);

        self.backend.insert(&key, encoded)
    }

    pub fn remove<E: Entity>(
        &self,
        address: impl Into<Address>,
    ) -> Result<(), EntityStorageBackendError> {
        let key = make_key(None, E::ID, address.into());
        self.backend.remove(&key)
    }

    pub fn contains<E: Entity>(
        &self,
        address: impl Into<Address>,
    ) -> Result<bool, EntityStorageBackendError> {
        let key = make_key(None, E::ID, address.into());
        self.backend.contains(&key)
    }

    pub fn iter<E: Entity>(&self) -> Result<EntityIterator<'_, E>, EntityStorageBackendError> {
        let pfx = make_type_prefix(None, E::ID);
        self.backend.iter_prefix(&pfx).map(|iter| {
            Box::new(iter.map(|result| {
                result.and_then(|(key, value)| {
                    let key = extract_address_from_key(&key)?;
                    let val = bincode::decode_from_slice::<E, _>(
                        value.as_slice(),
                        bincode::config::standard(),
                    )
                    .map(|(entity, _)| entity)
                    .map_err(EntityStorageBackendError::decode)?;
                    Ok((key, val))
                })
            })) as EntityIterator<'_, E>
        })
    }

    pub fn keys<E: Entity>(&self) -> Result<EntityKeyIterator<'_>, EntityStorageBackendError> {
        let pfx = make_type_prefix(None, E::ID);
        self.backend.iter_prefix_keys(&pfx).map(|iter| {
            Box::new(iter.map(|result| result.and_then(|key| extract_address_from_key(&key))))
                as EntityKeyIterator<'_>
        })
    }

    pub fn cache_for<E: Entity>(
        &self,
        size: usize,
    ) -> Result<EntityCache<E>, EntityStorageBackendError> {
        EntityCache::new(self.clone(), size)
    }
}

#[cfg(test)]
mod test {
    use uuid::uuid;

    use super::*;
    use crate::types::Address;

    #[test]
    fn test_entity_storage() {
        #[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
        struct TestEntity {
            id: u64,
            name: String,
        }

        impl Entity for TestEntity {
            const ID: Uuid = uuid!("12345678-1234-5678-1234-567812345678");
        }

        let storage = EntityStorage::new(InMemoryEntityStorage::new());

        let entity = TestEntity {
            id: 1,
            name: "Test".to_string(),
        };

        let address = Address::from(42u64);

        // insert entity
        storage.insert(address, &entity).unwrap();

        // get entity
        let retrieved = storage.get::<TestEntity>(address).unwrap();
        assert_eq!(retrieved, Some(entity));

        // check contains
        assert!(storage.contains::<TestEntity>(address).unwrap());

        // remove entity
        storage.remove::<TestEntity>(address).unwrap();
        assert!(!storage.contains::<TestEntity>(address).unwrap());

        // add many entities

        for i in 0..10 {
            let entity = TestEntity {
                id: i,
                name: format!("Entity {}", i),
            };
            storage.insert(Address::from(i as u64), &entity).unwrap();
        }

        // iterate over entities
        let iter = storage.iter::<TestEntity>().unwrap();
        let mut count = 0;
        for val in iter {
            let (address, entity) = val.unwrap();
            let expected = TestEntity {
                id: count,
                name: format!("Entity {}", count),
            };
            assert_eq!(entity, expected);
            assert_eq!(address, Address::from(count as u64));
            count += 1;
        }

        // iterate over keys
        let key_iter = storage.keys::<TestEntity>().unwrap();
        let mut key_count = 0;
        for key in key_iter {
            let address = key.unwrap();
            assert_eq!(address, Address::from(key_count as u64));
            key_count += 1;
        }

        // test a cache
        let cache = storage.cache_for::<TestEntity>(5).unwrap();

        for i in 0..5 {
            let entity = TestEntity {
                id: i,
                name: format!("Entity {}", i),
            };
            let cached = cache.get(Address::from(i as u64)).unwrap();

            assert!(cached.is_some());
            assert_eq!(*cached.unwrap(), entity);
        }

        // test cache insertion
        for i in 50..100 {
            let entity = TestEntity {
                id: i,
                name: format!("New Cached Entity {}", i),
            };
            cache.insert(Address::from(i as u64), entity).unwrap();
        }

        // verify cache contains new entities
        for i in 50..100 {
            let cached = cache.get(Address::from(i as u64)).unwrap();
            assert!(cached.is_some());
            assert_eq!(
                *cached.unwrap(),
                TestEntity {
                    id: i,
                    name: format!("New Cached Entity {}", i)
                }
            );
        }

        // verify cache does not contain old entities
        for i in 50..60 {
            cache.remove(Address::from(i as u64)).unwrap();
            let cached = cache.get(Address::from(i as u64)).unwrap();
            assert!(cached.is_none());

            let direct = storage.get::<TestEntity>(Address::from(i as u64)).unwrap();
            assert!(direct.is_none());
        }
    }
}
