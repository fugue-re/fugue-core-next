use std::sync::Arc;

use quick_cache::sync::Cache;
use thiserror::Error;

pub mod common;
pub use common::{Entity, EntityId, EntityKey, EntityKeyId, EntityKeyPrefix};

pub mod memory;
pub use memory::InMemoryEntityStorage;

pub mod rocksdb;
pub use rocksdb::RocksDbEntityStorage;

use crate::loader::Loadable;
use crate::types::BytesOrSlice;

pub type DefaultPersistentEntityStorage = RocksDbEntityStorage;
pub type DefaultTransientEntityStorage = InMemoryEntityStorage;

#[derive(Debug, Error)]
pub enum EntityStorageError {
    #[error(transparent)]
    Backing(anyhow::Error),
    #[error("failed to decode entity: {0}")]
    Decode(anyhow::Error),
    #[error("failed to encode entity: {0}")]
    Encode(anyhow::Error),
    #[error("invalid key format")]
    InvalidKeyFormat,
    #[error("invalid key size")]
    InvalidKeySize,
}

impl EntityStorageError {
    pub fn encode<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Encode(anyhow::Error::from(err))
    }

    pub fn decode<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Decode(anyhow::Error::from(err))
    }

    pub fn backing<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Backing(anyhow::Error::from(err))
    }

    pub fn backing_with<M>(msg: M) -> Self
    where
        M: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    {
        Self::Backing(anyhow::Error::msg(msg))
    }
}

pub trait EntityStorageBulkInserter<'a> {
    fn insert(
        &mut self,
        key: BytesOrSlice<'a>,
        value: BytesOrSlice<'a>,
    ) -> Result<(), EntityStorageError>;
    fn finish(self: Box<Self>) -> Result<(), EntityStorageError>;
}

pub type EntityBytesIterator<'a> =
    Box<dyn Iterator<Item = Result<(BytesOrSlice<'a>, BytesOrSlice<'a>), EntityStorageError>> + 'a>;

pub type EntityKeyBytesIterator<'a> =
    Box<dyn Iterator<Item = Result<BytesOrSlice<'a>, EntityStorageError>> + 'a>;

pub type EntityIterator<'a, K, E> =
    Box<dyn Iterator<Item = Result<(K, E), EntityStorageError>> + 'a>;

pub type EntityKeyIterator<'a, K> = Box<dyn Iterator<Item = Result<K, EntityStorageError>> + 'a>;

pub type EntityBytesBulkInserter<'a> = Box<dyn EntityStorageBulkInserter<'a> + 'a>;

pub struct EntityBulkInserter<'a> {
    inner: EntityBytesBulkInserter<'a>,
}

impl<'a> EntityBulkInserter<'a> {
    pub fn new(inner: EntityBytesBulkInserter<'a>) -> Self {
        Self { inner }
    }

    pub fn insert<K: EntityKey, E: Entity>(
        &mut self,
        key: &K,
        entity: &E,
    ) -> Result<(), EntityStorageError> {
        let key = common::make_key::<K, E>(key);
        let encoded = bincode::encode_to_vec(entity, bincode::config::standard())
            .map_err(EntityStorageError::encode)?;

        let key = BytesOrSlice::from(key);
        let encoded = BytesOrSlice::from(encoded);

        self.inner.insert(key, encoded)
    }

    pub fn finish(self) -> Result<(), EntityStorageError> {
        self.inner.finish()
    }
}

pub trait EntityStorageProviderFromLoadable: EntityStorageProvider + 'static {
    // Creates a new storage provider from the given loadable object.
    fn from_loadable(loader: &impl Loadable) -> Result<Self, EntityStorageError>
    where
        Self: Sized;
}

pub trait EntityStorageProvider: Send + Sync {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError>;
    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError>;
    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError>;
    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError>;

    fn iter_prefix_keys(
        &self,
        prefix: &[u8],
    ) -> Result<EntityKeyBytesIterator<'_>, EntityStorageError>;
    fn iter_prefix(&self, prefix: &[u8]) -> Result<EntityBytesIterator<'_>, EntityStorageError>;

    fn bulk_inserter(&self) -> Result<EntityBytesBulkInserter, EntityStorageError>;
}

pub struct EntityCache<K: EntityKey, E: Entity> {
    entities: Cache<K, Arc<E>>,
    storage: EntityStorage,
}

impl<K, E> EntityCache<K, E>
where
    K: EntityKey,
    E: Entity,
{
    pub fn new(storage: EntityStorage, size: usize) -> Result<Self, EntityStorageError> {
        Ok(Self {
            entities: Cache::new(size),
            storage,
        })
    }

    pub fn get(&self, key: &K) -> Result<Option<Arc<E>>, EntityStorageError> {
        if let Some(entity) = self.entities.get(key) {
            return Ok(Some(entity.clone()));
        }

        if let Some(entity) = self.storage.get::<K, E>(key)? {
            let entity = Arc::new(entity);
            self.entities.insert(*key, entity.clone());
            return Ok(Some(entity));
        }

        Ok(None)
    }

    pub fn contains(&self, key: &K) -> Result<bool, EntityStorageError> {
        if self.entities.contains_key(key) {
            return Ok(true);
        }

        self.storage.contains::<K, E>(key)
    }

    pub fn insert(&self, key: K, entity: E) -> Result<(), EntityStorageError> {
        // NOTE: we could check if the entity already exists in the cache and if it is the same,
        // then we exit early. Similarly, we could check if the entity exists in the storage
        // backing and if it is the same, then avoid inserting it again.

        self.storage.insert(&key, &entity)?;
        self.entities.insert(key, Arc::new(entity));

        Ok(())
    }

    pub fn bulk_inserter(&self) -> Result<EntityBulkInserter, EntityStorageError> {
        // NOTE: this will bypass the cache and directly insert into the storage backing
        // we therefore clear the cache to avoid inconsistencies

        self.entities.clear();
        self.storage.bulk_inserter()
    }

    pub fn remove(&self, key: &K) -> Result<(), EntityStorageError> {
        self.storage.remove::<K, E>(key)?;
        self.entities.remove(key);

        Ok(())
    }

    pub fn keys(&self) -> Result<EntityKeyIterator<'_, K>, EntityStorageError> {
        self.storage.keys::<K, E>()
    }

    pub fn iter(&self) -> Result<EntityIterator<'_, K, Arc<E>>, EntityStorageError> {
        // TODO: should we cache the elements in the iterator if the cache has capacity?
        let pfx = common::make_prefix::<K, E>();
        self.storage.backing.iter_prefix(&pfx).map(|iter| {
            Box::new(iter.map(|result| {
                result.and_then(|(key, value)| {
                    let key = common::extract_key::<K, E>(key)
                        .ok_or(EntityStorageError::InvalidKeyFormat)?;
                    if let Some(val) = self.entities.get(&key) {
                        return Ok((key, val));
                    }

                    let val = bincode::decode_from_slice::<E, _>(
                        value.as_slice(),
                        bincode::config::standard(),
                    )
                    .map(|(entity, _)| entity)
                    .map_err(EntityStorageError::decode)?;

                    Ok((key, Arc::new(val)))
                })
            })) as EntityIterator<'_, K, Arc<E>>
        })
    }
}

#[derive(Clone)]
pub struct EntityStorage {
    backing: Arc<dyn EntityStorageProvider>,
}

impl EntityStorage {
    pub fn new(backing: impl EntityStorageProvider + 'static) -> Self {
        Self {
            backing: Arc::new(backing),
        }
    }

    pub fn get<K: EntityKey, E: Entity>(&self, key: &K) -> Result<Option<E>, EntityStorageError> {
        let key = common::make_key::<K, E>(key);
        let Some(val) = self.backing.get(&key)? else {
            return Ok(None);
        };

        bincode::decode_from_slice::<E, _>(val.as_slice(), bincode::config::standard())
            .map(|(entity, _)| Some(entity))
            .map_err(EntityStorageError::decode)
    }

    pub fn insert<K: EntityKey, E: Entity>(
        &self,
        key: &K,
        entity: &E,
    ) -> Result<(), EntityStorageError> {
        let key = common::make_key::<K, E>(key);
        let encoded = bincode::encode_to_vec(entity, bincode::config::standard())
            .map_err(EntityStorageError::encode)?;
        let encoded = BytesOrSlice::from(encoded);

        self.backing.insert(&key, encoded)
    }

    pub fn bulk_inserter(&self) -> Result<EntityBulkInserter, EntityStorageError> {
        Ok(EntityBulkInserter::new(self.backing.bulk_inserter()?))
    }

    pub fn remove<K: EntityKey, E: Entity>(&self, key: &K) -> Result<(), EntityStorageError> {
        let key = common::make_key::<K, E>(key);
        self.backing.remove(&key)
    }

    pub fn contains<K: EntityKey, E: Entity>(&self, key: &K) -> Result<bool, EntityStorageError> {
        let key = common::make_key::<K, E>(key);
        self.backing.contains(&key)
    }

    pub fn iter<K: EntityKey, E: Entity>(
        &self,
    ) -> Result<EntityIterator<'_, K, E>, EntityStorageError> {
        let pfx = common::make_prefix::<K, E>();
        self.backing.iter_prefix(&pfx).map(|iter| {
            Box::new(iter.map(|result| {
                result.and_then(|(key, value)| {
                    let key = common::extract_key::<K, E>(key)
                        .ok_or(EntityStorageError::InvalidKeyFormat)?;
                    let val = bincode::decode_from_slice::<E, _>(
                        value.as_slice(),
                        bincode::config::standard(),
                    )
                    .map(|(entity, _)| entity)
                    .map_err(EntityStorageError::decode)?;
                    Ok((key, val))
                })
            })) as EntityIterator<'_, K, E>
        })
    }

    pub fn keys<K: EntityKey, E: Entity>(
        &self,
    ) -> Result<EntityKeyIterator<'_, K>, EntityStorageError> {
        let pfx = common::make_prefix::<K, E>();
        self.backing.iter_prefix_keys(&pfx).map(|iter| {
            Box::new(iter.map(|result| {
                result.and_then(|key| {
                    common::extract_key::<K, E>(key).ok_or(EntityStorageError::InvalidKeyFormat)
                })
            })) as EntityKeyIterator<'_, K>
        })
    }

    pub fn cache_for<K: EntityKey, E: Entity>(
        &self,
        size: usize,
    ) -> Result<EntityCache<K, E>, EntityStorageError> {
        EntityCache::new(self.clone(), size)
    }
}

#[cfg(test)]
mod test {
    use bincode::{Decode, Encode};

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
            const ID: EntityId = 0;
        }

        let storage = EntityStorage::new(InMemoryEntityStorage::new());

        let entity = TestEntity {
            id: 1,
            name: "Test".to_string(),
        };

        let address = Address::from(42u64);

        // insert entity
        storage.insert(&address, &entity).unwrap();

        // get entity
        let retrieved = storage.get::<_, TestEntity>(&address).unwrap();
        assert_eq!(retrieved, Some(entity));

        // check contains
        assert!(storage.contains::<_, TestEntity>(&address).unwrap());

        // remove entity
        storage.remove::<_, TestEntity>(&address).unwrap();
        assert!(!storage.contains::<_, TestEntity>(&address).unwrap());

        // add many entities
        for i in 0..10 {
            let entity = TestEntity {
                id: i,
                name: format!("Entity {}", i),
            };
            storage.insert(&Address::from(i as u64), &entity).unwrap();
        }

        // iterate over entities
        let iter = storage.iter::<Address, TestEntity>().unwrap();
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
        let key_iter = storage.keys::<Address, TestEntity>().unwrap();
        let mut key_count = 0;
        for key in key_iter {
            let address = key.unwrap();
            assert_eq!(address, Address::from(key_count as u64));
            key_count += 1;
        }

        // test a cache
        let cache = storage.cache_for::<Address, TestEntity>(5).unwrap();

        for i in 0..5 {
            let entity = TestEntity {
                id: i,
                name: format!("Entity {}", i),
            };
            let cached = cache.get(&Address::from(i as u64)).unwrap();

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
            let cached = cache.get(&Address::from(i as u64)).unwrap();
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
            cache.remove(&Address::from(i as u64)).unwrap();
            let cached = cache.get(&Address::from(i as u64)).unwrap();
            assert!(cached.is_none());

            let direct = storage
                .get::<Address, TestEntity>(&Address::from(i as u64))
                .unwrap();
            assert!(direct.is_none());
        }
    }
}
