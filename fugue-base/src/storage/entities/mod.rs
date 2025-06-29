use std::fmt::{Debug, Display};
use std::mem::ManuallyDrop;
use std::ops::Deref;
use std::sync::Arc;

use bitflags::bitflags;
use quick_cache::sync::Cache;
use thiserror::Error;

use crate::loader::Loadable;
use crate::types::{AttributeMap, BytesOrSlice};

pub mod common;
pub use common::{Entity, EntityId, EntityKey, EntityKeyId, EntityKeyPrefix, ProjectEntity};

pub mod memory;
pub use memory::InMemoryEntityStorage;

pub mod rocksdb;
pub use rocksdb::RocksDbEntityStorage;

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
    #[error("no project path specified")]
    NoProjectPath,
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
    fn from_loadable(
        loader: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError>
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct EntityRef<E>(Arc<E>)
where
    E: Entity;

impl<E> Display for EntityRef<E>
where
    E: Entity + Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<E> AsRef<E> for EntityRef<E>
where
    E: Entity,
{
    fn as_ref(&self) -> &E {
        &self.0
    }
}

impl<E> Deref for EntityRef<E>
where
    E: Entity,
{
    type Target = E;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<E> EntityRef<E>
where
    E: Entity,
{
    pub(crate) fn new(entity: Arc<E>) -> Self {
        Self(entity)
    }
}

pub trait MutableEntity<K: EntityKey>: Entity {
    fn entity_key(&self) -> K;
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct EntityMutFlags: u8 {
        const NONE = 0b0000_0000;
        const CHANGED = 0b0000_0001;
        const DROPPED = 0b0000_0010;
    }
}

pub struct EntityMut<'a, K: EntityKey, E: Entity + MutableEntity<K>> {
    entity: ManuallyDrop<Arc<E>>,
    flags: EntityMutFlags,
    cache: &'a EntityCache<K, E>,
}

impl<K, E> Debug for EntityMut<'_, K, E>
where
    K: EntityKey,
    E: Entity + MutableEntity<K> + Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntityMut")
            .field("entity", &self.entity)
            .field("flags", &self.flags)
            .finish()
    }
}

impl<K, E> Display for EntityMut<'_, K, E>
where
    K: EntityKey,
    E: Entity + MutableEntity<K> + Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.entity.fmt(f)
    }
}

impl<K, E> PartialEq<E> for EntityMut<'_, K, E>
where
    K: EntityKey,
    E: Entity + MutableEntity<K> + PartialEq,
{
    fn eq(&self, other: &E) -> bool {
        **self.entity == *other
    }
}

impl<K, E> PartialEq for EntityMut<'_, K, E>
where
    K: EntityKey,
    E: Entity + MutableEntity<K> + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.entity == other.entity
    }
}

impl<K, E> Clone for EntityMut<'_, K, E>
where
    K: EntityKey,
    E: Entity + MutableEntity<K>,
{
    fn clone(&self) -> Self {
        Self {
            entity: self.entity.clone(),
            flags: EntityMutFlags::NONE,
            cache: self.cache,
        }
    }
}

impl<K, E> Deref for EntityMut<'_, K, E>
where
    K: EntityKey,
    E: Entity + MutableEntity<K>,
{
    type Target = E;

    fn deref(&self) -> &Self::Target {
        &self.entity
    }
}

impl<K, E> AsMut<E> for EntityMut<'_, K, E>
where
    K: EntityKey,
    E: Entity + MutableEntity<K>,
{
    fn as_mut(&mut self) -> &mut E {
        self.flags |= EntityMutFlags::CHANGED;
        Arc::make_mut(&mut self.entity)
    }
}

impl<K, E> AsRef<E> for EntityMut<'_, K, E>
where
    K: EntityKey,
    E: Entity + MutableEntity<K>,
{
    fn as_ref(&self) -> &E {
        &self.entity
    }
}

impl<'a, K, E> EntityMut<'a, K, E>
where
    K: EntityKey,
    E: Entity + MutableEntity<K>,
{
    pub(crate) fn new(entity: Arc<E>, cache: &'a EntityCache<K, E>) -> Self {
        Self {
            entity: ManuallyDrop::new(entity),
            flags: EntityMutFlags::NONE,
            cache,
        }
    }

    /// SAFETY: Use of the entity after calling this method will lead to undefined behaviour.
    ///
    /// This method is used to persist the entity to the cache and mark it as dropped, it is
    /// a separate method so we can reuse the logic for `EntityMut::drop` and
    /// EntityCache::persist`.
    unsafe fn persist(&mut self) -> Result<(), EntityStorageError> {
        if self.flags.contains(EntityMutFlags::DROPPED) {
            // If the entity was already dropped, we do not persist it again.
            return Ok(());
        }

        // NOTE: if we were not the last reference to the entity, we do not persist it under the
        // assumption that the final version of the entity's modifications will be take
        // prescedence. It's unclear if we should even allow this possibility, as is, we do
        // since EntityMut is clonable.
        let entity_ref = unsafe { ManuallyDrop::take(&mut self.entity) };

        // NOTE: we mark the entity as dropped to avoid persisting it again and potential undefined
        // behaviour if we try to access the entity after this point.
        self.flags.insert(EntityMutFlags::DROPPED);

        if self.flags.contains(EntityMutFlags::CHANGED)
            && let Some(entity) = Arc::into_inner(entity_ref)
        {
            let key = entity.entity_key();
            self.cache.insert(key, entity)?;
        }

        Ok(())
    }
}

impl<K, E> EntityMut<'_, K, E>
where
    K: EntityKey,
    E: Entity + MutableEntity<K>,
{
    pub fn changed(&self) -> bool {
        self.flags.contains(EntityMutFlags::CHANGED)
    }

    pub fn mark_changed(&mut self) {
        self.flags.insert(EntityMutFlags::CHANGED);
    }

    pub fn clear_changed(&mut self) {
        self.flags.remove(EntityMutFlags::CHANGED);
    }
}

impl<K, E> Drop for EntityMut<'_, K, E>
where
    K: EntityKey,
    E: Entity + MutableEntity<K>,
{
    fn drop(&mut self) {
        if let Err(err) = unsafe { self.persist() } {
            tracing::error!("failed to persist entity: {err}");
        }
    }
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

    pub fn get(&self, key: &K) -> Result<Option<EntityRef<E>>, EntityStorageError> {
        if let Some(entity) = self.entities.get(key) {
            return Ok(Some(EntityRef::new(entity)));
        }

        if let Some(entity) = self.storage.get::<K, E>(key)? {
            let entity = Arc::new(entity);
            self.entities.insert(key.to_owned(), entity.to_owned());
            return Ok(Some(EntityRef::new(entity)));
        }

        Ok(None)
    }

    pub fn get_mut(&self, key: &K) -> Result<Option<EntityMut<'_, K, E>>, EntityStorageError>
    where
        E: MutableEntity<K>,
    {
        Ok(self.get(key)?.map(|e| EntityMut::new(e.0, self)))
    }

    pub fn persist(&self, mut entity: EntityMut<'_, K, E>) -> Result<(), EntityStorageError>
    where
        E: MutableEntity<K>,
    {
        unsafe { entity.persist() }
    }

    pub fn contains(&self, key: &K) -> Result<bool, EntityStorageError> {
        if self.entities.contains_key(key) {
            return Ok(true);
        }

        self.storage.contains::<K, E>(key)
    }

    pub fn insert(&self, key: K, entity: E) -> Result<EntityRef<E>, EntityStorageError> {
        // NOTE: we could check if the entity already exists in the cache and if it is the same,
        // then we exit early. Similarly, we could check if the entity exists in the storage
        // backing and if it is the same, then avoid inserting it again.

        self.storage.insert(&key, &entity)?;

        let entity = Arc::new(entity);

        self.entities.insert(key, entity.clone());

        Ok(EntityRef::new(entity))
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

    pub fn iter(&self) -> Result<EntityIterator<'_, K, EntityRef<E>>, EntityStorageError> {
        // TODO: should we cache the elements in the iterator if the cache has capacity?
        let pfx = common::make_prefix::<K, E>();
        self.storage.backing.iter_prefix(&pfx).map(|iter| {
            Box::new(iter.map(|result| {
                result.and_then(|(key, value)| {
                    let key = common::extract_key::<K, E>(key)
                        .ok_or(EntityStorageError::InvalidKeyFormat)?;
                    if let Some(val) = self.entities.get(&key) {
                        return Ok((key, EntityRef::new(val)));
                    }

                    let val = bincode::decode_from_slice::<E, _>(
                        value.as_slice(),
                        bincode::config::standard(),
                    )
                    .map(|(entity, _)| entity)
                    .map_err(EntityStorageError::decode)?;

                    Ok((key, EntityRef::new(Arc::new(val))))
                })
            })) as EntityIterator<'_, K, EntityRef<E>>
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
