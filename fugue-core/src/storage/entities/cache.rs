use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;
use std::ops::{Bound, Deref, DerefMut};
use std::sync::Arc;

use bytes::Bytes;
use quick_cache::Weighter;
use quick_cache::sync::Cache;

use super::{
    Entity, EntityIterator, EntityKey, EntityStorage, EntityStorageError, WriteBackAction,
    WriteBackWorker, decode_entity, schema,
};
use crate::types::BytesOrSlice;

const ENTITY_CACHE_ENTRY_OVERHEAD: u32 = 64;
const ENTITY_CACHE_ESTIMATED_ENTRY_SIZE: usize = 256;
const ENTITY_CACHE_MAINTENANCE_BATCH_COUNT: usize = 256;

type EntityLru<K, E> = Cache<K, Cached<E>, ByteWeighter>;
type PendingRange<'a, K, E> = Vec<(K, Option<CachedRef<'a, E>>)>;

#[derive(Clone)]
struct Cached<E> {
    value: Arc<E>,
    weight: u32,
}

#[derive(Clone, Copy)]
struct ByteWeighter;

impl ByteWeighter {
    fn entry_weight(encoded_len: usize) -> u32 {
        u32::try_from(encoded_len)
            .unwrap_or(u32::MAX)
            .saturating_add(ENTITY_CACHE_ENTRY_OVERHEAD)
    }
}

impl<K, E: Entity> Weighter<K, Cached<E>> for ByteWeighter {
    fn weight(&self, _key: &K, value: &Cached<E>) -> u64 {
        u64::from(value.weight)
    }
}

#[derive(Clone)]
enum WriteSink {
    Worker(Arc<WriteBackWorker>),
    WriteThrough,
}

#[derive(Clone)]
pub(crate) struct EntityCache<K: EntityKey, E: Entity> {
    entities: Arc<EntityLru<K, E>>,
    storage: EntityStorage,
    sink: WriteSink,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub(crate) struct CachedRef<'a, E>(Arc<E>, PhantomData<&'a E>)
where
    E: Entity;

impl<E> Display for CachedRef<'_, E>
where
    E: Entity + Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<E> AsRef<E> for CachedRef<'_, E>
where
    E: Entity,
{
    fn as_ref(&self) -> &E {
        &self.0
    }
}

impl<E> Deref for CachedRef<'_, E>
where
    E: Entity,
{
    type Target = E;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, E> CachedRef<'a, E>
where
    E: Entity,
{
    pub fn new(entity: E) -> Self {
        Self(Arc::new(entity), PhantomData)
    }

    pub fn from_arc(entity: Arc<E>) -> Self {
        Self(entity, PhantomData)
    }

    pub fn into_arc(self) -> Arc<E> {
        self.0
    }
}

pub(crate) struct CachedMut<'a, E>
where
    E: MutableEntity,
{
    cache: &'a EntityCache<E::Key, E>,
    entity: Arc<E>,
    dirty: bool,
}

impl<E> Deref for CachedMut<'_, E>
where
    E: MutableEntity,
{
    type Target = E;

    fn deref(&self) -> &Self::Target {
        self.entity.as_ref()
    }
}

impl<E> DerefMut for CachedMut<'_, E>
where
    E: MutableEntity,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.dirty = true;
        Arc::make_mut(&mut self.entity)
    }
}

impl<E> Drop for CachedMut<'_, E>
where
    E: MutableEntity,
{
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }

        if self.dirty {
            let key = self.entity.entity_key();
            self.cache.put(key, Arc::clone(&self.entity));
        }
    }
}

pub struct EntityRef<'a, E>(RefRepr<'a, E>)
where
    E: Entity;

enum RefRepr<'a, E>
where
    E: Entity,
{
    Borrowed(&'a E),
    Cached(CachedRef<'a, E>),
}

impl<'a, E> EntityRef<'a, E>
where
    E: Entity,
{
    pub(crate) fn borrowed(entity: &'a E) -> Self {
        Self(RefRepr::Borrowed(entity))
    }

    pub(crate) fn cached(entity: CachedRef<'a, E>) -> Self {
        Self(RefRepr::Cached(entity))
    }

    pub(crate) fn owned(entity: E) -> Self {
        Self::cached(CachedRef::new(entity))
    }
}

impl<E> Deref for EntityRef<'_, E>
where
    E: Entity,
{
    type Target = E;

    fn deref(&self) -> &Self::Target {
        match &self.0 {
            RefRepr::Borrowed(entity) => entity,
            RefRepr::Cached(entity) => entity.as_ref(),
        }
    }
}

pub struct EntityMut<'a, E>(MutRepr<'a, E>)
where
    E: MutableEntity;

enum MutRepr<'a, E>
where
    E: MutableEntity,
{
    Borrowed(&'a mut E),
    Cached(CachedMut<'a, E>),
}

impl<'a, E> EntityMut<'a, E>
where
    E: MutableEntity,
{
    pub(crate) fn borrowed(entity: &'a mut E) -> Self {
        Self(MutRepr::Borrowed(entity))
    }

    pub(crate) fn cached(entity: CachedMut<'a, E>) -> Self {
        Self(MutRepr::Cached(entity))
    }
}

impl<E> Deref for EntityMut<'_, E>
where
    E: MutableEntity,
{
    type Target = E;

    fn deref(&self) -> &Self::Target {
        match &self.0 {
            MutRepr::Borrowed(entity) => entity,
            MutRepr::Cached(guard) => guard,
        }
    }
}

impl<E> DerefMut for EntityMut<'_, E>
where
    E: MutableEntity,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        match &mut self.0 {
            MutRepr::Borrowed(entity) => entity,
            MutRepr::Cached(guard) => guard,
        }
    }
}

pub trait MutableEntity: Entity {
    type Key: EntityKey;

    fn entity_key(&self) -> Self::Key;
}

impl<K, E> EntityCache<K, E>
where
    K: EntityKey,
    E: Entity,
{
    pub fn new(storage: EntityStorage, capacity: usize) -> Result<Self, EntityStorageError> {
        let sink = if storage.is_transient() {
            WriteSink::WriteThrough
        } else {
            WriteSink::Worker(WriteBackWorker::new(storage.clone())?)
        };

        Ok(Self::build(storage, sink, capacity))
    }

    pub fn with_worker(
        storage: EntityStorage,
        worker: Arc<WriteBackWorker>,
        capacity: usize,
    ) -> Self {
        Self::build(storage, WriteSink::Worker(worker), capacity)
    }

    pub fn from_storage(
        storage: EntityStorage,
        worker: Option<Arc<WriteBackWorker>>,
        capacity: usize,
    ) -> Result<Self, EntityStorageError> {
        match worker {
            Some(worker) => Ok(Self::with_worker(storage, worker, capacity)),
            None => Self::new(storage, capacity),
        }
    }

    fn build(storage: EntityStorage, sink: WriteSink, capacity: usize) -> Self {
        let weight_capacity = capacity.max(1) as u64;
        let estimated_items = (capacity / ENTITY_CACHE_ESTIMATED_ENTRY_SIZE).max(1);
        let entities = Cache::with_weighter(estimated_items, weight_capacity, ByteWeighter);

        Self {
            entities: Arc::new(entities),
            storage,
            sink,
        }
    }

    pub fn try_get(&self, key: &K) -> Result<Option<CachedRef<'_, E>>, EntityStorageError> {
        if let Some(cached) = self.entities.get(key) {
            return Ok(Some(CachedRef::from_arc(cached.value)));
        }

        if let WriteSink::Worker(worker) = &self.sink {
            let key_bytes = schema::make_key::<K, E>(key);
            if let Some(pending) = worker.pending(&key_bytes) {
                return match pending {
                    WriteBackAction::Insert(bytes) => {
                        let entity = decode_entity(&bytes)?;
                        Ok(Some(self.admit(
                            key.clone(),
                            Arc::new(entity),
                            ByteWeighter::entry_weight(bytes.len()),
                        )))
                    }
                    WriteBackAction::Remove => Ok(None),
                };
            }
        }

        let Some((entity, weight)) = self.fetch(key)? else {
            return Ok(None);
        };

        Ok(Some(self.admit(key.clone(), Arc::new(entity), weight)))
    }

    fn admit(&self, key: K, entity: Arc<E>, weight: u32) -> CachedRef<'_, E> {
        self.entities.insert(
            key,
            Cached {
                value: entity.clone(),
                weight,
            },
        );

        CachedRef::from_arc(entity)
    }

    pub fn get(&self, key: &K) -> Option<CachedRef<'_, E>> {
        self.try_get(key).unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_put(
        &self,
        key: K,
        entity: impl Into<Arc<E>>,
    ) -> Result<CachedRef<'_, E>, EntityStorageError> {
        let entity = entity.into();
        let weight = self.stage(&key, entity.as_ref())?;

        Ok(self.admit(key, entity, weight))
    }

    pub fn put(&self, key: K, entity: impl Into<Arc<E>>) -> CachedRef<'_, E> {
        self.try_put(key, entity)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub(crate) fn publish_put(
        &self,
        key: K,
        entity: impl Into<Arc<E>>,
        encoded_len: usize,
    ) -> CachedRef<'_, E> {
        self.admit(key, entity.into(), ByteWeighter::entry_weight(encoded_len))
    }

    pub fn try_remove(&self, key: &K) -> Result<(), EntityStorageError> {
        match &self.sink {
            WriteSink::WriteThrough => self.storage.remove::<K, E>(key)?,
            WriteSink::Worker(worker) => {
                let key_bytes = schema::make_key::<K, E>(key);
                worker.enqueue(key_bytes, None)?;
            }
        }

        self.entities.remove(key);

        Ok(())
    }

    pub(crate) fn publish_remove(&self, key: &K) {
        self.entities.remove(key);
    }

    pub fn try_iter(&self) -> Result<EntityIterator<'_, K, CachedRef<'_, E>>, EntityStorageError> {
        self.flush()?;

        let entities = self.entities.clone();
        let iter = self.storage.iter::<K, E>()?.map(move |result| {
            result.map(|(key, value)| {
                let value = Self::reference_for(&entities, &key, value);
                (key, value)
            })
        });

        Ok(Box::new(iter))
    }

    pub fn try_iter_range(
        &self,
        start: Bound<&K>,
    ) -> Result<EntityIterator<'_, K, CachedRef<'_, E>>, EntityStorageError>
    where
        K: Ord,
    {
        match &self.sink {
            WriteSink::WriteThrough => self.iter_backing_range(start),
            WriteSink::Worker(worker) => {
                let prefix = schema::make_prefix::<K, E>();
                let start_key = Self::range_start_key(start);
                let pending_start = start_key.as_ref().map(|key| key.as_ref());
                let pending = worker.pending_range(&prefix, pending_start)?;
                let pending = self.decode_pending_range(pending)?;
                let backing = self.storage.iter_range::<K, E>(start)?;

                Ok(Box::new(self.merge_pending_range(backing, pending)))
            }
        }
    }

    pub fn try_iter_batch(
        &self,
        start: Bound<&K>,
    ) -> Result<Vec<(K, CachedRef<'_, E>)>, EntityStorageError>
    where
        K: Ord,
    {
        self.try_iter_range(start)?
            .take(ENTITY_CACHE_MAINTENANCE_BATCH_COUNT)
            .collect()
    }

    pub fn try_clear(&self) -> Result<(), EntityStorageError>
    where
        K: Ord,
    {
        loop {
            let entries = self.try_iter_batch(Bound::Unbounded)?;
            if entries.is_empty() {
                return Ok(());
            }
            for (key, _) in entries {
                self.try_remove(&key)?;
            }
        }
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        match &self.sink {
            WriteSink::WriteThrough => Ok(()),
            WriteSink::Worker(worker) => worker.flush(),
        }
    }

    fn fetch(&self, key: &K) -> Result<Option<(E, u32)>, EntityStorageError> {
        self.storage.get_as::<K, E, _, _>(key, |bytes| {
            let entity = decode_entity(bytes)?;
            Ok((entity, ByteWeighter::entry_weight(bytes.len())))
        })
    }

    fn iter_backing_range(
        &self,
        start: Bound<&K>,
    ) -> Result<EntityIterator<'_, K, CachedRef<'_, E>>, EntityStorageError> {
        let entities = self.entities.clone();
        let iter = self.storage.iter_range::<K, E>(start)?.map(move |result| {
            result.map(|(key, value)| {
                let value = Self::reference_for(&entities, &key, value);
                (key, value)
            })
        });

        Ok(Box::new(iter))
    }

    fn range_start_key(start: Bound<&K>) -> Bound<Bytes> {
        match start {
            Bound::Included(key) => Bound::Included(schema::make_key::<K, E>(key)),
            Bound::Excluded(key) => Bound::Excluded(schema::make_key::<K, E>(key)),
            Bound::Unbounded => Bound::Unbounded,
        }
    }

    fn decode_pending_range(
        &self,
        pending: Vec<(Bytes, WriteBackAction)>,
    ) -> Result<PendingRange<'_, K, E>, EntityStorageError> {
        pending
            .into_iter()
            .map(|(key, action)| {
                let key = schema::extract_key::<K, E>(BytesOrSlice::from(key))
                    .ok_or(EntityStorageError::InvalidKeyFormat)?;
                let value = match action {
                    WriteBackAction::Insert(bytes) => {
                        let entity = decode_entity(&bytes)?;
                        Some(Self::reference_for(&self.entities, &key, entity))
                    }
                    WriteBackAction::Remove => None,
                };
                Ok((key, value))
            })
            .collect()
    }

    fn merge_pending_range<'a>(
        &'a self,
        mut backing: EntityIterator<'a, K, E>,
        pending: Vec<(K, Option<CachedRef<'a, E>>)>,
    ) -> impl Iterator<Item = Result<(K, CachedRef<'a, E>), EntityStorageError>> + 'a
    where
        K: Ord,
    {
        let entities = self.entities.clone();
        let mut pending = pending.into_iter().peekable();
        let mut buffered = None;

        std::iter::from_fn(move || {
            loop {
                if buffered.is_none() {
                    buffered = backing.next();
                }

                match (pending.peek(), buffered.as_ref()) {
                    (None, None) => return None,
                    (Some(_), None) => {
                        let (key, value) = pending.next()?;
                        if let Some(value) = value {
                            return Some(Ok((key, value)));
                        }
                    }
                    (None, Some(_)) => return Self::take_backing(&entities, &mut buffered),
                    (Some((pending_key, _)), Some(Ok((backing_key, _)))) => {
                        match pending_key.cmp(backing_key) {
                            std::cmp::Ordering::Less => {
                                let (key, value) = pending.next()?;
                                if let Some(value) = value {
                                    return Some(Ok((key, value)));
                                }
                            }
                            std::cmp::Ordering::Equal => {
                                let _ = buffered.take();
                                let (key, value) = pending.next()?;
                                if let Some(value) = value {
                                    return Some(Ok((key, value)));
                                }
                            }
                            std::cmp::Ordering::Greater => {
                                return Self::take_backing(&entities, &mut buffered);
                            }
                        }
                    }
                    (Some(_), Some(Err(_))) => {
                        let Some(Err(error)) = buffered.take() else {
                            unreachable!("buffered value was checked as an error");
                        };
                        return Some(Err(error));
                    }
                }
            }
        })
    }

    fn take_backing<'a>(
        entities: &EntityLru<K, E>,
        buffered: &mut Option<Result<(K, E), EntityStorageError>>,
    ) -> Option<Result<(K, CachedRef<'a, E>), EntityStorageError>> {
        buffered.take().map(|result| {
            result.map(|(key, value)| {
                let value = Self::reference_for(entities, &key, value);
                (key, value)
            })
        })
    }

    fn reference_for<'a>(entities: &EntityLru<K, E>, key: &K, value: E) -> CachedRef<'a, E> {
        match entities.get(key) {
            Some(cached) => CachedRef::from_arc(cached.value),
            None => CachedRef::new(value),
        }
    }

    fn stage(&self, key: &K, entity: &E) -> Result<u32, EntityStorageError> {
        let encoded =
            rkyv::to_bytes::<rkyv::rancor::Error>(entity).map_err(EntityStorageError::encode)?;
        let weight = ByteWeighter::entry_weight(encoded.len());

        match &self.sink {
            WriteSink::WriteThrough => {
                self.storage
                    .insert_bytes::<K, E>(key, BytesOrSlice::from(encoded.as_ref()))?;
            }
            WriteSink::Worker(worker) => {
                let key_bytes = schema::make_key::<K, E>(key);
                worker.enqueue(key_bytes, Some(Bytes::from_owner(encoded)))?;
            }
        }

        Ok(weight)
    }
}

impl<K, E> EntityCache<K, E>
where
    K: EntityKey,
    E: MutableEntity<Key = K>,
{
    pub(crate) fn iter_disjoint_mut<'a>(
        &'a self,
        keys: impl IntoIterator<Item = K> + 'a,
    ) -> impl Iterator<Item = CachedMut<'a, E>> + 'a {
        keys.into_iter().filter_map(move |key| {
            let current = self
                .try_get(&key)
                .unwrap_or_else(|error| error.into_fatal())?;

            Some(CachedMut {
                cache: self,
                entity: current.into_arc(),
                dirty: false,
            })
        })
    }

    pub fn try_get_mut(&mut self, key: &K) -> Result<Option<CachedMut<'_, E>>, EntityStorageError> {
        let Some(current) = self.try_get(key)? else {
            return Ok(None);
        };

        Ok(Some(CachedMut {
            cache: &*self,
            entity: current.into_arc(),
            dirty: false,
        }))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = CachedMut<'_, E>> + '_ {
        let cache = &*self;

        cache
            .try_iter()
            .unwrap_or_else(|error| error.into_fatal())
            .map(move |entry| {
                let (_, current) = entry.unwrap_or_else(|error| error.into_fatal());

                CachedMut {
                    cache,
                    entity: current.into_arc(),
                    dirty: false,
                }
            })
    }

    pub fn try_modify<R>(
        &mut self,
        key: &K,
        f: impl FnOnce(&mut E) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        let Some(mut entity) = self.try_get_mut(key)? else {
            return Ok(None);
        };

        Ok(Some(f(&mut entity)))
    }
}

#[cfg(test)]
mod test {
    use std::ops::Bound;
    use std::time::Duration;

    use super::*;
    use crate::ir::Address;
    use crate::storage::entities::{
        Entity, EntityBytesAsIterator, EntityBytesIterator, EntityBytesTransactionalReader,
        EntityBytesTransactionalWriter, EntityId, EntityKeyBytesIterator, EntityStorage,
        EntityStorageError, EntityStorageProvider, InMemoryEntityStorage, WriteBackWorker,
    };
    use crate::types::BytesOrSlice;

    #[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    struct CacheEntity {
        id: u64,
        name: String,
    }

    impl Entity for CacheEntity {
        const ID: EntityId = EntityId::new(0);
    }

    impl MutableEntity for CacheEntity {
        type Key = Address;

        fn entity_key(&self) -> Address {
            Address::from(self.id)
        }
    }

    struct FailingWriteProvider(InMemoryEntityStorage);

    impl EntityStorageProvider for FailingWriteProvider {
        fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
            self.0.get(key)
        }

        fn get_as<F, T>(&self, key: &[u8], f: F) -> Result<Option<T>, EntityStorageError>
        where
            F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
        {
            self.0.get_as(key, f)
        }

        fn insert(&self, _key: &[u8], _value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
            Err(EntityStorageError::backing_with("write failed"))
        }

        fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
            self.0.remove(key)
        }

        fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
            self.0.contains(key)
        }

        fn iter_prefix_keys(
            &self,
            prefix: &[u8],
        ) -> Result<EntityKeyBytesIterator<'_>, EntityStorageError> {
            self.0.iter_prefix_keys(prefix)
        }

        fn iter_prefix(
            &self,
            prefix: &[u8],
        ) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
            self.0.iter_prefix(prefix)
        }

        fn iter_range(
            &self,
            prefix: &[u8],
            start: Bound<&[u8]>,
        ) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
            self.0.iter_range(prefix, start)
        }

        fn iter_prefix_as<'a, F, T>(
            &'a self,
            prefix: &[u8],
            f: F,
        ) -> Result<EntityBytesAsIterator<'a, T>, EntityStorageError>
        where
            F: FnMut(&[u8], &[u8]) -> Result<T, EntityStorageError> + 'a,
            T: 'a,
        {
            self.0.iter_prefix_as(prefix, f)
        }

        fn transactional_reader(
            &self,
        ) -> Result<EntityBytesTransactionalReader, EntityStorageError> {
            self.0.transactional_reader()
        }

        fn transactional_writer(
            &self,
        ) -> Result<EntityBytesTransactionalWriter, EntityStorageError> {
            Err(EntityStorageError::unsupported_with(
                "failing provider has no transactional writer",
            ))
        }
    }

    fn cache_entity(id: u64, name: &str) -> CacheEntity {
        CacheEntity {
            id,
            name: name.to_owned(),
        }
    }

    #[test]
    fn cache_reads_survive_eviction() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let cache = EntityCache::<Address, CacheEntity>::new(storage.clone(), 128).unwrap();

        let key = Address::from(1u64);
        cache.put(key, cache_entity(1, "one"));

        for i in 100u64..200 {
            cache.put(Address::from(i), cache_entity(i, "filler"));
        }

        let retrieved = cache
            .get(&key)
            .expect("entry reloads from storage after eviction");
        assert_eq!(*retrieved, cache_entity(1, "one"));
    }

    #[test]
    fn cache_iter_range_starts_at_cursor() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let cache = EntityCache::<Address, CacheEntity>::new(storage, 128).unwrap();

        for value in 1..=4 {
            cache.put(Address::from(value), cache_entity(value, "entry"));
        }

        let values = cache
            .try_iter_range(Bound::Excluded(&Address::from(2u64)))
            .unwrap()
            .map(|entry| entry.map(|(_, entity)| entity.id))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(values, vec![3, 4]);
    }

    #[test]
    fn cache_modify_persists_through_to_storage() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let mut cache =
            EntityCache::<Address, CacheEntity>::new(storage.clone(), 64 * 1024).unwrap();

        let key = Address::from(7u64);
        cache.put(key, cache_entity(7, "before"));

        let outcome = cache
            .try_modify(&key, |entity| {
                entity.name = "after".to_owned();
                entity.id
            })
            .unwrap();
        assert_eq!(outcome, Some(7));

        let stored = storage.get::<Address, CacheEntity>(&key).unwrap();
        assert_eq!(stored, Some(cache_entity(7, "after")));
    }

    #[test]
    fn cache_modify_missing_entry_returns_none() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let mut cache =
            EntityCache::<Address, CacheEntity>::new(storage.clone(), 64 * 1024).unwrap();

        let outcome = cache
            .try_modify(&Address::from(11u64), |entity: &mut CacheEntity| entity.id)
            .unwrap();
        assert_eq!(outcome, None);
    }

    #[test]
    fn cache_get_mut_persists_on_drop() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let mut cache =
            EntityCache::<Address, CacheEntity>::new(storage.clone(), 64 * 1024).unwrap();

        let key = Address::from(13u64);
        cache.put(key, cache_entity(13, "before"));

        {
            let mut guard = cache.try_get_mut(&key).unwrap().expect("entry exists");
            guard.name = "after".to_owned();
        }

        let stored = storage.get::<Address, CacheEntity>(&key).unwrap();
        assert_eq!(stored, Some(cache_entity(13, "after")));
    }

    #[test]
    fn cache_remove_hides_entry_everywhere() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let cache = EntityCache::<Address, CacheEntity>::new(storage.clone(), 64 * 1024).unwrap();

        let key = Address::from(9u64);
        cache.put(key, cache_entity(9, "nine"));
        cache.try_remove(&key).unwrap();

        assert!(cache.get(&key).is_none());
        assert!(cache.try_get(&key).unwrap().is_none());
        assert!(storage.get::<Address, CacheEntity>(&key).unwrap().is_none());
    }

    #[test]
    fn write_back_put_then_flush_persists() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        let cache =
            EntityCache::<Address, CacheEntity>::with_worker(storage.clone(), worker, 64 * 1024);

        for i in 0u64..50 {
            cache.put(Address::from(i), cache_entity(i, "entry"));
        }
        cache.flush().unwrap();

        for i in 0u64..50 {
            let stored = storage
                .get::<Address, CacheEntity>(&Address::from(i))
                .unwrap();
            assert_eq!(stored, Some(cache_entity(i, "entry")));
        }
    }

    #[test]
    fn write_back_reads_survive_eviction_before_flush() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        let cache = EntityCache::<Address, CacheEntity>::with_worker(storage.clone(), worker, 128);

        let key = Address::from(1u64);
        cache.put(key, cache_entity(1, "one"));

        for i in 100u64..200 {
            cache.put(Address::from(i), cache_entity(i, "filler"));
        }

        let retrieved = cache
            .get(&key)
            .expect("value served from pending or storage");
        assert_eq!(*retrieved, cache_entity(1, "one"));
    }

    #[test]
    fn write_back_iter_range_reflects_pending_writes() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let worker =
            WriteBackWorker::with_options(storage.clone(), 16, 1024, Duration::from_secs(3600))
                .unwrap();
        let cache =
            EntityCache::<Address, CacheEntity>::with_worker(storage.clone(), worker, 64 * 1024);

        cache.put(Address::from(1u64), cache_entity(1, "one"));
        cache.put(Address::from(2u64), cache_entity(2, "two"));
        cache.put(Address::from(3u64), cache_entity(3, "three"));
        cache.try_remove(&Address::from(2u64)).unwrap();

        let values = cache
            .try_iter_range(Bound::Included(&Address::from(1u64)))
            .unwrap()
            .map(|entry| entry.map(|(_, entity)| entity.id))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(values, vec![1, 3]);
        assert_eq!(
            storage
                .get::<Address, CacheEntity>(&Address::from(1u64))
                .unwrap(),
            None
        );
        assert_eq!(
            storage
                .get::<Address, CacheEntity>(&Address::from(2u64))
                .unwrap(),
            None
        );
    }

    #[test]
    fn write_back_remove_then_flush_clears_storage() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        let cache =
            EntityCache::<Address, CacheEntity>::with_worker(storage.clone(), worker, 64 * 1024);

        let key = Address::from(9u64);
        cache.put(key, cache_entity(9, "nine"));
        cache.flush().unwrap();
        assert!(storage.get::<Address, CacheEntity>(&key).unwrap().is_some());

        cache.try_remove(&key).unwrap();
        cache.flush().unwrap();

        assert!(cache.get(&key).is_none());
        assert!(storage.get::<Address, CacheEntity>(&key).unwrap().is_none());
    }

    #[test]
    fn write_back_shutdown_flushes_pending() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let key = Address::from(5u64);

        {
            let worker = WriteBackWorker::new(storage.clone()).unwrap();
            let cache = EntityCache::<Address, CacheEntity>::with_worker(
                storage.clone(),
                worker,
                64 * 1024,
            );
            cache.put(key, cache_entity(5, "five"));
        }

        let stored = storage.get::<Address, CacheEntity>(&key).unwrap();
        assert_eq!(stored, Some(cache_entity(5, "five")));
    }

    #[test]
    fn write_back_commit_failure_poisons_worker() {
        let storage = EntityStorage::new(FailingWriteProvider(InMemoryEntityStorage::new()));
        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        let cache = EntityCache::<Address, CacheEntity>::with_worker(storage, worker, 64 * 1024);

        cache.put(Address::from(1u64), cache_entity(1, "one"));

        assert!(cache.flush().is_err());
        assert!(
            cache
                .try_put(Address::from(2u64), cache_entity(2, "two"))
                .is_err()
        );
    }
}
