use std::fmt::Display;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use bytes::Bytes;
use quick_cache::Weighter;
use quick_cache::sync::Cache;

use crate::types::BytesOrSlice;

use super::schema;
use super::{
    Entity, EntityIterator, EntityKey, EntityStorage, EntityStorageError, WriteBackAction,
    WriteBackWorker,
};

const ENTITY_CACHE_ENTRY_OVERHEAD: u32 = 64;
const ENTITY_CACHE_ESTIMATED_ENTRY_SIZE: usize = 256;

type EntityLru<K, E> = Cache<K, Cached<E>, ByteWeighter>;

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

enum WriteSink {
    Worker(Arc<WriteBackWorker>),
    WriteThrough,
}

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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
                        let entity = rkyv::from_bytes::<E, rkyv::rancor::Error>(&bytes)
                            .map_err(EntityStorageError::decode)?;
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

    pub fn try_iter(&self) -> Result<EntityIterator<'_, K, CachedRef<'_, E>>, EntityStorageError> {
        self.flush()?;

        let entities = self.entities.clone();
        let iter = self.storage.iter::<K, E>()?.map(move |result| {
            result.map(|(key, value)| match entities.get(&key) {
                Some(cached) => (key, CachedRef::from_arc(cached.value)),
                None => (key, CachedRef::new(value)),
            })
        });

        Ok(Box::new(iter))
    }

    pub fn iter(&self) -> impl Iterator<Item = CachedRef<'_, E>> + '_ {
        self.try_iter()
            .unwrap_or_else(|error| error.into_fatal())
            .map(|result| result.unwrap_or_else(|error| error.into_fatal()).1)
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        match &self.sink {
            WriteSink::WriteThrough => Ok(()),
            WriteSink::Worker(worker) => worker.flush(),
        }
    }

    fn fetch(&self, key: &K) -> Result<Option<(E, u32)>, EntityStorageError> {
        self.storage.get_as::<K, E, _, _>(key, |bytes| {
            let entity = rkyv::from_bytes::<E, rkyv::rancor::Error>(bytes)
                .map_err(EntityStorageError::decode)?;
            Ok((entity, ByteWeighter::entry_weight(bytes.len())))
        })
    }

    fn try_get_uncached(&self, key: &K) -> Result<Option<Arc<E>>, EntityStorageError> {
        if let Some(cached) = self.entities.get(key) {
            return Ok(Some(cached.value));
        }

        if let WriteSink::Worker(worker) = &self.sink {
            let key_bytes = schema::make_key::<K, E>(key);
            if let Some(pending) = worker.pending(&key_bytes) {
                return match pending {
                    WriteBackAction::Insert(bytes) => Ok(Some(Arc::new(
                        rkyv::from_bytes::<E, rkyv::rancor::Error>(&bytes)
                            .map_err(EntityStorageError::decode)?,
                    ))),
                    WriteBackAction::Remove => Ok(None),
                };
            }
        }

        Ok(self.fetch(key)?.map(|(entity, _)| Arc::new(entity)))
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
                worker.enqueue(key_bytes, Some(Bytes::copy_from_slice(encoded.as_ref())))?;
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

    pub fn get_mut(&mut self, key: &K) -> Option<CachedMut<'_, E>> {
        self.try_get_mut(key)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn get_disjoint_mut<'a>(
        &'a mut self,
        keys: impl IntoIterator<Item = K> + 'a,
    ) -> impl Iterator<Item = CachedMut<'a, E>> + 'a {
        let cache = &*self;

        keys.into_iter().filter_map(move |key| {
            let entity = cache
                .try_get_uncached(&key)
                .unwrap_or_else(|error| error.into_fatal())?;

            Some(CachedMut {
                cache,
                entity,
                dirty: false,
            })
        })
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
