use std::fmt::{Debug, Display};
use std::io;
use std::mem::ManuallyDrop;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bitflags::bitflags;
use quick_cache::sync::Cache;
use thiserror::Error;

use crate::loader::Loadable;
use crate::types::any::Out;
use crate::types::{AttributeMap, BytesOrSlice};

pub mod common;
pub use common::{
    DefaultFromEntityStorage, Entity, EntityId, EntityKey, EntityKeyId, EntityKeyPrefix,
    PersistableEntity, ProjectEntity,
};

pub mod dummy;
pub use dummy::DummyEntityStorage;

pub mod memory;
pub use memory::InMemoryEntityStorage;

pub mod mdbx;
pub use mdbx::MdbxEntityStorage;

pub mod rocksdb;
pub use rocksdb::RocksDbEntityStorage;

pub mod sqlite;
pub use sqlite::SqliteEntityStorage;

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
    #[error("failed to load project data from `{0}`: {1}")]
    ProjectData(PathBuf, io::ErrorKind),
    #[error("no project path specified")]
    NoProjectPath,
    #[error(transparent)]
    Unsupported(anyhow::Error),
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

    pub fn project_data(path: impl Into<PathBuf>, kind: io::ErrorKind) -> Self {
        Self::ProjectData(path.into(), kind)
    }

    pub fn unsupported<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Unsupported(anyhow::Error::from(err))
    }

    pub fn unsupported_with<M>(msg: M) -> Self
    where
        M: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    {
        Self::Unsupported(anyhow::Error::msg(msg))
    }
}

pub trait EntityStorageBulkInserter<'a> {
    fn insert(
        &mut self,
        key: BytesOrSlice<'a>,
        value: BytesOrSlice<'a>,
    ) -> Result<(), EntityStorageError>;

    fn commit(self: Box<Self>) -> Result<(), EntityStorageError>;
}

pub type EntityBytesIterator<'a> =
    Box<dyn Iterator<Item = Result<(BytesOrSlice<'a>, BytesOrSlice<'a>), EntityStorageError>> + 'a>;

pub type EntityKeyBytesIterator<'a> =
    Box<dyn Iterator<Item = Result<BytesOrSlice<'a>, EntityStorageError>> + 'a>;

pub type EntityIterator<'a, K, E> =
    Box<dyn Iterator<Item = Result<(K, E), EntityStorageError>> + 'a>;

pub type EntityKeyIterator<'a, K> = Box<dyn Iterator<Item = Result<K, EntityStorageError>> + 'a>;

pub trait EntityStorageTransactionalReader<'a> {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError>;
    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError>;
}

pub type EntityBytesTransactionalReader<'a> = Box<dyn EntityStorageTransactionalReader<'a> + 'a>;

pub struct EntityTransactionalReader<'a> {
    inner: EntityBytesTransactionalReader<'a>,
}

impl<'a> EntityTransactionalReader<'a> {
    pub fn new(inner: EntityBytesTransactionalReader<'a>) -> Self {
        Self { inner }
    }

    pub fn get<K: EntityKey, E: Entity>(&self, key: &K) -> Result<Option<E>, EntityStorageError> {
        let key = common::make_key::<K, E>(key);
        self.inner
            .get(&key)?
            .map(|bytes| {
                bincode::decode_from_slice::<E, _>(bytes.as_slice(), bincode::config::standard())
                    .map(|(entity, _)| entity)
                    .map_err(EntityStorageError::decode)
            })
            .transpose()
    }

    pub fn get_as<K, E, F, T>(&self, key: &K, mut f: F) -> Result<Option<T>, EntityStorageError>
    where
        K: EntityKey,
        E: Entity,
        F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
    {
        let key = common::make_key::<K, E>(key);
        self.inner
            .get(&key)?
            .map(|bytes| f(bytes.as_slice()))
            .transpose()
            .map_err(EntityStorageError::decode)
    }

    pub fn contains<K: EntityKey, E: Entity>(&self, key: &K) -> Result<bool, EntityStorageError> {
        let key = common::make_key::<K, E>(key);
        self.inner.contains(&key)
    }
}

pub trait EntityStorageTransactionalWriter<'a>: EntityStorageTransactionalReader<'a> {
    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError>;
    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError>;
    fn commit(self: Box<Self>) -> Result<(), EntityStorageError>;
}

pub type EntityBytesTransactionalWriter<'a> = Box<dyn EntityStorageTransactionalWriter<'a> + 'a>;

pub struct EntityTransactionalWriter<'a> {
    inner: ManuallyDrop<EntityBytesTransactionalWriter<'a>>,
    flags: EntityTransactionalWriterFlags,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct EntityTransactionalWriterFlags: u8 {
        const NONE        = 0b0000_0000;
        const AUTO_COMMIT = 0b0000_0001;
        const DROPPED     = 0b0000_0010;
    }
}

impl<'a> EntityTransactionalWriter<'a> {
    pub fn new(inner: EntityBytesTransactionalWriter<'a>) -> Self {
        Self {
            inner: ManuallyDrop::new(inner),
            flags: EntityTransactionalWriterFlags::NONE,
        }
    }

    pub fn get<K: EntityKey, E: Entity>(&self, key: &K) -> Result<Option<E>, EntityStorageError> {
        let key = common::make_key::<K, E>(key);
        self.inner
            .get(&key)?
            .map(|bytes| {
                bincode::decode_from_slice::<E, _>(bytes.as_slice(), bincode::config::standard())
                    .map(|(entity, _)| entity)
                    .map_err(EntityStorageError::decode)
            })
            .transpose()
    }

    pub fn get_as<K, E, F, T>(&self, key: &K, mut f: F) -> Result<Option<T>, EntityStorageError>
    where
        K: EntityKey,
        E: Entity,
        F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
    {
        let key = common::make_key::<K, E>(key);
        self.inner
            .get(&key)?
            .map(|bytes| f(bytes.as_slice()))
            .transpose()
            .map_err(EntityStorageError::decode)
    }

    pub fn contains<K: EntityKey, E: Entity>(&self, key: &K) -> Result<bool, EntityStorageError> {
        let key = common::make_key::<K, E>(key);
        self.inner.contains(&key)
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

        self.inner.insert(&*key, encoded)
    }

    pub fn remove<K: EntityKey, E: Entity>(&self, key: &K) -> Result<(), EntityStorageError> {
        let key = common::make_key::<K, E>(key);
        self.inner.remove(&key)
    }

    pub fn enable_auto_commit(&mut self) {
        self.flags |= EntityTransactionalWriterFlags::AUTO_COMMIT;
    }

    pub fn disable_auto_commit(&mut self) {
        self.flags
            .remove(EntityTransactionalWriterFlags::AUTO_COMMIT);
    }

    pub fn commit(mut self) -> Result<(), EntityStorageError> {
        self.flags.insert(EntityTransactionalWriterFlags::DROPPED);
        unsafe { ManuallyDrop::take(&mut self.inner) }.commit()
    }
}

impl<'a> Drop for EntityTransactionalWriter<'a> {
    fn drop(&mut self) {
        if self.flags.contains(EntityTransactionalWriterFlags::DROPPED) {
            // if the writer was already dropped, we do not need to drop/commit
            return;
        }

        let inner = unsafe { ManuallyDrop::take(&mut self.inner) };

        if self
            .flags
            .contains(EntityTransactionalWriterFlags::AUTO_COMMIT)
            && let Err(e) = inner.commit()
        {
            tracing::error!("failed to commit transaction: {e}");
        }
    }
}

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

    pub fn commit(self) -> Result<(), EntityStorageError> {
        self.inner.commit()
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

pub trait EntityStorageProviderFromStorage: EntityStorageProviderFromLoadable {
    fn from_storage(
        path: impl AsRef<Path>,
        attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError>
    where
        Self: Sized;
}

/*
pub trait EntityStorageBytesAsIterator {
    fn next_as<F, T>(&mut self, f: F) -> Result<Option<T>, EntityStorageError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<T, EntityStorageError>;
}

pub trait ErasedEntityStorageBytesAsIterator {
    fn erased_next_as<'a>(
        &mut self,
        f: &mut OutMapper2<'a>,
    ) -> Result<Option<Out>, EntityStorageError>;
}

impl EntityStorageBytesAsIterator for dyn ErasedEntityStorageBytesAsIterator {
    fn next_as<F, T>(&mut self, f: F) -> Result<Option<T>, EntityStorageError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<T, EntityStorageError>,
    {
        let mut mapper = OutMapper2::new(f);
        let t = self
            .erased_next_as(&mut mapper)?
            .map(|out| unsafe { out.take::<T>() });
        Ok(t)
    }
}

impl<T> ErasedEntityStorageBytesAsIterator for T
where
    T: EntityStorageBytesAsIterator,
{
    fn erased_next_as<'a>(
        &mut self,
        mapper: &mut OutMapper2<'a>,
    ) -> Result<Option<Out>, EntityStorageError> {
        self.next_as(move |kbytes, ebytes| mapper.apply(kbytes, ebytes))
    }
}

pub struct EntityBytesAsIterator<'a, T> {
    iter: ErasedEntityBytesAsIterator<'a>,
    _marker: std::marker::PhantomData<T>,
}

pub struct ErasedEntityBytesAsIterator<'a> {
    mapper: OutMapper2<'a>,
    inner: Box<dyn ErasedEntityStorageBytesAsIterator + 'a>,
}

impl<T> Iterator for EntityBytesAsIterator<'_, T>
where
    T: Entity,
{
    type Item = Result<T, EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .inner
            .erased_next_as(&mut self.iter.mapper)
            .transpose()
            .map(|out| out.map(|v| unsafe { v.take::<T>() }))
    }
}
*/

pub type EntityBytesAsIterator<'a, T> =
    Box<dyn Iterator<Item = Result<T, EntityStorageError>> + 'a>;

pub trait EntityStorageProvider: Send + Sync {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError>;
    fn get_as<F, T>(&self, key: &[u8], f: F) -> Result<Option<T>, EntityStorageError>
    where
        F: FnMut(&[u8]) -> Result<T, EntityStorageError>;

    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError>;
    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError>;
    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError>;

    fn iter_prefix_keys(
        &self,
        prefix: &[u8],
    ) -> Result<EntityKeyBytesIterator<'_>, EntityStorageError>;
    fn iter_prefix(&self, prefix: &[u8]) -> Result<EntityBytesIterator<'_>, EntityStorageError>;
    fn iter_prefix_as<'a, F, T>(
        &'a self,
        prefix: &[u8],
        f: F,
    ) -> Result<EntityBytesAsIterator<'a, T>, EntityStorageError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<T, EntityStorageError> + 'a,
        T: 'a;

    fn bulk_inserter(&self) -> Result<EntityBytesBulkInserter, EntityStorageError>;

    fn transactional_reader(&self) -> Result<EntityBytesTransactionalReader, EntityStorageError>;
    fn transactional_writer(&self) -> Result<EntityBytesTransactionalWriter, EntityStorageError>;
}

pub trait ErasedEntityStorageProvider: Send + Sync {
    fn erased_get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError>;
    fn erased_get_as<'a>(
        &self,
        key: &[u8],
        mapper: OutMapper<'a>,
    ) -> Result<Option<Out>, EntityStorageError>;
    fn erased_insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError>;
    fn erased_remove(&self, key: &[u8]) -> Result<(), EntityStorageError>;
    fn erased_contains(&self, key: &[u8]) -> Result<bool, EntityStorageError>;

    fn erased_iter_prefix_keys(
        &self,
        prefix: &[u8],
    ) -> Result<EntityKeyBytesIterator<'_>, EntityStorageError>;
    fn erased_iter_prefix(
        &self,
        prefix: &[u8],
    ) -> Result<EntityBytesIterator<'_>, EntityStorageError>;
    fn erased_iter_prefix_as<'a>(
        &'a self,
        prefix: &[u8],
        mapper: OutMapper2<'a>,
    ) -> Result<EntityBytesAsIterator<'a, Out>, EntityStorageError>;

    fn erased_bulk_inserter(&self) -> Result<EntityBytesBulkInserter, EntityStorageError>;

    fn erased_transactional_reader(
        &self,
    ) -> Result<EntityBytesTransactionalReader, EntityStorageError>;

    fn erased_transactional_writer(
        &self,
    ) -> Result<EntityBytesTransactionalWriter, EntityStorageError>;
}

impl EntityStorageProvider for dyn ErasedEntityStorageProvider {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        self.erased_get(key)
    }

    fn get_as<F, T>(&self, key: &[u8], f: F) -> Result<Option<T>, EntityStorageError>
    where
        F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
    {
        let mapper = OutMapper::new(f);
        let t = self
            .erased_get_as(key, mapper)?
            .map(|out| unsafe { out.take::<T>() });
        Ok(t)
    }

    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        self.erased_insert(key, value)
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        self.erased_remove(key)
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        self.erased_contains(key)
    }

    fn iter_prefix_keys(
        &self,
        prefix: &[u8],
    ) -> Result<EntityKeyBytesIterator<'_>, EntityStorageError> {
        self.erased_iter_prefix_keys(prefix)
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        self.erased_iter_prefix(prefix)
    }

    fn iter_prefix_as<'a, F, T>(
        &'a self,
        prefix: &[u8],
        f: F,
    ) -> Result<EntityBytesAsIterator<'a, T>, EntityStorageError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<T, EntityStorageError> + 'a,
    {
        let mapper = OutMapper2::new(f);
        let iter = self
            .erased_iter_prefix_as(prefix, mapper)?
            .map(|out| out.map(|v| unsafe { v.take::<T>() }));
        Ok(Box::new(iter))
    }

    fn bulk_inserter(&self) -> Result<EntityBytesBulkInserter, EntityStorageError> {
        self.erased_bulk_inserter()
    }

    fn transactional_reader(&self) -> Result<EntityBytesTransactionalReader, EntityStorageError> {
        self.erased_transactional_reader()
    }

    fn transactional_writer(&self) -> Result<EntityBytesTransactionalWriter, EntityStorageError> {
        self.erased_transactional_writer()
    }
}

impl<T> ErasedEntityStorageProvider for T
where
    T: EntityStorageProvider,
{
    fn erased_get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        self.get(key)
    }

    fn erased_get_as<'a>(
        &self,
        key: &[u8],
        mut mapper: OutMapper<'a>,
    ) -> Result<Option<Out>, EntityStorageError> {
        self.get_as(key, move |bytes| mapper.apply(bytes))
    }

    fn erased_insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        self.insert(key, value)
    }

    fn erased_remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        self.remove(key)
    }

    fn erased_contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        self.contains(key)
    }

    fn erased_iter_prefix_keys(
        &self,
        prefix: &[u8],
    ) -> Result<EntityKeyBytesIterator<'_>, EntityStorageError> {
        self.iter_prefix_keys(prefix)
    }

    fn erased_iter_prefix(
        &self,
        prefix: &[u8],
    ) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        self.iter_prefix(prefix)
    }

    fn erased_iter_prefix_as<'a>(
        &'a self,
        prefix: &[u8],
        mut mapper: OutMapper2<'a>,
    ) -> Result<EntityBytesAsIterator<'a, Out>, EntityStorageError> {
        let iter =
            self.iter_prefix_as(prefix, move |kbytes, ebytes| mapper.apply(kbytes, ebytes))?;
        Ok(Box::new(iter))
    }

    fn erased_bulk_inserter(&self) -> Result<EntityBytesBulkInserter, EntityStorageError> {
        self.bulk_inserter()
    }

    fn erased_transactional_reader(
        &self,
    ) -> Result<EntityBytesTransactionalReader, EntityStorageError> {
        self.transactional_reader()
    }

    fn erased_transactional_writer(
        &self,
    ) -> Result<EntityBytesTransactionalWriter, EntityStorageError> {
        self.transactional_writer()
    }
}

pub struct OutMapper<'a> {
    f: Box<dyn FnMut(&[u8]) -> Result<Out, EntityStorageError> + 'a>,
}

impl<'a> OutMapper<'a> {
    fn new<E, F>(mut f: F) -> Self
    where
        F: FnMut(&[u8]) -> Result<E, EntityStorageError> + 'a,
    {
        Self {
            f: Box::new(move |bytes| f(bytes).map(|v| unsafe { Out::new(v) })),
        }
    }

    fn apply(&mut self, bytes: &[u8]) -> Result<Out, EntityStorageError> {
        (self.f)(bytes)
    }
}

pub struct OutMapper2<'a> {
    f: Box<dyn FnMut(&[u8], &[u8]) -> Result<Out, EntityStorageError> + 'a>,
}

impl<'a> OutMapper2<'a> {
    fn new<E, F>(mut f: F) -> Self
    where
        F: FnMut(&[u8], &[u8]) -> Result<E, EntityStorageError> + 'a,
    {
        Self {
            f: Box::new(move |kbytes, ebytes| f(kbytes, ebytes).map(|v| unsafe { Out::new(v) })),
        }
    }

    fn apply(&mut self, kbytes: &[u8], ebytes: &[u8]) -> Result<Out, EntityStorageError> {
        (self.f)(kbytes, ebytes)
    }
}

pub struct EntityCache<K: EntityKey, E: Entity> {
    entities: Arc<Cache<K, Arc<E>>>,
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
        const NONE    = 0b0000_0000;
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

pub struct EntityTransactionalCacheWriter<'a, K, E>
where
    K: EntityKey,
    E: Entity,
{
    inner: ManuallyDrop<EntityTransactionalWriter<'a>>,
    cache: Arc<Cache<K, Arc<E>>>,
    dropped: bool,
}

impl<'a, K, E> EntityTransactionalCacheWriter<'a, K, E>
where
    K: EntityKey,
    E: Entity,
{
    fn new(inner: EntityTransactionalWriter<'a>, cache: Arc<Cache<K, Arc<E>>>) -> Self {
        Self {
            inner: ManuallyDrop::new(inner),
            cache,
            dropped: false,
        }
    }

    pub fn get(&self, key: &K) -> Result<Option<E>, EntityStorageError> {
        self.inner.get::<K, E>(key)
    }

    pub fn get_as<F, T>(&self, key: &K, f: F) -> Result<Option<T>, EntityStorageError>
    where
        F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
    {
        self.inner.get_as::<K, E, F, T>(key, f)
    }

    pub fn contains(&self, key: &K) -> Result<bool, EntityStorageError> {
        self.inner.contains::<K, E>(key)
    }

    pub fn insert(&self, key: &K, entity: &E) -> Result<(), EntityStorageError> {
        self.inner.insert(key, entity)
    }

    pub fn remove(&self, key: &K) -> Result<(), EntityStorageError> {
        self.inner.remove::<K, E>(key)
    }

    pub fn enable_auto_commit(&mut self) {
        self.inner.enable_auto_commit();
    }

    pub fn disable_auto_commit(&mut self) {
        self.inner.disable_auto_commit();
    }

    pub fn commit(mut self) -> Result<(), EntityStorageError> {
        self.cache.clear();
        self.dropped = true;

        let inner = unsafe { ManuallyDrop::take(&mut self.inner) };

        inner.commit()?;

        Ok(())
    }
}

impl<'a, K, E> Drop for EntityTransactionalCacheWriter<'a, K, E>
where
    K: EntityKey,
    E: Entity,
{
    fn drop(&mut self) {
        if self.dropped {
            return;
        }

        let inner = unsafe { ManuallyDrop::take(&mut self.inner) };

        // if we didn't drop, then we haven't committed (yet), check if we should clear
        // the cache due to an auto-commit
        if inner
            .flags
            .contains(EntityTransactionalWriterFlags::AUTO_COMMIT)
        {
            self.cache.clear();
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
            entities: Arc::new(Cache::new(size)),
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
        Ok(self.storage.backing.iter_prefix_as(&pfx, |k, v| {
            let key = common::extract_key::<K, E>(k.into())
                .ok_or(EntityStorageError::InvalidKeyFormat)?;

            if let Some(val) = self.entities.get(&key) {
                return Ok((key, EntityRef::new(val)));
            }

            let val = bincode::decode_from_slice::<E, _>(v, bincode::config::standard())
                .map(|(entity, _)| entity)
                .map_err(EntityStorageError::decode)?;

            Ok((key, EntityRef::new(Arc::new(val))))
        })? as EntityIterator<'_, K, EntityRef<E>>)
    }

    pub fn transactional_reader(
        &self,
    ) -> Result<EntityTransactionalReader<'_>, EntityStorageError> {
        self.storage.transactional_reader()
    }

    pub fn transactional_writer(
        &self,
    ) -> Result<EntityTransactionalCacheWriter<'_, K, E>, EntityStorageError> {
        let writer = self.storage.transactional_writer()?;
        Ok(EntityTransactionalCacheWriter::new(
            writer,
            self.entities.clone(),
        ))
    }

    pub fn clear(&mut self) -> Result<(), EntityStorageError> {
        self.entities.clear();
        Ok(())
    }

    pub fn storage(&self) -> &EntityStorage {
        &self.storage
    }
}

#[derive(Clone)]
pub struct EntityStorage {
    backing: Arc<dyn ErasedEntityStorageProvider>,
}

impl EntityStorage {
    pub fn new(backing: impl EntityStorageProvider + 'static) -> Self {
        Self {
            backing: Arc::new(backing),
        }
    }

    pub fn get<K: EntityKey, E: Entity>(&self, key: &K) -> Result<Option<E>, EntityStorageError> {
        let key = common::make_key::<K, E>(key);

        self.backing.get_as(&key, |bytes| {
            bincode::decode_from_slice::<E, _>(bytes, bincode::config::standard())
                .map(|(entity, _)| entity)
                .map_err(EntityStorageError::decode)
        })
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

    pub fn transactional_reader(
        &self,
    ) -> Result<EntityTransactionalReader<'_>, EntityStorageError> {
        let reader = self.backing.transactional_reader()?;
        Ok(EntityTransactionalReader::new(reader))
    }

    pub fn transactional_writer(
        &self,
    ) -> Result<EntityTransactionalWriter<'_>, EntityStorageError> {
        let writer = self.backing.transactional_writer()?;
        Ok(EntityTransactionalWriter::new(writer))
    }

    pub fn cache_for<K: EntityKey, E: Entity>(
        &self,
        size: usize,
    ) -> Result<EntityCache<K, E>, EntityStorageError> {
        EntityCache::new(self.clone(), size)
    }

    pub fn storage_provider(&self) -> Arc<dyn ErasedEntityStorageProvider> {
        self.backing.clone()
    }
}

#[cfg(test)]
mod test {
    use bincode::{Decode, Encode};

    use super::*;
    use crate::ir::Address;

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
            name: "Test".to_owned(),
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
                name: format!("Entity {i}"),
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
                name: format!("Entity {count}"),
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
                name: format!("Entity {i}"),
            };
            let cached = cache.get(&Address::from(i as u64)).unwrap();

            assert!(cached.is_some());
            assert_eq!(*cached.unwrap(), entity);
        }

        // test cache insertion
        for i in 50..100 {
            let entity = TestEntity {
                id: i,
                name: format!("New Cached Entity {i}"),
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
                    name: format!("New Cached Entity {i}")
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
