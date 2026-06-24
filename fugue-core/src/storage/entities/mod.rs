use std::fmt::{Debug, Display};
use std::io;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bitflags::bitflags;
use bytes::Bytes;
use quick_cache::Weighter;
use quick_cache::sync::Cache;
use thiserror::Error;

use crate::loader::Loadable;
use crate::storage::{PERSISTENT, StoragePersistence, TRANSIENT};
use crate::types::any::Out;
use crate::types::{AttributeMap, BytesOrSlice};

pub mod dummy;
pub use dummy::DummyEntityStorage;

pub mod memory;
pub use memory::InMemoryEntityStorage;

#[cfg(feature = "mdbx")]
pub mod mdbx;
#[cfg(feature = "mdbx")]
pub use mdbx::MdbxEntityStorage;

#[cfg(feature = "rocksdb")]
pub mod rocksdb;
#[cfg(feature = "rocksdb")]
pub use rocksdb::RocksDbEntityStorage;

pub mod schema;
pub use schema::{Entity, EntityId, EntityKey, EntityKeyId, EntityKeyPrefix, ProjectEntity};

pub mod writeback;
pub use writeback::WriteBackWorker;

#[cfg(feature = "sqlite")]
pub mod sqlite;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteEntityStorage;

#[cfg(feature = "sqlite")]
pub type DefaultPersistentEntityStorage = SqliteEntityStorage<PERSISTENT>;
#[cfg(all(feature = "rocksdb", not(feature = "sqlite")))]
pub type DefaultPersistentEntityStorage = RocksDbEntityStorage;
#[cfg(all(feature = "mdbx", not(feature = "rocksdb"), not(feature = "sqlite")))]
pub type DefaultPersistentEntityStorage = MdbxEntityStorage;
#[cfg(all(
    not(feature = "mdbx"),
    not(feature = "rocksdb"),
    not(feature = "sqlite")
))]
pub type DefaultPersistentEntityStorage = InMemoryEntityStorage;
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

    pub(crate) fn into_fatal(self) -> ! {
        tracing::error!("fatal entity storage failure: {self}");
        panic!("fatal entity storage failure: {self}");
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
        let key = schema::make_key::<K, E>(key);
        self.inner
            .get(&key)?
            .map(|bytes| {
                rkyv::from_bytes::<E, rkyv::rancor::Error>(bytes.as_slice())
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
        let key = schema::make_key::<K, E>(key);
        self.inner
            .get(&key)?
            .map(|bytes| f(bytes.as_slice()))
            .transpose()
            .map_err(EntityStorageError::decode)
    }

    pub fn contains<K: EntityKey, E: Entity>(&self, key: &K) -> Result<bool, EntityStorageError> {
        let key = schema::make_key::<K, E>(key);
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
        let key = schema::make_key::<K, E>(key);
        self.inner
            .get(&key)?
            .map(|bytes| {
                rkyv::from_bytes::<E, rkyv::rancor::Error>(bytes.as_slice())
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
        let key = schema::make_key::<K, E>(key);
        self.inner
            .get(&key)?
            .map(|bytes| f(bytes.as_slice()))
            .transpose()
            .map_err(EntityStorageError::decode)
    }

    pub fn contains<K: EntityKey, E: Entity>(&self, key: &K) -> Result<bool, EntityStorageError> {
        let key = schema::make_key::<K, E>(key);
        self.inner.contains(&key)
    }

    pub fn insert<K: EntityKey, E: Entity>(
        &self,
        key: &K,
        entity: &E,
    ) -> Result<(), EntityStorageError> {
        let key = schema::make_key::<K, E>(key);
        let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(entity)
            .map(|v| v.to_vec())
            .map_err(EntityStorageError::encode)?;

        let encoded = BytesOrSlice::from(encoded);

        self.inner.insert(&key, encoded)
    }

    pub fn remove<K: EntityKey, E: Entity>(&self, key: &K) -> Result<(), EntityStorageError> {
        let key = schema::make_key::<K, E>(key);
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
        let key = schema::make_key::<K, E>(key);
        let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(entity)
            .map(|v| v.to_vec())
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

    fn persistence(&self) -> StoragePersistence {
        PERSISTENT
    }
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

    fn erased_persistence(&self) -> StoragePersistence;
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

    fn persistence(&self) -> StoragePersistence {
        self.erased_persistence()
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

    fn erased_persistence(&self) -> StoragePersistence {
        self.persistence()
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

pub struct EntityCache<K: EntityKey, E: Entity> {
    entities: Arc<EntityLru<K, E>>,
    storage: EntityStorage,
    sink: WriteSink,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct EntityRef<'a, E>(Arc<E>, PhantomData<&'a E>)
where
    E: Entity;

impl<E> Display for EntityRef<'_, E>
where
    E: Entity + Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<E> AsRef<E> for EntityRef<'_, E>
where
    E: Entity,
{
    fn as_ref(&self) -> &E {
        &self.0
    }
}

impl<E> Deref for EntityRef<'_, E>
where
    E: Entity,
{
    type Target = E;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, E> EntityRef<'a, E>
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

pub struct EntityMut<'a, E>
where
    E: MutableEntity,
{
    cache: &'a EntityCache<E::Key, E>,
    entity: Arc<E>,
    dirty: bool,
}

impl<E> Deref for EntityMut<'_, E>
where
    E: MutableEntity,
{
    type Target = E;

    fn deref(&self) -> &Self::Target {
        self.entity.as_ref()
    }
}

impl<E> DerefMut for EntityMut<'_, E>
where
    E: MutableEntity,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.dirty = true;
        Arc::make_mut(&mut self.entity)
    }
}

impl<E> Drop for EntityMut<'_, E>
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

pub enum Ref<'a, E>
where
    E: Entity,
{
    Borrowed(&'a E),
    Shared(EntityRef<'a, E>),
}

impl<E> Deref for Ref<'_, E>
where
    E: Entity,
{
    type Target = E;

    fn deref(&self) -> &Self::Target {
        match *self {
            Ref::Borrowed(entity) => entity,
            Ref::Shared(ref entity) => entity.as_ref(),
        }
    }
}

pub enum RefMut<'a, E>
where
    E: MutableEntity,
{
    Borrowed(&'a mut E),
    Guard(EntityMut<'a, E>),
}

impl<E> Deref for RefMut<'_, E>
where
    E: MutableEntity,
{
    type Target = E;

    fn deref(&self) -> &Self::Target {
        match self {
            RefMut::Borrowed(entity) => entity,
            RefMut::Guard(guard) => guard,
        }
    }
}

impl<E> DerefMut for RefMut<'_, E>
where
    E: MutableEntity,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            RefMut::Borrowed(entity) => entity,
            RefMut::Guard(guard) => guard,
        }
    }
}

pub trait MutableEntity: Entity {
    type Key: EntityKey;

    fn entity_key(&self) -> Self::Key;
}

pub struct EntityTransactionalCacheWriter<'a, K, E>
where
    K: EntityKey,
    E: Entity,
{
    inner: ManuallyDrop<EntityTransactionalWriter<'a>>,
    cache: Arc<EntityLru<K, E>>,
    dropped: bool,
}

impl<'a, K, E> EntityTransactionalCacheWriter<'a, K, E>
where
    K: EntityKey,
    E: Entity,
{
    fn new(inner: EntityTransactionalWriter<'a>, cache: Arc<EntityLru<K, E>>) -> Self {
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

    pub fn try_get(&self, key: &K) -> Result<Option<EntityRef<'_, E>>, EntityStorageError> {
        if let Some(cached) = self.entities.get(key) {
            return Ok(Some(EntityRef::from_arc(cached.value)));
        }

        if let WriteSink::Worker(worker) = &self.sink {
            let key_bytes = schema::make_key::<K, E>(key);
            if let Some(pending) = worker.pending(&key_bytes) {
                return match pending {
                    Some(bytes) => {
                        let entity = rkyv::from_bytes::<E, rkyv::rancor::Error>(&bytes)
                            .map_err(EntityStorageError::decode)?;
                        Ok(Some(self.admit(
                            key.clone(),
                            Arc::new(entity),
                            ByteWeighter::entry_weight(bytes.len()),
                        )))
                    }
                    None => Ok(None),
                };
            }
        }

        let Some((entity, weight)) = self.fetch(key)? else {
            return Ok(None);
        };

        Ok(Some(self.admit(key.clone(), Arc::new(entity), weight)))
    }

    fn admit(&self, key: K, entity: Arc<E>, weight: u32) -> EntityRef<'_, E> {
        self.entities.insert(
            key,
            Cached {
                value: entity.clone(),
                weight,
            },
        );

        EntityRef::from_arc(entity)
    }

    pub fn get(&self, key: &K) -> Option<EntityRef<'_, E>> {
        self.try_get(key).unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_contains(&self, key: &K) -> Result<bool, EntityStorageError> {
        if self.entities.contains_key(key) {
            return Ok(true);
        }

        if let WriteSink::Worker(worker) = &self.sink {
            let key_bytes = schema::make_key::<K, E>(key);
            if let Some(pending) = worker.pending(&key_bytes) {
                return Ok(pending.is_some());
            }
        }

        self.storage.contains::<K, E>(key)
    }

    pub fn contains(&self, key: &K) -> bool {
        self.try_contains(key)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_put(
        &self,
        key: K,
        entity: impl Into<Arc<E>>,
    ) -> Result<EntityRef<'_, E>, EntityStorageError> {
        let entity = entity.into();
        let weight = self.stage(&key, entity.as_ref())?;

        Ok(self.admit(key, entity, weight))
    }

    pub fn put(&self, key: K, entity: impl Into<Arc<E>>) -> EntityRef<'_, E> {
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

    pub fn remove(&self, key: &K) {
        self.try_remove(key)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_iter(&self) -> Result<EntityIterator<'_, K, EntityRef<'_, E>>, EntityStorageError> {
        self.flush()?;

        let entities = self.entities.clone();
        let iter = self.storage.iter::<K, E>()?.map(move |result| {
            result.map(|(key, value)| match entities.get(&key) {
                Some(cached) => (key, EntityRef::from_arc(cached.value)),
                None => (key, EntityRef::new(value)),
            })
        });

        Ok(Box::new(iter))
    }

    pub fn iter(&self) -> impl Iterator<Item = EntityRef<'_, E>> + '_ {
        self.try_iter()
            .unwrap_or_else(|error| error.into_fatal())
            .map(|result| result.unwrap_or_else(|error| error.into_fatal()).1)
    }

    pub fn keys(&self) -> Result<EntityKeyIterator<'_, K>, EntityStorageError> {
        self.storage.keys::<K, E>()
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        match &self.sink {
            WriteSink::WriteThrough => Ok(()),
            WriteSink::Worker(worker) => worker.flush(),
        }
    }

    pub fn bulk_inserter(&self) -> Result<EntityBulkInserter<'_>, EntityStorageError> {
        self.flush()?;
        self.entities.clear();
        self.storage.bulk_inserter()
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

    pub fn clear(&self) {
        self.entities.clear();
    }

    pub fn storage(&self) -> &EntityStorage {
        &self.storage
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
                    Some(bytes) => Ok(Some(Arc::new(
                        rkyv::from_bytes::<E, rkyv::rancor::Error>(&bytes)
                            .map_err(EntityStorageError::decode)?,
                    ))),
                    None => Ok(None),
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
    pub fn try_get_mut(&mut self, key: &K) -> Result<Option<EntityMut<'_, E>>, EntityStorageError> {
        let Some(current) = self.try_get(key)? else {
            return Ok(None);
        };

        Ok(Some(EntityMut {
            cache: &*self,
            entity: current.into_arc(),
            dirty: false,
        }))
    }

    pub fn get_mut(&mut self, key: &K) -> Option<EntityMut<'_, E>> {
        self.try_get_mut(key)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn get_disjoint_mut<'a>(
        &'a mut self,
        keys: impl IntoIterator<Item = K> + 'a,
    ) -> impl Iterator<Item = EntityMut<'a, E>> + 'a {
        let cache = &*self;

        keys.into_iter().filter_map(move |key| {
            let entity = cache
                .try_get_uncached(&key)
                .unwrap_or_else(|error| error.into_fatal())?;

            Some(EntityMut {
                cache,
                entity,
                dirty: false,
            })
        })
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = EntityMut<'_, E>> + '_ {
        let cache = &*self;

        cache
            .try_iter()
            .unwrap_or_else(|error| error.into_fatal())
            .map(move |entry| {
                let (_, current) = entry.unwrap_or_else(|error| error.into_fatal());

                EntityMut {
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

    pub fn modify<R>(&mut self, key: &K, f: impl FnOnce(&mut E) -> R) -> Option<R> {
        self.try_modify(key, f)
            .unwrap_or_else(|error| error.into_fatal())
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
        let key = schema::make_key::<K, E>(key);
        self.backing.get_as(&key, |bytes| {
            rkyv::from_bytes::<E, rkyv::rancor::Error>(bytes).map_err(EntityStorageError::decode)
        })
    }

    pub fn get_as<K, E, F, T>(&self, key: &K, f: F) -> Result<Option<T>, EntityStorageError>
    where
        K: EntityKey,
        E: Entity,
        F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
    {
        let key = schema::make_key::<K, E>(key);
        self.backing.get_as(&key, f)
    }

    pub fn insert<K: EntityKey, E: Entity>(
        &self,
        key: &K,
        entity: &E,
    ) -> Result<(), EntityStorageError> {
        let key = schema::make_key::<K, E>(key);
        let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(entity)
            .map(|v| v.to_vec())
            .map_err(EntityStorageError::encode)?;
        let encoded = BytesOrSlice::from(encoded);

        self.backing.insert(&key, encoded)
    }

    pub fn insert_bytes<K: EntityKey, E: Entity>(
        &self,
        key: &K,
        value: BytesOrSlice<'_>,
    ) -> Result<(), EntityStorageError> {
        let key = schema::make_key::<K, E>(key);
        self.backing.insert(&key, value)
    }

    pub fn bulk_inserter(&self) -> Result<EntityBulkInserter, EntityStorageError> {
        Ok(EntityBulkInserter::new(self.backing.bulk_inserter()?))
    }

    pub fn remove<K: EntityKey, E: Entity>(&self, key: &K) -> Result<(), EntityStorageError> {
        let key = schema::make_key::<K, E>(key);
        self.backing.remove(&key)
    }

    pub fn contains<K: EntityKey, E: Entity>(&self, key: &K) -> Result<bool, EntityStorageError> {
        let key = schema::make_key::<K, E>(key);
        self.backing.contains(&key)
    }

    pub fn iter<K: EntityKey, E: Entity>(
        &self,
    ) -> Result<EntityIterator<'_, K, E>, EntityStorageError> {
        let pfx = schema::make_prefix::<K, E>();
        self.backing.iter_prefix(&pfx).map(|iter| {
            Box::new(iter.map(|result| {
                result.and_then(|(key, value)| {
                    let key = schema::extract_key::<K, E>(key)
                        .ok_or(EntityStorageError::InvalidKeyFormat)?;
                    let val = rkyv::from_bytes::<E, rkyv::rancor::Error>(value.as_slice())
                        .map_err(EntityStorageError::decode)?;
                    Ok((key, val))
                })
            })) as EntityIterator<'_, K, E>
        })
    }

    pub fn keys<K: EntityKey, E: Entity>(
        &self,
    ) -> Result<EntityKeyIterator<'_, K>, EntityStorageError> {
        let pfx = schema::make_prefix::<K, E>();
        self.backing.iter_prefix_keys(&pfx).map(|iter| {
            Box::new(iter.map(|result| {
                result.and_then(|key| {
                    schema::extract_key::<K, E>(key).ok_or(EntityStorageError::InvalidKeyFormat)
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
        capacity: usize,
    ) -> Result<EntityCache<K, E>, EntityStorageError> {
        EntityCache::new(self.clone(), capacity)
    }

    pub fn persistence(&self) -> StoragePersistence {
        self.backing.persistence()
    }

    pub fn is_persistent(&self) -> bool {
        matches!(self.backing.persistence(), PERSISTENT)
    }

    pub fn is_transient(&self) -> bool {
        matches!(self.backing.persistence(), TRANSIENT)
    }

    pub fn storage_provider(&self) -> Arc<dyn ErasedEntityStorageProvider> {
        self.backing.clone()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ir::Address;

    #[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    struct TestEntity {
        id: u64,
        name: String,
    }

    impl Entity for TestEntity {
        const ID: EntityId = EntityId::new(0);
    }

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

    struct FailingBulkProvider(InMemoryEntityStorage);

    impl EntityStorageProvider for FailingBulkProvider {
        fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
            self.0.get(key)
        }

        fn get_as<F, T>(&self, key: &[u8], f: F) -> Result<Option<T>, EntityStorageError>
        where
            F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
        {
            self.0.get_as(key, f)
        }

        fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
            self.0.insert(key, value)
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

        fn bulk_inserter(&self) -> Result<EntityBytesBulkInserter, EntityStorageError> {
            Err(EntityStorageError::backing_with(
                "bulk inserter unavailable",
            ))
        }

        fn transactional_reader(
            &self,
        ) -> Result<EntityBytesTransactionalReader, EntityStorageError> {
            self.0.transactional_reader()
        }

        fn transactional_writer(
            &self,
        ) -> Result<EntityBytesTransactionalWriter, EntityStorageError> {
            self.0.transactional_writer()
        }
    }

    fn cache_entity(id: u64, name: &str) -> CacheEntity {
        CacheEntity {
            id,
            name: name.to_owned(),
        }
    }

    #[test]
    fn test_entity_storage() {
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
        let cache = storage.cache_for::<Address, TestEntity>(64 * 1024).unwrap();

        for i in 0..5 {
            let entity = TestEntity {
                id: i,
                name: format!("Entity {i}"),
            };
            let cached = cache.get(&Address::from(i as u64));

            assert!(cached.is_some());
            assert_eq!(*cached.unwrap(), entity);
        }

        for i in 50..100 {
            let entity = TestEntity {
                id: i,
                name: format!("New Cached Entity {i}"),
            };
            cache.put(Address::from(i as u64), entity);
        }

        for i in 50..100 {
            let cached = cache.get(&Address::from(i as u64));
            assert!(cached.is_some());
            assert_eq!(
                *cached.unwrap(),
                TestEntity {
                    id: i,
                    name: format!("New Cached Entity {i}")
                }
            );
        }

        for i in 50..60 {
            cache.remove(&Address::from(i as u64));
            let cached = cache.get(&Address::from(i as u64));
            assert!(cached.is_none());

            let direct = storage
                .get::<Address, TestEntity>(&Address::from(i as u64))
                .unwrap();
            assert!(direct.is_none());
        }
    }

    #[test]
    fn cache_reads_survive_eviction() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let cache = storage.cache_for::<Address, CacheEntity>(128).unwrap();

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
    fn cache_modify_persists_through_to_storage() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let mut cache = storage
            .cache_for::<Address, CacheEntity>(64 * 1024)
            .unwrap();

        let key = Address::from(7u64);
        cache.put(key, cache_entity(7, "before"));

        let outcome = cache.modify(&key, |entity| {
            entity.name = "after".to_owned();
            entity.id
        });
        assert_eq!(outcome, Some(7));

        let stored = storage.get::<Address, CacheEntity>(&key).unwrap();
        assert_eq!(stored, Some(cache_entity(7, "after")));
    }

    #[test]
    fn cache_modify_missing_entry_returns_none() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let mut cache = storage
            .cache_for::<Address, CacheEntity>(64 * 1024)
            .unwrap();

        let outcome = cache.modify(&Address::from(11u64), |entity: &mut CacheEntity| entity.id);
        assert_eq!(outcome, None);
    }

    #[test]
    fn cache_get_mut_persists_on_drop() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let mut cache = storage
            .cache_for::<Address, CacheEntity>(64 * 1024)
            .unwrap();

        let key = Address::from(13u64);
        cache.put(key, cache_entity(13, "before"));

        {
            let mut guard = cache.get_mut(&key).expect("entry exists");
            guard.name = "after".to_owned();
        }

        let stored = storage.get::<Address, CacheEntity>(&key).unwrap();
        assert_eq!(stored, Some(cache_entity(13, "after")));
    }

    #[test]
    fn cache_remove_hides_entry_everywhere() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let cache = storage
            .cache_for::<Address, CacheEntity>(64 * 1024)
            .unwrap();

        let key = Address::from(9u64);
        cache.put(key, cache_entity(9, "nine"));
        cache.remove(&key);

        assert!(cache.get(&key).is_none());
        assert!(!cache.contains(&key));
        assert!(storage.get::<Address, CacheEntity>(&key).unwrap().is_none());
    }

    #[test]
    fn writeback_put_then_flush_persists() {
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
    fn writeback_reads_survive_eviction_before_flush() {
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
    fn writeback_remove_then_flush_clears_storage() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        let cache =
            EntityCache::<Address, CacheEntity>::with_worker(storage.clone(), worker, 64 * 1024);

        let key = Address::from(9u64);
        cache.put(key, cache_entity(9, "nine"));
        cache.flush().unwrap();
        assert!(storage.get::<Address, CacheEntity>(&key).unwrap().is_some());

        cache.remove(&key);
        cache.flush().unwrap();

        assert!(cache.get(&key).is_none());
        assert!(storage.get::<Address, CacheEntity>(&key).unwrap().is_none());
    }

    #[test]
    fn writeback_shutdown_flushes_pending() {
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
    fn writeback_commit_failure_poisons_worker() {
        let storage = EntityStorage::new(FailingBulkProvider(InMemoryEntityStorage::new()));
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
