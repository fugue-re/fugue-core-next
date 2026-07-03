use std::fmt::Debug;
use std::io;
use std::mem::ManuallyDrop;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bitflags::bitflags;
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

#[cfg(feature = "sqlite")]
pub mod sqlite;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteEntityStorage;

pub mod writer;
pub use writer::{WriteBackAction, WriteBackWorker};

pub mod cache;
pub(crate) use cache::{CachedMut, CachedRef, EntityCache};
pub use cache::{EntityMut, EntityRef, MutableEntity};

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
        let cache = EntityCache::<Address, TestEntity>::new(storage.clone(), 64 * 1024).unwrap();

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
            cache.try_remove(&Address::from(i as u64)).unwrap();
            let cached = cache.get(&Address::from(i as u64));
            assert!(cached.is_none());

            let direct = storage
                .get::<Address, TestEntity>(&Address::from(i as u64))
                .unwrap();
            assert!(direct.is_none());
        }
    }
}
