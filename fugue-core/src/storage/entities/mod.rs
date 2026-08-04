use std::fmt::Debug;
use std::io;
use std::mem::align_of;
use std::ops::{Bound, Deref};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::vec::IntoIter;

use bytes::Bytes;
use rkyv::Archived;
use rkyv::api::root_position;
use rkyv::rancor::Error as RkyvError;
use rkyv::util::AlignedVec;
use thiserror::Error;

use crate::loader::Loadable;
use crate::storage::{PERSISTENT, StoragePersistence, TRANSIENT};
use crate::types::any::Out;
use crate::types::{AttributeMap, BytesOrSlice};

pub(crate) mod dummy;
pub use dummy::DummyEntityStorage;

pub(crate) mod memory;
pub use memory::InMemoryEntityStorage;

#[cfg(feature = "mdbx")]
pub(crate) mod mdbx;
#[cfg(feature = "mdbx")]
pub use mdbx::{ATTRIBUTE_ENTITY_STORAGE_MDBX_OPTIONS, MdbxEntityStorage, MdbxOptions};

#[cfg(feature = "rocksdb")]
pub(crate) mod rocksdb;
#[cfg(feature = "rocksdb")]
pub use rocksdb::options::RocksDbOptions;
#[cfg(feature = "rocksdb")]
pub use rocksdb::{ATTRIBUTE_ENTITY_STORAGE_ROCKSDB_OPTIONS, RocksDbEntityStorage};

pub(crate) mod schema;
pub use schema::{
    ENTITY_PROJECT_REVISION_ID, Entity, EntityId, EntityKey, EntityKeyBytes, EntityKeyId,
    EntityKeyPrefix, ProjectEntity,
};

#[cfg(feature = "sqlite")]
pub(crate) mod sqlite;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteEntityStorage;

pub(crate) mod writer;
pub use writer::{WriteBackAction, WriteBackWorker};

pub(crate) mod cache;
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
    #[error("no project path specified")]
    NoProjectPath,
    #[error("failed to load project data from `{0}`: {1}")]
    ProjectData(PathBuf, io::ErrorKind),
    #[error(transparent)]
    Unsupported(anyhow::Error),
    #[error("write-back worker poisoned: {0}")]
    WriteBackPoisoned(String),
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

    pub fn write_back_poisoned(message: impl Into<String>) -> Self {
        Self::WriteBackPoisoned(message.into())
    }

    pub fn is_write_back_poisoned(&self) -> bool {
        matches!(self, Self::WriteBackPoisoned(_))
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

pub(super) fn decode_entity<E: Entity>(bytes: &[u8]) -> Result<E, EntityStorageError> {
    let root = root_position::<Archived<E>>(bytes.len());
    let root_pointer = bytes.as_ptr().wrapping_add(root);
    if root_pointer.align_offset(align_of::<Archived<E>>()) == 0
        && let Ok(entity) = rkyv::from_bytes::<E, RkyvError>(bytes)
    {
        return Ok(entity);
    }

    let mut aligned = AlignedVec::<16>::with_capacity(bytes.len());
    aligned.extend_from_slice(bytes);
    rkyv::from_bytes::<E, RkyvError>(&aligned).map_err(EntityStorageError::decode)
}

pub type EntityBytesIterator<'a> =
    Box<dyn Iterator<Item = Result<(BytesOrSlice<'a>, BytesOrSlice<'a>), EntityStorageError>> + 'a>;

pub type EntityKeyBytesIterator<'a> =
    Box<dyn Iterator<Item = Result<BytesOrSlice<'a>, EntityStorageError>> + 'a>;

pub type EntityIterator<'a, K, E> =
    Box<dyn Iterator<Item = Result<(K, E), EntityStorageError>> + 'a>;

pub type EntityKeyIterator<'a, K> = Box<dyn Iterator<Item = Result<K, EntityStorageError>> + 'a>;

#[derive(Debug)]
pub struct EntityWrite {
    key: EntityKeyBytes,
    value: Option<EntityWriteValue>,
}

#[derive(Debug)]
enum EntityWriteValue {
    Archive(AlignedVec),
    Shared(Bytes),
}

impl EntityWriteValue {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Archive(value) => value.as_ref(),
            Self::Shared(value) => value.as_ref(),
        }
    }
}

impl EntityWrite {
    pub fn insert(key: impl Into<EntityKeyBytes>, value: Bytes) -> Self {
        Self {
            key: key.into(),
            value: Some(EntityWriteValue::Shared(value)),
        }
    }

    pub(crate) fn insert_archived(key: impl Into<EntityKeyBytes>, value: AlignedVec) -> Self {
        Self {
            key: key.into(),
            value: Some(EntityWriteValue::Archive(value)),
        }
    }

    pub fn remove(key: impl Into<EntityKeyBytes>) -> Self {
        Self {
            key: key.into(),
            value: None,
        }
    }

    pub fn key(&self) -> &[u8] {
        self.key.as_ref()
    }

    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_ref().map(EntityWriteValue::as_slice)
    }
}

#[derive(Default)]
pub(crate) struct EntityWriteBatch {
    writes: Vec<EntityWrite>,
}

impl EntityWriteBatch {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            writes: Vec::with_capacity(capacity),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.writes.clear();
    }

    pub(crate) fn insert_entity<K, E>(
        &mut self,
        key: &K,
        entity: &E,
    ) -> Result<(), EntityStorageError>
    where
        K: EntityKey,
        E: Entity,
    {
        let encoded =
            rkyv::to_bytes::<rkyv::rancor::Error>(entity).map_err(EntityStorageError::encode)?;
        self.push(EntityWrite::insert_archived(E::ID.key_for(key), encoded));
        Ok(())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.writes.len()
    }

    pub(crate) fn push(&mut self, write: EntityWrite) {
        self.writes.push(write);
    }

    pub(crate) fn remove_entity<K, E>(&mut self, key: &K)
    where
        K: EntityKey,
        E: Entity,
    {
        self.push(EntityWrite::remove(E::ID.key_for(key)));
    }

    pub(crate) fn sort_by_key(&mut self) {
        self.writes
            .sort_unstable_by(|left, right| left.key().cmp(right.key()));
    }
}

impl Extend<EntityWrite> for EntityWriteBatch {
    fn extend<T>(&mut self, writes: T)
    where
        T: IntoIterator<Item = EntityWrite>,
    {
        self.writes.extend(writes);
    }
}

impl IntoIterator for EntityWriteBatch {
    type Item = EntityWrite;
    type IntoIter = IntoIter<EntityWrite>;

    fn into_iter(self) -> Self::IntoIter {
        self.writes.into_iter()
    }
}

impl Deref for EntityWriteBatch {
    type Target = [EntityWrite];

    fn deref(&self) -> &Self::Target {
        &self.writes
    }
}

pub trait EntityStorageReadTransaction {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError>;
    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError>;
}

pub type EntityBytesReadTransaction<'a> = Box<dyn EntityStorageReadTransaction + 'a>;

pub struct EntityReadTransaction<'a> {
    inner: EntityBytesReadTransaction<'a>,
}

impl<'a> EntityReadTransaction<'a> {
    pub fn new(inner: EntityBytesReadTransaction<'a>) -> Self {
        Self { inner }
    }

    pub fn get<K: EntityKey, E: Entity>(&self, key: &K) -> Result<Option<E>, EntityStorageError> {
        let key = E::ID.key_for(key);
        self.inner
            .get(&key)?
            .map(|bytes| decode_entity(bytes.as_slice()))
            .transpose()
    }

    pub fn get_as<K, E, F, T>(&self, key: &K, mut f: F) -> Result<Option<T>, EntityStorageError>
    where
        K: EntityKey,
        E: Entity,
        F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
    {
        let key = E::ID.key_for(key);
        self.inner
            .get(&key)?
            .map(|bytes| f(bytes.as_slice()))
            .transpose()
    }

    pub fn contains<K: EntityKey, E: Entity>(&self, key: &K) -> Result<bool, EntityStorageError> {
        let key = E::ID.key_for(key);
        self.inner.contains(&key)
    }
}

pub trait EntityStorageWriteTransaction {
    fn insert(&mut self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError>;
    fn remove(&mut self, key: &[u8]) -> Result<(), EntityStorageError>;

    fn write_batch(&mut self, writes: &[EntityWrite]) -> Result<(), EntityStorageError> {
        for write in writes {
            match write.value() {
                Some(value) => self.insert(write.key(), BytesOrSlice::from(value))?,
                None => self.remove(write.key())?,
            }
        }
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<(), EntityStorageError>;
}

pub type EntityBytesWriteTransaction<'a> = Box<dyn EntityStorageWriteTransaction + 'a>;

pub struct EntityWriteTransaction<'a> {
    inner: Option<EntityBytesWriteTransaction<'a>>,
    auto_commit: bool,
}

impl<'a> EntityWriteTransaction<'a> {
    pub fn new(inner: EntityBytesWriteTransaction<'a>) -> Self {
        Self {
            inner: Some(inner),
            auto_commit: false,
        }
    }

    pub fn insert<K: EntityKey, E: Entity>(
        &mut self,
        key: &K,
        entity: &E,
    ) -> Result<(), EntityStorageError> {
        let key = E::ID.key_for(key);
        let encoded =
            rkyv::to_bytes::<rkyv::rancor::Error>(entity).map_err(EntityStorageError::encode)?;
        self.inner
            .as_mut()
            .expect("write transaction available")
            .insert(&key, BytesOrSlice::from(encoded.as_ref()))
    }

    pub fn remove<K: EntityKey, E: Entity>(&mut self, key: &K) -> Result<(), EntityStorageError> {
        let key = E::ID.key_for(key);
        self.inner
            .as_mut()
            .expect("write transaction available")
            .remove(&key)
    }

    pub fn enable_auto_commit(&mut self) {
        self.auto_commit = true;
    }

    pub fn disable_auto_commit(&mut self) {
        self.auto_commit = false;
    }

    pub fn commit(mut self) -> Result<(), EntityStorageError> {
        self.inner
            .take()
            .expect("write transaction available")
            .commit()
    }
}

impl Drop for EntityWriteTransaction<'_> {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        if self.auto_commit
            && let Err(error) = inner.commit()
        {
            tracing::error!("failed to commit transaction: {error}");
        }
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

pub type EntityBytesAsIterator<'a, T> =
    Box<dyn Iterator<Item = Result<T, EntityStorageError>> + 'a>;
#[cfg(any(feature = "mdbx", feature = "rocksdb"))]
pub(crate) type EntityBytesMapper<'a, T> =
    dyn FnMut(&[u8], &[u8]) -> Result<T, EntityStorageError> + 'a;

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
    fn iter_range(
        &self,
        prefix: &[u8],
        start: Bound<&[u8]>,
    ) -> Result<EntityBytesIterator<'_>, EntityStorageError>;
    fn iter_prefix_as<'a, F, T>(
        &'a self,
        prefix: &[u8],
        f: F,
    ) -> Result<EntityBytesAsIterator<'a, T>, EntityStorageError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<T, EntityStorageError> + 'a,
        T: 'a;

    fn read_transaction(&self) -> Result<EntityBytesReadTransaction, EntityStorageError>;
    fn write_transaction(&self) -> Result<EntityBytesWriteTransaction, EntityStorageError>;

    fn persistence(&self) -> StoragePersistence {
        PERSISTENT
    }
}

enum BufferedEntityWrite {
    Insert(Bytes, Bytes),
    Remove(Bytes),
}

pub struct BufferedEntityWriter<'a, S>
where
    S: EntityStorageProvider + ?Sized,
{
    storage: &'a S,
    writes: Vec<BufferedEntityWrite>,
}

impl<'a, S> BufferedEntityWriter<'a, S>
where
    S: EntityStorageProvider + ?Sized,
{
    pub fn new(storage: &'a S) -> Self {
        Self {
            storage,
            writes: Vec::new(),
        }
    }
}

impl<S> EntityStorageWriteTransaction for BufferedEntityWriter<'_, S>
where
    S: EntityStorageProvider + ?Sized,
{
    fn insert(&mut self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        if key.len() < schema::ENTITY_PREFIX_SIZE {
            return Err(EntityStorageError::InvalidKeyFormat);
        }
        self.writes.push(BufferedEntityWrite::Insert(
            Bytes::copy_from_slice(key),
            value.into_bytes(),
        ));
        Ok(())
    }

    fn remove(&mut self, key: &[u8]) -> Result<(), EntityStorageError> {
        if key.len() < schema::ENTITY_PREFIX_SIZE {
            return Err(EntityStorageError::InvalidKeyFormat);
        }
        self.writes
            .push(BufferedEntityWrite::Remove(Bytes::copy_from_slice(key)));
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<(), EntityStorageError> {
        for write in self.writes {
            match write {
                BufferedEntityWrite::Insert(key, value) => {
                    self.storage
                        .insert(key.as_ref(), BytesOrSlice::from(value))?;
                }
                BufferedEntityWrite::Remove(key) => {
                    self.storage.remove(key.as_ref())?;
                }
            }
        }
        Ok(())
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
    fn erased_iter_range(
        &self,
        prefix: &[u8],
        start: Bound<&[u8]>,
    ) -> Result<EntityBytesIterator<'_>, EntityStorageError>;
    fn erased_iter_prefix_as<'a>(
        &'a self,
        prefix: &[u8],
        mapper: OutMapper2<'a>,
    ) -> Result<EntityBytesAsIterator<'a, Out>, EntityStorageError>;

    fn erased_read_transaction(&self) -> Result<EntityBytesReadTransaction, EntityStorageError>;

    fn erased_write_transaction(&self) -> Result<EntityBytesWriteTransaction, EntityStorageError>;

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

    fn iter_range(
        &self,
        prefix: &[u8],
        start: Bound<&[u8]>,
    ) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        self.erased_iter_range(prefix, start)
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

    fn read_transaction(&self) -> Result<EntityBytesReadTransaction, EntityStorageError> {
        self.erased_read_transaction()
    }

    fn write_transaction(&self) -> Result<EntityBytesWriteTransaction, EntityStorageError> {
        self.erased_write_transaction()
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

    fn erased_iter_range(
        &self,
        prefix: &[u8],
        start: Bound<&[u8]>,
    ) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        self.iter_range(prefix, start)
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

    fn erased_read_transaction(&self) -> Result<EntityBytesReadTransaction, EntityStorageError> {
        self.read_transaction()
    }

    fn erased_write_transaction(&self) -> Result<EntityBytesWriteTransaction, EntityStorageError> {
        self.write_transaction()
    }

    fn erased_persistence(&self) -> StoragePersistence {
        self.persistence()
    }
}

type OutMapFn<'a> = dyn FnMut(&[u8]) -> Result<Out, EntityStorageError> + 'a;
type OutMapPairFn<'a> = dyn FnMut(&[u8], &[u8]) -> Result<Out, EntityStorageError> + 'a;

pub struct OutMapper<'a> {
    f: Box<OutMapFn<'a>>,
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
    f: Box<OutMapPairFn<'a>>,
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
        let key = E::ID.key_for(key);
        self.backing.get_as(&key, decode_entity::<E>)
    }

    pub fn get_as<K, E, F, T>(&self, key: &K, f: F) -> Result<Option<T>, EntityStorageError>
    where
        K: EntityKey,
        E: Entity,
        F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
    {
        let key = E::ID.key_for(key);
        self.backing.get_as(&key, f)
    }

    pub fn insert<K: EntityKey, E: Entity>(
        &self,
        key: &K,
        entity: &E,
    ) -> Result<(), EntityStorageError> {
        let key = E::ID.key_for(key);
        let encoded =
            rkyv::to_bytes::<rkyv::rancor::Error>(entity).map_err(EntityStorageError::encode)?;
        self.backing
            .insert(&key, BytesOrSlice::from(encoded.as_ref()))
    }

    pub fn insert_bytes<K: EntityKey, E: Entity>(
        &self,
        key: &K,
        value: BytesOrSlice<'_>,
    ) -> Result<(), EntityStorageError> {
        let key = E::ID.key_for(key);
        self.backing.insert(&key, value)
    }

    pub fn remove<K: EntityKey, E: Entity>(&self, key: &K) -> Result<(), EntityStorageError> {
        let key = E::ID.key_for(key);
        self.backing.remove(&key)
    }

    pub fn contains<K: EntityKey, E: Entity>(&self, key: &K) -> Result<bool, EntityStorageError> {
        let key = E::ID.key_for(key);
        self.backing.contains(&key)
    }

    pub fn iter<K: EntityKey, E: Entity>(
        &self,
    ) -> Result<EntityIterator<'_, K, E>, EntityStorageError> {
        let pfx = EntityKeyPrefix::of::<K, E>();
        self.backing.iter_prefix(pfx.as_ref()).map(|iter| {
            Box::new(iter.map(|result| {
                result.and_then(|(key, value)| {
                    let key = EntityKeyPrefix::extract::<K, E>(key)
                        .ok_or(EntityStorageError::InvalidKeyFormat)?;
                    let val = decode_entity::<E>(value.as_slice())?;
                    Ok((key, val))
                })
            })) as EntityIterator<'_, K, E>
        })
    }

    pub fn iter_range<K: EntityKey, E: Entity>(
        &self,
        start: Bound<&K>,
    ) -> Result<EntityIterator<'_, K, E>, EntityStorageError> {
        let pfx = EntityKeyPrefix::of::<K, E>();
        let start_key = match start {
            Bound::Included(key) => Bound::Included(E::ID.key_for(key)),
            Bound::Excluded(key) => Bound::Excluded(E::ID.key_for(key)),
            Bound::Unbounded => Bound::Unbounded,
        };
        let start = match start_key.as_ref() {
            Bound::Included(key) => Bound::Included(&key[..]),
            Bound::Excluded(key) => Bound::Excluded(&key[..]),
            Bound::Unbounded => Bound::Unbounded,
        };

        self.backing.iter_range(pfx.as_ref(), start).map(|iter| {
            Box::new(iter.map(|result| {
                result.and_then(|(key, value)| {
                    let key = EntityKeyPrefix::extract::<K, E>(key)
                        .ok_or(EntityStorageError::InvalidKeyFormat)?;
                    let val = decode_entity::<E>(value.as_slice())?;
                    Ok((key, val))
                })
            })) as EntityIterator<'_, K, E>
        })
    }

    pub fn keys<K: EntityKey, E: Entity>(
        &self,
    ) -> Result<EntityKeyIterator<'_, K>, EntityStorageError> {
        let pfx = EntityKeyPrefix::of::<K, E>();
        self.backing.iter_prefix_keys(pfx.as_ref()).map(|iter| {
            Box::new(iter.map(|result| {
                result.and_then(|key| {
                    EntityKeyPrefix::extract::<K, E>(key)
                        .ok_or(EntityStorageError::InvalidKeyFormat)
                })
            })) as EntityKeyIterator<'_, K>
        })
    }

    pub fn read_transaction(&self) -> Result<EntityReadTransaction<'_>, EntityStorageError> {
        let reader = self.backing.read_transaction()?;
        Ok(EntityReadTransaction::new(reader))
    }

    pub fn write_transaction(&self) -> Result<EntityWriteTransaction<'_>, EntityStorageError> {
        let writer = self.backing.write_transaction()?;
        Ok(EntityWriteTransaction::new(writer))
    }

    pub(crate) fn apply_batch(&self, writes: &[EntityWrite]) -> Result<(), EntityStorageError> {
        if writes.is_empty() {
            return Ok(());
        }

        let result = (|| {
            let mut writer = self.backing.write_transaction()?;
            writer.write_batch(writes)?;
            writer.commit()
        })();
        result.map_err(|error| {
            if matches!(error, EntityStorageError::Unsupported(_)) {
                EntityStorageError::unsupported_with(
                    "entity storage does not support atomic batch admission",
                )
            } else {
                error
            }
        })
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
    #[cfg(feature = "sqlite")]
    use crate::ir::{Switch, SwitchId, SwitchModel};

    #[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    struct TestEntity {
        id: u64,
        name: String,
    }

    impl Entity for TestEntity {
        const ID: EntityId = EntityId::new(0);
    }

    #[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    struct TestTableEntity {
        values: Vec<u64>,
    }

    impl Entity for TestTableEntity {
        const ID: EntityId = EntityId::new(1);
    }

    struct TestReadTransaction;

    impl EntityStorageReadTransaction for TestReadTransaction {
        fn get(&self, _key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
            Ok(Some(BytesOrSlice::from(Vec::new())))
        }

        fn contains(&self, _key: &[u8]) -> Result<bool, EntityStorageError> {
            Ok(true)
        }
    }

    #[test]
    fn decode_entity_accepts_unaligned_backend_bytes() -> Result<(), EntityStorageError> {
        let entity = TestEntity {
            id: 1,
            name: "unaligned".to_owned(),
        };
        let encoded = rkyv::to_bytes::<RkyvError>(&entity).map_err(EntityStorageError::encode)?;
        let mut storage = AlignedVec::<16>::with_capacity(encoded.len() + 1);
        storage.push(0);
        storage.extend_from_slice(&encoded);
        let bytes = &storage[1..];

        let root = root_position::<Archived<TestEntity>>(bytes.len());
        let root_pointer = bytes.as_ptr().wrapping_add(root);
        assert_ne!(
            root_pointer.align_offset(align_of::<Archived<TestEntity>>()),
            0
        );
        assert_eq!(decode_entity::<TestEntity>(bytes)?, entity);
        Ok(())
    }

    #[test]
    fn decode_entity_accepts_aligned_root_with_unaligned_interior() -> Result<(), EntityStorageError>
    {
        let entity = TestTableEntity {
            values: vec![1, 2, 3],
        };
        let encoded = rkyv::to_bytes::<RkyvError>(&entity).map_err(EntityStorageError::encode)?;
        let mut storage = AlignedVec::<16>::with_capacity(encoded.len() + 4);
        storage.extend_from_slice(&[0; 4]);
        storage.extend_from_slice(&encoded);
        let bytes = &storage[4..];

        let root = root_position::<Archived<TestTableEntity>>(bytes.len());
        let root_pointer = bytes.as_ptr().wrapping_add(root);
        assert_eq!(
            root_pointer.align_offset(align_of::<Archived<TestTableEntity>>()),
            0
        );
        assert_ne!(bytes.as_ptr().align_offset(align_of::<u64>()), 0);
        assert!(rkyv::from_bytes::<TestTableEntity, RkyvError>(bytes).is_err());
        assert_eq!(decode_entity::<TestTableEntity>(bytes)?, entity);
        Ok(())
    }

    #[test]
    fn read_transaction_get_as_preserves_closure_error_kind() {
        let address = Address::from(42u64);
        let reader = EntityReadTransaction::new(Box::new(TestReadTransaction));
        let error = reader
            .get_as::<_, TestEntity, _, ()>(&address, |_| {
                Err(EntityStorageError::backing_with("reader sentinel"))
            })
            .expect_err("reader closure error must be returned");
        assert!(matches!(error, EntityStorageError::Backing(_)));
    }

    #[test]
    fn storage_batch_requires_atomic_admission() {
        let storage = EntityStorage::new(DummyEntityStorage);
        let writes = [EntityWrite::insert(
            Bytes::from_static(b"key"),
            Bytes::from_static(b"value"),
        )];

        let error = storage
            .apply_batch(&writes)
            .expect_err("storage without transactions must reject the batch");

        assert!(matches!(error, EntityStorageError::Unsupported(_)));
    }

    #[test]
    fn failed_in_memory_batch_publishes_no_prefix() -> Result<(), EntityStorageError> {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let address = Address::from(42u64);
        let key = TestEntity::ID.key_for(&address);
        let entity = TestEntity {
            id: 42,
            name: "atomic".to_owned(),
        };
        let encoded = rkyv::to_bytes::<RkyvError>(&entity).map_err(EntityStorageError::encode)?;
        let writes = [
            EntityWrite::insert_archived(Bytes::copy_from_slice(&key), encoded),
            EntityWrite::insert(Bytes::from_static(b"x"), Bytes::from_static(b"value")),
        ];

        assert!(matches!(
            storage.apply_batch(&writes),
            Err(EntityStorageError::InvalidKeyFormat)
        ));
        assert!(storage.get::<_, TestEntity>(&address)?.is_none());
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn failed_sqlite_batch_publishes_no_prefix() -> Result<(), EntityStorageError> {
        let storage = EntityStorage::new(SqliteEntityStorage::<TRANSIENT>::new()?);
        let id = SwitchId::new(0);
        let key = Switch::ID.key_for(&id);
        let switch = Switch::new(id, Address::from(42u64), SwitchModel::Explicit);
        let encoded = rkyv::to_bytes::<RkyvError>(&switch).map_err(EntityStorageError::encode)?;
        let writes = [
            EntityWrite::insert_archived(Bytes::copy_from_slice(&key), encoded),
            EntityWrite::insert(Bytes::from_static(b"x"), Bytes::from_static(b"value")),
        ];

        assert!(matches!(
            storage.apply_batch(&writes),
            Err(EntityStorageError::InvalidKeyFormat)
        ));
        assert!(!storage.contains::<_, Switch>(&id)?);
        Ok(())
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
        for i in 0u64..10 {
            let entity = TestEntity {
                id: i,
                name: format!("Entity {i}"),
            };
            storage.insert(&Address::from(i), &entity).unwrap();
        }

        // iterate over entities
        let iter = storage.iter::<Address, TestEntity>().unwrap();
        for (count, val) in iter.enumerate() {
            let count = count as u64;
            let (address, entity) = val.unwrap();
            let expected = TestEntity {
                id: count,
                name: format!("Entity {count}"),
            };
            assert_eq!(entity, expected);
            assert_eq!(address, Address::from(count));
        }

        // iterate over keys
        let key_iter = storage.keys::<Address, TestEntity>().unwrap();
        for (key_count, key) in key_iter.enumerate() {
            let address = key.unwrap();
            assert_eq!(address, Address::from(key_count as u64));
        }

        // test a cache
        let cache = EntityCache::<Address, TestEntity>::new(storage.clone(), 64 * 1024).unwrap();

        for i in 0u64..5 {
            let entity = TestEntity {
                id: i,
                name: format!("Entity {i}"),
            };
            let cached = cache.get(&Address::from(i));

            assert!(cached.is_some());
            assert_eq!(*cached.unwrap(), entity);
        }

        for i in 50u64..100 {
            let entity = TestEntity {
                id: i,
                name: format!("New Cached Entity {i}"),
            };
            cache.insert(Address::from(i), entity);
        }

        for i in 50u64..100 {
            let cached = cache.get(&Address::from(i));
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
