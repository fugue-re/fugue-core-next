use std::cell::RefCell;
use std::fmt::Debug;
use std::io;
use std::mem::{ManuallyDrop, align_of};
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bitflags::bitflags;
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
pub use mdbx::MdbxEntityStorage;

#[cfg(feature = "rocksdb")]
pub(crate) mod rocksdb;
#[cfg(feature = "rocksdb")]
pub use rocksdb::RocksDbEntityStorage;

pub(crate) mod schema;
pub use schema::{
    ENTITY_PROJECT_REVISION_ID, Entity, EntityId, EntityKey, EntityKeyId, EntityKeyPrefix,
    ProjectEntity, make_key_with_entity_id,
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
    key: Bytes,
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
    pub fn insert(key: Bytes, value: Bytes) -> Self {
        Self {
            key,
            value: Some(EntityWriteValue::Shared(value)),
        }
    }

    pub(crate) fn insert_archive(key: Bytes, value: AlignedVec) -> Self {
        Self {
            key,
            value: Some(EntityWriteValue::Archive(value)),
        }
    }

    pub fn remove(key: Bytes) -> Self {
        Self { key, value: None }
    }

    pub fn key(&self) -> &[u8] {
        self.key.as_ref()
    }

    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_ref().map(EntityWriteValue::as_slice)
    }
}

pub(crate) type EntityWriteBatch = Vec<EntityWrite>;

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
            .map(|bytes| decode_entity(bytes.as_slice()))
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
    }

    pub fn contains<K: EntityKey, E: Entity>(&self, key: &K) -> Result<bool, EntityStorageError> {
        let key = schema::make_key::<K, E>(key);
        self.inner.contains(&key)
    }
}

pub trait EntityStorageTransactionalWriter<'a>: EntityStorageTransactionalReader<'a> {
    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError>;
    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError>;

    fn apply_batch(&self, writes: &[EntityWrite]) -> Result<(), EntityStorageError> {
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
            .map(|bytes| decode_entity(bytes.as_slice()))
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

    fn transactional_reader(&self) -> Result<EntityBytesTransactionalReader, EntityStorageError>;
    fn transactional_writer(&self) -> Result<EntityBytesTransactionalWriter, EntityStorageError>;

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
    writes: RefCell<Vec<BufferedEntityWrite>>,
}

impl<'a, S> BufferedEntityWriter<'a, S>
where
    S: EntityStorageProvider + ?Sized,
{
    pub fn new(storage: &'a S) -> Self {
        Self {
            storage,
            writes: RefCell::new(Vec::new()),
        }
    }
}

impl<'a, S> EntityStorageTransactionalReader<'a> for BufferedEntityWriter<'a, S>
where
    S: EntityStorageProvider + ?Sized,
{
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        self.storage.get(key)
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        self.storage.contains(key)
    }
}

impl<'a, S> EntityStorageTransactionalWriter<'a> for BufferedEntityWriter<'a, S>
where
    S: EntityStorageProvider + ?Sized,
{
    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        if key.len() < schema::ENTITY_PREFIX_SIZE {
            return Err(EntityStorageError::InvalidKeyFormat);
        }
        self.writes.borrow_mut().push(BufferedEntityWrite::Insert(
            Bytes::copy_from_slice(key),
            value.into_bytes(),
        ));
        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        if key.len() < schema::ENTITY_PREFIX_SIZE {
            return Err(EntityStorageError::InvalidKeyFormat);
        }
        self.writes
            .borrow_mut()
            .push(BufferedEntityWrite::Remove(Bytes::copy_from_slice(key)));
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<(), EntityStorageError> {
        for write in self.writes.into_inner() {
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
        let key = schema::make_key::<K, E>(key);
        self.backing.get_as(&key, decode_entity::<E>)
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
        let pfx = schema::make_prefix::<K, E>();
        let start_key = match start {
            Bound::Included(key) => Bound::Included(schema::make_key::<K, E>(key)),
            Bound::Excluded(key) => Bound::Excluded(schema::make_key::<K, E>(key)),
            Bound::Unbounded => Bound::Unbounded,
        };
        let start = match start_key.as_ref() {
            Bound::Included(key) => Bound::Included(&key[..]),
            Bound::Excluded(key) => Bound::Excluded(&key[..]),
            Bound::Unbounded => Bound::Unbounded,
        };

        self.backing.iter_range(&pfx, start).map(|iter| {
            Box::new(iter.map(|result| {
                result.and_then(|(key, value)| {
                    let key = schema::extract_key::<K, E>(key)
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

    pub(crate) fn apply_batch(&self, writes: &[EntityWrite]) -> Result<(), EntityStorageError> {
        if writes.is_empty() {
            return Ok(());
        }

        let writer = self.backing.transactional_writer().map_err(|error| {
            if matches!(error, EntityStorageError::Unsupported(_)) {
                EntityStorageError::unsupported_with(
                    "entity storage does not support atomic batch admission",
                )
            } else {
                error
            }
        })?;
        writer.apply_batch(writes)?;
        writer.commit()
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

    struct TestTransactionalStorage;

    impl<'a> EntityStorageTransactionalReader<'a> for TestTransactionalStorage {
        fn get(&self, _key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
            Ok(Some(BytesOrSlice::from(Vec::new())))
        }

        fn contains(&self, _key: &[u8]) -> Result<bool, EntityStorageError> {
            Ok(true)
        }
    }

    impl<'a> EntityStorageTransactionalWriter<'a> for TestTransactionalStorage {
        fn insert(&self, _key: &[u8], _value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
            Ok(())
        }

        fn remove(&self, _key: &[u8]) -> Result<(), EntityStorageError> {
            Ok(())
        }

        fn commit(self: Box<Self>) -> Result<(), EntityStorageError> {
            Ok(())
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
    fn transactional_get_as_preserves_closure_error_kind() {
        let address = Address::from(42u64);
        let reader = EntityTransactionalReader::new(Box::new(TestTransactionalStorage));
        let error = reader
            .get_as::<_, TestEntity, _, ()>(&address, |_| {
                Err(EntityStorageError::backing_with("reader sentinel"))
            })
            .expect_err("reader closure error must be returned");
        assert!(matches!(error, EntityStorageError::Backing(_)));

        let writer = EntityTransactionalWriter::new(Box::new(TestTransactionalStorage));
        let error = writer
            .get_as::<_, TestEntity, _, ()>(&address, |_| {
                Err(EntityStorageError::backing_with("writer sentinel"))
            })
            .expect_err("writer closure error must be returned");
        assert!(matches!(error, EntityStorageError::Backing(_)));
    }

    #[test]
    fn storage_batch_requires_atomic_admission() {
        let storage = EntityStorage::new(DummyEntityStorage);
        let writes = [(
            Bytes::from_static(b"key"),
            Some(Bytes::from_static(b"value")),
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
        let key = schema::make_key::<Address, TestEntity>(&address);
        let entity = TestEntity {
            id: 42,
            name: "atomic".to_owned(),
        };
        let encoded = rkyv::to_bytes::<RkyvError>(&entity).map_err(EntityStorageError::encode)?;
        let writes = [
            (
                Bytes::copy_from_slice(&key),
                Some(Bytes::from(encoded.into_vec())),
            ),
            (Bytes::from_static(b"x"), Some(Bytes::from_static(b"value"))),
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
        let key = schema::make_key::<SwitchId, Switch>(&id);
        let switch = Switch::new(id, Address::from(42u64), SwitchModel::Explicit);
        let encoded = rkyv::to_bytes::<RkyvError>(&switch).map_err(EntityStorageError::encode)?;
        let writes = [
            (
                Bytes::copy_from_slice(&key),
                Some(Bytes::from(encoded.into_vec())),
            ),
            (Bytes::from_static(b"x"), Some(Bytes::from_static(b"value"))),
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
            cache.put(Address::from(i), entity);
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
