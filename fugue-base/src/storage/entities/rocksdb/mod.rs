use std::mem;
use std::path::PathBuf;

use crate::loader::Loadable;
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;
use crate::types::{AttributeMap, BytesOrSlice};

pub mod options;

use super::{
    EntityBytesBulkInserter, EntityBytesIterator, EntityBytesTransactionalReader,
    EntityBytesTransactionalWriter, EntityKeyBytesIterator, EntityStorageBulkInserter,
    EntityStorageError, EntityStorageProvider, EntityStorageProviderFromLoadable,
    EntityStorageTransactionalReader, EntityStorageTransactionalWriter,
};

pub const ATTRIBUTE_ENTITY_STORAGE_ROCKSDB_OPTIONS: &str =
    "storage.entities.backend.rocksdb.options";

const PROJECT_ROCKSDB_DATA: &str = "entities.db";

// Maximum batch size for bulk operations
const BATCH_SIZE: usize = 1024;
// Maximum size of a batch in bytes
const BATCH_MEMORY_LIMIT: usize = 4 * 1024 * 1024; // 4 MiB

impl From<rocksdb::Error> for EntityStorageError {
    fn from(error: rocksdb::Error) -> Self {
        EntityStorageError::backing(error)
    }
}

pub struct RocksDbEntityStorage {
    database: rocksdb::OptimisticTransactionDB,
}

impl EntityStorageProviderFromLoadable for RocksDbEntityStorage {
    fn from_loadable(
        _loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError> {
        let project_path = attributes
            .get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH)
            .ok_or(EntityStorageError::NoProjectPath)?;

        let db_path = project_path.join(PROJECT_ROCKSDB_DATA);

        let mut options = rocksdb::Options::default();

        options.create_if_missing(true);

        options.set_recycle_log_file_num(5);
        options.set_keep_log_file_num(5);

        if let Some(db_options) =
            attributes.get_attr::<options::RocksDbOptions>(ATTRIBUTE_ENTITY_STORAGE_ROCKSDB_OPTIONS)
        {
            db_options.apply(&mut options);
        }

        Ok(Self {
            database: rocksdb::OptimisticTransactionDB::open(&options, db_path)?,
        })
    }
}

impl EntityStorageProvider for RocksDbEntityStorage {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        // TODO: add get_as so we can operate on PinnedSlice?
        Ok(self
            .database
            .get(key)
            .map_err(EntityStorageError::backing)?
            .map(BytesOrSlice::from))
    }

    fn get_as<F, T>(&self, key: &[u8], mut f: F) -> Result<Option<T>, EntityStorageError>
    where
        F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
    {
        self.database
            .get_pinned(key)
            .map_err(EntityStorageError::backing)?
            .map(|pinned| f(pinned.as_ref()))
            .transpose()
    }

    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        self.database
            .put(key, value)
            .map_err(EntityStorageError::backing)
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        self.database
            .delete(key)
            .map_err(EntityStorageError::backing)
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        if !self.database.key_may_exist(key) {
            return Ok(false);
        }

        // TODO: check if there's a more efficient way to check this without
        // fetching the value
        self.database
            .get_pinned(key)
            .map_err(EntityStorageError::backing)
            .map(|opt| opt.is_some())
    }

    fn iter_prefix_keys<'a>(
        &self,
        prefix: &[u8],
    ) -> Result<EntityKeyBytesIterator<'_>, EntityStorageError> {
        let mut opts = rocksdb::ReadOptions::default();
        opts.set_iterate_range(rocksdb::PrefixRange(prefix.to_vec()));

        Ok(RocksDbEntityKeyBytesIterator::new(
            self.database.raw_iterator_opt(opts),
        ))
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        Ok(RocksDbEntityBytesIterator::new(
            self.database.prefix_iterator(prefix),
        ))
    }

    fn bulk_inserter(&self) -> Result<EntityBytesBulkInserter, EntityStorageError> {
        Ok(RocksDbEntityInserter::new(self))
    }

    fn transactional_reader(&self) -> Result<EntityBytesTransactionalReader, EntityStorageError> {
        RocksDbEntityTransaction::new_reader(self)
    }

    fn transactional_writer(&self) -> Result<EntityBytesTransactionalWriter, EntityStorageError> {
        RocksDbEntityTransaction::new_writer(self)
    }
}

#[repr(transparent)]
struct RocksDbEntityKeyBytesIterator<'a, T>
where
    T: rocksdb::DBAccess,
{
    iter: rocksdb::DBRawIteratorWithThreadMode<'a, T>,
}

impl<'a, T> RocksDbEntityKeyBytesIterator<'a, T>
where
    T: rocksdb::DBAccess,
{
    fn new(iter: rocksdb::DBRawIteratorWithThreadMode<'a, T>) -> EntityKeyBytesIterator<'a> {
        Box::new(Self { iter })
    }
}

impl<'a, T> Iterator for RocksDbEntityKeyBytesIterator<'a, T>
where
    T: rocksdb::DBAccess,
{
    type Item = Result<BytesOrSlice<'a>, EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.iter.valid() {
            return None;
        }

        let key = BytesOrSlice::from(self.iter.key()?.to_vec());

        self.iter.next();

        Some(Ok(key))
    }
}

#[repr(transparent)]
struct RocksDbEntityBytesIterator<'a, T>
where
    T: rocksdb::DBAccess,
{
    iter: rocksdb::DBIteratorWithThreadMode<'a, T>,
}

impl<'a, T> RocksDbEntityBytesIterator<'a, T>
where
    T: rocksdb::DBAccess,
{
    fn new(iter: rocksdb::DBIteratorWithThreadMode<'a, T>) -> EntityBytesIterator<'a> {
        Box::new(Self { iter })
    }
}

impl<'a, T> Iterator for RocksDbEntityBytesIterator<'a, T>
where
    T: rocksdb::DBAccess,
{
    type Item = Result<(BytesOrSlice<'a>, BytesOrSlice<'a>), EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|kv| {
            kv.map(|(key, val)| {
                (
                    BytesOrSlice::from(key.into_vec()),
                    BytesOrSlice::from(val.into_vec()),
                )
            })
            .map_err(EntityStorageError::backing)
        })
    }
}

struct RocksDbEntityInserter<'a> {
    storage: &'a RocksDbEntityStorage,
    batch: rocksdb::WriteBatchWithTransaction<true>,
}

impl<'a> RocksDbEntityInserter<'a> {
    fn new(storage: &'a RocksDbEntityStorage) -> EntityBytesBulkInserter<'a> {
        Box::new(Self {
            storage,
            batch: rocksdb::WriteBatchWithTransaction::<true>::default(),
        })
    }
}

impl<'a> Drop for RocksDbEntityInserter<'a> {
    fn drop(&mut self) {
        // if the inserter is dropped without committing, we should still flush the batch
        if self.batch.is_empty() {
            return;
        }

        let batch = mem::take(&mut self.batch);

        if let Err(e) = self.storage.database.write(batch) {
            tracing::warn!("failed to flush batch to storage: {e}")
        }
    }
}

impl<'a> EntityStorageBulkInserter<'a> for RocksDbEntityInserter<'a> {
    fn insert(
        &mut self,
        key: BytesOrSlice<'a>,
        value: BytesOrSlice<'a>,
    ) -> Result<(), EntityStorageError> {
        // flush the current batch before inserting more, if it exceeds the limits
        if self.batch.len() >= BATCH_SIZE || self.batch.size_in_bytes() >= BATCH_MEMORY_LIMIT {
            let batch = std::mem::take(&mut self.batch);
            self.storage
                .database
                .write(batch)
                .map_err(EntityStorageError::backing)?;
        }

        self.batch.put(key, value);

        Ok(())
    }

    fn commit(mut self: Box<Self>) -> Result<(), EntityStorageError> {
        let batch = mem::take(&mut self.batch);
        self.storage
            .database
            .write(batch)
            .map_err(EntityStorageError::backing)
    }
}

struct RocksDbEntityTransaction<'a> {
    txn: rocksdb::Transaction<'a, rocksdb::OptimisticTransactionDB>,
}

impl<'a> RocksDbEntityTransaction<'a> {
    fn new_reader(
        storage: &'a RocksDbEntityStorage,
    ) -> Result<EntityBytesTransactionalReader<'a>, EntityStorageError> {
        let txn = storage.database.transaction();
        Ok(Box::new(Self { txn }))
    }

    fn new_writer(
        storage: &'a RocksDbEntityStorage,
    ) -> Result<EntityBytesTransactionalWriter<'a>, EntityStorageError> {
        let txn = storage.database.transaction();
        Ok(Box::new(Self { txn }))
    }
}

impl<'a> EntityStorageTransactionalReader<'a> for RocksDbEntityTransaction<'a> {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        self.txn
            .get(key)
            .map_err(EntityStorageError::backing)
            .map(|opt| opt.map(BytesOrSlice::from))
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        self.txn
            .get_pinned(key)
            .map_err(EntityStorageError::backing)
            .map(|opt| opt.is_some())
    }
}

impl<'a> EntityStorageTransactionalWriter<'a> for RocksDbEntityTransaction<'a> {
    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        self.txn
            .put(key, value)
            .map_err(EntityStorageError::backing)
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        self.txn.delete(key).map_err(EntityStorageError::backing)
    }

    fn commit(self: Box<Self>) -> Result<(), EntityStorageError> {
        self.txn.commit().map_err(EntityStorageError::backing)
    }
}
