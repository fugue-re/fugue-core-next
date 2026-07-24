use std::io;
use std::ops::Bound;
use std::path::{Path, PathBuf};

use crate::loader::Loadable;
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;
use crate::types::{AttributeMap, BytesOrSlice};

pub mod options;

use super::{
    EntityBytesAsIterator, EntityBytesIterator, EntityBytesTransactionalReader,
    EntityBytesTransactionalWriter, EntityKeyBytesIterator, EntityStorageError,
    EntityStorageProvider, EntityStorageProviderFromLoadable, EntityStorageProviderFromStorage,
    EntityStorageTransactionalReader, EntityStorageTransactionalWriter,
};

pub const ATTRIBUTE_ENTITY_STORAGE_ROCKSDB_OPTIONS: &str = "storage.entities.rocksdb.options";

const PROJECT_ROCKSDB_DATA: &str = "entities.db";

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

impl EntityStorageProviderFromStorage for RocksDbEntityStorage {
    fn from_storage(
        path: impl AsRef<Path>,
        attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError>
    where
        Self: Sized,
    {
        let project_path = path.as_ref();
        let db_path = project_path.join(PROJECT_ROCKSDB_DATA);

        if !db_path.exists() {
            return Err(EntityStorageError::project_data(
                db_path,
                io::ErrorKind::NotFound,
            ));
        }

        let mut options = rocksdb::Options::default();

        options.create_if_missing(false);

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
        tracing::trace!(
            "inserting key: {}, value: {}",
            BytesOrSlice::from(key),
            value
        );
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
        Ok(RocksDbEntityKeyBytesIterator::new(self, prefix))
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        Ok(RocksDbEntityBytesIterator::new(self, prefix))
    }

    fn iter_range(
        &self,
        prefix: &[u8],
        start: Bound<&[u8]>,
    ) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        Ok(RocksDbEntityRangeBytesIterator::new(self, prefix, start))
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
        Ok(RocksDbEntityBytesAsIterator::new(self, prefix, f))
    }

    fn transactional_reader(&self) -> Result<EntityBytesTransactionalReader, EntityStorageError> {
        RocksDbEntityTransaction::new_reader(self)
    }

    fn transactional_writer(&self) -> Result<EntityBytesTransactionalWriter, EntityStorageError> {
        RocksDbEntityTransaction::new_writer(self)
    }
}

#[repr(transparent)]
struct RocksDbEntityKeyBytesIterator<'a> {
    iter: rocksdb::DBRawIteratorWithThreadMode<'a, rocksdb::OptimisticTransactionDB>,
}

impl<'a> RocksDbEntityKeyBytesIterator<'a> {
    fn new(storage: &'a RocksDbEntityStorage, prefix: &[u8]) -> EntityKeyBytesIterator<'a> {
        let mut opts = rocksdb::ReadOptions::default();

        opts.set_prefix_same_as_start(true);
        opts.set_iterate_range(rocksdb::PrefixRange(prefix.to_vec()));

        let mut iter = storage.database.raw_iterator_opt(opts);
        iter.seek(prefix);

        Box::new(Self { iter })
    }
}

impl<'a> Iterator for RocksDbEntityKeyBytesIterator<'a> {
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

struct RocksDbEntityRangeBytesIterator<'a> {
    iter: rocksdb::DBRawIteratorWithThreadMode<'a, rocksdb::OptimisticTransactionDB>,
    prefix: Box<[u8]>,
}

impl<'a> RocksDbEntityRangeBytesIterator<'a> {
    fn new(
        storage: &'a RocksDbEntityStorage,
        prefix: &[u8],
        start: Bound<&[u8]>,
    ) -> EntityBytesIterator<'a> {
        let mut opts = rocksdb::ReadOptions::default();

        opts.set_prefix_same_as_start(true);
        opts.set_iterate_range(rocksdb::PrefixRange(prefix.to_vec()));

        let mut iter = storage.database.raw_iterator_opt(opts);
        match start {
            Bound::Included(key) => iter.seek(key),
            Bound::Excluded(key) => {
                iter.seek(key);
                if iter.valid() && iter.key() == Some(key) {
                    iter.next();
                }
            }
            Bound::Unbounded => iter.seek(prefix),
        }

        Box::new(Self {
            iter,
            prefix: prefix.into(),
        })
    }
}

impl<'a> Iterator for RocksDbEntityRangeBytesIterator<'a> {
    type Item = Result<(BytesOrSlice<'a>, BytesOrSlice<'a>), EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.iter.valid() {
            return None;
        }

        let key = self.iter.key()?;
        if !key.starts_with(&self.prefix) {
            return None;
        }

        let value = self.iter.value()?;
        let item = (
            BytesOrSlice::from(key.to_vec()),
            BytesOrSlice::from(value.to_vec()),
        );

        self.iter.next();

        Some(Ok(item))
    }
}

#[repr(transparent)]
struct RocksDbEntityBytesIterator<'a> {
    iter: rocksdb::DBIteratorWithThreadMode<'a, rocksdb::OptimisticTransactionDB>,
}

impl<'a> RocksDbEntityBytesIterator<'a> {
    fn new(storage: &'a RocksDbEntityStorage, prefix: &[u8]) -> EntityBytesIterator<'a> {
        Box::new(Self {
            iter: storage.database.prefix_iterator(prefix),
        })
    }
}

impl<'a> Iterator for RocksDbEntityBytesIterator<'a> {
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

struct RocksDbEntityBytesAsIterator<'a, T> {
    iter: rocksdb::DBIteratorWithThreadMode<'a, rocksdb::OptimisticTransactionDB>,
    f: Box<dyn FnMut(&[u8], &[u8]) -> Result<T, EntityStorageError> + 'a>,
}

impl<'a, T> RocksDbEntityBytesAsIterator<'a, T>
where
    T: 'a,
{
    fn new<F>(
        storage: &'a RocksDbEntityStorage,
        prefix: &[u8],
        f: F,
    ) -> EntityBytesAsIterator<'a, T>
    where
        F: FnMut(&[u8], &[u8]) -> Result<T, EntityStorageError> + 'a,
    {
        Box::new(Self {
            iter: storage.database.prefix_iterator(prefix),
            f: Box::new(f),
        })
    }
}

impl<'a, T> Iterator for RocksDbEntityBytesAsIterator<'a, T> {
    type Item = Result<T, EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|kv| {
            let kv = kv.map_err(EntityStorageError::backing);
            kv.and_then(|(key, val)| (self.f)(key.as_ref(), val.as_ref()))
        })
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

#[cfg(test)]
mod test {
    use std::ops::Bound;

    use super::RocksDbEntityStorage;
    use crate::ir::Address;
    use crate::storage::entities::schema::EntityId;
    use crate::storage::entities::{Entity, EntityStorage};

    #[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    struct TestEntity {
        value: u64,
    }

    impl TestEntity {
        fn new(value: u64) -> Self {
            Self { value }
        }
    }

    impl Entity for TestEntity {
        const ID: EntityId = EntityId::new(125);
    }

    #[test]
    fn rocksdb_iter_range_respects_inclusive_and_exclusive_bounds()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut options = rocksdb::Options::default();
        options.create_if_missing(true);
        let provider = RocksDbEntityStorage {
            database: rocksdb::OptimisticTransactionDB::open(&options, directory.path())?,
        };
        let storage = EntityStorage::new(provider);

        for value in 1..=4 {
            storage.insert(&Address::from(value), &TestEntity::new(value))?;
        }

        let included = storage
            .iter_range::<Address, TestEntity>(Bound::Included(&Address::from(2u64)))?
            .map(|entry| entry.map(|(_, entity)| entity.value))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(included, vec![2, 3, 4]);

        let excluded = storage
            .iter_range::<Address, TestEntity>(Bound::Excluded(&Address::from(2u64)))?
            .map(|entry| entry.map(|(_, entity)| entity.value))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(excluded, vec![3, 4]);

        let unbounded = storage
            .iter_range::<Address, TestEntity>(Bound::Unbounded)?
            .map(|entry| entry.map(|(_, entity)| entity.value))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(unbounded, vec![1, 2, 3, 4]);

        Ok(())
    }
}
