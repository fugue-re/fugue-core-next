use std::path::PathBuf;

use crate::loader::Loadable;
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;
use crate::types::{AttributeMap, BytesOrSlice};

pub mod options;

use super::{
    EntityBytesBulkInserter, EntityBytesIterator, EntityKeyBytesIterator, EntityStorageError,
    EntityStorageProvider, EntityStorageProviderFromLoadable,
};

pub const ATTRIBUTE_ENTITY_STORAGE_ROCKSDB_OPTIONS: &str =
    "storage.entities.backend.rocksdb.options";

const PROJECT_ROCKSDB_DATA: &str = "entities.rdb";

impl From<rocksdb::Error> for EntityStorageError {
    fn from(error: rocksdb::Error) -> Self {
        EntityStorageError::backing(error)
    }
}

pub struct RocksDbEntityStorage {
    database: rocksdb::DB,
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

        if let Some(db_options) =
            attributes.get_attr::<options::RocksDbOptions>(ATTRIBUTE_ENTITY_STORAGE_ROCKSDB_OPTIONS)
        {
            db_options.apply(&mut options);
        }

        Ok(Self {
            database: rocksdb::DB::open(&options, db_path)?,
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
        // TODO: test if a raw iterator is more efficient than a regular iterator for
        // keys
        Ok(RocksDbEntityKeyBytesIterator::new(
            self.database.raw_iterator(),
            prefix,
        ))
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        Ok(RocksDbEntityBytesIterator::new(
            self.database.prefix_iterator(prefix),
        ))
    }

    fn bulk_inserter(&self) -> Result<EntityBytesBulkInserter, EntityStorageError> {
        todo!()
    }
}

struct RocksDbEntityKeyBytesIterator<'a> {
    iter: rocksdb::DBRawIterator<'a>,
    prefix: Box<[u8]>,
}

impl<'a> RocksDbEntityKeyBytesIterator<'a> {
    fn new(mut iter: rocksdb::DBRawIterator<'a>, prefix: &[u8]) -> EntityKeyBytesIterator<'a> {
        iter.seek(prefix);
        Box::new(Self {
            iter,
            prefix: Box::from(prefix),
        })
    }
}

impl<'a> Iterator for RocksDbEntityKeyBytesIterator<'a> {
    type Item = Result<BytesOrSlice<'a>, EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.iter.valid() {
            return None;
        }

        let key = self.iter.key()?;

        if !key.starts_with(&self.prefix) {
            return None;
        }

        let key = BytesOrSlice::from(key.to_vec());

        self.iter.next();

        Some(Ok(key))
    }
}

#[repr(transparent)]
struct RocksDbEntityBytesIterator<'a> {
    iter: rocksdb::DBIterator<'a>,
}

impl<'a> RocksDbEntityBytesIterator<'a> {
    fn new(iter: rocksdb::DBIterator<'a>) -> EntityBytesIterator<'a> {
        Box::new(Self { iter })
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
