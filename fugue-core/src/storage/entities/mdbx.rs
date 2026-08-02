use std::borrow::Cow;
use std::io;
use std::ops::Bound;
use std::path::{Path, PathBuf};

use libmdbx as mdbx;
use serde::{Deserialize, Serialize};
use serde_with::{FromInto, serde_as};

use super::{
    EntityBytesAsIterator, EntityBytesIterator, EntityBytesMapper, EntityBytesTransactionalReader,
    EntityBytesTransactionalWriter, EntityKeyBytesIterator, EntityKeyPrefix, EntityStorageError,
    EntityStorageProvider, EntityStorageProviderFromLoadable, EntityStorageProviderFromStorage,
    EntityStorageTransactionalReader, EntityStorageTransactionalWriter,
};
use crate::loader::Loadable;
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;
use crate::types::{AttributeMap, BytesOrSlice};

pub const ATTRIBUTE_ENTITY_STORAGE_MDBX_OPTIONS: &str = "storage.entities.mdbx.options";

const PROJECT_MDBX_DATA: &str = "entities.db";

impl From<mdbx::Error> for EntityStorageError {
    fn from(error: mdbx::Error) -> Self {
        EntityStorageError::backing(error)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MdbxSyncMode {
    Durable,
    NoMetaSync,
    SafeNoSync,
    UtterlyNoSync,
}

impl From<MdbxSyncMode> for mdbx::SyncMode {
    fn from(mode: MdbxSyncMode) -> Self {
        match mode {
            MdbxSyncMode::Durable => mdbx::SyncMode::Durable,
            MdbxSyncMode::NoMetaSync => mdbx::SyncMode::NoMetaSync,
            MdbxSyncMode::SafeNoSync => mdbx::SyncMode::SafeNoSync,
            MdbxSyncMode::UtterlyNoSync => mdbx::SyncMode::UtterlyNoSync,
        }
    }
}

impl From<mdbx::SyncMode> for MdbxSyncMode {
    fn from(mode: mdbx::SyncMode) -> Self {
        match mode {
            mdbx::SyncMode::Durable => MdbxSyncMode::Durable,
            mdbx::SyncMode::NoMetaSync => MdbxSyncMode::NoMetaSync,
            mdbx::SyncMode::SafeNoSync => MdbxSyncMode::SafeNoSync,
            mdbx::SyncMode::UtterlyNoSync => MdbxSyncMode::UtterlyNoSync,
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MdbxOptions {
    #[serde_as(as = "FromInto<MdbxSyncMode>")]
    pub sync_mode: mdbx::SyncMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_lower: Option<isize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_upper: Option<isize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub growth_step: Option<isize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shrink_threshold: Option<isize>,
}

impl From<MdbxOptions> for mdbx::DatabaseOptions {
    fn from(options: MdbxOptions) -> Self {
        mdbx::DatabaseOptions {
            mode: mdbx::Mode::ReadWrite(mdbx::ReadWriteOptions {
                sync_mode: options.sync_mode,
                min_size: options.size_lower,
                max_size: options.size_upper,
                growth_step: options.growth_step,
                shrink_threshold: options.shrink_threshold,
            }),
            ..Default::default()
        }
    }
}

pub struct MdbxEntityStorage {
    database: mdbx::Database<mdbx::WriteMap>,
}

impl EntityStorageProviderFromLoadable for MdbxEntityStorage {
    fn from_loadable(
        _loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError> {
        let project_path = attributes
            .get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH)
            .ok_or(EntityStorageError::NoProjectPath)?;

        let db_path = project_path.join(PROJECT_MDBX_DATA);

        let db_options = attributes
            .get_attr::<MdbxOptions>(ATTRIBUTE_ENTITY_STORAGE_MDBX_OPTIONS)
            .map(mdbx::DatabaseOptions::from)
            .unwrap_or_default();

        let database = mdbx::Database::open_with_options(&db_path, db_options)?;
        {
            let txn = database.begin_rw_txn()?;
            txn.create_table(None, mdbx::TableFlags::default())?;
        }

        Ok(Self { database })
    }
}

impl EntityStorageProviderFromStorage for MdbxEntityStorage {
    fn from_storage(
        path: impl AsRef<Path>,
        attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError>
    where
        Self: Sized,
    {
        let project_path = path.as_ref();
        let db_path = project_path.join(PROJECT_MDBX_DATA);

        if !project_path.exists() {
            return Err(EntityStorageError::project_data(
                db_path,
                io::ErrorKind::NotFound,
            ));
        }

        let db_options = attributes
            .get_attr::<MdbxOptions>(ATTRIBUTE_ENTITY_STORAGE_MDBX_OPTIONS)
            .map(mdbx::DatabaseOptions::from)
            .unwrap_or_default();

        let database = mdbx::Database::open_with_options(&db_path, db_options)?;
        {
            let txn = database.begin_ro_txn()?;
            txn.open_table(None).map_err(|_| {
                EntityStorageError::project_data(db_path, io::ErrorKind::InvalidData)
            })?;
        }

        Ok(Self { database })
    }
}

impl EntityStorageProvider for MdbxEntityStorage {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        let txn = self.database.begin_ro_txn()?;
        let tbl = txn.open_table(None)?;
        let val = txn.get::<Vec<u8>>(&tbl, key)?;
        Ok(val.map(BytesOrSlice::from))
    }

    fn get_as<F, T>(&self, key: &[u8], mut f: F) -> Result<Option<T>, EntityStorageError>
    where
        F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
    {
        let txn = self.database.begin_ro_txn()?;
        let tbl = txn.open_table(None)?;
        let val = txn.get::<Cow<[u8]>>(&tbl, key)?;
        val.map(|bytes| f(bytes.as_ref())).transpose()
    }

    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        let txn = self.database.begin_rw_txn()?;
        let tbl = txn.open_table(None)?;
        txn.put(&tbl, key, value.as_ref(), mdbx::WriteFlags::default())?;
        txn.commit()?;
        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        let txn = self.database.begin_rw_txn()?;
        let tbl = txn.open_table(None)?;
        txn.del(&tbl, key, None)?;
        txn.commit()?;
        Ok(())
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        let txn = self.database.begin_ro_txn()?;
        let tbl = txn.open_table(None)?;
        let val = txn.get::<Cow<[u8]>>(&tbl, key)?;
        Ok(val.is_some())
    }

    fn iter_prefix_keys(
        &self,
        prefix: &[u8],
    ) -> Result<EntityKeyBytesIterator<'_>, EntityStorageError> {
        EntityKeyPrefix::try_from(prefix).map_err(|_| EntityStorageError::InvalidKeySize)?;
        MdbxEntityKeyBytesIterator::boxed(self, prefix)
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        EntityKeyPrefix::try_from(prefix).map_err(|_| EntityStorageError::InvalidKeySize)?;
        MdbxEntityBytesIterator::boxed(self, prefix)
    }

    fn iter_range(
        &self,
        prefix: &[u8],
        start: Bound<&[u8]>,
    ) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        EntityKeyPrefix::try_from(prefix).map_err(|_| EntityStorageError::InvalidKeySize)?;
        MdbxEntityBytesIterator::boxed_range(self, prefix, start)
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
        EntityKeyPrefix::try_from(prefix).map_err(|_| EntityStorageError::InvalidKeySize)?;
        MdbxEntityBytesAsIterator::boxed(self, prefix, f)
    }

    fn transactional_reader(
        &self,
    ) -> Result<EntityBytesTransactionalReader<'_>, EntityStorageError> {
        MdbxEntityReader::boxed(self)
    }

    fn transactional_writer(
        &self,
    ) -> Result<EntityBytesTransactionalWriter<'_>, EntityStorageError> {
        MdbxEntityWriter::boxed(self)
    }
}

#[ouroboros::self_referencing]
struct MdbxEntityKeyBytesIteratorInner<'a> {
    txn: mdbx::Transaction<'a, mdbx::RO, mdbx::WriteMap>,
    #[not_covariant]
    #[borrows(txn)]
    iter: mdbx::IntoIter<'this, mdbx::RO, Cow<'this, [u8]>, Cow<'this, [u8]>>,
}

struct MdbxEntityKeyBytesIterator<'a> {
    inner: MdbxEntityKeyBytesIteratorInner<'a>,
    prefix: Option<Box<[u8]>>,
}

impl<'a> MdbxEntityKeyBytesIterator<'a> {
    fn boxed(
        database: &'a MdbxEntityStorage,
        prefix: &[u8],
    ) -> Result<EntityKeyBytesIterator<'a>, EntityStorageError> {
        let txn = database.database.begin_ro_txn()?;

        let inner = MdbxEntityKeyBytesIteratorInner::try_new(
            txn,
            |txn| -> Result<_, EntityStorageError> {
                let tbl = txn.open_table(None)?;
                Ok(txn.cursor(&tbl)?.into_iter_from(prefix))
            },
        )?;

        Ok(Box::new(Self {
            inner,
            prefix: Some(prefix.to_vec().into_boxed_slice()),
        }))
    }
}

impl<'a> Iterator for MdbxEntityKeyBytesIterator<'a> {
    type Item = Result<BytesOrSlice<'a>, EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        let prefix = self.prefix.as_deref()?;

        let (key, _value) = match self.inner.with_iter_mut(|iter| iter.next()) {
            Some(Ok(entry)) => entry,
            Some(Err(error)) => {
                self.prefix = None;
                return Some(Err(EntityStorageError::backing(error)));
            }
            None => {
                self.prefix = None;
                return None;
            }
        };

        if key.starts_with(prefix) {
            Some(Ok(BytesOrSlice::from(key.to_vec())))
        } else {
            self.prefix = None;
            None
        }
    }
}

#[ouroboros::self_referencing]
struct MdbxEntityBytesIteratorInner<'a> {
    txn: mdbx::Transaction<'a, mdbx::RO, mdbx::WriteMap>,
    #[not_covariant]
    #[borrows(txn)]
    iter: mdbx::IntoIter<'this, mdbx::RO, Cow<'this, [u8]>, Cow<'this, [u8]>>,
}

struct MdbxEntityBytesIterator<'a> {
    inner: MdbxEntityBytesIteratorInner<'a>,
    excluded_start: Option<Box<[u8]>>,
    prefix: Option<Box<[u8]>>,
}

impl<'a> MdbxEntityBytesIterator<'a> {
    fn boxed(
        database: &'a MdbxEntityStorage,
        prefix: &[u8],
    ) -> Result<EntityBytesIterator<'a>, EntityStorageError> {
        let txn = database.database.begin_ro_txn()?;

        let inner =
            MdbxEntityBytesIteratorInner::try_new(txn, |txn| -> Result<_, EntityStorageError> {
                let tbl = txn.open_table(None)?;
                Ok(txn.cursor(&tbl)?.into_iter_from(prefix))
            })?;

        Ok(Box::new(Self {
            inner,
            excluded_start: None,
            prefix: Some(prefix.to_vec().into_boxed_slice()),
        }))
    }

    fn boxed_range(
        database: &'a MdbxEntityStorage,
        prefix: &[u8],
        start: Bound<&[u8]>,
    ) -> Result<EntityBytesIterator<'a>, EntityStorageError> {
        let txn = database.database.begin_ro_txn()?;
        let seek = match start {
            Bound::Included(key) | Bound::Excluded(key) => key,
            Bound::Unbounded => prefix,
        };

        let inner =
            MdbxEntityBytesIteratorInner::try_new(txn, |txn| -> Result<_, EntityStorageError> {
                let tbl = txn.open_table(None)?;
                Ok(txn.cursor(&tbl)?.into_iter_from(seek))
            })?;

        let excluded_start = match start {
            Bound::Excluded(key) => Some(key.to_vec().into_boxed_slice()),
            Bound::Included(_) | Bound::Unbounded => None,
        };

        Ok(Box::new(Self {
            inner,
            excluded_start,
            prefix: Some(prefix.to_vec().into_boxed_slice()),
        }))
    }
}

impl<'a> Iterator for MdbxEntityBytesIterator<'a> {
    type Item = Result<(BytesOrSlice<'a>, BytesOrSlice<'a>), EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        let prefix = self.prefix.as_deref()?;

        loop {
            let (key, val) = match self.inner.with_iter_mut(|iter| iter.next()) {
                Some(Ok(entry)) => entry,
                Some(Err(error)) => {
                    self.prefix = None;
                    return Some(Err(EntityStorageError::backing(error)));
                }
                None => {
                    self.prefix = None;
                    return None;
                }
            };

            if !key.starts_with(prefix) {
                self.prefix = None;
                return None;
            }

            if self
                .excluded_start
                .as_deref()
                .is_some_and(|start| start == key.as_ref())
            {
                self.excluded_start = None;
                continue;
            }

            return Some(Ok((
                BytesOrSlice::from(key.to_vec()),
                BytesOrSlice::from(val.to_vec()),
            )));
        }
    }
}

struct MdbxEntityBytesAsIterator<'a, T> {
    inner: MdbxEntityBytesIteratorInner<'a>,
    prefix: Option<Box<[u8]>>,
    f: Box<EntityBytesMapper<'a, T>>,
}

impl<'a, T> MdbxEntityBytesAsIterator<'a, T>
where
    T: 'a,
{
    fn boxed<F>(
        database: &'a MdbxEntityStorage,
        prefix: &[u8],
        f: F,
    ) -> Result<EntityBytesAsIterator<'a, T>, EntityStorageError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<T, EntityStorageError> + 'a,
    {
        let txn = database.database.begin_ro_txn()?;

        let inner =
            MdbxEntityBytesIteratorInner::try_new(txn, |txn| -> Result<_, EntityStorageError> {
                let tbl = txn.open_table(None)?;
                Ok(txn.cursor(&tbl)?.into_iter_from(prefix))
            })?;

        Ok(Box::new(Self {
            inner,
            prefix: Some(prefix.to_vec().into_boxed_slice()),
            f: Box::new(f),
        }))
    }
}

impl<'a, T> Iterator for MdbxEntityBytesAsIterator<'a, T> {
    type Item = Result<T, EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        let prefix = self.prefix.as_deref()?;

        let (key, val) = match self.inner.with_iter_mut(|iter| iter.next()) {
            Some(Ok(entry)) => entry,
            Some(Err(error)) => {
                self.prefix = None;
                return Some(Err(EntityStorageError::backing(error)));
            }
            None => {
                self.prefix = None;
                return None;
            }
        };

        if key.starts_with(prefix) {
            Some((self.f)(key.as_ref(), val.as_ref()))
        } else {
            self.prefix = None;
            None
        }
    }
}

struct MdbxEntityReader<'a> {
    txn: mdbx::Transaction<'a, mdbx::RO, mdbx::WriteMap>,
}

impl<'a> MdbxEntityReader<'a> {
    fn boxed(
        storage: &'a MdbxEntityStorage,
    ) -> Result<EntityBytesTransactionalReader<'a>, EntityStorageError> {
        let txn = storage.database.begin_ro_txn()?;
        Ok(Box::new(Self { txn }))
    }
}

impl<'a> EntityStorageTransactionalReader<'a> for MdbxEntityReader<'a> {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        let tbl = self.txn.open_table(None)?;
        let val = self.txn.get::<Cow<[u8]>>(&tbl, key)?;
        Ok(val.map(BytesOrSlice::from))
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        let tbl = self.txn.open_table(None)?;
        let val = self.txn.get::<Cow<[u8]>>(&tbl, key)?;
        Ok(val.is_some())
    }
}

struct MdbxEntityWriter<'a> {
    txn: mdbx::Transaction<'a, mdbx::RW, mdbx::WriteMap>,
}

impl<'a> MdbxEntityWriter<'a> {
    fn boxed(
        storage: &'a MdbxEntityStorage,
    ) -> Result<EntityBytesTransactionalWriter<'a>, EntityStorageError> {
        let txn = storage.database.begin_rw_txn()?;
        Ok(Box::new(Self { txn }))
    }
}

impl<'a> EntityStorageTransactionalReader<'a> for MdbxEntityWriter<'a> {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        let tbl = self.txn.open_table(None)?;
        let val = self.txn.get::<Cow<[u8]>>(&tbl, key)?;
        Ok(val.map(BytesOrSlice::from))
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        let tbl = self.txn.open_table(None)?;
        let val = self.txn.get::<Cow<[u8]>>(&tbl, key)?;
        Ok(val.is_some())
    }
}

impl<'a> EntityStorageTransactionalWriter<'a> for MdbxEntityWriter<'a> {
    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        let tbl = self.txn.open_table(None)?;
        self.txn
            .put(&tbl, key, value.as_ref(), mdbx::WriteFlags::default())?;
        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        let tbl = self.txn.open_table(None)?;
        self.txn.del(&tbl, key, None)?;
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<(), EntityStorageError> {
        self.txn.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::ops::Bound;

    use super::MdbxEntityStorage;
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
        const ID: EntityId = EntityId::new(124);
    }

    #[test]
    fn mdbx_iter_range_respects_inclusive_and_exclusive_bounds()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = libmdbx::Database::open(directory.path())?;
        {
            let txn = database.begin_rw_txn()?;
            txn.create_table(None, libmdbx::TableFlags::default())?;
            txn.commit()?;
        }
        let storage = EntityStorage::new(MdbxEntityStorage { database });

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
