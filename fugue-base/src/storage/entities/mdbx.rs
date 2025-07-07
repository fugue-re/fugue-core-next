use std::borrow::Cow;
use std::mem::{self, ManuallyDrop};
use std::path::PathBuf;

use libmdbx as mdbx;

use crate::loader::Loadable;
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;
use crate::types::{AttributeMap, BytesOrSlice};

use super::{
    EntityBytesBulkInserter, EntityBytesIterator, EntityBytesTransactionalReader,
    EntityKeyBytesIterator, EntityStorageBulkInserter, EntityStorageError, EntityStorageProvider,
    EntityStorageProviderFromLoadable, EntityStorageTransactionalReader,
};

const PROJECT_MDBX_DATA: &str = "entities.db";

// Maximum batch size for bulk operations
const BATCH_SIZE: usize = 1024;

impl From<mdbx::Error> for EntityStorageError {
    fn from(error: mdbx::Error) -> Self {
        EntityStorageError::backing(error)
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
        let database = mdbx::Database::open(&db_path)?;
        {
            let txn = database.begin_rw_txn()?;
            txn.create_table(None, mdbx::TableFlags::default())?;
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
        MdbxEntityKeyBytesIterator::new(self, prefix)
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        MdbxEntityBytesIterator::new(self, prefix)
    }

    fn bulk_inserter(&self) -> Result<EntityBytesBulkInserter, EntityStorageError> {
        MdbxEntityBytesBulkInserter::new(self)
    }

    fn reader(
        &self,
    ) -> Result<EntityBytesTransactionalReader<'_>, EntityStorageError> {
        MdbxEntityReader::new(self)
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
    fn new(
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

        let Some(Ok((key, _val))) = self.inner.with_iter_mut(|iter| iter.next()) else {
            self.prefix = None;
            return None;
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
    prefix: Option<Box<[u8]>>,
}

impl<'a> MdbxEntityBytesIterator<'a> {
    fn new(
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
            prefix: Some(prefix.to_vec().into_boxed_slice()),
        }))
    }
}

impl<'a> Iterator for MdbxEntityBytesIterator<'a> {
    type Item = Result<(BytesOrSlice<'a>, BytesOrSlice<'a>), EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        let prefix = self.prefix.as_deref()?;

        let Some(Ok((key, val))) = self.inner.with_iter_mut(|iter| iter.next()) else {
            self.prefix = None;
            return None;
        };

        if key.starts_with(prefix) {
            Some(Ok((
                BytesOrSlice::from(key.to_vec()),
                BytesOrSlice::from(val.to_vec()),
            )))
        } else {
            self.prefix = None;
            None
        }
    }
}

struct MdbxEntityBytesBulkInserter<'a> {
    storage: &'a MdbxEntityStorage,
    txn: ManuallyDrop<mdbx::Transaction<'a, mdbx::RW, mdbx::WriteMap>>,
    batch_size: usize,
}

impl<'a> MdbxEntityBytesBulkInserter<'a> {
    fn new(
        storage: &'a MdbxEntityStorage,
    ) -> Result<EntityBytesBulkInserter<'a>, EntityStorageError> {
        let txn = storage.database.begin_rw_txn()?;
        Ok(Box::new(Self {
            storage,
            txn: ManuallyDrop::new(txn),
            batch_size: 0,
        }))
    }

    fn force_commit(&mut self) -> Result<(), EntityStorageError> {
        let ntxn = self.storage.database.begin_rw_txn()?;

        let txn = mem::replace(&mut self.txn, ManuallyDrop::new(ntxn));

        let txn = ManuallyDrop::into_inner(txn);
        txn.commit()?;

        self.batch_size = 0;

        Ok(())
    }
}

impl<'a> Drop for MdbxEntityBytesBulkInserter<'a> {
    fn drop(&mut self) {
        let txn = unsafe { ManuallyDrop::take(&mut self.txn) };

        if self.batch_size == 0 {
            return;
        }

        if let Err(e) = txn.commit() {
            tracing::warn!("failed to flush batch to storage: {e}")
        }
    }
}

impl<'a> EntityStorageBulkInserter<'a> for MdbxEntityBytesBulkInserter<'a> {
    fn insert(
        &mut self,
        key: BytesOrSlice<'_>,
        value: BytesOrSlice<'_>,
    ) -> Result<(), EntityStorageError> {
        if self.batch_size >= BATCH_SIZE {
            self.force_commit()?;
        }

        let tbl = self.txn.open_table(None)?;

        self.txn
            .put(&tbl, key, value, mdbx::WriteFlags::default())?;

        Ok(())
    }

    fn commit(mut self: Box<Self>) -> Result<(), EntityStorageError> {
        self.force_commit()
    }
}

struct MdbxEntityReader<'a> {
    storage: &'a MdbxEntityStorage,
    txn: mdbx::Transaction<'a, mdbx::RO, mdbx::WriteMap>,
}

impl<'a> MdbxEntityReader<'a> {
    fn new(
        storage: &'a MdbxEntityStorage,
    ) -> Result<EntityBytesTransactionalReader<'a>, EntityStorageError> {
        let txn = storage.database.begin_ro_txn()?;
        Ok(Box::new(Self { storage, txn }))
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

    fn iter_prefix_keys(
        &self,
        prefix: &[u8],
    ) -> Result<EntityKeyBytesIterator<'_>, EntityStorageError> {
        MdbxEntityKeyBytesIterator::new(self.storage, prefix)
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        MdbxEntityBytesIterator::new(self.storage, prefix)
    }
}
