#![cfg(feature = "sqlite")]

use std::error::Error;
use std::io;
use std::ops::Bound;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};

use fugue_core::loader::Loadable;
use fugue_core::project::Project;
use fugue_core::storage::{
    DefaultPersistentSegmentStorage, EntityBytesAsIterator, EntityBytesIterator,
    EntityBytesTransactionalReader, EntityBytesTransactionalWriter, EntityKeyBytesIterator,
    EntityStorageError, EntityStorageProvider, EntityStorageProviderFromLoadable,
    EntityStorageProviderFromStorage, EntityStorageTransactionalReader,
    EntityStorageTransactionalWriter, PERSISTENT, PersistentStorageProvider, SqliteEntityStorage,
    StoragePersistence,
};
use fugue_core::types::{ATTRIBUTE_PROJECT_PATH, AttributeMap, BytesOrSlice};

mod common;

use common::one_block_function;

type InterruptingProjectProvider =
    PersistentStorageProvider<InterruptingSqliteStorage, DefaultPersistentSegmentStorage>;

static FAIL_COMMIT: AtomicBool = AtomicBool::new(false);
static INTERRUPT_AFTER: AtomicIsize = AtomicIsize::new(-1);
static WRITE_CALLS: AtomicUsize = AtomicUsize::new(0);

struct InterruptingSqliteStorage {
    inner: SqliteEntityStorage<PERSISTENT>,
}

struct InterruptingSqliteWriter<'a> {
    inner: EntityBytesTransactionalWriter<'a>,
}

impl InterruptingSqliteStorage {
    fn interrupt_write() -> Result<(), EntityStorageError> {
        let position = WRITE_CALLS.fetch_add(1, Ordering::SeqCst);
        if INTERRUPT_AFTER.load(Ordering::SeqCst) == position as isize {
            return Err(EntityStorageError::backing(io::Error::other(
                "injected entity write interruption",
            )));
        }
        Ok(())
    }
}

impl<'a> EntityStorageTransactionalReader<'a> for InterruptingSqliteWriter<'a> {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        self.inner.get(key)
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        self.inner.contains(key)
    }
}

impl<'a> EntityStorageTransactionalWriter<'a> for InterruptingSqliteWriter<'a> {
    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        InterruptingSqliteStorage::interrupt_write()?;
        self.inner.insert(key, value)
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        InterruptingSqliteStorage::interrupt_write()?;
        self.inner.remove(key)
    }

    fn commit(self: Box<Self>) -> Result<(), EntityStorageError> {
        if FAIL_COMMIT.load(Ordering::SeqCst) {
            return Err(EntityStorageError::backing(io::Error::other(
                "injected entity commit interruption",
            )));
        }

        let Self { inner } = *self;
        inner.commit()
    }
}

impl EntityStorageProviderFromLoadable for InterruptingSqliteStorage {
    fn from_loadable(
        loadable: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self {
            inner: SqliteEntityStorage::from_loadable(loadable, attributes)?,
        })
    }
}

impl EntityStorageProviderFromStorage for InterruptingSqliteStorage {
    fn from_storage(
        path: impl AsRef<Path>,
        attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self {
            inner: SqliteEntityStorage::from_storage(path, attributes)?,
        })
    }
}

impl EntityStorageProvider for InterruptingSqliteStorage {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        self.inner.get(key)
    }

    fn get_as<F, T>(&self, key: &[u8], f: F) -> Result<Option<T>, EntityStorageError>
    where
        F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
    {
        self.inner.get_as(key, f)
    }

    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        self.inner.insert(key, value)
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        self.inner.remove(key)
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        self.inner.contains(key)
    }

    fn iter_prefix_keys(
        &self,
        prefix: &[u8],
    ) -> Result<EntityKeyBytesIterator<'_>, EntityStorageError> {
        self.inner.iter_prefix_keys(prefix)
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        self.inner.iter_prefix(prefix)
    }

    fn iter_range(
        &self,
        prefix: &[u8],
        start: Bound<&[u8]>,
    ) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        self.inner.iter_range(prefix, start)
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
        self.inner.iter_prefix_as(prefix, f)
    }

    fn transactional_reader(&self) -> Result<EntityBytesTransactionalReader, EntityStorageError> {
        self.inner.transactional_reader()
    }

    fn transactional_writer(&self) -> Result<EntityBytesTransactionalWriter, EntityStorageError> {
        Ok(Box::new(InterruptingSqliteWriter {
            inner: self.inner.transactional_writer()?,
        }))
    }

    fn persistence(&self) -> StoragePersistence {
        PERSISTENT
    }
}

fn attributes(project_path: &Path) -> AttributeMap {
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path.to_owned());
    attributes
}

fn open_project(project_path: &Path) -> Result<Project, Box<dyn Error>> {
    Ok(Project::from_file_with_provider_and_attributes::<
        InterruptingProjectProvider,
    >("tests/ls.elf", attributes(project_path))?)
}

#[test]
fn interrupted_persistent_admission_reopens_at_one_revision() -> Result<(), Box<dyn Error>> {
    let measurement = tempfile::tempdir()?;
    let measurement_path = measurement.path().join("measurement.fdbz");
    let mut project = open_project(&measurement_path)?;
    let first = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?
        + 0x6000_0000u64;
    let second = first + 0x100u64;

    WRITE_CALLS.store(0, Ordering::SeqCst);
    let mut transaction = project.transaction("measure persistent admission");
    transaction.add_function(one_block_function(first, 1))?;
    transaction.add_function(one_block_function(second, 1))?;
    let committed = transaction.commit()?;
    let write_calls = WRITE_CALLS.load(Ordering::SeqCst);
    assert!(write_calls > 0);
    drop(project);

    let reopened = open_project(&measurement_path)?;
    assert_eq!(reopened.revision(), committed.revision());
    assert!(reopened.functions().get_by_address(first).is_some());
    assert!(reopened.functions().get_by_address(second).is_some());
    drop(reopened);

    for interrupted_at in 0..write_calls {
        let directory = tempfile::tempdir()?;
        let project_path = directory.path().join("interrupted-write.fdbz");
        let mut project = open_project(&project_path)?;
        let revision = project.revision();

        WRITE_CALLS.store(0, Ordering::SeqCst);
        INTERRUPT_AFTER.store(interrupted_at as isize, Ordering::SeqCst);
        let mut transaction = project.transaction("interrupt persistent admission");
        transaction.add_function(one_block_function(first, 1))?;
        transaction.add_function(one_block_function(second, 1))?;
        let result = transaction.commit();
        INTERRUPT_AFTER.store(-1, Ordering::SeqCst);

        assert!(
            result.is_err(),
            "write {interrupted_at} was not interrupted"
        );
        assert_eq!(project.revision(), revision);
        assert!(project.functions().get_by_address(first).is_none());
        assert!(project.functions().get_by_address(second).is_none());
        drop(project);

        let reopened = open_project(&project_path)?;
        assert_eq!(reopened.revision(), revision);
        assert!(reopened.functions().get_by_address(first).is_none());
        assert!(reopened.functions().get_by_address(second).is_none());
    }

    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("interrupted-commit.fdbz");
    let mut project = open_project(&project_path)?;
    let revision = project.revision();

    FAIL_COMMIT.store(true, Ordering::SeqCst);
    let mut transaction = project.transaction("interrupt persistent commit");
    transaction.add_function(one_block_function(first, 1))?;
    transaction.add_function(one_block_function(second, 1))?;
    let result = transaction.commit();
    FAIL_COMMIT.store(false, Ordering::SeqCst);

    assert!(result.is_err(), "provider commit was not interrupted");
    assert_eq!(project.revision(), revision);
    assert!(project.functions().get_by_address(first).is_none());
    assert!(project.functions().get_by_address(second).is_none());
    drop(project);

    let reopened = open_project(&project_path)?;
    assert_eq!(reopened.revision(), revision);
    assert!(reopened.functions().get_by_address(first).is_none());
    assert!(reopened.functions().get_by_address(second).is_none());

    Ok(())
}
