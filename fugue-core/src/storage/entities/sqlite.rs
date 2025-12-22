use std::collections::HashSet;
use std::io;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread::sleep;
use std::time::Duration;

use arrayvec::ArrayString;
use r2d2::{CustomizeConnection, Pool};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{OptionalExtension, params};
use thiserror::Error;

use crate::loader::Loadable;
use crate::storage::{PERSISTENT, StoragePersistence, TRANSIENT};
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;
use crate::types::{AttributeMap, BytesOrSlice};

use super::schema::ENTITY_PREFIX_SIZE;
use super::{
    EntityBytesAsIterator, EntityBytesBulkInserter, EntityBytesIterator,
    EntityBytesTransactionalReader, EntityBytesTransactionalWriter, EntityKeyBytesIterator,
    EntityKeyPrefix, EntityStorageBulkInserter, EntityStorageError, EntityStorageProvider,
    EntityStorageProviderFromLoadable, EntityStorageProviderFromStorage,
    EntityStorageTransactionalReader, EntityStorageTransactionalWriter,
};

const PROJECT_SQLITE_DATA: &str = "entities.db";
const BATCH_SIZE: usize = 1024;
const DEFAULT_POOL_SIZE: u32 = 16;

#[derive(Debug, Error)]
pub enum SqliteEntityStorageError {
    #[error("sqlite connection initialisation failed: {0}")]
    ConnectionInit(rusqlite::Error),
    #[error("sqlite database initialisation failed: {0}")]
    DatabaseInit(rusqlite::Error),
    #[error("sqlite pool error: {0}")]
    Pool(#[from] r2d2::Error),
}

impl From<rusqlite::Error> for EntityStorageError {
    fn from(error: rusqlite::Error) -> Self {
        EntityStorageError::backing(error)
    }
}

impl From<SqliteEntityStorageError> for EntityStorageError {
    fn from(error: SqliteEntityStorageError) -> Self {
        EntityStorageError::backing(error)
    }
}

fn extract_key_parts(key: &[u8]) -> Option<(EntityKeyPrefix, &[u8])> {
    if key.len() < ENTITY_PREFIX_SIZE {
        return None;
    }
    Some(([key[0], key[1]], &key[ENTITY_PREFIX_SIZE..]))
}

const fn hex_digit(n: u8) -> char {
    match n & 0xf {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + n - 10) as char,
    }
}

fn push_table_name<const N: usize>(s: &mut ArrayString<N>, prefix: &EntityKeyPrefix) {
    s.push_str("entity_");
    s.push(hex_digit(prefix[0] >> 4));
    s.push(hex_digit(prefix[0] & 0xf));
    s.push(hex_digit(prefix[1] >> 4));
    s.push(hex_digit(prefix[1] & 0xf));
}

fn build_create_table_query(prefix: &EntityKeyPrefix) -> ArrayString<128> {
    let mut query = ArrayString::new();
    query.push_str("CREATE TABLE IF NOT EXISTS ");
    push_table_name(&mut query, prefix);
    query.push_str(" (key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL) WITHOUT ROWID");
    query
}

fn build_select_value_query(prefix: &EntityKeyPrefix) -> ArrayString<64> {
    let mut query = ArrayString::new();
    query.push_str("SELECT value FROM ");
    push_table_name(&mut query, prefix);
    query.push_str(" WHERE key = ?1");
    query
}

fn build_insert_query(prefix: &EntityKeyPrefix) -> ArrayString<80> {
    let mut query = ArrayString::new();
    query.push_str("INSERT OR REPLACE INTO ");
    push_table_name(&mut query, prefix);
    query.push_str(" (key, value) VALUES (?1, ?2)");
    query
}

fn build_delete_query(prefix: &EntityKeyPrefix) -> ArrayString<64> {
    let mut query = ArrayString::new();
    query.push_str("DELETE FROM ");
    push_table_name(&mut query, prefix);
    query.push_str(" WHERE key = ?1");
    query
}

fn build_select_keys_query(prefix: &EntityKeyPrefix) -> ArrayString<64> {
    let mut query = ArrayString::new();
    query.push_str("SELECT key FROM ");
    push_table_name(&mut query, prefix);
    query.push_str(" ORDER BY key");
    query
}

fn build_select_all_query(prefix: &EntityKeyPrefix) -> ArrayString<64> {
    let mut query = ArrayString::new();
    query.push_str("SELECT key, value FROM ");
    push_table_name(&mut query, prefix);
    query.push_str(" ORDER BY key");
    query
}

fn build_contains_query(prefix: &EntityKeyPrefix) -> ArrayString<64> {
    let mut query = ArrayString::new();
    query.push_str("SELECT EXISTS(SELECT 1 FROM ");
    push_table_name(&mut query, prefix);
    query.push_str(" WHERE key = ?1)");
    query
}

fn create_table(
    conn: &rusqlite::Connection,
    prefix: &EntityKeyPrefix,
) -> Result<(), rusqlite::Error> {
    let query = build_create_table_query(prefix);
    conn.execute_batch(&query)
}

fn init_database(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA wal_autocheckpoint = 1000;
         PRAGMA synchronous = NORMAL;
         PRAGME wal_checkpoint(TRUNCATE);
         PRAGMA cache_size = -64000;",
    )
}

#[derive(Debug, Default)]
struct SqliteConnectionCustomiser;

impl SqliteConnectionCustomiser {
    fn busy_handler(_: i32) -> bool {
        sleep(Duration::from_millis(250));
        true
    }
}

impl CustomizeConnection<rusqlite::Connection, rusqlite::Error> for SqliteConnectionCustomiser {
    fn on_acquire(&self, conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
        conn.busy_handler(Some(Self::busy_handler))?;
        Ok(())
    }
}

pub struct SqliteEntityStorage<const P: StoragePersistence> {
    pool: Pool<SqliteConnectionManager>,
    created_tables: Mutex<HashSet<EntityKeyPrefix>>,
}

impl<const P: StoragePersistence> SqliteEntityStorage<P> {
    fn ensure_table(
        &self,
        conn: &rusqlite::Connection,
        prefix: &EntityKeyPrefix,
    ) -> Result<(), rusqlite::Error> {
        let mut tables = self.created_tables.lock().unwrap();
        if tables.contains(prefix) {
            return Ok(());
        }
        create_table(conn, prefix)?;
        tables.insert(*prefix);
        Ok(())
    }

    fn table_exists(&self, prefix: &EntityKeyPrefix) -> bool {
        let tables = self.created_tables.lock().unwrap();
        tables.contains(prefix)
    }
}

impl SqliteEntityStorage<PERSISTENT> {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, SqliteEntityStorageError> {
        let db_path = path.as_ref().join(PROJECT_SQLITE_DATA);
        let manager = SqliteConnectionManager::file(&db_path);
        let pool = Pool::builder()
            .max_size(DEFAULT_POOL_SIZE)
            .connection_customizer(Box::new(SqliteConnectionCustomiser::default()))
            .build(manager)
            .map_err(SqliteEntityStorageError::Pool)?;

        let conn = pool.get().map_err(SqliteEntityStorageError::Pool)?;
        init_database(&conn).map_err(SqliteEntityStorageError::DatabaseInit)?;

        Ok(Self {
            pool,
            created_tables: Mutex::new(HashSet::new()),
        })
    }
}

impl SqliteEntityStorage<TRANSIENT> {
    pub fn new() -> Result<Self, SqliteEntityStorageError> {
        let manager = SqliteConnectionManager::memory().with_flags(
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_SHARED_CACHE,
        );
        let pool = Pool::builder()
            .max_size(DEFAULT_POOL_SIZE)
            .build(manager)
            .map_err(SqliteEntityStorageError::Pool)?;

        let conn = pool.get().map_err(SqliteEntityStorageError::Pool)?;
        init_database(&conn).map_err(SqliteEntityStorageError::DatabaseInit)?;

        Ok(Self {
            pool,
            created_tables: Mutex::new(HashSet::new()),
        })
    }
}

impl Default for SqliteEntityStorage<TRANSIENT> {
    fn default() -> Self {
        Self::new().expect("failed to create transient sqlite storage")
    }
}

impl EntityStorageProviderFromLoadable for SqliteEntityStorage<PERSISTENT> {
    fn from_loadable(
        _loader: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError> {
        let project_path = attributes
            .get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH)
            .ok_or(EntityStorageError::NoProjectPath)?;

        Ok(Self::new(project_path)?)
    }
}

impl EntityStorageProviderFromLoadable for SqliteEntityStorage<TRANSIENT> {
    fn from_loadable(
        _loader: &impl Loadable,
        _attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError> {
        Self::new().map_err(EntityStorageError::backing)
    }
}

impl EntityStorageProviderFromStorage for SqliteEntityStorage<PERSISTENT> {
    fn from_storage(
        path: impl AsRef<Path>,
        _attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError>
    where
        Self: Sized,
    {
        let project_path = path.as_ref();
        let db_path = project_path.join(PROJECT_SQLITE_DATA);

        if !db_path.exists() {
            return Err(EntityStorageError::project_data(
                db_path,
                io::ErrorKind::NotFound,
            ));
        }

        Ok(Self::new(project_path)?)
    }
}

impl EntityStorageProviderFromStorage for SqliteEntityStorage<TRANSIENT> {
    fn from_storage(
        _path: impl AsRef<Path>,
        _attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError>
    where
        Self: Sized,
    {
        Err(EntityStorageError::unsupported_with(
            "transient sqlite entity storage cannot be loaded from existing storage",
        ))
    }
}

impl<const P: StoragePersistence> EntityStorageProvider for SqliteEntityStorage<P> {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        let (prefix, key_rest) =
            extract_key_parts(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        if !self.table_exists(&prefix) {
            return Ok(None);
        }

        let conn = self.pool.get().map_err(EntityStorageError::backing)?;
        let query = build_select_value_query(&prefix);
        let mut stmt = conn.prepare_cached(&query)?;

        let result = stmt
            .query_row(params![key_rest], |row| row.get::<_, Vec<u8>>(0))
            .optional()?;

        Ok(result.map(BytesOrSlice::from))
    }

    fn get_as<F, T>(&self, key: &[u8], mut f: F) -> Result<Option<T>, EntityStorageError>
    where
        F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
    {
        let (prefix, key_rest) =
            extract_key_parts(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        if !self.table_exists(&prefix) {
            return Ok(None);
        }

        let conn = self.pool.get().map_err(EntityStorageError::backing)?;
        let query = build_select_value_query(&prefix);
        let mut stmt = conn.prepare_cached(&query)?;

        let result = stmt
            .query_row(params![key_rest], |row| row.get::<_, Vec<u8>>(0))
            .optional()?;

        result.map(|bytes| f(&bytes)).transpose()
    }

    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        let (prefix, key_rest) =
            extract_key_parts(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        let conn = self.pool.get().map_err(EntityStorageError::backing)?;
        self.ensure_table(&conn, &prefix)?;

        let query = build_insert_query(&prefix);
        let mut stmt = conn.prepare_cached(&query)?;
        stmt.execute(params![key_rest, value.as_slice()])?;

        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        let (prefix, key_rest) =
            extract_key_parts(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        if !self.table_exists(&prefix) {
            return Ok(());
        }

        let conn = self.pool.get().map_err(EntityStorageError::backing)?;
        let query = build_delete_query(&prefix);
        let mut stmt = conn.prepare_cached(&query)?;
        stmt.execute(params![key_rest])?;

        Ok(())
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        let (prefix, key_rest) =
            extract_key_parts(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        if !self.table_exists(&prefix) {
            return Ok(false);
        }

        let conn = self.pool.get().map_err(EntityStorageError::backing)?;
        let query = build_contains_query(&prefix);
        let mut stmt = conn.prepare_cached(&query)?;

        let exists = stmt.query_row(params![key_rest], |row| row.get::<_, bool>(0))?;
        Ok(exists)
    }

    fn iter_prefix_keys<'a>(
        &'a self,
        prefix: &[u8],
    ) -> Result<EntityKeyBytesIterator<'a>, EntityStorageError> {
        if prefix.len() != ENTITY_PREFIX_SIZE {
            return Err(EntityStorageError::InvalidKeySize);
        }

        let prefix: EntityKeyPrefix = prefix
            .try_into()
            .map_err(|_| EntityStorageError::InvalidKeyFormat)?;

        if !self.table_exists(&prefix) {
            return Ok(Box::new(std::iter::empty()));
        }

        SqliteEntityKeyBytesIterator::new(&self.pool, prefix)
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        if prefix.len() != ENTITY_PREFIX_SIZE {
            return Err(EntityStorageError::InvalidKeySize);
        }

        let prefix: EntityKeyPrefix = prefix
            .try_into()
            .map_err(|_| EntityStorageError::InvalidKeyFormat)?;

        if !self.table_exists(&prefix) {
            return Ok(Box::new(std::iter::empty()));
        }

        SqliteEntityBytesIterator::new(&self.pool, prefix)
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
        if prefix.len() != ENTITY_PREFIX_SIZE {
            return Err(EntityStorageError::InvalidKeySize);
        }

        let prefix: EntityKeyPrefix = prefix
            .try_into()
            .map_err(|_| EntityStorageError::InvalidKeyFormat)?;

        if !self.table_exists(&prefix) {
            return Ok(Box::new(std::iter::empty()));
        }

        SqliteEntityBytesAsIterator::new(&self.pool, prefix, f)
    }

    fn bulk_inserter(&self) -> Result<EntityBytesBulkInserter, EntityStorageError> {
        SqliteEntityBytesBulkInserter::new(self)
    }

    fn transactional_reader(
        &self,
    ) -> Result<EntityBytesTransactionalReader<'_>, EntityStorageError> {
        SqliteEntityReader::new(self)
    }

    fn transactional_writer(
        &self,
    ) -> Result<EntityBytesTransactionalWriter<'_>, EntityStorageError> {
        SqliteEntityWriter::new(self)
    }

    fn persistence(&self) -> StoragePersistence {
        P
    }
}

#[ouroboros::self_referencing]
struct SqliteEntityBytesIteratorRows<'conn> {
    stmt: rusqlite::Statement<'conn>,
    #[borrows(mut stmt)]
    #[not_covariant]
    rows: rusqlite::Rows<'this>,
}

#[ouroboros::self_referencing]
struct SqliteEntityKeyBytesIteratorInner {
    conn: r2d2::PooledConnection<SqliteConnectionManager>,
    #[borrows(conn)]
    #[not_covariant]
    rows: SqliteEntityBytesIteratorRows<'this>,
}

struct SqliteEntityKeyBytesIterator<'a> {
    inner: SqliteEntityKeyBytesIteratorInner,
    prefix: EntityKeyPrefix,
    _marker: PhantomData<&'a ()>,
}

impl<'a> SqliteEntityKeyBytesIterator<'a> {
    fn new(
        pool: &'_ Pool<SqliteConnectionManager>,
        prefix: EntityKeyPrefix,
    ) -> Result<EntityKeyBytesIterator<'a>, EntityStorageError> {
        let conn = pool.get().map_err(EntityStorageError::backing)?;
        let query = build_select_keys_query(&prefix);

        let inner = SqliteEntityKeyBytesIteratorInner::try_new(conn, |conn| {
            let stmt = conn.prepare(&query)?;
            SqliteEntityBytesIteratorRows::try_new(stmt, |stmt| stmt.query([]))
        })?;

        Ok(Box::new(Self {
            inner,
            prefix,
            _marker: PhantomData,
        }))
    }
}

impl<'a> Iterator for SqliteEntityKeyBytesIterator<'a> {
    type Item = Result<BytesOrSlice<'a>, EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        fn mapper(row: &rusqlite::Row<'_>) -> rusqlite::Result<Vec<u8>> {
            row.get(0)
        }

        self.inner.with_rows_mut(|rows| {
            rows.with_rows_mut(|rows| {
                let value = match rows.next().transpose()?.and_then(mapper) {
                    Ok(key) => {
                        let mut full_key = Vec::with_capacity(ENTITY_PREFIX_SIZE + key.len());
                        full_key.extend_from_slice(&self.prefix);
                        full_key.extend_from_slice(&key);
                        Ok(BytesOrSlice::from(full_key))
                    }
                    Err(e) => Err(EntityStorageError::from(e)),
                };
                Some(value)
            })
        })
    }
}

#[ouroboros::self_referencing]
struct SqliteEntityBytesIteratorInner {
    conn: r2d2::PooledConnection<SqliteConnectionManager>,
    #[borrows(conn)]
    #[not_covariant]
    rows: SqliteEntityBytesIteratorRows<'this>,
}

struct SqliteEntityBytesIterator<'a> {
    inner: SqliteEntityBytesIteratorInner,
    prefix: EntityKeyPrefix,
    _marker: PhantomData<&'a ()>,
}

impl<'a> SqliteEntityBytesIterator<'a> {
    fn new(
        pool: &Pool<SqliteConnectionManager>,
        prefix: EntityKeyPrefix,
    ) -> Result<EntityBytesIterator<'a>, EntityStorageError> {
        let conn = pool.get().map_err(EntityStorageError::backing)?;
        let query = build_select_all_query(&prefix);

        let inner = SqliteEntityBytesIteratorInner::try_new(conn, |conn| {
            let stmt = conn.prepare(&query)?;
            SqliteEntityBytesIteratorRows::try_new(stmt, |stmt| stmt.query([]))
        })?;

        Ok(Box::new(Self {
            inner,
            prefix,
            _marker: PhantomData,
        }))
    }
}

impl<'a> Iterator for SqliteEntityBytesIterator<'a> {
    type Item = Result<(BytesOrSlice<'a>, BytesOrSlice<'a>), EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        fn mapper(row: &rusqlite::Row<'_>) -> rusqlite::Result<(Vec<u8>, Vec<u8>)> {
            Ok((row.get(0)?, row.get(1)?))
        }

        self.inner.with_rows_mut(|rows| {
            rows.with_rows_mut(|rows| {
                let value = match rows.next().transpose()?.and_then(mapper) {
                    Ok((key, value)) => {
                        let mut full_key = Vec::with_capacity(ENTITY_PREFIX_SIZE + key.len());
                        full_key.extend_from_slice(&self.prefix);
                        full_key.extend_from_slice(&key);
                        Ok((BytesOrSlice::from(full_key), BytesOrSlice::from(value)))
                    }
                    Err(e) => Err(EntityStorageError::from(e)),
                };
                Some(value)
            })
        })
    }
}

struct SqliteEntityBytesAsIterator<'a, T> {
    inner: SqliteEntityBytesIteratorInner,
    prefix: EntityKeyPrefix,
    f: Box<dyn FnMut(&[u8], &[u8]) -> Result<T, EntityStorageError> + 'a>,
}

impl<'a, T: 'a> SqliteEntityBytesAsIterator<'a, T> {
    fn new<F>(
        pool: &Pool<SqliteConnectionManager>,
        prefix: EntityKeyPrefix,
        f: F,
    ) -> Result<EntityBytesAsIterator<'a, T>, EntityStorageError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<T, EntityStorageError> + 'a,
    {
        let conn = pool.get().map_err(EntityStorageError::backing)?;
        let query = build_select_all_query(&prefix);

        let inner = SqliteEntityBytesIteratorInner::try_new(conn, |conn| {
            let stmt = conn.prepare(&query)?;
            SqliteEntityBytesIteratorRows::try_new(stmt, |stmt| stmt.query([]))
        })?;

        Ok(Box::new(Self {
            inner,
            prefix,
            f: Box::new(f),
        }))
    }
}

impl<T> Iterator for SqliteEntityBytesAsIterator<'_, T> {
    type Item = Result<T, EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        fn mapper(row: &rusqlite::Row<'_>) -> rusqlite::Result<(Vec<u8>, Vec<u8>)> {
            Ok((row.get(0)?, row.get(1)?))
        }

        self.inner.with_rows_mut(|rows| {
            rows.with_rows_mut(|rows| {
                let value = match rows.next().transpose()?.and_then(mapper) {
                    Ok((key, value)) => {
                        let mut full_key = Vec::with_capacity(ENTITY_PREFIX_SIZE + key.len());
                        full_key.extend_from_slice(&self.prefix);
                        full_key.extend_from_slice(&key);
                        (self.f)(&full_key, &value)
                    }
                    Err(e) => Err(EntityStorageError::from(e)),
                };
                Some(value)
            })
        })
    }
}

struct SqliteEntityBytesBulkInserter<'a, const P: StoragePersistence> {
    storage: &'a SqliteEntityStorage<P>,
    conn: r2d2::PooledConnection<SqliteConnectionManager>,
    batch_size: usize,
    in_transaction: bool,
}

impl<'a, const P: StoragePersistence> SqliteEntityBytesBulkInserter<'a, P> {
    fn new(
        storage: &'a SqliteEntityStorage<P>,
    ) -> Result<EntityBytesBulkInserter<'a>, EntityStorageError> {
        let conn = storage.pool.get().map_err(EntityStorageError::backing)?;
        conn.execute_batch("BEGIN TRANSACTION")?;

        Ok(Box::new(Self {
            storage,
            conn,
            batch_size: 0,
            in_transaction: true,
        }))
    }

    fn force_commit(&mut self) -> Result<(), EntityStorageError> {
        if self.in_transaction {
            self.conn.execute_batch("COMMIT")?;
            self.in_transaction = false;
        }

        self.conn = self
            .storage
            .pool
            .get()
            .map_err(EntityStorageError::backing)?;
        self.conn.execute_batch("BEGIN TRANSACTION")?;
        self.in_transaction = true;
        self.batch_size = 0;

        Ok(())
    }
}

impl<const P: StoragePersistence> Drop for SqliteEntityBytesBulkInserter<'_, P> {
    fn drop(&mut self) {
        if self.in_transaction {
            if let Err(e) = self.conn.execute_batch("COMMIT") {
                tracing::warn!("failed to flush batch to storage: {e}");
            }
        }
    }
}

impl<'a, const P: StoragePersistence> EntityStorageBulkInserter<'a>
    for SqliteEntityBytesBulkInserter<'a, P>
{
    fn insert(
        &mut self,
        key: BytesOrSlice<'_>,
        value: BytesOrSlice<'_>,
    ) -> Result<(), EntityStorageError> {
        if self.batch_size >= BATCH_SIZE {
            self.force_commit()?;
        }

        let (prefix, key_rest) =
            extract_key_parts(key.as_slice()).ok_or(EntityStorageError::InvalidKeyFormat)?;

        self.storage.ensure_table(&self.conn, &prefix)?;

        let query = build_insert_query(&prefix);
        let mut stmt = self.conn.prepare_cached(&query)?;
        stmt.execute(params![key_rest, value.as_slice()])?;

        self.batch_size += 1;

        Ok(())
    }

    fn commit(mut self: Box<Self>) -> Result<(), EntityStorageError> {
        if self.in_transaction {
            self.conn.execute_batch("COMMIT")?;
            self.in_transaction = false;
        }
        Ok(())
    }
}

struct SqliteEntityReader<'a, const P: StoragePersistence> {
    storage: &'a SqliteEntityStorage<P>,
    conn: r2d2::PooledConnection<SqliteConnectionManager>,
}

impl<'a, const P: StoragePersistence> SqliteEntityReader<'a, P> {
    fn new(
        storage: &'a SqliteEntityStorage<P>,
    ) -> Result<EntityBytesTransactionalReader<'a>, EntityStorageError> {
        let conn = storage.pool.get().map_err(EntityStorageError::backing)?;
        conn.execute_batch("BEGIN TRANSACTION")?;

        Ok(Box::new(Self { storage, conn }))
    }
}

impl<'a, const P: StoragePersistence> EntityStorageTransactionalReader<'a>
    for SqliteEntityReader<'a, P>
{
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        let (prefix, key_rest) =
            extract_key_parts(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        if !self.storage.table_exists(&prefix) {
            return Ok(None);
        }

        let query = build_select_value_query(&prefix);
        let mut stmt = self.conn.prepare_cached(&query)?;

        let result = stmt
            .query_row(params![key_rest], |row| row.get::<_, Vec<u8>>(0))
            .optional()?;

        Ok(result.map(BytesOrSlice::from))
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        let (prefix, key_rest) =
            extract_key_parts(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        if !self.storage.table_exists(&prefix) {
            return Ok(false);
        }

        let query = build_contains_query(&prefix);
        let mut stmt = self.conn.prepare_cached(&query)?;

        let exists = stmt.query_row(params![key_rest], |row| row.get::<_, bool>(0))?;
        Ok(exists)
    }
}

impl<const P: StoragePersistence> Drop for SqliteEntityReader<'_, P> {
    fn drop(&mut self) {
        if let Err(e) = self.conn.execute_batch("COMMIT") {
            tracing::warn!("failed to commit read transaction: {e}");
        }
    }
}

struct SqliteEntityWriter<'a, const P: StoragePersistence> {
    storage: &'a SqliteEntityStorage<P>,
    conn: r2d2::PooledConnection<SqliteConnectionManager>,
    committed: bool,
}

impl<'a, const P: StoragePersistence> SqliteEntityWriter<'a, P> {
    fn new(
        storage: &'a SqliteEntityStorage<P>,
    ) -> Result<EntityBytesTransactionalWriter<'a>, EntityStorageError> {
        let conn = storage.pool.get().map_err(EntityStorageError::backing)?;
        conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")?;

        Ok(Box::new(Self {
            storage,
            conn,
            committed: false,
        }))
    }
}

impl<const P: StoragePersistence> Drop for SqliteEntityWriter<'_, P> {
    fn drop(&mut self) {
        if !self.committed {
            if let Err(e) = self.conn.execute_batch("ROLLBACK") {
                tracing::warn!("failed to rollback transaction: {e}");
            }
        }
    }
}

impl<'a, const P: StoragePersistence> EntityStorageTransactionalReader<'a>
    for SqliteEntityWriter<'a, P>
{
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        let (prefix, key_rest) =
            extract_key_parts(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        if !self.storage.table_exists(&prefix) {
            return Ok(None);
        }

        let query = build_select_value_query(&prefix);
        let mut stmt = self.conn.prepare_cached(&query)?;

        let result = stmt
            .query_row(params![key_rest], |row| row.get::<_, Vec<u8>>(0))
            .optional()?;

        Ok(result.map(BytesOrSlice::from))
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        let (prefix, key_rest) =
            extract_key_parts(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        if !self.storage.table_exists(&prefix) {
            return Ok(false);
        }

        let query = build_contains_query(&prefix);
        let mut stmt = self.conn.prepare_cached(&query)?;

        let exists = stmt.query_row(params![key_rest], |row| row.get::<_, bool>(0))?;
        Ok(exists)
    }
}

impl<'a, const P: StoragePersistence> EntityStorageTransactionalWriter<'a>
    for SqliteEntityWriter<'a, P>
{
    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        let (prefix, key_rest) =
            extract_key_parts(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        self.storage.ensure_table(&self.conn, &prefix)?;

        let query = build_insert_query(&prefix);
        let mut stmt = self.conn.prepare_cached(&query)?;
        stmt.execute(params![key_rest, value.as_slice()])?;

        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        let (prefix, key_rest) =
            extract_key_parts(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        if !self.storage.table_exists(&prefix) {
            return Ok(());
        }

        let query = build_delete_query(&prefix);
        let mut stmt = self.conn.prepare_cached(&query)?;
        stmt.execute(params![key_rest])?;

        Ok(())
    }

    fn commit(mut self: Box<Self>) -> Result<(), EntityStorageError> {
        self.conn.execute_batch("COMMIT")?;
        self.committed = true;
        Ok(())
    }
}
