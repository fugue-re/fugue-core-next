use std::cell::RefCell;
use std::fmt::Write as _;
use std::io;
use std::marker::PhantomData;
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use arrayvec::ArrayString;
use dashmap::DashSet;
use r2d2::{CustomizeConnection, Pool};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{OptionalExtension, params, params_from_iter};
use smallvec::SmallVec;
use thiserror::Error;

use super::schema::ENTITY_PREFIX_SIZE;
use super::{
    EntityBytesAsIterator, EntityBytesIterator, EntityBytesTransactionalReader,
    EntityBytesTransactionalWriter, EntityKeyBytesIterator, EntityKeyPrefix, EntityStorageError,
    EntityStorageProvider, EntityStorageProviderFromLoadable, EntityStorageProviderFromStorage,
    EntityStorageTransactionalReader, EntityStorageTransactionalWriter, EntityWrite,
};
use crate::loader::Loadable;
use crate::storage::{PERSISTENT, StoragePersistence, TRANSIENT};
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;
use crate::types::{AttributeMap, BytesOrSlice};

const PROJECT_SQLITE_DATA: &str = "entities.db";
const DEFAULT_POOL_SIZE: u32 = 16;
const BUSY_RETRY_LIMIT: i32 = 50;
const BUSY_RETRY_DELAY: Duration = Duration::from_millis(1);
// An insertion binds two variables per row. Keep the statement below SQLite's
// historical 999-variable default as well as current builds' higher limit.
const WRITE_BATCH_ROWS: usize = 499;

#[derive(Debug, Error)]
pub enum SqliteEntityStorageError {
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

fn table_name(prefix: &EntityKeyPrefix) -> ArrayString<11> {
    let mut name = ArrayString::new();
    write!(
        name,
        "entity_{:02x}{:02x}",
        prefix.key_id(),
        prefix.entity_id(),
    )
    .expect("entity table name has fixed capacity");
    name
}

fn build_create_table_query(prefix: &EntityKeyPrefix) -> ArrayString<128> {
    let mut query = ArrayString::new();
    query.push_str("CREATE TABLE IF NOT EXISTS ");
    query.push_str(&table_name(prefix));
    query.push_str(" (key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL) WITHOUT ROWID");
    query
}

fn build_select_value_query(prefix: &EntityKeyPrefix) -> ArrayString<64> {
    let mut query = ArrayString::new();
    query.push_str("SELECT value FROM ");
    query.push_str(&table_name(prefix));
    query.push_str(" WHERE key = ?1");
    query
}

fn build_insert_query(prefix: &EntityKeyPrefix) -> ArrayString<80> {
    let mut query = ArrayString::new();
    query.push_str("INSERT OR REPLACE INTO ");
    query.push_str(&table_name(prefix));
    query.push_str(" (key, value) VALUES (?1, ?2)");
    query
}

fn build_insert_batch_query(prefix: &EntityKeyPrefix, rows: usize) -> String {
    let mut query = String::with_capacity(48 + rows * 8);
    query.push_str("INSERT OR REPLACE INTO ");
    query.push_str(&table_name(prefix));
    query.push_str(" (key, value) VALUES ");
    for row in 0..rows {
        if row != 0 {
            query.push(',');
        }
        query.push_str("(?, ?)");
    }
    query
}

fn build_delete_query(prefix: &EntityKeyPrefix) -> ArrayString<64> {
    let mut query = ArrayString::new();
    query.push_str("DELETE FROM ");
    query.push_str(&table_name(prefix));
    query.push_str(" WHERE key = ?1");
    query
}

fn build_delete_batch_query(prefix: &EntityKeyPrefix, rows: usize) -> String {
    let mut query = String::with_capacity(40 + rows * 2);
    query.push_str("DELETE FROM ");
    query.push_str(&table_name(prefix));
    query.push_str(" WHERE key IN (");
    for row in 0..rows {
        if row != 0 {
            query.push(',');
        }
        query.push('?');
    }
    query.push(')');
    query
}

fn build_select_keys_query(prefix: &EntityKeyPrefix) -> ArrayString<64> {
    let mut query = ArrayString::new();
    query.push_str("SELECT key FROM ");
    query.push_str(&table_name(prefix));
    query.push_str(" ORDER BY key");
    query
}

fn build_select_all_query(prefix: &EntityKeyPrefix) -> ArrayString<64> {
    let mut query = ArrayString::new();
    query.push_str("SELECT key, value FROM ");
    query.push_str(&table_name(prefix));
    query.push_str(" ORDER BY key");
    query
}

fn build_select_range_query(prefix: &EntityKeyPrefix, inclusive: bool) -> ArrayString<96> {
    let mut query = ArrayString::new();
    query.push_str("SELECT key, value FROM ");
    query.push_str(&table_name(prefix));
    if inclusive {
        query.push_str(" WHERE key >= ?1 ORDER BY key");
    } else {
        query.push_str(" WHERE key > ?1 ORDER BY key");
    }
    query
}

fn build_contains_query(prefix: &EntityKeyPrefix) -> ArrayString<64> {
    let mut query = ArrayString::new();
    query.push_str("SELECT EXISTS(SELECT 1 FROM ");
    query.push_str(&table_name(prefix));
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
        "PRAGMA page_size = 16384;
         PRAGMA journal_mode = WAL;
         PRAGMA wal_autocheckpoint = 1000;
         PRAGMA synchronous = NORMAL;
         PRAGMA wal_checkpoint(TRUNCATE);
         PRAGMA cache_size = -64000;",
    )?;

    Ok(())
}

#[derive(Default)]
struct SqliteSchema {
    tables: DashSet<EntityKeyPrefix>,
}

impl SqliteSchema {
    fn contains(&self, prefix: &EntityKeyPrefix) -> bool {
        self.tables.contains(prefix)
    }

    fn prepare_table(
        &self,
        conn: &rusqlite::Connection,
        prefix: &EntityKeyPrefix,
    ) -> Result<bool, rusqlite::Error> {
        if self.contains(prefix) {
            return Ok(false);
        }
        create_table(conn, prefix)?;
        Ok(true)
    }

    fn ensure_table(
        &self,
        conn: &rusqlite::Connection,
        prefix: &EntityKeyPrefix,
    ) -> Result<(), rusqlite::Error> {
        if self.prepare_table(conn, prefix)? {
            self.tables.insert(*prefix);
        }
        Ok(())
    }

    fn publish_tables(&self, tables: impl IntoIterator<Item = EntityKeyPrefix>) {
        for table in tables {
            self.tables.insert(table);
        }
    }
}

#[derive(Debug, Default)]
struct SqliteConnectionCustomiser;

impl SqliteConnectionCustomiser {
    fn busy_handler(attempt: i32) -> bool {
        if attempt >= BUSY_RETRY_LIMIT {
            return false;
        }
        sleep(BUSY_RETRY_DELAY);
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
    schema: Arc<SqliteSchema>,
}

impl SqliteEntityStorage<PERSISTENT> {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, SqliteEntityStorageError> {
        let db_path = path.as_ref().join(PROJECT_SQLITE_DATA);
        let manager = SqliteConnectionManager::file(&db_path);
        let pool = Pool::builder()
            .max_size(DEFAULT_POOL_SIZE)
            .connection_customizer(Box::new(SqliteConnectionCustomiser))
            .build(manager)
            .map_err(SqliteEntityStorageError::Pool)?;

        let conn = pool.get().map_err(SqliteEntityStorageError::Pool)?;
        init_database(&conn).map_err(SqliteEntityStorageError::DatabaseInit)?;

        Ok(Self {
            pool,
            schema: Arc::new(SqliteSchema::default()),
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
            .connection_customizer(Box::new(SqliteConnectionCustomiser))
            .build(manager)
            .map_err(SqliteEntityStorageError::Pool)?;

        let conn = pool.get().map_err(SqliteEntityStorageError::Pool)?;
        init_database(&conn).map_err(SqliteEntityStorageError::DatabaseInit)?;

        Ok(Self {
            pool,
            schema: Arc::new(SqliteSchema::default()),
        })
    }
}

impl Default for SqliteEntityStorage<TRANSIENT> {
    fn default() -> Self {
        Self::new().expect("failed to create transient sqlite storage")
    }
}

impl<const P: StoragePersistence> SqliteEntityStorage<P> {
    fn ensure_table(&self, prefix: &EntityKeyPrefix) -> Result<(), EntityStorageError> {
        if self.schema.contains(prefix) {
            return Ok(());
        }

        let conn = self.pool.get().map_err(EntityStorageError::backing)?;
        self.schema.ensure_table(&conn, prefix)?;
        Ok(())
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
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        let conn = self.pool.get().map_err(EntityStorageError::backing)?;
        self.schema.ensure_table(&conn, &prefix)?;
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
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        let conn = self.pool.get().map_err(EntityStorageError::backing)?;
        self.schema.ensure_table(&conn, &prefix)?;
        let query = build_select_value_query(&prefix);
        let mut stmt = conn.prepare_cached(&query)?;

        stmt.query_row(params![key_rest], |row| {
            let row = row.get_ref(0)?.as_blob()?;
            Ok(f(row))
        })
        .optional()?
        .transpose()
    }

    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        let (prefix, key_rest) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        let conn = self.pool.get().map_err(EntityStorageError::backing)?;
        self.schema.ensure_table(&conn, &prefix)?;
        let query = build_insert_query(&prefix);
        let mut stmt = conn.prepare_cached(&query)?;
        stmt.execute(params![key_rest, value.as_slice()])?;

        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        let (prefix, key_rest) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        let conn = self.pool.get().map_err(EntityStorageError::backing)?;
        self.schema.ensure_table(&conn, &prefix)?;
        let query = build_delete_query(&prefix);
        let mut stmt = conn.prepare_cached(&query)?;
        stmt.execute(params![key_rest])?;

        Ok(())
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        let (prefix, key_rest) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        let conn = self.pool.get().map_err(EntityStorageError::backing)?;
        self.schema.ensure_table(&conn, &prefix)?;
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

        let prefix =
            EntityKeyPrefix::try_from(prefix).map_err(|_| EntityStorageError::InvalidKeyFormat)?;

        self.ensure_table(&prefix)?;
        SqliteEntityKeyBytesIterator::new(&self.pool, prefix)
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        if prefix.len() != ENTITY_PREFIX_SIZE {
            return Err(EntityStorageError::InvalidKeySize);
        }

        let prefix =
            EntityKeyPrefix::try_from(prefix).map_err(|_| EntityStorageError::InvalidKeyFormat)?;

        self.ensure_table(&prefix)?;
        SqliteEntityBytesIterator::new(&self.pool, prefix)
    }

    fn iter_range(
        &self,
        prefix: &[u8],
        start: Bound<&[u8]>,
    ) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        if prefix.len() != ENTITY_PREFIX_SIZE {
            return Err(EntityStorageError::InvalidKeySize);
        }

        let prefix =
            EntityKeyPrefix::try_from(prefix).map_err(|_| EntityStorageError::InvalidKeyFormat)?;

        self.ensure_table(&prefix)?;
        SqliteEntityBytesIterator::new_range(&self.pool, prefix, start)
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

        let prefix =
            EntityKeyPrefix::try_from(prefix).map_err(|_| EntityStorageError::InvalidKeyFormat)?;

        self.ensure_table(&prefix)?;
        SqliteEntityBytesAsIterator::new(&self.pool, prefix, f)
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
    #[allow(clippy::new_ret_no_self)]
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
                        full_key.extend_from_slice(self.prefix.as_ref());
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
    #[allow(clippy::new_ret_no_self)]
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

    #[allow(clippy::new_ret_no_self)]
    fn new_range(
        pool: &Pool<SqliteConnectionManager>,
        prefix: EntityKeyPrefix,
        start: Bound<&[u8]>,
    ) -> Result<EntityBytesIterator<'a>, EntityStorageError> {
        match start {
            Bound::Unbounded => Self::new(pool, prefix),
            Bound::Included(key) | Bound::Excluded(key) => {
                let inclusive = matches!(start, Bound::Included(_));
                let conn = pool.get().map_err(EntityStorageError::backing)?;
                let query = build_select_range_query(&prefix, inclusive);
                let key = key
                    .strip_prefix(prefix.as_ref())
                    .ok_or(EntityStorageError::InvalidKeyFormat)?
                    .to_vec();

                let inner = SqliteEntityBytesIteratorInner::try_new(conn, |conn| {
                    let stmt = conn.prepare(&query)?;
                    SqliteEntityBytesIteratorRows::try_new(stmt, |stmt| stmt.query(params![key]))
                })?;

                Ok(Box::new(Self {
                    inner,
                    prefix,
                    _marker: PhantomData,
                }))
            }
        }
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
                        full_key.extend_from_slice(self.prefix.as_ref());
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

type EntityBytesMapper<'a, T> = dyn FnMut(&[u8], &[u8]) -> Result<T, EntityStorageError> + 'a;

struct SqliteEntityBytesAsIterator<'a, T> {
    inner: SqliteEntityBytesIteratorInner,
    prefix: EntityKeyPrefix,
    f: Box<EntityBytesMapper<'a, T>>,
}

impl<'a, T: 'a> SqliteEntityBytesAsIterator<'a, T> {
    #[allow(clippy::new_ret_no_self)]
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
                        full_key.extend_from_slice(self.prefix.as_ref());
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

struct SqliteEntityReader<'a, const P: StoragePersistence> {
    conn: r2d2::PooledConnection<SqliteConnectionManager>,
    pending_tables: RefCell<SmallVec<[EntityKeyPrefix; 4]>>,
    schema: Arc<SqliteSchema>,
    _marker: PhantomData<&'a SqliteEntityStorage<P>>,
}

impl<'a, const P: StoragePersistence> SqliteEntityReader<'a, P> {
    #[allow(clippy::new_ret_no_self)]
    fn new(
        storage: &'a SqliteEntityStorage<P>,
    ) -> Result<EntityBytesTransactionalReader<'a>, EntityStorageError> {
        let conn = storage.pool.get().map_err(EntityStorageError::backing)?;
        conn.execute_batch("BEGIN TRANSACTION")?;

        Ok(Box::new(Self {
            conn,
            pending_tables: RefCell::new(SmallVec::new()),
            schema: storage.schema.clone(),
            _marker: PhantomData,
        }))
    }

    fn ensure_table(&self, prefix: &EntityKeyPrefix) -> Result<(), EntityStorageError> {
        if self.pending_tables.borrow().contains(prefix) {
            return Ok(());
        }
        if self.schema.prepare_table(&self.conn, prefix)? {
            self.pending_tables.borrow_mut().push(*prefix);
        }
        Ok(())
    }
}

impl<'a, const P: StoragePersistence> EntityStorageTransactionalReader<'a>
    for SqliteEntityReader<'a, P>
{
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        let (prefix, key_rest) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        self.ensure_table(&prefix)?;
        let query = build_select_value_query(&prefix);
        let mut stmt = self.conn.prepare_cached(&query)?;

        let result = stmt
            .query_row(params![key_rest], |row| row.get::<_, Vec<u8>>(0))
            .optional()?;

        Ok(result.map(BytesOrSlice::from))
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        let (prefix, key_rest) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        self.ensure_table(&prefix)?;
        let query = build_contains_query(&prefix);
        let mut stmt = self.conn.prepare_cached(&query)?;

        let exists = stmt.query_row(params![key_rest], |row| row.get::<_, bool>(0))?;
        Ok(exists)
    }
}

impl<const P: StoragePersistence> Drop for SqliteEntityReader<'_, P> {
    fn drop(&mut self) {
        match self.conn.execute_batch("COMMIT") {
            Ok(()) => self
                .schema
                .publish_tables(self.pending_tables.get_mut().drain(..)),
            Err(error) => tracing::warn!("failed to commit read transaction: {error}"),
        }
    }
}

struct SqliteEntityWriter<'a, const P: StoragePersistence> {
    conn: r2d2::PooledConnection<SqliteConnectionManager>,
    committed: bool,
    pending_tables: RefCell<SmallVec<[EntityKeyPrefix; 4]>>,
    schema: Arc<SqliteSchema>,
    _marker: PhantomData<&'a SqliteEntityStorage<P>>,
}

impl<'a, const P: StoragePersistence> SqliteEntityWriter<'a, P> {
    #[allow(clippy::new_ret_no_self)]
    fn new(
        storage: &'a SqliteEntityStorage<P>,
    ) -> Result<EntityBytesTransactionalWriter<'a>, EntityStorageError> {
        let conn = storage.pool.get().map_err(EntityStorageError::backing)?;
        conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")?;

        Ok(Box::new(Self {
            conn,
            committed: false,
            pending_tables: RefCell::new(SmallVec::new()),
            schema: storage.schema.clone(),
            _marker: PhantomData,
        }))
    }

    fn ensure_table(&self, prefix: &EntityKeyPrefix) -> Result<(), EntityStorageError> {
        if self.pending_tables.borrow().contains(prefix) {
            return Ok(());
        }
        if self.schema.prepare_table(&self.conn, prefix)? {
            self.pending_tables.borrow_mut().push(*prefix);
        }
        Ok(())
    }

    fn insert_batch(
        &self,
        prefix: &EntityKeyPrefix,
        writes: &[EntityWrite],
    ) -> Result<(), EntityStorageError> {
        let mut chunks = writes.chunks_exact(WRITE_BATCH_ROWS);
        if writes.len() >= WRITE_BATCH_ROWS {
            let query = build_insert_batch_query(prefix, WRITE_BATCH_ROWS);
            let mut stmt = self.conn.prepare_cached(&query)?;
            for chunk in &mut chunks {
                let parameters = chunk.iter().flat_map(|write| {
                    [
                        &write.key()[ENTITY_PREFIX_SIZE..],
                        write.value().expect("insertion batch checked"),
                    ]
                });
                stmt.execute(params_from_iter(parameters))?;
            }
        }

        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let query = build_insert_batch_query(prefix, remainder.len());
            let mut stmt = self.conn.prepare_cached(&query)?;
            let parameters = remainder.iter().flat_map(|write| {
                [
                    &write.key()[ENTITY_PREFIX_SIZE..],
                    write.value().expect("insertion batch checked"),
                ]
            });
            stmt.execute(params_from_iter(parameters))?;
        }
        Ok(())
    }

    fn remove_batch(
        &self,
        prefix: &EntityKeyPrefix,
        writes: &[EntityWrite],
    ) -> Result<(), EntityStorageError> {
        let mut chunks = writes.chunks_exact(WRITE_BATCH_ROWS);
        if writes.len() >= WRITE_BATCH_ROWS {
            let query = build_delete_batch_query(prefix, WRITE_BATCH_ROWS);
            let mut stmt = self.conn.prepare_cached(&query)?;
            for chunk in &mut chunks {
                let parameters = chunk.iter().map(|write| &write.key()[ENTITY_PREFIX_SIZE..]);
                stmt.execute(params_from_iter(parameters))?;
            }
        }

        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let query = build_delete_batch_query(prefix, remainder.len());
            let mut stmt = self.conn.prepare_cached(&query)?;
            let parameters = remainder
                .iter()
                .map(|write| &write.key()[ENTITY_PREFIX_SIZE..]);
            stmt.execute(params_from_iter(parameters))?;
        }
        Ok(())
    }
}

impl<const P: StoragePersistence> Drop for SqliteEntityWriter<'_, P> {
    fn drop(&mut self) {
        if !self.committed
            && let Err(e) = self.conn.execute_batch("ROLLBACK")
        {
            tracing::warn!("failed to rollback transaction: {e}");
        }
    }
}

impl<'a, const P: StoragePersistence> EntityStorageTransactionalReader<'a>
    for SqliteEntityWriter<'a, P>
{
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        let (prefix, key_rest) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        self.ensure_table(&prefix)?;
        let query = build_select_value_query(&prefix);
        let mut stmt = self.conn.prepare_cached(&query)?;

        let result = stmt
            .query_row(params![key_rest], |row| row.get::<_, Vec<u8>>(0))
            .optional()?;

        Ok(result.map(BytesOrSlice::from))
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        let (prefix, key_rest) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        self.ensure_table(&prefix)?;
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
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        self.ensure_table(&prefix)?;
        let query = build_insert_query(&prefix);
        let mut stmt = self.conn.prepare_cached(&query)?;
        stmt.execute(params![key_rest, value.as_slice()])?;

        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        let (prefix, key_rest) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        self.ensure_table(&prefix)?;
        let query = build_delete_query(&prefix);
        let mut stmt = self.conn.prepare_cached(&query)?;
        stmt.execute(params![key_rest])?;

        Ok(())
    }

    fn apply_batch(&self, writes: &[EntityWrite]) -> Result<(), EntityStorageError> {
        let mut start = 0;
        while start < writes.len() {
            let write = &writes[start];
            let (prefix, _) =
                EntityKeyPrefix::split(write.key()).ok_or(EntityStorageError::InvalidKeyFormat)?;
            self.ensure_table(&prefix)?;
            let insertion = write.value().is_some();
            let mut end = start + 1;
            while end < writes.len() {
                let next = &writes[end];
                let Some((next_prefix, _)) = EntityKeyPrefix::split(next.key()) else {
                    return Err(EntityStorageError::InvalidKeyFormat);
                };
                if next_prefix != prefix || next.value().is_some() != insertion {
                    break;
                }
                end += 1;
            }

            if insertion {
                self.insert_batch(&prefix, &writes[start..end])?;
            } else {
                self.remove_batch(&prefix, &writes[start..end])?;
            }
            start = end;
        }
        Ok(())
    }

    fn commit(mut self: Box<Self>) -> Result<(), EntityStorageError> {
        self.conn.execute_batch("COMMIT")?;
        self.schema
            .publish_tables(self.pending_tables.get_mut().drain(..));
        self.committed = true;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::ops::Bound;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use r2d2::Pool;
    use r2d2::event::{CheckoutEvent, HandleEvent};
    use r2d2_sqlite::SqliteConnectionManager;

    use super::{
        SqliteConnectionCustomiser, SqliteEntityStorage, SqliteSchema, create_table, init_database,
    };
    use crate::ir::{Address, Switch, SwitchModel, SwitchTable};
    use crate::storage::TRANSIENT;
    use crate::storage::entities::schema::EntityId;
    use crate::storage::entities::{Entity, EntityKeyPrefix, EntityStorage};

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
        const ID: EntityId = EntityId::new(126);
    }

    #[derive(Debug)]
    struct CheckoutCounter(Arc<AtomicUsize>);

    impl HandleEvent for CheckoutCounter {
        fn handle_checkout(&self, _event: CheckoutEvent) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn sqlite_known_table_iterator_checks_out_once() -> Result<(), Box<dyn std::error::Error>> {
        let checkouts = Arc::new(AtomicUsize::new(0));
        let manager = SqliteConnectionManager::memory().with_flags(
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_SHARED_CACHE,
        );
        let pool = Pool::builder()
            .max_size(1)
            .connection_customizer(Box::new(SqliteConnectionCustomiser))
            .event_handler(Box::new(CheckoutCounter(checkouts.clone())))
            .build(manager)?;
        let conn = pool.get()?;
        init_database(&conn)?;
        drop(conn);

        let sqlite = SqliteEntityStorage::<TRANSIENT> {
            pool,
            schema: Arc::new(SqliteSchema::default()),
        };
        let storage = EntityStorage::new(sqlite);
        storage.insert(&Address::from(1u64), &TestEntity::new(1))?;
        checkouts.store(0, Ordering::Relaxed);

        let entities = storage
            .iter::<Address, TestEntity>()?
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(entities.len(), 1);
        assert_eq!(checkouts.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[test]
    fn sqlite_iter_range_respects_inclusive_and_exclusive_bounds()
    -> Result<(), Box<dyn std::error::Error>> {
        let sqlite = SqliteEntityStorage::<TRANSIENT>::new()?;
        let conn = sqlite.pool.get()?;
        create_table(&conn, &EntityKeyPrefix::of::<Address, TestEntity>())?;
        drop(conn);
        let storage = EntityStorage::new(sqlite);

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

    #[test]
    fn sqlite_initialises_switch_tables() -> Result<(), Box<dyn std::error::Error>> {
        let storage = EntityStorage::new(SqliteEntityStorage::<TRANSIENT>::new()?);
        let branch = Address::from(0x401000u64);
        let mut switches = SwitchTable::new(storage.clone(), 64 * 1024)?;
        let id = switches.insert(branch, |id, branch| {
            Ok(Switch::new(id, branch, SwitchModel::Explicit))
        })?;

        switches.flush()?;
        drop(switches);

        let switches = SwitchTable::new(storage, 64 * 1024)?;
        assert_eq!(
            switches.get_by_id(id).map(|switch| switch.branch()),
            Some(branch)
        );

        Ok(())
    }
}
