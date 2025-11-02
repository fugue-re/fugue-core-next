use std::path::Path;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use thiserror::Error;

use crate::storage::{StoragePersistence, PERSISTENT, TRANSIENT};

#[derive(Debug, Error)]
pub enum SqliteEntityStorageError {
    #[error("SQLite connection initialisation failed: {0}")]
    ConnectionInit(rusqlite::Error),
    #[error("SQLite database initialisation failed: {0}")]
    DatabaseInit(rusqlite::Error),
}

pub struct SqliteEntityStorage<const P: StoragePersistence> {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteEntityStorage<{ PERSISTENT }> {
    pub fn new(_path: impl AsRef<Path>) -> Result<Self, SqliteEntityStorageError> {
        todo!()
    }
}

impl SqliteEntityStorage<{ TRANSIENT }> {
    pub fn new() -> Result<Self, SqliteEntityStorageError> {
        todo!()
    }
}
