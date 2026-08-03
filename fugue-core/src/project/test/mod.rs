use super::{Project, ProjectError};
#[cfg(any(feature = "sqlite", feature = "rocksdb", feature = "mdbx"))]
use crate::attributes;
use crate::il::common::{IlArtefact, IlError, IlGraph, IlMetadata};
use crate::il::pcode::PCodeIr;
use crate::ir::FunctionId;
#[cfg(any(feature = "sqlite", feature = "rocksdb", feature = "mdbx"))]
use crate::platform::Format;
#[cfg(feature = "mdbx")]
use crate::storage::entities::MdbxEntityStorage;
#[cfg(feature = "rocksdb")]
use crate::storage::entities::RocksDbEntityStorage;
#[cfg(any(feature = "sqlite", feature = "rocksdb", feature = "mdbx"))]
use crate::storage::{
    DefaultPersistentEntityStorage, DefaultPersistentSegmentStorage, PersistentStorageProvider,
};
#[cfg(any(feature = "sqlite", feature = "rocksdb", feature = "mdbx"))]
use crate::types::ATTRIBUTE_PROJECT_PATH;

mod artefact_validity;
mod persistence;

fn with_logging(
    f: impl FnOnce() -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .with_line_number(true)
        .with_file(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .finish();

    tracing::subscriber::with_default(subscriber, f)
}
