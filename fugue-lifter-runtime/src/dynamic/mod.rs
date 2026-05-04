pub mod blob;
pub mod build;
pub mod builder;
pub mod install;
pub mod registry;

pub use builder::LanguageBuilder;

use std::io;
use std::path::PathBuf;

use rkyv::rancor::Error as RkyvError;
use thiserror::Error;

pub use crate::data::LanguageData;
use crate::language::LanguageParseError;

#[derive(Debug, Error)]
pub enum LanguageLoadError {
    #[error("sleigh build failed: {0}")]
    Build(#[from] build::BuildError),
    #[error("blob deserialise failed: {0}")]
    Deserialise(RkyvError),
    #[error("cannot {action} blob at `{path}`: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("malformed language id `{0}`: {1}")]
    LanguageId(String, LanguageParseError),
}

impl LanguageLoadError {
    pub(crate) fn io(action: &'static str, path: PathBuf, source: io::Error) -> Self {
        Self::Io {
            action,
            path,
            source,
        }
    }
}
