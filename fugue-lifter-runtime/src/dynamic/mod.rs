use std::io;
use std::path::PathBuf;

use rkyv::rancor::Error as RkyvError;
use thiserror::Error;

use crate::language::LanguageParseError;

mod constructor;
mod convention;
mod install;
mod language;
mod operand;
mod resolve;
mod space;
mod symbol;
mod tables;
mod template;

pub(crate) mod registry;

pub use language::{Language, LanguageBuildError};

#[derive(Debug, Error)]
pub enum LanguageLoadError {
    #[error("language build failed: {0}")]
    Build(#[from] LanguageBuildError),
    #[error("language deserialise failed: {0}")]
    Deserialise(RkyvError),
    #[error("cannot {action} blob at `{path}`: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid language identifier `{0}`: {1}")]
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
