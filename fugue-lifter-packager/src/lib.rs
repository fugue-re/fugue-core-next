use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use thiserror::Error;

mod sync;

pub use self::sync::{sync_languages, SyncOptions};

#[derive(Debug, Error)]
pub enum LifterPackagerError {
    #[error("{message}")]
    InvalidArguments { message: String },
    #[error("{kind} `{path}` cannot be read")]
    InvalidPath { kind: &'static str, path: PathBuf },
    #[error("missing {kind} `{path}`")]
    MissingPath { kind: &'static str, path: PathBuf },
    #[error("no stable release tag could be resolved from `{repository}`")]
    ReleaseNotFound { repository: String },
    #[error("cannot run `{command}`")]
    CommandSpawn {
        command: String,
        #[source]
        source: io::Error,
    },
    #[error("`{command}` failed with status {status}: {stderr}")]
    CommandFailed {
        command: String,
        status: ExitStatus,
        stderr: String,
    },
    #[error("cannot {action} `{path}`")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot rename `{from}` to `{to}`")]
    RenamePath {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot generate lifter: {0}")]
    GenerateLifter(#[from] fugue_lifter_codegen::CodegenError),
}

impl LifterPackagerError {
    pub fn invalid_arguments(message: impl Into<String>) -> Self {
        Self::InvalidArguments {
            message: message.into(),
        }
    }

    pub fn invalid_path(kind: &'static str, path: impl AsRef<Path>) -> Self {
        Self::InvalidPath {
            kind,
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn missing_path(kind: &'static str, path: impl AsRef<Path>) -> Self {
        Self::MissingPath {
            kind,
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn io(action: &'static str, path: impl AsRef<Path>, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.as_ref().to_path_buf(),
            source,
        }
    }

    pub fn rename_path(from: impl AsRef<Path>, to: impl AsRef<Path>, source: io::Error) -> Self {
        Self::RenamePath {
            from: from.as_ref().to_path_buf(),
            to: to.as_ref().to_path_buf(),
            source,
        }
    }

    pub fn release_not_found(repository: impl Into<String>) -> Self {
        Self::ReleaseNotFound {
            repository: repository.into(),
        }
    }
}

pub fn unpack_lifter(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<(), LifterPackagerError> {
    let input = input.as_ref();
    let output = output.as_ref();

    if !input.exists() {
        return Err(LifterPackagerError::missing_path("input file", input));
    }

    let input_file =
        File::open(input).map_err(|source| LifterPackagerError::io("read file", input, source))?;
    let output_file = File::create(output)
        .map_err(|source| LifterPackagerError::io("create file", output, source))?;

    let mut deflated = GzDecoder::new(input_file);
    let mut writer = BufWriter::new(output_file);
    io::copy(&mut deflated, &mut writer)
        .map_err(|source| LifterPackagerError::io("write file", output, source))?;

    Ok(())
}

pub fn pack_lifter(
    specs: impl AsRef<Path>,
    language: &str,
    output: impl AsRef<Path>,
) -> Result<(), LifterPackagerError> {
    let specs = specs.as_ref();
    let output = output.as_ref();

    if !specs.exists() || !specs.is_dir() {
        return Err(LifterPackagerError::invalid_path(
            "language specification directory",
            specs,
        ));
    }

    let lifter = fugue_lifter_codegen::build_with(specs, language, true)?;
    let output_file = File::create(output)
        .map_err(|source| LifterPackagerError::io("create file", output, source))?;
    let mut writer = GzEncoder::new(BufWriter::new(output_file), Default::default());

    writer
        .write_all(lifter.as_bytes())
        .map_err(|source| LifterPackagerError::io("write file", output, source))?;
    writer
        .finish()
        .map_err(|source| LifterPackagerError::io("finalise file", output, source))?;

    Ok(())
}
