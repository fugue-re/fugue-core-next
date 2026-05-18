use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use flate2::write::GzEncoder;
use fugue_lifter_codegen::CodegenError;
use fugue_lifter_runtime::dynamic::BuildError as RuntimeBuildError;
use fugue_sleighc::SleighCompilerError;
use rkyv::rancor::Error as RkyvError;
use thiserror::Error;

use crate::spec::LanguageSpec;
use crate::Packager;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("cannot build dynamic language: {0}")]
    Dynamic(#[from] RuntimeBuildError),
    #[error("{kind} `{path}` cannot be read")]
    InvalidPath { kind: &'static str, path: PathBuf },
    #[error("cannot {action} `{path}`")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("output file `{path}` already exists; refusing to overwrite")]
    OutputExists { path: PathBuf },
    #[error("cannot serialise dynamic language: {0}")]
    Serialise(#[source] RkyvError),
    #[error("cannot compile sleigh spec for `{language}`: {source}")]
    SleighCompile {
        language: String,
        #[source]
        source: SleighCompilerError,
    },
    #[error("cannot launch sleigh compiler: {0}")]
    SleighCompilerSpawn(#[source] SleighCompilerError),
    #[error("cannot build static lifter: {0}")]
    Static(#[from] CodegenError),
}

impl BuildError {
    pub(crate) fn invalid_path(kind: &'static str, path: impl AsRef<Path>) -> Self {
        Self::InvalidPath {
            kind,
            path: path.as_ref().to_path_buf(),
        }
    }

    pub(crate) fn io(action: &'static str, path: impl AsRef<Path>, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.as_ref().to_path_buf(),
            source,
        }
    }

    pub(crate) fn output_exists(path: impl AsRef<Path>) -> Self {
        Self::OutputExists {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub(crate) fn sleigh_compile(language: impl Into<String>, source: SleighCompilerError) -> Self {
        Self::SleighCompile {
            language: language.into(),
            source,
        }
    }
}

impl Packager {
    pub fn build_dynamic(
        &self,
        language_db: impl AsRef<Path>,
        language: impl AsRef<str>,
        output: impl AsRef<Path>,
    ) -> Result<(), BuildError> {
        let spec = LanguageSpec::new(language_db.as_ref(), language.as_ref())?;
        let output = output.as_ref();
        if output.exists() {
            return Err(BuildError::output_exists(output));
        }

        let language = spec.build_dynamic()?;
        let bytes = language.to_bytes().map_err(BuildError::Serialise)?;
        self.compress(output, bytes.as_ref())
    }

    pub fn build_static(
        &self,
        language_db: impl AsRef<Path>,
        language: impl AsRef<str>,
        output: impl AsRef<Path>,
        variants: &[&str],
    ) -> Result<(), BuildError> {
        let spec = LanguageSpec::new(language_db.as_ref(), language.as_ref())?;
        let lifter = spec.build_static(variants)?;
        self.compress(output.as_ref(), lifter.as_bytes())
    }

    fn compress(&self, output: &Path, bytes: &[u8]) -> Result<(), BuildError> {
        let file =
            File::create(output).map_err(|source| BuildError::io("create file", output, source))?;
        let mut writer = GzEncoder::new(BufWriter::new(file), Default::default());
        writer
            .write_all(bytes)
            .map_err(|source| BuildError::io("write file", output, source))?;
        writer
            .finish()
            .map_err(|source| BuildError::io("finalise file", output, source))?;
        Ok(())
    }
}
