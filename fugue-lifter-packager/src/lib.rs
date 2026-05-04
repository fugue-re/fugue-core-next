use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use fugue_lifter_codegen::CodegenError;
use fugue_lifter_runtime::dynamic::blob::language::Language as LanguageBlob;
use fugue_lifter_runtime::dynamic::build::{self, BuildError};
use fugue_sleighc::{SleighCompiler, SleighCompilerError};
use rkyv::rancor::Error as RkyvError;
use thiserror::Error;

mod sync;

pub use self::sync::{sync_languages, SyncOptions};

#[derive(Debug, Error)]
pub enum LifterPackagerError {
    #[error("cannot build dynamic blob: {0}")]
    BuildBlob(#[from] BuildError),
    #[error("`{command}` failed with status {status}: {stderr}")]
    CommandFailed {
        command: String,
        status: ExitStatus,
        stderr: String,
    },
    #[error("cannot run `{command}`")]
    CommandSpawn {
        command: String,
        #[source]
        source: io::Error,
    },
    #[error("cannot generate lifter: {0}")]
    GenerateLifter(#[from] CodegenError),
    #[error("{message}")]
    InvalidArguments { message: String },
    #[error("{kind} `{path}` cannot be read")]
    InvalidPath { kind: &'static str, path: PathBuf },
    #[error("cannot {action} `{path}`")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("missing {kind} `{path}`")]
    MissingPath { kind: &'static str, path: PathBuf },
    #[error("output file `{path}` already exists; refusing to overwrite")]
    OutputExists { path: PathBuf },
    #[error("no stable release tag could be resolved from `{repository}`")]
    ReleaseNotFound { repository: String },
    #[error("cannot rename `{from}` to `{to}`")]
    RenamePath {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot serialise blob: {0}")]
    Rkyv(#[source] RkyvError),
    #[error("cannot compile .sla for `{language}`: {source}")]
    SleighCompile {
        language: String,
        #[source]
        source: SleighCompilerError,
    },
    #[error("cannot launch sleigh compiler: {0}")]
    SleighCompilerSpawn(#[source] SleighCompilerError),
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

    fn output_exists(path: impl AsRef<Path>) -> Self {
        Self::OutputExists {
            path: path.as_ref().to_path_buf(),
        }
    }

    fn sleigh_compile(language: impl Into<String>, source: SleighCompilerError) -> Self {
        Self::SleighCompile {
            language: language.into(),
            source,
        }
    }
}

fn compile_and_build_blob(
    specs: &Path,
    language: &str,
) -> Result<LanguageBlob, LifterPackagerError> {
    match build::build(specs, language) {
        Ok(blob) => Ok(blob),
        Err(BuildError::SleighSlaMissing { path, .. }) => {
            let scratch = tempfile::tempdir()
                .map_err(|source| LifterPackagerError::io("create scratch dir", &path, source))?;
            let scratch_sla = scratch.path().join(
                path.file_name()
                    .expect("missing sla path has a file name component"),
            );
            compile_sla(language, &path, &scratch_sla)?;
            Ok(build::build_with_sla(specs, language, &scratch_sla)?)
        }
        Err(other) => Err(other.into()),
    }
}

fn compile_sla(
    language: &str,
    expected_sla: &Path,
    output_sla: &Path,
) -> Result<(), LifterPackagerError> {
    let compiler = SleighCompiler::new().map_err(LifterPackagerError::SleighCompilerSpawn)?;
    let slaspec = expected_sla.with_extension("");
    compiler
        .build_with(&slaspec, output_sla)
        .map_err(|source| LifterPackagerError::sleigh_compile(language, source))?;
    Ok(())
}

fn sibling_patches_dir(specs: &Path) -> Option<PathBuf> {
    let candidate = specs.parent()?.join("patches");
    if candidate.is_dir() {
        Some(candidate)
    } else {
        None
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

pub fn pack_blob(
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

    if output.exists() {
        return Err(LifterPackagerError::output_exists(output));
    }

    let blob = compile_and_build_blob(specs, language)?;
    let bytes = rkyv::to_bytes::<RkyvError>(&blob).map_err(LifterPackagerError::Rkyv)?;

    let output_file = File::create(output)
        .map_err(|source| LifterPackagerError::io("create file", output, source))?;
    let mut writer = GzEncoder::new(BufWriter::new(output_file), Default::default());

    writer
        .write_all(&bytes)
        .map_err(|source| LifterPackagerError::io("write file", output, source))?;
    writer
        .finish()
        .map_err(|source| LifterPackagerError::io("finalise file", output, source))?;

    Ok(())
}

pub fn unpack_blob(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<(), LifterPackagerError> {
    let input = input.as_ref();
    let output = output.as_ref();

    if !input.exists() {
        return Err(LifterPackagerError::missing_path("input file", input));
    }

    if output.exists() {
        return Err(LifterPackagerError::OutputExists {
            path: output.to_path_buf(),
        });
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
    variants: &[&str],
) -> Result<(), LifterPackagerError> {
    let specs = specs.as_ref();
    let output = output.as_ref();

    if !specs.exists() || !specs.is_dir() {
        return Err(LifterPackagerError::invalid_path(
            "language specification directory",
            specs,
        ));
    }

    let mut options = fugue_lifter_codegen::BuildOptions {
        pretty: true,
        ..Default::default()
    };
    if let Some(patches_dir) = sibling_patches_dir(specs) {
        options.add_patch(patches_dir);
    }
    options.add_variants(variants.iter().copied());

    let lifter = fugue_lifter_codegen::build_with(specs, language, options)?;
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
