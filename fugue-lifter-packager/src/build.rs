use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use flate2::write::GzEncoder;
use fugue_lifter_codegen::CodegenError;
use fugue_lifter_runtime::dynamic::blob::language::Language as LanguageBlob;
use fugue_lifter_runtime::dynamic::build::{
    self as runtime_build, BuildError as RuntimeBuildError,
};
use fugue_sleighc::{SleighCompiler, SleighCompilerError};
use rkyv::rancor::Error as RkyvError;
use thiserror::Error;

use crate::Packager;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("cannot build dynamic blob: {0}")]
    Build(#[from] RuntimeBuildError),
    #[error("cannot generate lifter: {0}")]
    GenerateLifter(#[from] CodegenError),
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

impl BuildError {
    fn invalid_path(kind: &'static str, path: impl AsRef<Path>) -> Self {
        Self::InvalidPath {
            kind,
            path: path.as_ref().to_path_buf(),
        }
    }

    fn io(action: &'static str, path: impl AsRef<Path>, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.as_ref().to_path_buf(),
            source,
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

impl Packager {
    pub fn pack_blob(
        &self,
        specs: impl AsRef<Path>,
        language: &str,
        output: impl AsRef<Path>,
    ) -> Result<(), BuildError> {
        let specs = Specs::new(specs.as_ref(), language)?;
        let output = output.as_ref();
        if output.exists() {
            return Err(BuildError::output_exists(output));
        }

        let blob = specs.build_blob()?;
        let bytes = rkyv::to_bytes::<RkyvError>(&blob).map_err(BuildError::Rkyv)?;
        GzippedOutput::new(output).write(&bytes)
    }

    pub fn pack_lifter(
        &self,
        specs: impl AsRef<Path>,
        language: &str,
        output: impl AsRef<Path>,
        variants: &[&str],
    ) -> Result<(), BuildError> {
        let specs = Specs::new(specs.as_ref(), language)?;
        let lifter = specs.build_lifter(variants)?;
        GzippedOutput::new(output.as_ref()).write(lifter.as_bytes())
    }
}

struct Specs<'a> {
    path: &'a Path,
    language: &'a str,
}

impl<'a> Specs<'a> {
    fn new(path: &'a Path, language: &'a str) -> Result<Self, BuildError> {
        if !path.exists() || !path.is_dir() {
            return Err(BuildError::invalid_path(
                "language specification directory",
                path,
            ));
        }
        Ok(Self { path, language })
    }

    fn build_blob(&self) -> Result<LanguageBlob, BuildError> {
        match runtime_build::build(self.path, self.language) {
            Ok(blob) => Ok(blob),
            Err(RuntimeBuildError::SleighSlaMissing { path, .. }) => {
                let scratch = tempfile::tempdir()
                    .map_err(|source| BuildError::io("create scratch dir", &path, source))?;
                let scratch_sla = scratch.path().join(
                    path.file_name()
                        .expect("missing sla path has a file name component"),
                );
                self.compile_sla(&path, &scratch_sla)?;
                Ok(runtime_build::build_with_sla(
                    self.path,
                    self.language,
                    &scratch_sla,
                )?)
            }
            Err(other) => Err(other.into()),
        }
    }

    fn build_lifter(&self, variants: &[&str]) -> Result<String, BuildError> {
        let mut options = fugue_lifter_codegen::BuildOptions {
            pretty: true,
            ..Default::default()
        };
        if let Some(patches_dir) = self.patches_dir() {
            options.add_patch(patches_dir);
        }
        options.add_variants(variants.iter().copied());

        Ok(fugue_lifter_codegen::build_with(
            self.path,
            self.language,
            options,
        )?)
    }

    fn compile_sla(&self, expected_sla: &Path, output_sla: &Path) -> Result<(), BuildError> {
        let compiler = SleighCompiler::new().map_err(BuildError::SleighCompilerSpawn)?;
        let slaspec = expected_sla.with_extension("");
        compiler
            .build_with(&slaspec, output_sla)
            .map_err(|source| BuildError::sleigh_compile(self.language, source))?;
        Ok(())
    }

    fn patches_dir(&self) -> Option<PathBuf> {
        let candidate = self.path.parent()?.join("patches");
        candidate.is_dir().then_some(candidate)
    }
}

struct GzippedOutput<'a> {
    path: &'a Path,
}

impl<'a> GzippedOutput<'a> {
    fn new(path: &'a Path) -> Self {
        Self { path }
    }

    fn write(&self, bytes: &[u8]) -> Result<(), BuildError> {
        let file = File::create(self.path)
            .map_err(|source| BuildError::io("create file", self.path, source))?;
        let mut writer = GzEncoder::new(BufWriter::new(file), Default::default());
        writer
            .write_all(bytes)
            .map_err(|source| BuildError::io("write file", self.path, source))?;
        writer
            .finish()
            .map_err(|source| BuildError::io("finalise file", self.path, source))?;
        Ok(())
    }
}
