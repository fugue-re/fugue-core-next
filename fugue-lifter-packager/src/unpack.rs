use std::fs::File;
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use thiserror::Error;

use crate::Packager;

#[derive(Debug, Error)]
pub enum UnpackError {
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
}

impl UnpackError {
    fn missing_path(kind: &'static str, path: impl AsRef<Path>) -> Self {
        Self::MissingPath {
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
}

impl Packager {
    pub fn unpack_dynamic(
        &self,
        input: impl AsRef<Path>,
        output: impl AsRef<Path>,
    ) -> Result<(), UnpackError> {
        let output = output.as_ref();
        if output.exists() {
            return Err(UnpackError::OutputExists {
                path: output.to_path_buf(),
            });
        }
        self.decompress(input.as_ref(), output)
    }

    pub fn unpack_static(
        &self,
        input: impl AsRef<Path>,
        output: impl AsRef<Path>,
    ) -> Result<(), UnpackError> {
        self.decompress(input.as_ref(), output.as_ref())
    }

    fn decompress(&self, input: &Path, output: &Path) -> Result<(), UnpackError> {
        if !input.exists() {
            return Err(UnpackError::missing_path("input file", input));
        }

        let input_file =
            File::open(input).map_err(|source| UnpackError::io("read file", input, source))?;
        let output_file = File::create(output)
            .map_err(|source| UnpackError::io("create file", output, source))?;

        let mut deflated = GzDecoder::new(input_file);
        let mut writer = BufWriter::new(output_file);
        io::copy(&mut deflated, &mut writer)
            .map_err(|source| UnpackError::io("write file", output, source))?;

        Ok(())
    }
}
