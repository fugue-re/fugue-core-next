use std::path::{Path, PathBuf};

use fugue_lifter_runtime::dynamic::{BuildError as RuntimeBuildError, Language as DynamicLanguage};
use fugue_sleighc::SleighCompiler;

use crate::build::BuildError;

pub(crate) struct LanguageSpec<'a> {
    path: &'a Path,
    language: &'a str,
}

impl<'a> LanguageSpec<'a> {
    pub(crate) fn new(path: &'a Path, language: &'a str) -> Result<Self, BuildError> {
        if !path.exists() || !path.is_dir() {
            return Err(BuildError::invalid_path(
                "language specification directory",
                path,
            ));
        }
        Ok(Self { path, language })
    }

    pub(crate) fn build_dynamic(&self) -> Result<DynamicLanguage, BuildError> {
        match DynamicLanguage::build(self.path, self.language) {
            Ok(language) => Ok(language),
            Err(RuntimeBuildError::SleighSlaMissing { path, .. }) => {
                let scratch = tempfile::tempdir()
                    .map_err(|source| BuildError::io("create scratch dir", &path, source))?;
                let scratch_sla = scratch.path().join(
                    path.file_name()
                        .expect("missing sla path has a file name component"),
                );
                let slaspec = path.with_extension("");
                self.compile(&slaspec, &scratch_sla)?;
                Ok(DynamicLanguage::build_with_sla(
                    self.path,
                    self.language,
                    &scratch_sla,
                )?)
            }
            Err(other) => Err(other.into()),
        }
    }

    pub(crate) fn build_static(&self, variants: &[&str]) -> Result<String, BuildError> {
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

    pub(crate) fn compile(&self, slaspec: &Path, output_sla: &Path) -> Result<(), BuildError> {
        let compiler = SleighCompiler::new().map_err(BuildError::SleighCompilerSpawn)?;
        compiler
            .build_with(slaspec, output_sla)
            .map_err(|source| BuildError::sleigh_compile(self.language, source))?;
        Ok(())
    }

    fn patches_dir(&self) -> Option<PathBuf> {
        let candidate = self.path.parent()?.join("patches");
        candidate.is_dir().then_some(candidate)
    }
}
