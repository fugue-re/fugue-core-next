use std::borrow::Cow;
use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;

use fugue_arch::ArchitectureDef;
use fugue_sleigh_language::{Language, LanguageDB};
#[cfg(feature = "bundled-compiler")]
use fugue_sleighc::{SleighCompiler, SleighCompilerError};
use proc_macro2::TokenStream;
use quote::ToTokens;
use thiserror::Error;

pub mod core;
pub mod error;
pub mod patcher;
pub mod types;

pub use self::core::LifterGenerator;
pub use self::error::LifterGeneratorError;
pub use self::patcher::{PatchSet, PatcherError};

#[derive(Debug, Error)]
pub enum CodegenError {
    #[error("cannot format generated lifter: {0:#?}")]
    Format(anyhow::Error),
    #[error("cannot generate lifter: {0}")]
    Generate(LifterGeneratorError),
    #[error("cannot locate language `{0}` in language database")]
    Language(String),
    #[error("cannot build language for `{0}`: {1}")]
    LanguageBuild(String, anyhow::Error),
    #[cfg(feature = "bundled-compiler")]
    #[error("cannot compile language: {0}")]
    LanguageCompile(#[from] SleighCompilerError),
    #[error("cannot load/locate language database: {0}")]
    LanguageDB(anyhow::Error),
    #[error("cannot apply language patches: {0}")]
    Patcher(#[from] PatcherError),
    #[error("variant `{variant}` has .sla `{actual}`, expected `{expected}`")]
    VariantSlaMismatch {
        variant: String,
        expected: PathBuf,
        actual: PathBuf,
    },
}

impl CodegenError {
    fn format<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        CodegenError::Format(anyhow::Error::new(err))
    }

    fn format_with<M>(msg: M) -> Self
    where
        M: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    {
        CodegenError::Format(anyhow::Error::msg(msg))
    }

    fn variant_sla_mismatch(
        variant: impl Into<String>,
        expected: PathBuf,
        actual: PathBuf,
    ) -> Self {
        CodegenError::VariantSlaMismatch {
            variant: variant.into(),
            expected,
            actual,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BuildOptions {
    pub pretty: bool,
    pub patches: Vec<PathBuf>,
    pub variants: Vec<String>,
}

impl BuildOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_pretty(&mut self, pretty: bool) -> &mut Self {
        self.pretty = pretty;
        self
    }

    pub fn with_pretty(mut self, pretty: bool) -> Self {
        self.set_pretty(pretty);
        self
    }

    pub fn add_patch(&mut self, dir: impl Into<PathBuf>) -> &mut Self {
        self.patches.push(dir.into());
        self
    }

    pub fn add_patches<I, P>(&mut self, dirs: I) -> &mut Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.patches.extend(dirs.into_iter().map(Into::into));
        self
    }

    pub fn with_patch(mut self, dir: impl Into<PathBuf>) -> Self {
        self.add_patch(dir);
        self
    }

    pub fn with_patches<I, P>(mut self, dirs: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.add_patches(dirs);
        self
    }

    pub fn add_variant(&mut self, variant: impl Into<String>) -> &mut Self {
        self.variants.push(variant.into());
        self
    }

    pub fn add_variants<I, V>(&mut self, variants: I) -> &mut Self
    where
        I: IntoIterator<Item = V>,
        V: Into<String>,
    {
        self.variants.extend(variants.into_iter().map(Into::into));
        self
    }

    pub fn with_variant(mut self, variant: impl Into<String>) -> Self {
        self.add_variant(variant);
        self
    }

    pub fn with_variants<I, V>(mut self, variants: I) -> Self
    where
        I: IntoIterator<Item = V>,
        V: Into<String>,
    {
        self.add_variants(variants);
        self
    }
}

pub fn from_language(
    language: &Language,
    primary: VariantData,
    extras: Vec<VariantData>,
) -> Result<TokenStream, LifterGeneratorError> {
    LifterGenerator::new(language, primary, extras).map(ToTokens::into_token_stream)
}

#[derive(Clone, Debug)]
pub struct VariantData {
    pub name: String,
    pub context_defaults: Vec<(String, u32)>,
}

impl VariantData {
    pub fn new(name: impl Into<String>, context_defaults: Vec<(String, u32)>) -> Self {
        Self {
            name: name.into(),
            context_defaults,
        }
    }
}

pub fn build(root: impl AsRef<Path>, language: impl AsRef<str>) -> Result<String, CodegenError> {
    build_with(root, language, BuildOptions::new())
}

fn out_or_temp_dir() -> PathBuf {
    if let Ok(out_dir) = env::var("OUT_DIR") {
        PathBuf::from(out_dir)
    } else {
        env::temp_dir()
    }
}

fn load_patch_set(dirs: &[PathBuf]) -> Result<PatchSet, PatcherError> {
    let mut combined = PatchSet::new();
    for dir in dirs {
        let set = PatchSet::load_dir(dir)?;
        combined.extend(set);
    }
    Ok(combined)
}

fn patched_root_dir(language_def: &str) -> PathBuf {
    let mut sanitised = String::with_capacity(language_def.len());
    for ch in language_def.chars() {
        if ch.is_ascii_alphanumeric() {
            sanitised.push(ch);
        } else {
            sanitised.push('_');
        }
    }
    out_or_temp_dir().join(format!("patched-processors-{sanitised}"))
}

pub fn build_with(
    root: impl AsRef<Path>,
    language: impl AsRef<str>,
    options: BuildOptions,
) -> Result<String, CodegenError> {
    let root = root.as_ref();
    let language_def = language.as_ref();

    let patches = load_patch_set(&options.patches)?;
    let effective_root = if patches.is_empty() {
        Cow::Borrowed(root)
    } else {
        let dst = patched_root_dir(language_def);
        Cow::Owned(patcher::materialise(root, &dst, &patches)?)
    };

    let builder = LanguageDB::from_directory_with(effective_root, true)
        .map_err(|e| CodegenError::LanguageDB(e.into()))?;

    let primary_def = builder
        .lookup_str(language_def)
        .ok()
        .flatten()
        .ok_or_else(|| CodegenError::Language(language_def.to_owned()))?;

    let primary_arch = ArchitectureDef::from_str(language_def)
        .map_err(|err| CodegenError::Language(format!("{language_def}: {err}")))?;

    let primary_context_defaults = primary_def
        .language()
        .context_set()
        .map(|(name, value)| (name.to_owned(), value))
        .collect::<Vec<(String, u32)>>();
    let primary_sla = primary_def.language().sla_file().to_path_buf();
    let primary_variant = VariantData::new(primary_arch.variant(), primary_context_defaults);

    let mut extra_variants = Vec::with_capacity(options.variants.len());
    for variant in &options.variants {
        let extra_id = format!(
            "{}:{}:{}:{}",
            primary_arch.processor(),
            if primary_arch.endian().is_big() {
                "BE"
            } else {
                "LE"
            },
            primary_arch.bits(),
            variant
        );
        let extra_def = builder
            .lookup_str(&extra_id)
            .ok()
            .flatten()
            .ok_or_else(|| CodegenError::Language(extra_id.clone()))?;
        let extra_sla = extra_def.language().sla_file();
        if extra_sla != primary_sla {
            return Err(CodegenError::variant_sla_mismatch(
                variant,
                primary_sla.clone(),
                extra_sla.to_path_buf(),
            ));
        }
        let extra_context_defaults = extra_def
            .language()
            .context_set()
            .map(|(name, value)| (name.to_owned(), value))
            .collect::<Vec<(String, u32)>>();
        extra_variants.push(VariantData::new(variant.clone(), extra_context_defaults));
    }

    let sla_file = primary_def.language().sla_file();

    let language = if sla_file.exists() {
        primary_def.build()
    } else {
        #[cfg(not(feature = "bundled-compiler"))]
        return Err(CodegenError::LanguageBuild(
            language_def.to_owned(),
            anyhow::msg!("no compiler available"),
        ));
        #[cfg(feature = "bundled-compiler")]
        {
            let slaf = out_or_temp_dir().join(sla_file.file_name().expect("sla file name"));
            let spec = sla_file.with_extension("");
            let slac = SleighCompiler::new()?
                .build_with(spec, slaf)?
                .expect("compiled sla file name");
            primary_def.build_with_sla(slac)
        }
    };

    let language =
        language.map_err(|e| CodegenError::LanguageBuild(language_def.to_owned(), e.into()))?;

    let tokens = from_language(&language, primary_variant, extra_variants)
        .map_err(CodegenError::Generate)?;

    if options.pretty {
        let mut child = Command::new("rustfmt")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(CodegenError::format)?;

        let stdin = child.stdin.as_mut().expect("stdin available");

        write!(stdin, "{tokens}").map_err(CodegenError::format)?;

        let output = child
            .wait_with_output()
            .map_err(|e| CodegenError::Format(e.into()))?;

        if !output.status.success() {
            return Err(CodegenError::format_with(format!(
                "rustfmt exited with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        String::from_utf8(output.stdout).map_err(CodegenError::format)
    } else {
        Ok(tokens.to_string())
    }
}
