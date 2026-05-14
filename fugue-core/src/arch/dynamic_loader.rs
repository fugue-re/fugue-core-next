use std::env;
use std::path::{Path, PathBuf};

use fugue_lifter::runtime::Language;
use fugue_lifter::runtime::dynamic::LanguageLoadError;
use thiserror::Error;

const ENV_VAR: &str = "FUGUE_LIFTERS_DIR";
const HOME_SUBDIR: &str = ".fugue/lifters";

#[derive(Debug, Error)]
pub enum DynamicLoadError {
    #[error("no lifter blob `{filename}` found in $FUGUE_LIFTERS_DIR or ~/{HOME_SUBDIR}")]
    NotFound { filename: String },
    #[error(transparent)]
    Load(#[from] LanguageLoadError),
}

fn filename_for(processor: &str, is_big: bool, bits: u32, variant: Option<&str>) -> String {
    let endian = if is_big { "BE" } else { "LE" };
    let variant = variant.unwrap_or("default");
    format!("{processor}_{endian}_{bits}_{variant}.flift")
}

fn search_dirs() -> impl Iterator<Item = PathBuf> {
    let from_env = env::var_os(ENV_VAR).map(PathBuf::from);
    let from_home = env::var_os("HOME").map(|h| PathBuf::from(h).join(HOME_SUBDIR));
    from_env.into_iter().chain(from_home)
}

pub fn locate(processor: &str, is_big: bool, bits: u32, variant: Option<&str>) -> Option<PathBuf> {
    let name = filename_for(processor, is_big, bits, variant);
    search_dirs().map(|d| d.join(&name)).find(|p| p.is_file())
}

pub fn load(
    processor: &str,
    is_big: bool,
    bits: u32,
    variant: Option<&str>,
) -> Result<&'static Language, DynamicLoadError> {
    let path = locate(processor, is_big, bits, variant).ok_or_else(|| DynamicLoadError::NotFound {
        filename: filename_for(processor, is_big, bits, variant),
    })?;
    Ok(Language::from_file(path)?)
}

pub fn load_from(path: impl AsRef<Path>) -> Result<&'static Language, DynamicLoadError> {
    Ok(Language::from_file(path)?)
}
