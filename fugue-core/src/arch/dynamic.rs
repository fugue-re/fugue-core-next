use std::env;
use std::path::{Path, PathBuf};

use fugue_lifter::runtime::Language;

use crate::arch::LanguageError;

const ENV_VAR: &str = "FUGUE_LIFTERS_DIR";
const HOME_SUBDIR: &str = ".fugue/lifters";

fn filename_for(processor: &str, is_le: bool, bits: u32, variant: Option<&str>) -> String {
    let endian = if is_le { "LE" } else { "BE" };
    let variant = variant.unwrap_or("default");
    format!("{processor}_{endian}_{bits}_{variant}.flift")
}

fn search_dirs() -> impl Iterator<Item = PathBuf> {
    let from_env = env::var_os(ENV_VAR).map(PathBuf::from);
    let from_home = env::var_os("HOME").map(|h| PathBuf::from(h).join(HOME_SUBDIR));
    from_env.into_iter().chain(from_home)
}

fn locate(processor: &str, is_le: bool, bits: u32, variant: Option<&str>) -> Option<PathBuf> {
    let name = filename_for(processor, is_le, bits, variant);
    search_dirs().map(|d| d.join(&name)).find(|p| p.is_file())
}

pub fn load(
    processor: &str,
    is_le: bool,
    bits: u32,
    variant: Option<&str>,
) -> Result<&'static Language, LanguageError> {
    let path = locate(processor, is_le, bits, variant).ok_or(LanguageError::Unsupported)?;
    Ok(Language::from_file(path)?)
}

pub fn load_from(path: impl AsRef<Path>) -> Result<&'static Language, LanguageError> {
    Ok(Language::from_file(path)?)
}
