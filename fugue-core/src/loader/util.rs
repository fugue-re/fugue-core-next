use crate::lifter::{LanguageId, LanguageVariant};
use crate::loader::LoaderError;

use crate::arch;

pub fn parse_language(language: impl AsRef<str>) -> Result<LanguageVariant, LoaderError> {
    let language = language
        .as_ref()
        .parse::<LanguageId>()
        .map_err(LoaderError::other)?;

    resolve_variant(
        language.processor(),
        language.is_big_endian(),
        language.bits(),
        language.variant(),
    )
}

#[cfg(feature = "dynamic")]
pub(crate) fn resolve_variant<'a>(
    processor: &str,
    is_be: bool,
    bits: u32,
    variant: impl Into<Option<&'a str>>,
) -> Result<LanguageVariant, LoaderError> {
    let variant = variant.into();
    let language =
        arch::dynamic_loader::load(processor, is_be, bits, variant).map_err(LoaderError::other)?;
    Ok(LanguageVariant::new(language.variant(), language))
}

#[cfg(not(feature = "dynamic"))]
pub(crate) fn resolve_variant<'a>(
    processor: &str,
    is_be: bool,
    bits: u32,
    variant: impl Into<Option<&'a str>>,
) -> Result<LanguageVariant, LoaderError> {
    let variant = variant.into();
    match (processor, bits) {
        ("ARM", 32) => parse_arm(is_be, variant),
        ("AARCH64", 64) => parse_aarch64(is_be, variant),
        ("x86", 32) => parse_x86(variant),
        ("x86", 64) => parse_x86_64(variant),
        _ => Err(LoaderError::UnsupportedArch),
    }
}

#[cfg(not(feature = "dynamic"))]
fn parse_arm(is_be: bool, variant: Option<&str>) -> Result<LanguageVariant, LoaderError> {
    let language = match variant {
        None | Some("v8") => {
            if is_be {
                arch::arm::be::variants::V8
            } else {
                arch::arm::le::variants::V8
            }
        }
        Some("v8T") => {
            if is_be {
                arch::arm::be::variants::V8T
            } else {
                arch::arm::le::variants::V8T
            }
        }
        _ => return Err(LoaderError::UnsupportedArch),
    };

    Ok(language)
}

#[cfg(not(feature = "dynamic"))]
fn parse_aarch64(is_be: bool, variant: Option<&str>) -> Result<LanguageVariant, LoaderError> {
    let language = match variant {
        None | Some("v8A") => {
            if is_be {
                arch::aarch64::be::variants::V8A
            } else {
                arch::aarch64::le::variants::V8A
            }
        }
        _ => return Err(LoaderError::UnsupportedArch),
    };

    Ok(language)
}

#[cfg(not(feature = "dynamic"))]
fn parse_x86(variant: Option<&str>) -> Result<LanguageVariant, LoaderError> {
    let language = match variant {
        None | Some("default") => arch::x86::variants::DEFAULT,
        _ => return Err(LoaderError::UnsupportedArch),
    };

    Ok(language)
}

#[cfg(not(feature = "dynamic"))]
fn parse_x86_64(variant: Option<&str>) -> Result<LanguageVariant, LoaderError> {
    let language = match variant {
        None | Some("default") => arch::x86_64::variants::DEFAULT,
        Some("compat32") => arch::x86_64::variants::COMPAT32,
        _ => return Err(LoaderError::UnsupportedArch),
    };

    Ok(language)
}
