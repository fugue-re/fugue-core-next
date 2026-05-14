use crate::lifter::{LanguageId, LanguageVariant};
use crate::loader::LoaderError;

#[cfg(not(feature = "dynamic"))]
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
        language.variant().unwrap_or("default"),
    )
}

#[cfg(feature = "dynamic")]
pub(crate) fn resolve_variant(
    processor: &str,
    is_big: bool,
    bits: u32,
    variant: &str,
) -> Result<LanguageVariant, LoaderError> {
    if !is_known_variant(processor, bits, variant) {
        return Err(LoaderError::UnsupportedArch);
    }
    let builder = crate::arch::dynamic_loader::load(processor, is_big, bits, variant)
        .map_err(LoaderError::other)?;
    let language = builder.language();
    Ok(LanguageVariant::new(language.variant(), language))
}

#[cfg(feature = "dynamic")]
fn is_known_variant(processor: &str, bits: u32, variant: &str) -> bool {
    matches!(
        (processor, bits, variant),
        ("ARM", 32, "v8" | "v8T")
            | ("AARCH64", 64, "v8A")
            | ("x86", 32, "default")
            | ("x86", 64, "default" | "compat32"),
    )
}

#[cfg(not(feature = "dynamic"))]
pub(crate) fn resolve_variant(
    processor: &str,
    is_big: bool,
    bits: u32,
    variant: &str,
) -> Result<LanguageVariant, LoaderError> {
    let is_le = !is_big;
    let variant_opt = if variant == "default" {
        None
    } else {
        Some(variant)
    };
    match (processor, bits) {
        ("ARM", 32) => parse_arm(is_le, variant_opt),
        ("AARCH64", 64) => parse_aarch64(is_le, variant_opt),
        ("x86", 32) => parse_x86(variant_opt),
        ("x86", 64) => parse_x86_64(variant_opt),
        _ => Err(LoaderError::UnsupportedArch),
    }
}

#[cfg(not(feature = "dynamic"))]
fn parse_arm(is_le: bool, variant: Option<&str>) -> Result<LanguageVariant, LoaderError> {
    let language = match variant {
        None | Some("v8") => {
            if is_le {
                arch::arm::le::variants::V8
            } else {
                arch::arm::be::variants::V8
            }
        }
        Some("v8T") => {
            if is_le {
                arch::arm::le::variants::V8T
            } else {
                arch::arm::be::variants::V8T
            }
        }
        _ => return Err(LoaderError::UnsupportedArch),
    };

    Ok(language)
}

#[cfg(not(feature = "dynamic"))]
fn parse_aarch64(is_le: bool, variant: Option<&str>) -> Result<LanguageVariant, LoaderError> {
    let language = match variant {
        None | Some("v8A") => {
            if is_le {
                arch::aarch64::le::variants::V8A
            } else {
                arch::aarch64::be::variants::V8A
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
