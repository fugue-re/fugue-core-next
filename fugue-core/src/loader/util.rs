use crate::arch;
use crate::lifter::{LanguageId, LanguageVariant};
use crate::loader::LoaderError;

pub fn parse_language(language: impl AsRef<str>) -> Result<LanguageVariant, LoaderError> {
    let language = language
        .as_ref()
        .parse::<LanguageId>()
        .map_err(LoaderError::other)?;
    let bits = language.bits();

    if bits != 32 && bits != 64 {
        return Err(LoaderError::UnsupportedArch);
    }

    let is_le = language.is_little_endian();

    let language = match language.processor() {
        "ARM" if bits == 32 => parse_arm(is_le, language.variant())?,
        "AARCH64" if bits == 64 => parse_aarch64(is_le, language.variant())?,
        "MIPS" if bits == 32 => parse_mips(is_le, language.variant())?,
        "x86" if bits == 32 => parse_x86(language.variant())?,
        "x86" if bits == 64 => parse_x86_64(language.variant())?,
        _ => return Err(LoaderError::UnsupportedArch),
    };

    Ok(language)
}

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

fn parse_mips(is_le: bool, variant: Option<&str>) -> Result<LanguageVariant, LoaderError> {
    let language = match variant {
        None | Some("default") => {
            if is_le {
                arch::mips::le::variants::DEFAULT
            } else {
                arch::mips::be::variants::DEFAULT
            }
        }
        _ => return Err(LoaderError::UnsupportedArch),
    };

    Ok(language)
}

fn parse_x86(variant: Option<&str>) -> Result<LanguageVariant, LoaderError> {
    let language = match variant {
        None | Some("default") => arch::x86::variants::DEFAULT,
        _ => return Err(LoaderError::UnsupportedArch),
    };

    Ok(language)
}

fn parse_x86_64(variant: Option<&str>) -> Result<LanguageVariant, LoaderError> {
    let language = match variant {
        None | Some("default") => arch::x86_64::variants::DEFAULT,
        Some("compat32") => arch::x86_64::variants::COMPAT32,
        _ => return Err(LoaderError::UnsupportedArch),
    };

    Ok(language)
}
