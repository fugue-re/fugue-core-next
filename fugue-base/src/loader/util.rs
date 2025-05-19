use crate::lifter::{Language, LanguageId};
use crate::loader::LoaderError;

pub fn parse_language(language: impl AsRef<str>) -> Result<&'static Language, LoaderError> {
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
        "ARM" if is_le && bits == 32 => crate::lifter::arm::le::LANGUAGE,
        "ARM" if bits == 32 => crate::lifter::arm::be::LANGUAGE,
        "AARCH64" if is_le && bits == 64 => crate::lifter::aarch64::le::LANGUAGE,
        "AARCH64" if bits == 64 => crate::lifter::aarch64::be::LANGUAGE,
        "x86" if bits == 32 => crate::lifter::x86::LANGUAGE,
        "x86" if bits == 64 => crate::lifter::x86_64::LANGUAGE,
        _ => return Err(LoaderError::UnsupportedArch),
    };

    Ok(language)
}
