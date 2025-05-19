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
        "ARM" if is_le && bits == 32 => crate::lifter::arm::le::variants::DEFAULT,
        "ARM" if bits == 32 => crate::lifter::arm::be::variants::DEFAULT,
        "AARCH64" if is_le && bits == 64 => crate::lifter::aarch64::le::variants::DEFAULT,
        "AARCH64" if bits == 64 => crate::lifter::aarch64::be::variants::DEFAULT,
        "x86" if bits == 32 => crate::lifter::x86::variants::DEFAULT,
        "x86" if bits == 64 => crate::lifter::x86_64::variants::DEFAULT,
        _ => return Err(LoaderError::UnsupportedArch),
    };

    Ok(language)
}
