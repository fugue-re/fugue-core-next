use std::str::FromStr;

use fugue_bytes::Endian;
use thiserror::Error;

use crate::runtime::language::LanguageParseError;
use crate::runtime::{LanguageId, Lifter};

pub struct LifterBuilder {
    processor: String,
    bits: Option<u32>,
    is_big: bool,
    variant: Option<String>,
}

#[derive(Debug, Error)]
pub enum LifterBuilderError {
    #[error("could not parse processor name")]
    ParseProcessor,
    #[error("invalid language bits; must be: 8, 16, 32, or 64")]
    ParseBits,
    #[error("invalid endian; must be BE or LE")]
    ParseEndian,
    #[error("could not parse processor variant")]
    ParseVariant,
    #[error("invalid language format")]
    ParseFormat,
    #[error("unsupported architecture")]
    Unsupported,
}

impl From<LanguageParseError> for LifterBuilderError {
    fn from(e: LanguageParseError) -> Self {
        match e {
            LanguageParseError::ParseBits => Self::ParseBits,
            LanguageParseError::ParseEndian => Self::ParseEndian,
            LanguageParseError::ParseProcessor => Self::ParseProcessor,
            LanguageParseError::ParseVariant => Self::ParseVariant,
            LanguageParseError::ParseFormat => Self::ParseFormat,
        }
    }
}

impl FromStr for LifterBuilder {
    type Err = LifterBuilderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let language = LanguageId::from_str(s)?;

        Ok(Self {
            processor: language.processor().to_owned(),
            is_big: language.is_big_endian(),
            bits: Some(language.bits()),
            variant: language.variant().map(ToOwned::to_owned),
        })
    }
}

impl LifterBuilder {
    pub fn new(processor: impl Into<String>) -> Self {
        Self {
            processor: processor.into(),
            bits: None,
            is_big: false,
            variant: None,
        }
    }

    pub fn set_bits(&mut self, bits: u32) {
        self.bits = Some(bits);
    }

    pub fn bits(mut self, bits: u32) -> Self {
        self.set_bits(bits);
        self
    }

    pub fn big_endian(mut self) -> Self {
        self.is_big = true;
        self
    }

    pub fn little_endian(mut self) -> Self {
        self.is_big = false;
        self
    }

    pub fn set_endian(&mut self, endian: Endian) {
        self.is_big = endian.is_big();
    }

    pub fn endian(mut self, endian: Endian) -> Self {
        self.set_endian(endian);
        self
    }

    pub fn set_variant(&mut self, variant: impl Into<String>) {
        self.variant = Some(variant.into());
    }

    pub fn variant(mut self, variant: impl Into<String>) -> Self {
        self.set_variant(variant);
        self
    }

    pub fn build_str(language: impl AsRef<str>) -> Result<Lifter, LifterBuilderError> {
        language.as_ref().parse::<Self>()?.build()
    }

    pub fn build(&self) -> Result<Lifter, LifterBuilderError> {
        match (
            self.processor.as_ref() as &str,
            self.is_big,
            self.bits,
            self.variant.as_deref() as Option<&str>,
        ) {
            #[cfg(feature = "x86")]
            ("x86", false, Some(32), None | Some("default")) => {
                Ok(crate::x86::LifterFactory::new_default())
            }
            #[cfg(feature = "x86-64")]
            ("x86", false, Some(64), None | Some("default")) => {
                Ok(crate::x86_64::LifterFactory::new_default())
            }
            #[cfg(feature = "x86-64")]
            ("x86", false, Some(64), Some("compat32")) => {
                Ok(crate::x86_64::LifterFactory::new_compat32())
            }
            #[cfg(feature = "arm-be")]
            ("ARM", true, None | Some(32), variant) => match variant {
                None | Some("v8") => Ok(crate::arm::be::LifterFactory::new_v8()),
                Some("v8T") => Ok(crate::arm::be::LifterFactory::new_v8t()),
                _ => Err(LifterBuilderError::Unsupported),
            },
            #[cfg(feature = "arm-le")]
            ("ARM", false, None | Some(32), variant) => match variant {
                None | Some("v8") => Ok(crate::arm::le::LifterFactory::new_v8()),
                Some("v8T") => Ok(crate::arm::le::LifterFactory::new_v8t()),
                _ => Err(LifterBuilderError::Unsupported),
            },
            #[cfg(feature = "aarch64-be")]
            ("AARCH64", true, None | Some(64), None | Some("v8A")) => {
                Ok(crate::aarch64::be::LifterFactory::new_v8a())
            }
            #[cfg(feature = "aarch64-le")]
            ("AARCH64", false, None | Some(64), None | Some("v8A")) => {
                Ok(crate::aarch64::le::LifterFactory::new_v8a())
            }
            #[cfg(feature = "mips-be")]
            ("MIPS", true, None | Some(32), None | Some("default")) => {
                Ok(crate::mips::be::LifterFactory::new_default())
            }
            #[cfg(feature = "mips-le")]
            ("MIPS", false, None | Some(32), None | Some("default")) => {
                Ok(crate::mips::le::LifterFactory::new_default())
            }
            #[cfg(feature = "mips64-be")]
            ("MIPS", true, Some(64), variant) => match variant {
                None | Some("default") => Ok(crate::mips64::be::LifterFactory::new_default()),
                Some("64-32addr") => Ok(crate::mips64::be::LifterFactory::new_64_32addr()),
                _ => Err(LifterBuilderError::Unsupported),
            },
            #[cfg(feature = "mips64-le")]
            ("MIPS", false, Some(64), variant) => match variant {
                None | Some("default") => Ok(crate::mips64::le::LifterFactory::new_default()),
                Some("64-32addr") => Ok(crate::mips64::le::LifterFactory::new_64_32addr()),
                _ => Err(LifterBuilderError::Unsupported),
            },
            #[cfg(feature = "ppc-be")]
            ("PowerPC", true, Some(32), None | Some("default")) => {
                Ok(crate::ppc::be::LifterFactory::new_default())
            }
            #[cfg(feature = "ppc-le")]
            ("PowerPC", false, Some(32), None | Some("default")) => {
                Ok(crate::ppc::le::LifterFactory::new_default())
            }
            #[cfg(feature = "ppc64-be")]
            ("PowerPC", true, Some(64), variant) => match variant {
                None | Some("default") => Ok(crate::ppc64::be::LifterFactory::new_default()),
                Some("64-32addr") => Ok(crate::ppc64::be::LifterFactory::new_64_32addr()),
                _ => Err(LifterBuilderError::Unsupported),
            },
            #[cfg(feature = "ppc64-le")]
            ("PowerPC", false, Some(64), variant) => match variant {
                None | Some("default") => Ok(crate::ppc64::le::LifterFactory::new_default()),
                Some("64-32addr") => Ok(crate::ppc64::le::LifterFactory::new_64_32addr()),
                _ => Err(LifterBuilderError::Unsupported),
            },
            #[cfg(feature = "riscv")]
            ("RISCV", false, Some(32), None | Some("default")) => {
                Ok(crate::riscv::LifterFactory::new_default())
            }
            #[cfg(feature = "riscv64")]
            ("RISCV", false, Some(64), None | Some("default")) => {
                Ok(crate::riscv64::LifterFactory::new_default())
            }
            _ => Err(LifterBuilderError::Unsupported),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_builder_defaults() -> Result<(), LifterBuilderError> {
        let _ = LifterBuilder::new("x86").bits(32).build()?;
        let _ = LifterBuilder::new("x86").bits(64).build()?;

        let _ = LifterBuilder::new("ARM").little_endian().build()?;
        let _ = LifterBuilder::new("ARM")
            .bits(32)
            .big_endian()
            .variant("v8T")
            .build()?;

        let _ = LifterBuilder::new("AARCH64").little_endian();
        let _ = LifterBuilder::new("AARCH64").big_endian().bits(64);
        let _ = LifterBuilder::new("AARCH64")
            .little_endian()
            .bits(64)
            .variant("v8A");

        Ok(())
    }

    #[test]
    fn test_from_str_defaults() -> Result<(), LifterBuilderError> {
        let _ = "x86:LE:32".parse::<LifterBuilder>()?.build()?;
        let _ = "x86:LE:32:default".parse::<LifterBuilder>()?.build()?;

        assert!("x86:LE".parse::<LifterBuilder>().is_err());
        assert!(
            "x86:BE:32:default"
                .parse::<LifterBuilder>()?
                .build()
                .is_err()
        );

        let _ = "x86:LE:64:default".parse::<LifterBuilder>()?.build()?;

        let _ = "ARM:BE:32".parse::<LifterBuilder>()?.build()?;
        let _ = "ARM:BE:32:v8".parse::<LifterBuilder>()?.build()?;
        let _ = "ARM:BE:32:v8T".parse::<LifterBuilder>()?.build()?;

        let _ = "ARM:LE:32".parse::<LifterBuilder>()?.build()?;
        let _ = "ARM:LE:32:v8".parse::<LifterBuilder>()?.build()?;
        let _ = "ARM:LE:32:v8T".parse::<LifterBuilder>()?.build()?;

        let _ = "AARCH64:BE:64".parse::<LifterBuilder>()?.build()?;
        let _ = "AARCH64:BE:64:v8A".parse::<LifterBuilder>()?.build()?;

        let _ = "AARCH64:LE:64".parse::<LifterBuilder>()?.build()?;
        let _ = "AARCH64:LE:64:v8A".parse::<LifterBuilder>()?.build()?;

        let _ = "MIPS:BE:64:default".parse::<LifterBuilder>()?.build()?;
        let _ = "MIPS:LE:64:64-32addr".parse::<LifterBuilder>()?.build()?;

        let _ = "PowerPC:BE:32:default".parse::<LifterBuilder>()?.build()?;
        let _ = "PowerPC:LE:32:default".parse::<LifterBuilder>()?.build()?;
        let _ = "PowerPC:BE:64:default".parse::<LifterBuilder>()?.build()?;
        let _ = "PowerPC:LE:64:64-32addr"
            .parse::<LifterBuilder>()?
            .build()?;

        let _ = "RISCV:LE:32:default".parse::<LifterBuilder>()?.build()?;
        let _ = "RISCV:LE:64:default".parse::<LifterBuilder>()?.build()?;

        Ok(())
    }
}
