use std::num::ParseIntError;
use std::path::{Path, PathBuf};
use std::str::{ParseBoolError, Utf8Error};

use fugue_bytes::Endian;
use fugue_sleigh_marshal::MarshalError;
use roxmltree::Error as XmlError;
use thiserror::Error;

use crate::language::LanguageError;

#[derive(Debug, Error)]
pub enum DeserialiseError {
    #[error("attribute `{0}` expected")]
    AttributeExpected(&'static str),
    #[error(transparent)]
    Decoder(#[from] MarshalError),
    #[error("cannot deserialise dependency `{}`: {}", path.display(), error)]
    DeserialiseDepends {
        path: PathBuf,
        error: Box<LanguageError>,
    },
    #[error("unexpected element `{0}`")]
    ElementUnexpected(u32),
    #[error("invariant not satisfied: {0}")]
    Invariant(&'static str),
    #[error("could not parse boolean: {0}")]
    ParseBool(#[from] ParseBoolError),
    #[error("could not parse endian")]
    ParseEndian,
    #[error("could not parse integer: {0}")]
    ParseInteger(#[from] ParseIntError),
    #[error("unexpected tag `{0}`")]
    TagUnexpected(String),
    #[error("expected UTF-8 encoded input: {0}")]
    Utf8Expected(#[from] Utf8Error),
    #[error(transparent)]
    Xml(#[from] XmlError),
}

impl DeserialiseError {
    pub fn attribute_expected(name: &'static str) -> Self {
        Self::AttributeExpected(name)
    }

    pub fn decoder(error: MarshalError) -> Self {
        Self::Decoder(error)
    }

    pub fn deserialise_depends(path: impl AsRef<Path>, error: LanguageError) -> Self {
        Self::DeserialiseDepends {
            path: path.as_ref().to_owned(),
            error: Box::new(error),
        }
    }

    pub fn element_unexpected(element: u32) -> Self {
        Self::ElementUnexpected(element)
    }

    pub fn invariant(message: &'static str) -> Self {
        Self::Invariant(message)
    }

    pub fn parse_bool(error: ParseBoolError) -> Self {
        Self::ParseBool(error)
    }

    pub fn parse_endian() -> Self {
        Self::ParseEndian
    }

    pub fn parse_integer(error: ParseIntError) -> Self {
        Self::ParseInteger(error)
    }

    pub fn tag_unexpected(tag: impl Into<String>) -> Self {
        Self::TagUnexpected(tag.into())
    }

    pub fn utf8_expected(error: Utf8Error) -> Self {
        Self::Utf8Expected(error)
    }

    pub fn xml(error: XmlError) -> Self {
        Self::Xml(error)
    }
}

pub trait XmlExt {
    fn attribute_endian(&self, name: &'static str) -> Result<Endian, DeserialiseError>;

    fn attribute_processor(&self, name: &'static str) -> Result<String, DeserialiseError> {
        self.attribute_string(name)
    }

    fn attribute_variant(&self, name: &'static str) -> Result<String, DeserialiseError> {
        self.attribute_string(name)
    }

    fn attribute_str(&self, name: &'static str) -> Result<&str, DeserialiseError>;

    fn attribute_string(&self, name: &'static str) -> Result<String, DeserialiseError>;

    fn attribute_string_or(
        &self,
        name1: &'static str,
        name2: &'static str,
    ) -> Result<String, DeserialiseError>;

    fn attribute_string_opt(&self, name: &'static str, default: &str) -> String;

    fn attribute_int<T: FromStrRadix>(&self, name: &'static str) -> Result<T, DeserialiseError>;

    fn attribute_int_or<T: FromStrRadix>(
        &self,
        name1: &'static str,
        name2: &'static str,
    ) -> Result<T, DeserialiseError>;

    fn attribute_line_number<T: Default + FromStrRadix>(
        &self,
        name: &'static str,
    ) -> Result<(T, T), DeserialiseError>;

    fn attribute_int_opt<T: FromStrRadix>(
        &self,
        name: &'static str,
        default: T,
    ) -> Result<T, DeserialiseError>;

    fn attribute_bool(&self, name: &'static str) -> Result<bool, DeserialiseError>;

    fn attribute_bool_opt(
        &self,
        name: &'static str,
        default: bool,
    ) -> Result<bool, DeserialiseError>;
}

pub(crate) fn parse_bool(input: &str) -> Result<bool, DeserialiseError> {
    match input {
        "true" | "yes" | "1" => Ok(true),
        "false" | "no" | "0" => Ok(false),
        _ => input.parse::<bool>().map_err(DeserialiseError::parse_bool),
    }
}

#[inline(always)]
pub(crate) fn parse_int_radix<T: FromStrRadix>(s: &str) -> Result<T, DeserialiseError> {
    parse_int_radix_with(s, 10)
}

#[inline(always)]
pub(crate) fn parse_int_radix_with<T: FromStrRadix>(
    s: &str,
    default_radix: u32,
) -> Result<T, DeserialiseError> {
    let b = s.as_bytes();
    if b.len() > 2 && b[0] == b'0' && (b[1] == b'X' || b[1] == b'x') {
        T::from_str_base(&s[2..], 16)
    } else {
        T::from_str_base(s, default_radix)
    }
}

pub trait FromStrRadix: Sized {
    fn from_str_base(s: &str, radix: u32) -> Result<Self, DeserialiseError>;
}

impl FromStrRadix for i8 {
    fn from_str_base(s: &str, radix: u32) -> Result<Self, DeserialiseError> {
        Self::from_str_radix(s, radix).map_err(DeserialiseError::parse_integer)
    }
}

impl FromStrRadix for i16 {
    fn from_str_base(s: &str, radix: u32) -> Result<Self, DeserialiseError> {
        Self::from_str_radix(s, radix).map_err(DeserialiseError::parse_integer)
    }
}

impl FromStrRadix for i32 {
    fn from_str_base(s: &str, radix: u32) -> Result<Self, DeserialiseError> {
        Self::from_str_radix(s, radix).map_err(DeserialiseError::parse_integer)
    }
}

impl FromStrRadix for i64 {
    fn from_str_base(s: &str, radix: u32) -> Result<Self, DeserialiseError> {
        Self::from_str_radix(s, radix).map_err(DeserialiseError::parse_integer)
    }
}

impl FromStrRadix for isize {
    fn from_str_base(s: &str, radix: u32) -> Result<Self, DeserialiseError> {
        Self::from_str_radix(s, radix).map_err(DeserialiseError::parse_integer)
    }
}

impl FromStrRadix for u8 {
    fn from_str_base(s: &str, radix: u32) -> Result<Self, DeserialiseError> {
        Self::from_str_radix(s, radix).map_err(DeserialiseError::parse_integer)
    }
}

impl FromStrRadix for u16 {
    fn from_str_base(s: &str, radix: u32) -> Result<Self, DeserialiseError> {
        Self::from_str_radix(s, radix).map_err(DeserialiseError::parse_integer)
    }
}

impl FromStrRadix for u32 {
    fn from_str_base(s: &str, radix: u32) -> Result<Self, DeserialiseError> {
        Self::from_str_radix(s, radix).map_err(DeserialiseError::parse_integer)
    }
}

impl FromStrRadix for u64 {
    fn from_str_base(s: &str, radix: u32) -> Result<Self, DeserialiseError> {
        Self::from_str_radix(s, radix).map_err(DeserialiseError::parse_integer)
    }
}

impl FromStrRadix for usize {
    fn from_str_base(s: &str, radix: u32) -> Result<Self, DeserialiseError> {
        Self::from_str_radix(s, radix).map_err(DeserialiseError::parse_integer)
    }
}

impl XmlExt for xml::Node<'_, '_> {
    fn attribute_endian(&self, name: &'static str) -> Result<Endian, DeserialiseError> {
        let n = self
            .attribute(name)
            .ok_or(DeserialiseError::attribute_expected(name))?;
        match n {
            "big" | "BIG" | "be" | "BE" => Ok(Endian::Big),
            "little" | "LITTLE" | "le" | "LE" => Ok(Endian::Little),
            _ => Err(DeserialiseError::parse_endian()),
        }
    }

    fn attribute_str(&self, name: &'static str) -> Result<&str, DeserialiseError> {
        self.attribute(name)
            .ok_or(DeserialiseError::attribute_expected(name))
    }

    fn attribute_string(&self, name: &'static str) -> Result<String, DeserialiseError> {
        self.attribute_str(name).map(str::to_owned)
    }

    fn attribute_string_or(
        &self,
        name1: &'static str,
        name2: &'static str,
    ) -> Result<String, DeserialiseError> {
        self.attribute(name1)
            .or_else(|| self.attribute(name2))
            .map(String::from)
            .ok_or(DeserialiseError::attribute_expected(name1))
    }

    fn attribute_string_opt(&self, name: &'static str, default: &str) -> String {
        self.attribute(name)
            .map(String::from)
            .unwrap_or_else(|| default.to_owned())
    }

    fn attribute_line_number<T: Default + FromStrRadix>(
        &self,
        name: &'static str,
    ) -> Result<(T, T), DeserialiseError> {
        let s = self
            .attribute(name)
            .ok_or(DeserialiseError::attribute_expected(name))?;

        let b = s.as_bytes();
        if let Some(pos) = b.iter().position(|v| *v == b':') {
            // Two part index:line
            let index = parse_int_radix(&s[..pos])?;
            let line = parse_int_radix(&s[pos + 1..])?;
            Ok((index, line))
        } else {
            // One part 0:line
            let index = T::default();
            let line = parse_int_radix(s)?;
            Ok((index, line))
        }
    }

    fn attribute_int<T: FromStrRadix>(&self, name: &'static str) -> Result<T, DeserialiseError> {
        let s = self
            .attribute(name)
            .ok_or(DeserialiseError::attribute_expected(name))?;
        parse_int_radix(s)
    }

    fn attribute_int_or<T: FromStrRadix>(
        &self,
        name1: &'static str,
        name2: &'static str,
    ) -> Result<T, DeserialiseError> {
        let s = self
            .attribute(name1)
            .or_else(|| self.attribute(name2))
            .ok_or(DeserialiseError::attribute_expected(name1))?;
        parse_int_radix(s)
    }

    fn attribute_int_opt<T: FromStrRadix>(
        &self,
        name: &'static str,
        default: T,
    ) -> Result<T, DeserialiseError> {
        if let Some(s) = self.attribute(name) {
            parse_int_radix(s)
        } else {
            Ok(default)
        }
    }

    fn attribute_bool(&self, name: &'static str) -> Result<bool, DeserialiseError> {
        parse_bool(
            self.attribute(name)
                .ok_or(DeserialiseError::attribute_expected(name))?,
        )
    }

    fn attribute_bool_opt(
        &self,
        name: &'static str,
        default: bool,
    ) -> Result<bool, DeserialiseError> {
        match self.attribute(name) {
            Some(s) => parse_bool(s),
            None => Ok(default),
        }
    }
}
