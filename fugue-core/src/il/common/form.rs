use std::fmt;
use std::str::FromStr;

use smol_str::SmolStr;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IlFormIdError {
    #[error("identifier `{identifier}` has an empty component")]
    EmptyComponent { identifier: String },
    #[error("identifier `{identifier}` contains `{character}`, which is not permitted")]
    InvalidCharacter { identifier: String, character: char },
    #[error("identifier is empty")]
    Missing,
    #[error("form identifier `{identifier}` must have at least a dialect and a form component")]
    MissingFormComponent { identifier: String },
}

enum ValidationFailure {
    EmptyComponent,
    InvalidCharacter(usize),
    Missing,
}

impl ValidationFailure {
    const fn check(identifier: &str) -> Result<(), Self> {
        let bytes = identifier.as_bytes();
        if bytes.is_empty() {
            return Err(Self::Missing);
        }

        let mut index = 0;
        let mut component_start = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            if byte == b'.' {
                if index == component_start {
                    return Err(Self::EmptyComponent);
                }
                component_start = index + 1;
            } else if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_') {
                return Err(Self::InvalidCharacter(index));
            }
            index += 1;
        }

        if component_start == bytes.len() {
            return Err(Self::EmptyComponent);
        }

        Ok(())
    }

    fn into_error(self, identifier: &str) -> IlFormIdError {
        match self {
            Self::EmptyComponent => IlFormIdError::EmptyComponent {
                identifier: String::from(identifier),
            },
            Self::InvalidCharacter(index) => IlFormIdError::InvalidCharacter {
                identifier: String::from(identifier),
                character: identifier[index..]
                    .chars()
                    .next()
                    .expect("validation reported a character boundary"),
            },
            Self::Missing => IlFormIdError::Missing,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DialectId(SmolStr);

impl DialectId {
    pub const RESERVED_NAMESPACE: &str = "fugue";

    pub const fn from_static(identifier: &'static str) -> Self {
        if ValidationFailure::check(identifier).is_err() {
            panic!("dialect identifier is not a dot-separated lower-case ASCII name");
        }
        Self(SmolStr::new_static(identifier))
    }

    pub fn new(identifier: impl AsRef<str>) -> Result<Self, IlFormIdError> {
        let identifier = identifier.as_ref();
        ValidationFailure::check(identifier).map_err(|failure| failure.into_error(identifier))?;
        Ok(Self(SmolStr::new(identifier)))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn is_reserved(&self) -> bool {
        self.namespace() == Self::RESERVED_NAMESPACE
    }

    pub fn namespace(&self) -> &str {
        self.as_str()
            .split_once('.')
            .map_or(self.as_str(), |(namespace, _)| namespace)
    }
}

impl fmt::Display for DialectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DialectId {
    type Err = IlFormIdError;

    fn from_str(identifier: &str) -> Result<Self, Self::Err> {
        Self::new(identifier)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IlFormId(SmolStr);

impl IlFormId {
    pub const fn from_static(identifier: &'static str) -> Self {
        if ValidationFailure::check(identifier).is_err() {
            panic!("form identifier is not a dot-separated lower-case ASCII name");
        }
        if Self::component_count(identifier) < 2 {
            panic!("form identifier must have at least a dialect and a form component");
        }
        Self(SmolStr::new_static(identifier))
    }

    pub fn new(identifier: impl AsRef<str>) -> Result<Self, IlFormIdError> {
        let identifier = identifier.as_ref();
        ValidationFailure::check(identifier).map_err(|failure| failure.into_error(identifier))?;
        if Self::component_count(identifier) < 2 {
            return Err(IlFormIdError::MissingFormComponent {
                identifier: String::from(identifier),
            });
        }
        Ok(Self(SmolStr::new(identifier)))
    }

    pub(crate) fn from_stored(identifier: &str) -> Self {
        debug_assert!(
            ValidationFailure::check(identifier).is_ok() && Self::component_count(identifier) >= 2,
            "a stored form identifier was written malformed"
        );
        Self(SmolStr::new(identifier))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn dialect(&self) -> DialectId {
        let (dialect, _) = self
            .as_str()
            .rsplit_once('.')
            .expect("form identifier has at least two components");
        DialectId(SmolStr::new(dialect))
    }

    const fn component_count(identifier: &str) -> usize {
        let bytes = identifier.as_bytes();
        let mut index = 0;
        let mut count = 1;
        while index < bytes.len() {
            if bytes[index] == b'.' {
                count += 1;
            }
            index += 1;
        }
        count
    }
}

impl fmt::Display for IlFormId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IlFormId {
    type Err = IlFormIdError;

    fn from_str(identifier: &str) -> Result<Self, Self::Err> {
        Self::new(identifier)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn identifiers_round_trip_through_their_durable_encoding() {
        let form = IlFormId::from_static("fugue.ecode.ssa");

        assert_eq!(form.as_str(), "fugue.ecode.ssa");
        assert_eq!(form.as_str().parse(), Ok(form.clone()));
        assert_eq!(form.dialect(), DialectId::from_static("fugue.ecode"));
        assert!(form.dialect().is_reserved());
    }

    #[test]
    fn identifiers_reject_malformed_names() {
        assert_eq!(DialectId::new(""), Err(IlFormIdError::Missing));
        assert!(matches!(
            DialectId::new("fugue..pcode"),
            Err(IlFormIdError::EmptyComponent { .. })
        ));
        assert!(matches!(
            DialectId::new("fugue.pcode."),
            Err(IlFormIdError::EmptyComponent { .. })
        ));
        assert!(matches!(
            DialectId::new("Fugue.pcode"),
            Err(IlFormIdError::InvalidCharacter { .. })
        ));
        assert!(matches!(
            DialectId::new("fugue pcode"),
            Err(IlFormIdError::InvalidCharacter { .. })
        ));
    }

    #[test]
    fn form_identifiers_require_a_dialect_component() {
        assert!(matches!(
            IlFormId::new("pcode"),
            Err(IlFormIdError::MissingFormComponent { .. })
        ));
        assert!(IlFormId::new("acme.taint").is_ok());
    }

    #[test]
    fn external_dialects_are_not_reserved() {
        assert!(!DialectId::from_static("acme.taint").is_reserved());
    }
}
