use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::il::common::{IlAnalysis, IlGraph, IlRewrite};
use crate::ir::FunctionId;
use crate::storage::entities::MutableEntity;
use crate::types::common::Revision;

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(transparent)]
pub struct IlSchemaVersion(u16);

impl IlSchemaVersion {
    pub(crate) const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u16 {
        self.0
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(u8)]
pub enum IlLevel {
    PCode = 0,
    ECode = 1,
    ECodeSsa = 2,
}

impl IlLevel {
    pub const ALL: [Self; 3] = [Self::PCode, Self::ECode, Self::ECodeSsa];

    pub const fn name(&self) -> &'static str {
        match self {
            Self::PCode => "pcode",
            Self::ECode => "ecode",
            Self::ECodeSsa => "ecode_ssa",
        }
    }

    pub fn descendants_from(self) -> impl Iterator<Item = Self> {
        Self::ALL.into_iter().filter(move |level| *level >= self)
    }
}

impl fmt::Display for IlLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("unknown IL level: {name}")]
pub struct ParseIlLevelError {
    name: String,
}

impl FromStr for IlLevel {
    type Err = ParseIlLevelError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "pcode" => Ok(Self::PCode),
            "ecode" => Ok(Self::ECode),
            "ecode_ssa" => Ok(Self::ECodeSsa),
            _ => Err(ParseIlLevelError {
                name: String::from(name),
            }),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct IlMetadata {
    function: FunctionId,
    schema: IlSchemaVersion,
    input_revision: Revision,
}

impl IlMetadata {
    pub(crate) fn new(
        function: FunctionId,
        schema: IlSchemaVersion,
        input_revision: impl Into<Revision>,
    ) -> Self {
        Self {
            function,
            schema,
            input_revision: input_revision.into(),
        }
    }

    pub const fn function(&self) -> FunctionId {
        self.function
    }

    pub const fn schema(&self) -> IlSchemaVersion {
        self.schema
    }

    pub const fn input_revision(&self) -> Revision {
        self.input_revision
    }

    pub fn set_input_revision(&mut self, revision: Revision) {
        self.input_revision = revision;
    }
}

pub trait IlArtefact: MutableEntity<Key = FunctionId> {
    const LEVEL: IlLevel;
    const SCHEMA: IlSchemaVersion;

    fn metadata(&self) -> &IlMetadata;
    fn metadata_mut(&mut self) -> &mut IlMetadata;
    fn graph(&self) -> &IlGraph;

    fn analyse<A: IlAnalysis<Self>>(&self) -> A {
        A::analyse(self)
    }

    fn rewrite<R: IlRewrite<Self>>(&mut self, mut rewrite: R) {
        rewrite.rewrite(self);
    }
}

#[cfg(test)]
mod test {
    use super::IlLevel;

    #[test]
    fn level_names_round_trip() {
        for level in IlLevel::ALL {
            assert_eq!(level.name().parse(), Ok(level));
        }

        assert!("".parse::<IlLevel>().is_err());
    }
}
