use std::mem::size_of;

use crate::il::common::{IlBlockArgId, IlBlockId, IlOpId, IlSsaDef, IlValueId};
use crate::il::mcode::MCodeVarId;

#[derive(
    Debug,
    Copy,
    Clone,
    Default,
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
pub struct MCodeVersion(u32);

impl MCodeVersion {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u32 {
        self.0
    }

    pub const fn checked_next(&self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct MCodeValue {
    width: u32,
    definition: IlSsaDef,
    variable: Option<MCodeVarId>,
    version: MCodeVersion,
}

const _: () = assert!(size_of::<MCodeValue>() <= 20);

impl MCodeValue {
    pub(crate) const fn new(width: u32, definition: IlSsaDef) -> Self {
        Self {
            width,
            definition,
            variable: None,
            version: MCodeVersion::new(0),
        }
    }

    pub const fn op_result(width: u32, operation: IlOpId) -> Self {
        Self::new(width, IlSsaDef::Op(operation))
    }

    pub const fn block_arg(width: u32, arg: IlBlockArgId) -> Self {
        Self::new(width, IlSsaDef::BlockArg(arg))
    }

    pub(crate) fn set_binding(&mut self, variable: MCodeVarId, version: MCodeVersion) {
        self.variable = Some(variable);
        self.version = version;
    }

    pub const fn width(&self) -> u32 {
        self.width
    }

    pub const fn definition(&self) -> IlSsaDef {
        self.definition
    }

    pub fn binding(&self) -> Option<MCodeBinding> {
        self.variable
            .map(|variable| MCodeBinding::new(variable, self.version))
    }

    pub(crate) const fn variable(&self) -> Option<MCodeVarId> {
        self.variable
    }

    pub(crate) const fn version(&self) -> MCodeVersion {
        self.version
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MCodeBinding {
    variable: MCodeVarId,
    version: MCodeVersion,
}

impl MCodeBinding {
    pub(crate) const fn new(variable: MCodeVarId, version: MCodeVersion) -> Self {
        Self { variable, version }
    }

    pub const fn variable(&self) -> MCodeVarId {
        self.variable
    }

    pub const fn version(&self) -> MCodeVersion {
        self.version
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct MCodeBlockArg {
    block: IlBlockId,
    value: IlValueId,
    width: u32,
}

const _: () = assert!(size_of::<MCodeBlockArg>() <= 12);

impl MCodeBlockArg {
    pub(crate) const fn new(block: IlBlockId, value: IlValueId, width: u32) -> Self {
        Self {
            block,
            value,
            width,
        }
    }

    pub const fn block(&self) -> IlBlockId {
        self.block
    }

    pub const fn value(&self) -> IlValueId {
        self.value
    }

    pub const fn width(&self) -> u32 {
        self.width
    }
}
