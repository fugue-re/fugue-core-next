use crate::il::common::{IlBlockArgId, IlBlockId, IlOpId, IlSsaDef, IlValueId};
use crate::il::mcode::MCodeVarId;
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(transparent)]
struct MCodeValueType(u32);

impl MCodeValueType {
    const MEMORY_TAG: u32 = 1 << 31;

    const fn bits(width: u32) -> Option<Self> {
        if width & Self::MEMORY_TAG == 0 {
            Some(Self(width))
        } else {
            None
        }
    }

    const fn memory(space: AddressSpaceId) -> Self {
        Self(Self::MEMORY_TAG | space.value() as u32)
    }

    const fn memory_domain(&self) -> Option<AddressSpaceId> {
        if self.0 & Self::MEMORY_TAG == 0 {
            return None;
        }
        let value = self.0 & !Self::MEMORY_TAG;
        if value > u16::MAX as u32 {
            return None;
        }
        Some(AddressSpaceId::new(value as usize))
    }

    const fn width(&self) -> u32 {
        if self.0 & Self::MEMORY_TAG == 0 {
            self.0
        } else {
            0
        }
    }
}

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
    value_type: MCodeValueType,
    definition: IlSsaDef,
    variable: Option<MCodeVarId>,
    version: MCodeVersion,
}

impl MCodeValue {
    const fn new(definition: IlSsaDef, width: u32) -> Option<Self> {
        let Some(value_type) = MCodeValueType::bits(width) else {
            return None;
        };
        Some(Self {
            value_type,
            definition,
            variable: None,
            version: MCodeVersion::new(0),
        })
    }

    pub(crate) const fn op_result(operation: IlOpId, width: u32) -> Option<Self> {
        Self::new(IlSsaDef::Op(operation), width)
    }

    pub(crate) const fn block_arg(arg: IlBlockArgId, width: u32) -> Option<Self> {
        Self::new(IlSsaDef::BlockArg(arg), width)
    }

    pub(crate) fn set_binding(&mut self, variable: MCodeVarId, version: MCodeVersion) {
        self.variable = Some(variable);
        self.version = version;
    }

    pub(crate) fn set_memory_domain(&mut self, space: AddressSpaceId) {
        self.value_type = MCodeValueType::memory(space);
    }

    pub const fn width(&self) -> u32 {
        self.value_type.width()
    }

    pub(crate) const fn memory_domain(&self) -> Option<AddressSpaceId> {
        self.value_type.memory_domain()
    }

    pub const fn definition(&self) -> IlSsaDef {
        self.definition
    }

    pub(crate) const fn variable(&self) -> Option<MCodeVarId> {
        self.variable
    }

    pub(crate) const fn version(&self) -> MCodeVersion {
        self.version
    }

    pub fn binding(&self) -> Option<MCodeBinding> {
        self.variable
            .map(|variable| MCodeBinding::new(variable, self.version))
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
