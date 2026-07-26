use crate::il::common::{IlBlockId, IlOpId, IlValueId};

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct ECodeSsaValue {
    width: u32,
    definition_kind: ECodeSsaValueKind,
    definition_index: u32,
}

impl ECodeSsaValue {
    pub(crate) const fn new(
        width: u32,
        definition_kind: ECodeSsaValueKind,
        definition_index: u32,
    ) -> Self {
        Self {
            width,
            definition_kind,
            definition_index,
        }
    }

    pub const fn operation_result(width: u32, operation: IlOpId) -> Self {
        Self::new(
            width,
            ECodeSsaValueKind::Operation,
            operation.index() as u32,
        )
    }

    pub const fn block_argument(width: u32, argument: u32) -> Self {
        Self::new(width, ECodeSsaValueKind::BlockArgument, argument)
    }

    pub const fn width(&self) -> u32 {
        self.width
    }

    pub const fn definition_kind(&self) -> ECodeSsaValueKind {
        self.definition_kind
    }

    pub const fn definition_index(&self) -> u32 {
        self.definition_index
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(u8)]
pub enum ECodeSsaValueKind {
    Operation = 0,
    BlockArgument = 1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct ECodeSsaBlockArg {
    block: IlBlockId,
    value: IlValueId,
    width: u32,
}

impl ECodeSsaBlockArg {
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
