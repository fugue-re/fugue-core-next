use std::mem::size_of;

use crate::il::common::{IlBlockArgId, IlBlockId, IlOpId, IlSsaDef, IlValueId};

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct ECodeValue {
    width: u32,
    definition: IlSsaDef,
}

const _: () = assert!(size_of::<ECodeValue>() <= 12);

impl ECodeValue {
    pub(crate) const fn new(width: u32, definition: IlSsaDef) -> Self {
        Self { width, definition }
    }

    pub const fn operation_result(width: u32, operation: IlOpId) -> Self {
        Self::new(width, IlSsaDef::Op(operation))
    }

    pub const fn block_arg(width: u32, arg: IlBlockArgId) -> Self {
        Self::new(width, IlSsaDef::BlockArg(arg))
    }

    pub const fn width(&self) -> u32 {
        self.width
    }

    pub const fn definition(&self) -> IlSsaDef {
        self.definition
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct ECodeBlockArg {
    block: IlBlockId,
    value: IlValueId,
    width: u32,
}

const _: () = assert!(size_of::<ECodeBlockArg>() <= 12);

impl ECodeBlockArg {
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
