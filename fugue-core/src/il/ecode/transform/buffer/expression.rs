use std::mem::size_of;

use crate::il::common::IlIndexRange;
use crate::il::ecode::ECodeOpcode;
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum PCodeToECodeExprKind {
    Op(ECodeOpcode),
    ReadFlag,
    ReadRegister,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct PCodeToECodeExpr {
    kind: PCodeToECodeExprKind,
    width: u32,
    operands: IlIndexRange,
    immediate: u64,
    address_space: Option<AddressSpaceId>,
}

const _: () = assert!(size_of::<PCodeToECodeExpr>() <= 32);

impl PCodeToECodeExpr {
    pub(crate) const fn new(
        kind: PCodeToECodeExprKind,
        width: u32,
        operands: IlIndexRange,
        immediate: u64,
        address_space: Option<AddressSpaceId>,
    ) -> Self {
        Self {
            kind,
            width,
            operands,
            immediate,
            address_space,
        }
    }

    pub(crate) const fn kind(&self) -> PCodeToECodeExprKind {
        self.kind
    }

    pub(crate) const fn width(&self) -> u32 {
        self.width
    }

    pub(crate) const fn operands(&self) -> IlIndexRange {
        self.operands
    }

    pub(crate) const fn immediate(&self) -> u64 {
        self.immediate
    }

    pub(crate) const fn address_space(&self) -> Option<AddressSpaceId> {
        self.address_space
    }
}
