use crate::il::common::IlIndexRange;
use crate::il::ecode::ECodeOpcode;
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum ECodeLiftExprKind {
    Op(ECodeOpcode),
    ReadFlag,
    ReadRegister,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct ECodeLiftExpr {
    kind: ECodeLiftExprKind,
    width: u32,
    operands: IlIndexRange,
    immediate: u64,
    address_space: Option<AddressSpaceId>,
}

impl ECodeLiftExpr {
    pub(crate) const fn new(
        kind: ECodeLiftExprKind,
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

    pub(crate) const fn kind(&self) -> ECodeLiftExprKind {
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
