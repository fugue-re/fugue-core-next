use crate::il::common::{IlExprId, IlIndexRange};
use crate::ir::Address;
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(u16)]
pub enum ECodeStmtOpcode {
    WriteRegister = 0,
    WriteFlag = 1,
    Store = 2,
    Intrinsic = 3,
    Branch = 4,
    BranchIndirect = 5,
    ConditionalBranch = 6,
    Call = 7,
    CallIndirect = 8,
    Return = 9,
    Trap = 10,
}

impl ECodeStmtOpcode {
    pub const fn mnemonic(&self) -> &'static str {
        match self {
            Self::WriteRegister => "write_reg",
            Self::WriteFlag => "write_flag",
            Self::Store => "store",
            Self::Intrinsic => "intrinsic",
            Self::Branch => "br",
            Self::BranchIndirect => "ibr",
            Self::ConditionalBranch => "cbr",
            Self::Call => "call",
            Self::CallIndirect => "icall",
            Self::Return => "ret",
            Self::Trap => "trap",
        }
    }

    pub const fn fixed_operand_count(&self) -> Option<usize> {
        match self {
            Self::WriteRegister | Self::WriteFlag | Self::Branch | Self::Call | Self::Trap => {
                Some(0)
            }
            Self::BranchIndirect | Self::ConditionalBranch | Self::CallIndirect | Self::Return => {
                Some(1)
            }
            Self::Store => Some(2),
            Self::Intrinsic => None,
        }
    }

    pub const fn requires_address(&self) -> bool {
        matches!(self, Self::Branch | Self::ConditionalBranch | Self::Call)
    }

    pub const fn requires_address_space(&self) -> bool {
        matches!(
            self,
            Self::Store | Self::BranchIndirect | Self::CallIndirect
        )
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ECodeStmt {
    opcode: ECodeStmtOpcode,
    operands: IlIndexRange,
    value: Option<IlExprId>,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<AddressSpaceId>,
}

impl ECodeStmt {
    pub(crate) const fn new(
        opcode: ECodeStmtOpcode,
        operands: IlIndexRange,
        value: Option<IlExprId>,
        address: Option<Address>,
        address_space: Option<AddressSpaceId>,
    ) -> Self {
        Self {
            opcode,
            operands,
            value,
            immediate: 0,
            address,
            address_space,
        }
    }

    pub const fn with_immediate(mut self, immediate: u64) -> Self {
        self.immediate = immediate;
        self
    }

    pub const fn opcode(&self) -> ECodeStmtOpcode {
        self.opcode
    }

    pub const fn operands(&self) -> IlIndexRange {
        self.operands
    }

    pub const fn value(&self) -> Option<IlExprId> {
        self.value
    }

    pub const fn immediate(&self) -> u64 {
        self.immediate
    }

    pub const fn address(&self) -> Option<Address> {
        self.address
    }

    pub const fn address_space(&self) -> Option<AddressSpaceId> {
        self.address_space
    }
}

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn statement_records_stay_compact() {
        assert!(size_of::<ECodeStmt>() <= 64);
    }
}
