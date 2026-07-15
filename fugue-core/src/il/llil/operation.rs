use crate::il::common::{ExpressionId, PackedRange};
use crate::ir::Address;
use crate::storage::segments::space::AddressSpaceId;

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(u16)]
pub enum StatementOpcode {
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

impl StatementOpcode {
    pub const fn mnemonic(&self) -> &'static str {
        match self {
            Self::WriteRegister => "write_register",
            Self::WriteFlag => "write_flag",
            Self::Store => "store",
            Self::Intrinsic => "intrinsic",
            Self::Branch => "branch",
            Self::BranchIndirect => "branch_indirect",
            Self::ConditionalBranch => "conditional_branch",
            Self::Call => "call",
            Self::CallIndirect => "call_indirect",
            Self::Return => "return",
            Self::Trap => "trap",
        }
    }

    pub const fn fixed_operand_count(&self) -> Option<usize> {
        match self {
            Self::WriteRegister | Self::WriteFlag | Self::Trap => Some(0),
            Self::Branch
            | Self::BranchIndirect
            | Self::Call
            | Self::CallIndirect
            | Self::Return => Some(1),
            Self::Store | Self::ConditionalBranch => Some(2),
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

    pub const fn requires_immediate(&self) -> bool {
        matches!(self, Self::WriteRegister | Self::WriteFlag)
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct Statement {
    opcode: StatementOpcode,
    operands: PackedRange,
    value: Option<ExpressionId>,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<AddressSpaceId>,
}

impl Statement {
    pub const fn new(
        opcode: StatementOpcode,
        operands: PackedRange,
        value: Option<ExpressionId>,
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

    pub const fn opcode(&self) -> StatementOpcode {
        self.opcode
    }

    pub const fn operands(&self) -> PackedRange {
        self.operands
    }

    pub const fn value(&self) -> Option<ExpressionId> {
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
mod tests {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn statement_records_stay_compact() {
        assert!(size_of::<Statement>() <= 64);
    }
}
