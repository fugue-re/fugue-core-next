pub mod builder;
pub mod def_use;
pub mod dominance;
pub mod error;
pub mod format;
pub mod liveness;
pub mod memory;
pub mod transform;
pub mod verify;

pub use builder::{LLIL_SSA_SCHEMA_VERSION, SsaBody, SsaBuilder};
pub use def_use::{Use, UseIndex};
pub use dominance::{Dominance, DominanceFrontier, PhiPlacement};
pub use error::SsaError;
pub use format::{SsaBodyDisplay, SsaOpcodeDisplay, SsaOperationDisplay, ValueDisplay};
pub use liveness::Liveness;
pub use memory::MemoryDomain;
pub use verify::SsaVerifier;

use crate::il::common::{BlockId, OperationId, PackedRange, ValueId};
use crate::il::llil::{ExpressionOpcode, StatementOpcode};
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
pub struct Value {
    width: u32,
    definition_kind: ValueDefinitionKind,
    definition_index: u32,
}

impl Value {
    pub const fn new(
        width: u32,
        definition_kind: ValueDefinitionKind,
        definition_index: u32,
    ) -> Self {
        Self {
            width,
            definition_kind,
            definition_index,
        }
    }

    pub const fn operation_result(width: u32, operation: OperationId) -> Self {
        Self::new(
            width,
            ValueDefinitionKind::Operation,
            operation.index() as u32,
        )
    }

    pub const fn block_argument(width: u32, argument: u32) -> Self {
        Self::new(width, ValueDefinitionKind::BlockArgument, argument)
    }

    pub const fn width(&self) -> u32 {
        self.width
    }

    pub const fn definition_kind(&self) -> ValueDefinitionKind {
        self.definition_kind
    }

    pub const fn definition_index(&self) -> u32 {
        self.definition_index
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
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(u8)]
pub enum ValueDefinitionKind {
    Operation = 0,
    BlockArgument = 1,
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
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct BlockArgument {
    block: BlockId,
    value: ValueId,
    width: u32,
}

impl BlockArgument {
    pub const fn new(block: BlockId, value: ValueId, width: u32) -> Self {
        Self {
            block,
            value,
            width,
        }
    }

    pub const fn block(&self) -> BlockId {
        self.block
    }

    pub const fn value(&self) -> ValueId {
        self.value
    }

    pub const fn width(&self) -> u32 {
        self.width
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
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(u16)]
pub enum SsaOpcode {
    Constant = 0,
    Address = 1,
    Extract = 2,
    Insert = 3,
    Load = 4,
    Store = 5,
    Intrinsic = 6,
    Branch = 7,
    ConditionalBranch = 8,
    Call = 9,
    Return = 10,
    Undefined = 11,
    Add = 12,
    Sub = 13,
    Mul = 14,
    UnsignedDiv = 15,
    SignedDiv = 16,
    UnsignedRem = 17,
    SignedRem = 18,
    LeftShift = 19,
    LogicalRightShift = 20,
    ArithmeticRightShift = 21,
    Compare = 22,
    Carry = 23,
    Borrow = 24,
    Bool = 25,
    Not = 26,
    Negate = 27,
    CountOnes = 28,
    CountLeadingZeros = 29,
    ZeroExtend = 30,
    SignExtend = 31,
    Truncate = 32,
    Copy = 33,
    CallIndirect = 34,
    Trap = 35,
    IntrinsicResult = 36,
    BranchIndirect = 37,
}

impl SsaOpcode {
    pub const fn mnemonic(&self) -> &'static str {
        match self {
            Self::Constant => "constant",
            Self::Address => "address",
            Self::Extract => "extract",
            Self::Insert => "insert",
            Self::Load => "load",
            Self::Store => "store",
            Self::Intrinsic => "intrinsic",
            Self::Branch => "branch",
            Self::ConditionalBranch => "conditional_branch",
            Self::Call => "call",
            Self::Return => "return",
            Self::Undefined => "undefined",
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Mul => "mul",
            Self::UnsignedDiv => "unsigned_div",
            Self::SignedDiv => "signed_div",
            Self::UnsignedRem => "unsigned_rem",
            Self::SignedRem => "signed_rem",
            Self::LeftShift => "left_shift",
            Self::LogicalRightShift => "logical_right_shift",
            Self::ArithmeticRightShift => "arithmetic_right_shift",
            Self::Compare => "compare",
            Self::Carry => "carry",
            Self::Borrow => "borrow",
            Self::Bool => "bool",
            Self::Not => "not",
            Self::Negate => "negate",
            Self::CountOnes => "count_ones",
            Self::CountLeadingZeros => "count_leading_zeros",
            Self::ZeroExtend => "zero_extend",
            Self::SignExtend => "sign_extend",
            Self::Truncate => "truncate",
            Self::Copy => "copy",
            Self::CallIndirect => "call_indirect",
            Self::Trap => "trap",
            Self::IntrinsicResult => "intrinsic_result",
            Self::BranchIndirect => "branch_indirect",
        }
    }

    pub const fn from_expression(opcode: ExpressionOpcode) -> Option<Self> {
        match opcode {
            ExpressionOpcode::Constant => Some(Self::Constant),
            ExpressionOpcode::Address => Some(Self::Address),
            ExpressionOpcode::ReadRegister | ExpressionOpcode::ReadFlag => None,
            ExpressionOpcode::Load => Some(Self::Load),
            ExpressionOpcode::Add => Some(Self::Add),
            ExpressionOpcode::Sub => Some(Self::Sub),
            ExpressionOpcode::Mul => Some(Self::Mul),
            ExpressionOpcode::UnsignedDiv => Some(Self::UnsignedDiv),
            ExpressionOpcode::SignedDiv => Some(Self::SignedDiv),
            ExpressionOpcode::UnsignedRem => Some(Self::UnsignedRem),
            ExpressionOpcode::SignedRem => Some(Self::SignedRem),
            ExpressionOpcode::LeftShift => Some(Self::LeftShift),
            ExpressionOpcode::LogicalRightShift => Some(Self::LogicalRightShift),
            ExpressionOpcode::ArithmeticRightShift => Some(Self::ArithmeticRightShift),
            ExpressionOpcode::Compare => Some(Self::Compare),
            ExpressionOpcode::Carry => Some(Self::Carry),
            ExpressionOpcode::Borrow => Some(Self::Borrow),
            ExpressionOpcode::Bool => Some(Self::Bool),
            ExpressionOpcode::Not => Some(Self::Not),
            ExpressionOpcode::Negate => Some(Self::Negate),
            ExpressionOpcode::CountOnes => Some(Self::CountOnes),
            ExpressionOpcode::CountLeadingZeros => Some(Self::CountLeadingZeros),
            ExpressionOpcode::ZeroExtend => Some(Self::ZeroExtend),
            ExpressionOpcode::SignExtend => Some(Self::SignExtend),
            ExpressionOpcode::Truncate => Some(Self::Truncate),
            ExpressionOpcode::Extract => Some(Self::Extract),
            ExpressionOpcode::Insert => Some(Self::Insert),
            ExpressionOpcode::IntrinsicResult => Some(Self::IntrinsicResult),
            ExpressionOpcode::Undefined => Some(Self::Undefined),
            ExpressionOpcode::Copy => Some(Self::Copy),
        }
    }

    pub const fn from_statement(opcode: StatementOpcode) -> Option<Self> {
        match opcode {
            StatementOpcode::WriteRegister | StatementOpcode::WriteFlag => None,
            StatementOpcode::Store => Some(Self::Store),
            StatementOpcode::Intrinsic => Some(Self::Intrinsic),
            StatementOpcode::Branch => Some(Self::Branch),
            StatementOpcode::BranchIndirect => Some(Self::BranchIndirect),
            StatementOpcode::ConditionalBranch => Some(Self::ConditionalBranch),
            StatementOpcode::Call => Some(Self::Call),
            StatementOpcode::CallIndirect => Some(Self::CallIndirect),
            StatementOpcode::Return => Some(Self::Return),
            StatementOpcode::Trap => Some(Self::Trap),
        }
    }

    pub const fn requires_memory_domain(&self) -> bool {
        matches!(self, Self::Load | Self::Store)
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
pub struct SsaOperation {
    opcode: SsaOpcode,
    results: PackedRange,
    operands: PackedRange,
    width: u32,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<AddressSpaceId>,
}

impl SsaOperation {
    pub const fn new(
        opcode: SsaOpcode,
        results: PackedRange,
        operands: PackedRange,
        width: u32,
    ) -> Self {
        Self {
            opcode,
            results,
            operands,
            width,
            immediate: 0,
            address: None,
            address_space: None,
        }
    }

    pub const fn with_immediate(mut self, immediate: u64) -> Self {
        self.immediate = immediate;
        self
    }

    pub const fn with_address(mut self, address: Address) -> Self {
        self.address = Some(address);
        self
    }

    pub const fn with_address_space(mut self, address_space: AddressSpaceId) -> Self {
        self.address_space = Some(address_space);
        self
    }

    pub const fn opcode(&self) -> SsaOpcode {
        self.opcode
    }

    pub const fn results(&self) -> PackedRange {
        self.results
    }

    pub const fn operands(&self) -> PackedRange {
        self.operands
    }

    pub const fn width(&self) -> u32 {
        self.width
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
    fn ssa_records_stay_compact() {
        assert!(size_of::<Value>() <= 12);
        assert!(size_of::<BlockArgument>() <= 12);
        assert!(size_of::<SsaOperation>() <= 64);
    }
}
