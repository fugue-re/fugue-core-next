pub mod builder;
pub mod def_use;
pub mod format;
pub mod liveness;
pub mod memory;
pub mod transform;

pub(crate) use builder::ECodeSsaBuilder;
pub use builder::{ECODE_SSA_SCHEMA_VERSION, ECodeSsaIr};
pub use def_use::{ECodeSsaUse, ECodeSsaUses};
pub use format::{
    ECodeSsaIrDisplay, ECodeSsaOpDisplay, ECodeSsaOpcodeDisplay, ECodeSsaValueDisplay,
};
pub use liveness::ECodeSsaLiveness;
pub use memory::ECodeSsaMemoryDomain;
pub use transform::ECodeToSsa;

use crate::il::common::{IlBlockId, IlIndexRange, IlOpId, IlValueId};
use crate::il::ecode::{ECodeExprOpcode, ECodeStmtOpcode};
use crate::ir::Address;
use crate::storage::segments::space::AddressSpaceId;

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

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(u16)]
pub enum ECodeSsaOpcode {
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

impl ECodeSsaOpcode {
    pub const fn mnemonic(&self) -> &'static str {
        match self {
            Self::Constant => "const",
            Self::Address => "addr",
            Self::Extract => "extract",
            Self::Insert => "insert",
            Self::Load => "load",
            Self::Store => "store",
            Self::Intrinsic => "intrinsic",
            Self::Branch => "br",
            Self::ConditionalBranch => "cbr",
            Self::Call => "call",
            Self::Return => "ret",
            Self::Undefined => "undef",
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Mul => "mul",
            Self::UnsignedDiv => "udiv",
            Self::SignedDiv => "sdiv",
            Self::UnsignedRem => "urem",
            Self::SignedRem => "srem",
            Self::LeftShift => "shl",
            Self::LogicalRightShift => "lshr",
            Self::ArithmeticRightShift => "ashr",
            Self::Compare => "cmp",
            Self::Carry => "carry",
            Self::Borrow => "borrow",
            Self::Bool => "bool",
            Self::Not => "not",
            Self::Negate => "neg",
            Self::CountOnes => "popcount",
            Self::CountLeadingZeros => "clz",
            Self::ZeroExtend => "zext",
            Self::SignExtend => "sext",
            Self::Truncate => "trunc",
            Self::Copy => "copy",
            Self::CallIndirect => "icall",
            Self::Trap => "trap",
            Self::IntrinsicResult => "intrinsic_result",
            Self::BranchIndirect => "ibr",
        }
    }

    pub const fn from_expression(opcode: ECodeExprOpcode) -> Option<Self> {
        match opcode {
            ECodeExprOpcode::Constant => Some(Self::Constant),
            ECodeExprOpcode::Address => Some(Self::Address),
            ECodeExprOpcode::ReadRegister | ECodeExprOpcode::ReadFlag => None,
            ECodeExprOpcode::Load => Some(Self::Load),
            ECodeExprOpcode::Add => Some(Self::Add),
            ECodeExprOpcode::Sub => Some(Self::Sub),
            ECodeExprOpcode::Mul => Some(Self::Mul),
            ECodeExprOpcode::UnsignedDiv => Some(Self::UnsignedDiv),
            ECodeExprOpcode::SignedDiv => Some(Self::SignedDiv),
            ECodeExprOpcode::UnsignedRem => Some(Self::UnsignedRem),
            ECodeExprOpcode::SignedRem => Some(Self::SignedRem),
            ECodeExprOpcode::LeftShift => Some(Self::LeftShift),
            ECodeExprOpcode::LogicalRightShift => Some(Self::LogicalRightShift),
            ECodeExprOpcode::ArithmeticRightShift => Some(Self::ArithmeticRightShift),
            ECodeExprOpcode::Compare => Some(Self::Compare),
            ECodeExprOpcode::Carry => Some(Self::Carry),
            ECodeExprOpcode::Borrow => Some(Self::Borrow),
            ECodeExprOpcode::Bool => Some(Self::Bool),
            ECodeExprOpcode::Not => Some(Self::Not),
            ECodeExprOpcode::Negate => Some(Self::Negate),
            ECodeExprOpcode::CountOnes => Some(Self::CountOnes),
            ECodeExprOpcode::CountLeadingZeros => Some(Self::CountLeadingZeros),
            ECodeExprOpcode::ZeroExtend => Some(Self::ZeroExtend),
            ECodeExprOpcode::SignExtend => Some(Self::SignExtend),
            ECodeExprOpcode::Truncate => Some(Self::Truncate),
            ECodeExprOpcode::Extract => Some(Self::Extract),
            ECodeExprOpcode::Insert => Some(Self::Insert),
            ECodeExprOpcode::IntrinsicResult => Some(Self::IntrinsicResult),
            ECodeExprOpcode::Undefined => Some(Self::Undefined),
            ECodeExprOpcode::Copy => Some(Self::Copy),
        }
    }

    pub const fn from_statement(opcode: ECodeStmtOpcode) -> Option<Self> {
        match opcode {
            ECodeStmtOpcode::WriteRegister | ECodeStmtOpcode::WriteFlag => None,
            ECodeStmtOpcode::Store => Some(Self::Store),
            ECodeStmtOpcode::Intrinsic => Some(Self::Intrinsic),
            ECodeStmtOpcode::Branch => Some(Self::Branch),
            ECodeStmtOpcode::BranchIndirect => Some(Self::BranchIndirect),
            ECodeStmtOpcode::ConditionalBranch => Some(Self::ConditionalBranch),
            ECodeStmtOpcode::Call => Some(Self::Call),
            ECodeStmtOpcode::CallIndirect => Some(Self::CallIndirect),
            ECodeStmtOpcode::Return => Some(Self::Return),
            ECodeStmtOpcode::Trap => Some(Self::Trap),
        }
    }

    pub const fn requires_memory_domain(&self) -> bool {
        matches!(self, Self::Load | Self::Store)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ECodeSsaOp {
    opcode: ECodeSsaOpcode,
    results: IlIndexRange,
    operands: IlIndexRange,
    width: u32,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<AddressSpaceId>,
}

impl ECodeSsaOp {
    pub(crate) const fn new(
        opcode: ECodeSsaOpcode,
        results: IlIndexRange,
        operands: IlIndexRange,
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

    pub const fn opcode(&self) -> ECodeSsaOpcode {
        self.opcode
    }

    pub const fn results(&self) -> IlIndexRange {
        self.results
    }

    pub const fn operands(&self) -> IlIndexRange {
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
mod test {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn ssa_records_stay_compact() {
        assert!(size_of::<ECodeSsaValue>() <= 12);
        assert!(size_of::<ECodeSsaBlockArg>() <= 12);
        assert!(size_of::<ECodeSsaOp>() <= 64);
    }
}
