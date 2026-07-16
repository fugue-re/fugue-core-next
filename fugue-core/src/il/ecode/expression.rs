use crate::il::common::{IlExprId, IlIndexRange};
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(u16)]
pub enum ECodeExprOpcode {
    Constant = 0,
    Address = 1,
    ReadRegister = 2,
    ReadFlag = 3,
    Load = 4,
    Add = 5,
    Sub = 6,
    Mul = 7,
    UnsignedDiv = 8,
    SignedDiv = 9,
    UnsignedRem = 10,
    SignedRem = 11,
    LeftShift = 12,
    LogicalRightShift = 13,
    ArithmeticRightShift = 14,
    Compare = 15,
    Carry = 16,
    Borrow = 17,
    Bool = 18,
    Not = 19,
    Negate = 20,
    CountOnes = 21,
    CountLeadingZeros = 22,
    ZeroExtend = 23,
    SignExtend = 24,
    Truncate = 25,
    Extract = 26,
    Insert = 27,
    IntrinsicResult = 28,
    Undefined = 29,
    Copy = 30,
}

impl ECodeExprOpcode {
    pub const fn mnemonic(&self) -> &'static str {
        match self {
            Self::Constant => "const",
            Self::Address => "addr",
            Self::ReadRegister => "read_reg",
            Self::ReadFlag => "read_flag",
            Self::Load => "load",
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
            Self::Extract => "extract",
            Self::Insert => "insert",
            Self::IntrinsicResult => "intrinsic_result",
            Self::Undefined => "undef",
            Self::Copy => "copy",
        }
    }

    pub const fn fixed_operand_count(&self) -> Option<usize> {
        match self {
            Self::Constant
            | Self::Address
            | Self::ReadRegister
            | Self::ReadFlag
            | Self::IntrinsicResult
            | Self::Undefined => Some(0),
            Self::Load
            | Self::Not
            | Self::Negate
            | Self::CountOnes
            | Self::CountLeadingZeros
            | Self::ZeroExtend
            | Self::SignExtend
            | Self::Truncate
            | Self::Copy => Some(1),
            Self::Add
            | Self::Sub
            | Self::Mul
            | Self::UnsignedDiv
            | Self::SignedDiv
            | Self::UnsignedRem
            | Self::SignedRem
            | Self::LeftShift
            | Self::LogicalRightShift
            | Self::ArithmeticRightShift
            | Self::Compare
            | Self::Carry
            | Self::Borrow
            | Self::Bool
            | Self::Extract
            | Self::Insert => Some(2),
        }
    }

    pub const fn requires_address_space(&self) -> bool {
        matches!(self, Self::Load)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ECodeExpr {
    opcode: ECodeExprOpcode,
    width: u32,
    operands: IlIndexRange,
    immediate: u64,
    address_space: Option<AddressSpaceId>,
}

impl ECodeExpr {
    pub(crate) const fn new(
        opcode: ECodeExprOpcode,
        width: u32,
        operands: IlIndexRange,
        immediate: u64,
        address_space: Option<AddressSpaceId>,
    ) -> Self {
        Self {
            opcode,
            width,
            operands,
            immediate,
            address_space,
        }
    }

    pub const fn opcode(&self) -> ECodeExprOpcode {
        self.opcode
    }

    pub const fn width(&self) -> u32 {
        self.width
    }

    pub const fn operands(&self) -> IlIndexRange {
        self.operands
    }

    pub const fn immediate(&self) -> u64 {
        self.immediate
    }

    pub const fn address_space(&self) -> Option<AddressSpaceId> {
        self.address_space
    }
}

pub type ExpressionOperand = IlExprId;

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn expression_records_stay_compact() {
        assert_eq!(size_of::<ExpressionOperand>(), 4);
        assert_eq!(size_of::<Option<ExpressionOperand>>(), 4);
        assert!(size_of::<ECodeExpr>() <= 32);
    }
}
