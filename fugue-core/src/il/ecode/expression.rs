use crate::il::common::{IlArtefact, IlError, IlIndexRange};
use crate::il::ecode::ECodeIr;
use crate::il::pcode::PCodeOpcode;
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(u16)]
pub enum ECodeExprOpcode {
    Constant = 0,
    Address = 1,
    ReadRegister = 2,
    ReadFlag = 3,
    Undefined = 4,
    Load = 5,
    Copy = 6,
    Add = 7,
    Sub = 8,
    Mul = 9,
    UnsignedDiv = 10,
    SignedDiv = 11,
    UnsignedRem = 12,
    SignedRem = 13,
    Negate = 14,
    LeftShift = 15,
    LogicalRightShift = 16,
    ArithmeticRightShift = 17,
    And = 18,
    Or = 19,
    Xor = 20,
    Not = 21,
    BoolAnd = 22,
    BoolOr = 23,
    BoolXor = 24,
    BoolNot = 25,
    IntEqual = 26,
    IntNotEqual = 27,
    IntLess = 28,
    IntSignedLess = 29,
    IntLessEqual = 30,
    IntSignedLessEqual = 31,
    Carry = 32,
    SignedCarry = 33,
    SignedBorrow = 34,
    CountOnes = 35,
    CountLeadingZeros = 36,
    ZeroExtend = 37,
    SignExtend = 38,
    Truncate = 39,
    Extract = 40,
    Insert = 41,
    FloatAdd = 42,
    FloatSub = 43,
    FloatMul = 44,
    FloatDiv = 45,
    FloatNegate = 46,
    FloatAbs = 47,
    FloatSqrt = 48,
    FloatCeiling = 49,
    FloatFloor = 50,
    FloatRound = 51,
    FloatIsNan = 52,
    FloatEqual = 53,
    FloatNotEqual = 54,
    FloatLess = 55,
    FloatLessEqual = 56,
    FloatToInt = 57,
    FloatToFloat = 58,
    IntToFloat = 59,
    IntrinsicResult = 60,
}

impl ECodeExprOpcode {
    pub(crate) fn from_pcode(opcode: PCodeOpcode) -> Result<Self, IlError> {
        match opcode {
            PCodeOpcode::Copy => Ok(Self::Copy),
            PCodeOpcode::Load => Ok(Self::Load),
            PCodeOpcode::IntAdd => Ok(Self::Add),
            PCodeOpcode::IntSub => Ok(Self::Sub),
            PCodeOpcode::IntMul => Ok(Self::Mul),
            PCodeOpcode::IntDiv => Ok(Self::UnsignedDiv),
            PCodeOpcode::IntSignedDiv => Ok(Self::SignedDiv),
            PCodeOpcode::IntRem => Ok(Self::UnsignedRem),
            PCodeOpcode::IntSignedRem => Ok(Self::SignedRem),
            PCodeOpcode::IntLeftShift => Ok(Self::LeftShift),
            PCodeOpcode::IntRightShift => Ok(Self::LogicalRightShift),
            PCodeOpcode::IntSignedRightShift => Ok(Self::ArithmeticRightShift),
            PCodeOpcode::IntEq => Ok(Self::IntEqual),
            PCodeOpcode::IntNotEq => Ok(Self::IntNotEqual),
            PCodeOpcode::IntLess => Ok(Self::IntLess),
            PCodeOpcode::IntSignedLess => Ok(Self::IntSignedLess),
            PCodeOpcode::IntLessEq => Ok(Self::IntLessEqual),
            PCodeOpcode::IntSignedLessEq => Ok(Self::IntSignedLessEqual),
            PCodeOpcode::IntCarry => Ok(Self::Carry),
            PCodeOpcode::IntSignedCarry => Ok(Self::SignedCarry),
            PCodeOpcode::IntSignedBorrow => Ok(Self::SignedBorrow),
            PCodeOpcode::IntAnd => Ok(Self::And),
            PCodeOpcode::IntOr => Ok(Self::Or),
            PCodeOpcode::IntXor => Ok(Self::Xor),
            PCodeOpcode::IntNot => Ok(Self::Not),
            PCodeOpcode::BoolAnd => Ok(Self::BoolAnd),
            PCodeOpcode::BoolOr => Ok(Self::BoolOr),
            PCodeOpcode::BoolXor => Ok(Self::BoolXor),
            PCodeOpcode::BoolNot => Ok(Self::BoolNot),
            PCodeOpcode::IntNeg => Ok(Self::Negate),
            PCodeOpcode::CountOnes => Ok(Self::CountOnes),
            PCodeOpcode::CountLeadingZeros => Ok(Self::CountLeadingZeros),
            PCodeOpcode::ZeroExt => Ok(Self::ZeroExtend),
            PCodeOpcode::SignExt => Ok(Self::SignExtend),
            PCodeOpcode::Subpiece => Ok(Self::Extract),
            PCodeOpcode::FloatAdd => Ok(Self::FloatAdd),
            PCodeOpcode::FloatSub => Ok(Self::FloatSub),
            PCodeOpcode::FloatMul => Ok(Self::FloatMul),
            PCodeOpcode::FloatDiv => Ok(Self::FloatDiv),
            PCodeOpcode::FloatNeg => Ok(Self::FloatNegate),
            PCodeOpcode::FloatAbs => Ok(Self::FloatAbs),
            PCodeOpcode::FloatSqrt => Ok(Self::FloatSqrt),
            PCodeOpcode::FloatCeiling => Ok(Self::FloatCeiling),
            PCodeOpcode::FloatFloor => Ok(Self::FloatFloor),
            PCodeOpcode::FloatRound => Ok(Self::FloatRound),
            PCodeOpcode::FloatIsNan => Ok(Self::FloatIsNan),
            PCodeOpcode::FloatEq => Ok(Self::FloatEqual),
            PCodeOpcode::FloatNotEq => Ok(Self::FloatNotEqual),
            PCodeOpcode::FloatLess => Ok(Self::FloatLess),
            PCodeOpcode::FloatLessEq => Ok(Self::FloatLessEqual),
            PCodeOpcode::FloatToInt => Ok(Self::FloatToInt),
            PCodeOpcode::FloatToFloat => Ok(Self::FloatToFloat),
            PCodeOpcode::IntToFloat => Ok(Self::IntToFloat),
            PCodeOpcode::UserOp => Ok(Self::IntrinsicResult),
            PCodeOpcode::Store
            | PCodeOpcode::Branch
            | PCodeOpcode::CBranch
            | PCodeOpcode::IBranch
            | PCodeOpcode::Call
            | PCodeOpcode::ICall
            | PCodeOpcode::Return => Err(IlError::unsupported_opcode(ECodeIr::FORM)),
        }
    }

    pub const fn mnemonic(&self) -> &'static str {
        match self {
            Self::Constant => "const",
            Self::Address => "addr",
            Self::ReadRegister => "read_reg",
            Self::ReadFlag => "read_flag",
            Self::Undefined => "undef",
            Self::Load => "load",
            Self::Copy => "copy",
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Mul => "mul",
            Self::UnsignedDiv => "udiv",
            Self::SignedDiv => "sdiv",
            Self::UnsignedRem => "urem",
            Self::SignedRem => "srem",
            Self::Negate => "neg",
            Self::LeftShift => "shl",
            Self::LogicalRightShift => "lshr",
            Self::ArithmeticRightShift => "ashr",
            Self::And => "and",
            Self::Or => "or",
            Self::Xor => "xor",
            Self::Not => "not",
            Self::BoolAnd => "band",
            Self::BoolOr => "bor",
            Self::BoolXor => "bxor",
            Self::BoolNot => "bnot",
            Self::IntEqual => "eq",
            Self::IntNotEqual => "ne",
            Self::IntLess => "lt",
            Self::IntSignedLess => "slt",
            Self::IntLessEqual => "le",
            Self::IntSignedLessEqual => "sle",
            Self::Carry => "carry",
            Self::SignedCarry => "scarry",
            Self::SignedBorrow => "sborrow",
            Self::CountOnes => "popcount",
            Self::CountLeadingZeros => "clz",
            Self::ZeroExtend => "zext",
            Self::SignExtend => "sext",
            Self::Truncate => "trunc",
            Self::Extract => "extract",
            Self::Insert => "insert",
            Self::FloatAdd => "fadd",
            Self::FloatSub => "fsub",
            Self::FloatMul => "fmul",
            Self::FloatDiv => "fdiv",
            Self::FloatNegate => "fneg",
            Self::FloatAbs => "fabs",
            Self::FloatSqrt => "fsqrt",
            Self::FloatCeiling => "fceil",
            Self::FloatFloor => "ffloor",
            Self::FloatRound => "fround",
            Self::FloatIsNan => "fisnan",
            Self::FloatEqual => "feq",
            Self::FloatNotEqual => "fne",
            Self::FloatLess => "flt",
            Self::FloatLessEqual => "fle",
            Self::FloatToInt => "f2i",
            Self::FloatToFloat => "f2f",
            Self::IntToFloat => "i2f",
            Self::IntrinsicResult => "intrinsic_result",
        }
    }

    pub const fn fixed_operand_count(&self) -> Option<usize> {
        match self {
            Self::Constant
            | Self::Address
            | Self::ReadRegister
            | Self::ReadFlag
            | Self::Undefined => Some(0),
            Self::Load
            | Self::Copy
            | Self::Negate
            | Self::Not
            | Self::CountOnes
            | Self::CountLeadingZeros
            | Self::ZeroExtend
            | Self::SignExtend
            | Self::Truncate
            | Self::BoolNot
            | Self::FloatNegate
            | Self::FloatAbs
            | Self::FloatSqrt
            | Self::FloatCeiling
            | Self::FloatFloor
            | Self::FloatRound
            | Self::FloatIsNan
            | Self::FloatToInt
            | Self::FloatToFloat
            | Self::IntToFloat
            | Self::Extract => Some(1),
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
            | Self::And
            | Self::Or
            | Self::Xor
            | Self::BoolAnd
            | Self::BoolOr
            | Self::BoolXor
            | Self::IntEqual
            | Self::IntNotEqual
            | Self::IntLess
            | Self::IntSignedLess
            | Self::IntLessEqual
            | Self::IntSignedLessEqual
            | Self::Carry
            | Self::SignedCarry
            | Self::SignedBorrow
            | Self::Insert
            | Self::FloatAdd
            | Self::FloatSub
            | Self::FloatMul
            | Self::FloatDiv
            | Self::FloatEqual
            | Self::FloatNotEqual
            | Self::FloatLess
            | Self::FloatLessEqual => Some(2),
            Self::IntrinsicResult => None,
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

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::*;
    use crate::il::common::IlExprId;

    #[test]
    fn expression_records_stay_compact() {
        assert_eq!(size_of::<IlExprId>(), 4);
        assert_eq!(size_of::<Option<IlExprId>>(), 4);
        assert!(size_of::<ECodeExpr>() <= 32);
    }
}
