use std::borrow::Borrow;

use fugue_bv::BitVec;

use crate::il::common::IlScalarOp;

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(u16)]
pub enum ECodeOpcode {
    Add = 5,
    Address = 1,
    And = 16,
    ArithmeticRightShift = 15,
    BoolAnd = 20,
    BoolNot = 23,
    BoolOr = 21,
    BoolXor = 22,
    Branch = 61,
    BranchIndirect = 63,
    Call = 64,
    CallIndirect = 65,
    Carry = 30,
    ConditionalBranch = 62,
    Constant = 0,
    Copy = 4,
    CountLeadingZeros = 34,
    CountOnes = 33,
    Extract = 38,
    FloatAbs = 45,
    FloatAdd = 40,
    FloatCeiling = 47,
    FloatDiv = 43,
    FloatEqual = 51,
    FloatFloor = 48,
    FloatIsNan = 50,
    FloatLess = 53,
    FloatLessEqual = 54,
    FloatMul = 42,
    FloatNegate = 44,
    FloatNotEqual = 52,
    FloatRound = 49,
    FloatSqrt = 46,
    FloatSub = 41,
    FloatToFloat = 56,
    FloatToInt = 55,
    Insert = 39,
    IntEqual = 24,
    IntLess = 26,
    IntLessEqual = 28,
    IntNotEqual = 25,
    IntSignedLess = 27,
    IntSignedLessEqual = 29,
    IntToFloat = 57,
    Intrinsic = 59,
    IntrinsicResult = 58,
    LeftShift = 13,
    Load = 3,
    LogicalRightShift = 14,
    Mul = 7,
    Negate = 12,
    Not = 19,
    Or = 17,
    Return = 66,
    SignExtend = 36,
    SignedBorrow = 32,
    SignedCarry = 31,
    SignedDiv = 9,
    SignedRem = 11,
    Store = 60,
    Sub = 6,
    Trap = 67,
    Truncate = 37,
    Undefined = 2,
    UnsignedDiv = 8,
    UnsignedRem = 10,
    WriteFlag = 69,
    WriteRegister = 68,
    Xor = 18,
    ZeroExtend = 35,
}

impl ECodeOpcode {
    pub const fn mnemonic(&self) -> &'static str {
        match self {
            Self::Constant => "const",
            Self::Address => "addr",
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
            Self::Intrinsic => "intrinsic",
            Self::Store => "store",
            Self::Branch => "br",
            Self::ConditionalBranch => "cbr",
            Self::BranchIndirect => "ibr",
            Self::Call => "call",
            Self::CallIndirect => "icall",
            Self::Return => "ret",
            Self::Trap => "trap",
            Self::WriteRegister => "write_reg",
            Self::WriteFlag => "write_flag",
        }
    }

    pub const fn requires_memory_domain(&self) -> bool {
        matches!(self, Self::Load | Self::Store)
    }

    pub(crate) const fn has_side_effect(self) -> bool {
        matches!(
            self,
            Self::Store
                | Self::Intrinsic
                | Self::IntrinsicResult
                | Self::Branch
                | Self::ConditionalBranch
                | Self::BranchIndirect
                | Self::Call
                | Self::CallIndirect
                | Self::Return
                | Self::Trap
                | Self::WriteRegister
                | Self::WriteFlag
        )
    }

    pub(crate) const fn has_uniform_operand_width(self) -> bool {
        matches!(
            self,
            Self::Add
                | Self::Sub
                | Self::Mul
                | Self::UnsignedDiv
                | Self::SignedDiv
                | Self::UnsignedRem
                | Self::SignedRem
                | Self::Negate
                | Self::And
                | Self::Or
                | Self::Xor
                | Self::Not
                | Self::WriteRegister
                | Self::WriteFlag
        )
    }

    pub(crate) fn evaluate<T>(self, width: u32, operands: &[T]) -> Option<BitVec>
    where
        T: Borrow<BitVec>,
    {
        let operation = match self {
            Self::Add => IlScalarOp::Add,
            Self::And => IlScalarOp::And,
            Self::ArithmeticRightShift => IlScalarOp::ArithmeticRightShift,
            Self::BoolAnd => IlScalarOp::BoolAnd,
            Self::BoolNot => IlScalarOp::BoolNot,
            Self::BoolOr => IlScalarOp::BoolOr,
            Self::BoolXor => IlScalarOp::BoolXor,
            Self::Carry => IlScalarOp::Carry,
            Self::Copy => IlScalarOp::Copy,
            Self::CountLeadingZeros => IlScalarOp::CountLeadingZeros,
            Self::CountOnes => IlScalarOp::CountOnes,
            Self::IntEqual => IlScalarOp::IntEqual,
            Self::IntLess => IlScalarOp::IntLess,
            Self::IntLessEqual => IlScalarOp::IntLessEqual,
            Self::IntNotEqual => IlScalarOp::IntNotEqual,
            Self::IntSignedLess => IlScalarOp::IntSignedLess,
            Self::IntSignedLessEqual => IlScalarOp::IntSignedLessEqual,
            Self::LeftShift => IlScalarOp::LeftShift,
            Self::LogicalRightShift => IlScalarOp::LogicalRightShift,
            Self::Mul => IlScalarOp::Mul,
            Self::Negate => IlScalarOp::Negate,
            Self::Not => IlScalarOp::Not,
            Self::Or => IlScalarOp::Or,
            Self::SignedBorrow => IlScalarOp::SignedBorrow,
            Self::SignedCarry => IlScalarOp::SignedCarry,
            Self::SignedDiv => IlScalarOp::SignedDiv,
            Self::SignedRem => IlScalarOp::SignedRem,
            Self::SignExtend => IlScalarOp::SignExtend,
            Self::Sub => IlScalarOp::Sub,
            Self::Truncate => IlScalarOp::Truncate,
            Self::UnsignedDiv => IlScalarOp::UnsignedDiv,
            Self::UnsignedRem => IlScalarOp::UnsignedRem,
            Self::Xor => IlScalarOp::Xor,
            Self::ZeroExtend => IlScalarOp::ZeroExtend,
            _ => return None,
        };

        operation.evaluate(width, operands)
    }
}

#[cfg(test)]
mod test;
