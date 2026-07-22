use crate::il::ecode::{ECodeExprOpcode, ECodeStmtOpcode};

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(u16)]
pub enum ECodeSsaOpcode {
    Constant = 0,
    Address = 1,
    Undefined = 2,
    Load = 3,
    Copy = 4,
    Add = 5,
    Sub = 6,
    Mul = 7,
    UnsignedDiv = 8,
    SignedDiv = 9,
    UnsignedRem = 10,
    SignedRem = 11,
    Negate = 12,
    LeftShift = 13,
    LogicalRightShift = 14,
    ArithmeticRightShift = 15,
    And = 16,
    Or = 17,
    Xor = 18,
    Not = 19,
    IntEqual = 20,
    IntNotEqual = 21,
    IntLess = 22,
    IntSignedLess = 23,
    IntLessEqual = 24,
    IntSignedLessEqual = 25,
    Carry = 26,
    SignedCarry = 27,
    SignedBorrow = 28,
    CountOnes = 29,
    CountLeadingZeros = 30,
    ZeroExtend = 31,
    SignExtend = 32,
    Truncate = 33,
    Extract = 34,
    Insert = 35,
    FloatAdd = 36,
    FloatSub = 37,
    FloatMul = 38,
    FloatDiv = 39,
    FloatNegate = 40,
    FloatAbs = 41,
    FloatSqrt = 42,
    FloatCeiling = 43,
    FloatFloor = 44,
    FloatRound = 45,
    FloatIsNan = 46,
    FloatEqual = 47,
    FloatNotEqual = 48,
    FloatLess = 49,
    FloatLessEqual = 50,
    FloatToInt = 51,
    FloatToFloat = 52,
    IntToFloat = 53,
    IntrinsicResult = 54,
    Intrinsic = 55,
    Store = 56,
    Branch = 57,
    ConditionalBranch = 58,
    BranchIndirect = 59,
    Call = 60,
    CallIndirect = 61,
    Return = 62,
    Trap = 63,
    BoolAnd = 64,
    BoolOr = 65,
    BoolXor = 66,
    BoolNot = 67,
}

impl ECodeSsaOpcode {
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
            Self::BoolAnd => "booland",
            Self::BoolOr => "boolor",
            Self::BoolXor => "boolxor",
            Self::BoolNot => "boolnot",
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
        }
    }

    pub const fn from_expression(opcode: ECodeExprOpcode) -> Option<Self> {
        match opcode {
            ECodeExprOpcode::ReadRegister | ECodeExprOpcode::ReadFlag => None,
            ECodeExprOpcode::Constant => Some(Self::Constant),
            ECodeExprOpcode::Address => Some(Self::Address),
            ECodeExprOpcode::Undefined => Some(Self::Undefined),
            ECodeExprOpcode::Load => Some(Self::Load),
            ECodeExprOpcode::Copy => Some(Self::Copy),
            ECodeExprOpcode::Add => Some(Self::Add),
            ECodeExprOpcode::Sub => Some(Self::Sub),
            ECodeExprOpcode::Mul => Some(Self::Mul),
            ECodeExprOpcode::UnsignedDiv => Some(Self::UnsignedDiv),
            ECodeExprOpcode::SignedDiv => Some(Self::SignedDiv),
            ECodeExprOpcode::UnsignedRem => Some(Self::UnsignedRem),
            ECodeExprOpcode::SignedRem => Some(Self::SignedRem),
            ECodeExprOpcode::Negate => Some(Self::Negate),
            ECodeExprOpcode::LeftShift => Some(Self::LeftShift),
            ECodeExprOpcode::LogicalRightShift => Some(Self::LogicalRightShift),
            ECodeExprOpcode::ArithmeticRightShift => Some(Self::ArithmeticRightShift),
            ECodeExprOpcode::And => Some(Self::And),
            ECodeExprOpcode::Or => Some(Self::Or),
            ECodeExprOpcode::Xor => Some(Self::Xor),
            ECodeExprOpcode::Not => Some(Self::Not),
            ECodeExprOpcode::BoolAnd => Some(Self::BoolAnd),
            ECodeExprOpcode::BoolOr => Some(Self::BoolOr),
            ECodeExprOpcode::BoolXor => Some(Self::BoolXor),
            ECodeExprOpcode::BoolNot => Some(Self::BoolNot),
            ECodeExprOpcode::IntEqual => Some(Self::IntEqual),
            ECodeExprOpcode::IntNotEqual => Some(Self::IntNotEqual),
            ECodeExprOpcode::IntLess => Some(Self::IntLess),
            ECodeExprOpcode::IntSignedLess => Some(Self::IntSignedLess),
            ECodeExprOpcode::IntLessEqual => Some(Self::IntLessEqual),
            ECodeExprOpcode::IntSignedLessEqual => Some(Self::IntSignedLessEqual),
            ECodeExprOpcode::Carry => Some(Self::Carry),
            ECodeExprOpcode::SignedCarry => Some(Self::SignedCarry),
            ECodeExprOpcode::SignedBorrow => Some(Self::SignedBorrow),
            ECodeExprOpcode::CountOnes => Some(Self::CountOnes),
            ECodeExprOpcode::CountLeadingZeros => Some(Self::CountLeadingZeros),
            ECodeExprOpcode::ZeroExtend => Some(Self::ZeroExtend),
            ECodeExprOpcode::SignExtend => Some(Self::SignExtend),
            ECodeExprOpcode::Truncate => Some(Self::Truncate),
            ECodeExprOpcode::Extract => Some(Self::Extract),
            ECodeExprOpcode::Insert => Some(Self::Insert),
            ECodeExprOpcode::FloatAdd => Some(Self::FloatAdd),
            ECodeExprOpcode::FloatSub => Some(Self::FloatSub),
            ECodeExprOpcode::FloatMul => Some(Self::FloatMul),
            ECodeExprOpcode::FloatDiv => Some(Self::FloatDiv),
            ECodeExprOpcode::FloatNegate => Some(Self::FloatNegate),
            ECodeExprOpcode::FloatAbs => Some(Self::FloatAbs),
            ECodeExprOpcode::FloatSqrt => Some(Self::FloatSqrt),
            ECodeExprOpcode::FloatCeiling => Some(Self::FloatCeiling),
            ECodeExprOpcode::FloatFloor => Some(Self::FloatFloor),
            ECodeExprOpcode::FloatRound => Some(Self::FloatRound),
            ECodeExprOpcode::FloatIsNan => Some(Self::FloatIsNan),
            ECodeExprOpcode::FloatEqual => Some(Self::FloatEqual),
            ECodeExprOpcode::FloatNotEqual => Some(Self::FloatNotEqual),
            ECodeExprOpcode::FloatLess => Some(Self::FloatLess),
            ECodeExprOpcode::FloatLessEqual => Some(Self::FloatLessEqual),
            ECodeExprOpcode::FloatToInt => Some(Self::FloatToInt),
            ECodeExprOpcode::FloatToFloat => Some(Self::FloatToFloat),
            ECodeExprOpcode::IntToFloat => Some(Self::IntToFloat),
            ECodeExprOpcode::IntrinsicResult => Some(Self::IntrinsicResult),
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

    pub(crate) const fn is_dce_root(self) -> bool {
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
        )
    }
}
