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
mod test {
    use fugue_bv::BitVec;

    use super::ECodeOpcode;

    #[test]
    fn evaluate_folds_comparisons_at_operand_width() {
        let seven = BitVec::from_u64(7, 32);
        let nine = BitVec::from_u64(9, 32);
        let one = BitVec::from_u64(1, 1);
        let zero = BitVec::from_u64(0, 1);

        assert_eq!(
            ECodeOpcode::IntLess.evaluate(1, &[seven.clone(), nine.clone()]),
            Some(one.clone())
        );
        assert_eq!(
            ECodeOpcode::IntLessEqual.evaluate(1, &[seven.clone(), seven.clone()]),
            Some(one.clone())
        );
        assert_eq!(
            ECodeOpcode::IntEqual.evaluate(1, &[seven.clone(), nine.clone()]),
            Some(zero.clone())
        );
        assert_eq!(
            ECodeOpcode::IntNotEqual.evaluate(1, &[seven.clone(), nine.clone()]),
            Some(one.clone())
        );

        let minus_one = BitVec::from_u64(u64::from(u32::MAX), 32);
        assert_eq!(
            ECodeOpcode::IntSignedLess.evaluate(1, &[minus_one.clone(), seven.clone()]),
            Some(one.clone())
        );
        assert_eq!(
            ECodeOpcode::IntLess.evaluate(1, &[minus_one, seven.clone()]),
            Some(zero)
        );
    }

    #[test]
    fn evaluate_folds_unsigned_comparisons_of_sign_extended_operands() {
        let extended = ECodeOpcode::SignExtend
            .evaluate(16, &[BitVec::from_u64(0x80, 8)])
            .expect("sign extension folds");
        assert_eq!(extended, BitVec::from_u64(0xff80, 16).signed());

        let five = BitVec::from_u64(5, 16);
        let zero = BitVec::from_u64(0, 1);
        assert_eq!(
            ECodeOpcode::IntLess.evaluate(1, &[extended.clone(), five.clone()]),
            Some(zero.clone())
        );
        assert_eq!(
            ECodeOpcode::IntLessEqual.evaluate(1, &[extended.clone(), five]),
            Some(zero)
        );
        assert_eq!(
            ECodeOpcode::IntSignedLess.evaluate(1, &[extended, BitVec::from_u64(5, 16)]),
            Some(BitVec::from_u64(1, 1))
        );
    }

    #[test]
    fn evaluate_folds_byte_wide_boolean_operations_to_zero_or_one() {
        let zero = BitVec::from_u64(0, 8);
        let one = BitVec::from_u64(1, 8);
        let nonzero = BitVec::from_u64(0x80, 8);

        assert_eq!(
            ECodeOpcode::BoolAnd.evaluate(8, &[one.clone(), nonzero.clone()]),
            Some(one.clone())
        );
        assert_eq!(
            ECodeOpcode::BoolOr.evaluate(8, &[zero.clone(), nonzero.clone()]),
            Some(one.clone())
        );
        assert_eq!(
            ECodeOpcode::BoolXor.evaluate(8, &[one.clone(), nonzero.clone()]),
            Some(zero.clone())
        );
        assert_eq!(
            ECodeOpcode::BoolNot.evaluate(8, std::slice::from_ref(&one)),
            Some(zero.clone())
        );
        assert_eq!(
            ECodeOpcode::BoolNot.evaluate(8, std::slice::from_ref(&zero)),
            Some(one)
        );
    }

    #[test]
    fn evaluate_guards_width_mismatch_and_zero_divisor() {
        let wide = BitVec::from_u64(7, 32);
        let narrow = BitVec::from_u64(7, 16);
        assert_eq!(
            ECodeOpcode::IntLess.evaluate(1, &[wide.clone(), narrow]),
            None
        );

        let zero = BitVec::from_u64(0, 32);
        assert_eq!(
            ECodeOpcode::UnsignedDiv.evaluate(32, &[wide.clone(), zero.clone()]),
            None
        );
        assert_eq!(ECodeOpcode::SignedRem.evaluate(32, &[wide, zero]), None);
    }

    #[test]
    fn evaluate_folds_division_and_bit_counts() {
        assert_eq!(
            ECodeOpcode::UnsignedDiv
                .evaluate(32, &[BitVec::from_u64(20, 32), BitVec::from_u64(6, 32)]),
            Some(BitVec::from_u64(3, 32))
        );
        assert_eq!(
            ECodeOpcode::UnsignedRem
                .evaluate(32, &[BitVec::from_u64(20, 32), BitVec::from_u64(6, 32)]),
            Some(BitVec::from_u64(2, 32))
        );
        assert_eq!(
            ECodeOpcode::CountOnes.evaluate(32, &[BitVec::from_u64(0b1011, 32)]),
            Some(BitVec::from_u64(3, 32))
        );
        assert_eq!(
            ECodeOpcode::CountLeadingZeros.evaluate(32, &[BitVec::from_u64(1, 32)]),
            Some(BitVec::from_u64(31, 32))
        );
    }

    #[test]
    fn evaluate_folds_carries_and_borrows() {
        let one = BitVec::from_u64(1, 1);
        let zero = BitVec::from_u64(0, 1);
        let max = BitVec::from_u64(u64::from(u32::MAX), 32);
        let signed_min = BitVec::from_u64(0x8000_0000, 32);
        let signed_max = BitVec::from_u64(0x7fff_ffff, 32);
        let unit = BitVec::from_u64(1, 32);

        assert_eq!(
            ECodeOpcode::Carry.evaluate(1, &[max.clone(), unit.clone()]),
            Some(one.clone())
        );
        assert_eq!(
            ECodeOpcode::Carry.evaluate(1, &[unit.clone(), unit.clone()]),
            Some(zero.clone())
        );
        assert_eq!(
            ECodeOpcode::Carry.evaluate(1, &[max.signed(), unit.clone()]),
            Some(one.clone())
        );

        assert_eq!(
            ECodeOpcode::SignedCarry.evaluate(1, &[signed_max, unit.clone()]),
            Some(one.clone())
        );
        assert_eq!(
            ECodeOpcode::SignedCarry.evaluate(1, &[unit.clone(), unit.clone()]),
            Some(zero.clone())
        );
        assert_eq!(
            ECodeOpcode::SignedBorrow.evaluate(1, &[signed_min, unit.clone()]),
            Some(one)
        );
        assert_eq!(
            ECodeOpcode::SignedBorrow.evaluate(1, &[BitVec::from_u64(0, 32), unit]),
            Some(zero)
        );
    }

    #[test]
    fn evaluate_folds_boolean_and_signed_operations() {
        let one = BitVec::from_u64(1, 1);
        let zero = BitVec::from_u64(0, 1);

        assert_eq!(
            ECodeOpcode::BoolAnd.evaluate(1, &[one.clone(), zero.clone()]),
            Some(zero.clone())
        );
        assert_eq!(
            ECodeOpcode::BoolOr.evaluate(1, &[one.clone(), zero.clone()]),
            Some(one.clone())
        );
        assert_eq!(
            ECodeOpcode::BoolXor.evaluate(1, &[one.clone(), one.clone()]),
            Some(zero.clone())
        );
        assert_eq!(
            ECodeOpcode::BoolNot.evaluate(1, std::slice::from_ref(&zero)),
            Some(one.clone())
        );

        let minus_twenty = BitVec::from_u64((-20i64) as u64, 32);
        let six = BitVec::from_u64(6, 32);
        assert_eq!(
            ECodeOpcode::SignedDiv
                .evaluate(32, &[minus_twenty.clone(), six.clone()])
                .map(BitVec::unsigned),
            Some(BitVec::from_u64((-3i64) as u64, 32))
        );
        assert_eq!(
            ECodeOpcode::SignedRem
                .evaluate(32, &[minus_twenty.clone(), six.clone()])
                .map(BitVec::unsigned),
            Some(BitVec::from_u64((-2i64) as u64, 32))
        );
        assert_eq!(
            ECodeOpcode::IntSignedLessEqual.evaluate(1, &[minus_twenty, six]),
            Some(one)
        );
    }

    #[test]
    fn evaluate_leaves_extract_and_insert_unfolded() {
        let operand = BitVec::from_u64(0xff, 32);
        assert_eq!(
            ECodeOpcode::Extract.evaluate(8, std::slice::from_ref(&operand)),
            None
        );
        assert_eq!(
            ECodeOpcode::Insert.evaluate(32, &[operand.clone(), operand]),
            None
        );
    }
}
