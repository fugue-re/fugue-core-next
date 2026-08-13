use std::borrow::Borrow;

use fugue_bv::BitVec;

use crate::il::common::IlScalarOp;
use crate::il::ecode::ssa::ECodeSsaOpcode;

#[cfg(test)]
mod test;

impl ECodeSsaOpcode {
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
