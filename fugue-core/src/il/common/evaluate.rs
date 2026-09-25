use std::borrow::{Borrow, Cow};
use std::cmp::Ordering;

use fugue_bv::BitVec;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum IlScalarOp {
    Add,
    And,
    ArithmeticRightShift,
    BoolAnd,
    BoolNot,
    BoolOr,
    BoolXor,
    Carry,
    Copy,
    CountLeadingZeros,
    CountOnes,
    IntEqual,
    IntLess,
    IntLessEqual,
    IntNotEqual,
    IntSignedLess,
    IntSignedLessEqual,
    LeftShift,
    LogicalRightShift,
    Mul,
    Negate,
    Not,
    Or,
    SignedBorrow,
    SignedCarry,
    SignedDiv,
    SignedRem,
    SignExtend,
    Sub,
    Truncate,
    UnsignedDiv,
    UnsignedRem,
    Xor,
    ZeroExtend,
}

impl IlScalarOp {
    pub(crate) fn evaluate<T>(self, width: u32, operands: &[T]) -> Option<BitVec>
    where
        T: Borrow<BitVec>,
    {
        let operand = |index: usize| operands.get(index).map(Borrow::borrow);
        let cast_operand = |index: usize| {
            let value = operand(index)?;
            Some(if value.bits() == width {
                Cow::Borrowed(value)
            } else {
                Cow::Owned(value.clone().cast(width))
            })
        };
        match self {
            Self::Copy | Self::Truncate => Some(operand(0)?.clone().cast(width)),
            Self::Not => Some(!cast_operand(0)?.as_ref()),
            Self::Negate => Some(-cast_operand(0)?.as_ref()),
            Self::Add => Some(cast_operand(0)?.as_ref() + cast_operand(1)?.as_ref()),
            Self::Sub => Some(cast_operand(0)?.as_ref() - cast_operand(1)?.as_ref()),
            Self::Mul => Some(cast_operand(0)?.as_ref() * cast_operand(1)?.as_ref()),
            Self::And => Some(cast_operand(0)?.as_ref() & cast_operand(1)?.as_ref()),
            Self::Or => Some(cast_operand(0)?.as_ref() | cast_operand(1)?.as_ref()),
            Self::Xor => Some(cast_operand(0)?.as_ref() ^ cast_operand(1)?.as_ref()),
            Self::LeftShift => Some(cast_operand(0)?.as_ref() << cast_operand(1)?.as_ref()),
            Self::LogicalRightShift => {
                let value = cast_operand(0)?;
                let amount = cast_operand(1)?;
                if value.is_unsigned() {
                    Some(value.as_ref() >> amount.as_ref())
                } else {
                    let value = value.as_ref().unsigned_cast(width);
                    Some(&value >> amount.as_ref())
                }
            }
            Self::ArithmeticRightShift => {
                let value = cast_operand(0)?;
                let amount = cast_operand(1)?;
                Some(value.signed_shr(amount.as_ref()))
            }
            Self::ZeroExtend => Some(operand(0)?.unsigned_cast(width)),
            Self::SignExtend => Some(operand(0)?.signed_cast(width)),
            Self::BoolAnd => Some(BitVec::from_u64(
                (!operand(0)?.is_zero() && !operand(1)?.is_zero()) as u64,
                width,
            )),
            Self::BoolOr => Some(BitVec::from_u64(
                (!operand(0)?.is_zero() || !operand(1)?.is_zero()) as u64,
                width,
            )),
            Self::BoolXor => Some(BitVec::from_u64(
                (operand(0)?.is_zero() != operand(1)?.is_zero()) as u64,
                width,
            )),
            Self::BoolNot => Some(BitVec::from_u64(operand(0)?.is_zero() as u64, width)),
            Self::CountOnes => Some(BitVec::from_u64(u64::from(operand(0)?.count_ones()), width)),
            Self::CountLeadingZeros => Some(BitVec::from_u64(
                u64::from(operand(0)?.leading_zeros()),
                width,
            )),
            Self::UnsignedDiv => {
                let (left, right) = (cast_operand(0)?, cast_operand(1)?);
                if right.is_zero() {
                    None
                } else if left.is_unsigned() && right.is_unsigned() {
                    Some(left.as_ref() / right.as_ref())
                } else {
                    Some(left.as_ref().unsigned_cast(width) / right.as_ref().unsigned_cast(width))
                }
            }
            Self::SignedDiv => {
                let (left, right) = (cast_operand(0)?, cast_operand(1)?);
                (!right.is_zero()).then(|| left.signed_div(right.as_ref()))
            }
            Self::UnsignedRem => {
                let (left, right) = (cast_operand(0)?, cast_operand(1)?);
                if right.is_zero() {
                    None
                } else if left.is_unsigned() && right.is_unsigned() {
                    Some(left.as_ref() % right.as_ref())
                } else {
                    Some(left.as_ref().unsigned_cast(width) % right.as_ref().unsigned_cast(width))
                }
            }
            Self::SignedRem => {
                let (left, right) = (cast_operand(0)?, cast_operand(1)?);
                (!right.is_zero()).then(|| left.signed_rem(right.as_ref()))
            }
            Self::IntEqual => {
                let (left, right) = (operand(0)?, operand(1)?);
                (left.bits() == right.bits())
                    .then(|| BitVec::from_u64((left == right) as u64, width))
            }
            Self::IntNotEqual => {
                let (left, right) = (operand(0)?, operand(1)?);
                (left.bits() == right.bits())
                    .then(|| BitVec::from_u64((left != right) as u64, width))
            }
            Self::IntLess => {
                let (left, right) = (operand(0)?, operand(1)?);
                if left.bits() != right.bits() {
                    return None;
                }
                let less = if left.is_unsigned() && right.is_unsigned() {
                    left < right
                } else {
                    left.clone().unsigned() < right.clone().unsigned()
                };
                Some(BitVec::from_u64(less as u64, width))
            }
            Self::IntLessEqual => {
                let (left, right) = (operand(0)?, operand(1)?);
                if left.bits() != right.bits() {
                    return None;
                }
                let less_equal = if left.is_unsigned() && right.is_unsigned() {
                    left <= right
                } else {
                    left.clone().unsigned() <= right.clone().unsigned()
                };
                Some(BitVec::from_u64(less_equal as u64, width))
            }
            Self::IntSignedLess => {
                let (left, right) = (operand(0)?, operand(1)?);
                (left.bits() == right.bits()).then(|| {
                    BitVec::from_u64((left.signed_cmp(right) == Ordering::Less) as u64, width)
                })
            }
            Self::IntSignedLessEqual => {
                let (left, right) = (operand(0)?, operand(1)?);
                (left.bits() == right.bits()).then(|| {
                    BitVec::from_u64((left.signed_cmp(right) != Ordering::Greater) as u64, width)
                })
            }
            Self::Carry => {
                let (left, right) = (operand(0)?, operand(1)?);
                if left.bits() != right.bits() {
                    return None;
                }
                let carry = if left.is_unsigned() && right.is_unsigned() {
                    left.carry(right)
                } else {
                    left.clone().unsigned().carry(&right.clone().unsigned())
                };
                Some(BitVec::from_u64(carry as u64, width))
            }
            Self::SignedCarry => {
                let (left, right) = (operand(0)?, operand(1)?);
                (left.bits() == right.bits())
                    .then(|| BitVec::from_u64(left.signed_carry(right) as u64, width))
            }
            Self::SignedBorrow => {
                let (left, right) = (operand(0)?, operand(1)?);
                (left.bits() == right.bits())
                    .then(|| BitVec::from_u64(left.signed_borrow(right) as u64, width))
            }
        }
    }
}
