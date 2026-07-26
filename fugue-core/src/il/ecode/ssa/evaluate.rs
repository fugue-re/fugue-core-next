use std::borrow::{Borrow, Cow};
use std::cmp::Ordering;

use fugue_bv::BitVec;

use crate::il::ecode::ssa::ECodeSsaOpcode;

#[cfg(test)]
mod test;

impl ECodeSsaOpcode {
    pub(crate) fn evaluate<T>(self, width: u32, operands: &[T]) -> Option<BitVec>
    where
        T: Borrow<BitVec>,
    {
        let arg_ref = |index: usize| operands.get(index).map(Borrow::borrow);
        let arg_cast = |index: usize| {
            let value = arg_ref(index)?;
            Some(if value.bits() == width {
                Cow::Borrowed(value)
            } else {
                Cow::Owned(value.clone().cast(width))
            })
        };
        match self {
            Self::Copy | Self::Truncate => Some(arg_ref(0)?.clone().cast(width)),
            Self::Not => Some(!arg_cast(0)?.as_ref()),
            Self::Negate => Some(-arg_cast(0)?.as_ref()),
            Self::Add => Some(arg_cast(0)?.as_ref() + arg_cast(1)?.as_ref()),
            Self::Sub => Some(arg_cast(0)?.as_ref() - arg_cast(1)?.as_ref()),
            Self::Mul => Some(arg_cast(0)?.as_ref() * arg_cast(1)?.as_ref()),
            Self::And => Some(arg_cast(0)?.as_ref() & arg_cast(1)?.as_ref()),
            Self::Or => Some(arg_cast(0)?.as_ref() | arg_cast(1)?.as_ref()),
            Self::Xor => Some(arg_cast(0)?.as_ref() ^ arg_cast(1)?.as_ref()),
            Self::LeftShift => Some(arg_cast(0)?.as_ref() << arg_cast(1)?.as_ref()),
            Self::LogicalRightShift => {
                let value = arg_cast(0)?;
                let amount = arg_cast(1)?;
                if value.is_unsigned() {
                    Some(value.as_ref() >> amount.as_ref())
                } else {
                    let value = value.as_ref().unsigned_cast(width);
                    Some(&value >> amount.as_ref())
                }
            }
            Self::ArithmeticRightShift => {
                let value = arg_cast(0)?;
                let amount = arg_cast(1)?;
                Some(value.signed_shr(amount.as_ref()))
            }
            Self::ZeroExtend => Some(arg_ref(0)?.unsigned_cast(width)),
            Self::SignExtend => Some(arg_ref(0)?.signed_cast(width)),
            Self::BoolAnd => Some(BitVec::from_u64(
                (!arg_ref(0)?.is_zero() && !arg_ref(1)?.is_zero()) as u64,
                width,
            )),
            Self::BoolOr => Some(BitVec::from_u64(
                (!arg_ref(0)?.is_zero() || !arg_ref(1)?.is_zero()) as u64,
                width,
            )),
            Self::BoolXor => Some(BitVec::from_u64(
                (arg_ref(0)?.is_zero() != arg_ref(1)?.is_zero()) as u64,
                width,
            )),
            Self::BoolNot => Some(BitVec::from_u64(arg_ref(0)?.is_zero() as u64, width)),
            Self::CountOnes => Some(BitVec::from_u64(u64::from(arg_ref(0)?.count_ones()), width)),
            Self::CountLeadingZeros => Some(BitVec::from_u64(
                u64::from(arg_ref(0)?.leading_zeros()),
                width,
            )),
            Self::UnsignedDiv => {
                let (a, b) = (arg_cast(0)?, arg_cast(1)?);
                if b.is_zero() {
                    None
                } else if a.is_unsigned() && b.is_unsigned() {
                    Some(a.as_ref() / b.as_ref())
                } else {
                    Some(a.as_ref().unsigned_cast(width) / b.as_ref().unsigned_cast(width))
                }
            }
            Self::SignedDiv => {
                let (a, b) = (arg_cast(0)?, arg_cast(1)?);
                (!b.is_zero()).then(|| a.signed_div(b.as_ref()))
            }
            Self::UnsignedRem => {
                let (a, b) = (arg_cast(0)?, arg_cast(1)?);
                if b.is_zero() {
                    None
                } else if a.is_unsigned() && b.is_unsigned() {
                    Some(a.as_ref() % b.as_ref())
                } else {
                    Some(a.as_ref().unsigned_cast(width) % b.as_ref().unsigned_cast(width))
                }
            }
            Self::SignedRem => {
                let (a, b) = (arg_cast(0)?, arg_cast(1)?);
                (!b.is_zero()).then(|| a.signed_rem(b.as_ref()))
            }
            Self::IntEqual => {
                let (a, b) = (arg_ref(0)?, arg_ref(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64((a == b) as u64, width))
            }
            Self::IntNotEqual => {
                let (a, b) = (arg_ref(0)?, arg_ref(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64((a != b) as u64, width))
            }
            Self::IntLess => {
                let (a, b) = (arg_ref(0)?, arg_ref(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                let less = if a.is_unsigned() && b.is_unsigned() {
                    a < b
                } else {
                    a.clone().unsigned() < b.clone().unsigned()
                };
                Some(BitVec::from_u64(less as u64, width))
            }
            Self::IntLessEqual => {
                let (a, b) = (arg_ref(0)?, arg_ref(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                let less_equal = if a.is_unsigned() && b.is_unsigned() {
                    a <= b
                } else {
                    a.clone().unsigned() <= b.clone().unsigned()
                };
                Some(BitVec::from_u64(less_equal as u64, width))
            }
            Self::IntSignedLess => {
                let (a, b) = (arg_ref(0)?, arg_ref(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64(
                    (a.signed_cmp(b) == Ordering::Less) as u64,
                    width,
                ))
            }
            Self::IntSignedLessEqual => {
                let (a, b) = (arg_ref(0)?, arg_ref(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64(
                    (a.signed_cmp(b) != Ordering::Greater) as u64,
                    width,
                ))
            }
            Self::Carry => {
                let (a, b) = (arg_ref(0)?, arg_ref(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                let carry = if a.is_unsigned() && b.is_unsigned() {
                    a.carry(b)
                } else {
                    a.clone().unsigned().carry(&b.clone().unsigned())
                };
                Some(BitVec::from_u64(carry as u64, width))
            }
            Self::SignedCarry => {
                let (a, b) = (arg_ref(0)?, arg_ref(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64(a.signed_carry(b) as u64, width))
            }
            Self::SignedBorrow => {
                let (a, b) = (arg_ref(0)?, arg_ref(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64(a.signed_borrow(b) as u64, width))
            }
            _ => None,
        }
    }
}
