use std::borrow::Borrow;

use fugue_bv::BitVec;

use crate::il::ecode::ssa::ECodeSsaOpcode;

#[cfg(test)]
mod test;

impl ECodeSsaOpcode {
    pub(crate) fn evaluate<T>(self, width: u32, operands: &[T]) -> Option<BitVec>
    where
        T: Borrow<BitVec>,
    {
        let arg = |index: usize| operands.get(index).map(|operand| operand.borrow().clone());
        match self {
            Self::Copy => Some(arg(0)?.cast(width)),
            Self::Not => Some(!arg(0)?.cast(width)),
            Self::Negate => Some(-arg(0)?.cast(width)),
            Self::Add => Some(arg(0)?.cast(width) + arg(1)?.cast(width)),
            Self::Sub => Some(arg(0)?.cast(width) - arg(1)?.cast(width)),
            Self::Mul => Some(arg(0)?.cast(width) * arg(1)?.cast(width)),
            Self::And => Some(arg(0)?.cast(width) & arg(1)?.cast(width)),
            Self::Or => Some(arg(0)?.cast(width) | arg(1)?.cast(width)),
            Self::Xor => Some(arg(0)?.cast(width) ^ arg(1)?.cast(width)),
            Self::LeftShift => Some(arg(0)?.cast(width) << arg(1)?.cast(width)),
            Self::LogicalRightShift => Some(arg(0)?.cast(width).unsigned() >> arg(1)?.cast(width)),
            Self::ArithmeticRightShift => Some(arg(0)?.cast(width).signed() >> arg(1)?.cast(width)),
            Self::ZeroExtend => Some(arg(0)?.unsigned_cast(width)),
            Self::SignExtend => Some(arg(0)?.signed_cast(width)),
            Self::Truncate => Some(arg(0)?.cast(width)),
            Self::BoolAnd => Some(BitVec::from_u64(
                (!arg(0)?.is_zero() && !arg(1)?.is_zero()) as u64,
                width,
            )),
            Self::BoolOr => Some(BitVec::from_u64(
                (!arg(0)?.is_zero() || !arg(1)?.is_zero()) as u64,
                width,
            )),
            Self::BoolXor => Some(BitVec::from_u64(
                (arg(0)?.is_zero() != arg(1)?.is_zero()) as u64,
                width,
            )),
            Self::BoolNot => Some(BitVec::from_u64(arg(0)?.is_zero() as u64, width)),
            Self::CountOnes => Some(BitVec::from_u64(u64::from(arg(0)?.count_ones()), width)),
            Self::CountLeadingZeros => {
                Some(BitVec::from_u64(u64::from(arg(0)?.leading_zeros()), width))
            }
            Self::UnsignedDiv => {
                let (a, b) = (arg(0)?.cast(width), arg(1)?.cast(width));
                (!b.is_zero()).then(|| a.unsigned() / b.unsigned())
            }
            Self::SignedDiv => {
                let (a, b) = (arg(0)?.cast(width), arg(1)?.cast(width));
                (!b.is_zero()).then(|| a.signed() / b.signed())
            }
            Self::UnsignedRem => {
                let (a, b) = (arg(0)?.cast(width), arg(1)?.cast(width));
                (!b.is_zero()).then(|| a.unsigned() % b.unsigned())
            }
            Self::SignedRem => {
                let (a, b) = (arg(0)?.cast(width), arg(1)?.cast(width));
                (!b.is_zero()).then(|| a.signed() % b.signed())
            }
            Self::IntEqual => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64((a == b) as u64, width))
            }
            Self::IntNotEqual => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64((a != b) as u64, width))
            }
            Self::IntLess => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64(
                    (a.unsigned() < b.unsigned()) as u64,
                    width,
                ))
            }
            Self::IntLessEqual => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64(
                    (a.unsigned() <= b.unsigned()) as u64,
                    width,
                ))
            }
            Self::IntSignedLess => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64((a.signed() < b.signed()) as u64, width))
            }
            Self::IntSignedLessEqual => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64((a.signed() <= b.signed()) as u64, width))
            }
            Self::Carry => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64(
                    a.unsigned().carry(&b.unsigned()) as u64,
                    width,
                ))
            }
            Self::SignedCarry => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64(a.signed_carry(&b) as u64, width))
            }
            Self::SignedBorrow => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64(a.signed_borrow(&b) as u64, width))
            }
            _ => None,
        }
    }
}
