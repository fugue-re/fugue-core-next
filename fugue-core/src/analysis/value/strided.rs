use std::iter;

use fugue_bv::BitVec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StridedInterval(StridedIntervalRepr);

#[derive(Debug, Clone, PartialEq, Eq)]
enum StridedIntervalRepr {
    Empty(u32),
    Interval {
        lo: BitVec,
        hi: BitVec,
        stride: BitVec,
    },
}

impl StridedInterval {
    pub fn empty(width: u32) -> Self {
        Self(StridedIntervalRepr::Empty(width))
    }

    pub fn full(width: u32) -> Self {
        Self(StridedIntervalRepr::Interval {
            lo: BitVec::zero(width),
            hi: BitVec::max_value_with(width, false),
            stride: BitVec::one(width),
        })
    }

    pub fn single(value: BitVec) -> Self {
        let stride = BitVec::zero(value.bits());
        Self(StridedIntervalRepr::Interval {
            lo: value.clone(),
            hi: value,
            stride,
        })
    }

    pub fn range(lo: BitVec, hi: BitVec, stride: BitVec) -> Self {
        if lo > hi {
            return Self(StridedIntervalRepr::Empty(lo.bits()));
        }
        if lo == hi {
            return Self::single(lo);
        }
        let span = &hi - &lo;
        let stride = if stride.is_zero() {
            BitVec::one(lo.bits())
        } else {
            stride.min(span.clone())
        };
        let hi = &lo + &(&(&span / &stride) * &stride);
        Self(StridedIntervalRepr::Interval { lo, hi, stride })
    }

    pub fn masked(mask: &BitVec) -> Self {
        if mask.is_zero() {
            return Self::single(mask.clone());
        }
        let stride = mask.clone() & -mask.clone();
        Self::range(BitVec::zero(mask.bits()), mask.clone(), stride)
    }

    pub fn is_empty(&self) -> bool {
        matches!(self.0, StridedIntervalRepr::Empty(_))
    }

    pub fn lower(&self) -> Option<&BitVec> {
        match &self.0 {
            StridedIntervalRepr::Empty(_) => None,
            StridedIntervalRepr::Interval { lo, .. } => Some(lo),
        }
    }

    pub fn upper(&self) -> Option<&BitVec> {
        match &self.0 {
            StridedIntervalRepr::Empty(_) => None,
            StridedIntervalRepr::Interval { hi, .. } => Some(hi),
        }
    }

    pub fn stride(&self) -> Option<&BitVec> {
        match &self.0 {
            StridedIntervalRepr::Empty(_) => None,
            StridedIntervalRepr::Interval { stride, .. } => Some(stride),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = BitVec> + '_ {
        let mut current = self.lower().cloned();
        let step = match &self.0 {
            StridedIntervalRepr::Empty(bits) => BitVec::zero(*bits),
            StridedIntervalRepr::Interval { stride, .. } => stride.clone(),
        };
        iter::from_fn(move || {
            let value = current.take()?;
            let hi = self.upper()?;
            if &value < hi && !step.is_zero() {
                current = Some(&value + &step);
            }
            Some(value)
        })
    }

    pub fn contains(&self, value: &BitVec) -> bool {
        match &self.0 {
            StridedIntervalRepr::Empty(_) => false,
            StridedIntervalRepr::Interval { lo, hi, stride } => {
                if value < lo || value > hi {
                    false
                } else if stride.is_zero() {
                    value == lo
                } else {
                    (&(value - lo) % stride).is_zero()
                }
            }
        }
    }

    pub fn width(&self) -> u32 {
        match &self.0 {
            StridedIntervalRepr::Empty(width) => *width,
            StridedIntervalRepr::Interval { lo, .. } => lo.bits(),
        }
    }

    pub fn count(&self) -> Option<usize> {
        match &self.0 {
            StridedIntervalRepr::Empty(_) => Some(0),
            StridedIntervalRepr::Interval { stride, .. } if stride.is_zero() => Some(1),
            StridedIntervalRepr::Interval { lo, hi, stride } => {
                let steps = usize::try_from((&(hi - lo) / stride).to_u64()?).ok()?;
                steps.checked_add(1)
            }
        }
    }

    pub fn meet(&self, other: &Self) -> Self {
        let (
            StridedIntervalRepr::Interval {
                lo: l1,
                hi: h1,
                stride: s1,
            },
            StridedIntervalRepr::Interval {
                lo: l2,
                hi: h2,
                stride: s2,
            },
        ) = (&self.0, &other.0)
        else {
            return Self(StridedIntervalRepr::Empty(self.width()));
        };
        let lo = l1.max(l2).clone();
        let hi = h1.min(h2).clone();
        if lo > hi {
            return Self(StridedIntervalRepr::Empty(self.width()));
        }
        Self::range(lo, hi, s1.gcd(s2))
    }

    pub fn join(&self, other: &Self) -> Self {
        let (
            StridedIntervalRepr::Interval {
                lo: l1,
                hi: h1,
                stride: s1,
            },
            StridedIntervalRepr::Interval {
                lo: l2,
                hi: h2,
                stride: s2,
            },
        ) = (&self.0, &other.0)
        else {
            return if self.is_empty() {
                other.clone()
            } else {
                self.clone()
            };
        };
        let lo = l1.min(l2).clone();
        let hi = h1.max(h2).clone();
        let offset = if l1 >= l2 { l1 - l2 } else { l2 - l1 };
        Self::range(lo, hi, s1.gcd(s2).gcd(&offset))
    }

    pub fn widen(&self, other: &Self) -> Self {
        let (
            StridedIntervalRepr::Interval {
                lo: l1,
                hi: h1,
                stride: s1,
            },
            StridedIntervalRepr::Interval {
                lo: l2,
                hi: h2,
                stride: s2,
            },
        ) = (&self.0, &other.0)
        else {
            return if self.is_empty() {
                other.clone()
            } else {
                self.clone()
            };
        };
        let bits = l1.bits();
        let lo = if l2 < l1 {
            BitVec::zero(bits)
        } else {
            l1.clone()
        };
        let hi = if h2 > h1 {
            BitVec::max_value_with(bits, false)
        } else {
            h1.clone()
        };
        let stride = s1.gcd(s2).gcd(&(l1 - &lo)).gcd(&(l2 - &lo));
        Self::range(lo, hi, stride)
    }

    pub fn cast_to(&self, width: u32) -> Self {
        if self.width() == width {
            self.clone()
        } else if width > self.width() {
            self.zero_extend(width)
        } else {
            self.truncate(width)
        }
    }

    pub fn zero_extend(&self, width: u32) -> Self {
        let StridedIntervalRepr::Interval { lo, hi, stride } = &self.0 else {
            return Self(StridedIntervalRepr::Empty(width));
        };
        Self::range(
            lo.clone().unsigned_cast(width),
            hi.clone().unsigned_cast(width),
            stride.clone().unsigned_cast(width),
        )
    }

    pub fn sign_extend(&self, width: u32) -> Self {
        let StridedIntervalRepr::Interval { lo, hi, stride } = &self.0 else {
            return Self(StridedIntervalRepr::Empty(width));
        };
        let sign = BitVec::min_value_with(lo.bits(), true);
        if (lo < &sign) != (hi < &sign) {
            return Self::full(width);
        }
        Self::range(
            lo.signed_cast(width).unsigned(),
            hi.signed_cast(width).unsigned(),
            stride.unsigned_cast(width),
        )
    }

    pub fn truncate(&self, width: u32) -> Self {
        let StridedIntervalRepr::Interval { lo, hi, stride } = &self.0 else {
            return Self(StridedIntervalRepr::Empty(width));
        };
        if width >= lo.bits() {
            return self.zero_extend(width);
        }
        let limit = BitVec::max_value_with(width, false).unsigned_cast(lo.bits());
        if hi > &limit {
            return Self::full(width);
        }
        Self::range(
            lo.clone().cast(width),
            hi.clone().cast(width),
            stride.clone().cast(width),
        )
    }

    pub fn add(&self, other: &Self) -> Self {
        let (
            StridedIntervalRepr::Interval {
                lo: l1,
                hi: h1,
                stride: s1,
            },
            StridedIntervalRepr::Interval {
                lo: l2,
                hi: h2,
                stride: s2,
            },
        ) = (&self.0, &other.0)
        else {
            return Self(StridedIntervalRepr::Empty(self.width()));
        };
        let headroom = &BitVec::max_value_with(l1.bits(), false) - h2;
        if h1 > &headroom {
            return Self::full(l1.bits());
        }
        Self::range(l1 + l2, h1 + h2, s1.gcd(s2))
    }

    pub fn sub(&self, other: &Self) -> Self {
        let (
            StridedIntervalRepr::Interval {
                lo: l1,
                hi: h1,
                stride: s1,
            },
            StridedIntervalRepr::Interval {
                lo: l2,
                hi: h2,
                stride: s2,
            },
        ) = (&self.0, &other.0)
        else {
            return Self(StridedIntervalRepr::Empty(self.width()));
        };
        if l1 < h2 {
            return Self::full(l1.bits());
        }
        Self::range(l1 - h2, h1 - l2, s1.gcd(s2))
    }

    pub fn mul(&self, other: &Self) -> Self {
        match (self.to_value(), other.to_value()) {
            (Some(factor), _) => other.scale(&factor),
            (_, Some(factor)) => self.scale(&factor),
            _ => Self::full(self.width()),
        }
    }

    pub fn shift_left(&self, amount: &Self) -> Self {
        match amount.to_value().and_then(|value| value.to_u64()) {
            Some(shift) if shift < u64::from(self.width()) => {
                let factor = BitVec::one(self.width()) << BitVec::from_u64(shift, self.width());
                self.scale(&factor)
            }
            _ => Self::full(self.width()),
        }
    }

    pub fn and(&self, other: &Self) -> Self {
        match (self.to_value(), other.to_value()) {
            (Some(a), Some(b)) => Self::single(a & b),
            (Some(mask), None) | (None, Some(mask)) => Self::masked(&mask),
            (None, None) => Self::full(self.width()),
        }
    }

    pub fn or(&self, other: &Self) -> Self {
        match (self.to_value(), other.to_value()) {
            (Some(a), Some(b)) => Self::single(a | b),
            _ => Self::full(self.width()),
        }
    }

    pub fn shift_right(&self, amount: &Self) -> Self {
        let Some(shift) = amount.to_value().and_then(|value| value.to_u64()) else {
            return Self::full(self.width());
        };
        if shift >= u64::from(self.width()) {
            return Self::single(BitVec::zero(self.width()));
        }
        let StridedIntervalRepr::Interval { lo, hi, .. } = &self.0 else {
            return Self(StridedIntervalRepr::Empty(self.width()));
        };
        let places = BitVec::from_u64(shift, self.width());
        Self::range(lo >> &places, hi >> &places, BitVec::one(self.width()))
    }

    fn scale(&self, factor: &BitVec) -> Self {
        let StridedIntervalRepr::Interval { lo, hi, stride } = &self.0 else {
            return Self(StridedIntervalRepr::Empty(self.width()));
        };
        if factor.is_zero() {
            return Self::single(BitVec::zero(lo.bits()));
        }
        let headroom = &BitVec::max_value_with(lo.bits(), false) / factor;
        if hi > &headroom {
            return Self::full(lo.bits());
        }
        Self::range(lo * factor, hi * factor, stride * factor)
    }

    fn to_value(&self) -> Option<BitVec> {
        match &self.0 {
            StridedIntervalRepr::Interval { lo, stride, .. } if stride.is_zero() => {
                Some(lo.clone())
            }
            _ => None,
        }
    }
}
