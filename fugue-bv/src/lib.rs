use std::cmp::Ordering;
use std::fmt;
use std::mem;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};
use std::str::FromStr;

use fugue_bytes::ByteOrder;
use malachite::base::num::arithmetic::traits::{ExtendedGcd, Gcd, Lcm, ModPowerOf2, PowerOf2};
use malachite::base::num::basic::traits::{One, Zero};
use malachite::base::num::conversion::traits::{FromStringBase, PowerOf2Digits, WrappingFrom};
use malachite::base::num::logic::traits::{BitAccess, CountOnes, LowMask, SignificantBits};
use malachite::{Integer as BigInt, Natural};

use crate::error::{ParseError, TryFromBitVecError};

pub mod error;
mod repr;

pub use self::repr::{BitVec, MAX_BITS};

impl fmt::Display for BitVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_small() {
            write!(f, "{}:{}", self.small(), self.bits())
        } else {
            write!(f, "{}:{}", self.large(), self.bits())
        }
    }
}

impl fmt::LowerHex for BitVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_small() {
            write!(f, "{:#x}:{}", self.small(), self.bits())
        } else {
            write!(f, "{:#x}:{}", self.large(), self.bits())
        }
    }
}

impl fmt::UpperHex for BitVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_small() {
            write!(f, "{:#X}:{}", self.small(), self.bits())
        } else {
            write!(f, "{:#X}:{}", self.large(), self.bits())
        }
    }
}

impl fmt::Binary for BitVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_small() {
            write!(f, "{:#b}:{}", self.small(), self.bits())
        } else {
            write!(f, "{:#b}:{}", self.large(), self.bits())
        }
    }
}

impl FromStr for BitVec {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (cst, sz) = s.rsplit_once(':').ok_or(ParseError::InvalidFormat)?;

        let val = if let Some(cstv) = cst.strip_prefix("0x") {
            BigInt::from_string_base(16, cstv)
        } else {
            BigInt::from_string_base(10, cst)
        }
        .ok_or(ParseError::InvalidConst)?;

        let bits = sz.parse::<u32>().map_err(|_| ParseError::InvalidSize)?;
        if !(1..=MAX_BITS).contains(&bits) {
            return Err(ParseError::InvalidSize);
        }

        Ok(Self::from_bigint(val, bits))
    }
}

impl BitVec {
    pub fn from_str_radix(s: &str, radix: u32) -> Result<Self, ParseError> {
        let (cst, sz) = s.rsplit_once(':').ok_or(ParseError::InvalidFormat)?;
        let val = BigInt::from_string_base(radix as u8, cst).ok_or(ParseError::InvalidConst)?;

        let bits = sz.parse::<u32>().map_err(|_| ParseError::InvalidSize)?;
        if !(1..=MAX_BITS).contains(&bits) {
            return Err(ParseError::InvalidSize);
        }

        Ok(Self::from_bigint(val, bits))
    }

    pub fn from_bigint(value: BigInt, bits: u32) -> Self {
        let meta = Self::pack_meta(false, bits);
        let value = value.mod_power_of_2(bits as u64);
        if bits <= 64 {
            Self::from_small(
                u64::try_from(&value).expect("residue fits in 64 bits"),
                meta,
            )
        } else {
            Self::from_large(value, meta)
        }
    }

    pub fn to_bigint(&self) -> BigInt {
        if self.is_small() {
            BigInt::from(self.small())
        } else {
            BigInt::from(self.large().clone())
        }
    }

    pub fn zero(bits: u32) -> Self {
        Self::from_u64(0, bits)
    }

    pub fn one(bits: u32) -> Self {
        Self::from_u64(1, bits)
    }

    pub fn count_ones(&self) -> u32 {
        if self.is_small() {
            self.small().count_ones()
        } else {
            self.large().count_ones() as u32
        }
    }

    pub fn count_zeros(&self) -> u32 {
        self.bits() - self.count_ones()
    }

    fn significant_bits(&self) -> u32 {
        if self.is_small() {
            64 - self.small().leading_zeros()
        } else {
            self.large().significant_bits() as u32
        }
    }

    pub fn leading_zeros(&self) -> u32 {
        self.bits() - self.significant_bits()
    }

    pub fn leading_ones(&self) -> u32 {
        if self.is_small() {
            (self.small() << (64 - self.bits())).leading_ones()
        } else {
            let flipped = Natural::low_mask(self.bits() as u64) - self.large();
            self.bits() - flipped.significant_bits() as u32
        }
    }

    pub fn leading_one(&self) -> Option<u32> {
        self.significant_bits().checked_sub(1)
    }

    pub fn bit(&self, index: u32) -> bool {
        if self.is_small() {
            index < 64 && (self.small() >> index) & 1 != 0
        } else {
            self.large().get_bit(index as u64)
        }
    }

    pub fn set_bit(&mut self, index: u32) {
        if index >= self.bits() {
            return;
        }
        if self.is_small() {
            let value = self.small() | (1u64 << index);
            self.set_small(value);
        } else {
            self.large_mut().set_bit(index as u64);
        }
    }

    pub fn msb(&self) -> bool {
        self.bit(self.bits() - 1)
    }

    pub fn lsb(&self) -> bool {
        self.bit(0)
    }

    pub fn is_zero(&self) -> bool {
        if self.is_small() {
            self.small() == 0
        } else {
            *self.large() == Natural::ZERO
        }
    }

    pub fn is_one(&self) -> bool {
        if self.is_small() {
            self.small() == 1
        } else {
            *self.large() == Natural::ONE
        }
    }

    pub fn is_negative(&self) -> bool {
        self.is_signed() && self.msb()
    }

    pub fn bytes(&self) -> usize {
        self.bits().div_ceil(8) as usize
    }

    fn expect_buf_size(len: usize, bits: u32) {
        let size = bits.div_ceil(8) as usize;
        if len != size {
            panic!("invalid buf size {len}; expected {size}");
        }
    }

    pub fn from_be_bytes(buf: &[u8]) -> Self {
        Self::from_be_bytes_with(buf, buf.len() as u32 * 8)
    }

    pub fn from_be_bytes_with(buf: &[u8], bits: u32) -> Self {
        let meta = Self::pack_meta(false, bits);
        Self::expect_buf_size(buf.len(), bits);
        if bits <= 64 {
            let mut raw = [0u8; 8];
            raw[8 - buf.len()..].copy_from_slice(buf);
            Self::from_small(u64::from_be_bytes(raw), meta)
        } else {
            let value = Natural::from_power_of_2_digits_desc(8, buf.iter().copied())
                .expect("bytes are valid base-256 digits");
            Self::from_large(value, meta)
        }
    }

    pub fn from_le_bytes(buf: &[u8]) -> Self {
        Self::from_le_bytes_with(buf, buf.len() as u32 * 8)
    }

    pub fn from_le_bytes_with(buf: &[u8], bits: u32) -> Self {
        let meta = Self::pack_meta(false, bits);
        Self::expect_buf_size(buf.len(), bits);
        if bits <= 64 {
            let mut raw = [0u8; 8];
            raw[..buf.len()].copy_from_slice(buf);
            Self::from_small(u64::from_le_bytes(raw), meta)
        } else {
            let value = Natural::from_power_of_2_digits_asc(8, buf.iter().copied())
                .expect("bytes are valid base-256 digits");
            Self::from_large(value, meta)
        }
    }

    #[inline(always)]
    pub fn from_ne_bytes(buf: &[u8]) -> Self {
        if cfg!(target_endian = "big") {
            Self::from_be_bytes(buf)
        } else {
            Self::from_le_bytes(buf)
        }
    }

    #[inline(always)]
    pub fn from_ne_bytes_with(buf: &[u8], bits: u32) -> Self {
        if cfg!(target_endian = "big") {
            Self::from_be_bytes_with(buf, bits)
        } else {
            Self::from_le_bytes_with(buf, bits)
        }
    }

    pub fn to_be_bytes(&self, buf: &mut [u8]) {
        Self::expect_buf_size(buf.len(), self.bits());
        if self.is_small() {
            buf.copy_from_slice(&self.small().to_be_bytes()[8 - buf.len()..]);
        } else {
            let digits = self.large().to_power_of_2_digits_desc(8);
            let split = buf.len() - digits.len();
            buf[..split].fill(0);
            buf[split..].copy_from_slice(&digits);
        }
    }

    pub fn to_le_bytes(&self, buf: &mut [u8]) {
        Self::expect_buf_size(buf.len(), self.bits());
        if self.is_small() {
            buf.copy_from_slice(&self.small().to_le_bytes()[..buf.len()]);
        } else {
            let digits = self.large().to_power_of_2_digits_asc(8);
            buf[..digits.len()].copy_from_slice(&digits);
            buf[digits.len()..].fill(0);
        }
    }

    #[inline(always)]
    pub fn to_ne_bytes(&self, buf: &mut [u8]) {
        if cfg!(target_endian = "big") {
            self.to_be_bytes(buf)
        } else {
            self.to_le_bytes(buf)
        }
    }

    pub fn from_bytes<O: ByteOrder>(bytes: &[u8], signed: bool) -> Self {
        Self::from_bytes_with::<O>(bytes, bytes.len() as u32 * 8, signed)
    }

    pub fn from_bytes_with<O: ByteOrder>(bytes: &[u8], bits: u32, signed: bool) -> Self {
        let value = if O::ENDIAN.is_big() {
            Self::from_be_bytes_with(bytes, bits)
        } else {
            Self::from_le_bytes_with(bytes, bits)
        };

        if signed { value.signed() } else { value }
    }

    pub fn into_bytes<O: ByteOrder>(self, bytes: &mut [u8]) {
        if O::ENDIAN.is_big() {
            self.to_be_bytes(bytes)
        } else {
            self.to_le_bytes(bytes)
        }
    }

    pub fn incr(&self, value: u64) -> Self {
        self + &Self::from_u64(value, self.bits())
    }

    pub fn succ(&self) -> Self {
        self.incr(1)
    }

    pub fn decr(&self, value: u64) -> Self {
        self - &Self::from_u64(value, self.bits())
    }

    pub fn pred(&self) -> Self {
        self.decr(1)
    }

    pub fn abs(&self) -> Self {
        if self.is_negative() {
            -self
        } else {
            self.clone()
        }
    }

    fn expect_same_bits(&self, rhs: &Self, op: &str) {
        if self.bits() != rhs.bits() {
            panic!(
                "cannot use `{op}` with bit vector of size {} and bit vector of size {}",
                self.bits(),
                rhs.bits()
            );
        }
    }

    fn expect_comparable(&self, other: &Self) {
        if self.bits() != other.bits() {
            panic!(
                "bit vector of size {} cannot be compared with bit vector of size {}",
                self.bits(),
                other.bits()
            );
        }
    }

    fn small_signed(&self) -> i64 {
        let shift = 64 - self.bits();
        ((self.small() << shift) as i64) >> shift
    }

    fn large_signed(&self) -> BigInt {
        let value = BigInt::from(self.large().clone());
        if self.msb() {
            value - BigInt::power_of_2(self.bits() as u64)
        } else {
            value
        }
    }

    fn small_magnitude(&self) -> u64 {
        if self.msb() {
            (self.small() ^ Self::mask_u64(self.bits())).wrapping_add(1)
        } else {
            self.small()
        }
    }

    fn large_magnitude(&self) -> Natural {
        if self.msb() {
            Natural::power_of_2(self.bits() as u64) - self.large()
        } else {
            self.large().clone()
        }
    }

    pub fn lcm(&self, rhs: &Self) -> Self {
        self.expect_same_bits(rhs, "lcm");
        if self.is_small() {
            Self::from_small(
                Lcm::lcm(self.small_magnitude(), rhs.small_magnitude()),
                self.meta(),
            )
        } else {
            Self::from_large(
                Lcm::lcm(self.large_magnitude(), rhs.large_magnitude()),
                self.meta(),
            )
        }
    }

    pub fn gcd(&self, rhs: &Self) -> Self {
        self.expect_same_bits(rhs, "gcd");

        if self.is_zero() {
            return rhs.clone();
        }

        if rhs.is_zero() {
            return self.clone();
        }

        if self.is_small() {
            Self::from_small(
                Gcd::gcd(self.small_magnitude(), rhs.small_magnitude()),
                self.meta(),
            )
        } else {
            Self::from_large(
                Gcd::gcd(self.large_magnitude(), rhs.large_magnitude()),
                self.meta(),
            )
        }
    }

    pub fn gcd_ext(&self, rhs: &Self) -> (Self, Self, Self) {
        self.expect_same_bits(rhs, "gcd_ext");

        if self.is_zero() {
            return (rhs.clone(), Self::zero(self.bits()), Self::one(self.bits()));
        }

        if rhs.is_zero() {
            return (
                self.clone(),
                Self::one(self.bits()),
                Self::zero(self.bits()),
            );
        }

        if self.is_small() {
            let (gcd, x, y) = ExtendedGcd::extended_gcd(self.small_signed(), rhs.small_signed());
            (
                Self::from_small(gcd, self.meta()),
                Self::from_small(u64::wrapping_from(x), self.meta()),
                Self::from_small(u64::wrapping_from(y), self.meta()),
            )
        } else {
            let bits = self.bits() as u64;
            let (gcd, x, y) = ExtendedGcd::extended_gcd(self.large_signed(), rhs.large_signed());
            (
                Self::from_large(gcd, self.meta()),
                Self::from_large(x.mod_power_of_2(bits), self.meta()),
                Self::from_large(y.mod_power_of_2(bits), self.meta()),
            )
        }
    }

    pub fn signed_borrow(&self, rhs: &Self) -> bool {
        self.expect_same_bits(rhs, "signed_borrow");

        let mut l = self.msb();
        let r = rhs.msb();
        let mut v = (self - rhs).msb();

        l ^= v;
        v ^= r;
        v ^= true;
        l &= v;
        l
    }

    pub fn carry(&self, rhs: &Self) -> bool {
        self.expect_same_bits(rhs, "carry");
        if self.is_signed() || rhs.is_signed() {
            self.signed_carry(rhs)
        } else {
            self.cmp_residue(&(self + rhs)) == Ordering::Greater
        }
    }

    pub fn signed_carry(&self, rhs: &Self) -> bool {
        self.expect_same_bits(rhs, "signed_carry");

        let mut l = self.msb();
        let r = rhs.msb();
        let mut v = (self + rhs).msb();

        v ^= l;
        l ^= r;
        l ^= true;
        v &= l;
        v
    }

    pub fn rem_euclid(&self, rhs: &Self) -> Self {
        self.expect_same_bits(rhs, "rem_euclid");

        let r = self.rem(rhs);

        if r.msb() {
            r + if rhs.msb() { -rhs } else { rhs.clone() }
        } else {
            r
        }
    }

    pub fn max_value_with(bits: u32, signed: bool) -> Self {
        let meta = Self::pack_meta(signed, bits);
        if bits <= 64 {
            let mask = Self::mask_u64(bits);
            Self::from_small(if signed { mask >> 1 } else { mask }, meta)
        } else {
            let mask = Natural::low_mask(bits as u64);
            Self::from_large(if signed { mask >> 1u64 } else { mask }, meta)
        }
    }

    pub fn max_value(&self) -> Self {
        Self::max_value_with(self.bits(), self.is_signed())
    }

    pub fn min_value_with(bits: u32, signed: bool) -> Self {
        let meta = Self::pack_meta(signed, bits);
        if !signed {
            if bits <= 64 {
                Self::from_small(0, meta)
            } else {
                Self::from_large(Natural::ZERO, meta)
            }
        } else if bits <= 64 {
            Self::from_small(1u64 << (bits - 1), meta)
        } else {
            Self::from_large(Natural::power_of_2((bits - 1) as u64), meta)
        }
    }

    pub fn min_value(&self) -> Self {
        Self::min_value_with(self.bits(), self.is_signed())
    }

    pub fn signed_cast(&self, bits: u32) -> Self {
        self.clone().signed().cast(bits)
    }

    pub fn unsigned_cast(&self, bits: u32) -> Self {
        self.clone().unsigned().cast(bits)
    }

    pub fn signed_cast_assign(&mut self, bits: u32) {
        self.signed_assign();
        self.cast_assign(bits);
    }

    pub fn unsigned_cast_assign(&mut self, bits: u32) {
        self.unsigned_assign();
        self.cast_assign(bits);
    }

    pub fn cast(self, bits: u32) -> Self {
        let meta = Self::pack_meta(self.is_signed(), bits);
        let extend = self.is_signed() && bits > self.bits() && self.msb();
        match (self.is_small(), bits <= 64) {
            (true, true) => {
                let value = if extend {
                    self.small() | (Self::mask_u64(bits) ^ Self::mask_u64(self.bits()))
                } else {
                    self.small()
                };
                Self::from_small(value, meta)
            }
            (true, false) => {
                let mut value = Natural::from(self.small());
                if extend {
                    value |= Natural::low_mask(bits as u64) - Natural::low_mask(self.bits() as u64);
                }
                Self::from_large(value, meta)
            }
            (false, true) => {
                let value = u64::try_from(&self.large().mod_power_of_2(bits as u64))
                    .expect("residue fits in 64 bits");
                Self::from_small(value, meta)
            }
            (false, false) => {
                let from_bits = self.bits();
                let mut value = self.into_large();
                if extend {
                    value |= Natural::low_mask(bits as u64) - Natural::low_mask(from_bits as u64);
                }
                Self::from_large(value, meta)
            }
        }
    }

    pub fn cast_assign(&mut self, bits: u32) {
        let this = mem::replace(self, Self::zero(1));
        *self = this.cast(bits);
    }

    fn cmp_residue(&self, other: &Self) -> Ordering {
        if self.is_small() {
            self.small().cmp(&other.small())
        } else {
            self.large().cmp(other.large())
        }
    }

    fn cmp_with(&self, other: &Self, lneg: bool, rneg: bool) -> Ordering {
        match (lneg, rneg) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => self.cmp_residue(other),
        }
    }

    pub fn signed_cmp(&self, other: &Self) -> Ordering {
        self.expect_comparable(other);
        self.cmp_with(other, self.msb(), other.msb())
    }

    fn shift_amount(&self, width: u32) -> Option<u32> {
        let amount = if self.is_small() {
            u32::try_from(self.small()).ok()
        } else {
            u32::try_from(self.large()).ok()
        };
        amount.filter(|amount| *amount < width)
    }

    fn shr_assign_with(&mut self, arithmetic: bool, rhs: u32) {
        let bits = self.bits();
        let fill = arithmetic && self.msb();
        if rhs >= bits {
            if self.is_small() {
                self.set_small(if fill { u64::MAX } else { 0 });
            } else {
                *self.large_mut() = if fill {
                    Natural::low_mask(bits as u64)
                } else {
                    Natural::ZERO
                };
            }
        } else if self.is_small() {
            let mask = Self::mask_u64(bits);
            let value = self.small() >> rhs;
            self.set_small(if fill {
                value | (mask ^ (mask >> rhs))
            } else {
                value
            });
        } else {
            *self.large_mut() >>= rhs;
            if fill {
                let high = Natural::low_mask(bits as u64) ^ Natural::low_mask((bits - rhs) as u64);
                *self.large_mut() |= high;
            }
        }
    }

    pub fn signed_shr(&self, rhs: &Self) -> Self {
        let mut value = self.clone();
        value.signed_shr_assign(rhs);
        value
    }

    pub fn signed_shr_assign(&mut self, rhs: &Self) {
        self.expect_same_bits(rhs, ">>");
        let amount = rhs.shift_amount(self.bits()).unwrap_or(self.bits());
        self.shr_assign_with(true, amount);
    }

    fn udiv_assign(&mut self, rhs: &Self) {
        if self.is_small() {
            self.set_small(self.small() / rhs.small());
        } else {
            *self.large_mut() /= rhs.large();
        }
    }

    fn urem_assign(&mut self, rhs: &Self) {
        if self.is_small() {
            self.set_small(self.small() % rhs.small());
        } else {
            *self.large_mut() %= rhs.large();
        }
    }

    fn div_assign_with(&mut self, lneg: bool, rneg: bool, rhs: &Self) {
        match (lneg, rneg) {
            (false, false) => self.udiv_assign(rhs),
            (true, false) => {
                self.neg_assign();
                self.udiv_assign(rhs);
                self.neg_assign();
            }
            (false, true) => {
                self.udiv_assign(&-rhs);
                self.neg_assign();
            }
            (true, true) => {
                self.neg_assign();
                self.udiv_assign(&-rhs);
            }
        }
    }

    fn rem_assign_with(&mut self, lneg: bool, rneg: bool, rhs: &Self) {
        match (lneg, rneg) {
            (false, false) => self.urem_assign(rhs),
            (true, false) => {
                self.neg_assign();
                self.urem_assign(rhs);
                self.neg_assign();
            }
            (false, true) => self.urem_assign(&-rhs),
            (true, true) => {
                self.neg_assign();
                self.urem_assign(&-rhs);
                self.neg_assign();
            }
        }
    }

    pub fn signed_div(&self, rhs: &Self) -> Self {
        let mut value = self.clone();
        value.signed_div_assign(rhs);
        value
    }

    pub fn signed_div_assign(&mut self, rhs: &Self) {
        self.expect_same_bits(rhs, "/");
        let lneg = self.msb();
        let rneg = rhs.msb();
        self.div_assign_with(lneg, rneg, rhs);
    }

    pub fn signed_rem(&self, rhs: &Self) -> Self {
        let mut value = self.clone();
        value.signed_rem_assign(rhs);
        value
    }

    pub fn signed_rem_assign(&mut self, rhs: &Self) {
        self.expect_same_bits(rhs, "%");
        let lneg = self.msb();
        let rneg = rhs.msb();
        self.rem_assign_with(lneg, rneg, rhs);
    }

    pub fn neg_assign(&mut self) {
        if self.is_small() {
            let mask = Self::mask_u64(self.bits());
            self.set_small((self.small() ^ mask).wrapping_add(1));
        } else {
            let bits = self.bits() as u64;
            let value = self.large_mut();
            if *value != Natural::ZERO {
                *value = Natural::power_of_2(bits) - &*value;
            }
        }
    }

    pub fn not_assign(&mut self) {
        if self.is_small() {
            let mask = Self::mask_u64(self.bits());
            self.set_small(self.small() ^ mask);
        } else {
            let bits = self.bits() as u64;
            let value = self.large_mut();
            *value = Natural::low_mask(bits) - &*value;
        }
    }
}

impl PartialOrd for BitVec {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BitVec {
    fn cmp(&self, other: &Self) -> Ordering {
        self.expect_comparable(other);
        self.cmp_with(other, self.is_negative(), other.is_negative())
    }
}

impl Neg for BitVec {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        self.neg_assign();
        self
    }
}

impl Neg for &BitVec {
    type Output = BitVec;

    fn neg(self) -> Self::Output {
        let mut value = self.clone();
        value.neg_assign();
        value
    }
}

impl Not for BitVec {
    type Output = Self;

    fn not(mut self) -> Self::Output {
        self.not_assign();
        self
    }
}

impl Not for &BitVec {
    type Output = BitVec;

    fn not(self) -> Self::Output {
        let mut value = self.clone();
        value.not_assign();
        value
    }
}

macro_rules! impl_binop {
    ($op:ident, $f:ident, $opa:ident, $fa:ident) => {
        impl $op for BitVec {
            type Output = BitVec;

            fn $f(mut self, rhs: Self) -> Self::Output {
                $opa::<&BitVec>::$fa(&mut self, &rhs);
                self
            }
        }

        impl $op for &BitVec {
            type Output = BitVec;

            fn $f(self, rhs: Self) -> Self::Output {
                let mut value = self.clone();
                $opa::<&BitVec>::$fa(&mut value, rhs);
                value
            }
        }

        impl $opa for BitVec {
            fn $fa(&mut self, rhs: Self) {
                $opa::<&BitVec>::$fa(self, &rhs);
            }
        }
    };
}

impl_binop!(Add, add, AddAssign, add_assign);
impl_binop!(Sub, sub, SubAssign, sub_assign);
impl_binop!(Mul, mul, MulAssign, mul_assign);
impl_binop!(Div, div, DivAssign, div_assign);
impl_binop!(Rem, rem, RemAssign, rem_assign);
impl_binop!(BitAnd, bitand, BitAndAssign, bitand_assign);
impl_binop!(BitOr, bitor, BitOrAssign, bitor_assign);
impl_binop!(BitXor, bitxor, BitXorAssign, bitxor_assign);
impl_binop!(Shl, shl, ShlAssign, shl_assign);
impl_binop!(Shr, shr, ShrAssign, shr_assign);

impl AddAssign<&BitVec> for BitVec {
    fn add_assign(&mut self, rhs: &BitVec) {
        self.expect_same_bits(rhs, "+");
        if self.is_small() {
            self.set_small(self.small().wrapping_add(rhs.small()));
        } else {
            *self.large_mut() += rhs.large();
            self.mask_large_assign();
        }
    }
}

impl SubAssign<&BitVec> for BitVec {
    fn sub_assign(&mut self, rhs: &BitVec) {
        self.expect_same_bits(rhs, "-");
        if self.is_small() {
            self.set_small(self.small().wrapping_sub(rhs.small()));
        } else {
            let bits = self.bits() as u64;
            let value = self.large_mut();
            if *value >= *rhs.large() {
                *value -= rhs.large();
            } else {
                *value = Natural::power_of_2(bits) - (rhs.large() - &*value);
            }
        }
    }
}

impl MulAssign<&BitVec> for BitVec {
    fn mul_assign(&mut self, rhs: &BitVec) {
        self.expect_same_bits(rhs, "*");
        if self.is_small() {
            self.set_small(self.small().wrapping_mul(rhs.small()));
        } else {
            *self.large_mut() *= rhs.large();
            self.mask_large_assign();
        }
    }
}

impl DivAssign<&BitVec> for BitVec {
    fn div_assign(&mut self, rhs: &BitVec) {
        self.expect_same_bits(rhs, "/");
        let lneg = self.is_negative();
        let rneg = rhs.is_negative();
        self.div_assign_with(lneg, rneg, rhs);
    }
}

impl RemAssign<&BitVec> for BitVec {
    fn rem_assign(&mut self, rhs: &BitVec) {
        self.expect_same_bits(rhs, "%");
        let lneg = self.is_negative();
        let rneg = rhs.is_negative();
        self.rem_assign_with(lneg, rneg, rhs);
    }
}

impl BitAndAssign<&BitVec> for BitVec {
    fn bitand_assign(&mut self, rhs: &BitVec) {
        self.expect_same_bits(rhs, "&");
        if self.is_small() {
            self.set_small(self.small() & rhs.small());
        } else {
            *self.large_mut() &= rhs.large();
        }
    }
}

impl BitOrAssign<&BitVec> for BitVec {
    fn bitor_assign(&mut self, rhs: &BitVec) {
        self.expect_same_bits(rhs, "|");
        if self.is_small() {
            self.set_small(self.small() | rhs.small());
        } else {
            *self.large_mut() |= rhs.large();
        }
    }
}

impl BitXorAssign<&BitVec> for BitVec {
    fn bitxor_assign(&mut self, rhs: &BitVec) {
        self.expect_same_bits(rhs, "^");
        if self.is_small() {
            self.set_small(self.small() ^ rhs.small());
        } else {
            *self.large_mut() ^= rhs.large();
        }
    }
}

impl ShlAssign<&BitVec> for BitVec {
    fn shl_assign(&mut self, rhs: &BitVec) {
        self.expect_same_bits(rhs, "<<");
        let amount = rhs.shift_amount(self.bits()).unwrap_or(self.bits());
        ShlAssign::<u32>::shl_assign(self, amount);
    }
}

impl ShrAssign<&BitVec> for BitVec {
    fn shr_assign(&mut self, rhs: &BitVec) {
        self.expect_same_bits(rhs, ">>");
        let amount = rhs.shift_amount(self.bits()).unwrap_or(self.bits());
        self.shr_assign_with(self.is_signed(), amount);
    }
}

impl ShlAssign<u32> for BitVec {
    fn shl_assign(&mut self, rhs: u32) {
        if self.is_small() {
            self.set_small(self.small().checked_shl(rhs).unwrap_or(0));
        } else if rhs >= self.bits() {
            *self.large_mut() = Natural::ZERO;
        } else {
            *self.large_mut() <<= rhs;
            self.mask_large_assign();
        }
    }
}

impl Shl<u32> for BitVec {
    type Output = Self;

    fn shl(mut self, rhs: u32) -> Self::Output {
        ShlAssign::<u32>::shl_assign(&mut self, rhs);
        self
    }
}

impl Shl<u32> for &BitVec {
    type Output = BitVec;

    fn shl(self, rhs: u32) -> Self::Output {
        let mut value = self.clone();
        ShlAssign::<u32>::shl_assign(&mut value, rhs);
        value
    }
}

impl ShrAssign<u32> for BitVec {
    fn shr_assign(&mut self, rhs: u32) {
        self.shr_assign_with(self.is_signed(), rhs);
    }
}

impl Shr<u32> for BitVec {
    type Output = Self;

    fn shr(mut self, rhs: u32) -> Self::Output {
        ShrAssign::<u32>::shr_assign(&mut self, rhs);
        self
    }
}

impl Shr<u32> for &BitVec {
    type Output = BitVec;

    fn shr(self, rhs: u32) -> Self::Output {
        let mut value = self.clone();
        ShrAssign::<u32>::shr_assign(&mut value, rhs);
        value
    }
}

macro_rules! impl_from_prim {
    ($($t:ident),* $(,)?) => {$(
        ::paste::paste! {
            impl BitVec {
                pub fn [<from_ $t>](value: $t, bits: u32) -> Self {
                    let meta = Self::pack_meta(false, bits);
                    if bits <= 64 {
                        Self::from_small(u64::wrapping_from(value), meta)
                    } else {
                        Self::from_large(BigInt::from(value).mod_power_of_2(bits as u64), meta)
                    }
                }
            }

            impl From<$t> for BitVec {
                fn from(value: $t) -> Self {
                    Self::[<from_ $t>](value, $t::BITS)
                }
            }
        }
    )*};
}

macro_rules! impl_to_uint {
    ($($t:tt),* $(,)?) => {$(
        ::paste::paste! {
            impl BitVec {
                pub fn [<to_u $t>](&self) -> Option<[<u $t>]> {
                    if self.is_small() {
                        [<u $t>]::try_from(self.small()).ok()
                    } else {
                        [<u $t>]::try_from(self.large()).ok()
                    }
                }
            }

            impl TryFrom<&'_ BitVec> for [<u $t>] {
                type Error = TryFromBitVecError;

                fn try_from(bv: &BitVec) -> Result<[<u $t>], TryFromBitVecError> {
                    bv.[<to_u $t>]().ok_or(TryFromBitVecError)
                }
            }

            impl TryFrom<BitVec> for [<u $t>] {
                type Error = TryFromBitVecError;

                fn try_from(bv: BitVec) -> Result<[<u $t>], TryFromBitVecError> {
                    bv.[<to_u $t>]().ok_or(TryFromBitVecError)
                }
            }
        }
    )*};
}

macro_rules! impl_to_int {
    ($($t:tt),* $(,)?) => {$(
        ::paste::paste! {
            impl BitVec {
                pub fn [<to_i $t>](&self) -> Option<[<i $t>]> {
                    if self.is_small() {
                        [<i $t>]::try_from(self.small_signed()).ok()
                    } else {
                        [<i $t>]::try_from(&self.large_signed()).ok()
                    }
                }
            }

            impl TryFrom<&'_ BitVec> for [<i $t>] {
                type Error = TryFromBitVecError;

                fn try_from(bv: &BitVec) -> Result<[<i $t>], TryFromBitVecError> {
                    bv.[<to_i $t>]().ok_or(TryFromBitVecError)
                }
            }

            impl TryFrom<BitVec> for [<i $t>] {
                type Error = TryFromBitVecError;

                fn try_from(bv: BitVec) -> Result<[<i $t>], TryFromBitVecError> {
                    bv.[<to_i $t>]().ok_or(TryFromBitVecError)
                }
            }
        }
    )*};
}

impl_from_prim! { i8, i16, i32, i64, i128, isize }
impl_from_prim! { u8, u16, u32, u64, u128, usize }

impl_to_int! { 8, 16, 32, 64, 128, size }
impl_to_uint! { 8, 16, 32, 64, 128, size }
