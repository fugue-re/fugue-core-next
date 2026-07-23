use std::borrow::Cow;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::mem::ManuallyDrop;

use malachite::Natural;
use malachite::base::num::arithmetic::traits::{ModPowerOf2, ModPowerOf2Assign};
use serde::{Deserializer, Serializer};

pub const MAX_BITS: u32 = u32::MAX >> 1;

pub struct BitVec {
    value: Value,
    meta: u32,
}

union Value {
    small: u64,
    large: ManuallyDrop<Box<Natural>>,
}

impl BitVec {
    pub(crate) fn pack_meta(sign: bool, bits: u32) -> u32 {
        assert!(
            (1..=MAX_BITS).contains(&bits),
            "bits must be in 1..={MAX_BITS}"
        );
        (bits << 1) | sign as u32
    }

    pub(crate) fn meta(&self) -> u32 {
        self.meta
    }

    pub(crate) fn mask_u64(bits: u32) -> u64 {
        1u64.checked_shl(bits).unwrap_or(0).wrapping_sub(1)
    }

    pub(crate) fn from_small(value: u64, meta: u32) -> Self {
        debug_assert!(meta >> 1 <= 64);
        Self {
            value: Value {
                small: value & Self::mask_u64(meta >> 1),
            },
            meta,
        }
    }

    pub(crate) fn from_large(value: Natural, meta: u32) -> Self {
        debug_assert!(meta >> 1 > 64);
        Self {
            value: Value {
                large: ManuallyDrop::new(Box::new(value.mod_power_of_2((meta >> 1) as u64))),
            },
            meta,
        }
    }

    pub(crate) fn is_small(&self) -> bool {
        self.bits() <= 64
    }

    pub(crate) fn small(&self) -> u64 {
        debug_assert!(self.is_small());
        unsafe { self.value.small }
    }

    pub(crate) fn set_small(&mut self, value: u64) {
        debug_assert!(self.is_small());
        self.value.small = value & Self::mask_u64(self.bits());
    }

    pub(crate) fn large(&self) -> &Natural {
        debug_assert!(!self.is_small());
        unsafe { &self.value.large }
    }

    pub(crate) fn large_mut(&mut self) -> &mut Natural {
        debug_assert!(!self.is_small());
        unsafe { &mut self.value.large }
    }

    pub(crate) fn into_large(self) -> Natural {
        debug_assert!(!self.is_small());
        let mut this = ManuallyDrop::new(self);
        unsafe { *ManuallyDrop::take(&mut this.value.large) }
    }

    pub(crate) fn mask_large_assign(&mut self) {
        let bits = self.bits() as u64;
        self.large_mut().mod_power_of_2_assign(bits);
    }

    pub fn bits(&self) -> u32 {
        self.meta >> 1
    }

    pub fn is_signed(&self) -> bool {
        (self.meta & 1) != 0
    }

    pub fn is_unsigned(&self) -> bool {
        !self.is_signed()
    }

    pub fn signed(mut self) -> Self {
        self.signed_assign();
        self
    }

    pub fn signed_assign(&mut self) {
        self.meta |= 1;
    }

    pub fn unsigned(mut self) -> Self {
        self.unsigned_assign();
        self
    }

    pub fn unsigned_assign(&mut self) {
        self.meta &= !1;
    }
}

impl Drop for BitVec {
    fn drop(&mut self) {
        if !self.is_small() {
            unsafe { ManuallyDrop::drop(&mut self.value.large) }
        }
    }
}

impl Clone for BitVec {
    fn clone(&self) -> Self {
        let value = if self.is_small() {
            Value {
                small: self.small(),
            }
        } else {
            Value {
                large: ManuallyDrop::new(Box::new(self.large().clone())),
            }
        };
        Self {
            value,
            meta: self.meta,
        }
    }
}

impl PartialEq for BitVec {
    fn eq(&self, other: &Self) -> bool {
        if self.bits() != other.bits() {
            return false;
        }
        if self.is_small() {
            self.small() == other.small()
        } else {
            self.large() == other.large()
        }
    }
}

impl Eq for BitVec {}

impl Hash for BitVec {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bits().hash(state);
        if self.is_small() {
            self.small().hash(state);
        } else {
            self.large().hash(state);
        }
    }
}

impl fmt::Debug for BitVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut repr = f.debug_struct("BitVec");
        if self.is_small() {
            repr.field("value", &self.small());
        } else {
            repr.field("value", self.large());
        }
        repr.field("bits", &self.bits())
            .field("signed", &self.is_signed())
            .finish()
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
enum Encoded<'a> {
    Large { value: Cow<'a, Natural>, meta: u32 },
    Small { value: u64, meta: u32 },
}

impl serde::Serialize for BitVec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = if self.is_small() {
            Encoded::Small {
                value: self.small(),
                meta: self.meta,
            }
        } else {
            Encoded::Large {
                value: Cow::Borrowed(self.large()),
                meta: self.meta,
            }
        };
        encoded.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for BitVec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Encoded::deserialize(deserializer)? {
            Encoded::Small { value, meta } => {
                if !(1..=64).contains(&(meta >> 1)) {
                    return Err(serde::de::Error::custom("invalid bit vector size"));
                }
                Ok(Self::from_small(value, meta))
            }
            Encoded::Large { value, meta } => {
                if !(65..=MAX_BITS).contains(&(meta >> 1)) {
                    return Err(serde::de::Error::custom("invalid bit vector size"));
                }
                Ok(Self::from_large(value.into_owned(), meta))
            }
        }
    }
}
