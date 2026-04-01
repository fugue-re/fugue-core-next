use std::fmt;
use std::ops::{Add, AddAssign};

use bincode::{Decode, Encode};

use crate::il::pcode::Varnode;
use crate::ir::{Address, MetaAddress};
use crate::lifter::Language;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Decode, Encode)]
pub struct Location {
    address: MetaAddress,
    position: u16,
}

impl Default for Location {
    fn default() -> Self {
        MetaAddress::default().into()
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.address, self.position)
    }
}

impl AsRef<Location> for Location {
    fn as_ref(&self) -> &Location {
        self
    }
}

impl AsRef<Address> for Location {
    fn as_ref(&self) -> &Address {
        self.address.as_ref()
    }
}

impl Add<u16> for Location {
    type Output = Self;

    fn add(self, rhs: u16) -> Self::Output {
        Self {
            position: self.position + rhs,
            ..self
        }
    }
}

impl AddAssign<u16> for Location {
    fn add_assign(&mut self, rhs: u16) {
        self.position += rhs;
    }
}

impl Add<usize> for Location {
    type Output = Self;

    fn add(self, rhs: usize) -> Self::Output {
        Self {
            position: self.position + rhs as u16,
            ..self
        }
    }
}

impl AddAssign<usize> for Location {
    fn add_assign(&mut self, rhs: usize) {
        self.position += rhs as u16;
    }
}

impl Location {
    pub fn new(address: impl Into<MetaAddress>, position: u16) -> Location {
        Self {
            address: address.into(),
            position,
        }
    }

    pub fn address(&self) -> MetaAddress {
        self.address
    }

    pub fn position(&self) -> u16 {
        self.position
    }

    pub fn absolute_from(
        language: &Language,
        base: MetaAddress,
        address: Varnode,
        position: u16,
    ) -> Option<Self> {
        if language.in_default_space(&address) {
            return Some(Self::new(MetaAddress::new(base.space(), address.offset()), 0));
        }

        if !language.in_constant_space(&address) {
            return None;
        }

        let offset = address.offset() as i64;
        let position = if offset.is_negative() {
            position
                .checked_sub(offset.unsigned_abs() as u16)
                .expect("negative offset from position in valid range")
        } else {
            position
                .checked_add(offset as u16)
                .expect("positive offset from position in valid range")
        };

        Some(Self {
            address: base,
            position,
        })
    }
}

impl From<MetaAddress> for Location {
    fn from(value: MetaAddress) -> Self {
        Self {
            address: value,
            position: 0,
        }
    }
}
