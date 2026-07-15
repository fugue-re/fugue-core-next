use crate::il::llil::LlilError;

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(transparent)]
pub struct RegisterId(u32);

impl RegisterId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u32 {
        self.0
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(transparent)]
pub struct FlagId(u32);

impl FlagId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u32 {
        self.0
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct RegisterSlice {
    root: RegisterId,
    least_significant_bit: u32,
    width: u32,
}

impl RegisterSlice {
    pub const fn new(root: RegisterId, least_significant_bit: u32, width: u32) -> Self {
        Self {
            root,
            least_significant_bit,
            width,
        }
    }

    pub const fn root(&self) -> RegisterId {
        self.root
    }

    pub const fn least_significant_bit(&self) -> u32 {
        self.least_significant_bit
    }

    pub const fn width(&self) -> u32 {
        self.width
    }

    pub const fn end_bit(&self) -> u32 {
        self.least_significant_bit + self.width
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegisterBank {
    root_widths: Vec<u32>,
}

impl RegisterBank {
    pub fn new(root_widths: Vec<u32>) -> Self {
        Self { root_widths }
    }

    pub fn root_width(&self, register: RegisterId) -> Option<u32> {
        self.root_widths.get(register.value() as usize).copied()
    }

    pub fn verify_slice(&self, slice: RegisterSlice) -> Result<(), LlilError> {
        let Some(root_width) = self.root_width(slice.root()) else {
            return Err(LlilError::invalid_register_slice(
                slice.root().value(),
                slice.least_significant_bit(),
                slice.width(),
                0,
            ));
        };

        if slice.end_bit() > root_width {
            Err(LlilError::invalid_register_slice(
                slice.root().value(),
                slice.least_significant_bit(),
                slice.width(),
                root_width,
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_bank_accepts_slice_inside_root() {
        let bank = RegisterBank::new(vec![64]);
        let slice = RegisterSlice::new(RegisterId::new(0), 8, 16);

        assert_eq!(bank.verify_slice(slice), Ok(()));
    }

    #[test]
    fn register_bank_rejects_slice_past_root() {
        let bank = RegisterBank::new(vec![32]);
        let slice = RegisterSlice::new(RegisterId::new(0), 24, 16);

        assert!(matches!(
            bank.verify_slice(slice),
            Err(LlilError::InvalidRegisterSlice { .. })
        ));
    }
}
