use crate::il::common::{RegisterBank, RegisterId};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MCodeStorageLocation {
    Register(RegisterId),
    RegisterPair { high: RegisterId, low: RegisterId },
    Stack { offset: i64 },
}

impl MCodeStorageLocation {
    pub(crate) fn register_width(&self, registers: &RegisterBank) -> Option<u32> {
        match *self {
            Self::Register(register) => registers.root_bits(register),
            Self::RegisterPair { high, low } => registers.root_bits(high).and_then(|high| {
                registers
                    .root_bits(low)
                    .and_then(|low| high.checked_add(low))
            }),
            Self::Stack { .. } => None,
        }
    }
}
