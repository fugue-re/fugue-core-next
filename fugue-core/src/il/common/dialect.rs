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
pub struct DialectId(u16);

impl DialectId {
    pub const TEST: Self = Self(0);
    pub const PCODE: Self = Self(1);
    pub const LLIL: Self = Self(2);
    pub const LLIL_SSA: Self = Self(3);
    pub const MAPPED_MLIL: Self = Self(4);
    pub const MLIL: Self = Self(5);

    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u16 {
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
pub struct SchemaVersion(u16);

impl SchemaVersion {
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u16 {
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
#[repr(u8)]
pub enum IrLevel {
    PCode = 0,
    Llil = 1,
    LlilSsa = 2,
    MappedMlil = 3,
    Mlil = 4,
}

impl IrLevel {
    pub const ALL: [Self; 5] = [
        Self::PCode,
        Self::Llil,
        Self::LlilSsa,
        Self::MappedMlil,
        Self::Mlil,
    ];

    pub const fn dialect_id(&self) -> DialectId {
        match self {
            Self::PCode => DialectId::PCODE,
            Self::Llil => DialectId::LLIL,
            Self::LlilSsa => DialectId::LLIL_SSA,
            Self::MappedMlil => DialectId::MAPPED_MLIL,
            Self::Mlil => DialectId::MLIL,
        }
    }

    pub const fn name(&self) -> &'static str {
        match self {
            Self::PCode => "pcode",
            Self::Llil => "llil",
            Self::LlilSsa => "llil_ssa",
            Self::MappedMlil => "mapped_mlil",
            Self::Mlil => "mlil",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "pcode" => Some(Self::PCode),
            "llil" => Some(Self::Llil),
            "llil_ssa" => Some(Self::LlilSsa),
            "mapped_mlil" => Some(Self::MappedMlil),
            "mlil" => Some(Self::Mlil),
            _ => None,
        }
    }

    pub fn descendants_from(self) -> impl Iterator<Item = Self> {
        Self::ALL.into_iter().filter(move |level| *level >= self)
    }

    pub const fn parent(self) -> Option<Self> {
        match self {
            Self::PCode => None,
            Self::Llil => Some(Self::PCode),
            Self::LlilSsa => Some(Self::Llil),
            Self::MappedMlil => Some(Self::LlilSsa),
            Self::Mlil => Some(Self::MappedMlil),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::IrLevel;

    #[test]
    fn ir_level_names_round_trip() {
        for level in IrLevel::ALL {
            assert_eq!(IrLevel::from_name(level.name()), Some(level));
        }

        assert_eq!(IrLevel::from_name(""), None);
    }
}
