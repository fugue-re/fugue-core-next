use crate::il::common::{FlagId, RegisterId};
use crate::storage::segments::space::AddressSpaceId;

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
pub enum ECodeDomain {
    Flag(FlagId),
    Memory(AddressSpaceId),
    Register(RegisterId),
}

impl ECodeDomain {
    pub const fn is_memory(&self) -> bool {
        matches!(self, Self::Memory(_))
    }

    pub const fn is_flag(&self) -> bool {
        matches!(self, Self::Flag(_))
    }

    pub const fn is_register(&self) -> bool {
        matches!(self, Self::Register(_))
    }

    pub const fn is_register_or_flag(&self) -> bool {
        matches!(self, Self::Flag(_) | Self::Register(_))
    }
}
