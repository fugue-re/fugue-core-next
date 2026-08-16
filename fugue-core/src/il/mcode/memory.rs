use std::mem::size_of;

use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct MCodeMemoryDomain {
    space: AddressSpaceId,
}

const _: () = assert!(size_of::<MCodeMemoryDomain>() <= 8);

impl MCodeMemoryDomain {
    pub(crate) const fn new(space: AddressSpaceId) -> Self {
        Self { space }
    }

    pub const fn space(&self) -> AddressSpaceId {
        self.space
    }
}
