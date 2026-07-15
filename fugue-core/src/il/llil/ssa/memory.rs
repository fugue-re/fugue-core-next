use crate::storage::segments::space::AddressSpaceId;

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
pub struct MemoryDomain {
    space: AddressSpaceId,
}

impl MemoryDomain {
    pub const fn new(space: AddressSpaceId) -> Self {
        Self { space }
    }

    pub const fn space(&self) -> AddressSpaceId {
        self.space
    }
}
