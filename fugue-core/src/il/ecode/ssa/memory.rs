use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ECodeSsaMemoryDomain {
    space: AddressSpaceId,
}

impl ECodeSsaMemoryDomain {
    pub(crate) const fn new(space: AddressSpaceId) -> Self {
        Self { space }
    }

    pub const fn space(&self) -> AddressSpaceId {
        self.space
    }
}
