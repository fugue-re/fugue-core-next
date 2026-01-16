use crate::ir::SegmentProperties;

use super::{SegmentStorageError, SegmentStorageProvider};

pub type SegmentStorageProviderId = u32;

pub struct SegmentStorageDescriptor {
    id: SegmentStorageProviderId,
    provider: Box<dyn SegmentStorageProvider>,
    permissions: SegmentProperties,
}

impl SegmentStorageDescriptor {
    pub fn new(
        id: SegmentStorageProviderId,
        provider: impl SegmentStorageProvider + 'static,
        permissions: SegmentProperties,
    ) -> Self {
        Self {
            id,
            provider: Box::new(provider),
            permissions,
        }
    }

    pub fn from_boxed(
        id: SegmentStorageProviderId,
        provider: Box<dyn SegmentStorageProvider>,
        permissions: SegmentProperties,
    ) -> Self {
        Self {
            id,
            provider,
            permissions,
        }
    }

    pub fn id(&self) -> SegmentStorageProviderId {
        self.id
    }

    pub fn permissions(&self) -> SegmentProperties {
        self.permissions
    }

    pub fn set_permissions(&mut self, permissions: SegmentProperties) {
        self.permissions = permissions;
    }

    pub fn provider(&self) -> &dyn SegmentStorageProvider {
        &*self.provider
    }

    pub fn provider_mut(&mut self) -> &mut dyn SegmentStorageProvider {
        &mut *self.provider
    }

    pub fn size(&self) -> usize {
        self.provider.size()
    }

    pub fn resize(&mut self, new_size: u64) -> Result<(), SegmentStorageError> {
        self.provider.resize(new_size)
    }

    pub fn flush(&mut self) -> Result<(), SegmentStorageError> {
        self.provider.flush()
    }
}

impl std::fmt::Debug for SegmentStorageDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegmentStorageDescriptor")
            .field("id", &self.id)
            .field("permissions", &self.permissions)
            .finish()
    }
}
