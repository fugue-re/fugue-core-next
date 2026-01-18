use std::borrow::Cow;
use std::fmt::Debug;
use std::path::Path;

use crate::ir::SegmentProperties;
use crate::loader::Loadable;
use crate::types::AttributeMap;

use super::SegmentStorageError;

pub mod memmap;
pub use memmap::MemoryMappedSegmentStorage;

pub mod memory;
pub use memory::InMemorySegmentStorage;

pub type SegmentStorageProviderId = u32;

pub struct SegmentStorageDescriptor {
    id: SegmentStorageProviderId,
    provider: Box<dyn SegmentStorageProvider>,
    permissions: SegmentProperties,
}

impl Debug for SegmentStorageDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegmentStorageDescriptor")
            .field("id", &self.id)
            .field("permissions", &self.permissions)
            .finish()
    }
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

    pub fn size(&self) -> u64 {
        self.provider.size()
    }

    pub fn resize(&mut self, new_size: u64) -> Result<(), SegmentStorageError> {
        self.provider.resize(new_size)
    }

    pub fn flush(&mut self) -> Result<(), SegmentStorageError> {
        self.provider.flush()
    }
}

pub trait SegmentStorageProviderFromLoadable: SegmentStorageProvider + 'static {
    fn from_loadable(
        loader: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError>
    where
        Self: Sized;
}

pub trait SegmentStorageProviderFromStorage: SegmentStorageProviderFromLoadable {
    fn from_storage(
        path: impl AsRef<Path>,
        attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError>
    where
        Self: Sized;
}

pub trait SegmentStorageProvider {
    fn read_bytes(&self, offset: u64, bytes: &mut [u8]) -> Result<usize, SegmentStorageError>;

    fn read_bytes_exact(&self, offset: u64, bytes: &mut [u8]) -> Result<(), SegmentStorageError> {
        if self.read_bytes(offset, bytes)? != bytes.len() {
            return Err(SegmentStorageError::InvalidAddressRange);
        }
        Ok(())
    }

    fn write_bytes(&mut self, offset: u64, bytes: &[u8]) -> Result<usize, SegmentStorageError>;

    fn write_bytes_exact(&mut self, offset: u64, bytes: &[u8]) -> Result<(), SegmentStorageError> {
        if self.write_bytes(offset, bytes)? != bytes.len() {
            return Err(SegmentStorageError::InvalidAddressRange);
        }
        Ok(())
    }

    fn view_bytes(&self, offset: u64, n: usize) -> Result<Cow<'_, [u8]>, SegmentStorageError>;

    fn view_bytes_from(&self, offset: u64) -> Result<Cow<'_, [u8]>, SegmentStorageError>;

    fn size(&self) -> u64;

    fn resize(&mut self, _new_size: u64) -> Result<(), SegmentStorageError> {
        Err(SegmentStorageError::backing_with("resize not supported"))
    }

    fn flush(&mut self) -> Result<(), SegmentStorageError> {
        Ok(())
    }
}
