use std::borrow::Cow;
use std::fmt::Debug;
use std::path::Path;

use crate::ir::{Address, SegmentProperties};
use crate::loader::Loadable;
use crate::types::AttributeMap;

use super::SegmentStorageError;

pub mod memmap;
pub use memmap::MemoryMappedSegmentStorage;

pub mod memory;
pub use memory::InMemorySegmentStorage;

pub mod registry;
pub use registry::*;

pub type SegmentStorageProviderId = u32;

pub struct SegmentStorageDescriptor {
    id: SegmentStorageProviderId,
    provider: Box<dyn SegmentStorageProvider>,
    permissions: SegmentProperties,
    stable_tag: Cow<'static, str>,
}

impl Debug for SegmentStorageDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegmentStorageDescriptor")
            .field("id", &self.id)
            .field("permissions", &self.permissions)
            .field("stable_tag", &self.stable_tag)
            .finish_non_exhaustive()
    }
}

impl SegmentStorageDescriptor {
    pub fn new(
        id: SegmentStorageProviderId,
        provider: impl StableSegmentStorageProvider + 'static,
        permissions: SegmentProperties,
    ) -> Self {
        Self {
            id,
            permissions,
            stable_tag: Cow::Borrowed(provider.stable_tag()),
            provider: Box::new(provider),
        }
    }

    pub fn from_boxed(
        id: SegmentStorageProviderId,
        provider: Box<dyn SegmentStorageProvider>,
        permissions: SegmentProperties,
        stable_tag: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            id,
            permissions,
            provider,
            stable_tag: stable_tag.into(),
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

    pub fn stable_tag(&self) -> &str {
        self.stable_tag.as_ref()
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

pub trait SegmentStorageProviderFromSegmentRange: SegmentStorageProvider + 'static {
    fn from_segment_range(
        start: Address,
        end: Address,
        attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError>
    where
        Self: Sized;
}

pub trait SegmentStorageProviderFromLoadable: SegmentStorageProviderFromSegmentRange {
    fn from_loadable(
        loader: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError>
    where
        Self: Sized,
    {
        let bounds = loader.segment_bounds();
        let range = bounds.first();
        Self::from_segment_range(range.start, range.end, attributes)
    }
}

impl<T: SegmentStorageProviderFromSegmentRange> SegmentStorageProviderFromLoadable for T {}

pub trait SegmentStorageProviderFromStorage:
    SegmentStorageProviderFromLoadable + StableSegmentStorageProvider
{
    fn from_storage(
        path: impl AsRef<Path>,
        attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError>
    where
        Self: Sized;
}

pub trait StableSegmentStorageProvider: SegmentStorageProvider {
    const STABLE_TAG: &'static str;

    fn stable_tag(&self) -> &'static str;
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
