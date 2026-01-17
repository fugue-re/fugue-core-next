use std::borrow::Cow;
use std::fmt::Debug;
use std::path::Path;

use crate::ir::{Address, SegmentProperties};
use crate::loader::{Loadable, LoadableSegment, LoadableSegmentMetadata};
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

pub trait SegmentStorageProviderFromLoadable: SegmentStorageProvider + 'static {
    // Creates a new storage provider from the given loadable object.
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

pub struct SegmentStorageMetadataIter<'a> {
    iter: Box<dyn Iterator<Item = Cow<'a, LoadableSegmentMetadata>> + 'a>,
}

impl SegmentStorageMetadataIter<'_> {
    pub fn new<'a>(
        iter: impl Iterator<Item = Cow<'a, LoadableSegmentMetadata>> + 'a,
    ) -> SegmentStorageMetadataIter<'a> {
        SegmentStorageMetadataIter {
            iter: Box::new(iter),
        }
    }
}

impl<'a> Iterator for SegmentStorageMetadataIter<'a> {
    type Item = Cow<'a, LoadableSegmentMetadata>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

pub trait SegmentStorageProvider {
    // Reads the given bytes from the storage at the specified address; returns the number of bytes
    // read.
    fn read_bytes(&self, addr: Address, bytes: &mut [u8]) -> Result<usize, SegmentStorageError>;

    // Reads the given bytes from the storage at the specified address; fails if not all bytes can
    // be read, e.g., due to gaps or lack of segment coverage.
    fn read_bytes_exact(&self, addr: Address, bytes: &mut [u8]) -> Result<(), SegmentStorageError> {
        if self.read_bytes(addr, bytes)? != bytes.len() {
            return Err(SegmentStorageError::InvalidAddressRange);
        }
        Ok(())
    }

    // Writes the given bytes to the storage at the specified address; returns the number of bytes
    // written.
    fn write_bytes(&mut self, addr: Address, bytes: &[u8]) -> Result<usize, SegmentStorageError>;

    // Writes the given bytes to the storage at the specified address; fails if not all bytes can
    // be written, e.g., due to gaps or lack of segment coverage.
    fn write_bytes_exact(
        &mut self,
        addr: Address,
        bytes: &[u8],
    ) -> Result<(), SegmentStorageError> {
        if self.write_bytes(addr, bytes)? != bytes.len() {
            return Err(SegmentStorageError::InvalidAddressRange);
        }
        Ok(())
    }

    // Returns true if the storage has a segment that contains the given address.
    fn contains_segment(&self, at: Address) -> bool;

    // Returns the segment that contains the given address, if any.
    fn find_segment_containing(
        &self,
        addr: Address,
    ) -> Result<Cow<LoadableSegment<'_>>, SegmentStorageError>;

    // Returns a view of length `size` over the bytes of the segment containing the given address.
    fn view_segment_bytes(
        &self,
        addr: Address,
        size: usize,
    ) -> Result<Cow<[u8]>, SegmentStorageError> {
        let addr = addr.into();
        let segm = self.find_segment_containing(addr)?;

        let offset = usize::from(addr - segm.address());
        let bytes = match segm {
            Cow::Borrowed(segm) => Cow::Borrowed(
                segm.view_bytes_at(offset, size)
                    .ok_or(SegmentStorageError::InvalidSize)?,
            ),
            Cow::Owned(segm) => Cow::Owned(
                segm.view_bytes_at(offset, size)
                    .ok_or(SegmentStorageError::InvalidSize)?
                    .to_owned(),
            ),
        };

        Ok(bytes)
    }

    // Returns a view over the bytes of the segment containing the given address, starting from the
    // given address.
    fn view_segment_bytes_from(&self, addr: Address) -> Result<Cow<[u8]>, SegmentStorageError> {
        let addr = addr.into();
        let segm = self.find_segment_containing(addr)?;

        let offset = usize::from(addr - segm.address());
        let bytes = match segm {
            Cow::Borrowed(segm) => Cow::Borrowed(
                segm.view_bytes_from(offset)
                    .ok_or(SegmentStorageError::InvalidSize)?,
            ),
            Cow::Owned(segm) => Cow::Owned(
                segm.view_bytes_from(offset)
                    .ok_or(SegmentStorageError::InvalidSize)?
                    .to_owned(),
            ),
        };

        Ok(bytes)
    }

    // Returns an iterator over the metadata of all segments in the storage.
    fn metadata(&self) -> Result<SegmentStorageMetadataIter<'_>, SegmentStorageError>;

    fn size(&self) -> usize {
        self.metadata()
            .map(|iter| {
                iter.map(|meta| usize::from(meta.address()) + meta.len())
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0)
    }

    // Resizes the backing storage to the given new size.
    fn resize(&mut self, _new_size: u64) -> Result<(), SegmentStorageError> {
        Err(SegmentStorageError::backing_with("resize not supported"))
    }

    // Flushes any pending changes to the backing storage.
    fn flush(&mut self) -> Result<(), SegmentStorageError> {
        Ok(())
    }
}
