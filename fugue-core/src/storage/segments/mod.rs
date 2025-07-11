use std::borrow::Cow;

use thiserror::Error;

use crate::loader::{Loadable, LoadableSegment, LoaderError};
use crate::types::{Address, AttributeMap};

pub mod memory;
pub use memory::InMemorySegmentStorage;

pub mod memmap;
pub use memmap::MemoryMappedSegmentStorage;

pub type DefaultPersistentSegmentStorage = MemoryMappedSegmentStorage<{ super::PERSISTENT }>;
pub type DefaultTransientSegmentStorage = InMemorySegmentStorage;

#[derive(Debug, Error)]
pub enum SegmentStorageError {
    #[error("storage error: {0}")]
    Backing(anyhow::Error),
    #[error("invalid address range")]
    InvalidAddressRange,
    #[error("invalid address")]
    InvalidAddress,
    #[error("invalid size")]
    InvalidSize,
    #[error(transparent)]
    Loader(#[from] LoaderError),
}

impl SegmentStorageError {
    pub fn backing<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Backing(anyhow::Error::from(e))
    }

    pub fn backing_with<M>(msg: M) -> Self
    where
        M: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    {
        Self::Backing(anyhow::Error::msg(msg))
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

    // Returns true if the storage has a segment that contaings the given address.
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
}

pub struct SegmentStorage {
    backing: Box<dyn SegmentStorageProvider>,
}

impl SegmentStorage {
    pub fn new(backing: impl SegmentStorageProvider + 'static) -> Self {
        Self {
            backing: Box::new(backing),
        }
    }

    pub fn read_bytes(
        &self,
        addr: Address,
        bytes: &mut [u8],
    ) -> Result<usize, SegmentStorageError> {
        self.backing.read_bytes(addr, bytes)
    }

    pub fn read_bytes_exact(
        &self,
        addr: Address,
        bytes: &mut [u8],
    ) -> Result<(), SegmentStorageError> {
        self.backing.read_bytes_exact(addr, bytes)
    }

    pub fn write_bytes(
        &mut self,
        addr: Address,
        bytes: &[u8],
    ) -> Result<usize, SegmentStorageError> {
        self.backing.write_bytes(addr, bytes)
    }

    pub fn write_bytes_exact(
        &mut self,
        addr: Address,
        bytes: &[u8],
    ) -> Result<(), SegmentStorageError> {
        self.backing.write_bytes_exact(addr, bytes)
    }

    pub fn contains_segment(&self, at: Address) -> bool {
        self.backing.contains_segment(at)
    }

    pub fn find_segment_containing(
        &self,
        addr: Address,
    ) -> Result<Cow<LoadableSegment<'_>>, SegmentStorageError> {
        self.backing.find_segment_containing(addr)
    }

    pub fn view_segment_bytes(
        &self,
        addr: Address,
        size: usize,
    ) -> Result<Cow<[u8]>, SegmentStorageError> {
        self.backing.view_segment_bytes(addr, size)
    }

    pub fn view_segment_bytes_from(&self, addr: Address) -> Result<Cow<[u8]>, SegmentStorageError> {
        self.backing.view_segment_bytes_from(addr)
    }
}
