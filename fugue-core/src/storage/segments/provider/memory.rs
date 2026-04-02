use std::borrow::Cow;

use crate::ir::Address;
use crate::storage::segments::SegmentStorageError;
use crate::storage::segments::provider::{
    SegmentStorageProvider, SegmentStorageProviderFromSegmentRange,
};
use crate::types::AttributeMap;

#[derive(crate::SegmentStorageProvider)]
#[provider(tag = "in-memory", persistent = false)]
pub struct InMemorySegmentStorage {
    backing: Vec<u8>,
}

impl InMemorySegmentStorage {
    pub fn with_size(size: usize) -> Self {
        Self {
            backing: vec![0u8; size],
        }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { backing: bytes }
    }
}

impl SegmentStorageProviderFromSegmentRange for InMemorySegmentStorage {
    fn from_segment_range(
        start: Address,
        end: Address,
        _attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError> {
        let total_size = (end.offset() - start.offset()) as usize + 1usize;

        tracing::trace!("creating in-memory storage with size {total_size} bytes");

        Ok(Self::with_size(total_size))
    }
}

impl SegmentStorageProvider for InMemorySegmentStorage {
    fn read_bytes(&self, offset: u64, bytes: &mut [u8]) -> Result<usize, SegmentStorageError> {
        let offset = offset as usize;
        let available = self.backing.len().saturating_sub(offset);
        let read_size = bytes.len().min(available);

        if read_size == 0 && !bytes.is_empty() {
            return Err(SegmentStorageError::InvalidAddress);
        }

        bytes[..read_size].copy_from_slice(&self.backing[offset..offset + read_size]);
        Ok(read_size)
    }

    fn write_bytes(&mut self, offset: u64, bytes: &[u8]) -> Result<usize, SegmentStorageError> {
        let offset = offset as usize;
        let available = self.backing.len().saturating_sub(offset);
        let write_size = bytes.len().min(available);

        if write_size == 0 && !bytes.is_empty() {
            return Err(SegmentStorageError::InvalidAddress);
        }

        self.backing[offset..offset + write_size].copy_from_slice(&bytes[..write_size]);

        Ok(write_size)
    }

    fn view_bytes(&self, offset: u64, n: usize) -> Result<Cow<'_, [u8]>, SegmentStorageError> {
        let offset = offset as usize;
        if offset >= self.backing.len() {
            return Err(SegmentStorageError::InvalidAddress);
        }

        let end = (offset + n).min(self.backing.len());
        if end - offset < n {
            return Err(SegmentStorageError::InvalidSize);
        }

        Ok(Cow::Borrowed(&self.backing[offset..end]))
    }

    fn view_bytes_from(&self, offset: u64) -> Result<Cow<'_, [u8]>, SegmentStorageError> {
        let offset = offset as usize;
        if offset >= self.backing.len() {
            return Err(SegmentStorageError::InvalidAddress);
        }

        Ok(Cow::Borrowed(&self.backing[offset..]))
    }

    fn size(&self) -> u64 {
        self.backing.len() as u64
    }

    fn resize(&mut self, new_size: u64) -> Result<(), SegmentStorageError> {
        self.backing.resize(new_size as usize, 0);
        Ok(())
    }
}
