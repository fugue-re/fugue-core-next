use std::borrow::Cow;
use std::fmt::Debug;
use std::ops::Range;
use std::path::Path;

use smallvec::SmallVec;

use crate::ir::{Address, SegmentProperties};
use crate::storage::StoragePersistence;
use crate::storage::segments::SegmentStorageError;
use crate::types::AttributeMap;

pub mod memmap;
pub use memmap::MemoryMappedSegmentStorage;

pub mod memory;
pub use memory::InMemorySegmentStorage;

pub mod registry;
pub use registry::*;

#[derive(
    Debug,
    Copy,
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(transparent)]
pub struct SegmentStorageProviderId(u32);

impl SegmentStorageProviderId {
    pub(crate) const fn new(index: usize) -> Self {
        assert!(index <= u32::MAX as usize, "index out of range");
        Self(index as u32)
    }

    pub const fn index(&self) -> usize {
        self.0 as usize
    }
}

impl std::fmt::Display for SegmentStorageProviderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<usize> for SegmentStorageProviderId {
    type Error = std::num::TryFromIntError;

    fn try_from(index: usize) -> Result<Self, Self::Error> {
        u32::try_from(index).map(Self)
    }
}

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
        provider: impl SegmentStorageProviderDescriptor + 'static,
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

pub trait SegmentStorageProviderFromLoadable:
    SegmentStorageProviderFromSegmentRange + SegmentStorageProviderDescriptor
{
}

impl<T> SegmentStorageProviderFromLoadable for T where
    T: SegmentStorageProviderFromSegmentRange + SegmentStorageProviderDescriptor
{
}

pub trait SegmentStorageProviderFromStorage: SegmentStorageProviderFromLoadable {
    fn from_storage(
        path: impl AsRef<Path>,
        attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError>
    where
        Self: Sized;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentChunk<'a> {
    offset: u64,
    bytes: Cow<'a, [u8]>,
}

impl<'a> SegmentChunk<'a> {
    pub fn new(offset: u64, bytes: impl Into<Cow<'a, [u8]>>) -> Self {
        Self {
            offset,
            bytes: bytes.into(),
        }
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SegmentView<'a> {
    chunks: SmallVec<[SegmentChunk<'a>; 1]>,
    len: u64,
}

impl<'a> SegmentView<'a> {
    pub fn new(len: u64) -> Self {
        Self {
            chunks: SmallVec::new(),
            len,
        }
    }

    pub fn contiguous(bytes: impl Into<Cow<'a, [u8]>>) -> Self {
        let bytes = bytes.into();
        let len = bytes.len() as u64;
        let mut view = Self::new(len);
        view.push(0, bytes);
        view
    }

    pub fn push(&mut self, offset: u64, bytes: impl Into<Cow<'a, [u8]>>) {
        let bytes = bytes.into();
        if !bytes.is_empty() {
            self.chunks.push(SegmentChunk::new(offset, bytes));
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn set_len(&mut self, len: u64) {
        self.len = len;
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn chunks(&self) -> &[SegmentChunk<'a>] {
        &self.chunks
    }

    pub fn as_contiguous(&self) -> Option<&[u8]> {
        if self.len == 0 {
            return Some(&[]);
        }
        self.chunks
            .iter()
            .find(|chunk| chunk.offset == 0)
            .map(SegmentChunk::bytes)
    }

    pub fn read_into(&self, buf: &mut [u8]) {
        buf.fill(0);
        for chunk in &self.chunks {
            let start = chunk.offset as usize;
            if start >= buf.len() {
                continue;
            }
            let end = (start + chunk.bytes.len()).min(buf.len());
            buf[start..end].copy_from_slice(&chunk.bytes[..end - start]);
        }
    }
}

pub(super) struct SegmentRangeOverlap {
    window_offset: usize,
    run_offset: usize,
    len: usize,
}

impl SegmentRangeOverlap {
    pub(super) fn new(run_start: usize, run_len: usize, offset: usize, end: usize) -> Option<Self> {
        let from = offset.max(run_start);
        let to = end.min(run_start + run_len);
        (from < to).then(|| Self {
            window_offset: from - offset,
            run_offset: from - run_start,
            len: to - from,
        })
    }

    pub(super) fn window_offset(&self) -> usize {
        self.window_offset
    }

    pub(super) fn window(&self) -> Range<usize> {
        self.window_offset..self.window_offset + self.len
    }

    pub(super) fn source(&self) -> Range<usize> {
        self.run_offset..self.run_offset + self.len
    }
}

pub trait SegmentStorageProvider: Send + Sync {
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

    fn view_bytes(&self, offset: u64, n: usize) -> Result<SegmentView<'_>, SegmentStorageError>;

    fn view_bytes_from(&self, offset: u64) -> Result<SegmentView<'_>, SegmentStorageError>;

    fn size(&self) -> u64;

    fn resize(&mut self, _new_size: u64) -> Result<(), SegmentStorageError> {
        Err(SegmentStorageError::backing_with("resize not supported"))
    }

    fn flush(&mut self) -> Result<(), SegmentStorageError> {
        Ok(())
    }
}

pub trait SegmentStorageProviderDescriptor: SegmentStorageProvider {
    const STABLE_TAG: &'static str;
    const PERSISTENCE: StoragePersistence;

    fn stable_tag(&self) -> &'static str {
        Self::STABLE_TAG
    }

    fn persistence(&self) -> StoragePersistence {
        Self::PERSISTENCE
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_as_contiguous_yields_leading_run() {
        assert_eq!(SegmentView::new(0).as_contiguous(), Some(&[][..]));

        let mut padded = SegmentView::new(8);
        padded.push(0, &b"CODE"[..]);
        assert_eq!(
            padded.as_contiguous(),
            Some(&b"CODE"[..]),
            "a leading run followed by padding is contiguous up to the padding"
        );

        let mut front_gap = SegmentView::new(8);
        front_gap.push(4, &b"DATA"[..]);
        assert_eq!(
            front_gap.as_contiguous(),
            None,
            "a gap at the front has no leading run"
        );
    }
}
