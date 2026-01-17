use std::borrow::Cow;

use crate::ir::{Address, SegmentProperties};
use crate::loader::LoadableSegment;

use super::mapping::{SegmentMapping, SegmentMappingRef, SegmentSubMapping};
use super::provider::SegmentStorageDescriptor;
use super::{SegmentStorage, SegmentStorageError};

#[derive(Clone)]
pub struct SegmentMappingView<'a> {
    storage: &'a SegmentStorage,
    mapping: &'a SegmentMapping,
    provider: &'a SegmentStorageDescriptor,
    submap: SegmentSubMapping,
    segment: Cow<'a, LoadableSegment<'a>>,
    mapping_version: u64,
}

impl<'a> SegmentMappingView<'a> {
    pub(super) fn new(
        storage: &'a SegmentStorage,
        mapping: &'a SegmentMapping,
        provider: &'a SegmentStorageDescriptor,
        submap: SegmentSubMapping,
        segment: Cow<'a, LoadableSegment<'a>>,
    ) -> Self {
        Self {
            storage,
            mapping,
            provider,
            submap,
            segment,
            mapping_version: mapping.version(),
        }
    }

    pub fn start(&self) -> Address {
        self.submap.start()
    }

    pub fn last(&self) -> Address {
        self.submap.last()
    }

    pub fn end(&self) -> Address {
        self.submap.end()
    }

    pub fn size(&self) -> usize {
        self.submap.size()
    }

    pub fn contains(&self, addr: impl Into<Address>) -> bool {
        self.submap.contains(addr)
    }

    pub fn properties(&self) -> SegmentProperties {
        self.mapping.properties()
    }

    pub fn is_valid(&self) -> bool {
        self.mapping.version() == self.mapping_version
    }

    pub fn bytes_from(&self, addr: impl Into<Address>) -> Option<&[u8]> {
        let addr = addr.into();
        if !self.submap.contains(addr) {
            return None;
        }
        self.segment.view_bytes_from_address(addr)
    }

    pub fn bytes_at(&self, addr: impl Into<Address>, size: usize) -> Option<&[u8]> {
        let addr = addr.into();
        if !self.submap.contains(addr) {
            return None;
        }
        self.segment.view_bytes_at_address(addr, size)
    }

    pub fn read_bytes(
        &self,
        addr: impl Into<Address>,
        buf: &mut [u8],
    ) -> Result<usize, SegmentStorageError> {
        let addr = addr.into();
        if buf.is_empty() {
            return Ok(0);
        }

        if !self.submap.contains(addr) {
            return Err(SegmentStorageError::InvalidAddress);
        }

        let view_remaining = usize::from(self.submap.end() - addr);
        let read_size = buf.len().min(view_remaining);
        let buf_slice = &mut buf[..read_size];

        let phys_offset = self.mapping.to_offset(addr);
        self.provider
            .provider()
            .read_bytes(phys_offset.into(), buf_slice)?;

        if self.storage.is_overlay_enabled() {
            self.mapping.overlay().read(addr, buf_slice);
        }

        Ok(read_size)
    }

    pub fn segment(&self) -> &LoadableSegment<'a> {
        &self.segment
    }

    pub fn mapping_ref(&self) -> SegmentMappingRef {
        self.submap.mapping_ref()
    }
}
