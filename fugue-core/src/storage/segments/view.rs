use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use crate::ir::{MetaAddress, SegmentProperties};
use crate::lifter::ContextHint;
use crate::storage::segments::SegmentStorageError;
use crate::storage::segments::mapping::{SegmentMapping, SegmentMappingRef, SegmentSubMapping};
use crate::storage::segments::provider::SegmentStorageDescriptor;
use crate::storage::segments::space::AddressSpaceId;

#[derive(Clone)]
pub struct SegmentMappingView<'a> {
    mapping: &'a SegmentMapping,
    provider: &'a SegmentStorageDescriptor,
    submap: &'a SegmentSubMapping,
    mapping_version: u64,
}

impl<'a> SegmentMappingView<'a> {
    pub(super) fn new(
        mapping: &'a SegmentMapping,
        provider: &'a SegmentStorageDescriptor,
        submap: &'a SegmentSubMapping,
    ) -> Self {
        Self {
            mapping,
            provider,
            submap,
            mapping_version: mapping.version(),
        }
    }

    pub fn start(&self) -> MetaAddress {
        self.submap.start()
    }

    pub fn last(&self) -> MetaAddress {
        self.submap.last()
    }

    pub fn end(&self) -> MetaAddress {
        self.submap.end()
    }

    pub fn space(&self) -> AddressSpaceId {
        self.mapping.space()
    }

    pub fn size(&self) -> usize {
        self.submap.size()
    }

    pub fn contains(&self, addr: impl Into<MetaAddress>) -> bool {
        self.submap.contains(addr)
    }

    pub fn properties(&self) -> SegmentProperties {
        self.mapping.properties()
    }

    pub fn is_valid(&self) -> bool {
        self.mapping.version() == self.mapping_version
    }

    pub fn name(&self) -> &str {
        self.mapping.name()
    }

    pub fn mapping_hints(&self) -> &BTreeMap<MetaAddress, ContextHint> {
        self.mapping.mapping_hints()
    }

    pub fn function_hints(&self) -> &BTreeSet<MetaAddress> {
        self.mapping.function_hints()
    }

    pub fn bytes_from(&self, addr: impl Into<MetaAddress>) -> Option<Cow<'a, [u8]>> {
        let addr = addr.into();
        if !self.submap.contains(addr) {
            return None;
        }
        let phys_offset = self.mapping.to_offset(addr);
        self.provider.provider().view_bytes_from(phys_offset).ok()
    }

    pub fn bytes_at(&self, addr: impl Into<MetaAddress>, size: usize) -> Option<Cow<'a, [u8]>> {
        let addr = addr.into();
        if !self.submap.contains(addr) {
            return None;
        }
        let phys_offset = self.mapping.to_offset(addr);
        self.provider.provider().view_bytes(phys_offset, size).ok()
    }

    pub fn read_bytes(
        &self,
        addr: impl Into<MetaAddress>,
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
            .read_bytes(phys_offset, buf_slice)?;

        Ok(read_size)
    }

    pub fn mapping_ref(&self) -> SegmentMappingRef {
        self.submap.mapping_ref()
    }
}
