use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use crate::ir::{Address, SegmentProperties};
use crate::lifter::ContextHint;

use super::mapping::{SegmentMapping, SegmentMappingRef, SegmentSubMapping};
use super::provider::SegmentStorageDescriptor;
use super::{SegmentStorage, SegmentStorageError};

#[derive(Clone)]
pub struct SegmentMappingView<'a> {
    storage: &'a SegmentStorage,
    mapping: &'a SegmentMapping,
    provider: &'a SegmentStorageDescriptor,
    submap: &'a SegmentSubMapping,
    mapping_version: u64,
}

impl<'a> SegmentMappingView<'a> {
    pub(super) fn new(
        storage: &'a SegmentStorage,
        mapping: &'a SegmentMapping,
        provider: &'a SegmentStorageDescriptor,
        submap: &'a SegmentSubMapping,
    ) -> Self {
        Self {
            storage,
            mapping,
            provider,
            submap,
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

    pub fn name(&self) -> &str {
        self.mapping.name()
    }

    pub fn mapping_hints(&self) -> &BTreeMap<Address, ContextHint> {
        self.mapping.mapping_hints()
    }

    pub fn function_hints(&self) -> &BTreeSet<Address> {
        self.mapping.function_hints()
    }

    pub fn bytes_from(&self, addr: impl Into<Address>) -> Option<Cow<'a, [u8]>> {
        let addr = addr.into();
        if !self.submap.contains(addr) {
            return None;
        }
        let phys_offset = self.mapping.to_offset(addr);
        self.provider.provider().view_bytes_from(phys_offset).ok()
    }

    pub fn bytes_at(&self, addr: impl Into<Address>, size: usize) -> Option<Cow<'a, [u8]>> {
        let addr = addr.into();
        if !self.submap.contains(addr) {
            return None;
        }
        let phys_offset = self.mapping.to_offset(addr);
        self.provider.provider().view_bytes(phys_offset, size).ok()
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
        self.provider.provider().read_bytes(phys_offset, buf_slice)?;

        if self.storage.is_overlay_enabled() {
            self.mapping.overlay().read(addr, buf_slice);
        }

        Ok(read_size)
    }

    pub fn mapping_ref(&self) -> SegmentMappingRef {
        self.submap.mapping_ref()
    }
}
