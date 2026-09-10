use crate::ir::{Address, SegmentProperties};
use crate::lifter::ContextHint;
use crate::storage::segments::SegmentStorageError;
use crate::storage::segments::mapping::{
    SegmentMapping, SegmentMappingKind, SegmentMappingProvenance, SegmentMappingRef,
    SegmentSubMapping,
};
use crate::storage::segments::provider::{SegmentStorageDescriptor, SegmentView};
use crate::storage::segments::space::AddressSpaceId;

#[derive(Clone)]
pub struct SegmentMappingView<'a> {
    mapping: &'a SegmentMapping,
    provider: &'a SegmentStorageDescriptor,
    mapping_ref: SegmentMappingRef,
    start: Address,
    size: u64,
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
            mapping_ref: submap.mapping_ref(),
            start: submap.start(),
            size: submap.size(),
            mapping_version: mapping.version(),
        }
    }

    pub(super) fn from_parts(
        mapping: &'a SegmentMapping,
        provider: &'a SegmentStorageDescriptor,
        mapping_ref: SegmentMappingRef,
        start: Address,
        size: u64,
    ) -> Self {
        Self {
            mapping,
            provider,
            mapping_ref,
            start,
            size,
            mapping_version: mapping.version(),
        }
    }

    pub fn start(&self) -> Address {
        self.start
    }

    pub fn last(&self) -> Address {
        self.end() - 1usize
    }

    pub fn end(&self) -> Address {
        self.start + self.size
    }

    pub fn space(&self) -> AddressSpaceId {
        self.mapping.space()
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn contains(&self, addr: impl Into<Address>) -> bool {
        let addr = addr.into();
        self.space() == addr.space() && addr >= self.start && addr < self.end()
    }

    pub fn properties(&self) -> SegmentProperties {
        self.mapping.properties()
    }

    pub fn kind(&self) -> SegmentMappingKind {
        self.mapping.kind()
    }

    pub fn provenance(&self) -> SegmentMappingProvenance {
        self.mapping.provenance()
    }

    pub fn is_valid(&self) -> bool {
        self.mapping.version() == self.mapping_version
    }

    pub fn name(&self) -> &str {
        self.mapping.name()
    }

    pub fn mapping_hints(&self) -> impl Iterator<Item = (Address, &ContextHint)> + '_ {
        self.mapping.mapping_hints()
    }

    pub fn mapping_hint_at(&self, addr: impl Into<Address>) -> Option<&ContextHint> {
        self.mapping.mapping_hint_at(addr)
    }

    pub fn function_hints(&self) -> impl Iterator<Item = Address> + '_ {
        self.mapping.function_hints()
    }

    pub fn bytes_from(&self, addr: impl Into<Address>) -> Option<SegmentView<'a>> {
        let addr = addr.into();
        if !self.contains(addr) {
            return None;
        }
        let phys_offset = self.mapping.to_offset(addr);
        self.provider.provider().view_bytes_from(phys_offset).ok()
    }

    pub fn bytes_at(&self, addr: impl Into<Address>, size: usize) -> Option<SegmentView<'a>> {
        let addr = addr.into();
        if !self.contains(addr) {
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

        if !self.contains(addr) {
            return Err(SegmentStorageError::InvalidAddress);
        }

        let view_remaining = usize::from(self.end() - addr);
        let read_size = buf.len().min(view_remaining);
        let buf_slice = &mut buf[..read_size];

        let phys_offset = self.mapping.to_offset(addr);
        self.provider
            .provider()
            .read_bytes(phys_offset, buf_slice)?;

        Ok(read_size)
    }

    pub fn mapping_ref(&self) -> SegmentMappingRef {
        self.mapping_ref
    }
}
