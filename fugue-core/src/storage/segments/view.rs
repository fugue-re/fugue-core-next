use crate::ir::{Address, AddressRange};
use crate::lifter::ContextHint;
use crate::storage::segments::mapping::{
    SegmentMapping, SegmentMappingKind, SegmentMappingProvenance, SegmentMappingRef,
    SegmentSubMapping,
};
use crate::storage::segments::provider::{SegmentStorageDescriptor, SegmentView};
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::segments::{SegmentProperties, SegmentStorageError};
use crate::types::Revision;

#[derive(Clone)]
pub struct SegmentMappingView<'a> {
    mapping: &'a SegmentMapping,
    provider: &'a SegmentStorageDescriptor,
    mapping_ref: SegmentMappingRef,
    range: AddressRange,
    mapping_revision: Revision,
    fill_byte: u8,
}

impl<'a> SegmentMappingView<'a> {
    pub(crate) fn new(
        mapping: &'a SegmentMapping,
        provider: &'a SegmentStorageDescriptor,
        submap: &SegmentSubMapping,
        fill_byte: u8,
    ) -> Self {
        Self {
            mapping,
            provider,
            mapping_ref: submap.mapping_ref(),
            range: submap.range(),
            mapping_revision: mapping.revision(),
            fill_byte,
        }
    }

    pub(crate) fn from_parts(
        mapping: &'a SegmentMapping,
        provider: &'a SegmentStorageDescriptor,
        mapping_ref: SegmentMappingRef,
        range: AddressRange,
        fill_byte: u8,
    ) -> Self {
        Self {
            mapping,
            provider,
            mapping_ref,
            range,
            mapping_revision: mapping.revision(),
            fill_byte,
        }
    }

    pub fn start(&self) -> Address {
        self.range.start_address()
    }

    pub fn last(&self) -> Address {
        self.range.end_address()
    }

    pub fn range(&self) -> AddressRange {
        self.range
    }

    pub fn space(&self) -> AddressSpaceId {
        self.range.space()
    }

    pub fn size(&self) -> u64 {
        self.range.size()
    }

    pub fn contains(&self, addr: impl Into<Address>) -> bool {
        self.range.contains_address(addr.into())
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

    pub fn name(&self) -> &str {
        self.mapping.name()
    }

    pub fn mapping(&self) -> &'a SegmentMapping {
        self.mapping
    }

    pub fn mapping_ref(&self) -> SegmentMappingRef {
        self.mapping_ref
    }

    pub fn mapping_hint_at(&self, addr: impl Into<Address>) -> Option<&ContextHint> {
        let addr = addr.into();
        self.contains(addr).then(|| {
            self.mapping
                .mapping_hint_at(Address::new(self.mapping.space(), addr.raw_address()))
        })?
    }

    pub fn is_valid(&self) -> bool {
        self.mapping.revision() == self.mapping_revision
    }

    pub fn mapping_hints(&self) -> impl Iterator<Item = (Address, &ContextHint)> + '_ {
        self.mapping.mapping_hints().filter_map(|(address, hint)| {
            let mapped = Address::new(self.space(), address.raw_address());
            self.contains(mapped).then_some((mapped, hint))
        })
    }

    pub(crate) fn mapping_hints_from(
        &self,
        address: Address,
    ) -> impl Iterator<Item = (Address, &ContextHint)> + '_ {
        self.mapping
            .mapping_hints_from(address.raw_address())
            .map(|(address, hint)| (Address::new(self.space(), address.raw_address()), hint))
            .take_while(|(address, _)| self.contains(*address))
    }

    pub fn function_hints(&self) -> impl Iterator<Item = Address> + '_ {
        self.mapping.function_hints().filter_map(|address| {
            let mapped = Address::new(self.space(), address.raw_address());
            self.contains(mapped).then_some(mapped)
        })
    }

    pub fn bytes_at(&self, addr: impl Into<Address>, size: usize) -> Option<SegmentView<'a>> {
        let addr = addr.into();
        if !self.contains(addr) {
            return None;
        }
        let phys_offset = self.mapping.to_offset(addr);
        self.provider.provider().view_bytes(phys_offset, size).ok()
    }

    pub fn bytes_from(&self, addr: impl Into<Address>) -> Option<SegmentView<'a>> {
        let addr = addr.into();
        if !self.contains(addr) {
            return None;
        }
        let phys_offset = self.mapping.to_offset(addr);
        self.provider.provider().view_bytes_from(phys_offset).ok()
    }

    pub fn read_bytes(
        &self,
        addr: impl Into<Address>,
        buffer: &mut [u8],
    ) -> Result<usize, SegmentStorageError> {
        let addr = addr.into();
        if buffer.is_empty() {
            return Ok(0);
        }

        if !self.contains(addr) {
            return Err(SegmentStorageError::InvalidAddress);
        }

        let view_remaining = usize::try_from(
            self.range
                .remaining_from(addr)
                .expect("view contains the read address"),
        )
        .unwrap_or(usize::MAX);
        let read_size = buffer.len().min(view_remaining);
        let buffer = &mut buffer[..read_size];

        let phys_offset = self.mapping.to_offset(addr);
        let available = usize::try_from(self.provider.size().saturating_sub(phys_offset))
            .unwrap_or(usize::MAX)
            .min(read_size);
        if available == 0 {
            buffer.fill(self.fill_byte);
            return Ok(read_size);
        }

        let view = self
            .provider
            .provider()
            .view_bytes(phys_offset, available)?;
        view.read_into_with_fill(buffer, self.fill_byte);

        Ok(read_size)
    }
}
