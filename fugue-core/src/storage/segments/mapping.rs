use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Range, RangeInclusive};

use bincode::{BorrowDecode, Decode, Encode};
use bitflags::bitflags;

use crate::ir::{Address, SegmentProperties};
use crate::lifter::ContextHint;

use crate::storage::segments::overlay::OverlayTree;
use crate::storage::segments::provider::SegmentStorageProviderId;

pub type SegmentMappingId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, bincode::Encode, bincode::Decode)]
pub enum SegmentMappingKind {
    #[default]
    None,
    Heap,
    Stack,
    Mmap,
    Mmio,
    Dma,
    Jit,
    Bss,
    Shared,
    Kernel,
    Guard,
    Null,
    Gpu,
    Tls,
    Buffer,
    Cow,
    PageTable,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct SegmentMappingFlags: u32 {
        const NONE = 0;
        const PAGED = 0x0001;
        const PRIVATE = 0x0002;
        const PERSISTENT = 0x0004;
        const OVERLAY_ENABLED = 0x0008;
        const COMPRESSED = 0x0010;
        const ENCRYPTED = 0x0020;
        const LARGE_PAGE = 0x0040;
    }
}

impl Encode for SegmentMappingFlags {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.bits().encode(encoder)
    }
}

impl<C> Decode<C> for SegmentMappingFlags {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let bits = u32::decode(decoder)?;
        Ok(SegmentMappingFlags::from_bits_truncate(bits))
    }
}

impl<'de, C> BorrowDecode<'de, C> for SegmentMappingFlags {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let bits = u32::borrow_decode(decoder)?;
        Ok(SegmentMappingFlags::from_bits_truncate(bits))
    }
}

#[derive(Debug)]
pub struct SegmentMapping {
    id: SegmentMappingId,
    start: Address,
    size: usize,
    offset: u64,
    provider_id: SegmentStorageProviderId,
    properties: SegmentProperties,
    kind: SegmentMappingKind,
    flags: SegmentMappingFlags,
    overlay: OverlayTree,
    version: u64,
    name: String,
    mapping_hints: BTreeMap<Address, ContextHint>,
    function_hints: BTreeSet<Address>,
}

impl SegmentMapping {
    pub fn new(
        id: SegmentMappingId,
        start: impl Into<Address>,
        size: usize,
        offset: u64,
        provider_id: SegmentStorageProviderId,
        properties: SegmentProperties,
    ) -> Self {
        Self {
            id,
            start: start.into(),
            size,
            offset,
            provider_id,
            properties,
            kind: SegmentMappingKind::None,
            flags: SegmentMappingFlags::NONE,
            overlay: OverlayTree::new(),
            version: 0,
            name: String::new(),
            mapping_hints: BTreeMap::new(),
            function_hints: BTreeSet::new(),
        }
    }

    pub fn new_with_metadata(
        id: SegmentMappingId,
        start: impl Into<Address>,
        size: usize,
        offset: u64,
        provider_id: SegmentStorageProviderId,
        properties: SegmentProperties,
        name: impl Into<String>,
        mapping_hints: BTreeMap<Address, ContextHint>,
        function_hints: BTreeSet<Address>,
    ) -> Self {
        Self {
            id,
            start: start.into(),
            size,
            offset,
            provider_id,
            properties,
            kind: SegmentMappingKind::None,
            flags: SegmentMappingFlags::NONE,
            overlay: OverlayTree::new(),
            version: 0,
            name: name.into(),
            mapping_hints,
            function_hints,
        }
    }

    pub fn id(&self) -> SegmentMappingId {
        self.id
    }

    pub fn start(&self) -> Address {
        self.start
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn end(&self) -> Address {
        self.start + self.size
    }

    pub fn last(&self) -> Address {
        self.end() - 1usize
    }

    pub fn range(&self) -> Range<Address> {
        self.start..self.end()
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn provider_id(&self) -> SegmentStorageProviderId {
        self.provider_id
    }

    pub fn properties(&self) -> SegmentProperties {
        self.properties
    }

    pub fn set_properties(&mut self, properties: SegmentProperties) {
        self.properties = properties;
        self.touch();
    }

    pub fn kind(&self) -> SegmentMappingKind {
        self.kind
    }

    pub fn set_kind(&mut self, kind: SegmentMappingKind) {
        self.kind = kind;
        self.touch();
    }

    pub fn flags(&self) -> SegmentMappingFlags {
        self.flags
    }

    pub fn set_flags(&mut self, flags: SegmentMappingFlags) {
        self.flags = flags;
        self.touch();
    }

    pub fn overlay(&self) -> &OverlayTree {
        &self.overlay
    }

    pub fn overlay_mut(&mut self) -> &mut OverlayTree {
        &mut self.overlay
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    fn touch(&mut self) {
        self.version += 1;
    }

    pub fn contains(&self, addr: impl Into<Address>) -> bool {
        let addr = addr.into();
        addr >= self.start && addr < self.end()
    }

    pub fn to_offset(&self, addr: impl Into<Address>) -> u64 {
        let addr = addr.into();
        let relative = addr.offset() - self.start.offset();
        self.offset + relative
    }

    pub fn to_address(&self, phys_offset: u64) -> Address {
        let relative = phys_offset - self.offset;
        Address::from(self.start.offset() + relative)
    }

    pub fn set_start(&mut self, start: impl Into<Address>) {
        self.start = start.into();
        self.touch();
    }

    pub fn set_size(&mut self, size: usize) {
        self.size = size;
        self.touch();
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
        self.touch();
    }

    pub fn mapping_hints(&self) -> &BTreeMap<Address, ContextHint> {
        &self.mapping_hints
    }

    pub fn mapping_hints_mut(&mut self) -> &mut BTreeMap<Address, ContextHint> {
        &mut self.mapping_hints
    }

    pub fn function_hints(&self) -> &BTreeSet<Address> {
        &self.function_hints
    }

    pub fn function_hints_mut(&mut self) -> &mut BTreeSet<Address> {
        &mut self.function_hints
    }

    pub fn make_ref(&self) -> SegmentMappingRef {
        SegmentMappingRef {
            mapping_id: self.id,
            version: self.version,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentMappingRef {
    mapping_id: SegmentMappingId,
    version: u64,
}

impl SegmentMappingRef {
    pub fn new(mapping_id: SegmentMappingId, version: u64) -> Self {
        Self {
            mapping_id,
            version,
        }
    }

    pub fn mapping_id(&self) -> SegmentMappingId {
        self.mapping_id
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn is_valid(&self, mapping: &SegmentMapping) -> bool {
        self.mapping_id == mapping.id() && self.version == mapping.version()
    }
}

#[derive(Debug, Clone)]
pub struct SegmentSubMapping {
    mapping_ref: SegmentMappingRef,
    start: Address,
    size: usize,
    properties: SegmentProperties,
}

impl SegmentSubMapping {
    pub fn new(
        mapping_ref: SegmentMappingRef,
        start: impl Into<Address>,
        size: usize,
        properties: SegmentProperties,
    ) -> Self {
        Self {
            mapping_ref,
            start: start.into(),
            size,
            properties,
        }
    }

    pub fn mapping_ref(&self) -> SegmentMappingRef {
        self.mapping_ref
    }

    pub fn start(&self) -> Address {
        self.start
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn end(&self) -> Address {
        self.start + self.size
    }

    pub fn last(&self) -> Address {
        self.end() - 1usize
    }

    pub fn range(&self) -> Range<Address> {
        self.start..self.end()
    }

    pub fn range_inclusive(&self) -> RangeInclusive<Address> {
        self.start..=self.last()
    }

    pub fn properties(&self) -> SegmentProperties {
        self.properties
    }

    pub fn contains(&self, addr: impl Into<Address>) -> bool {
        let addr = addr.into();
        addr >= self.start && addr < self.end()
    }

    pub fn with_start(&self, new_start: impl Into<Address>) -> Option<Self> {
        let new_start = new_start.into();
        if new_start >= self.end() {
            return None;
        }
        let new_size = usize::from(self.end() - new_start);
        Some(Self::new(
            self.mapping_ref,
            new_start,
            new_size,
            self.properties,
        ))
    }

    pub fn with_end(&self, new_end: impl Into<Address>) -> Option<Self> {
        let new_end = new_end.into();
        if new_end <= self.start {
            return None;
        }
        let new_size = usize::from(new_end - self.start);
        Some(Self::new(
            self.mapping_ref,
            self.start,
            new_size,
            self.properties,
        ))
    }

    pub fn split_at(&self, addr: impl Into<Address>) -> (Option<Self>, Option<Self>) {
        let addr = addr.into();

        if addr <= self.start {
            return (None, Some(self.clone()));
        }

        if addr >= self.end() {
            return (Some(self.clone()), None);
        }

        let left_size = usize::from(addr - self.start);
        let right_size = usize::from(self.end() - addr);

        let left = Self::new(self.mapping_ref, self.start, left_size, self.properties);
        let right = Self::new(self.mapping_ref, addr, right_size, self.properties);

        (Some(left), Some(right))
    }
}

impl PartialEq for SegmentSubMapping {
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start
    }
}

impl Eq for SegmentSubMapping {}

impl PartialOrd for SegmentSubMapping {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SegmentSubMapping {
    fn cmp(&self, other: &Self) -> Ordering {
        self.start.cmp(&other.start)
    }
}
