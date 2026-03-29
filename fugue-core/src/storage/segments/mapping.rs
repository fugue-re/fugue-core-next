use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Range, RangeInclusive};

use bitflags::bitflags;
use uuid::Uuid;

use crate::ir::{Address, SegmentProperties};
use crate::lifter::ContextHint;
use crate::storage::segments::overlay::OverlayTree;
use crate::storage::segments::provider::SegmentStorageProviderId;
use crate::storage::segments::{SegmentStorage, SegmentStorageError};

pub type SegmentMappingId = u32;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
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

#[repr(transparent)]
pub struct ArchivedSegmentMappingFlags(rkyv::Archived<u32>);

unsafe impl rkyv::Portable for ArchivedSegmentMappingFlags {}
unsafe impl rkyv::traits::NoUndef for ArchivedSegmentMappingFlags {}

unsafe impl<C: rkyv::rancor::Fallible + ?Sized> rkyv::bytecheck::CheckBytes<C>
    for ArchivedSegmentMappingFlags
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe {
            <rkyv::Archived<u32> as rkyv::bytecheck::CheckBytes<C>>::check_bytes(
                value.cast(),
                context,
            )
        }
    }
}

impl rkyv::Archive for SegmentMappingFlags {
    type Archived = ArchivedSegmentMappingFlags;
    type Resolver = rkyv::Resolver<u32>;

    fn resolve(&self, resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        let out = unsafe { out.cast_unchecked::<rkyv::Archived<u32>>() };
        self.bits().resolve(resolver, out);
    }
}

impl<S: rkyv::rancor::Fallible + rkyv::ser::Writer<S::Error> + ?Sized> rkyv::Serialize<S>
    for SegmentMappingFlags
{
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        self.bits().serialize(serializer)
    }
}

impl<D: rkyv::rancor::Fallible + ?Sized> rkyv::Deserialize<SegmentMappingFlags, D>
    for ArchivedSegmentMappingFlags
{
    fn deserialize(&self, deserializer: &mut D) -> Result<SegmentMappingFlags, D::Error> {
        let bits = rkyv::Deserialize::<u32, D>::deserialize(&self.0, deserializer)?;
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

#[derive(Debug)]
pub struct SegmentMappingBuilder {
    start: Address,
    size: usize,
    offset: u64,
    provider_id: SegmentStorageProviderId,
    properties: SegmentProperties,
    kind: SegmentMappingKind,
    flags: SegmentMappingFlags,
    name: String,
    mapping_hints: BTreeMap<Address, ContextHint>,
    function_hints: BTreeSet<Address>,
}

impl SegmentMappingBuilder {
    pub fn new(
        start: impl Into<Address>,
        size: usize,
        offset: u64,
        provider_id: SegmentStorageProviderId,
    ) -> Self {
        Self {
            start: start.into(),
            size,
            offset,
            provider_id,
            properties: SegmentProperties::default(),
            kind: SegmentMappingKind::default(),
            flags: SegmentMappingFlags::default(),
            name: Uuid::now_v7().to_string(),
            mapping_hints: BTreeMap::new(),
            function_hints: BTreeSet::new(),
        }
    }

    pub fn start(&self) -> Address {
        self.start
    }

    pub fn set_start(&mut self, start: impl Into<Address>) {
        self.start = start.into();
    }

    pub fn with_start(mut self, start: impl Into<Address>) -> Self {
        self.set_start(start);
        self
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn set_size(&mut self, size: usize) {
        self.size = size;
    }

    pub fn with_size(mut self, size: usize) -> Self {
        self.set_size(size);
        self
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn set_offset(&mut self, offset: u64) {
        self.offset = offset;
    }

    pub fn with_offset(mut self, offset: u64) -> Self {
        self.set_offset(offset);
        self
    }

    pub fn provider_id(&self) -> SegmentStorageProviderId {
        self.provider_id
    }

    pub fn set_provider_id(&mut self, provider_id: SegmentStorageProviderId) {
        self.provider_id = provider_id;
    }

    pub fn with_provider_id(mut self, provider_id: SegmentStorageProviderId) -> Self {
        self.set_provider_id(provider_id);
        self
    }

    pub fn properties(&self) -> SegmentProperties {
        self.properties
    }

    pub fn set_properties(&mut self, properties: impl Into<SegmentProperties>) {
        self.properties = properties.into();
    }

    pub fn with_properties(mut self, properties: impl Into<SegmentProperties>) -> Self {
        self.set_properties(properties);
        self
    }

    pub fn kind(&self) -> SegmentMappingKind {
        self.kind
    }

    pub fn set_kind(&mut self, kind: impl Into<SegmentMappingKind>) {
        self.kind = kind.into();
    }

    pub fn with_kind(mut self, kind: impl Into<SegmentMappingKind>) -> Self {
        self.set_kind(kind);
        self
    }

    pub fn flags(&self) -> SegmentMappingFlags {
        self.flags
    }

    pub fn set_flags(&mut self, flags: impl Into<SegmentMappingFlags>) {
        self.flags = flags.into();
    }

    pub fn with_flags(mut self, flags: impl Into<SegmentMappingFlags>) -> Self {
        self.set_flags(flags);
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.set_name(name);
        self
    }

    pub fn mapping_hints(&self) -> &BTreeMap<Address, ContextHint> {
        &self.mapping_hints
    }

    pub fn set_mapping_hints(&mut self, mapping_hints: impl Into<BTreeMap<Address, ContextHint>>) {
        self.mapping_hints = mapping_hints.into();
    }

    pub fn extend_mapping_hints(
        &mut self,
        mapping_hints: impl IntoIterator<Item = (Address, ContextHint)>,
    ) {
        self.mapping_hints.extend(mapping_hints);
    }

    pub fn add_mapping_hint(&mut self, address: impl Into<Address>, hint: ContextHint) {
        self.mapping_hints.insert(address.into(), hint);
    }

    pub fn with_mapping_hints(
        mut self,
        mapping_hints: impl IntoIterator<Item = (Address, ContextHint)>,
    ) -> Self {
        self.extend_mapping_hints(mapping_hints);
        self
    }

    pub fn function_hints(&self) -> &BTreeSet<Address> {
        &self.function_hints
    }

    pub fn set_function_hints(&mut self, function_hints: impl Into<BTreeSet<Address>>) {
        self.function_hints = function_hints.into();
    }

    pub fn extend_function_hints(&mut self, function_hints: impl IntoIterator<Item = Address>) {
        self.function_hints.extend(function_hints);
    }

    pub fn add_function_hint(&mut self, address: impl Into<Address>) {
        self.function_hints.insert(address.into());
    }

    pub fn with_function_hints(
        mut self,
        function_hints: impl IntoIterator<Item = Address>,
    ) -> Self {
        self.extend_function_hints(function_hints);
        self
    }

    pub fn build(
        self,
        storage: &mut SegmentStorage,
    ) -> Result<SegmentMappingId, SegmentStorageError> {
        storage.create_mapping_from_builder(self)
    }
}
