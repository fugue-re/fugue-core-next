use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::{RangeBounds, RangeInclusive};

use bitflags::bitflags;
use itertools::Itertools;

use crate::ir::{Address, AddressRange, RawAddress, RawAddressRangeMap};
use crate::lifter::{ContextHint, TrackedSet};
use crate::storage::schema::bitflags::archived_bitflags;
use crate::storage::segments::provider::SegmentStorageProviderId;
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::segments::{SegmentProperties, SegmentStorage, SegmentStorageError};
use crate::types::Revision;

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
pub struct SegmentMappingId(u32);

impl SegmentMappingId {
    pub(crate) const fn new(index: usize) -> Self {
        assert!(index <= u32::MAX as usize, "index out of range");
        Self(index as u32)
    }

    pub const fn index(&self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for SegmentMappingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<usize> for SegmentMappingId {
    type Error = std::num::TryFromIntError;

    fn try_from(index: usize) -> Result<Self, Self::Error> {
        u32::try_from(index).map(Self)
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub enum SegmentMappingKind {
    Bss,
    Buffer,
    Cow,
    Dma,
    Gpu,
    Guard,
    Heap,
    Jit,
    Kernel,
    Mmap,
    Mmio,
    #[default]
    None,
    Null,
    PageTable,
    Shared,
    Stack,
    Tls,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Default,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum SegmentMappingProvenance {
    #[default]
    Generic,
    External,
    FileResidue,
    Section,
    Segment,
    Synthetic,
    Uninitialised,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct SegmentMappingFlags: u32 {
        const NONE = 0;
        const PAGED = 0x0001;
        const PRIVATE = 0x0002;
        const PERSISTENT = 0x0004;
        const COMPRESSED = 0x0008;
        const ENCRYPTED = 0x0010;
        const LARGE_PAGE = 0x0020;
    }
}

archived_bitflags!(SegmentMappingFlags, ArchivedSegmentMappingFlags, u32);

#[derive(Debug)]
pub struct SegmentMapping {
    id: SegmentMappingId,
    range: AddressRange,
    offset: u64,
    provider_id: SegmentStorageProviderId,
    properties: SegmentProperties,
    kind: SegmentMappingKind,
    provenance: SegmentMappingProvenance,
    flags: SegmentMappingFlags,
    revision: Revision,
    name: String,
    mapping_hints: SegmentMappingHints,
}

#[derive(
    Debug, Clone, Default, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct SegmentMappingHints {
    context_hints: BTreeMap<RawAddress, ContextHint>,
    context_hint_ranges: RawAddressRangeMap<ContextHint>,
    functions: BTreeSet<RawAddress>,
    symbol_pointers: BTreeSet<RawAddress>,
    tracked_sets: RawAddressRangeMap<TrackedSet>,
}

impl SegmentMappingHints {
    pub fn is_empty(&self) -> bool {
        self.context_hints.is_empty()
            && self.context_hint_ranges.is_empty()
            && self.functions.is_empty()
            && self.symbol_pointers.is_empty()
            && self.tracked_sets.is_empty()
    }

    pub fn context_hint_at(&self, address: impl Into<RawAddress>) -> Option<&ContextHint> {
        let address = address.into();
        self.context_hints
            .get(&address)
            .or_else(|| self.context_hint_ranges.get(address))
    }

    pub fn context_hints_in_range(
        &self,
        range: impl RangeBounds<RawAddress>,
    ) -> impl Iterator<Item = (RawAddress, &ContextHint)> {
        let bounds = (range.start_bound().cloned(), range.end_bound().cloned());
        self.context_hints
            .range(bounds)
            .map(|(address, hint)| (*address, hint))
            .merge_by(
                self.context_hint_ranges
                    .overlapping_ranges(bounds)
                    .filter(move |(range, _)| bounds.contains(range.start()))
                    .map(|(range, hint)| (*range.start(), hint)),
                |(address, _), (start, _)| address <= start,
            )
    }

    pub fn functions(&self) -> impl DoubleEndedIterator<Item = RawAddress> + '_ {
        self.functions.iter().copied()
    }

    pub fn contains_function(&self, address: impl Into<RawAddress>) -> bool {
        self.functions.contains(&address.into())
    }

    pub fn contains_symbol_pointer(&self, address: impl Into<RawAddress>) -> bool {
        self.symbol_pointers.contains(&address.into())
    }

    pub fn tracked_set_at(&self, address: impl Into<RawAddress>) -> Option<&TrackedSet> {
        self.tracked_sets.get(address)
    }

    pub fn insert_context_hint(&mut self, address: impl Into<RawAddress>, hint: ContextHint) {
        self.context_hints.insert(address.into(), hint);
    }

    pub fn insert_context_hint_range(
        &mut self,
        range: impl Into<RangeInclusive<RawAddress>>,
        hint: ContextHint,
    ) {
        self.context_hint_ranges.insert_range(range, hint);
    }

    pub fn insert_function(&mut self, address: impl Into<RawAddress>) {
        self.functions.insert(address.into());
    }

    pub fn insert_symbol_pointer(&mut self, address: impl Into<RawAddress>) {
        self.symbol_pointers.insert(address.into());
    }

    pub fn insert_tracked_set(
        &mut self,
        range: impl Into<RangeInclusive<RawAddress>>,
        tracked_set: TrackedSet,
    ) {
        self.tracked_sets.insert_range(range, tracked_set);
    }

    pub fn merge(&mut self, other: SegmentMappingHints) {
        self.context_hints.extend(other.context_hints);
        self.context_hint_ranges.extend(other.context_hint_ranges);
        self.functions.extend(other.functions);
        self.symbol_pointers.extend(other.symbol_pointers);
        self.tracked_sets.extend(other.tracked_sets);
    }

    pub fn clamp(&self, range: impl Into<RangeInclusive<RawAddress>>) -> Self {
        let range = range.into();
        let (start, last) = (*range.start(), *range.end());
        Self {
            context_hints: self
                .context_hints
                .range(start..=last)
                .map(|(address, hint)| (*address, hint.clone()))
                .collect(),
            context_hint_ranges: self.context_hint_ranges.clamp(start..=last),
            functions: self.functions.range(start..=last).copied().collect(),
            symbol_pointers: self.symbol_pointers.range(start..=last).copied().collect(),
            tracked_sets: self.tracked_sets.clamp(start..=last),
        }
    }
}

impl SegmentMapping {
    pub fn new(
        id: SegmentMappingId,
        range: AddressRange,
        offset: u64,
        provider_id: SegmentStorageProviderId,
        properties: SegmentProperties,
    ) -> Result<Self, SegmentStorageError> {
        if AddressRange::from_size(range.start_address(), range.size()) != Some(range) {
            return Err(SegmentStorageError::InvalidAddressRange);
        }

        Ok(Self {
            id,
            range,
            offset,
            provider_id,
            properties,
            kind: SegmentMappingKind::None,
            provenance: SegmentMappingProvenance::default(),
            flags: SegmentMappingFlags::NONE,
            revision: Revision::default(),
            name: String::new(),
            mapping_hints: SegmentMappingHints::default(),
        })
    }

    pub(crate) fn from_builder(
        id: SegmentMappingId,
        builder: SegmentMappingBuilder,
    ) -> Result<Self, SegmentStorageError> {
        let range = builder
            .range()
            .ok_or(SegmentStorageError::InvalidAddressRange)?;
        let mut mapping = Self::new(
            id,
            range,
            builder.offset,
            builder.provider_id,
            builder.properties,
        )?;
        mapping.kind = builder.kind;
        mapping.provenance = builder.provenance;
        mapping.flags = builder.flags;
        mapping.name = builder.name;
        mapping.mapping_hints = builder.mapping_hints;
        Ok(mapping)
    }

    pub fn id(&self) -> SegmentMappingId {
        self.id
    }

    pub fn start(&self) -> Address {
        self.range.start_address()
    }

    pub fn size(&self) -> u64 {
        self.range.size()
    }

    pub fn last(&self) -> Address {
        self.range.end_address()
    }

    pub fn range(&self) -> AddressRange {
        self.range
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn space(&self) -> AddressSpaceId {
        self.range.space()
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

    pub fn provenance(&self) -> SegmentMappingProvenance {
        self.provenance
    }

    pub fn set_provenance(&mut self, provenance: SegmentMappingProvenance) {
        self.provenance = provenance;
        self.touch();
    }

    pub fn flags(&self) -> SegmentMappingFlags {
        self.flags
    }

    pub fn set_flags(&mut self, flags: SegmentMappingFlags) {
        self.flags = flags;
        self.touch();
    }

    pub fn revision(&self) -> Revision {
        self.revision
    }

    pub fn contains(&self, addr: impl Into<Address>) -> bool {
        self.range.contains_address(addr.into())
    }

    pub fn set_start(&mut self, start: impl Into<Address>) -> Result<(), SegmentStorageError> {
        self.range = AddressRange::from_size(start.into(), self.size())
            .ok_or(SegmentStorageError::InvalidAddressRange)?;
        self.touch();
        Ok(())
    }

    pub fn set_size(&mut self, size: u64) -> Result<(), SegmentStorageError> {
        self.range = AddressRange::from_size(self.start(), size)
            .ok_or(SegmentStorageError::InvalidAddressRange)?;
        self.touch();
        Ok(())
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
        self.touch();
    }

    pub fn mapping_hints(&self) -> &SegmentMappingHints {
        &self.mapping_hints
    }

    pub fn mapping_ref(&self) -> SegmentMappingRef {
        SegmentMappingRef {
            mapping_id: self.id,
            revision: self.revision,
        }
    }

    pub(crate) fn update_metadata(
        &mut self,
        kind: SegmentMappingKind,
        provenance: SegmentMappingProvenance,
        flags: SegmentMappingFlags,
    ) {
        self.kind = kind;
        self.provenance = provenance;
        self.flags = flags;
        self.touch();
    }

    fn touch(&mut self) {
        self.revision = self.revision.next();
    }

    pub fn to_offset(&self, addr: impl Into<Address>) -> u64 {
        let addr = addr.into();
        let relative = addr.offset() - self.start().offset();
        self.offset + relative
    }

    pub fn to_address(&self, phys_offset: u64) -> Address {
        let relative = phys_offset - self.offset;
        Address::new(self.space(), self.start().offset() + relative)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentMappingRef {
    mapping_id: SegmentMappingId,
    revision: Revision,
}

impl SegmentMappingRef {
    pub fn mapping_id(&self) -> SegmentMappingId {
        self.mapping_id
    }

    pub fn revision(&self) -> Revision {
        self.revision
    }

    pub fn is_valid(&self, mapping: &SegmentMapping) -> bool {
        self.mapping_id == mapping.id() && self.revision == mapping.revision()
    }
}

#[derive(Debug, Clone)]
pub struct SegmentSubMapping {
    mapping_ref: SegmentMappingRef,
    range: AddressRange,
    properties: SegmentProperties,
}

impl SegmentSubMapping {
    pub(crate) fn new(
        mapping_ref: SegmentMappingRef,
        range: AddressRange,
        properties: SegmentProperties,
    ) -> Self {
        Self {
            mapping_ref,
            range,
            properties,
        }
    }

    pub fn mapping_ref(&self) -> SegmentMappingRef {
        self.mapping_ref
    }

    pub fn start(&self) -> Address {
        self.range.start_address()
    }

    pub fn size(&self) -> u64 {
        self.range.size()
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

    pub fn properties(&self) -> SegmentProperties {
        self.properties
    }

    pub fn contains(&self, addr: impl Into<Address>) -> bool {
        self.range.contains_address(addr.into())
    }

    pub fn with_start(&self, new_start: impl Into<Address>) -> Option<Self> {
        let new_start = new_start.into();
        if new_start.space() != self.space() || new_start > self.last() {
            return None;
        }

        Some(Self::new(
            self.mapping_ref,
            AddressRange::new(self.space(), new_start.raw_address(), self.range.end()),
            self.properties,
        ))
    }

    pub fn with_last(&self, new_last: impl Into<Address>) -> Option<Self> {
        let new_last = new_last.into();
        if new_last.space() != self.space() || new_last < self.start() {
            return None;
        }

        Some(Self::new(
            self.mapping_ref,
            AddressRange::new(self.space(), self.range.start(), new_last.raw_address()),
            self.properties,
        ))
    }

    pub fn split_at(&self, addr: impl Into<Address>) -> (Option<Self>, Option<Self>) {
        let addr = addr.into();
        if addr.space() != self.space() {
            return (None, None);
        }

        if addr <= self.start() {
            return (None, Some(self.clone()));
        }

        if addr > self.last() {
            return (Some(self.clone()), None);
        }

        let left = Self::new(
            self.mapping_ref,
            AddressRange::new(
                self.space(),
                self.range.start(),
                (addr - 1usize).raw_address(),
            ),
            self.properties,
        );
        let right = Self::new(
            self.mapping_ref,
            AddressRange::new(self.space(), addr.raw_address(), self.range.end()),
            self.properties,
        );

        (Some(left), Some(right))
    }
}

impl PartialEq for SegmentSubMapping {
    fn eq(&self, other: &Self) -> bool {
        self.start() == other.start()
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
        self.start().cmp(&other.start())
    }
}

#[derive(Debug)]
pub struct SegmentMappingBuilder {
    start: Address,
    size: u64,
    offset: u64,
    provider_id: SegmentStorageProviderId,
    properties: SegmentProperties,
    kind: SegmentMappingKind,
    provenance: SegmentMappingProvenance,
    flags: SegmentMappingFlags,
    name: String,
    mapping_hints: SegmentMappingHints,
}

impl SegmentMappingBuilder {
    pub fn new(
        start: impl Into<Address>,
        size: u64,
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
            provenance: SegmentMappingProvenance::default(),
            flags: SegmentMappingFlags::default(),
            name: String::new(),
            mapping_hints: SegmentMappingHints::default(),
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

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn set_size(&mut self, size: u64) {
        self.size = size;
    }

    pub fn with_size(mut self, size: u64) -> Self {
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

    pub fn provenance(&self) -> SegmentMappingProvenance {
        self.provenance
    }

    pub fn set_provenance(&mut self, provenance: impl Into<SegmentMappingProvenance>) {
        self.provenance = provenance.into();
    }

    pub fn with_provenance(mut self, provenance: impl Into<SegmentMappingProvenance>) -> Self {
        self.set_provenance(provenance);
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

    pub fn mapping_hints(&self) -> &SegmentMappingHints {
        &self.mapping_hints
    }

    pub fn set_mapping_hints(&mut self, mapping_hints: SegmentMappingHints) {
        self.mapping_hints = mapping_hints;
    }

    pub fn with_mapping_hints(mut self, mapping_hints: SegmentMappingHints) -> Self {
        self.set_mapping_hints(mapping_hints);
        self
    }

    pub fn range(&self) -> Option<AddressRange> {
        AddressRange::from_size(self.start, self.size)
    }

    pub fn build(
        self,
        storage: &mut SegmentStorage,
    ) -> Result<SegmentMappingId, SegmentStorageError> {
        storage.create_mapping_from_builder(self)
    }
}
