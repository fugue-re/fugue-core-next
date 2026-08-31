use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use bitflags::bitflags;

use crate::ir::{Address, AddressRange, RawAddress};
use crate::lifter::ContextHint;
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
        const OVERLAY_ENABLED = 0x0008;
        const COMPRESSED = 0x0010;
        const ENCRYPTED = 0x0020;
        const LARGE_PAGE = 0x0040;
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
    mapping_hints: BTreeMap<RawAddress, ContextHint>,
    function_hints: BTreeSet<RawAddress>,
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
            mapping_hints: BTreeMap::new(),
            function_hints: BTreeSet::new(),
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
        mapping.function_hints = builder.function_hints;
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

    pub(crate) fn mapping_hint_offsets(&self) -> &BTreeMap<RawAddress, ContextHint> {
        &self.mapping_hints
    }

    pub(crate) fn function_hint_offsets(&self) -> &BTreeSet<RawAddress> {
        &self.function_hints
    }

    pub fn mapping_hint_at(&self, addr: impl Into<Address>) -> Option<&ContextHint> {
        let addr = addr.into();
        (addr.space() == self.space())
            .then(|| self.mapping_hints.get(&addr.raw_address()))
            .flatten()
    }

    pub fn mapping_hints(&self) -> impl Iterator<Item = (Address, &ContextHint)> + '_ {
        let space = self.space();
        self.mapping_hints
            .iter()
            .map(move |(&offset, hint)| (Address::new(space, offset), hint))
    }

    pub(crate) fn mapping_hints_from(
        &self,
        offset: RawAddress,
    ) -> impl Iterator<Item = (Address, &ContextHint)> + '_ {
        let space = self.space();
        self.mapping_hints
            .range(offset..)
            .map(move |(&offset, hint)| (Address::new(space, offset), hint))
    }

    pub fn function_hints(&self) -> impl Iterator<Item = Address> + '_ {
        let space = self.space();
        self.function_hints
            .iter()
            .map(move |&offset| Address::new(space, offset))
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
    mapping_hints: BTreeMap<RawAddress, ContextHint>,
    function_hints: BTreeSet<RawAddress>,
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

    pub fn mapping_hints(&self) -> &BTreeMap<RawAddress, ContextHint> {
        &self.mapping_hints
    }

    pub fn function_hints(&self) -> &BTreeSet<RawAddress> {
        &self.function_hints
    }

    pub fn set_mapping_hints(
        &mut self,
        mapping_hints: impl IntoIterator<Item = (RawAddress, ContextHint)>,
    ) {
        self.mapping_hints.clear();
        self.mapping_hints.extend(mapping_hints);
    }

    pub fn with_mapping_hints(
        mut self,
        mapping_hints: impl IntoIterator<Item = (RawAddress, ContextHint)>,
    ) -> Self {
        self.set_mapping_hints(mapping_hints);
        self
    }

    pub fn set_function_hints(&mut self, function_hints: impl IntoIterator<Item = RawAddress>) {
        self.function_hints.clear();
        self.function_hints.extend(function_hints);
    }

    pub fn with_function_hints(
        mut self,
        function_hints: impl IntoIterator<Item = RawAddress>,
    ) -> Self {
        self.set_function_hints(function_hints);
        self
    }

    pub fn range(&self) -> Option<AddressRange> {
        AddressRange::from_size(self.start, self.size)
    }

    pub fn extend_mapping_hints(
        &mut self,
        mapping_hints: impl IntoIterator<Item = (RawAddress, ContextHint)>,
    ) {
        self.mapping_hints.extend(mapping_hints);
    }

    pub fn add_mapping_hint(&mut self, offset: impl Into<RawAddress>, hint: ContextHint) {
        self.mapping_hints.insert(offset.into(), hint);
    }

    pub fn extend_function_hints(&mut self, function_hints: impl IntoIterator<Item = RawAddress>) {
        self.function_hints.extend(function_hints);
    }

    pub fn add_function_hint(&mut self, offset: impl Into<RawAddress>) {
        self.function_hints.insert(offset.into());
    }

    pub fn build(
        self,
        storage: &mut SegmentStorage,
    ) -> Result<SegmentMappingId, SegmentStorageError> {
        storage.create_mapping_from_builder(self)
    }
}
