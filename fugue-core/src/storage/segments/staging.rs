use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use bytes::Bytes;
use smallvec::SmallVec;

use crate::ir::{Address, AddressRange, RawAddress};
use crate::storage::segments::mapping::{
    SegmentMapping, SegmentMappingBuilder, SegmentMappingFlags, SegmentMappingId,
    SegmentMappingKind, SegmentMappingProvenance,
};
use crate::storage::segments::provider::SegmentStorageProviderId;
use crate::storage::segments::space::{AddressSpaceId, AddressSpaceKind};
use crate::storage::segments::{SegmentProperties, SegmentStorage, SegmentStorageError};

#[derive(Clone, Copy)]
struct StagedMappingRecord {
    range: AddressRange,
    flags: SegmentMappingFlags,
    kind: SegmentMappingKind,
    offset: u64,
    properties: SegmentProperties,
    provenance: SegmentMappingProvenance,
    provider: SegmentStorageProviderId,
}

impl StagedMappingRecord {
    fn from_builder(builder: &SegmentMappingBuilder) -> Result<Self, SegmentStorageError> {
        Ok(Self {
            range: builder
                .range()
                .ok_or(SegmentStorageError::InvalidAddressRange)?,
            flags: builder.flags(),
            kind: builder.kind(),
            offset: builder.offset(),
            properties: builder.properties(),
            provenance: builder.provenance(),
            provider: builder.provider_id(),
        })
    }

    fn from_storage(
        storage: &SegmentStorage,
        id: SegmentMappingId,
    ) -> Result<Self, SegmentStorageError> {
        let mapping = storage
            .mapping(id)
            .ok_or(SegmentStorageError::UnknownMapping(id))?;
        Ok(Self {
            range: mapping.range(),
            flags: mapping.flags(),
            kind: mapping.kind(),
            offset: mapping.offset(),
            properties: mapping.properties(),
            provenance: mapping.provenance(),
            provider: mapping.provider_id(),
        })
    }

    fn range(&self) -> AddressRange {
        self.range
    }

    fn flags(&self) -> SegmentMappingFlags {
        self.flags
    }

    fn kind(&self) -> SegmentMappingKind {
        self.kind
    }

    fn properties(&self) -> SegmentProperties {
        self.properties
    }

    fn provenance(&self) -> SegmentMappingProvenance {
        self.provenance
    }

    fn provider(&self) -> SegmentStorageProviderId {
        self.provider
    }

    fn set_start(&mut self, start: Address) -> Result<(), SegmentStorageError> {
        let size = self
            .range
            .size()
            .ok_or(SegmentStorageError::InvalidAddressRange)?;
        self.range =
            AddressRange::from_size(start, size).ok_or(SegmentStorageError::InvalidAddressRange)?;
        Ok(())
    }

    fn set_size(&mut self, size: u64) -> Result<(), SegmentStorageError> {
        self.range = AddressRange::from_size(self.range.start_address(), size)
            .ok_or(SegmentStorageError::InvalidAddressRange)?;
        Ok(())
    }

    fn contains(&self, address: RawAddress) -> bool {
        self.range.contains(address)
    }

    fn remaining_from(&self, address: RawAddress) -> Option<u64> {
        self.range
            .remaining_from(Address::new(self.range.space(), address))
    }

    fn physical_offset(&self, address: RawAddress) -> Option<u64> {
        self.offset
            .checked_add(address.offset().checked_sub(self.range.start().offset())?)
    }

    fn update_metadata(
        &mut self,
        kind: SegmentMappingKind,
        provenance: SegmentMappingProvenance,
        flags: SegmentMappingFlags,
    ) {
        self.flags = flags;
        self.kind = kind;
        self.provenance = provenance;
    }
}

struct StagedAddressSpace {
    name: Option<String>,
    kind: AddressSpaceKind,
}

struct StagedSyntheticProvider {
    id: SegmentStorageProviderId,
    size: u64,
}

#[derive(Clone, Copy)]
enum StagedMappingPlacementRecord {
    Bottom {
        mapping: SegmentMappingId,
        space: AddressSpaceId,
    },
    Top {
        mapping: SegmentMappingId,
        space: AddressSpaceId,
    },
}

impl StagedMappingPlacementRecord {
    fn mapping(&self) -> SegmentMappingId {
        match self {
            Self::Bottom { mapping, .. } | Self::Top { mapping, .. } => *mapping,
        }
    }

    fn space(&self) -> AddressSpaceId {
        match self {
            Self::Bottom { space, .. } | Self::Top { space, .. } => *space,
        }
    }
}

pub(crate) struct PreparedSegmentWriteRecord {
    bytes: Bytes,
    offset: u64,
    provider: SegmentStorageProviderId,
}

impl PreparedSegmentWriteRecord {
    fn new(provider: SegmentStorageProviderId, offset: u64, bytes: Bytes) -> Self {
        Self {
            bytes,
            offset,
            provider,
        }
    }
}

pub(crate) struct PreparedSegmentWriteRecords {
    ranges: SmallVec<[AddressRange; 4]>,
    records: SmallVec<[PreparedSegmentWriteRecord; 4]>,
}

impl PreparedSegmentWriteRecords {
    fn new(
        ranges: SmallVec<[AddressRange; 4]>,
        records: SmallVec<[PreparedSegmentWriteRecord; 4]>,
    ) -> Self {
        Self { ranges, records }
    }

    pub(crate) fn ranges(&self) -> &[AddressRange] {
        &self.ranges
    }
}

pub(crate) struct PreparedSegmentBatch {
    created_mappings: BTreeMap<SegmentMappingId, SegmentMappingBuilder>,
    created_spaces: BTreeMap<AddressSpaceId, StagedAddressSpace>,
    placements: BTreeMap<u64, StagedMappingPlacementRecord>,
    removed_mappings: BTreeSet<SegmentMappingId>,
    staged_mappings: BTreeMap<SegmentMappingId, StagedMappingRecord>,
    synthetic_provider: Option<StagedSyntheticProvider>,
    writes: Vec<PreparedSegmentWriteRecord>,
}

#[derive(Default)]
pub(crate) struct SegmentStorageStaging {
    created_mappings: BTreeMap<SegmentMappingId, SegmentMappingBuilder>,
    created_spaces: BTreeMap<AddressSpaceId, StagedAddressSpace>,
    mapping_reservations: usize,
    placement_order: BTreeMap<(AddressSpaceId, SegmentMappingId), u64>,
    placements: BTreeMap<u64, StagedMappingPlacementRecord>,
    removed_mappings: BTreeSet<SegmentMappingId>,
    sequence: u64,
    staged_mappings: BTreeMap<SegmentMappingId, StagedMappingRecord>,
    synthetic_provider: Option<StagedSyntheticProvider>,
    writes: Vec<PreparedSegmentWriteRecord>,
}

impl SegmentStorageStaging {
    fn has_mapping_placement(
        &self,
        storage: &SegmentStorage,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> bool {
        self.placement_order.contains_key(&(space, mapping))
            || storage.is_mapping_in_space(space, mapping)
    }

    fn staged_mapping_mut(
        &mut self,
        storage: &SegmentStorage,
        id: SegmentMappingId,
    ) -> Result<&mut StagedMappingRecord, SegmentStorageError> {
        if self.removed_mappings.contains(&id) {
            return Err(SegmentStorageError::UnknownMapping(id));
        }
        if let Entry::Vacant(entry) = self.staged_mappings.entry(id) {
            entry.insert(StagedMappingRecord::from_storage(storage, id)?);
        }
        Ok(self
            .staged_mappings
            .get_mut(&id)
            .expect("mapping was inserted before mutable lookup"))
    }

    fn set_mapping_placement(&mut self, placement: StagedMappingPlacementRecord) {
        let key = (placement.space(), placement.mapping());
        if let Some(previous) = self.placement_order.remove(&key) {
            self.placements.remove(&previous);
        }
        let sequence = self.sequence;
        self.sequence = self
            .sequence
            .checked_add(1)
            .expect("mapping placement sequence exhausted");
        self.placement_order.insert(key, sequence);
        self.placements.insert(sequence, placement);
    }

    fn staged_mapping(
        &self,
        storage: &SegmentStorage,
        id: SegmentMappingId,
    ) -> Result<StagedMappingRecord, SegmentStorageError> {
        if self.removed_mappings.contains(&id) {
            return Err(SegmentStorageError::UnknownMapping(id));
        }
        if let Some(mapping) = self.created_mappings.get(&id) {
            return StagedMappingRecord::from_builder(mapping);
        }
        self.staged_mappings
            .get(&id)
            .copied()
            .map(Ok)
            .unwrap_or_else(|| StagedMappingRecord::from_storage(storage, id))
    }

    fn staged_mappings_in_space(
        &self,
        storage: &SegmentStorage,
        space: AddressSpaceId,
    ) -> Result<Vec<StagedMappingRecord>, SegmentStorageError> {
        let mut mappings = match storage.spaces().find(|candidate| candidate.id() == space) {
            Some(space) => space
                .priority_list()
                .map(|mapping| mapping.mapping_id())
                .filter(|mapping| !self.removed_mappings.contains(mapping))
                .collect::<Vec<_>>(),
            None if self.created_spaces.contains_key(&space) => Vec::new(),
            None => return Err(SegmentStorageError::UnknownSpace(space)),
        };

        for placement in self
            .placements
            .values()
            .filter(|placement| placement.space() == space)
        {
            let mapping = placement.mapping();
            mappings.retain(|candidate| *candidate != mapping);
            match placement {
                StagedMappingPlacementRecord::Bottom { .. } => mappings.insert(0, mapping),
                StagedMappingPlacementRecord::Top { .. } => mappings.push(mapping),
            }
        }

        mappings
            .into_iter()
            .map(|mapping| self.staged_mapping(storage, mapping))
            .collect()
    }

    pub(crate) fn create_mapping(
        &mut self,
        storage: &SegmentStorage,
        builder: SegmentMappingBuilder,
    ) -> Result<SegmentMappingId, SegmentStorageError> {
        if !storage.contains_provider(builder.provider_id()) {
            return Err(SegmentStorageError::UnknownProvider(builder.provider_id()));
        }
        builder
            .range()
            .ok_or(SegmentStorageError::InvalidAddressRange)?;

        let id = storage.pending_mapping_id(self.mapping_reservations)?;
        self.mapping_reservations = self
            .mapping_reservations
            .checked_add(1)
            .expect("mapping reservation count exhausted");
        self.created_mappings.insert(id, builder);
        Ok(id)
    }

    pub(crate) fn create_synthetic_mapping(
        &mut self,
        storage: &SegmentStorage,
        start: Address,
        bytes: &[u8],
        properties: SegmentProperties,
    ) -> Result<SegmentMappingId, SegmentStorageError> {
        if !self.created_spaces.contains_key(&start.space())
            && !storage
                .spaces()
                .any(|candidate| candidate.id() == start.space())
        {
            return Err(SegmentStorageError::UnknownSpace(start.space()));
        }

        let size = bytes.len() as u64;
        if size == 0 || start.checked_add(size - 1).is_none() {
            return Err(SegmentStorageError::InvalidAddressRange);
        }

        let provider = match &self.synthetic_provider {
            Some(staged) => staged.id,
            None => match storage.synthetic_provider() {
                Some(provider) => provider.id(),
                None => storage.pending_provider_id()?,
            },
        };
        let mut offset = match &self.synthetic_provider {
            Some(staged) => staged.size,
            None => {
                let mut offset = 0;
                for mapping in storage
                    .mappings()
                    .filter(|mapping| mapping.provider_id() == provider)
                {
                    let end = mapping
                        .offset()
                        .checked_add(mapping.size())
                        .ok_or(SegmentStorageError::InvalidAddressRange)?;
                    offset = offset.max(end);
                }
                offset
            }
        };
        for mapping in self
            .created_mappings
            .values()
            .filter(|mapping| mapping.provider_id() == provider)
        {
            let end = mapping
                .offset()
                .checked_add(mapping.size())
                .ok_or(SegmentStorageError::InvalidAddressRange)?;
            offset = offset.max(end);
        }
        for mapping in self
            .staged_mappings
            .values()
            .filter(|mapping| mapping.provider() == provider)
        {
            let size = mapping
                .range()
                .size()
                .ok_or(SegmentStorageError::InvalidAddressRange)?;
            let end = mapping
                .offset
                .checked_add(size)
                .ok_or(SegmentStorageError::InvalidAddressRange)?;
            offset = offset.max(end);
        }
        let builder = SegmentMappingBuilder::new(start, size, offset, provider)
            .with_properties(properties)
            .with_provenance(SegmentMappingProvenance::Synthetic);
        let end = offset
            .checked_add(size)
            .ok_or(SegmentStorageError::InvalidAddressRange)?;
        self.synthetic_provider = Some(StagedSyntheticProvider {
            id: provider,
            size: end,
        });

        let id = storage.pending_mapping_id(self.mapping_reservations)?;
        self.mapping_reservations = self
            .mapping_reservations
            .checked_add(1)
            .expect("mapping reservation count exhausted");
        self.created_mappings.insert(id, builder);
        self.writes.push(PreparedSegmentWriteRecord::new(
            provider,
            offset,
            Bytes::copy_from_slice(bytes),
        ));
        Ok(id)
    }

    pub(crate) fn create_space(
        &mut self,
        storage: &SegmentStorage,
    ) -> Result<AddressSpaceId, SegmentStorageError> {
        let id = storage.pending_space_id(self.created_spaces.len())?;
        self.create_space_with_id(storage, id, None, AddressSpaceKind::Base)?;
        Ok(id)
    }

    pub(crate) fn create_space_with(
        &mut self,
        storage: &SegmentStorage,
        name: String,
        kind: AddressSpaceKind,
    ) -> Result<AddressSpaceId, SegmentStorageError> {
        let id = storage.pending_space_id(self.created_spaces.len())?;
        self.create_space_with_id(storage, id, Some(name), kind)?;
        Ok(id)
    }

    pub(crate) fn create_space_with_id(
        &mut self,
        storage: &SegmentStorage,
        id: AddressSpaceId,
        name: impl Into<Option<String>>,
        kind: AddressSpaceKind,
    ) -> Result<(), SegmentStorageError> {
        if self.created_spaces.contains_key(&id) || storage.spaces().any(|space| space.id() == id) {
            return Err(SegmentStorageError::DuplicateAddressSpace(id));
        }
        let name = name.into();
        if let Some(name) = name.as_deref()
            && (self
                .created_spaces
                .values()
                .any(|space| space.name.as_deref() == Some(name))
                || storage.address_space_by_name(name).is_some())
        {
            return Err(SegmentStorageError::DuplicateAddressSpaceName(
                name.to_owned(),
            ));
        }
        if let AddressSpaceKind::Overlay { base } = kind {
            match self.created_spaces.get(&base) {
                Some(space) if matches!(space.kind, AddressSpaceKind::Overlay { .. }) => {
                    return Err(SegmentStorageError::InvalidOverlayBase(base));
                }
                Some(_) => {}
                None => match storage.spaces.get(&base) {
                    None => return Err(SegmentStorageError::UnknownSpace(base)),
                    Some(space) if space.is_overlay() => {
                        return Err(SegmentStorageError::InvalidOverlayBase(base));
                    }
                    Some(_) => {}
                },
            }
        }

        self.created_spaces
            .insert(id, StagedAddressSpace { name, kind });
        Ok(())
    }

    pub(crate) fn add_mapping(
        &mut self,
        storage: &SegmentStorage,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        let placement = match self.staged_mapping(storage, mapping)?.provenance() {
            SegmentMappingProvenance::FileResidue
            | SegmentMappingProvenance::Segment
            | SegmentMappingProvenance::Synthetic => {
                StagedMappingPlacementRecord::Bottom { mapping, space }
            }
            _ => StagedMappingPlacementRecord::Top { mapping, space },
        };
        self.add_mapping_with_placement(storage, placement)
    }

    pub(crate) fn add_mapping_top(
        &mut self,
        storage: &SegmentStorage,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        self.add_mapping_with_placement(
            storage,
            StagedMappingPlacementRecord::Top { mapping, space },
        )
    }

    pub(crate) fn add_mapping_bottom(
        &mut self,
        storage: &SegmentStorage,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        self.add_mapping_with_placement(
            storage,
            StagedMappingPlacementRecord::Bottom { mapping, space },
        )
    }

    pub(crate) fn remove_mapping(
        &mut self,
        storage: &SegmentStorage,
        id: SegmentMappingId,
    ) -> Result<SmallVec<[AddressRange; 4]>, SegmentStorageError> {
        let placements = self.mapping_placements(storage, id)?;
        if self.created_mappings.remove(&id).is_none() {
            self.staged_mapping(storage, id)?;
            self.staged_mappings.remove(&id);
            self.removed_mappings.insert(id);
        }
        self.placements
            .retain(|_, placement| placement.mapping() != id);
        self.placement_order
            .retain(|(_, mapping), _| *mapping != id);
        Ok(placements)
    }

    pub(crate) fn remap_mapping(
        &mut self,
        storage: &SegmentStorage,
        id: SegmentMappingId,
        start: Address,
    ) -> Result<(), SegmentStorageError> {
        let range = self.staged_mapping(storage, id)?.range();
        let size = range
            .size()
            .ok_or(SegmentStorageError::InvalidAddressRange)?;
        if size == 0 || start.checked_add(size - 1).is_none() {
            return Err(SegmentStorageError::InvalidAddressRange);
        }
        if let Some(builder) = self.created_mappings.get_mut(&id) {
            builder.set_start(start);
        } else {
            self.staged_mapping_mut(storage, id)?.set_start(start)?;
        }
        Ok(())
    }

    pub(crate) fn resize_mapping(
        &mut self,
        storage: &SegmentStorage,
        id: SegmentMappingId,
        size: u64,
    ) -> Result<(), SegmentStorageError> {
        let range = self.staged_mapping(storage, id)?.range();
        if size == 0 || range.start_address().checked_add(size - 1).is_none() {
            return Err(SegmentStorageError::InvalidAddressRange);
        }
        if let Some(builder) = self.created_mappings.get_mut(&id) {
            builder.set_size(size);
        } else {
            self.staged_mapping_mut(storage, id)?.set_size(size)?;
        }
        Ok(())
    }

    pub(crate) fn update_mapping_metadata(
        &mut self,
        storage: &SegmentStorage,
        id: SegmentMappingId,
        kind: SegmentMappingKind,
        provenance: SegmentMappingProvenance,
        flags: SegmentMappingFlags,
    ) -> Result<(), SegmentStorageError> {
        if let Some(builder) = self.created_mappings.get_mut(&id) {
            builder.set_kind(kind);
            builder.set_provenance(provenance);
            builder.set_flags(flags);
        } else {
            self.staged_mapping_mut(storage, id)?
                .update_metadata(kind, provenance, flags);
        }
        Ok(())
    }

    pub(crate) fn prioritise_mapping(
        &mut self,
        storage: &SegmentStorage,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        self.reprioritise_mapping(
            storage,
            StagedMappingPlacementRecord::Top { mapping, space },
        )
    }

    pub(crate) fn deprioritise_mapping(
        &mut self,
        storage: &SegmentStorage,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        self.reprioritise_mapping(
            storage,
            StagedMappingPlacementRecord::Bottom { mapping, space },
        )
    }

    pub(crate) fn mapping_range(
        &self,
        storage: &SegmentStorage,
        space: AddressSpaceId,
        id: SegmentMappingId,
    ) -> Result<Option<AddressRange>, SegmentStorageError> {
        let range = self.staged_mapping(storage, id)?.range();
        Ok(Some(AddressRange::new(space, range.start(), range.end())))
    }

    pub(crate) fn mapping_placements(
        &self,
        storage: &SegmentStorage,
        id: SegmentMappingId,
    ) -> Result<SmallVec<[AddressRange; 4]>, SegmentStorageError> {
        let range = self.staged_mapping(storage, id)?.range();
        let mut spaces = SmallVec::<[AddressSpaceId; 4]>::new();

        if !self.created_mappings.contains_key(&id) {
            for space in storage.mapping_space_ids(id) {
                if let Err(index) = spaces.binary_search(&space) {
                    spaces.insert(index, space);
                }
            }
        }
        for &(space, mapping) in self.placement_order.keys() {
            if mapping == id
                && let Err(index) = spaces.binary_search(&space)
            {
                spaces.insert(index, space);
            }
        }

        Ok(spaces
            .into_iter()
            .map(|space| AddressRange::new(space, range.start(), range.end()))
            .collect())
    }

    pub(crate) fn prepare_write(
        &self,
        storage: &SegmentStorage,
        address: Address,
        bytes: &[u8],
    ) -> Result<Option<PreparedSegmentWriteRecords>, SegmentStorageError> {
        if bytes.is_empty() {
            return Ok(None);
        }

        let size = bytes.len() as u64;
        if address.checked_add(size - 1).is_none() {
            return Err(SegmentStorageError::InvalidAddressRange);
        }

        let mappings = self.staged_mappings_in_space(storage, address.space())?;
        let mut current = address.raw_address();
        let mut remaining = bytes.len();
        let mut source_offset = 0usize;
        let mut targets = SmallVec::<[(SegmentStorageProviderId, u64, Range<usize>); 4]>::new();

        while remaining > 0 {
            let Some((index, mapping)) = mappings
                .iter()
                .enumerate()
                .rev()
                .find(|(_, mapping)| mapping.contains(current))
            else {
                return Err(SegmentStorageError::InvalidAddressRange);
            };
            if !mapping.properties().is_writable() {
                return Err(SegmentStorageError::InvalidAddressRange);
            }

            let mut write_size = mapping
                .remaining_from(current)
                .ok_or(SegmentStorageError::InvalidAddressRange)?;
            for higher in &mappings[index + 1..] {
                let range = higher.range();
                let start = range.start();
                if start > current {
                    let distance = start
                        .offset()
                        .checked_sub(current.offset())
                        .ok_or(SegmentStorageError::InvalidAddressRange)?;
                    write_size = write_size.min(distance);
                }
            }

            let write_size = write_size.min(remaining as u64) as usize;

            if write_size == 0 {
                return Err(SegmentStorageError::InvalidAddressRange);
            }
            let physical_offset = mapping
                .physical_offset(current)
                .ok_or(SegmentStorageError::InvalidAddressRange)?;
            let write_size_u64 = write_size as u64;
            let physical_end = physical_offset
                .checked_add(write_size_u64)
                .ok_or(SegmentStorageError::InvalidAddressRange)?;
            let provider = mapping.provider();
            let committed_size = storage.provider_size(provider);
            let provider_size = self
                .synthetic_provider
                .as_ref()
                .filter(|staged| staged.id == provider)
                .map(|staged| staged.size.max(committed_size.unwrap_or(0)))
                .or(committed_size)
                .ok_or(SegmentStorageError::UnknownProvider(provider))?;
            if physical_end > provider_size {
                return Err(SegmentStorageError::InvalidAddressRange);
            }

            targets.push((
                provider,
                physical_offset,
                source_offset..source_offset + write_size,
            ));
            remaining -= write_size;
            source_offset += write_size;
            if remaining > 0 {
                current = current
                    .checked_add(write_size_u64)
                    .ok_or(SegmentStorageError::InvalidAddressRange)?;
            }
        }

        let mut ranges = SmallVec::new();
        for &(provider, offset, ref source) in &targets {
            self.pending_write_ranges_into(
                storage,
                provider,
                offset,
                source.len() as _,
                &mut ranges,
            )?;
        }

        ranges.sort_unstable();
        ranges.dedup();

        let bytes = Bytes::copy_from_slice(bytes);
        let writes = targets
            .into_iter()
            .map(|(provider, offset, source)| {
                PreparedSegmentWriteRecord::new(provider, offset, bytes.slice(source))
            })
            .collect();
        Ok(Some(PreparedSegmentWriteRecords::new(ranges, writes)))
    }

    fn pending_write_ranges_into(
        &self,
        storage: &SegmentStorage,
        provider: SegmentStorageProviderId,
        offset: u64,
        size: u64,
        ranges: &mut SmallVec<[AddressRange; 4]>,
    ) -> Result<(), SegmentStorageError> {
        let written_end = offset
            .checked_add(size)
            .ok_or(SegmentStorageError::InvalidAddressRange)?;
        let mappings = storage
            .mappings()
            .map(SegmentMapping::id)
            .filter(|id| !self.removed_mappings.contains(id))
            .chain(self.created_mappings.keys().copied());

        for id in mappings {
            let mapping = self.staged_mapping(storage, id)?;
            if mapping.provider() != provider {
                continue;
            }
            let mapping_size = mapping
                .range()
                .size()
                .ok_or(SegmentStorageError::InvalidAddressRange)?;
            let mapping_end = mapping
                .offset
                .checked_add(mapping_size)
                .ok_or(SegmentStorageError::InvalidAddressRange)?;
            let start = offset.max(mapping.offset);
            let end = written_end.min(mapping_end);
            if start >= end {
                continue;
            }
            let first = mapping.range().start().offset() + (start - mapping.offset);
            let last = first + (end - start - 1);
            for placement in self.mapping_placements(storage, id)? {
                ranges.push(AddressRange::new(
                    placement.space(),
                    first.into(),
                    last.into(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn stage_writes(&mut self, writes: PreparedSegmentWriteRecords) {
        self.writes.extend(writes.records);
    }

    pub(crate) fn prepare(self) -> PreparedSegmentBatch {
        PreparedSegmentBatch {
            created_mappings: self.created_mappings,
            created_spaces: self.created_spaces,
            placements: self.placements,
            removed_mappings: self.removed_mappings,
            staged_mappings: self.staged_mappings,
            synthetic_provider: self.synthetic_provider,
            writes: self.writes,
        }
    }

    fn add_mapping_with_placement(
        &mut self,
        storage: &SegmentStorage,
        placement: StagedMappingPlacementRecord,
    ) -> Result<(), SegmentStorageError> {
        let space = placement.space();
        let mapping = placement.mapping();
        self.validate_mapping_space(storage, space, mapping)?;
        if self.has_mapping_placement(storage, space, mapping) {
            return Err(SegmentStorageError::MappingAlreadyInSpace(mapping, space));
        }
        self.set_mapping_placement(placement);
        Ok(())
    }

    fn reprioritise_mapping(
        &mut self,
        storage: &SegmentStorage,
        placement: StagedMappingPlacementRecord,
    ) -> Result<(), SegmentStorageError> {
        let space = placement.space();
        let mapping = placement.mapping();
        self.validate_mapping_space(storage, space, mapping)?;
        if !self.has_mapping_placement(storage, space, mapping) {
            return Err(SegmentStorageError::MappingNotInSpace(mapping, space));
        }
        self.set_mapping_placement(placement);
        Ok(())
    }

    fn validate_mapping_space(
        &self,
        storage: &SegmentStorage,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        if !self.created_spaces.contains_key(&space)
            && !storage.spaces().any(|candidate| candidate.id() == space)
        {
            return Err(SegmentStorageError::UnknownSpace(space));
        }
        self.staged_mapping(storage, mapping)?;
        Ok(())
    }
}

impl PreparedSegmentBatch {
    pub(crate) fn publish(self, storage: &mut SegmentStorage) {
        if let Some(provider) = self.synthetic_provider {
            storage
                .open_synthetic_provider(provider.id, provider.size)
                .expect("synthetic segment backing failed");
        }
        for write in self.writes {
            let written = storage
                .write_bytes_direct(write.provider, write.offset, &write.bytes)
                .expect("staged segment write was admitted before publication");
            assert_eq!(
                written,
                write.bytes.len(),
                "staged segment write was admitted before publication"
            );
        }
        for (id, space) in self.created_spaces {
            storage
                .create_space_with_id(id, space.name, space.kind)
                .expect("staged address space was validated before publication");
        }
        for (id, builder) in self.created_mappings {
            storage
                .create_mapping_with_id(id, builder)
                .expect("staged mapping was validated before publication");
        }
        for (id, mapping) in self.staged_mappings {
            let current = storage
                .mapping(id)
                .expect("staged mapping exists during publication");
            let range = mapping.range();
            let range_size = range
                .size()
                .expect("staged mapping size was validated before publication");
            let start = current.start();
            let size = current.size();
            let kind = current.kind();
            let provenance = current.provenance();
            let flags = current.flags();

            if start != range.start_address() {
                storage
                    .remap_mapping(id, range.start_address())
                    .expect("staged mapping start was validated before publication");
            }
            if size != range_size {
                storage
                    .resize_mapping(id, range_size)
                    .expect("staged mapping size was validated before publication");
            }
            if kind != mapping.kind()
                || provenance != mapping.provenance()
                || flags != mapping.flags()
            {
                storage
                    .update_mapping_metadata(
                        id,
                        mapping.kind(),
                        mapping.provenance(),
                        mapping.flags(),
                    )
                    .expect("staged mapping metadata was validated before publication");
            }
        }
        for (_, placement) in self.placements {
            match (
                storage.is_mapping_in_space(placement.space(), placement.mapping()),
                placement,
            ) {
                (false, StagedMappingPlacementRecord::Bottom { mapping, space }) => storage
                    .add_mapping_to_space_bottom(space, mapping)
                    .expect("staged mapping addition was validated before publication"),
                (false, StagedMappingPlacementRecord::Top { mapping, space }) => storage
                    .add_mapping_to_space_top(space, mapping)
                    .expect("staged mapping addition was validated before publication"),
                (true, StagedMappingPlacementRecord::Bottom { mapping, space }) => storage
                    .deprioritise_mapping(space, mapping)
                    .expect("staged mapping priority was validated before publication"),
                (true, StagedMappingPlacementRecord::Top { mapping, space }) => storage
                    .prioritise_mapping(space, mapping)
                    .expect("staged mapping priority was validated before publication"),
            }
        }
        for mapping in self.removed_mappings {
            storage
                .remove_mapping(mapping)
                .expect("staged mapping removal was validated before publication");
        }
    }
}
