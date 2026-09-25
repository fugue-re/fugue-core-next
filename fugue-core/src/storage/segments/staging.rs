use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use bytes::Bytes;
use smallvec::SmallVec;

use crate::ir::{Address, AddressRange, RawAddress};
use crate::storage::segments::mapping::{
    SegmentMappingBuilder, SegmentMappingFlags, SegmentMappingId, SegmentMappingKind,
    SegmentMappingProvenance,
};
use crate::storage::segments::provider::SegmentStorageProviderId;
use crate::storage::segments::space::AddressSpaceId;
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
        self.range = AddressRange::from_size(start, self.range.size())
            .ok_or(SegmentStorageError::InvalidAddressRange)?;
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
    range: AddressRange,
    records: SmallVec<[PreparedSegmentWriteRecord; 4]>,
}

impl PreparedSegmentWriteRecords {
    fn new(range: AddressRange, records: SmallVec<[PreparedSegmentWriteRecord; 4]>) -> Self {
        Self { range, records }
    }

    pub(crate) fn range(&self) -> AddressRange {
        self.range
    }
}

pub(crate) struct PreparedSegmentBatch {
    created_mappings: BTreeMap<SegmentMappingId, SegmentMappingBuilder>,
    created_spaces: BTreeSet<AddressSpaceId>,
    placements: BTreeMap<u64, StagedMappingPlacementRecord>,
    removed_mappings: BTreeSet<SegmentMappingId>,
    staged_mappings: BTreeMap<SegmentMappingId, StagedMappingRecord>,
    writes: Vec<PreparedSegmentWriteRecord>,
}

#[derive(Default)]
pub(crate) struct SegmentStorageStaging {
    created_mappings: BTreeMap<SegmentMappingId, SegmentMappingBuilder>,
    created_spaces: BTreeSet<AddressSpaceId>,
    mapping_reservations: usize,
    placement_order: BTreeMap<(AddressSpaceId, SegmentMappingId), u64>,
    placements: BTreeMap<u64, StagedMappingPlacementRecord>,
    removed_mappings: BTreeSet<SegmentMappingId>,
    sequence: u64,
    staged_mappings: BTreeMap<SegmentMappingId, StagedMappingRecord>,
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
            None if self.created_spaces.contains(&space) => Vec::new(),
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

    pub(crate) fn create_space(
        &mut self,
        storage: &SegmentStorage,
    ) -> Result<AddressSpaceId, SegmentStorageError> {
        let id = storage.pending_space_id(self.created_spaces.len())?;
        self.created_spaces.insert(id);
        Ok(id)
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
        let range = AddressRange::from_size(start, range.size())
            .ok_or(SegmentStorageError::InvalidAddressRange)?;
        if let Some(builder) = self.created_mappings.get_mut(&id) {
            builder.set_start(range.start_address());
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
        let range = AddressRange::from_size(range.start_address(), size)
            .ok_or(SegmentStorageError::InvalidAddressRange)?;
        if let Some(builder) = self.created_mappings.get_mut(&id) {
            builder.set_size(range.size());
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

        let size =
            u64::try_from(bytes.len()).map_err(|_| SegmentStorageError::InvalidAddressRange)?;
        let range = AddressRange::from_size(address, size)
            .ok_or(SegmentStorageError::InvalidAddressRange)?;
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

            let mut write_size_u64 = mapping
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
                    write_size_u64 = write_size_u64.min(distance);
                }
            }

            let write_size = usize::try_from(write_size_u64)
                .unwrap_or(usize::MAX)
                .min(remaining);
            if write_size == 0 {
                return Err(SegmentStorageError::InvalidAddressRange);
            }
            let physical_offset = mapping
                .physical_offset(current)
                .ok_or(SegmentStorageError::InvalidAddressRange)?;
            let write_size_u64 =
                u64::try_from(write_size).map_err(|_| SegmentStorageError::InvalidAddressRange)?;
            let physical_end = physical_offset
                .checked_add(write_size_u64)
                .ok_or(SegmentStorageError::InvalidAddressRange)?;
            let provider = mapping.provider();
            let provider_size = storage
                .provider_size(provider)
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

        let bytes = Bytes::copy_from_slice(bytes);
        let writes = targets
            .into_iter()
            .map(|(provider, offset, source)| {
                PreparedSegmentWriteRecord::new(provider, offset, bytes.slice(source))
            })
            .collect();
        Ok(Some(PreparedSegmentWriteRecords::new(range, writes)))
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
        if !self.created_spaces.contains(&space)
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
        for space in self.created_spaces {
            storage
                .create_space_with_id(space)
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
            if size != range.size() {
                storage
                    .resize_mapping(id, range.size())
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
