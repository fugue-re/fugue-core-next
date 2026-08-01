use std::collections::{BTreeMap, BTreeSet};

use smallvec::SmallVec;

use crate::ir::{Address, AddressRange, RawAddress};
use crate::storage::segments::mapping::{
    SegmentMappingBuilder, SegmentMappingFlags, SegmentMappingId, SegmentMappingKind,
    SegmentMappingProvenance,
};
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::segments::{SegmentStorage, SegmentStorageError};

type MappingPlacements = SmallVec<[(AddressSpaceId, (RawAddress, RawAddress)); 4]>;

#[derive(Clone, Copy)]
struct ExistingMapping {
    flags: SegmentMappingFlags,
    kind: SegmentMappingKind,
    provenance: SegmentMappingProvenance,
    size: u64,
    start: Address,
}

impl ExistingMapping {
    fn from_storage(
        storage: &SegmentStorage,
        id: SegmentMappingId,
    ) -> Result<Self, SegmentStorageError> {
        let mapping = storage
            .mapping(id)
            .ok_or_else(|| SegmentStorageError::backing_with("mapping not found"))?;
        Ok(Self {
            flags: mapping.flags(),
            kind: mapping.kind(),
            provenance: mapping.provenance(),
            size: mapping.size(),
            start: mapping.start(),
        })
    }
}

#[derive(Clone, Copy)]
enum PlacementPriority {
    Bottom,
    Top,
}

#[derive(Clone, Copy)]
struct MappingPlacement {
    mapping: SegmentMappingId,
    priority: PlacementPriority,
    space: AddressSpaceId,
}

#[derive(Default)]
pub(super) struct SegmentMetadataStage {
    created_mappings: BTreeMap<SegmentMappingId, SegmentMappingBuilder>,
    created_spaces: BTreeSet<AddressSpaceId>,
    mapping_reservations: usize,
    placement_order: BTreeMap<(AddressSpaceId, SegmentMappingId), u64>,
    placements: BTreeMap<u64, MappingPlacement>,
    removed_mappings: BTreeSet<SegmentMappingId>,
    sequence: u64,
    updated_mappings: BTreeMap<SegmentMappingId, ExistingMapping>,
}

impl SegmentMetadataStage {
    pub(super) fn create_mapping(
        &mut self,
        storage: &SegmentStorage,
        builder: SegmentMappingBuilder,
    ) -> Result<SegmentMappingId, SegmentStorageError> {
        if !storage.has_provider(builder.provider_id()) {
            return Err(SegmentStorageError::backing_with("provider not found"));
        }
        Self::validate_extent(builder.start(), builder.size())?;

        let id = storage.preview_mapping_id(self.mapping_reservations)?;
        self.mapping_reservations = self
            .mapping_reservations
            .checked_add(1)
            .expect("mapping reservation count exhausted");
        self.created_mappings.insert(id, builder);
        Ok(id)
    }

    pub(super) fn create_space(
        &mut self,
        storage: &SegmentStorage,
    ) -> Result<AddressSpaceId, SegmentStorageError> {
        let id = storage.preview_space_id(self.created_spaces.len())?;
        self.created_spaces.insert(id);
        Ok(id)
    }

    pub(super) fn add_mapping(
        &mut self,
        storage: &SegmentStorage,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        let priority = match self.mapping_provenance(storage, mapping)? {
            SegmentMappingProvenance::FileResidue
            | SegmentMappingProvenance::Segment
            | SegmentMappingProvenance::Synthetic => PlacementPriority::Bottom,
            _ => PlacementPriority::Top,
        };
        self.place_mapping(storage, space, mapping, priority)
    }

    pub(super) fn add_mapping_top(
        &mut self,
        storage: &SegmentStorage,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        self.place_mapping(storage, space, mapping, PlacementPriority::Top)
    }

    pub(super) fn add_mapping_bottom(
        &mut self,
        storage: &SegmentStorage,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        self.place_mapping(storage, space, mapping, PlacementPriority::Bottom)
    }

    pub(super) fn remove_mapping(
        &mut self,
        storage: &SegmentStorage,
        id: SegmentMappingId,
    ) -> Result<MappingPlacements, SegmentStorageError> {
        let placements = self.mapping_placements(storage, id)?;
        if self.created_mappings.remove(&id).is_none() {
            self.existing_mapping(storage, id)?;
            self.updated_mappings.remove(&id);
            self.removed_mappings.insert(id);
        }
        self.placements
            .retain(|_, placement| placement.mapping != id);
        self.placement_order
            .retain(|(_, mapping), _| *mapping != id);
        Ok(placements)
    }

    pub(super) fn remap_mapping(
        &mut self,
        storage: &SegmentStorage,
        id: SegmentMappingId,
        start: Address,
    ) -> Result<(), SegmentStorageError> {
        let size = self.mapping_extent(storage, id)?.1;
        Self::validate_extent(start, size)?;
        if let Some(builder) = self.created_mappings.get_mut(&id) {
            builder.set_start(start);
        } else {
            self.existing_mapping_mut(storage, id)?.start = start;
        }
        Ok(())
    }

    pub(super) fn resize_mapping(
        &mut self,
        storage: &SegmentStorage,
        id: SegmentMappingId,
        size: u64,
    ) -> Result<(), SegmentStorageError> {
        let start = self.mapping_extent(storage, id)?.0;
        Self::validate_extent(start, size)?;
        if let Some(builder) = self.created_mappings.get_mut(&id) {
            builder.set_size(size);
        } else {
            self.existing_mapping_mut(storage, id)?.size = size;
        }
        Ok(())
    }

    pub(super) fn update_mapping_metadata(
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
            let mapping = self.existing_mapping_mut(storage, id)?;
            mapping.kind = kind;
            mapping.provenance = provenance;
            mapping.flags = flags;
        }
        Ok(())
    }

    pub(super) fn prioritise_mapping(
        &mut self,
        storage: &SegmentStorage,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        self.place_mapping(storage, space, mapping, PlacementPriority::Top)
    }

    pub(super) fn deprioritise_mapping(
        &mut self,
        storage: &SegmentStorage,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        self.place_mapping(storage, space, mapping, PlacementPriority::Bottom)
    }

    pub(super) fn mapping_range(
        &self,
        storage: &SegmentStorage,
        space: AddressSpaceId,
        id: SegmentMappingId,
    ) -> Result<Option<AddressRange>, SegmentStorageError> {
        let (start, size) = self.mapping_extent(storage, id)?;
        if size == 0 {
            return Ok(None);
        }
        AddressRange::from_size(Address::new(space, start.raw_address()), size)
            .map(Some)
            .ok_or(SegmentStorageError::InvalidAddressRange)
    }

    pub(super) fn mapping_placements(
        &self,
        storage: &SegmentStorage,
        id: SegmentMappingId,
    ) -> Result<MappingPlacements, SegmentStorageError> {
        if self.removed_mappings.contains(&id) {
            return Err(SegmentStorageError::backing_with("mapping not found"));
        }
        let (start, size) = self.mapping_extent(storage, id)?;
        if size == 0 {
            return Ok(SmallVec::new());
        }
        let range =
            AddressRange::from_size(start, size).ok_or(SegmentStorageError::InvalidAddressRange)?;
        let mut spaces = SmallVec::<[AddressSpaceId; 4]>::new();

        if !self.created_mappings.contains_key(&id) {
            for (space, _) in storage.mapping_placements(id) {
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
            .map(|space| (space, (range.start(), range.end())))
            .collect())
    }

    pub(super) fn publish(self, storage: &mut SegmentStorage) {
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
        for (id, mapping) in self.updated_mappings {
            let current = storage
                .mapping(id)
                .expect("staged mapping exists during publication");
            let start = current.start();
            let size = current.size();
            let kind = current.kind();
            let provenance = current.provenance();
            let flags = current.flags();

            if start != mapping.start {
                storage
                    .remap_mapping(id, mapping.start)
                    .expect("staged mapping start was validated before publication");
            }
            if size != mapping.size {
                storage
                    .resize_mapping(id, mapping.size)
                    .expect("staged mapping size was validated before publication");
            }
            if kind != mapping.kind || provenance != mapping.provenance || flags != mapping.flags {
                storage
                    .update_mapping_metadata(id, mapping.kind, mapping.provenance, mapping.flags)
                    .expect("staged mapping metadata was validated before publication");
            }
        }
        for (_, placement) in self.placements {
            match placement.priority {
                PlacementPriority::Bottom => storage
                    .add_mapping_to_space_bottom(placement.space, placement.mapping)
                    .expect("staged mapping placement was validated before publication"),
                PlacementPriority::Top => storage
                    .add_mapping_to_space_top(placement.space, placement.mapping)
                    .expect("staged mapping placement was validated before publication"),
            }
        }
        for mapping in self.removed_mappings {
            storage
                .remove_mapping(mapping)
                .expect("staged mapping removal was validated before publication");
        }
    }

    fn existing_mapping(
        &self,
        storage: &SegmentStorage,
        id: SegmentMappingId,
    ) -> Result<ExistingMapping, SegmentStorageError> {
        if self.removed_mappings.contains(&id) {
            return Err(SegmentStorageError::backing_with("mapping not found"));
        }
        self.updated_mappings
            .get(&id)
            .copied()
            .map(Ok)
            .unwrap_or_else(|| ExistingMapping::from_storage(storage, id))
    }

    fn existing_mapping_mut(
        &mut self,
        storage: &SegmentStorage,
        id: SegmentMappingId,
    ) -> Result<&mut ExistingMapping, SegmentStorageError> {
        if self.removed_mappings.contains(&id) {
            return Err(SegmentStorageError::backing_with("mapping not found"));
        }
        if let std::collections::btree_map::Entry::Vacant(entry) = self.updated_mappings.entry(id) {
            entry.insert(ExistingMapping::from_storage(storage, id)?);
        }
        Ok(self
            .updated_mappings
            .get_mut(&id)
            .expect("mapping was inserted before mutable lookup"))
    }

    fn mapping_extent(
        &self,
        storage: &SegmentStorage,
        id: SegmentMappingId,
    ) -> Result<(Address, u64), SegmentStorageError> {
        if self.removed_mappings.contains(&id) {
            return Err(SegmentStorageError::backing_with("mapping not found"));
        }
        if let Some(mapping) = self.created_mappings.get(&id) {
            return Ok((mapping.start(), mapping.size()));
        }
        let mapping = self.existing_mapping(storage, id)?;
        Ok((mapping.start, mapping.size))
    }

    fn mapping_provenance(
        &self,
        storage: &SegmentStorage,
        id: SegmentMappingId,
    ) -> Result<SegmentMappingProvenance, SegmentStorageError> {
        if self.removed_mappings.contains(&id) {
            return Err(SegmentStorageError::backing_with("mapping not found"));
        }
        if let Some(mapping) = self.created_mappings.get(&id) {
            return Ok(mapping.provenance());
        }
        Ok(self.existing_mapping(storage, id)?.provenance)
    }

    fn place_mapping(
        &mut self,
        storage: &SegmentStorage,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
        priority: PlacementPriority,
    ) -> Result<(), SegmentStorageError> {
        if !self.created_spaces.contains(&space)
            && !storage.spaces().any(|candidate| candidate.id() == space)
        {
            return Err(SegmentStorageError::backing_with("space not found"));
        }
        self.mapping_extent(storage, mapping)?;

        let key = (space, mapping);
        if let Some(previous) = self.placement_order.remove(&key) {
            self.placements.remove(&previous);
        }
        let sequence = self.sequence;
        self.sequence = self
            .sequence
            .checked_add(1)
            .expect("mapping placement sequence exhausted");
        self.placement_order.insert(key, sequence);
        self.placements.insert(
            sequence,
            MappingPlacement {
                mapping,
                priority,
                space,
            },
        );
        Ok(())
    }

    fn validate_extent(start: Address, size: u64) -> Result<(), SegmentStorageError> {
        if size == 0 || AddressRange::from_size(start, size).is_some() {
            Ok(())
        } else {
            Err(SegmentStorageError::InvalidAddressRange)
        }
    }
}
