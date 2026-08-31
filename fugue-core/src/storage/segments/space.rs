use std::collections::BTreeMap;
use std::fmt;
use std::mem::size_of;

use iset::IntervalMap;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use thiserror::Error;

use crate::ir::{Address, AddressRange, AddressRangeExt, RawAddress};
use crate::storage::EntityKeyCodec;
use crate::storage::segments::SegmentProperties;
use crate::storage::segments::mapping::{SegmentMappingId, SegmentMappingRef, SegmentSubMapping};
use crate::types::Revision;

#[derive(Debug, Error)]
pub enum AddressSpaceError {
    #[error("address space index {0} out of range")]
    IndexOutOfRange(usize),
}

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
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(transparent)]
pub struct AddressSpaceId(u16);

impl fmt::Display for AddressSpaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl AddressSpaceId {
    pub fn try_new(index: usize) -> Result<Self, AddressSpaceError> {
        u16::try_from(index)
            .map(Self)
            .map_err(|_| AddressSpaceError::IndexOutOfRange(index))
    }

    pub const fn new(index: usize) -> Self {
        assert!(
            index <= u16::MAX as usize,
            "address space index out of range"
        );
        Self(index as u16)
    }

    pub const fn value(&self) -> u16 {
        self.0
    }

    pub const fn index(&self) -> usize {
        self.value() as usize
    }
}

impl EntityKeyCodec for AddressSpaceId {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let (value, rest) = input.split_at_checked(size_of::<u16>())?;
        *input = rest;
        Some(Self::from(u16::from_be_bytes(value.try_into().ok()?)))
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        output.extend(self.value().to_be_bytes());
    }
}

impl TryFrom<usize> for AddressSpaceId {
    type Error = AddressSpaceError;

    fn try_from(index: usize) -> Result<Self, Self::Error> {
        Self::try_new(index)
    }
}

impl From<u8> for AddressSpaceId {
    fn from(id: u8) -> Self {
        Self(id as u16)
    }
}

impl From<u16> for AddressSpaceId {
    fn from(id: u16) -> Self {
        Self(id)
    }
}

impl From<AddressSpaceId> for usize {
    fn from(id: AddressSpaceId) -> Self {
        id.0 as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(PartialEq, Eq))]
pub enum AddressSpaceKind {
    Base,
    Overlay { base: AddressSpaceId },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
struct MappingPriority(i64);

impl MappingPriority {
    fn higher(self) -> Self {
        Self(
            self.0
                .checked_add(1)
                .expect("mapping priority range exhausted"),
        )
    }

    fn lower(self) -> Self {
        Self(
            self.0
                .checked_sub(1)
                .expect("mapping priority range exhausted"),
        )
    }
}

#[derive(Debug, Clone)]
struct MappingPlacement {
    priority: MappingPriority,
    range: AddressRange,
}

#[derive(Debug, Clone)]
pub struct AddressSpace {
    id: AddressSpaceId,
    kind: AddressSpaceKind,
    submaps: IntervalMap<Address, SegmentSubMapping>,
    mapping_extents: IntervalMap<Address, SegmentMappingId>,
    mappings_by_priority: BTreeMap<MappingPriority, SegmentMappingRef>,
    mapping_placements: FxHashMap<SegmentMappingId, MappingPlacement>,
    highest_priority: MappingPriority,
    lowest_priority: MappingPriority,
    revision: Revision,
}

impl AddressSpace {
    pub fn new(id: AddressSpaceId) -> Self {
        Self::new_with(id, AddressSpaceKind::Base)
    }

    pub fn new_with(id: AddressSpaceId, kind: AddressSpaceKind) -> Self {
        Self {
            id,
            kind,
            submaps: IntervalMap::new(),
            mapping_extents: IntervalMap::new(),
            mappings_by_priority: BTreeMap::new(),
            mapping_placements: FxHashMap::default(),
            highest_priority: MappingPriority::default(),
            lowest_priority: MappingPriority::default(),
            revision: Revision::default(),
        }
    }

    pub fn id(&self) -> AddressSpaceId {
        self.id
    }

    pub(crate) fn revision(&self) -> Revision {
        self.revision
    }

    pub fn find_containing_mut(
        &mut self,
        addr: impl Into<Address>,
    ) -> Option<&mut SegmentSubMapping> {
        let addr = Address::new(self.id, addr.into());
        self.submaps.values_overlap_mut(addr).next()
    }

    pub(crate) fn contains_mapping(&self, mapping_id: SegmentMappingId) -> bool {
        self.mapping_placements.contains_key(&mapping_id)
    }

    pub fn is_empty(&self) -> bool {
        self.submaps.is_empty()
    }

    pub fn is_overlay(&self) -> bool {
        matches!(self.kind, AddressSpaceKind::Overlay { .. })
    }

    pub fn kind(&self) -> AddressSpaceKind {
        self.kind
    }

    pub fn priority_list(
        &self,
    ) -> impl DoubleEndedIterator<Item = &SegmentMappingRef> + ExactSizeIterator + Clone {
        self.mappings_by_priority.values()
    }

    pub fn iter(&self) -> impl Iterator<Item = &SegmentSubMapping> {
        self.submaps.iter(..).map(|(_, view)| view)
    }

    pub fn iter_from(
        &self,
        start: Option<Address>,
    ) -> Box<dyn Iterator<Item = &SegmentSubMapping> + '_> {
        match start {
            Some(start) => {
                let end = Address::new(self.id, RawAddress::MAX);
                Box::new(self.submaps.iter(start..=end).map(|(_, view)| view))
            }
            None => Box::new(self.iter()),
        }
    }

    pub fn find_containing(&self, addr: impl Into<Address>) -> Option<&SegmentSubMapping> {
        let addr = Address::new(self.id, addr.into());
        self.submaps.values_overlap(addr).next()
    }

    pub fn gap_len_at(&self, addr: impl Into<Address>, max: usize) -> usize {
        let addr = Address::new(self.id, addr.into());
        let end = Address::new(self.id, RawAddress::MAX);
        self.submaps
            .values(addr..=end)
            .map(SegmentSubMapping::start)
            .find(|start| *start > addr)
            .map_or(max, |next| usize::from(next - addr).min(max))
    }

    pub fn base(&self) -> Option<AddressSpaceId> {
        match self.kind {
            AddressSpaceKind::Base => None,
            AddressSpaceKind::Overlay { base } => Some(base),
        }
    }

    fn touch(&mut self) {
        self.revision = self.revision.next();
    }

    pub(crate) fn add_mapping_top(
        &mut self,
        mapping_ref: SegmentMappingRef,
        addr: impl Into<Address>,
        size: u64,
        properties: SegmentProperties,
    ) {
        let start = Address::new(self.id, addr.into());
        let range =
            AddressRange::from_size(start, size).expect("mapping range is non-empty and bounded");

        self.highest_priority = self.highest_priority.higher();
        self.update_mapping_placement(mapping_ref, self.highest_priority, range);
        self.touch();

        self.insert_submap_top(mapping_ref, range, properties);
    }

    fn insert_submap_top(
        &mut self,
        mapping_ref: SegmentMappingRef,
        range: AddressRange,
        properties: SegmentProperties,
    ) {
        let range = AddressRange::new(self.id, range.start(), range.end());
        let start = range.start_address();
        let last = range.end_address();

        let overlapping = self
            .submaps
            .iter(start..=last)
            .map(|(iv, view)| (iv.clone(), view.clone()))
            .collect::<SmallVec<[_; 8]>>();

        for (iv, view) in overlapping {
            self.submaps.remove(iv);

            if view.start() < start
                && let Some(left) = view.with_last(start - 1usize)
            {
                self.submaps.insert(
                    left.range().start_address()..=left.range().end_address(),
                    left,
                );
            }
            if view.last() > last
                && let Some(right) = view.with_start(last + 1usize)
            {
                self.submaps.insert(
                    right.range().start_address()..=right.range().end_address(),
                    right,
                );
            }
        }

        let new_view = SegmentSubMapping::new(mapping_ref, range, properties);
        self.submaps.insert(start..=last, new_view);
    }

    pub(crate) fn add_mapping_bottom(
        &mut self,
        mapping_ref: SegmentMappingRef,
        addr: impl Into<Address>,
        size: u64,
        properties: SegmentProperties,
    ) {
        let start = Address::new(self.id, addr.into());
        let range =
            AddressRange::from_size(start, size).expect("mapping range is non-empty and bounded");

        self.lowest_priority = self.lowest_priority.lower();
        self.update_mapping_placement(mapping_ref, self.lowest_priority, range);
        self.touch();

        let start = range.start_address();
        let last = range.end_address();

        let mut gaps = SmallVec::<[_; 8]>::new();
        let mut current = Some(start);

        let overlapping = self
            .submaps
            .iter(start..=last)
            .map(|(iv, _)| iv.clone())
            .collect::<SmallVec<[_; 8]>>();

        for iv in overlapping {
            let iv_start = *iv.start();
            let Some(gap_start) = current else {
                break;
            };
            if iv_start > gap_start {
                gaps.push(gap_start..=(iv_start - 1usize));
            }
            if *iv.end() >= last {
                current = None;
                break;
            }
            current = Some((*iv.end() + 1usize).max(gap_start));
        }

        if let Some(gap_start) = current
            && gap_start <= last
        {
            gaps.push(gap_start..=last);
        }

        for gap in gaps {
            let view = SegmentSubMapping::new(
                mapping_ref,
                AddressRange::new(self.id, gap.first().raw_address(), gap.last().raw_address()),
                properties,
            );
            self.submaps.insert(gap, view);
        }
    }

    pub(crate) fn deprioritise(&mut self, mapping_id: SegmentMappingId) {
        let Some(placement) = self.mapping_placements.get_mut(&mapping_id) else {
            return;
        };
        let mapping_ref = self
            .mappings_by_priority
            .remove(&placement.priority)
            .expect("mapping priority index is consistent");

        self.lowest_priority = self.lowest_priority.lower();
        placement.priority = self.lowest_priority;
        assert!(
            self.mappings_by_priority
                .insert(self.lowest_priority, mapping_ref)
                .is_none(),
            "mapping priority is unique"
        );
        self.touch();
    }

    pub(crate) fn rebuild_range(
        &mut self,
        range: AddressRange,
        mappings: impl IntoIterator<Item = (SegmentMappingRef, RawAddress, u64, SegmentProperties)>,
    ) {
        let range = AddressRange::new(self.id, range.start(), range.end());
        let range_start = range.start_address();
        let range_last = range.end_address();

        let overlapping = self
            .submaps
            .iter(range_start..=range_last)
            .map(|(iv, view)| (iv.clone(), view.clone()))
            .collect::<SmallVec<[_; 8]>>();

        for (iv, view) in overlapping {
            self.submaps.remove(iv);

            if view.start() < range_start
                && let Some(left) = view.with_last(range_start - 1usize)
            {
                self.submaps.insert(
                    left.range().start_address()..=left.range().end_address(),
                    left,
                );
            }
            if view.last() > range_last
                && let Some(right) = view.with_start(range_last + 1usize)
            {
                self.submaps.insert(
                    right.range().start_address()..=right.range().end_address(),
                    right,
                );
            }
        }

        for (mapping_ref, start, size, properties) in mappings {
            let mapping_range = AddressRange::from_size(Address::new(self.id, start), size)
                .expect("mapping range is non-empty and bounded");
            if !range.intersects(&mapping_range) {
                continue;
            }

            let clamped = AddressRange::new(
                self.id,
                mapping_range.start().max(range.start()),
                mapping_range.end().min(range.end()),
            );
            self.insert_submap_top(mapping_ref, clamped, properties);
        }

        self.touch();
    }

    pub(crate) fn remove_mapping_ref(&mut self, mapping_id: SegmentMappingId) -> bool {
        let Some(placement) = self.mapping_placements.remove(&mapping_id) else {
            return false;
        };

        self.mappings_by_priority
            .remove(&placement.priority)
            .expect("mapping priority index is consistent");
        self.mapping_extents
            .remove_where(
                placement.range.start_address()..=placement.range.end_address(),
                |candidate| *candidate == mapping_id,
            )
            .expect("mapping extent index is consistent");
        true
    }

    pub(crate) fn update_mapping_ref(
        &mut self,
        mapping_ref: SegmentMappingRef,
        range: AddressRange,
    ) {
        let mapping_id = mapping_ref.mapping_id();
        let priority = self
            .mapping_placements
            .get(&mapping_id)
            .expect("mapping placement exists")
            .priority;
        let range = AddressRange::new(self.id, range.start(), range.end());
        self.update_mapping_placement(mapping_ref, priority, range);
        self.touch();
    }

    pub(crate) fn mappings_overlapping(
        &self,
        range: AddressRange,
    ) -> SmallVec<[SegmentMappingRef; 8]> {
        let start = Address::new(self.id, range.start());
        let last = Address::new(self.id, range.end());
        let mut mappings = self
            .mapping_extents
            .values(start..=last)
            .map(|mapping_id| {
                let placement = self
                    .mapping_placements
                    .get(mapping_id)
                    .expect("mapping extent index is consistent");
                let mapping_ref = self
                    .mappings_by_priority
                    .get(&placement.priority)
                    .expect("mapping priority index is consistent");
                (placement.priority, *mapping_ref)
            })
            .collect::<SmallVec<[_; 8]>>();
        mappings.sort_unstable_by_key(|(priority, _)| *priority);
        mappings
            .into_iter()
            .map(|(_, mapping_ref)| mapping_ref)
            .collect()
    }

    fn update_mapping_placement(
        &mut self,
        mapping_ref: SegmentMappingRef,
        priority: MappingPriority,
        range: AddressRange,
    ) {
        let mapping_id = mapping_ref.mapping_id();
        if let Some(previous) = self.mapping_placements.remove(&mapping_id) {
            self.mappings_by_priority
                .remove(&previous.priority)
                .expect("mapping priority index is consistent");
            self.mapping_extents
                .remove_where(
                    previous.range.start_address()..=previous.range.end_address(),
                    |candidate| *candidate == mapping_id,
                )
                .expect("mapping extent index is consistent");
        }
        self.mapping_extents
            .force_insert(range.start_address()..=range.end_address(), mapping_id);
        assert!(
            self.mappings_by_priority
                .insert(priority, mapping_ref)
                .is_none(),
            "mapping priority is unique"
        );
        self.mapping_placements
            .insert(mapping_id, MappingPlacement { priority, range });
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::storage::segments::mapping::SegmentMapping;
    use crate::storage::segments::provider::SegmentStorageProviderId;

    const MODEL_BASE: u64 = 0x1000;
    const MODEL_SIZE: usize = 64;
    const MODEL_MAX_MAPPING_SIZE: usize = 16;

    #[derive(Clone, Copy)]
    struct ModelMapping {
        id: SegmentMappingId,
        size: u64,
        start: RawAddress,
    }

    impl ModelMapping {
        fn contains(self, address: RawAddress) -> bool {
            address >= self.start && address < self.end()
        }

        fn end(self) -> RawAddress {
            self.start + self.size
        }

        fn last(self) -> RawAddress {
            self.end() - 1usize
        }

        fn overlaps(self, start: RawAddress, end: RawAddress) -> bool {
            self.start < end && self.end() > start
        }
    }

    #[derive(Default)]
    struct SpaceModel {
        mappings: Vec<ModelMapping>,
        priority: Vec<SegmentMappingId>,
    }

    impl SpaceModel {
        fn add_mapping(&mut self, mapping: ModelMapping) {
            self.mappings.push(mapping);
        }

        fn add_bottom(&mut self, id: SegmentMappingId) {
            self.priority.retain(|candidate| *candidate != id);
            self.priority.insert(0, id);
        }

        fn add_top(&mut self, id: SegmentMappingId) {
            self.priority.retain(|candidate| *candidate != id);
            self.priority.push(id);
        }

        fn covering(&self, address: RawAddress) -> Vec<SegmentMappingId> {
            self.priority
                .iter()
                .rev()
                .filter(|id| self.mapping(**id).contains(address))
                .copied()
                .collect()
        }

        fn deprioritise(&mut self, id: SegmentMappingId) {
            if self.is_placed(id) {
                self.add_bottom(id);
            }
        }

        fn is_placed(&self, id: SegmentMappingId) -> bool {
            self.priority.contains(&id)
        }

        fn mapping(&self, id: SegmentMappingId) -> ModelMapping {
            self.mappings
                .iter()
                .find(|mapping| mapping.id == id)
                .copied()
                .expect("model mapping exists")
        }

        fn mappings_overlapping(
            &self,
            start: RawAddress,
            end: RawAddress,
        ) -> Vec<(SegmentMappingRef, RawAddress, u64, SegmentProperties)> {
            self.priority
                .iter()
                .filter_map(|id| {
                    let mapping = self.mapping(*id);
                    mapping.overlaps(start, end).then_some((
                        mapping_ref(id.index()),
                        mapping.start,
                        mapping.size,
                        SegmentProperties::default(),
                    ))
                })
                .collect()
        }

        fn remove_mapping(&mut self, id: SegmentMappingId) -> ModelMapping {
            self.priority.retain(|candidate| *candidate != id);
            let index = self
                .mappings
                .iter()
                .position(|mapping| mapping.id == id)
                .expect("model mapping exists");
            self.mappings.remove(index)
        }

        fn set_size(&mut self, id: SegmentMappingId, size: u64) {
            self.mappings
                .iter_mut()
                .find(|mapping| mapping.id == id)
                .expect("model mapping exists")
                .size = size;
        }

        fn set_start(&mut self, id: SegmentMappingId, start: RawAddress) {
            self.mappings
                .iter_mut()
                .find(|mapping| mapping.id == id)
                .expect("model mapping exists")
                .start = start;
        }

        fn unplace(&mut self, id: SegmentMappingId) {
            self.priority.retain(|candidate| *candidate != id);
        }
    }

    struct ModelRng(u64);

    impl ModelRng {
        fn index(&mut self, upper: usize) -> usize {
            let mut value = self.0;
            value ^= value << 13;
            value ^= value >> 7;
            value ^= value << 17;
            self.0 = value;
            value as usize % upper
        }
    }

    fn mapping_ref(id: usize) -> SegmentMappingRef {
        SegmentMapping::new(
            SegmentMappingId::new(id),
            AddressRange::point(Address::from(0u64)),
            0,
            SegmentStorageProviderId::new(0),
            SegmentProperties::default(),
        )
        .expect("model mapping range is valid")
        .mapping_ref()
    }

    fn model_range(rng: &mut ModelRng) -> (RawAddress, u64) {
        let start = RawAddress::from(MODEL_BASE + rng.index(MODEL_SIZE) as u64);
        let size = rng.index(MODEL_MAX_MAPPING_SIZE) as u64 + 1;
        (start, size)
    }

    fn rebuild_from_model(
        space: &mut AddressSpace,
        model: &SpaceModel,
        start: RawAddress,
        end: RawAddress,
    ) {
        space.rebuild_range(
            AddressRange::new(space.id(), start, end - 1usize),
            model.mappings_overlapping(start, end),
        );
    }

    fn validate_model(space: &AddressSpace, model: &SpaceModel, step: usize) {
        let priority = space
            .priority_list()
            .map(SegmentMappingRef::mapping_id)
            .collect::<Vec<_>>();
        assert_eq!(priority, model.priority, "priority mismatch at step {step}");
        assert_eq!(space.mapping_placements.len(), model.priority.len());
        assert_eq!(space.mappings_by_priority.len(), model.priority.len());
        assert_eq!(space.mapping_extents.len(), model.priority.len());

        let mut expected_extents = model
            .priority
            .iter()
            .map(|id| {
                let mapping = model.mapping(*id);
                (mapping.start, mapping.last(), *id)
            })
            .collect::<Vec<_>>();
        expected_extents.sort_unstable();
        let mut actual_extents = space
            .mapping_extents
            .iter(..)
            .map(|(range, id)| (range.start().raw_address(), range.end().raw_address(), *id))
            .collect::<Vec<_>>();
        actual_extents.sort_unstable();
        assert_eq!(
            actual_extents, expected_extents,
            "extent mismatch at step {step}"
        );

        for mapping in &model.mappings {
            let placement = space.mapping_placements.get(&mapping.id);
            assert_eq!(placement.is_some(), model.is_placed(mapping.id));
            let Some(placement) = placement else {
                continue;
            };
            let range = placement.range;
            assert_eq!(range.start(), mapping.start);
            assert_eq!(range.end(), mapping.last());
            assert_eq!(
                space
                    .mappings_by_priority
                    .get(&placement.priority)
                    .map(SegmentMappingRef::mapping_id),
                Some(mapping.id)
            );
        }

        let query_start = MODEL_BASE - 1;
        let query_end = MODEL_BASE + MODEL_SIZE as u64 + MODEL_MAX_MAPPING_SIZE as u64;
        for address in query_start..query_end {
            let address = RawAddress::from(address);
            let expected = model.covering(address);
            let actual = space
                .mappings_overlapping(AddressRange::point(Address::new(space.id(), address)))
                .into_iter()
                .rev()
                .map(|mapping_ref| mapping_ref.mapping_id())
                .collect::<Vec<_>>();
            assert_eq!(
                actual, expected,
                "coverage mismatch at {address:#x}, step {step}"
            );
            assert_eq!(
                space
                    .find_containing(address)
                    .map(|submap| submap.mapping_ref().mapping_id()),
                expected.first().copied(),
                "visible mapping mismatch at {address:#x}, step {step}"
            );
        }

        let mut previous_last = None;
        for submap in space.iter() {
            if let Some(previous_last) = previous_last {
                assert!(
                    previous_last < submap.start(),
                    "overlapping submaps at step {step}"
                );
            }
            previous_last = Some(submap.last());
        }
    }

    #[test]
    fn test_address_space_indexes_follow_modelled_mutations() {
        let mut rng = ModelRng(0x4d59_5df4_d0f3_3173);
        let mut model = SpaceModel::default();
        let mut space = AddressSpace::new(AddressSpaceId::new(0));
        let properties = SegmentProperties::default();
        let mut next_id = 0;

        for index in 0..8 {
            let (start, size) = model_range(&mut rng);
            let id = SegmentMappingId::new(next_id);
            next_id += 1;
            model.add_mapping(ModelMapping { id, size, start });
            if index % 2 == 0 {
                space.add_mapping_top(mapping_ref(id.index()), start, size, properties);
                model.add_top(id);
            } else {
                space.add_mapping_bottom(mapping_ref(id.index()), start, size, properties);
                model.add_bottom(id);
            }
        }
        validate_model(&space, &model, 0);

        for step in 1..=512 {
            let mapping = model.mappings[rng.index(model.mappings.len())];
            match step % 7 {
                0 => {
                    space.add_mapping_top(
                        mapping_ref(mapping.id.index()),
                        mapping.start,
                        mapping.size,
                        properties,
                    );
                    model.add_top(mapping.id);
                }
                1 => {
                    if model.is_placed(mapping.id) {
                        assert!(space.remove_mapping_ref(mapping.id));
                        model.unplace(mapping.id);
                        rebuild_from_model(&mut space, &model, mapping.start, mapping.end());
                    }
                    space.add_mapping_bottom(
                        mapping_ref(mapping.id.index()),
                        mapping.start,
                        mapping.size,
                        properties,
                    );
                    model.add_bottom(mapping.id);
                }
                2 => {
                    space.deprioritise(mapping.id);
                    model.deprioritise(mapping.id);
                    rebuild_from_model(&mut space, &model, mapping.start, mapping.end());
                }
                3 => {
                    let was_placed = model.is_placed(mapping.id);
                    if was_placed {
                        assert!(space.remove_mapping_ref(mapping.id));
                        model.unplace(mapping.id);
                        rebuild_from_model(&mut space, &model, mapping.start, mapping.end());
                    }
                    let (start, _) = model_range(&mut rng);
                    model.set_start(mapping.id, start);
                    if was_placed {
                        space.add_mapping_top(
                            mapping_ref(mapping.id.index()),
                            start,
                            mapping.size,
                            properties,
                        );
                        model.add_top(mapping.id);
                    }
                }
                4 => {
                    let was_placed = model.is_placed(mapping.id);
                    if was_placed {
                        assert!(space.remove_mapping_ref(mapping.id));
                        model.unplace(mapping.id);
                        rebuild_from_model(&mut space, &model, mapping.start, mapping.end());
                    }
                    let size = rng.index(MODEL_MAX_MAPPING_SIZE) as u64 + 1;
                    model.set_size(mapping.id, size);
                    if was_placed {
                        space.add_mapping_top(
                            mapping_ref(mapping.id.index()),
                            mapping.start,
                            size,
                            properties,
                        );
                        model.add_top(mapping.id);
                    }
                }
                5 => {
                    let removed = model.remove_mapping(mapping.id);
                    if space.remove_mapping_ref(mapping.id) {
                        rebuild_from_model(&mut space, &model, removed.start, removed.end());
                    }
                    let (start, size) = model_range(&mut rng);
                    let id = SegmentMappingId::new(next_id);
                    next_id += 1;
                    model.add_mapping(ModelMapping { id, size, start });
                }
                6 => {
                    let start = RawAddress::from(MODEL_BASE + rng.index(MODEL_SIZE) as u64);
                    let end = start + rng.index(MODEL_MAX_MAPPING_SIZE) as u64 + 1u64;
                    rebuild_from_model(&mut space, &model, start, end);
                }
                _ => unreachable!(),
            }
            validate_model(&space, &model, step);
        }
    }

    #[test]
    fn test_add_mapping_top() {
        let mut space = AddressSpace::new(AddressSpaceId::new(0));
        let properties = SegmentProperties::default();

        space.add_mapping_top(mapping_ref(1), 0x1000u64, 0x1001, properties);
        space.add_mapping_top(mapping_ref(2), 0x1500u64, 0x301, properties);

        let view = space.find_containing(0x1500u64).unwrap();
        assert_eq!(view.mapping_ref().mapping_id(), SegmentMappingId::new(2));

        let view = space.find_containing(0x1000u64).unwrap();
        assert_eq!(view.mapping_ref().mapping_id(), SegmentMappingId::new(1));

        let view = space.find_containing(0x1900u64).unwrap();
        assert_eq!(view.mapping_ref().mapping_id(), SegmentMappingId::new(1));

        space.add_mapping_top(mapping_ref(1), 0x1000u64, 0x1001, properties);
        assert_eq!(
            space
                .priority_list()
                .map(SegmentMappingRef::mapping_id)
                .collect::<Vec<_>>(),
            [SegmentMappingId::new(2), SegmentMappingId::new(1)]
        );
    }

    #[test]
    fn test_add_mapping_bottom() {
        let mut space = AddressSpace::new(AddressSpaceId::new(0));
        let properties = SegmentProperties::default();

        space.add_mapping_top(mapping_ref(1), 0x1000u64, 0x501, properties);
        space.add_mapping_bottom(mapping_ref(2), 0x1000u64, 0x1001, properties);

        let view = space.find_containing(0x1200u64).unwrap();
        assert_eq!(view.mapping_ref().mapping_id(), SegmentMappingId::new(1));

        let view = space.find_containing(0x1800u64).unwrap();
        assert_eq!(view.mapping_ref().mapping_id(), SegmentMappingId::new(2));
        assert_eq!(
            space
                .priority_list()
                .map(SegmentMappingRef::mapping_id)
                .collect::<Vec<_>>(),
            [SegmentMappingId::new(2), SegmentMappingId::new(1)]
        );
    }

    #[test]
    fn test_remove_mapping_ref() {
        let mut space = AddressSpace::new(AddressSpaceId::new(0));
        let properties = SegmentProperties::default();

        space.add_mapping_top(mapping_ref(1), 0x1000u64, 0x1001, properties);
        space.add_mapping_top(mapping_ref(2), 0x3000u64, 0x1001, properties);

        assert!(space.remove_mapping_ref(SegmentMappingId::new(1)));
        space.rebuild_range(
            AddressRange::new(
                space.id(),
                RawAddress::from(0x1000u64),
                RawAddress::from(0x2000u64),
            ),
            [],
        );

        assert!(space.find_containing(0x1500u64).is_none());
        assert!(space.find_containing(0x3500u64).is_some());
        assert_eq!(
            space
                .priority_list()
                .map(SegmentMappingRef::mapping_id)
                .collect::<Vec<_>>(),
            [SegmentMappingId::new(2)]
        );
    }

    #[test]
    fn test_rebuild_range_priority_order() {
        let mut space = AddressSpace::new(AddressSpaceId::new(0));
        let props = SegmentProperties::default();

        space.add_mapping_top(mapping_ref(1), 0x1000u64, 0x1000, props);
        space.add_mapping_top(mapping_ref(2), 0x1500u64, 0x1000, props);

        assert_eq!(
            space
                .find_containing(0x1800u64)
                .unwrap()
                .mapping_ref()
                .mapping_id(),
            SegmentMappingId::new(2)
        );

        space.deprioritise(SegmentMappingId::new(2));
        assert_eq!(
            space
                .priority_list()
                .map(SegmentMappingRef::mapping_id)
                .collect::<Vec<_>>(),
            [SegmentMappingId::new(2), SegmentMappingId::new(1)]
        );

        let mappings = vec![
            (
                mapping_ref(2),
                RawAddress::from(0x1500u64),
                0x1000u64,
                props,
            ),
            (
                mapping_ref(1),
                RawAddress::from(0x1000u64),
                0x1000u64,
                props,
            ),
        ];
        space.rebuild_range(
            AddressRange::new(
                space.id(),
                RawAddress::from(0x1500u64),
                RawAddress::from(0x1fffu64),
            ),
            mappings,
        );

        assert_eq!(
            space
                .find_containing(0x1800u64)
                .unwrap()
                .mapping_ref()
                .mapping_id(),
            SegmentMappingId::new(1)
        );

        assert_eq!(
            space
                .find_containing(0x1200u64)
                .unwrap()
                .mapping_ref()
                .mapping_id(),
            SegmentMappingId::new(1)
        );

        assert_eq!(
            space
                .find_containing(0x2100u64)
                .unwrap()
                .mapping_ref()
                .mapping_id(),
            SegmentMappingId::new(2)
        );
    }

    #[test]
    fn test_rebuild_range_clamps_to_bounds() {
        let mut space = AddressSpace::new(AddressSpaceId::new(0));
        let props = SegmentProperties::default();

        space.add_mapping_top(mapping_ref(1), 0x1000u64, 0x2000, props);

        let mappings = vec![(
            mapping_ref(2),
            RawAddress::from(0x1000u64),
            0x2000u64,
            props,
        )];
        space.rebuild_range(
            AddressRange::new(
                space.id(),
                RawAddress::from(0x1500u64),
                RawAddress::from(0x1fffu64),
            ),
            mappings,
        );

        assert_eq!(
            space
                .find_containing(0x1200u64)
                .unwrap()
                .mapping_ref()
                .mapping_id(),
            SegmentMappingId::new(1)
        );

        assert_eq!(
            space
                .find_containing(0x1800u64)
                .unwrap()
                .mapping_ref()
                .mapping_id(),
            SegmentMappingId::new(2)
        );

        assert_eq!(
            space
                .find_containing(0x2500u64)
                .unwrap()
                .mapping_ref()
                .mapping_id(),
            SegmentMappingId::new(1)
        );
    }
}
