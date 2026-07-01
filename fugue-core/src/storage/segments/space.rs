use std::fmt;

use iset::IntervalMap;
use smallvec::SmallVec;
use thiserror::Error;

use crate::ir::{Address, RawAddress, SegmentProperties};
use crate::storage::segments::mapping::{SegmentMappingId, SegmentMappingRef, SegmentSubMapping};

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
#[rkyv(derive(PartialEq, Eq, PartialOrd, Ord, Hash))]
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

    pub const fn index(&self) -> usize {
        self.0 as usize
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

#[derive(Debug)]
pub struct AddressSpace {
    id: AddressSpaceId,
    kind: AddressSpaceKind,
    submaps: IntervalMap<Address, SegmentSubMapping>,
    priority_list: Vec<SegmentMappingRef>,
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
            priority_list: Vec::new(),
        }
    }

    pub fn id(&self) -> AddressSpaceId {
        self.id
    }

    pub fn base(&self) -> Option<AddressSpaceId> {
        match self.kind {
            AddressSpaceKind::Base => None,
            AddressSpaceKind::Overlay { base } => Some(base),
        }
    }

    pub fn is_overlay(&self) -> bool {
        matches!(self.kind, AddressSpaceKind::Overlay { .. })
    }

    pub fn kind(&self) -> AddressSpaceKind {
        self.kind
    }

    pub(crate) fn add_mapping_top(
        &mut self,
        mapping_ref: SegmentMappingRef,
        addr: impl Into<Address>,
        size: usize,
        properties: SegmentProperties,
    ) {
        let start = addr.into();
        self.insert_submap_top(mapping_ref, start, size, properties);

        self.priority_list
            .retain(|r| r.mapping_id() != mapping_ref.mapping_id());
        self.priority_list.push(mapping_ref);
    }

    fn insert_submap_top(
        &mut self,
        mapping_ref: SegmentMappingRef,
        addr: impl Into<Address>,
        size: usize,
        properties: SegmentProperties,
    ) {
        let start = Address::new(self.id, addr.into());
        let end = start + size;
        let last = end - 1usize;

        let overlapping = self
            .submaps
            .iter(start..end)
            .map(|(iv, view)| (iv.clone(), view.clone()))
            .collect::<SmallVec<[_; 8]>>();

        for (iv, view) in overlapping {
            self.submaps.remove(iv);

            if view.start() < start
                && let Some(left) = view.with_end(start)
            {
                self.submaps.insert(left.range(), left);
            }
            if view.last() > last
                && let Some(right) = view.with_start(end)
            {
                self.submaps.insert(right.range(), right);
            }
        }

        let new_view = SegmentSubMapping::new(mapping_ref, start, size, properties);
        self.submaps.insert(start..end, new_view);
    }

    pub(crate) fn add_mapping_bottom(
        &mut self,
        mapping_ref: SegmentMappingRef,
        addr: impl Into<Address>,
        size: usize,
        properties: SegmentProperties,
    ) {
        let start = Address::new(self.id, addr.into());
        let end = start + size;

        let mut gaps = SmallVec::<[_; 8]>::new();
        let mut current = start;

        let overlapping = self
            .submaps
            .iter(start..end)
            .map(|(iv, _)| iv.clone())
            .collect::<SmallVec<[_; 8]>>();

        for iv in overlapping {
            if iv.start > current {
                let gap_end = iv.start.min(end);
                if gap_end > current {
                    gaps.push(current..gap_end);
                }
            }
            current = iv.end.max(current);
        }

        if current < end {
            gaps.push(current..end);
        }

        for gap in gaps {
            let gap_size = usize::from(gap.end - gap.start);
            let view = SegmentSubMapping::new(mapping_ref, gap.start, gap_size, properties);
            self.submaps.insert(gap, view);
        }

        self.priority_list
            .retain(|r| r.mapping_id() != mapping_ref.mapping_id());
        self.priority_list.insert(0, mapping_ref);
    }

    pub fn find_containing(&self, addr: impl Into<Address>) -> Option<&SegmentSubMapping> {
        let addr = Address::new(self.id, addr.into());
        self.submaps.values(addr..(addr + 1usize)).next()
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

    pub fn find_containing_mut(
        &mut self,
        addr: impl Into<Address>,
    ) -> Option<&mut SegmentSubMapping> {
        let addr = Address::new(self.id, addr.into());
        self.submaps.values_mut(addr..(addr + 1usize)).next()
    }

    pub(crate) fn deprioritise(&mut self, mapping_id: SegmentMappingId) {
        if let Some(pos) = self
            .priority_list
            .iter()
            .position(|r| r.mapping_id() == mapping_id)
        {
            let mapping_ref = self.priority_list.remove(pos);
            self.priority_list.insert(0, mapping_ref);
        }
    }

    pub(crate) fn rebuild_range(
        &mut self,
        range_start: RawAddress,
        range_end: RawAddress,
        mappings: impl IntoIterator<Item = (SegmentMappingRef, RawAddress, usize, SegmentProperties)>,
    ) {
        let range_start = Address::new(self.id, range_start);
        let range_end = Address::new(self.id, range_end);
        let range_last = range_end - 1usize;

        let overlapping = self
            .submaps
            .iter(range_start..range_end)
            .map(|(iv, view)| (iv.clone(), view.clone()))
            .collect::<SmallVec<[_; 8]>>();

        for (iv, view) in overlapping {
            self.submaps.remove(iv);

            // preserve the portion before the rebuild range
            if view.start() < range_start {
                if let Some(left) = view.with_end(range_start) {
                    self.submaps.insert(left.range(), left);
                }
            }
            if view.last() > range_last {
                // preserve the portion after the rebuild range
                if let Some(right) = view.with_start(range_end) {
                    self.submaps.insert(right.range(), right);
                }
            }
        }

        for (mapping_ref, start, size, properties) in mappings {
            let end = start + size;

            let range_start = range_start.address();
            let range_end = range_end.address();

            if end <= range_start || start >= range_end {
                continue;
            }

            let clamped_start = start.max(range_start);
            let clamped_end = end.min(range_end);
            let clamped_size = usize::from(clamped_end - clamped_start);

            self.insert_submap_top(mapping_ref, clamped_start, clamped_size, properties);
        }
    }

    pub(crate) fn remove_mapping(&mut self, mapping_id: SegmentMappingId) {
        let to_remove = self
            .submaps
            .iter(..)
            .filter(|(_, view)| view.mapping_ref().mapping_id() == mapping_id)
            .map(|(iv, _)| iv.clone())
            .collect::<SmallVec<[_; 8]>>();

        for iv in to_remove {
            self.submaps.remove(iv);
        }

        self.priority_list.retain(|r| r.mapping_id() != mapping_id);
    }

    pub fn priority_list(&self) -> &[SegmentMappingRef] {
        &self.priority_list
    }

    pub fn is_empty(&self) -> bool {
        self.submaps.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &SegmentSubMapping> {
        self.submaps.iter(..).map(|(_, view)| view)
    }

    pub fn clear(&mut self) {
        self.submaps.clear();
        self.priority_list.clear();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn make_ref(id: usize) -> SegmentMappingRef {
        SegmentMappingRef::new(SegmentMappingId::new(id), 1)
    }

    #[test]
    fn test_add_mapping_top() {
        let mut space = AddressSpace::new(AddressSpaceId::new(0));
        let properties = SegmentProperties::default();

        space.add_mapping_top(make_ref(1), 0x1000u64, 0x1001, properties);
        space.add_mapping_top(make_ref(2), 0x1500u64, 0x301, properties);

        let view = space.find_containing(0x1500u64).unwrap();
        assert_eq!(view.mapping_ref().mapping_id(), SegmentMappingId::new(2));

        let view = space.find_containing(0x1000u64).unwrap();
        assert_eq!(view.mapping_ref().mapping_id(), SegmentMappingId::new(1));

        let view = space.find_containing(0x1900u64).unwrap();
        assert_eq!(view.mapping_ref().mapping_id(), SegmentMappingId::new(1));
    }

    #[test]
    fn test_add_mapping_bottom() {
        let mut space = AddressSpace::new(AddressSpaceId::new(0));
        let properties = SegmentProperties::default();

        space.add_mapping_top(make_ref(1), 0x1000u64, 0x501, properties);
        space.add_mapping_bottom(make_ref(2), 0x1000u64, 0x1001, properties);

        let view = space.find_containing(0x1200u64).unwrap();
        assert_eq!(view.mapping_ref().mapping_id(), SegmentMappingId::new(1));

        let view = space.find_containing(0x1800u64).unwrap();
        assert_eq!(view.mapping_ref().mapping_id(), SegmentMappingId::new(2));
    }

    #[test]
    fn test_remove_mapping() {
        let mut space = AddressSpace::new(AddressSpaceId::new(0));
        let properties = SegmentProperties::default();

        space.add_mapping_top(make_ref(1), 0x1000u64, 0x1001, properties);
        space.add_mapping_top(make_ref(2), 0x3000u64, 0x1001, properties);

        space.remove_mapping(SegmentMappingId::new(1));

        assert!(space.find_containing(0x1500u64).is_none());
        assert!(space.find_containing(0x3500u64).is_some());
    }

    #[test]
    fn test_rebuild_range_priority_order() {
        let mut space = AddressSpace::new(AddressSpaceId::new(0));
        let props = SegmentProperties::default();

        // Add two overlapping mappings: mapping 1 at 0x1000-0x2000, mapping 2 at 0x1500-0x2500
        space.add_mapping_top(make_ref(1), 0x1000u64, 0x1000, props);
        space.add_mapping_top(make_ref(2), 0x1500u64, 0x1000, props);

        // Mapping 2 is on top, so it should be visible at 0x1800
        assert_eq!(
            space
                .find_containing(0x1800u64)
                .unwrap()
                .mapping_ref()
                .mapping_id(),
            SegmentMappingId::new(2)
        );

        // Deprioritise mapping 2 (move to bottom of priority list)
        space.deprioritise(SegmentMappingId::new(2));

        // Rebuild the range where mapping 2 exists (0x1500-0x2500)
        // Mappings in priority order (lowest first): mapping 2, then mapping 1
        let mappings = vec![
            (make_ref(2), RawAddress::from(0x1500u64), 0x1000usize, props),
            (make_ref(1), RawAddress::from(0x1000u64), 0x1000usize, props),
        ];
        space.rebuild_range(
            RawAddress::from(0x1500u64),
            RawAddress::from(0x2000u64),
            mappings,
        );

        // Now mapping 1 should be visible at 0x1800 (overlap region)
        assert_eq!(
            space
                .find_containing(0x1800u64)
                .unwrap()
                .mapping_ref()
                .mapping_id(),
            SegmentMappingId::new(1)
        );

        // Mapping 1 should still be visible at 0x1200 (non-overlap region)
        assert_eq!(
            space
                .find_containing(0x1200u64)
                .unwrap()
                .mapping_ref()
                .mapping_id(),
            SegmentMappingId::new(1)
        );

        // Mapping 2 should be visible at 0x2100 (non-overlap region, past mapping 1's end)
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

        // Add a mapping at 0x1000-0x3000
        space.add_mapping_top(make_ref(1), 0x1000u64, 0x2000, props);

        // Rebuild only 0x1500-0x2000 with a new mapping
        let mappings = vec![(make_ref(2), RawAddress::from(0x1000u64), 0x2000usize, props)];
        space.rebuild_range(
            RawAddress::from(0x1500u64),
            RawAddress::from(0x2000u64),
            mappings,
        );

        // Mapping 1 should still be at 0x1200 (before rebuild range)
        assert_eq!(
            space
                .find_containing(0x1200u64)
                .unwrap()
                .mapping_ref()
                .mapping_id(),
            SegmentMappingId::new(1)
        );

        // Mapping 2 should be at 0x1800 (inside rebuild range)
        assert_eq!(
            space
                .find_containing(0x1800u64)
                .unwrap()
                .mapping_ref()
                .mapping_id(),
            SegmentMappingId::new(2)
        );

        // Mapping 1 should still be at 0x2500 (after rebuild range)
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
