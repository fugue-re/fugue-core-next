use std::ops::Range;

use iset::IntervalMap;
use smallvec::SmallVec;

use crate::ir::Address;
use crate::storage::segments::mapping::{SegmentMappingId, SegmentMappingRef, SegmentMappingView};

pub type SegmentBankId = u32;

#[derive(Debug)]
pub struct SegmentBank {
    id: SegmentBankId,
    name: Option<String>,
    submaps: IntervalMap<Address, SegmentMappingView>,
    priority_list: Vec<SegmentMappingRef>,
}

impl SegmentBank {
    pub fn new(id: SegmentBankId, name: impl Into<Option<String>>) -> Self {
        Self {
            id,
            name: name.into(),
            submaps: IntervalMap::new(),
            priority_list: Vec::new(),
        }
    }

    pub fn id(&self) -> SegmentBankId {
        self.id
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn add_mapping_top(&mut self, mapping_ref: SegmentMappingRef, addr: impl Into<Address>, size: usize) {
        let start = addr.into();
        let end = start + size;
        let last = end - 1usize;

        let overlapping: SmallVec<[_; 8]> = self
            .submaps
            .iter(start..end)
            .map(|(iv, view)| (iv.clone(), view.clone()))
            .collect();

        for (iv, view) in overlapping {
            self.submaps.remove(iv);

            if view.start() < start {
                if let Some(left) = view.with_end(start) {
                    self.submaps.insert(left.range(), left);
                }
            }

            if view.last() > last {
                if let Some(right) = view.with_start(end) {
                    self.submaps.insert(right.range(), right);
                }
            }
        }

        let new_view = SegmentMappingView::new(mapping_ref, start, size);
        self.submaps.insert(start..end, new_view);

        self.priority_list.retain(|r| r.mapping_id() != mapping_ref.mapping_id());
        self.priority_list.push(mapping_ref);
    }

    pub fn add_mapping_bottom(&mut self, mapping_ref: SegmentMappingRef, addr: impl Into<Address>, size: usize) {
        let start = addr.into();
        let end = start + size;

        let mut gaps: SmallVec<[Range<Address>; 8]> = SmallVec::new();
        let mut current = start;

        let overlapping: SmallVec<[_; 8]> = self
            .submaps
            .iter(start..end)
            .map(|(iv, _)| iv.clone())
            .collect();

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
            let view = SegmentMappingView::new(mapping_ref, gap.start, gap_size);
            self.submaps.insert(gap, view);
        }

        self.priority_list.retain(|r| r.mapping_id() != mapping_ref.mapping_id());
        self.priority_list.insert(0, mapping_ref);
    }

    pub fn find_containing(&self, addr: impl Into<Address>) -> Option<&SegmentMappingView> {
        let addr = addr.into();
        self.submaps.values(addr..(addr + 1usize)).next()
    }

    pub fn find_containing_mut(&mut self, addr: impl Into<Address>) -> Option<&mut SegmentMappingView> {
        let addr = addr.into();
        self.submaps.values_mut(addr..(addr + 1usize)).next()
    }

    pub fn prioritise(&mut self, mapping_id: SegmentMappingId) {
        if let Some(pos) = self.priority_list.iter().position(|r| r.mapping_id() == mapping_id) {
            let mapping_ref = self.priority_list.remove(pos);
            self.priority_list.push(mapping_ref);
        }
    }

    pub fn deprioritise(&mut self, mapping_id: SegmentMappingId) {
        if let Some(pos) = self.priority_list.iter().position(|r| r.mapping_id() == mapping_id) {
            let mapping_ref = self.priority_list.remove(pos);
            self.priority_list.insert(0, mapping_ref);
        }
    }

    pub fn remove_mapping(&mut self, mapping_id: SegmentMappingId) {
        let to_remove: SmallVec<[_; 8]> = self
            .submaps
            .iter(..)
            .filter(|(_, view)| view.mapping_ref().mapping_id() == mapping_id)
            .map(|(iv, _)| iv.clone())
            .collect();

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

    pub fn iter(&self) -> impl Iterator<Item = &SegmentMappingView> {
        self.submaps.iter(..).map(|(_, view)| view)
    }

    pub fn clear(&mut self) {
        self.submaps.clear();
        self.priority_list.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ref(id: u32) -> SegmentMappingRef {
        SegmentMappingRef::new(id, 1)
    }

    #[test]
    fn test_add_mapping_top() {
        let mut bank = SegmentBank::new(0, None::<String>);

        bank.add_mapping_top(make_ref(1), 0x1000u64, 0x1001);
        bank.add_mapping_top(make_ref(2), 0x1500u64, 0x301);

        let view = bank.find_containing(0x1500u64).unwrap();
        assert_eq!(view.mapping_ref().mapping_id(), 2);

        let view = bank.find_containing(0x1000u64).unwrap();
        assert_eq!(view.mapping_ref().mapping_id(), 1);

        let view = bank.find_containing(0x1900u64).unwrap();
        assert_eq!(view.mapping_ref().mapping_id(), 1);
    }

    #[test]
    fn test_add_mapping_bottom() {
        let mut bank = SegmentBank::new(0, None::<String>);

        bank.add_mapping_top(make_ref(1), 0x1000u64, 0x501);
        bank.add_mapping_bottom(make_ref(2), 0x1000u64, 0x1001);

        let view = bank.find_containing(0x1200u64).unwrap();
        assert_eq!(view.mapping_ref().mapping_id(), 1);

        let view = bank.find_containing(0x1800u64).unwrap();
        assert_eq!(view.mapping_ref().mapping_id(), 2);
    }

    #[test]
    fn test_remove_mapping() {
        let mut bank = SegmentBank::new(0, None::<String>);

        bank.add_mapping_top(make_ref(1), 0x1000u64, 0x1001);
        bank.add_mapping_top(make_ref(2), 0x3000u64, 0x1001);

        bank.remove_mapping(1);

        assert!(bank.find_containing(0x1500u64).is_none());
        assert!(bank.find_containing(0x3500u64).is_some());
    }
}
