use smallvec::SmallVec;

use crate::ir::{AddressRange, AddressRangeSet};
use crate::project::{ChangeKinds, ChangeSet};

pub(crate) const MAX_READ_RANGES: usize = 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadSet {
    bounded: SmallVec<[(ChangeKinds, AddressRangeSet); 2]>,
    unbounded: ChangeKinds,
}

impl ReadSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.unbounded.is_empty() && self.bounded.is_empty()
    }

    pub fn record(&mut self, kinds: ChangeKinds, range: AddressRange) -> bool {
        let kinds = kinds.difference(self.unbounded);
        if kinds.is_empty() {
            return false;
        }

        if let Some((_, ranges)) = self
            .bounded
            .iter_mut()
            .find(|(existing, _)| *existing == kinds)
        {
            ranges.insert_range(range);
            if ranges.range_count() > MAX_READ_RANGES {
                self.record_unbounded(kinds);
                return true;
            }
            return false;
        }

        let mut ranges = AddressRangeSet::new();
        ranges.insert_range(range);
        self.bounded.push((kinds, ranges));
        false
    }

    pub fn record_unbounded(&mut self, kinds: ChangeKinds) {
        self.unbounded |= kinds;
        for (existing, _) in &mut self.bounded {
            existing.remove(kinds);
        }
        self.bounded.retain(|(existing, _)| !existing.is_empty());
    }

    pub fn intersects(&self, kinds: ChangeKinds, regions: &AddressRangeSet) -> bool {
        if self.unbounded.intersects(kinds) {
            return true;
        }

        self.bounded
            .iter()
            .any(|(observed, ranges)| observed.intersects(kinds) && ranges.intersects(regions))
    }

    pub(crate) fn conflicts_with(&self, changes: &ChangeSet) -> bool {
        changes.records().iter().any(|record| {
            let kind = record.kind();
            if !self.observes(kind) {
                return false;
            }

            let ranges = record.ranges();
            ranges.is_empty()
                || ranges.iter().any(|range| {
                    self.unbounded.intersects(kind)
                        || self.bounded.iter().any(|(observed, observed_ranges)| {
                            observed.intersects(kind) && observed_ranges.intersects_range(range)
                        })
                })
        })
    }

    pub fn escapes(&self, kinds: ChangeKinds, region: &AddressRangeSet) -> bool {
        if self.unbounded.intersects(kinds) {
            return true;
        }

        self.bounded.iter().any(|(observed, ranges)| {
            observed.intersects(kinds) && !ranges.difference(region).is_empty()
        })
    }

    pub fn observes(&self, kinds: ChangeKinds) -> bool {
        self.unbounded.intersects(kinds)
            || self
                .bounded
                .iter()
                .any(|(observed, _)| observed.intersects(kinds))
    }

    pub fn observed(&self) -> ChangeKinds {
        self.bounded
            .iter()
            .fold(self.unbounded, |kinds, (observed, _)| kinds | *observed)
    }

    pub fn merge(&mut self, other: &Self) -> bool {
        self.record_unbounded(other.unbounded);
        let mut collapsed = false;
        for (kinds, ranges) in &other.bounded {
            for range in ranges.ranges() {
                collapsed |= self.record(*kinds, range);
            }
        }
        collapsed
    }
}
