use std::collections::BTreeMap;

use crate::engine::change::{ChangeKinds, ChangeSet, Revision};
use crate::ir::{AddressRange, AddressRangeSet, RawAddress, RawAddressMap};
use crate::storage::segments::space::AddressSpaceId;

pub(crate) const MAX_CHANGE_RUNS: usize = 4096;

const GROUPS: [ChangeKinds; 4] = [
    ChangeKinds::BYTES_WRITTEN,
    ChangeKinds::FUNCTIONS,
    ChangeKinds::SYMBOLS,
    ChangeKinds::SEGMENTS,
];

pub(crate) struct ChangeIndex {
    floors: [Revision; GROUPS.len()],
    spaces: [BTreeMap<AddressSpaceId, RawAddressMap<Revision>>; GROUPS.len()],
}

impl ChangeIndex {
    pub(crate) fn new(revision: Revision) -> Self {
        Self {
            floors: [revision; GROUPS.len()],
            spaces: std::array::from_fn(|_| BTreeMap::new()),
        }
    }

    pub(crate) fn apply(&mut self, changes: &ChangeSet) {
        let revision = changes.revision();

        for record in changes.records() {
            let kind = record.kind();

            if kind == ChangeKinds::RESTORED {
                for floor in &mut self.floors {
                    *floor = (*floor).max(revision);
                }
                continue;
            }

            let Some(group) = Self::group_of(kind) else {
                continue;
            };

            for range in record.ranges() {
                self.touch(group, range, revision);
            }

            self.compact(group, revision);
        }
    }

    pub(crate) fn latest_change(&self, kinds: ChangeKinds, region: &AddressRangeSet) -> Revision {
        let mut latest = Revision::new(0);

        for (group, mask) in GROUPS.iter().enumerate() {
            if !kinds.intersects(*mask) {
                continue;
            }

            latest = latest.max(self.floors[group]);

            if region.is_empty() {
                for map in self.spaces[group].values() {
                    if let Some(revision) = map.max_in_range(RawAddress::zero()..=RawAddress::MAX) {
                        latest = latest.max(revision);
                    }
                }
            } else {
                for range in region.ranges() {
                    if let Some(map) = self.spaces[group].get(&range.space())
                        && let Some(revision) = map.max_in_range(range.raw_range())
                    {
                        latest = latest.max(revision);
                    }
                }
            }
        }

        latest
    }

    pub(crate) fn changed_since(
        &self,
        since: Revision,
        kinds: ChangeKinds,
        region: &AddressRangeSet,
    ) -> bool {
        self.latest_change(kinds, region) > since
    }

    fn touch(&mut self, group: usize, range: AddressRange, revision: Revision) {
        self.spaces[group]
            .entry(range.space())
            .or_default()
            .insert_range(range.raw_range(), revision);
    }

    fn compact(&mut self, group: usize, revision: Revision) {
        let runs = self.spaces[group]
            .values()
            .map(RawAddressMap::run_count)
            .sum::<usize>();
        if runs <= MAX_CHANGE_RUNS {
            return;
        }

        self.floors[group] = self.floors[group].max(revision);
        self.spaces[group].clear();
    }

    fn group_of(kind: ChangeKinds) -> Option<usize> {
        GROUPS.iter().position(|mask| mask.intersects(kind))
    }
}
