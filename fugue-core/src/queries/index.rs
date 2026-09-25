use std::array;
use std::collections::BTreeMap;

use crate::ir::{AddressRange, AddressRangeSet, RawAddressMap};
use crate::project::{ChangeKinds, ChangeSet};
use crate::storage::segments::space::AddressSpaceId;
use crate::types::Revision;

pub(crate) const MAX_CHANGE_RUNS: usize = 4096;
pub(crate) const CENSUS_INTERVAL: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegionGroupKind {
    Bytes,
    Functions,
    Problems,
    References,
    Segments,
    Switches,
    Symbols,
}

impl RegionGroupKind {
    const ALL: [RegionGroupKind; 7] = [
        RegionGroupKind::Bytes,
        RegionGroupKind::Functions,
        RegionGroupKind::Problems,
        RegionGroupKind::References,
        RegionGroupKind::Segments,
        RegionGroupKind::Switches,
        RegionGroupKind::Symbols,
    ];

    fn index(self) -> usize {
        match self {
            RegionGroupKind::Bytes => 0,
            RegionGroupKind::Functions => 1,
            RegionGroupKind::Problems => 2,
            RegionGroupKind::References => 3,
            RegionGroupKind::Segments => 4,
            RegionGroupKind::Switches => 5,
            RegionGroupKind::Symbols => 6,
        }
    }

    fn mask(self) -> ChangeKinds {
        match self {
            RegionGroupKind::Bytes => ChangeKinds::BYTES_WRITTEN,
            RegionGroupKind::Functions => ChangeKinds::FUNCTIONS,
            RegionGroupKind::Symbols => ChangeKinds::SYMBOLS,
            RegionGroupKind::Segments => {
                ChangeKinds::SEGMENT_MAPPED | ChangeKinds::SEGMENT_UNMAPPED
            }
            RegionGroupKind::Problems => ChangeKinds::PROBLEMS,
            RegionGroupKind::References => ChangeKinds::REFERENCES,
            RegionGroupKind::Switches => ChangeKinds::SWITCHES,
        }
    }

    fn of_record(kind: ChangeKinds) -> Option<RegionGroupKind> {
        RegionGroupKind::ALL
            .into_iter()
            .find(|group| group.mask().intersects(kind))
    }
}

struct RegionGroup {
    floor: Revision,
    max: Revision,
    spaces: BTreeMap<AddressSpaceId, RawAddressMap<Revision>>,
    inserts_since_census: usize,
}

impl RegionGroup {
    fn new(revision: Revision) -> Self {
        Self {
            floor: revision,
            max: revision,
            spaces: BTreeMap::new(),
            inserts_since_census: 0,
        }
    }

    fn run_count(&self) -> usize {
        self.spaces
            .values()
            .map(RawAddressMap::run_count)
            .sum::<usize>()
    }

    fn touch(&mut self, range: AddressRange, revision: Revision) -> bool {
        self.spaces
            .entry(range.space())
            .or_default()
            .insert_range(range.raw_range(), revision);
        self.max = self.max.max(revision);

        self.inserts_since_census += 1;
        if self.inserts_since_census >= CENSUS_INTERVAL {
            self.inserts_since_census = 0;
            return self.compact();
        }

        false
    }

    fn compact(&mut self) -> bool {
        if self.run_count() <= MAX_CHANGE_RUNS {
            return false;
        }

        self.floor = self.max;
        self.spaces.clear();
        true
    }

    fn latest_over(&self, region: &AddressRangeSet) -> Revision {
        if region.is_empty() {
            return self.floor.max(self.max);
        }

        let mut latest = self.floor;
        for range in region.ranges() {
            if let Some(map) = self.spaces.get(&range.space())
                && let Some(revision) = map.max_in_range(range.raw_range())
            {
                latest = latest.max(revision);
            }
        }
        latest
    }

    fn resynchronise(&mut self, revision: Revision) {
        self.floor = self.floor.max(revision);
        self.max = self.max.max(revision);
        self.spaces.clear();
        self.inserts_since_census = 0;
    }
}

struct GlobalWatermarks {
    lifted: Revision,
    resynchronised: Revision,
    space_created: Revision,
    mapping_created: Revision,
    mapping_changed: Revision,
}

impl GlobalWatermarks {
    fn new(revision: Revision) -> Self {
        Self {
            lifted: revision,
            resynchronised: revision,
            space_created: revision,
            mapping_created: revision,
            mapping_changed: revision,
        }
    }

    fn bump(&mut self, kind: ChangeKinds, revision: Revision) {
        if kind.intersects(ChangeKinds::LIFTED) {
            self.lifted = self.lifted.max(revision);
        }
        if kind.intersects(ChangeKinds::SPACE_CREATED) {
            self.space_created = self.space_created.max(revision);
        }
        if kind.intersects(ChangeKinds::SEGMENT_MAPPING_CREATED) {
            self.mapping_created = self.mapping_created.max(revision);
        }
        if kind.intersects(ChangeKinds::SEGMENT_MAPPING_CHANGED) {
            self.mapping_changed = self.mapping_changed.max(revision);
        }
    }

    fn latest(&self, kinds: ChangeKinds) -> Revision {
        let mut latest = Revision::new(0);
        if kinds.intersects(ChangeKinds::LIFTED) {
            latest = latest.max(self.lifted);
        }
        if kinds.intersects(ChangeKinds::RESYNCHRONISE) {
            latest = latest.max(self.resynchronised);
        }
        if kinds.intersects(ChangeKinds::SPACE_CREATED) {
            latest = latest.max(self.space_created);
        }
        if kinds.intersects(ChangeKinds::SEGMENT_MAPPING_CREATED) {
            latest = latest.max(self.mapping_created);
        }
        if kinds.intersects(ChangeKinds::SEGMENT_MAPPING_CHANGED) {
            latest = latest.max(self.mapping_changed);
        }
        latest
    }

    fn resynchronise(&mut self, revision: Revision) {
        self.lifted = self.lifted.max(revision);
        self.resynchronised = self.resynchronised.max(revision);
        self.space_created = self.space_created.max(revision);
        self.mapping_created = self.mapping_created.max(revision);
        self.mapping_changed = self.mapping_changed.max(revision);
    }
}

pub(crate) struct ChangeIndex {
    groups: [RegionGroup; RegionGroupKind::ALL.len()],
    global: GlobalWatermarks,
}

impl ChangeIndex {
    pub(crate) fn new(revision: Revision) -> Self {
        Self {
            groups: array::from_fn(|_| RegionGroup::new(revision)),
            global: GlobalWatermarks::new(revision),
        }
    }

    pub(crate) fn apply(&mut self, changes: &ChangeSet) -> bool {
        let revision = changes.revision();
        let mut collapsed = false;

        for record in changes.records() {
            let kind = record.kind();

            if kind == ChangeKinds::RESYNCHRONISE {
                self.resynchronise(revision);
                continue;
            }

            if let Some(group) = RegionGroupKind::of_record(kind) {
                let group = &mut self.groups[group.index()];
                for range in record.ranges() {
                    collapsed |= group.touch(range, revision);
                }
            } else {
                self.global.bump(kind, revision);
            }
        }

        collapsed
    }

    pub(crate) fn latest_change(&self, kinds: ChangeKinds, region: &AddressRangeSet) -> Revision {
        let mut latest = self.global.latest(kinds);

        for group in RegionGroupKind::ALL {
            if kinds.intersects(group.mask()) {
                latest = latest.max(self.groups[group.index()].latest_over(region));
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

    fn resynchronise(&mut self, revision: Revision) {
        for group in &mut self.groups {
            group.resynchronise(revision);
        }
        self.global.resynchronise(revision);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::IlArtefact;
    use crate::il::ecode::ECodeIr;
    use crate::ir::{FunctionId, RawAddress};
    use crate::project::ChangeRecord;

    #[test]
    fn test_change_index_compaction_is_conservative() {
        let space = AddressSpaceId::from(0u8);
        let mut index = ChangeIndex::new(Revision::new(0));
        let mut truth = Vec::new();

        for step in 1..(MAX_CHANGE_RUNS as u64 + 512) {
            let range = AddressRange::new(
                space,
                RawAddress::from(step * 0x400),
                RawAddress::from(step * 0x400 + 0x3f),
            );
            let revision = Revision::new(step);
            index.apply(&ChangeSet::with_records(
                revision,
                [ChangeRecord::BytesWritten { range }],
            ));
            truth.push((range, revision));
        }

        let probes = (0..16u64).map(|i| {
            AddressRange::new(
                space,
                RawAddress::from(i * 0x4000),
                RawAddress::from(i * 0x4000 + 0x1ff),
            )
        });
        let snapshots = (0..8u64)
            .map(|i| Revision::new(i * (MAX_CHANGE_RUNS as u64 / 8)))
            .collect::<Vec<_>>();

        for probe in probes {
            let mut region = AddressRangeSet::new();
            region.insert_range(probe);

            for &snapshot in &snapshots {
                let truly_changed = truth
                    .iter()
                    .any(|&(range, revision)| revision > snapshot && range.intersects(&probe));
                if truly_changed {
                    assert!(
                        index.changed_since(snapshot, ChangeKinds::BYTES_WRITTEN, &region),
                        "compaction reported unchanged where a real change occurred"
                    );
                }
            }
        }
    }

    #[test]
    fn census_bounds_run_count() {
        let space = AddressSpaceId::from(0u8);
        let mut index = ChangeIndex::new(Revision::new(0));

        for step in 1..(MAX_CHANGE_RUNS as u64 * 4) {
            let range = AddressRange::new(
                space,
                RawAddress::from(step * 0x400),
                RawAddress::from(step * 0x400 + 0x3f),
            );
            index.apply(&ChangeSet::with_records(
                Revision::new(step),
                [ChangeRecord::BytesWritten { range }],
            ));

            let max_run_count = index
                .groups
                .iter()
                .map(RegionGroup::run_count)
                .max()
                .unwrap_or(0);
            assert!(
                max_run_count <= MAX_CHANGE_RUNS + CENSUS_INTERVAL,
                "amortised census let a group exceed the run bound by more than one interval"
            );
        }
    }

    #[test]
    fn lifted_changes_advance_global_watermark() {
        let mut index = ChangeIndex::new(Revision::new(0));
        index.apply(&ChangeSet::with_records(
            Revision::new(7),
            [ChangeRecord::LiftedMaterialised {
                function: FunctionId::default(),
                form: ECodeIr::FORM,
            }],
        ));
        assert_eq!(
            index.latest_change(ChangeKinds::LIFTED, &AddressRangeSet::new()),
            Revision::new(7)
        );
    }

    #[test]
    fn resynchronisation_advances_global_watermark() {
        let mut index = ChangeIndex::new(Revision::new(0));
        index.apply(&ChangeSet::with_records(
            Revision::new(7),
            [ChangeRecord::Resynchronise {
                to: Revision::new(7),
            }],
        ));
        assert_eq!(
            index.latest_change(ChangeKinds::RESYNCHRONISE, &AddressRangeSet::new()),
            Revision::new(7)
        );
    }
}
