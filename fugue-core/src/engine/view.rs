use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::sync::Arc;

use smallvec::SmallVec;

use crate::arch::Arch;
use crate::engine::change::{ChangeKinds, ChangeSet};
use crate::ir::{
    Address, AddressRange, AddressRangeSet, CodeBlockId, CodeBlockRef, CodeBlockTable, FunctionRef,
    FunctionTable, ProblemKind, ProblemRef, ProblemTable, ReferenceIndex, SwitchRef, SwitchTable,
    SymbolTable,
};
use crate::lifter::Language;
use crate::platform::Platform;
use crate::project::Project;
use crate::storage::segments::{SegmentStorage, SegmentStorageError};

const MAX_READ_RANGES: usize = 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadSet {
    bounded: SmallVec<[(ChangeKinds, AddressRangeSet); 2]>,
    unbounded: ChangeKinds,
}

impl ReadSet {
    pub fn new() -> Self {
        Self::default()
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

    pub fn is_empty(&self) -> bool {
        self.unbounded.is_empty() && self.bounded.is_empty()
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

struct AnalyserDependencies {
    addressless: Option<Arc<ReadSet>>,
    regional: BTreeMap<AddressRange, Arc<ReadSet>>,
}

impl AnalyserDependencies {
    fn new() -> Self {
        Self {
            addressless: None,
            regional: BTreeMap::new(),
        }
    }
}

pub(crate) struct DependencyInvalidation {
    addressless: bool,
    regions: AddressRangeSet,
}

impl DependencyInvalidation {
    pub(crate) fn has_addressless(&self) -> bool {
        self.addressless
    }

    pub(crate) fn regions(&self) -> &AddressRangeSet {
        &self.regions
    }

    pub(crate) fn is_empty(&self) -> bool {
        !self.addressless && self.regions.is_empty()
    }
}

pub(crate) struct DependencyIndex {
    entries: Vec<AnalyserDependencies>,
}

impl DependencyIndex {
    pub(crate) fn with_analysers(count: usize) -> Self {
        let mut entries = Vec::with_capacity(count);
        entries.resize_with(count, AnalyserDependencies::new);
        Self { entries }
    }

    pub(crate) fn record(&mut self, analyser: usize, regions: &AddressRangeSet, reads: ReadSet) {
        let entries = self
            .entries
            .get_mut(analyser)
            .expect("scheduled analyser must have a dependency index");

        if regions.is_empty() {
            entries.addressless = (!reads.is_empty()).then(|| Arc::new(reads));
            return;
        }

        let affected = entries
            .regional
            .keys()
            .filter(|range| regions.intersects_range(range))
            .copied()
            .collect::<SmallVec<[_; 8]>>();

        for range in affected {
            let reads = entries
                .regional
                .remove(&range)
                .expect("selected dependency range must exist");
            let mut previous = AddressRangeSet::new();
            previous.insert_range(range);
            for surviving in previous.difference(regions).ranges() {
                entries.regional.insert(surviving, reads.clone());
            }
        }

        if reads.is_empty() {
            return;
        }

        let reads = Arc::new(reads);
        for range in regions.ranges() {
            entries.regional.insert(range, reads.clone());
        }
    }

    pub(crate) fn invalidated(
        &self,
        analyser: usize,
        kinds: ChangeKinds,
        changed: Option<&AddressRangeSet>,
    ) -> DependencyInvalidation {
        let Some(entries) = self.entries.get(analyser) else {
            return DependencyInvalidation {
                addressless: false,
                regions: AddressRangeSet::new(),
            };
        };

        let affected = |reads: &ReadSet| match changed {
            Some(changed) => reads.intersects(kinds, changed),
            None => reads.observes(kinds),
        };
        let addressless = entries.addressless.as_deref().is_some_and(&affected);
        let mut regions = AddressRangeSet::new();
        for (range, reads) in &entries.regional {
            if affected(reads) {
                regions.insert_range(*range);
            }
        }

        DependencyInvalidation {
            addressless,
            regions,
        }
    }
}

pub struct ProjectView<'a> {
    project: &'a Project,
    reads: RefCell<ReadSet>,
    collapsed: Cell<bool>,
}

impl<'a> ProjectView<'a> {
    pub fn new(project: &'a Project) -> Self {
        Self {
            project,
            reads: RefCell::new(ReadSet::new()),
            collapsed: Cell::new(false),
        }
    }

    pub(crate) fn with_independent_reads(&self) -> Self {
        Self::new(self.project)
    }

    pub(crate) fn merge_reads(&self, reads: &ReadSet) {
        let collapsed = self.reads.borrow_mut().merge(reads);
        self.collapsed.set(self.collapsed.get() || collapsed);
    }

    pub(crate) fn into_reads(self) -> ReadSet {
        self.reads.into_inner()
    }

    fn record(&self, kinds: ChangeKinds, range: AddressRange) {
        if self.reads.borrow_mut().record(kinds, range) {
            self.collapsed.set(true);
        }
    }

    pub(crate) fn collapsed(&self) -> bool {
        self.collapsed.get()
    }

    fn record_unbounded(&self, kinds: ChangeKinds) {
        self.reads.borrow_mut().record_unbounded(kinds);
    }

    pub fn arch(&self) -> &Arch {
        self.project.arch()
    }

    pub fn platform(&self) -> &Platform {
        self.project.platform()
    }

    pub fn entry(&self) -> Option<Address> {
        self.project.entry()
    }

    pub fn language(&self) -> &'static Language {
        self.project.language()
    }

    pub fn is_non_returning_at(&self, address: Address) -> bool {
        self.record(
            ChangeKinds::SYMBOLS | ChangeKinds::FUNCTIONS,
            AddressRange::point(address),
        );

        self.project
            .symbols()
            .get_by_address(address)
            .any(|(_, entry)| entry.is_non_returning())
            || self
                .project
                .functions()
                .get_by_address(address)
                .is_some_and(|function| function.is_non_returning())
    }

    pub fn function_at(&self, address: Address) -> Option<FunctionRef<'_>> {
        self.record(ChangeKinds::FUNCTIONS, AddressRange::point(address));
        self.project.functions().get_by_address(address)
    }

    pub fn has_function_at(&self, address: Address) -> bool {
        self.record(ChangeKinds::FUNCTIONS, AddressRange::point(address));
        self.project.functions().contains(address)
    }

    pub fn function_entries(&self) -> impl Iterator<Item = Address> + '_ {
        self.record_unbounded(ChangeKinds::FUNCTIONS);
        self.project.functions().addresses()
    }

    pub fn block(&self, id: CodeBlockId) -> Option<CodeBlockRef<'_>> {
        let Some(block) = self.project.blocks().get_by_id(id) else {
            self.record_unbounded(ChangeKinds::FUNCTIONS);
            return None;
        };
        self.record(
            ChangeKinds::FUNCTIONS,
            AddressRange::new(
                block.start().space(),
                block.start().raw_address(),
                block.last_address().raw_address(),
            ),
        );
        Some(block)
    }

    pub fn switch_at(&self, branch: Address) -> Option<SwitchRef<'_>> {
        self.record(ChangeKinds::SWITCHES, AddressRange::point(branch));
        self.project.switches().get_by_branch(branch)
    }

    pub fn has_problem(&self, address: Address) -> bool {
        self.record(ChangeKinds::PROBLEMS, AddressRange::point(address));
        self.project.problems().contains(address)
    }

    pub fn has_problem_kind(&self, address: Address, kinds: &[ProblemKind]) -> bool {
        self.record(ChangeKinds::PROBLEMS, AddressRange::point(address));
        kinds
            .iter()
            .any(|kind| self.project.problems().get(address, *kind).is_some())
    }

    pub fn problem_at(&self, address: Address, kind: ProblemKind) -> Option<ProblemRef<'_>> {
        self.record(ChangeKinds::PROBLEMS, AddressRange::point(address));
        self.project.problems().get(address, kind)
    }

    pub fn problem_at_any(
        &self,
        address: Address,
        kinds: &[ProblemKind],
    ) -> Option<ProblemRef<'_>> {
        self.record(ChangeKinds::PROBLEMS, AddressRange::point(address));
        kinds
            .iter()
            .find_map(|kind| self.project.problems().get(address, *kind))
    }

    pub fn read_bytes(
        &self,
        address: Address,
        bytes: &mut [u8],
    ) -> Result<usize, SegmentStorageError> {
        let read = self.project.segments().read_bytes(address, bytes)?;
        if !bytes.is_empty() {
            self.record(
                ChangeKinds::BYTES_WRITTEN | ChangeKinds::SEGMENTS,
                if read == 0 {
                    AddressRange::point(address)
                } else {
                    AddressRange::from_size(address, read as u64)
                        .expect("a completed segment read has a valid address range")
                },
            );
        }
        Ok(read)
    }

    pub fn functions(&self) -> &FunctionTable {
        self.record_unbounded(ChangeKinds::FUNCTIONS);
        self.project.functions()
    }

    pub fn blocks(&self) -> &CodeBlockTable {
        self.record_unbounded(ChangeKinds::FUNCTIONS);
        self.project.blocks()
    }

    pub fn symbols(&self) -> &SymbolTable {
        self.record_unbounded(ChangeKinds::SYMBOLS);
        self.project.symbols()
    }

    pub fn switches(&self) -> &SwitchTable {
        self.record_unbounded(ChangeKinds::SWITCHES);
        self.project.switches()
    }

    pub fn problems(&self) -> &ProblemTable {
        self.record_unbounded(ChangeKinds::PROBLEMS);
        self.project.problems()
    }

    pub fn references(&self) -> &ReferenceIndex {
        self.record_unbounded(ChangeKinds::REFERENCES);
        self.project.references()
    }

    pub fn segments(&self) -> &SegmentStorage {
        self.record_unbounded(ChangeKinds::SEGMENTS | ChangeKinds::SPACE_CREATED);
        self.project.segments()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::change::ChangeRecord;
    use crate::ir::Address;
    use crate::storage::segments::{AddressSpaceId, DEFAULT_SPACE_ID};

    fn range(start: u64, end: u64) -> AddressRange {
        AddressRange::new(DEFAULT_SPACE_ID, start.into(), end.into())
    }

    fn regions(start: u64, end: u64) -> AddressRangeSet {
        let mut set = AddressRangeSet::new();
        set.insert_range(range(start, end));
        set
    }

    #[test]
    fn a_bounded_read_only_matches_its_own_range() {
        let mut reads = ReadSet::new();
        reads.record(ChangeKinds::SWITCHES, range(0x1000, 0x1fff));

        assert!(reads.intersects(ChangeKinds::SWITCHES, &regions(0x1800, 0x1900)));
        assert!(!reads.intersects(ChangeKinds::SWITCHES, &regions(0x3000, 0x3fff)));
        assert!(!reads.intersects(ChangeKinds::SYMBOLS, &regions(0x1800, 0x1900)));
    }

    #[test]
    fn an_unbounded_read_matches_any_range_of_that_kind() {
        let mut reads = ReadSet::new();
        reads.record_unbounded(ChangeKinds::FUNCTIONS);

        assert!(reads.intersects(ChangeKinds::FUNCTIONS, &regions(0, u64::MAX - 1)));
        assert!(!reads.intersects(ChangeKinds::SWITCHES, &regions(0, u64::MAX - 1)));
    }

    #[test]
    fn an_unbounded_read_subsumes_bounded_ones() {
        let mut reads = ReadSet::new();
        reads.record(
            ChangeKinds::FUNCTIONS | ChangeKinds::SYMBOLS,
            range(0x1000, 0x1fff),
        );
        reads.record_unbounded(ChangeKinds::FUNCTIONS);

        assert!(reads.intersects(ChangeKinds::FUNCTIONS, &regions(0x9000, 0x9fff)));
        assert!(reads.intersects(ChangeKinds::SYMBOLS, &regions(0x1800, 0x1900)));
        assert!(!reads.intersects(ChangeKinds::SYMBOLS, &regions(0x9000, 0x9fff)));
        assert_eq!(
            reads.observed(),
            ChangeKinds::FUNCTIONS | ChangeKinds::SYMBOLS
        );
    }

    #[test]
    fn an_unbounded_read_set_collapses_rather_than_growing_without_bound() {
        let mut reads = ReadSet::new();
        let mut collapsed = false;

        for index in 0..(MAX_READ_RANGES as u64 + 8) {
            let start = index * 0x10;
            collapsed |= reads.record(ChangeKinds::PROBLEMS, range(start, start + 1));
        }

        assert!(
            collapsed,
            "an unbounded number of distinct reads must collapse, not grow without limit"
        );
        assert!(reads.intersects(ChangeKinds::PROBLEMS, &regions(u64::MAX - 8, u64::MAX - 1)));
    }

    #[test]
    fn conflicts_are_limited_to_captured_kinds_and_ranges() {
        let mut reads = ReadSet::new();
        reads.record(ChangeKinds::BYTES_WRITTEN, range(0x1000, 0x1fff));

        let overlapping = ChangeSet::with_records(
            1u64.into(),
            [ChangeRecord::BytesWritten {
                range: range(0x1800, 0x18ff),
            }],
        );
        let elsewhere = ChangeSet::with_records(
            2u64.into(),
            [ChangeRecord::BytesWritten {
                range: range(0x3000, 0x30ff),
            }],
        );
        let other_kind = ChangeSet::with_records(
            3u64.into(),
            [ChangeRecord::SwitchRemoved {
                branch: Address::from(0x1800u64),
            }],
        );

        assert!(reads.conflicts_with(&overlapping));
        assert!(!reads.conflicts_with(&elsewhere));
        assert!(!reads.conflicts_with(&other_kind));
    }

    #[test]
    fn addressless_changes_conflict_with_unbounded_reads() {
        let mut reads = ReadSet::new();
        reads.record_unbounded(ChangeKinds::SPACE_CREATED);
        let changes = ChangeSet::with_records(
            1u64.into(),
            [ChangeRecord::SpaceCreated {
                space: AddressSpaceId::from(7u8),
            }],
        );

        assert!(reads.conflicts_with(&changes));
    }

    #[test]
    fn the_index_reports_only_regions_whose_reads_intersect() {
        let mut index = DependencyIndex::with_analysers(1);

        let mut first = AddressRangeSet::new();
        first.insert_range(range(0x1000, 0x1fff));
        let mut first_reads = ReadSet::new();
        first_reads.record(ChangeKinds::SYMBOLS, range(0x8000, 0x80ff));
        index.record(0, &first, first_reads);

        let mut second = AddressRangeSet::new();
        second.insert_range(range(0x3000, 0x3fff));
        let mut second_reads = ReadSet::new();
        second_reads.record(ChangeKinds::SYMBOLS, range(0x9000, 0x90ff));
        index.record(0, &second, second_reads);

        let invalidated =
            index.invalidated(0, ChangeKinds::SYMBOLS, Some(&regions(0x8000, 0x80ff)));

        assert!(
            invalidated
                .regions()
                .contains(Address::in_default_space(0x1000u64)),
            "the production whose reads changed must be rescheduled"
        );
        assert!(
            !invalidated
                .regions()
                .contains(Address::in_default_space(0x3000u64)),
            "a production reading elsewhere must not be rescheduled"
        );
    }

    #[test]
    fn replacing_a_production_removes_superseded_dependencies() {
        let mut index = DependencyIndex::with_analysers(1);
        let mut old_reads = ReadSet::new();
        old_reads.record(ChangeKinds::SYMBOLS, range(0x8000, 0x80ff));
        index.record(0, &regions(0x1000, 0x1fff), old_reads);

        let mut new_reads = ReadSet::new();
        new_reads.record(ChangeKinds::SWITCHES, range(0x9000, 0x90ff));
        index.record(0, &regions(0x1400, 0x17ff), new_reads);

        let stale_old = index.invalidated(0, ChangeKinds::SYMBOLS, Some(&regions(0x8000, 0x80ff)));
        assert!(stale_old.regions().contains(Address::from(0x1200u64)));
        assert!(!stale_old.regions().contains(Address::from(0x1500u64)));
        assert!(stale_old.regions().contains(Address::from(0x1800u64)));

        let stale_new = index.invalidated(0, ChangeKinds::SWITCHES, Some(&regions(0x9000, 0x90ff)));
        assert!(!stale_new.regions().contains(Address::from(0x1200u64)));
        assert!(stale_new.regions().contains(Address::from(0x1500u64)));
        assert!(!stale_new.regions().contains(Address::from(0x1800u64)));
    }

    #[test]
    fn addressless_productions_retain_observed_dependencies() {
        let mut index = DependencyIndex::with_analysers(1);
        let mut reads = ReadSet::new();
        reads.record_unbounded(ChangeKinds::SPACE_CREATED);
        index.record(0, &AddressRangeSet::new(), reads);

        let invalidated = index.invalidated(0, ChangeKinds::SPACE_CREATED, None);

        assert!(invalidated.has_addressless());
        assert!(invalidated.regions().is_empty());
    }

    #[test]
    fn an_empty_read_set_depends_on_nothing() {
        let reads = ReadSet::new();

        assert!(reads.is_empty());
        assert!(!reads.intersects(ChangeKinds::all(), &regions(0, u64::MAX - 1)));
    }
}
