use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::RwLock;

use super::{Cached, Dependency, QueryEngine, QueryPage, QueryReader};
use crate::analysis::function::recovery::{PartialCodeBlock, PartialFunction};
use crate::engine::change::{ChangeKinds, ChangeRecord, ChangeSet, Revision};
use crate::ir::{
    Address, AddressRange, AddressRangeSet, RawAddress, ReferenceKind, ReferenceTarget,
};
use crate::loader::Loader;
use crate::project::Project;
use crate::queries::cache::QUERY_MEMO_CAPACITY;
use crate::queries::index::{CENSUS_INTERVAL, ChangeIndex, MAX_CHANGE_RUNS};
use crate::storage::segments::mapping::SegmentMappingId;
use crate::storage::segments::space::AddressSpaceId;

#[test]
fn test_query_page_exposes_entries_and_next_cursor() {
    let page = QueryPage::new([1, 2, 3], Some(3));

    assert_eq!(page.entries(), &[1, 2, 3]);
    assert_eq!(page.next_cursor(), Some(&3));
}

struct Fixture {
    project: Arc<RwLock<Project>>,
    queries: QueryEngine,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let loader = Loader::from_file("tests/ls.elf")?;
        let project = Arc::new(RwLock::new(Project::new_transient(&loader)?));
        let queries = QueryEngine::new(project.clone());
        Ok(Self { project, queries })
    }

    fn reader(&self) -> QueryReader {
        self.queries.reader()
    }

    fn next_revision(&self) -> Revision {
        self.project.read().revision().next()
    }

    fn commit_function(
        &mut self,
        function: PartialFunction,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let changes = {
            let mut project = self.project.write();
            let mut transaction = project.transaction("query fixture");
            transaction.add_function(function)?;
            transaction.commit()?
        };
        self.queries.apply_changes(&changes);
        Ok(())
    }

    fn remove_function(&mut self, entry: Address) -> Result<(), Box<dyn std::error::Error>> {
        let changes = {
            let mut project = self.project.write();
            let mut transaction = project.transaction("query fixture");
            transaction.remove_function(entry)?;
            transaction.commit()?
        };
        self.queries.apply_changes(&changes);
        Ok(())
    }

    fn apply(&mut self, changes: &ChangeSet) {
        self.queries.apply_changes(changes);
    }

    fn function_at(entry: Address) -> PartialFunction {
        Self::function_with_len(entry, 1)
    }

    fn function_with_len(entry: Address, len: usize) -> PartialFunction {
        let mut function = PartialFunction::new(entry);
        function.push_block(PartialCodeBlock::new(
            entry,
            len,
            Vec::new(),
            Default::default(),
        ));
        function
    }
}

#[test]
fn test_flow_graph_cache_is_exact_per_function() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let edited = Address::from(0x1_0000_0000u64);
    let same_window = Address::new(edited.space(), edited.offset() + 0x10);
    let distant = Address::from(0x9_0000_0000u64);

    fixture.commit_function(Fixture::function_at(edited))?;
    fixture.commit_function(Fixture::function_at(same_window))?;
    fixture.commit_function(Fixture::function_at(distant))?;

    let reader = fixture.reader();
    let edited_before = reader.flow_graph(edited)?.ok_or("edited missing")?;
    let neighbour_before = reader.flow_graph(same_window)?.ok_or("neighbour missing")?;
    let distant_before = reader.flow_graph(distant)?.ok_or("distant missing")?;

    fixture.commit_function(Fixture::function_with_len(edited, 2))?;

    let edited_after = reader.flow_graph(edited)?.ok_or("edited missing after")?;
    let neighbour_after = reader
        .flow_graph(same_window)?
        .ok_or("neighbour missing after")?;
    let distant_after = reader.flow_graph(distant)?.ok_or("distant missing after")?;

    assert!(!Arc::ptr_eq(&edited_before, &edited_after));
    assert!(Arc::ptr_eq(&neighbour_before, &neighbour_after));
    assert!(Arc::ptr_eq(&distant_before, &distant_after));

    Ok(())
}

#[test]
fn test_flow_graph_cache_invalidation_property() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let entries = (0..8u64)
        .map(|index| Address::from(0x1_0000_0000u64 + index * 0x10))
        .collect::<Vec<_>>();

    for entry in &entries {
        fixture.commit_function(Fixture::function_at(*entry))?;
    }

    let reader = fixture.reader();

    for edited_index in 0..entries.len() {
        let before = entries
            .iter()
            .map(|entry| Ok(reader.flow_graph(*entry)?.ok_or("function missing")?))
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;

        fixture.commit_function(Fixture::function_with_len(
            entries[edited_index],
            2 + edited_index,
        ))?;

        for (index, entry) in entries.iter().enumerate() {
            let after = reader.flow_graph(*entry)?.ok_or("function missing after")?;
            let stable = Arc::ptr_eq(&before[index], &after);
            assert_eq!(
                stable,
                index != edited_index,
                "only the edited function's cached graph may be invalidated"
            );
        }
    }

    Ok(())
}

#[test]
fn test_function_removal_invalidates_cached_flow_graph() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let entry = Address::from(0x1_0000_0000u64);

    fixture.commit_function(Fixture::function_at(entry))?;

    let reader = fixture.reader();
    assert!(reader.flow_graph(entry)?.is_some());

    fixture.remove_function(entry)?;

    assert!(reader.flow_graph(entry)?.is_none());

    Ok(())
}

#[test]
fn test_function_add_invalidates_cached_absence() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let entry = Address::from(0x1_0000_0000u64);

    let reader = fixture.reader();
    assert!(reader.flow_graph(entry)?.is_none());
    assert!(reader.flow_graph(entry)?.is_none());

    fixture.commit_function(Fixture::function_at(entry))?;

    assert!(reader.flow_graph(entry)?.is_some());

    Ok(())
}

#[test]
fn test_byte_write_leaves_flow_graph_cached() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let entry = Address::from(0x1_0000_0000u64);

    fixture.commit_function(Fixture::function_at(entry))?;

    let reader = fixture.reader();
    let before = reader.flow_graph(entry)?.ok_or("function missing")?;

    let revision = fixture.next_revision();
    fixture.apply(&ChangeSet::with_records(
        revision,
        [ChangeRecord::BytesWritten {
            range: AddressRange::new(entry.space(), entry.raw_address(), entry.raw_address()),
        }],
    ));

    let after = reader
        .flow_graph(entry)?
        .ok_or("function missing after write")?;

    assert!(Arc::ptr_eq(&before, &after));

    Ok(())
}

#[test]
fn test_query_memo_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let reader = fixture.reader();

    for index in 0..(QUERY_MEMO_CAPACITY as u64 * 2) {
        let _ = reader.flow_graph(Address::from(0x1_0000_0000u64 + index * 0x10))?;
    }

    assert!(fixture.queries.cache.len() <= QUERY_MEMO_CAPACITY);

    Ok(())
}

#[test]
fn test_cache_is_pure_derived_state() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let entry = Address::from(0x1_0000_0000u64);

    fixture.commit_function(Fixture::function_with_len(entry, 4))?;

    let reader = fixture.reader();
    let before = reader.flow_graph(entry)?.ok_or("function missing")?;

    fixture.queries.cache.clear();

    let after = reader
        .flow_graph(entry)?
        .ok_or("function missing after clear")?;

    assert!(!Arc::ptr_eq(&before, &after));
    assert_eq!(before.targets(), after.targets());

    Ok(())
}

#[test]
fn test_latest_change_tracks_region_and_kinds() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let reader = fixture.reader();

    let inside = AddressRange::new(
        AddressSpaceId::from(0u8),
        RawAddress::from(0x1000u64),
        RawAddress::from(0x1fffu64),
    );
    let outside = AddressRange::new(
        AddressSpaceId::from(0u8),
        RawAddress::from(0x8000u64),
        RawAddress::from(0x8fffu64),
    );
    let mut region = AddressRangeSet::new();
    region.insert_range(inside);

    let baseline = reader.revision()?;
    assert!(!reader.changed_since(baseline, ChangeKinds::BYTES_WRITTEN, &region)?);

    let outside_revision = fixture.next_revision();
    fixture.apply(&ChangeSet::with_records(
        outside_revision,
        [ChangeRecord::BytesWritten { range: outside }],
    ));
    assert!(!reader.changed_since(baseline, ChangeKinds::BYTES_WRITTEN, &region)?);

    let inside_revision = fixture.next_revision();
    fixture.apply(&ChangeSet::with_records(
        inside_revision,
        [ChangeRecord::BytesWritten { range: inside }],
    ));
    assert!(reader.changed_since(baseline, ChangeKinds::BYTES_WRITTEN, &region)?);
    assert_eq!(
        reader.latest_change(ChangeKinds::BYTES_WRITTEN, &region)?,
        inside_revision
    );
    assert!(!reader.changed_since(baseline, ChangeKinds::FUNCTIONS, &region)?);

    Ok(())
}

#[test]
fn test_reference_change_is_observable_from_both_endpoints()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let reader = fixture.reader();

    let from = Address::new(AddressSpaceId::from(0u8), 0x1000u64);
    let to = Address::new(AddressSpaceId::from(0u8), 0x8000u64);
    let disjoint = Address::new(AddressSpaceId::from(0u8), 0x9000u64);

    let baseline = reader.revision()?;
    let revision = fixture.next_revision();
    fixture.apply(&ChangeSet::with_records(
        revision,
        [ChangeRecord::ReferenceAdded {
            from,
            target: ReferenceTarget::from(to),
            kind: ReferenceKind::call(),
        }],
    ));

    for observed in [from, to] {
        let mut region = AddressRangeSet::new();
        region.insert_range(AddressRange::point(observed));
        assert!(reader.changed_since(baseline, ChangeKinds::REFERENCES, &region)?);
    }

    let mut disjoint_region = AddressRangeSet::new();
    disjoint_region.insert_range(AddressRange::point(disjoint));
    assert!(!reader.changed_since(baseline, ChangeKinds::REFERENCES, &disjoint_region)?);

    Ok(())
}

#[test]
fn test_latest_change_kinds_mask_selects_groups() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let reader = fixture.reader();

    let range = AddressRange::new(
        AddressSpaceId::from(0u8),
        RawAddress::from(0x1000u64),
        RawAddress::from(0x1fffu64),
    );
    let mut region = AddressRangeSet::new();
    region.insert_range(range);

    let baseline = reader.revision()?;
    let mapped_revision = fixture.next_revision();
    fixture.apply(&ChangeSet::with_records(
        mapped_revision,
        [ChangeRecord::SegmentMapped {
            mapping: SegmentMappingId::new(0),
            range,
        }],
    ));

    assert!(!reader.changed_since(baseline, ChangeKinds::BYTES_WRITTEN, &region)?);
    assert!(reader.changed_since(baseline, ChangeKinds::SEGMENTS, &region)?);
    assert!(reader.changed_since(
        baseline,
        ChangeKinds::BYTES_WRITTEN | ChangeKinds::SEGMENTS,
        &region
    )?);

    Ok(())
}

#[test]
fn test_region_less_changes_are_observable() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let reader = fixture.reader();

    let mut region = AddressRangeSet::new();
    region.insert_range(AddressRange::new(
        AddressSpaceId::from(0u8),
        RawAddress::from(0x1000u64),
        RawAddress::from(0x1fffu64),
    ));
    let baseline = reader.revision()?;
    let created = Revision::new(baseline.value() + 1);
    let changed = Revision::new(baseline.value() + 2);
    let space = Revision::new(baseline.value() + 3);

    fixture.apply(&ChangeSet::with_records(
        created,
        [ChangeRecord::SegmentMappingCreated {
            mapping: SegmentMappingId::new(0),
        }],
    ));
    assert!(reader.changed_since(baseline, ChangeKinds::SEGMENT_MAPPING_CREATED, &region)?);
    assert!(reader.changed_since(baseline, ChangeKinds::SEGMENTS, &region)?);
    assert!(!reader.changed_since(baseline, ChangeKinds::BYTES_WRITTEN, &region)?);

    fixture.apply(&ChangeSet::with_records(
        changed,
        [ChangeRecord::SegmentMappingChanged {
            mapping: SegmentMappingId::new(0),
        }],
    ));
    assert!(reader.changed_since(created, ChangeKinds::SEGMENT_MAPPING_CHANGED, &region)?);

    fixture.apply(&ChangeSet::with_records(
        space,
        [ChangeRecord::SpaceCreated {
            space: AddressSpaceId::from(7u8),
        }],
    ));
    assert!(reader.changed_since(changed, ChangeKinds::SPACE_CREATED, &region)?);

    Ok(())
}

#[test]
fn test_region_bearing_precision_survives_region_less_kinds()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let reader = fixture.reader();

    let touched = AddressRange::new(
        AddressSpaceId::from(0u8),
        RawAddress::from(0x1000u64),
        RawAddress::from(0x1fffu64),
    );
    let mut disjoint = AddressRangeSet::new();
    disjoint.insert_range(AddressRange::new(
        AddressSpaceId::from(0u8),
        RawAddress::from(0x8000u64),
        RawAddress::from(0x8fffu64),
    ));

    let baseline = reader.revision()?;
    let write = fixture.next_revision();
    fixture.apply(&ChangeSet::with_records(
        write,
        [ChangeRecord::BytesWritten { range: touched }],
    ));

    assert!(!reader.changed_since(baseline, ChangeKinds::BYTES_WRITTEN, &disjoint)?);

    Ok(())
}

#[test]
fn test_restored_marks_every_region_changed() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let reader = fixture.reader();

    let baseline = reader.revision()?;
    let restored_revision = fixture.next_revision();
    fixture.apply(&ChangeSet::with_records(
        restored_revision,
        [ChangeRecord::Restored {
            to: restored_revision,
        }],
    ));

    let region = AddressRangeSet::new();
    assert!(reader.changed_since(baseline, ChangeKinds::all(), &region)?);
    assert!(reader.changed_since(baseline, ChangeKinds::FUNCTIONS, &region)?);

    Ok(())
}

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
fn test_change_index_census_bounds_run_count() {
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

        assert!(
            index.max_run_count() <= MAX_CHANGE_RUNS + CENSUS_INTERVAL,
            "amortised census let a group exceed the run bound by more than one interval"
        );
    }
}

#[test]
fn test_cached_recomputes_only_on_dependency_change() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let reader = fixture.reader();

    let inside = AddressRange::new(
        AddressSpaceId::from(0u8),
        RawAddress::from(0x1000u64),
        RawAddress::from(0x1fffu64),
    );
    let outside = AddressRange::new(
        AddressSpaceId::from(0u8),
        RawAddress::from(0x8000u64),
        RawAddress::from(0x8fffu64),
    );
    let mut region = AddressRangeSet::new();
    region.insert_range(inside);

    let calls = AtomicUsize::new(0);
    let mut cached = Cached::new(Dependency::on(ChangeKinds::BYTES_WRITTEN).within(region));

    let first = cached.get(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let second = cached.get(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(first, second);

    let base = reader.revision()?;
    fixture.apply(&ChangeSet::with_records(
        Revision::new(base.value() + 1),
        [ChangeRecord::BytesWritten { range: outside }],
    ));
    cached.get(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    fixture.apply(&ChangeSet::with_records(
        Revision::new(base.value() + 2),
        [ChangeRecord::BytesWritten { range: inside }],
    ));
    let refreshed = cached.get(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_ne!(first, refreshed);

    Ok(())
}

#[test]
fn test_cached_composes_across_inputs() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let reader = fixture.reader();

    let functions = AddressRange::new(
        AddressSpaceId::from(0u8),
        RawAddress::from(0x1000u64),
        RawAddress::from(0x1fffu64),
    );
    let bytes = AddressRange::new(
        AddressSpaceId::from(0u8),
        RawAddress::from(0x4000u64),
        RawAddress::from(0x4fffu64),
    );
    let mut function_region = AddressRangeSet::new();
    function_region.insert_range(functions);
    let mut byte_region = AddressRangeSet::new();
    byte_region.insert_range(bytes);

    let calls = AtomicUsize::new(0);
    let mut cached = Cached::new(
        Dependency::on(ChangeKinds::FUNCTIONS)
            .within(function_region)
            .and(Dependency::on(ChangeKinds::BYTES_WRITTEN).within(byte_region)),
    );

    cached.get(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let base = reader.revision()?;
    let mut function_coverage = AddressRangeSet::new();
    function_coverage.insert_range(functions);
    fixture.apply(&ChangeSet::with_records(
        Revision::new(base.value() + 1),
        [ChangeRecord::FunctionChanged {
            entry: functions.start_address(),
            kind: crate::engine::change::FunctionChangeKind::Body,
            coverage: function_coverage,
        }],
    ));
    cached.get(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    fixture.apply(&ChangeSet::with_records(
        Revision::new(base.value() + 2),
        [ChangeRecord::BytesWritten { range: bytes }],
    ));
    cached.get(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    fixture.apply(&ChangeSet::with_records(
        Revision::new(base.value() + 3),
        [ChangeRecord::BytesWritten {
            range: AddressRange::new(
                AddressSpaceId::from(0u8),
                RawAddress::from(0x9000u64),
                RawAddress::from(0x9fffu64),
            ),
        }],
    ));
    cached.get(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    Ok(())
}

#[test]
fn test_cached_region_less_dependency() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let reader = fixture.reader();

    let calls = AtomicUsize::new(0);
    let mut cached = Cached::new(Dependency::on(ChangeKinds::SEGMENT_MAPPING_CREATED));

    cached.get(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let base = reader.revision()?;
    fixture.apply(&ChangeSet::with_records(
        Revision::new(base.value() + 1),
        [ChangeRecord::SegmentMappingCreated {
            mapping: SegmentMappingId::new(0),
        }],
    ));
    cached.get(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    Ok(())
}
