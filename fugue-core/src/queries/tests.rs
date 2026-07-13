use std::sync::Arc;

use parking_lot::RwLock;

use super::{QueryEngine, QueryPage, QueryReader};
use crate::analysis::function::recovery::{PartialCodeBlock, PartialFunction};
use crate::engine::change::{ChangeKinds, ChangeRecord, ChangeSet, Revision};
use crate::ir::{Address, AddressRange, AddressRangeSet, RawAddress};
use crate::loader::Loader;
use crate::project::Project;
use crate::queries::cache::QUERY_MEMO_CAPACITY;
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

    assert_eq!(fixture.queries.cache.lock().len(), QUERY_MEMO_CAPACITY);

    Ok(())
}

#[test]
fn test_cache_is_pure_derived_state() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let entry = Address::from(0x1_0000_0000u64);

    fixture.commit_function(Fixture::function_with_len(entry, 4))?;

    let reader = fixture.reader();
    let before = reader.flow_graph(entry)?.ok_or("function missing")?;

    fixture.queries.cache.lock().clear();

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
fn test_latest_change_kinds_mask_selects_groups() -> Result<(), Box<dyn std::error::Error>> {
    use crate::storage::segments::mapping::SegmentMappingId;

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
    use crate::queries::index::{ChangeIndex, MAX_CHANGE_RUNS};

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
