use std::sync::Arc;

use parking_lot::RwLock;

use super::{QueryEngine, QueryPage, QueryReader};
use crate::analysis::function::recovery::{PartialCodeBlock, PartialFunction};
use crate::engine::change::{ChangeRecord, ChangeSet, Revision};
use crate::ir::Address;
use crate::loader::Loader;
use crate::project::Project;
use crate::queries::stamps::{
    RANGE_STAMP_BUCKET_BITS, RANGE_STAMP_BUCKETS, RANGE_STAMP_WINDOW_CAP, RangeBucket,
    RangeBuckets, STAMP_BUCKETS, STAMP_FAMILIES, STAMP_INPUTS, StampBucket,
};

#[test]
fn test_query_page_exposes_entries_and_next_cursor() {
    let page = QueryPage::new([1, 2, 3], Some(3));

    assert_eq!(page.entries(), &[1, 2, 3]);
    assert_eq!(page.next_cursor(), Some(&3));
}

#[test]
fn test_query_stamps_have_fixed_cardinality() {
    assert_eq!(
        STAMP_INPUTS,
        STAMP_BUCKETS * STAMP_FAMILIES + 2 * RANGE_STAMP_BUCKETS + 1
    );
    assert_eq!(STAMP_INPUTS, 2049);
}

#[test]
fn test_query_stamp_cardinality_does_not_scale_with_function_count()
-> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use parking_lot::RwLock;

    use crate::analysis::function::recovery::{PartialCodeBlock, PartialFunction};
    use crate::ir::Address;
    use crate::loader::Loader;
    use crate::project::Project;
    use crate::queries::stamps::StampDatabase;

    fn function_at(entry: Address) -> PartialFunction {
        let mut function = PartialFunction::new(entry);
        function.push_block(PartialCodeBlock::new(
            entry,
            1,
            Vec::new(),
            Default::default(),
        ));
        function
    }

    fn project_with_functions(count: usize) -> Result<Project, Box<dyn std::error::Error>> {
        let loader = Loader::from_file("tests/ls.elf")?;
        let mut project = Project::new_transient(&loader)?;
        let mut transaction = project.transaction("stamp cardinality test");

        for index in 0..count {
            let entry = Address::from(0x1_0000_0000u64 + (index as u64 * 0x10));
            transaction.add_function(function_at(entry))?;
        }

        transaction.commit()?;
        Ok(project)
    }

    for count in [1, 10, 100] {
        let project = Arc::new(RwLock::new(project_with_functions(count)?));
        let database = StampDatabase::new(project);

        assert_eq!(database.stamp_input_count(), STAMP_INPUTS);
    }

    Ok(())
}

#[test]
fn test_function_stamp_bucket_precision_groups_same_bucket_only()
-> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use parking_lot::RwLock;

    use super::QueryEngine;
    use crate::analysis::function::recovery::{PartialCodeBlock, PartialFunction};
    use crate::ir::Address;
    use crate::loader::Loader;
    use crate::project::Project;
    use crate::queries::stamps::{RANGE_STAMP_BUCKET_BITS, RangeBucket, RangeBuckets};

    let loader = Loader::from_file("tests/ls.elf")?;
    let mut project = Project::new_transient(&loader)?;
    let changed = Address::from(0x1_0000_0000u64);
    let changed_bucket = range_bucket_of(changed);
    let same_bucket = Address::new(changed.space(), changed.offset() + 0x10);
    let different_bucket = find_window_peer(changed, |bucket| bucket != changed_bucket)?;
    let mut transaction = project.transaction("stamp precision test");

    transaction.add_function(function_at(changed))?;
    transaction.add_function(function_at(same_bucket))?;
    transaction.add_function(function_at(different_bucket))?;
    transaction.commit()?;

    let project = Arc::new(RwLock::new(project));
    let mut queries = QueryEngine::new(project.clone());
    let reader = queries.reader();

    assert_eq!(range_bucket_of(same_bucket), changed_bucket);
    assert_ne!(range_bucket_of(different_bucket), changed_bucket);

    let same_before = reader
        .flow_graph(same_bucket)?
        .ok_or("same-bucket function missing")?;
    let different_before = reader
        .flow_graph(different_bucket)?
        .ok_or("different-bucket function missing")?;

    let changes = {
        let mut project = project.write();
        let mut transaction = project.transaction("stamp precision edit");
        transaction.add_function(function_with_len(changed, 2))?;
        transaction.commit()?
    };
    queries.apply_changes(&changes);

    let same_after = reader
        .flow_graph(same_bucket)?
        .ok_or("same-bucket function missing after edit")?;
    let different_after = reader
        .flow_graph(different_bucket)?
        .ok_or("different-bucket function missing after edit")?;

    assert!(!Arc::ptr_eq(&same_before, &same_after));
    assert!(Arc::ptr_eq(&different_before, &different_after));

    fn range_bucket_of(address: Address) -> RangeBucket {
        RangeBucket::for_window(address.space(), RangeBuckets::window_of(address.offset()))
    }

    fn find_window_peer(
        start: Address,
        predicate: impl Fn(RangeBucket) -> bool,
    ) -> Result<Address, Box<dyn std::error::Error>> {
        for step in 1..0x10000u64 {
            let candidate = Address::new(
                start.space(),
                start.offset() + (step << RANGE_STAMP_BUCKET_BITS),
            );
            if predicate(range_bucket_of(candidate)) {
                return Ok(candidate);
            }
        }

        Err("could not find address for requested range bucket".into())
    }

    fn function_at(entry: Address) -> PartialFunction {
        function_with_len(entry, 1)
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

    Ok(())
}

struct RangeStampFixture {
    project: Arc<RwLock<Project>>,
    queries: QueryEngine,
}

impl RangeStampFixture {
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
            let mut transaction = project.transaction("range stamp fixture");
            transaction.add_function(function)?;
            transaction.commit()?
        };
        self.queries.apply_changes(&changes);
        Ok(())
    }

    fn remove_function(&mut self, entry: Address) -> Result<(), Box<dyn std::error::Error>> {
        let changes = {
            let mut project = self.project.write();
            let mut transaction = project.transaction("range stamp fixture");
            transaction.remove_function(entry)?;
            transaction.commit()?
        };
        self.queries.apply_changes(&changes);
        Ok(())
    }

    fn apply(&mut self, changes: &ChangeSet) {
        self.queries.apply_changes(changes);
    }

    fn address_range_revision(&self, bucket: RangeBucket) -> Revision {
        let database = self.queries.stamps.lock().worker();
        database.address_range_stamp(bucket).revision(&database)
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

    fn function_with_body(entry: Address, body: Address) -> PartialFunction {
        let mut function = PartialFunction::new(entry);
        function.push_block(PartialCodeBlock::new(
            body,
            1,
            Vec::new(),
            Default::default(),
        ));
        function
    }

    fn wide_function(entry: Address, windows: u64) -> PartialFunction {
        let mut function = PartialFunction::new(entry);
        for index in 0..windows {
            let address = Address::new(
                entry.space(),
                entry.offset() + (index << RANGE_STAMP_BUCKET_BITS),
            );
            function.push_block(PartialCodeBlock::new(
                address,
                1,
                Vec::new(),
                Default::default(),
            ));
        }
        function
    }

    fn range_bucket_of(address: Address) -> RangeBucket {
        RangeBucket::for_window(address.space(), RangeBuckets::window_of(address.offset()))
    }

    fn window_peer(
        start: Address,
        predicate: impl Fn(Address) -> bool,
    ) -> Result<Address, Box<dyn std::error::Error>> {
        for step in 1..0x20000u64 {
            let candidate = Address::new(
                start.space(),
                start.offset() + (step << RANGE_STAMP_BUCKET_BITS),
            );
            if predicate(candidate) {
                return Ok(candidate);
            }
        }

        Err("could not find address for requested predicate".into())
    }
}

#[test]
fn test_function_replacement_touches_old_and_new_range_buckets()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RangeStampFixture::new()?;
    let entry = Address::from(0x1_0000_0000u64);
    let old_neighbour = Address::new(entry.space(), entry.offset() + 0x10);
    let entry_bucket = RangeStampFixture::range_bucket_of(entry);
    let new_body = RangeStampFixture::window_peer(entry, |candidate| {
        RangeStampFixture::range_bucket_of(candidate) != entry_bucket
    })?;
    let new_bucket = RangeStampFixture::range_bucket_of(new_body);
    let new_neighbour = Address::new(new_body.space(), new_body.offset() + 0x10);
    let unrelated = RangeStampFixture::window_peer(new_body, |candidate| {
        let bucket = RangeStampFixture::range_bucket_of(candidate);
        bucket != entry_bucket && bucket != new_bucket
    })?;

    fixture.commit_function(RangeStampFixture::function_at(entry))?;
    fixture.commit_function(RangeStampFixture::function_at(old_neighbour))?;
    fixture.commit_function(RangeStampFixture::function_at(new_neighbour))?;
    fixture.commit_function(RangeStampFixture::function_at(unrelated))?;

    let reader = fixture.reader();
    let old_before = reader
        .flow_graph(old_neighbour)?
        .ok_or("old-range neighbour missing")?;
    let new_before = reader
        .flow_graph(new_neighbour)?
        .ok_or("new-range neighbour missing")?;
    let unrelated_before = reader
        .flow_graph(unrelated)?
        .ok_or("unrelated function missing")?;

    fixture.commit_function(RangeStampFixture::function_with_body(entry, new_body))?;

    let old_after = reader
        .flow_graph(old_neighbour)?
        .ok_or("old-range neighbour missing after edit")?;
    let new_after = reader
        .flow_graph(new_neighbour)?
        .ok_or("new-range neighbour missing after edit")?;
    let unrelated_after = reader
        .flow_graph(unrelated)?
        .ok_or("unrelated function missing after edit")?;

    assert!(!Arc::ptr_eq(&old_before, &old_after));
    assert!(!Arc::ptr_eq(&new_before, &new_after));
    assert!(Arc::ptr_eq(&unrelated_before, &unrelated_after));

    Ok(())
}

#[test]
fn test_function_removal_invalidates_cached_flow_graph() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RangeStampFixture::new()?;
    let entry = Address::from(0x1_0000_0000u64);

    fixture.commit_function(RangeStampFixture::function_at(entry))?;

    let reader = fixture.reader();
    assert!(reader.flow_graph(entry)?.is_some());

    fixture.remove_function(entry)?;

    assert!(reader.flow_graph(entry)?.is_none());

    Ok(())
}

#[test]
fn test_function_add_invalidates_missing_result_through_membership()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RangeStampFixture::new()?;
    let entry = Address::from(0x1_0000_0000u64);

    let reader = fixture.reader();
    assert!(reader.flow_graph(entry)?.is_none());
    assert!(reader.flow_graph(entry)?.is_none());

    fixture.commit_function(RangeStampFixture::function_at(entry))?;

    assert!(reader.flow_graph(entry)?.is_some());

    Ok(())
}

#[test]
fn test_byte_writes_touch_address_ranges_and_leave_flow_graphs_cached()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RangeStampFixture::new()?;
    let entry = Address::from(0x1_0000_0000u64);

    fixture.commit_function(RangeStampFixture::function_at(entry))?;

    let reader = fixture.reader();
    let before = reader.flow_graph(entry)?.ok_or("function missing")?;

    let written = RangeStampFixture::range_bucket_of(entry);
    let distant_address = RangeStampFixture::window_peer(entry, |candidate| {
        RangeStampFixture::range_bucket_of(candidate) != written
    })?;
    let distant = RangeStampFixture::range_bucket_of(distant_address);
    let written_before = fixture.address_range_revision(written);
    let distant_before = fixture.address_range_revision(distant);
    let revision = fixture.next_revision();

    fixture.apply(&ChangeSet::with_records(
        revision,
        [ChangeRecord::BytesWritten {
            space: entry.space(),
            range: (entry.raw_address(), entry.raw_address()),
        }],
    ));

    let after = reader
        .flow_graph(entry)?
        .ok_or("function missing after write")?;

    assert!(Arc::ptr_eq(&before, &after));
    assert_ne!(written_before, revision);
    assert_eq!(fixture.address_range_revision(written), revision);
    assert_eq!(fixture.address_range_revision(distant), distant_before);

    Ok(())
}

#[test]
fn test_wide_function_coverage_uses_overflow_fallback() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RangeStampFixture::new()?;
    let entry = Address::from(0x1_0000_0000u64);
    let windows = RANGE_STAMP_WINDOW_CAP as u64 + 1;

    fixture.commit_function(RangeStampFixture::wide_function(entry, windows))?;

    let reader = fixture.reader();
    let before = reader.flow_graph(entry)?.ok_or("wide function missing")?;

    let far = Address::from(0x9_0000_0000u64);
    fixture.commit_function(RangeStampFixture::function_at(far))?;

    let after = reader
        .flow_graph(entry)?
        .ok_or("wide function missing after unrelated edit")?;

    assert!(!Arc::ptr_eq(&before, &after));

    Ok(())
}

#[test]
fn test_entry_hash_collision_no_longer_invalidates_unrelated_function()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RangeStampFixture::new()?;
    let changed = Address::from(0x1_0000_0000u64);
    let changed_stamp = StampBucket::for_address(changed);
    let changed_range = RangeStampFixture::range_bucket_of(changed);
    let collided = RangeStampFixture::window_peer(changed, |candidate| {
        StampBucket::for_address(candidate) == changed_stamp
            && RangeStampFixture::range_bucket_of(candidate) != changed_range
    })?;

    fixture.commit_function(RangeStampFixture::function_at(changed))?;
    fixture.commit_function(RangeStampFixture::function_at(collided))?;

    let reader = fixture.reader();
    let changed_before = reader
        .flow_graph(changed)?
        .ok_or("changed function missing")?;
    let collided_before = reader
        .flow_graph(collided)?
        .ok_or("collided function missing")?;

    fixture.commit_function(RangeStampFixture::function_with_len(changed, 2))?;

    let changed_after = reader
        .flow_graph(changed)?
        .ok_or("changed function missing after edit")?;
    let collided_after = reader
        .flow_graph(collided)?
        .ok_or("collided function missing after edit")?;

    assert!(!Arc::ptr_eq(&changed_before, &changed_after));
    assert!(Arc::ptr_eq(&collided_before, &collided_after));

    Ok(())
}

#[test]
fn test_range_bucket_classification_bounds() {
    use crate::ir::{CoveredAddressRange, RawAddress};
    use crate::storage::segments::space::AddressSpaceId;

    let space = AddressSpaceId::from(0u8);
    let range = |start: u64, end: u64| {
        CoveredAddressRange::new(space, RawAddress::from(start), RawAddress::from(end))
    };

    assert_eq!(RangeBuckets::covering(&[]), RangeBuckets::Overflow);
    assert_eq!(
        RangeBuckets::covering(&[range(0, u64::MAX)]),
        RangeBuckets::Overflow
    );

    let cap_windows = RANGE_STAMP_WINDOW_CAP as u64;
    let at_cap = range(0, (cap_windows << RANGE_STAMP_BUCKET_BITS) - 1);
    let RangeBuckets::Buckets(buckets) = RangeBuckets::covering(&[at_cap]) else {
        panic!("coverage of exactly the window cap must stay bucketed");
    };
    assert!(!buckets.is_empty());
    assert!(buckets.len() <= RANGE_STAMP_WINDOW_CAP);

    assert_eq!(
        RangeBuckets::covering(&[range(0, cap_windows << RANGE_STAMP_BUCKET_BITS)]),
        RangeBuckets::Overflow
    );

    let RangeBuckets::Buckets(deduped) =
        RangeBuckets::covering(&[range(0x1000, 0x1004), range(0x1008, 0x100c)])
    else {
        panic!("two sub-window ranges must stay bucketed");
    };
    assert_eq!(deduped.len(), 1);
}
