use std::hash::{Hash, Hasher};
use std::sync::Arc;

use parking_lot::RwLock;
use rustc_hash::FxHasher;
use salsa::{Database, Setter, Storage, StorageHandle};

use crate::engine::change::{ChangeRecord, ChangeSet, Revision};
use crate::ir::cfg::FlowGraph;
use crate::ir::{Address, CoveredAddressRange};
use crate::project::Project;
use crate::queries::read::ProjectRead;
use crate::storage::segments::mapping::SegmentMappingId;
use crate::storage::segments::space::AddressSpaceId;

pub(crate) const STAMP_BUCKETS: usize = 256;
pub(crate) const STAMP_FAMILIES: usize = 4;
pub(crate) const RANGE_STAMP_BUCKET_BITS: u32 = 12;
pub(crate) const RANGE_STAMP_BUCKETS: usize = 512;
pub(crate) const RANGE_STAMP_WINDOW_CAP: usize = 64;
pub(crate) const STAMP_INPUTS: usize = STAMP_BUCKETS * STAMP_FAMILIES + 2 * RANGE_STAMP_BUCKETS + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StampBucket(usize);

impl StampBucket {
    pub(crate) fn for_address(address: Address) -> Self {
        Self::for_key(&(address.space().index(), address.offset()))
    }

    fn for_mapping(mapping: SegmentMappingId) -> Self {
        Self::for_key(&mapping.index())
    }

    fn for_key(key: &impl Hash) -> Self {
        let mut hasher = FxHasher::default();
        key.hash(&mut hasher);
        Self((hasher.finish() as usize) % STAMP_BUCKETS)
    }

    pub(crate) fn index(&self) -> usize {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RangeBucket(usize);

impl RangeBucket {
    pub(crate) fn for_window(space: AddressSpaceId, window: u64) -> Self {
        let mut hasher = FxHasher::default();
        (space.index(), window).hash(&mut hasher);
        Self((hasher.finish() as usize) % RANGE_STAMP_BUCKETS)
    }

    pub(crate) fn index(&self) -> usize {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RangeBuckets {
    Buckets(Vec<RangeBucket>),
    Overflow,
}

impl RangeBuckets {
    pub(crate) fn covering(ranges: &[CoveredAddressRange]) -> Self {
        let mut total = 0usize;

        for range in ranges {
            if range.end() < range.start() {
                continue;
            }
            total = total.saturating_add(Self::window_count(range));
            if total > RANGE_STAMP_WINDOW_CAP {
                return Self::Overflow;
            }
        }

        if total == 0 {
            return Self::Overflow;
        }

        let mut buckets = Vec::with_capacity(total);

        for range in ranges {
            if range.end() < range.start() {
                continue;
            }
            let start = Self::window_of(range.start().offset());
            let end = Self::window_of(range.end().offset());
            for window in start..=end {
                buckets.push(RangeBucket::for_window(range.space(), window));
            }
        }

        buckets.sort_unstable();
        buckets.dedup();
        Self::Buckets(buckets)
    }

    pub(crate) fn window_of(offset: u64) -> u64 {
        offset >> RANGE_STAMP_BUCKET_BITS
    }

    fn window_count(range: &CoveredAddressRange) -> usize {
        let windows =
            Self::window_of(range.end().offset()) - Self::window_of(range.start().offset());
        usize::try_from(windows).map_or(usize::MAX, |count| count.saturating_add(1))
    }
}

#[salsa::input]
pub(crate) struct FunctionDataStamp {
    revision: Revision,
}

#[salsa::input]
pub(crate) struct FunctionMembershipStamp {
    revision: Revision,
}

#[salsa::input]
pub(crate) struct MappingTableStamp {
    revision: Revision,
}

#[salsa::input]
pub(crate) struct SymbolTableStamp {
    revision: Revision,
}

#[salsa::input]
pub(crate) struct FunctionRangeStamp {
    revision: Revision,
}

#[salsa::input]
pub(crate) struct FunctionRangeOverflowStamp {
    revision: Revision,
}

#[salsa::input]
pub(crate) struct AddressRangeStamp {
    pub(crate) revision: Revision,
}

#[salsa::interned]
struct AddressKey<'db> {
    address: Address,
}

#[salsa::db]
pub(crate) trait QueryDatabase: Database {
    fn project(&self) -> &Arc<RwLock<Project>>;
    fn function_membership_stamp(&self, bucket: StampBucket) -> FunctionMembershipStamp;
    fn function_range_stamp(&self, bucket: RangeBucket) -> FunctionRangeStamp;
    fn function_range_overflow_stamp(&self) -> FunctionRangeOverflowStamp;
}

#[salsa::db]
pub(crate) struct StampDatabase {
    storage: Storage<Self>,
    project: Arc<RwLock<Project>>,
    function_data: Arc<[FunctionDataStamp]>,
    function_membership: Arc<[FunctionMembershipStamp]>,
    mapping_table: Arc<[MappingTableStamp]>,
    symbol_table: Arc<[SymbolTableStamp]>,
    function_range: Arc<[FunctionRangeStamp]>,
    function_range_overflow: Arc<[FunctionRangeOverflowStamp]>,
    address_range: Arc<[AddressRangeStamp]>,
}

pub(crate) struct StampDatabaseState {
    storage: Option<StorageHandle<StampDatabase>>,
    project: Arc<RwLock<Project>>,
    function_data: Arc<[FunctionDataStamp]>,
    function_membership: Arc<[FunctionMembershipStamp]>,
    mapping_table: Arc<[MappingTableStamp]>,
    symbol_table: Arc<[SymbolTableStamp]>,
    function_range: Arc<[FunctionRangeStamp]>,
    function_range_overflow: Arc<[FunctionRangeOverflowStamp]>,
    address_range: Arc<[AddressRangeStamp]>,
}

impl StampDatabaseState {
    pub(crate) fn new(project: Arc<RwLock<Project>>) -> Self {
        StampDatabase::new(project).into_state()
    }

    pub(crate) fn worker(&self) -> StampDatabase {
        let Some(storage) = self.storage.as_ref() else {
            panic!("stamp database state has no storage handle");
        };
        self.database(storage.clone().into_storage())
    }

    pub(crate) fn apply_changes(&mut self, changes: &ChangeSet) {
        self.with_database_mut(|database| database.apply_changes(changes));
    }

    fn with_database_mut<T>(&mut self, query: impl FnOnce(&mut StampDatabase) -> T) -> T {
        let mut lease = StampDatabaseLease::new(self);
        let result = query(lease.database_mut());
        lease.finish();
        result
    }

    fn take_database(&mut self) -> StampDatabase {
        let Some(storage) = self.storage.take() else {
            panic!("stamp database state has no storage handle");
        };
        self.database(storage.into_storage())
    }

    fn database(&self, storage: Storage<StampDatabase>) -> StampDatabase {
        StampDatabase {
            storage,
            project: self.project.clone(),
            function_data: self.function_data.clone(),
            function_membership: self.function_membership.clone(),
            mapping_table: self.mapping_table.clone(),
            symbol_table: self.symbol_table.clone(),
            function_range: self.function_range.clone(),
            function_range_overflow: self.function_range_overflow.clone(),
            address_range: self.address_range.clone(),
        }
    }

    fn replace(&mut self, database: StampDatabase) {
        let StampDatabase {
            storage,
            project,
            function_data,
            function_membership,
            mapping_table,
            symbol_table,
            function_range,
            function_range_overflow,
            address_range,
        } = database;

        self.storage = Some(storage.into_zalsa_handle());
        self.project = project;
        self.function_data = function_data;
        self.function_membership = function_membership;
        self.mapping_table = mapping_table;
        self.symbol_table = symbol_table;
        self.function_range = function_range;
        self.function_range_overflow = function_range_overflow;
        self.address_range = address_range;
    }
}

struct StampDatabaseLease<'a> {
    state: &'a mut StampDatabaseState,
    database: Option<StampDatabase>,
}

impl<'a> StampDatabaseLease<'a> {
    fn new(state: &'a mut StampDatabaseState) -> Self {
        let database = state.take_database();
        Self {
            state,
            database: Some(database),
        }
    }

    fn database_mut(&mut self) -> &mut StampDatabase {
        let Some(database) = self.database.as_mut() else {
            panic!("stamp database lease has no database");
        };
        database
    }

    fn finish(mut self) {
        self.return_database();
    }

    fn return_database(&mut self) {
        if let Some(database) = self.database.take() {
            self.state.replace(database);
        }
    }
}

impl Drop for StampDatabaseLease<'_> {
    fn drop(&mut self) {
        self.return_database();
    }
}

impl StampDatabase {
    pub(crate) fn new(project: Arc<RwLock<Project>>) -> Self {
        let revision = project.read().revision();
        let mut stamps = Self {
            storage: Storage::new(None),
            project,
            function_data: Vec::new().into(),
            function_membership: Vec::new().into(),
            mapping_table: Vec::new().into(),
            symbol_table: Vec::new().into(),
            function_range: Vec::new().into(),
            function_range_overflow: Vec::new().into(),
            address_range: Vec::new().into(),
        };

        stamps.function_data = (0..STAMP_BUCKETS)
            .map(|_| FunctionDataStamp::new(&stamps, revision))
            .collect::<Vec<_>>()
            .into();
        stamps.function_membership = (0..STAMP_BUCKETS)
            .map(|_| FunctionMembershipStamp::new(&stamps, revision))
            .collect::<Vec<_>>()
            .into();
        stamps.mapping_table = (0..STAMP_BUCKETS)
            .map(|_| MappingTableStamp::new(&stamps, revision))
            .collect::<Vec<_>>()
            .into();
        stamps.symbol_table = (0..STAMP_BUCKETS)
            .map(|_| SymbolTableStamp::new(&stamps, revision))
            .collect::<Vec<_>>()
            .into();
        stamps.function_range = (0..RANGE_STAMP_BUCKETS)
            .map(|_| FunctionRangeStamp::new(&stamps, revision))
            .collect::<Vec<_>>()
            .into();
        stamps.function_range_overflow =
            [FunctionRangeOverflowStamp::new(&stamps, revision)].into();
        stamps.address_range = (0..RANGE_STAMP_BUCKETS)
            .map(|_| AddressRangeStamp::new(&stamps, revision))
            .collect::<Vec<_>>()
            .into();
        debug_assert_eq!(stamps.stamp_input_count(), STAMP_INPUTS);
        stamps
    }

    fn into_state(self) -> StampDatabaseState {
        let Self {
            storage,
            project,
            function_data,
            function_membership,
            mapping_table,
            symbol_table,
            function_range,
            function_range_overflow,
            address_range,
        } = self;

        StampDatabaseState {
            storage: Some(storage.into_zalsa_handle()),
            project,
            function_data,
            function_membership,
            mapping_table,
            symbol_table,
            function_range,
            function_range_overflow,
            address_range,
        }
    }

    pub(crate) fn stamp_input_count(&self) -> usize {
        self.function_data.len()
            + self.function_membership.len()
            + self.mapping_table.len()
            + self.symbol_table.len()
            + self.function_range.len()
            + self.function_range_overflow.len()
            + self.address_range.len()
    }

    pub(crate) fn apply_changes(&mut self, changes: &ChangeSet) {
        for record in changes.records() {
            self.apply_record(changes.revision(), record);
        }
    }

    pub(crate) fn flow_graph(&self, entry: Address) -> Option<Arc<FlowGraph>> {
        tracked_flow_graph(self, AddressKey::new(self, entry))
    }

    fn apply_record(&mut self, revision: Revision, record: &ChangeRecord) {
        match record {
            ChangeRecord::BytesWritten { space, range } => {
                let written = [CoveredAddressRange::new(*space, range.0, range.1)];
                self.touch_address_ranges(&written, revision);
            }
            ChangeRecord::FunctionAdded { entry, coverage } => {
                let bucket = StampBucket::for_address(*entry);
                self.touch_function_data(bucket, revision);
                self.touch_function_membership(bucket, revision);
                self.touch_function_ranges(coverage.ranges(), revision);
            }
            ChangeRecord::FunctionChanged {
                entry, coverage, ..
            } => {
                self.touch_function_data(StampBucket::for_address(*entry), revision);
                self.touch_function_ranges(coverage.ranges(), revision);
            }
            ChangeRecord::FunctionRemoved { entry, coverage } => {
                let bucket = StampBucket::for_address(*entry);
                self.touch_function_data(bucket, revision);
                self.touch_function_membership(bucket, revision);
                self.touch_function_ranges(coverage.ranges(), revision);
            }
            ChangeRecord::Restored { .. } => {
                self.reset(revision);
            }
            ChangeRecord::SegmentMapped { mapping, .. } => {
                self.touch_mapping_table(StampBucket::for_mapping(*mapping), revision);
            }
            ChangeRecord::SegmentMappingChanged { mapping }
            | ChangeRecord::SegmentMappingCreated { mapping } => {
                self.touch_mapping_table(StampBucket::for_mapping(*mapping), revision);
            }
            ChangeRecord::SegmentUnmapped { mapping, .. } => {
                self.touch_mapping_table(StampBucket::for_mapping(*mapping), revision);
            }
            ChangeRecord::SpaceCreated { .. } => {}
            ChangeRecord::SymbolAdded { address, .. }
            | ChangeRecord::SymbolRemoved { address, .. } => {
                self.touch_symbol_table(StampBucket::for_address(*address), revision);
            }
        }
    }

    fn reset(&mut self, revision: Revision) {
        for bucket in Self::buckets() {
            self.touch_function_data(bucket, revision);
            self.touch_function_membership(bucket, revision);
            self.touch_mapping_table(bucket, revision);
            self.touch_symbol_table(bucket, revision);
        }
        for bucket in Self::range_buckets() {
            self.touch_function_range(bucket, revision);
            self.touch_address_range(bucket, revision);
        }
        self.touch_function_range_overflow(revision);
    }

    fn touch_function_ranges(&mut self, ranges: &[CoveredAddressRange], revision: Revision) {
        match RangeBuckets::covering(ranges) {
            RangeBuckets::Buckets(buckets) => {
                for bucket in buckets {
                    self.touch_function_range(bucket, revision);
                }
            }
            RangeBuckets::Overflow => {
                for bucket in Self::range_buckets() {
                    self.touch_function_range(bucket, revision);
                }
            }
        }
        self.touch_function_range_overflow(revision);
    }

    fn touch_address_ranges(&mut self, ranges: &[CoveredAddressRange], revision: Revision) {
        match RangeBuckets::covering(ranges) {
            RangeBuckets::Buckets(buckets) => {
                for bucket in buckets {
                    self.touch_address_range(bucket, revision);
                }
            }
            RangeBuckets::Overflow => {
                for bucket in Self::range_buckets() {
                    self.touch_address_range(bucket, revision);
                }
            }
        }
    }

    fn touch_function_data(&mut self, bucket: StampBucket, revision: Revision) {
        self.function_data_stamp(bucket)
            .set_revision(self)
            .to(revision);
    }

    fn touch_function_membership(&mut self, bucket: StampBucket, revision: Revision) {
        self.function_membership_stamp(bucket)
            .set_revision(self)
            .to(revision);
    }

    fn touch_mapping_table(&mut self, bucket: StampBucket, revision: Revision) {
        self.mapping_table_stamp(bucket)
            .set_revision(self)
            .to(revision);
    }

    fn touch_symbol_table(&mut self, bucket: StampBucket, revision: Revision) {
        self.symbol_table_stamp(bucket)
            .set_revision(self)
            .to(revision);
    }

    fn touch_function_range(&mut self, bucket: RangeBucket, revision: Revision) {
        self.function_range_stamp(bucket)
            .set_revision(self)
            .to(revision);
    }

    fn touch_function_range_overflow(&mut self, revision: Revision) {
        self.function_range_overflow_stamp()
            .set_revision(self)
            .to(revision);
    }

    fn touch_address_range(&mut self, bucket: RangeBucket, revision: Revision) {
        self.address_range_stamp(bucket)
            .set_revision(self)
            .to(revision);
    }

    fn buckets() -> impl Iterator<Item = StampBucket> {
        (0..STAMP_BUCKETS).map(StampBucket)
    }

    fn range_buckets() -> impl Iterator<Item = RangeBucket> {
        (0..RANGE_STAMP_BUCKETS).map(RangeBucket)
    }

    fn function_data_stamp(&self, bucket: StampBucket) -> FunctionDataStamp {
        self.function_data[bucket.index()]
    }

    fn function_membership_stamp(&self, bucket: StampBucket) -> FunctionMembershipStamp {
        self.function_membership[bucket.index()]
    }

    fn mapping_table_stamp(&self, bucket: StampBucket) -> MappingTableStamp {
        self.mapping_table[bucket.index()]
    }

    fn symbol_table_stamp(&self, bucket: StampBucket) -> SymbolTableStamp {
        self.symbol_table[bucket.index()]
    }

    fn function_range_stamp(&self, bucket: RangeBucket) -> FunctionRangeStamp {
        self.function_range[bucket.index()]
    }

    fn function_range_overflow_stamp(&self) -> FunctionRangeOverflowStamp {
        self.function_range_overflow[0]
    }

    pub(crate) fn address_range_stamp(&self, bucket: RangeBucket) -> AddressRangeStamp {
        self.address_range[bucket.index()]
    }
}

#[salsa::db]
impl QueryDatabase for StampDatabase {
    fn project(&self) -> &Arc<RwLock<Project>> {
        &self.project
    }

    fn function_membership_stamp(&self, bucket: StampBucket) -> FunctionMembershipStamp {
        StampDatabase::function_membership_stamp(self, bucket)
    }

    fn function_range_stamp(&self, bucket: RangeBucket) -> FunctionRangeStamp {
        StampDatabase::function_range_stamp(self, bucket)
    }

    fn function_range_overflow_stamp(&self) -> FunctionRangeOverflowStamp {
        StampDatabase::function_range_overflow_stamp(self)
    }
}

#[salsa::db]
impl Database for StampDatabase {}

#[salsa::tracked]
fn function_membership_revision(
    database: &dyn QueryDatabase,
    stamp: FunctionMembershipStamp,
) -> Revision {
    stamp.revision(database)
}

#[salsa::tracked]
fn function_range_revision(database: &dyn QueryDatabase, stamp: FunctionRangeStamp) -> Revision {
    stamp.revision(database)
}

#[salsa::tracked]
fn function_range_overflow_revision(
    database: &dyn QueryDatabase,
    stamp: FunctionRangeOverflowStamp,
) -> Revision {
    stamp.revision(database)
}

#[salsa::tracked]
fn tracked_flow_graph<'db>(
    database: &'db dyn QueryDatabase,
    key: AddressKey<'db>,
) -> Option<Arc<FlowGraph>> {
    let entry = key.address(database);
    let bucket = StampBucket::for_address(entry);
    let _ = function_membership_revision(database, database.function_membership_stamp(bucket));
    let project = database.project().read();
    let read = ProjectRead::new(&project);
    let function = read.function(entry)?;
    match RangeBuckets::covering(read.function_coverage(&function).ranges()) {
        RangeBuckets::Buckets(buckets) => {
            for bucket in buckets {
                let _ = function_range_revision(database, database.function_range_stamp(bucket));
            }
        }
        RangeBuckets::Overflow => {
            let _ = function_range_overflow_revision(
                database,
                database.function_range_overflow_stamp(),
            );
        }
    }
    Some(read.flow_graph(function))
}
