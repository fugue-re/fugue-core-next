use std::sync::Arc;

use parking_lot::RwLock;
use salsa::{Database, Setter, Storage};

use super::{CallEdge, MappingRecord, QueryPage, SymbolRecord};
use crate::engine::change::{ChangeRecord, ChangeSet, Revision};
use crate::ir::Address;
use crate::ir::cfg::FlowGraph;
use crate::project::Project;
use crate::queries::read::ProjectRead;
use crate::storage::segments::space::AddressSpaceId;

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

#[salsa::interned]
struct AddressKey<'db> {
    address: Address,
}

#[salsa::interned]
struct AddressPageKey<'db> {
    entry: Address,
    after: Option<Address>,
    limit: usize,
}

#[salsa::interned]
struct CallEdgePageKey<'db> {
    after: Option<CallEdge>,
    limit: usize,
}

#[salsa::interned]
struct FunctionPageKey<'db> {
    after: Option<Address>,
    limit: usize,
}

#[salsa::interned]
struct MappingPageKey<'db> {
    space: AddressSpaceId,
    after: Option<MappingRecord>,
    limit: usize,
}

#[salsa::interned]
struct SymbolPageKey<'db> {
    after: Option<SymbolRecord>,
    limit: usize,
}

#[salsa::interned]
struct SymbolsAtKey<'db> {
    address: Address,
    after: Option<SymbolRecord>,
    limit: usize,
}

#[salsa::db]
pub(crate) trait QueryDatabase: Database {
    fn project(&self) -> &Arc<RwLock<Project>>;
    fn function_data_stamp(&self) -> FunctionDataStamp;
    fn function_membership_stamp(&self) -> FunctionMembershipStamp;
    fn mapping_table_stamp(&self) -> MappingTableStamp;
    fn symbol_table_stamp(&self) -> SymbolTableStamp;
}

#[salsa::db]
#[derive(Clone)]
pub(crate) struct StampDatabase {
    storage: Storage<Self>,
    project: Arc<RwLock<Project>>,
    function_data: Option<FunctionDataStamp>,
    function_membership: Option<FunctionMembershipStamp>,
    mapping_table: Option<MappingTableStamp>,
    symbol_table: Option<SymbolTableStamp>,
}

impl StampDatabase {
    pub(crate) fn new(project: Arc<RwLock<Project>>) -> Self {
        let revision = project.read().revision();
        let mut stamps = Self {
            storage: Storage::new(None),
            project,
            function_data: None,
            function_membership: None,
            mapping_table: None,
            symbol_table: None,
        };

        stamps.function_data = Some(FunctionDataStamp::new(&stamps, revision));
        stamps.function_membership = Some(FunctionMembershipStamp::new(&stamps, revision));
        stamps.mapping_table = Some(MappingTableStamp::new(&stamps, revision));
        stamps.symbol_table = Some(SymbolTableStamp::new(&stamps, revision));
        stamps
    }

    pub(crate) fn apply_changes(&mut self, changes: &ChangeSet) {
        for record in changes.records() {
            self.apply_record(changes.revision(), record);
        }
    }

    pub(crate) fn revision(&self) -> Revision {
        self.project.read().revision()
    }

    pub(crate) fn flow_graph(&self, entry: Address) -> Option<Arc<FlowGraph>> {
        tracked_flow_graph(self, AddressKey::new(self, entry))
    }

    pub(crate) fn call_edges(&self, after: Option<CallEdge>, limit: usize) -> QueryPage<CallEdge> {
        tracked_call_edges(self, CallEdgePageKey::new(self, after, limit))
    }

    pub(crate) fn callees_of(
        &self,
        entry: Address,
        after: Option<Address>,
        limit: usize,
    ) -> QueryPage<Address> {
        tracked_callees_of(self, AddressPageKey::new(self, entry, after, limit))
    }

    pub(crate) fn callers_of(
        &self,
        entry: Address,
        after: Option<Address>,
        limit: usize,
    ) -> QueryPage<Address> {
        tracked_callers_of(self, AddressPageKey::new(self, entry, after, limit))
    }

    pub(crate) fn function_page(&self, after: Option<Address>, limit: usize) -> QueryPage<Address> {
        tracked_function_page(self, FunctionPageKey::new(self, after, limit))
    }

    pub(crate) fn mapping_page(
        &self,
        space: AddressSpaceId,
        after: Option<MappingRecord>,
        limit: usize,
    ) -> QueryPage<MappingRecord> {
        tracked_mapping_page(self, MappingPageKey::new(self, space, after, limit))
    }

    pub(crate) fn symbol_page(
        &self,
        after: Option<SymbolRecord>,
        limit: usize,
    ) -> QueryPage<SymbolRecord> {
        tracked_symbol_page(self, SymbolPageKey::new(self, after, limit))
    }

    pub(crate) fn symbols_at(
        &self,
        address: Address,
        after: Option<SymbolRecord>,
        limit: usize,
    ) -> QueryPage<SymbolRecord> {
        tracked_symbols_at(self, SymbolsAtKey::new(self, address, after, limit))
    }

    fn apply_record(&mut self, revision: Revision, record: &ChangeRecord) {
        match record {
            ChangeRecord::BytesWritten { .. } => {}
            ChangeRecord::FunctionAdded { .. } => {
                self.touch_function_data(revision);
                self.touch_function_membership(revision);
            }
            ChangeRecord::FunctionChanged { .. } => {
                self.touch_function_data(revision);
            }
            ChangeRecord::FunctionRemoved { .. } => {
                self.touch_function_data(revision);
                self.touch_function_membership(revision);
            }
            ChangeRecord::Restored { .. } => {
                self.reset(revision);
            }
            ChangeRecord::SegmentMapped { .. } => {
                self.touch_mapping_table(revision);
            }
            ChangeRecord::SegmentMappingChanged { .. }
            | ChangeRecord::SegmentMappingCreated { .. } => {
                self.touch_mapping_table(revision);
            }
            ChangeRecord::SegmentUnmapped { .. } => {
                self.touch_mapping_table(revision);
            }
            ChangeRecord::SpaceCreated { .. } => {}
            ChangeRecord::SymbolAdded { .. } | ChangeRecord::SymbolRemoved { .. } => {
                self.touch_symbol_table(revision);
            }
        }
    }

    fn reset(&mut self, revision: Revision) {
        self.touch_function_data(revision);
        self.touch_function_membership(revision);
        self.touch_mapping_table(revision);
        self.touch_symbol_table(revision);
    }

    fn touch_function_data(&mut self, revision: Revision) {
        self.function_data_stamp().set_revision(self).to(revision);
    }

    fn touch_function_membership(&mut self, revision: Revision) {
        self.function_membership_stamp()
            .set_revision(self)
            .to(revision);
    }

    fn touch_mapping_table(&mut self, revision: Revision) {
        self.mapping_table_stamp().set_revision(self).to(revision);
    }

    fn touch_symbol_table(&mut self, revision: Revision) {
        self.symbol_table_stamp().set_revision(self).to(revision);
    }

    fn function_data_stamp(&self) -> FunctionDataStamp {
        match self.function_data {
            Some(stamp) => stamp,
            None => unreachable!("function data stamp must be initialised"),
        }
    }

    fn function_membership_stamp(&self) -> FunctionMembershipStamp {
        match self.function_membership {
            Some(stamp) => stamp,
            None => unreachable!("function membership stamp must be initialised"),
        }
    }

    fn mapping_table_stamp(&self) -> MappingTableStamp {
        match self.mapping_table {
            Some(stamp) => stamp,
            None => unreachable!("mapping table stamp must be initialised"),
        }
    }

    fn symbol_table_stamp(&self) -> SymbolTableStamp {
        match self.symbol_table {
            Some(stamp) => stamp,
            None => unreachable!("symbol table stamp must be initialised"),
        }
    }
}

#[salsa::db]
impl QueryDatabase for StampDatabase {
    fn project(&self) -> &Arc<RwLock<Project>> {
        &self.project
    }

    fn function_data_stamp(&self) -> FunctionDataStamp {
        StampDatabase::function_data_stamp(self)
    }

    fn function_membership_stamp(&self) -> FunctionMembershipStamp {
        StampDatabase::function_membership_stamp(self)
    }

    fn mapping_table_stamp(&self) -> MappingTableStamp {
        StampDatabase::mapping_table_stamp(self)
    }

    fn symbol_table_stamp(&self) -> SymbolTableStamp {
        StampDatabase::symbol_table_stamp(self)
    }
}

#[salsa::db]
impl Database for StampDatabase {}

#[salsa::tracked]
fn function_data_revision(database: &dyn QueryDatabase, stamp: FunctionDataStamp) -> Revision {
    stamp.revision(database)
}

#[salsa::tracked]
fn function_membership_revision(
    database: &dyn QueryDatabase,
    stamp: FunctionMembershipStamp,
) -> Revision {
    stamp.revision(database)
}

#[salsa::tracked]
fn mapping_table_revision(database: &dyn QueryDatabase, stamp: MappingTableStamp) -> Revision {
    stamp.revision(database)
}

#[salsa::tracked]
fn symbol_table_revision(database: &dyn QueryDatabase, stamp: SymbolTableStamp) -> Revision {
    stamp.revision(database)
}

#[salsa::tracked]
fn tracked_flow_graph<'db>(
    database: &'db dyn QueryDatabase,
    key: AddressKey<'db>,
) -> Option<Arc<FlowGraph>> {
    let _ = function_data_revision(database, database.function_data_stamp());
    let _ = function_membership_revision(database, database.function_membership_stamp());
    let project = database.project().read();
    let read = ProjectRead::new(&project);
    read.function(key.address(database))
        .map(|function| read.flow_graph(function))
}

#[salsa::tracked]
fn tracked_call_edges<'db>(
    database: &'db dyn QueryDatabase,
    key: CallEdgePageKey<'db>,
) -> QueryPage<CallEdge> {
    let _ = function_data_revision(database, database.function_data_stamp());
    let _ = function_membership_revision(database, database.function_membership_stamp());
    let project = database.project().read();
    ProjectRead::new(&project).call_edges(key.after(database), key.limit(database))
}

#[salsa::tracked]
fn tracked_callees_of<'db>(
    database: &'db dyn QueryDatabase,
    key: AddressPageKey<'db>,
) -> QueryPage<Address> {
    let _ = function_data_revision(database, database.function_data_stamp());
    let _ = function_membership_revision(database, database.function_membership_stamp());
    let project = database.project().read();
    let read = ProjectRead::new(&project);
    read.function(key.entry(database))
        .map(|function| {
            read.function_callee_page(function, key.after(database), key.limit(database))
        })
        .unwrap_or_else(|| QueryPage::new(Vec::new(), None))
}

#[salsa::tracked]
fn tracked_callers_of<'db>(
    database: &'db dyn QueryDatabase,
    key: AddressPageKey<'db>,
) -> QueryPage<Address> {
    let _ = function_data_revision(database, database.function_data_stamp());
    let _ = function_membership_revision(database, database.function_membership_stamp());
    let project = database.project().read();
    ProjectRead::new(&project).callers_of(
        key.entry(database),
        key.after(database),
        key.limit(database),
    )
}

#[salsa::tracked]
fn tracked_function_page<'db>(
    database: &'db dyn QueryDatabase,
    key: FunctionPageKey<'db>,
) -> QueryPage<Address> {
    let _ = function_membership_revision(database, database.function_membership_stamp());
    let project = database.project().read();
    ProjectRead::new(&project).function_page(key.after(database), key.limit(database))
}

#[salsa::tracked]
fn tracked_mapping_page<'db>(
    database: &'db dyn QueryDatabase,
    key: MappingPageKey<'db>,
) -> QueryPage<MappingRecord> {
    let _ = mapping_table_revision(database, database.mapping_table_stamp());
    let project = database.project().read();
    ProjectRead::new(&project).mapping_page(
        key.space(database),
        key.after(database),
        key.limit(database),
    )
}

#[salsa::tracked]
fn tracked_symbol_page<'db>(
    database: &'db dyn QueryDatabase,
    key: SymbolPageKey<'db>,
) -> QueryPage<SymbolRecord> {
    let _ = symbol_table_revision(database, database.symbol_table_stamp());
    let project = database.project().read();
    ProjectRead::new(&project).symbol_page(key.after(database), key.limit(database))
}

#[salsa::tracked]
fn tracked_symbols_at<'db>(
    database: &'db dyn QueryDatabase,
    key: SymbolsAtKey<'db>,
) -> QueryPage<SymbolRecord> {
    let _ = symbol_table_revision(database, database.symbol_table_stamp());
    let project = database.project().read();
    ProjectRead::new(&project).symbols_at(
        key.address(database),
        key.after(database),
        key.limit(database),
    )
}
