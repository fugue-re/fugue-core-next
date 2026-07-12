use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::{ArcRwLockReadGuard, ArcRwLockWriteGuard, Mutex, RwLock};
use thiserror::Error;

use crate::engine::change::{ChangeSet, Revision};
use crate::ir::cfg::FlowGraph;
use crate::ir::{Address, RawAddress, SegmentProperties, Symbol, SymbolEntry, SymbolProperties};
use crate::project::Project;
use crate::queries::read::ProjectRead;
use crate::storage::segments::mapping::SegmentMappingId;
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::segments::view::SegmentMappingView;

mod read;
mod stamps;
#[cfg(test)]
mod tests;

use stamps::{StampDatabase, StampDatabaseState};

const MAX_QUERY_PAGE_LEN: usize = 4096;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryPage<T> {
    entries: Arc<[T]>,
    next_cursor: Option<T>,
}

impl<T> QueryPage<T> {
    pub fn new(entries: impl Into<Arc<[T]>>, next_cursor: Option<T>) -> Self {
        Self {
            entries: entries.into(),
            next_cursor,
        }
    }

    pub fn entries(&self) -> &[T] {
        &self.entries
    }

    pub fn next_cursor(&self) -> Option<&T> {
        self.next_cursor.as_ref()
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum QueryError {
    #[error("analysis engine stopped")]
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallEdge {
    caller: Address,
    callee: Address,
}

impl CallEdge {
    pub fn new(caller: impl Into<Address>, callee: impl Into<Address>) -> Self {
        Self {
            caller: caller.into(),
            callee: callee.into(),
        }
    }

    pub fn caller(&self) -> Address {
        self.caller
    }

    pub fn callee(&self) -> Address {
        self.callee
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolRecord {
    address: Address,
    properties: SymbolProperties,
    symbol: Symbol,
}

impl SymbolRecord {
    pub fn new(
        address: impl Into<Address>,
        symbol: impl Into<Symbol>,
        properties: SymbolProperties,
    ) -> Self {
        Self {
            address: address.into(),
            properties,
            symbol: symbol.into(),
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn properties(&self) -> SymbolProperties {
        self.properties
    }

    pub fn symbol(&self) -> Symbol {
        self.symbol
    }

    fn from_entry(entry: &SymbolEntry) -> Self {
        Self::new(entry.address(), entry.symbol(), entry.properties())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MappingRecord {
    mapping: SegmentMappingId,
    start: Address,
    size: u64,
    properties: SegmentProperties,
}

impl MappingRecord {
    pub fn new(
        mapping: SegmentMappingId,
        start: impl Into<Address>,
        size: u64,
        properties: SegmentProperties,
    ) -> Self {
        Self {
            mapping,
            start: start.into(),
            size,
            properties,
        }
    }

    pub fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }

    pub fn start(&self) -> Address {
        self.start
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn properties(&self) -> SegmentProperties {
        self.properties
    }

    fn from_view(view: &SegmentMappingView<'_>) -> Self {
        Self::new(
            view.mapping_ref().mapping_id(),
            view.start(),
            view.size(),
            view.properties(),
        )
    }
}

impl PartialOrd for MappingRecord {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MappingRecord {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.start
            .cmp(&other.start)
            .then_with(|| self.mapping.cmp(&other.mapping))
            .then_with(|| self.size.cmp(&other.size))
            .then_with(|| self.properties.cmp(&other.properties))
    }
}

#[derive(Clone)]
pub struct QueryReader {
    active: Arc<AtomicBool>,
    gate: Arc<RwLock<()>>,
    project: Arc<RwLock<Project>>,
    stamps: Arc<Mutex<StampDatabaseState>>,
}

impl QueryReader {
    pub(crate) fn new(
        active: Arc<AtomicBool>,
        gate: Arc<RwLock<()>>,
        project: Arc<RwLock<Project>>,
        stamps: Arc<Mutex<StampDatabaseState>>,
    ) -> Self {
        Self {
            active,
            gate,
            project,
            stamps,
        }
    }

    pub fn revision(&self) -> Result<Revision, QueryError> {
        self.with_project(|read| read.project().revision())
    }

    pub fn flow_graph(&self, entry: Address) -> Result<Option<Arc<FlowGraph>>, QueryError> {
        self.with_database(|database| database.flow_graph(entry))
    }

    pub fn call_edges(
        &self,
        after: Option<CallEdge>,
        limit: usize,
    ) -> Result<QueryPage<CallEdge>, QueryError> {
        self.with_project(|read| read.call_edges(after, limit))
    }

    pub fn callees_of(
        &self,
        entry: Address,
        after: Option<Address>,
        limit: usize,
    ) -> Result<QueryPage<Address>, QueryError> {
        self.with_project(|read| read.callees_of(entry, after, limit))
    }

    pub fn function_page(
        &self,
        space: AddressSpaceId,
        after: Option<RawAddress>,
        limit: usize,
    ) -> Result<QueryPage<Address>, QueryError> {
        self.with_project(|read| read.function_page(space, after, limit))
    }

    pub fn callers_of(
        &self,
        entry: Address,
        after: Option<Address>,
        limit: usize,
    ) -> Result<QueryPage<Address>, QueryError> {
        self.with_project(|read| read.callers_of(entry, after, limit))
    }

    pub fn mapping_page(
        &self,
        space: AddressSpaceId,
        after: Option<MappingRecord>,
        limit: usize,
    ) -> Result<QueryPage<MappingRecord>, QueryError> {
        self.with_project(|read| read.mapping_page(space, after, limit))
    }

    pub fn symbol_page(
        &self,
        after: Option<SymbolRecord>,
        limit: usize,
    ) -> Result<QueryPage<SymbolRecord>, QueryError> {
        self.with_project(|read| read.symbol_page(after, limit))
    }

    pub fn symbols_at(
        &self,
        address: Address,
        after: Option<SymbolRecord>,
        limit: usize,
    ) -> Result<QueryPage<SymbolRecord>, QueryError> {
        self.with_project(|read| read.symbols_at(address, after, limit))
    }

    fn with_database<T>(&self, query: impl FnOnce(&StampDatabase) -> T) -> Result<T, QueryError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(QueryError::Stopped);
        }

        let _query_guard = self.enter_query()?;

        let database = self.stamps.lock().worker();
        Ok(query(&database))
    }

    fn with_project<T>(&self, query: impl FnOnce(ProjectRead<'_>) -> T) -> Result<T, QueryError> {
        let _query_guard = self.enter_query()?;
        let project = self.project.read();
        Ok(query(ProjectRead::new(&project)))
    }

    fn enter_query(&self) -> Result<ArcRwLockReadGuard<parking_lot::RawRwLock, ()>, QueryError> {
        let guard = self.gate.read_arc();
        if self.active.load(Ordering::Acquire) {
            Ok(guard)
        } else {
            Err(QueryError::Stopped)
        }
    }
}

pub(crate) struct QueryEngine {
    active: Arc<AtomicBool>,
    gate: Arc<RwLock<()>>,
    project: Arc<RwLock<Project>>,
    stamps: Arc<Mutex<StampDatabaseState>>,
}

impl QueryEngine {
    pub(crate) fn new(project: Arc<RwLock<Project>>) -> Self {
        Self {
            active: Arc::new(AtomicBool::new(true)),
            gate: Arc::new(RwLock::new(())),
            project: project.clone(),
            stamps: Arc::new(Mutex::new(StampDatabaseState::new(project))),
        }
    }

    pub(crate) fn reader(&self) -> QueryReader {
        QueryReader::new(
            self.active.clone(),
            self.gate.clone(),
            self.project.clone(),
            self.stamps.clone(),
        )
    }

    pub(crate) fn write_guard(&self) -> QueryWriteGuard {
        self.gate.write_arc()
    }

    pub(crate) fn apply_changes(&mut self, changes: &ChangeSet) {
        self.stamps.lock().apply_changes(changes);
    }

    pub(crate) fn mark_dead(&self) {
        self.active.store(false, Ordering::Release);
    }
}

impl Drop for QueryEngine {
    fn drop(&mut self) {
        self.mark_dead();
    }
}

pub(crate) type QueryWriteGuard = ArcRwLockWriteGuard<parking_lot::RawRwLock, ()>;
