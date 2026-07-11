use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::{Mutex, RwLock};
use thiserror::Error;

use crate::engine::change::{ChangeSet, Revision};
use crate::ir::cfg::FlowGraph;
use crate::ir::{Address, SegmentProperties, Symbol, SymbolEntry, SymbolProperties};
use crate::project::Project;
use crate::storage::segments::mapping::SegmentMappingId;
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::segments::view::SegmentMappingView;

mod read;
mod stamps;
#[cfg(test)]
mod tests;

use stamps::StampDatabase;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

#[derive(Clone)]
pub struct QueryReader {
    active: Arc<AtomicBool>,
    gate: Arc<RwLock<()>>,
    stamps: Arc<Mutex<StampDatabase>>,
}

impl QueryReader {
    pub(crate) fn new(
        active: Arc<AtomicBool>,
        gate: Arc<RwLock<()>>,
        stamps: Arc<Mutex<StampDatabase>>,
    ) -> Self {
        Self {
            active,
            gate,
            stamps,
        }
    }

    pub fn revision(&self) -> Result<Revision, QueryError> {
        self.with_database(|database| database.revision())
    }

    pub fn flow_graph(&self, entry: Address) -> Result<Option<Arc<FlowGraph>>, QueryError> {
        self.with_database(|database| database.flow_graph(entry))
    }

    pub fn call_edges(
        &self,
        after: Option<CallEdge>,
        limit: usize,
    ) -> Result<QueryPage<CallEdge>, QueryError> {
        self.with_database(|database| database.call_edges(after, limit))
    }

    pub fn callees_of(
        &self,
        entry: Address,
        after: Option<Address>,
        limit: usize,
    ) -> Result<QueryPage<Address>, QueryError> {
        self.with_database(|database| database.callees_of(entry, after, limit))
    }

    pub fn function_page(
        &self,
        after: Option<Address>,
        limit: usize,
    ) -> Result<QueryPage<Address>, QueryError> {
        self.with_database(|database| database.function_page(after, limit))
    }

    pub fn callers_of(
        &self,
        entry: Address,
        after: Option<Address>,
        limit: usize,
    ) -> Result<QueryPage<Address>, QueryError> {
        self.with_database(|database| database.callers_of(entry, after, limit))
    }

    pub fn mapping_page(
        &self,
        space: AddressSpaceId,
        after: Option<MappingRecord>,
        limit: usize,
    ) -> Result<QueryPage<MappingRecord>, QueryError> {
        self.with_database(|database| database.mapping_page(space, after, limit))
    }

    pub fn symbol_page(
        &self,
        after: Option<SymbolRecord>,
        limit: usize,
    ) -> Result<QueryPage<SymbolRecord>, QueryError> {
        self.with_database(|database| database.symbol_page(after, limit))
    }

    pub fn symbols_at(
        &self,
        address: Address,
        after: Option<SymbolRecord>,
        limit: usize,
    ) -> Result<QueryPage<SymbolRecord>, QueryError> {
        self.with_database(|database| database.symbols_at(address, after, limit))
    }

    fn with_database<T>(&self, query: impl FnOnce(&StampDatabase) -> T) -> Result<T, QueryError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(QueryError::Stopped);
        }

        let _read = self.gate.read();
        if !self.active.load(Ordering::Acquire) {
            return Err(QueryError::Stopped);
        }

        let database = self.stamps.lock().clone();
        Ok(query(&database))
    }
}

pub(crate) struct QueryEngine {
    active: Arc<AtomicBool>,
    gate: Arc<RwLock<()>>,
    stamps: Arc<Mutex<StampDatabase>>,
}

impl QueryEngine {
    pub(crate) fn new(project: Arc<RwLock<Project>>) -> Self {
        Self {
            active: Arc::new(AtomicBool::new(true)),
            gate: Arc::new(RwLock::new(())),
            stamps: Arc::new(Mutex::new(StampDatabase::new(project))),
        }
    }

    pub(crate) fn reader(&self) -> QueryReader {
        QueryReader::new(self.active.clone(), self.gate.clone(), self.stamps.clone())
    }

    pub(crate) fn apply_changes(&mut self, changes: &ChangeSet) {
        let _write = self.gate.write();
        self.stamps.lock().apply_changes(changes);
    }
}

impl Drop for QueryEngine {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}
