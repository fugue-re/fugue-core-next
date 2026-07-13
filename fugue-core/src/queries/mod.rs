use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::{ArcRwLockReadGuard, ArcRwLockWriteGuard, Mutex, RwLock};
use thiserror::Error;

use crate::engine::change::{ChangeKinds, ChangeRecord, ChangeSet, Revision};
use crate::ir::cfg::FlowGraph;
use crate::ir::{
    Address, AddressRangeSet, RawAddress, SegmentProperties, Symbol, SymbolEntry, SymbolProperties,
};
use crate::project::Project;
use crate::queries::read::ProjectRead;
use crate::storage::segments::mapping::SegmentMappingId;
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::segments::view::SegmentMappingView;

mod cache;
mod index;
mod read;
#[cfg(test)]
mod tests;

use cache::QueryCache;
use index::ChangeIndex;

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

const WALK_PAGE_LEN: usize = 256;

pub struct Paged<T, F> {
    fetch: F,
    buffer: VecDeque<T>,
    cursor: Option<T>,
    exhausted: bool,
}

impl<T, F> Paged<T, F>
where
    T: Clone,
    F: FnMut(Option<T>) -> Result<QueryPage<T>, QueryError>,
{
    fn new(fetch: F) -> Self {
        Self {
            fetch,
            buffer: VecDeque::new(),
            cursor: None,
            exhausted: false,
        }
    }
}

impl<T, F> Iterator for Paged<T, F>
where
    T: Clone,
    F: FnMut(Option<T>) -> Result<QueryPage<T>, QueryError>,
{
    type Item = Result<T, QueryError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.buffer.pop_front() {
                return Some(Ok(item));
            }

            if self.exhausted {
                return None;
            }

            match (self.fetch)(self.cursor.take()) {
                Ok(page) => {
                    self.buffer.extend(page.entries().iter().cloned());
                    match page.next_cursor() {
                        Some(cursor) => self.cursor = Some(cursor.clone()),
                        None => self.exhausted = true,
                    }
                }
                Err(error) => {
                    self.exhausted = true;
                    return Some(Err(error));
                }
            }
        }
    }
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
    cache: Arc<Mutex<QueryCache>>,
    changes: Arc<Mutex<ChangeIndex>>,
}

impl QueryReader {
    pub(crate) fn new(
        active: Arc<AtomicBool>,
        gate: Arc<RwLock<()>>,
        project: Arc<RwLock<Project>>,
        cache: Arc<Mutex<QueryCache>>,
        changes: Arc<Mutex<ChangeIndex>>,
    ) -> Self {
        Self {
            active,
            gate,
            project,
            cache,
            changes,
        }
    }

    pub fn revision(&self) -> Result<Revision, QueryError> {
        self.with_project(|read| read.project().revision())
    }

    pub fn latest_change(
        &self,
        kinds: ChangeKinds,
        region: &AddressRangeSet,
    ) -> Result<Revision, QueryError> {
        let _query_guard = self.enter_query()?;
        Ok(self.changes.lock().latest_change(kinds, region))
    }

    pub fn changed_since(
        &self,
        since: Revision,
        kinds: ChangeKinds,
        region: &AddressRangeSet,
    ) -> Result<bool, QueryError> {
        let _query_guard = self.enter_query()?;
        Ok(self.changes.lock().changed_since(since, kinds, region))
    }

    pub fn flow_graph(&self, entry: Address) -> Result<Option<Arc<FlowGraph>>, QueryError> {
        let _query_guard = self.enter_query()?;

        if let Some(cached) = self.cache.lock().get(entry) {
            return Ok(cached);
        }

        let graph = {
            let project = self.project.read();
            let read = ProjectRead::new(&project);
            read.function(entry)
                .map(|function| read.flow_graph(function))
        };

        self.cache.lock().insert(entry, graph.clone());
        Ok(graph)
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

    pub fn functions(
        &self,
        space: AddressSpaceId,
    ) -> impl Iterator<Item = Result<Address, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor: Option<Address>| {
            reader.function_page(
                space,
                cursor.map(|address| address.raw_address()),
                WALK_PAGE_LEN,
            )
        })
    }

    pub fn symbols(&self) -> impl Iterator<Item = Result<SymbolRecord, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.symbol_page(cursor, WALK_PAGE_LEN))
    }

    pub fn symbols_at_address(
        &self,
        address: Address,
    ) -> impl Iterator<Item = Result<SymbolRecord, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.symbols_at(address, cursor, WALK_PAGE_LEN))
    }

    pub fn mappings(
        &self,
        space: AddressSpaceId,
    ) -> impl Iterator<Item = Result<MappingRecord, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.mapping_page(space, cursor, WALK_PAGE_LEN))
    }

    pub fn edges(&self) -> impl Iterator<Item = Result<CallEdge, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.call_edges(cursor, WALK_PAGE_LEN))
    }

    pub fn callers(&self, entry: Address) -> impl Iterator<Item = Result<Address, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.callers_of(entry, cursor, WALK_PAGE_LEN))
    }

    pub fn callees(&self, entry: Address) -> impl Iterator<Item = Result<Address, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.callees_of(entry, cursor, WALK_PAGE_LEN))
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
    cache: Arc<Mutex<QueryCache>>,
    changes: Arc<Mutex<ChangeIndex>>,
}

impl QueryEngine {
    pub(crate) fn new(project: Arc<RwLock<Project>>) -> Self {
        let revision = project.read().revision();
        Self {
            active: Arc::new(AtomicBool::new(true)),
            gate: Arc::new(RwLock::new(())),
            project,
            cache: Arc::new(Mutex::new(QueryCache::new())),
            changes: Arc::new(Mutex::new(ChangeIndex::new(revision))),
        }
    }

    pub(crate) fn reader(&self) -> QueryReader {
        QueryReader::new(
            self.active.clone(),
            self.gate.clone(),
            self.project.clone(),
            self.cache.clone(),
            self.changes.clone(),
        )
    }

    pub(crate) fn write_guard(&self) -> QueryWriteGuard {
        self.gate.write_arc()
    }

    pub(crate) fn apply_changes(&mut self, changes: &ChangeSet) {
        self.changes.lock().apply(changes);

        let mut cache = self.cache.lock();
        for record in changes.records() {
            match record {
                ChangeRecord::FunctionAdded { entry, .. }
                | ChangeRecord::FunctionChanged { entry, .. }
                | ChangeRecord::FunctionRemoved { entry, .. } => cache.evict(*entry),
                ChangeRecord::Restored { .. } => cache.clear(),
                _ => {}
            }
        }
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
