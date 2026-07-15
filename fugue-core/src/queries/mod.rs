use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use flume::Sender;
use parking_lot::{ArcRwLockReadGuard, ArcRwLockWriteGuard, RwLock};
use thiserror::Error;

use crate::engine::change::{ChangeKinds, ChangeRecord, ChangeSet, Revision};
use crate::engine::{EngineError, Intake};
use crate::il::common::{IlError, IrArtefact, IrArtefactKey, IrLevel, RawIrArtefact};
use crate::il::llil::LlilBody;
use crate::il::llil::ssa::{Dominance, DominanceFrontier, Liveness, SsaBody, UseIndex};
use crate::il::pcode::PCodeBody;
use crate::ir::cfg::FlowGraph;
use crate::ir::{
    Address, AddressRangeSet, FunctionId, RawAddress, Reference, ReferenceTarget,
    SegmentProperties, Symbol, SymbolEntry, SymbolProperties,
};
use crate::project::{Project, ProjectError};
use crate::queries::read::ProjectRead;
use crate::storage::segments::mapping::SegmentMappingId;
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::segments::view::SegmentMappingView;

mod cache;
mod derived;
mod index;
mod read;

use cache::QueryCache;
pub use derived::{Cached, Dependency};
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

#[derive(Debug, Error)]
pub enum QueryError {
    #[error("analysis engine stopped")]
    Stopped,
    #[error(transparent)]
    Project(#[from] ProjectError),
    #[error(transparent)]
    Engine(Box<EngineError>),
}

impl From<EngineError> for QueryError {
    fn from(error: EngineError) -> Self {
        match error {
            EngineError::Stopped => Self::Stopped,
            EngineError::Project(error) => Self::Project(error),
            error => Self::Engine(Box::new(error)),
        }
    }
}

impl PartialEq for QueryError {
    fn eq(&self, other: &Self) -> bool {
        matches!((self, other), (Self::Stopped, Self::Stopped))
    }
}

impl Eq for QueryError {}

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
    cache: Arc<QueryCache>,
    changes: Arc<RwLock<ChangeIndex>>,
    intake: Option<Sender<Intake>>,
}

impl QueryReader {
    pub(crate) fn new(
        active: Arc<AtomicBool>,
        gate: Arc<RwLock<()>>,
        project: Arc<RwLock<Project>>,
        cache: Arc<QueryCache>,
        changes: Arc<RwLock<ChangeIndex>>,
    ) -> Self {
        Self {
            active,
            gate,
            project,
            cache,
            changes,
            intake: None,
        }
    }

    pub(crate) fn with_intake(mut self, intake: Sender<Intake>) -> Self {
        self.intake = Some(intake);
        self
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
        Ok(self.changes.read().latest_change(kinds, region))
    }

    pub fn changed_since(
        &self,
        since: Revision,
        kinds: ChangeKinds,
        region: &AddressRangeSet,
    ) -> Result<bool, QueryError> {
        let _query_guard = self.enter_query()?;
        Ok(self.changes.read().changed_since(since, kinds, region))
    }

    pub fn flow_graph(&self, entry: Address) -> Result<Option<Arc<FlowGraph>>, QueryError> {
        let _query_guard = self.enter_query()?;

        if let Some(cached) = self.cache.get(entry) {
            return Ok(cached);
        }

        let graph = {
            let project = self.project.read();
            let read = ProjectRead::new(&project);
            read.function(entry)
                .map(|function| read.flow_graph(function))
        };

        self.cache.insert(entry, graph.clone());
        Ok(graph)
    }

    fn cached_ir_artefact(
        &self,
        function: FunctionId,
        level: IrLevel,
    ) -> Result<Option<Arc<RawIrArtefact>>, QueryError> {
        let _query_guard = self.enter_query()?;
        let key = IrArtefactKey::new(function, level);

        if let Some(cached) = self.cache.get_ir(key) {
            return Ok(cached);
        }

        let artefact = {
            let project = self.project.read();
            let read = ProjectRead::new(&project);
            read.ir_artefact(function, level)?
        }
        .map(Arc::new);

        self.cache.insert_ir(key, artefact.clone());
        Ok(artefact)
    }

    fn cached_body<T>(&self, function: FunctionId) -> Result<Option<T>, QueryError>
    where
        T: IrArtefact,
    {
        if let Some(raw) = self.cached_ir_artefact(function, T::LEVEL)? {
            return Self::decode_body(&raw).map(Some);
        }

        if !self.build_ir(function, T::LEVEL)? {
            return Ok(None);
        }

        self.cached_ir_artefact(function, T::LEVEL)?
            .map(|raw| Self::decode_body(&raw))
            .transpose()
    }

    fn decode_body<T>(raw: &RawIrArtefact) -> Result<T, QueryError>
    where
        T: IrArtefact,
    {
        T::from_raw_artefact(raw.clone())
            .map_err(ProjectError::from)
            .map_err(QueryError::from)
    }

    fn build_ir(&self, function: FunctionId, level: IrLevel) -> Result<bool, QueryError> {
        let Some(intake) = &self.intake else {
            return Ok(false);
        };

        let (reply_tx, reply_rx) = flume::bounded(1);
        intake
            .send(Intake::EnsureIr {
                function,
                level,
                reply: reply_tx,
            })
            .map_err(|_| QueryError::Stopped)?;

        match reply_rx.recv().map_err(|_| QueryError::Stopped)? {
            Ok(_) => Ok(true),
            Err(EngineError::Project(ProjectError::Il(IlError::MissingArtefact { .. }))) => {
                Ok(false)
            }
            Err(error) => Err(QueryError::from(error)),
        }
    }

    pub fn ir_artefact(
        &self,
        function: FunctionId,
        level: IrLevel,
    ) -> Result<Option<RawIrArtefact>, QueryError> {
        Ok(self
            .cached_ir_artefact(function, level)?
            .map(|raw| (*raw).clone()))
    }

    pub fn ir_body<T>(&self, function: FunctionId) -> Result<Option<T>, QueryError>
    where
        T: IrArtefact,
    {
        self.cached_body(function)
    }

    pub fn pcode_body(&self, function: FunctionId) -> Result<Option<PCodeBody>, QueryError> {
        self.cached_body(function)
    }

    pub fn llil_body(&self, function: FunctionId) -> Result<Option<LlilBody>, QueryError> {
        self.cached_body(function)
    }

    pub fn llil_ssa_body(&self, function: FunctionId) -> Result<Option<SsaBody>, QueryError> {
        self.cached_body(function)
    }

    pub fn llil_ssa_use_index(&self, function: FunctionId) -> Result<Option<UseIndex>, QueryError> {
        self.cached_body::<SsaBody>(function)?
            .map(|body| body.use_index())
            .transpose()
            .map_err(ProjectError::from)
            .map_err(QueryError::from)
    }

    pub fn llil_ssa_dominance(
        &self,
        function: FunctionId,
    ) -> Result<Option<Dominance>, QueryError> {
        self.cached_body::<SsaBody>(function)?
            .map(|body| body.dominance())
            .transpose()
            .map_err(ProjectError::from)
            .map_err(QueryError::from)
    }

    pub fn llil_ssa_dominance_frontiers(
        &self,
        function: FunctionId,
    ) -> Result<Option<DominanceFrontier>, QueryError> {
        self.cached_body::<SsaBody>(function)?
            .map(|body| body.dominance_frontiers())
            .transpose()
            .map_err(ProjectError::from)
            .map_err(QueryError::from)
    }

    pub fn llil_ssa_liveness(&self, function: FunctionId) -> Result<Option<Liveness>, QueryError> {
        self.cached_body::<SsaBody>(function)?
            .map(|body| body.liveness())
            .transpose()
            .map_err(ProjectError::from)
            .map_err(QueryError::from)
    }

    pub fn function_id(&self, entry: Address) -> Result<Option<FunctionId>, QueryError> {
        self.with_project(|read| read.function_id(entry))
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

    pub fn references_from(
        &self,
        from: Address,
        after: Option<Reference>,
        limit: usize,
    ) -> Result<QueryPage<Reference>, QueryError> {
        self.with_project(|read| read.references_from(from, after, limit))
    }

    pub fn references_to(
        &self,
        to: Address,
        after: Option<Reference>,
        limit: usize,
    ) -> Result<QueryPage<Reference>, QueryError> {
        self.with_project(|read| read.references_to(ReferenceTarget::from(to), after, limit))
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

    pub fn outgoing_references(
        &self,
        from: Address,
    ) -> impl Iterator<Item = Result<Reference, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.references_from(from, cursor, WALK_PAGE_LEN))
    }

    pub fn incoming_references(
        &self,
        to: Address,
    ) -> impl Iterator<Item = Result<Reference, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.references_to(to, cursor, WALK_PAGE_LEN))
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
    cache: Arc<QueryCache>,
    changes: Arc<RwLock<ChangeIndex>>,
}

impl QueryEngine {
    pub(crate) fn new(project: Arc<RwLock<Project>>) -> Self {
        let revision = project.read().revision();
        Self {
            active: Arc::new(AtomicBool::new(true)),
            gate: Arc::new(RwLock::new(())),
            project,
            cache: Arc::new(QueryCache::new()),
            changes: Arc::new(RwLock::new(ChangeIndex::new(revision))),
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
        self.changes.write().apply(changes);

        for record in changes.records() {
            match record {
                ChangeRecord::FunctionAdded { entry, .. }
                | ChangeRecord::FunctionChanged { entry, .. }
                | ChangeRecord::FunctionRemoved { entry, .. } => {
                    self.cache.evict(*entry);
                }
                ChangeRecord::IrArtefactPublished { function, level }
                | ChangeRecord::IrArtefactRemoved { function, level } => {
                    self.cache.evict_ir(*function, *level);
                }
                ChangeRecord::Restored { .. } => self.cache.clear(),
                _ => {}
            }

            if record.affects_ir_inputs() {
                self.cache.clear_ir();
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

#[cfg(test)]
mod test {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use parking_lot::RwLock;

    use super::{Cached, Dependency, QueryEngine, QueryError, QueryPage, QueryReader};
    use crate::analysis::function::recovery::{PartialCodeBlock, PartialFunction};
    use crate::engine::change::{
        ChangeKinds, ChangeRecord, ChangeSet, FunctionChangeKind, Revision,
    };
    use crate::il::common::{
        ArtefactHeader, BlockId, BuildStatus, CommonBody, Finish, IlError, IrArtefact,
        IrArtefactKey, IrLevel, PackedRange, RawIrArtefact, SourceRun, ValueId,
    };
    use crate::il::llil::ssa::{LLIL_SSA_SCHEMA_VERSION, SsaBody, SsaBuilder};
    use crate::il::llil::{LLIL_SCHEMA_VERSION, LlilBody, LlilBuilder};
    use crate::il::pcode::{PCODE_SCHEMA_VERSION, PCodeBody, PCodeBuilder};
    use crate::ir::{
        Address, AddressRange, AddressRangeSet, FunctionId, RawAddress, ReferenceKind,
        ReferenceTarget,
    };
    use crate::loader::Loader;
    use crate::project::{Project, ProjectError};
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
            self.commit_function_with_id(function).map(drop)
        }

        fn commit_function_with_id(
            &mut self,
            function: PartialFunction,
        ) -> Result<FunctionId, Box<dyn std::error::Error>> {
            let (changes, function) = {
                let mut project = self.project.write();
                let mut transaction = project.transaction("query fixture");
                let function = transaction.add_function(function)?;
                (transaction.commit()?, function)
            };
            self.queries.apply_changes(&changes);
            Ok(function)
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

        fn publish_ir_artefact(
            &mut self,
            artefact: RawIrArtefact,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let changes = {
                let mut project = self.project.write();
                let mut transaction = project.transaction("query fixture");
                if let Err(error) = transaction.publish_ir_artefact(artefact) {
                    transaction.rollback()?;
                    return Err(error.into());
                }
                transaction.commit()?
            };
            self.queries.apply_changes(&changes);
            Ok(())
        }

        fn publish_ir_body<T>(&mut self, artefact: &mut T) -> Result<(), Box<dyn std::error::Error>>
        where
            T: IrArtefact,
        {
            let changes = {
                let mut project = self.project.write();
                let mut transaction = project.transaction("query fixture");
                if let Err(error) = transaction.publish_ir_body(artefact) {
                    transaction.rollback()?;
                    return Err(error.into());
                }
                transaction.commit()?
            };
            self.queries.apply_changes(&changes);
            Ok(())
        }

        fn insert_ir_artefact_direct(
            &mut self,
            artefact: &RawIrArtefact,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let project = self.project.write();
            let key = IrArtefactKey::new(artefact.header().function(), artefact.header().level());

            project.storage.entities.insert(&key, artefact)?;
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

        fn ir_artefact(payload: Vec<u8>) -> RawIrArtefact {
            let tag = payload.first().copied().unwrap_or_default();
            let header = ArtefactHeader::new(
                FunctionId::default(),
                IrLevel::PCode,
                PCODE_SCHEMA_VERSION,
                0,
            );
            let common = CommonBody::new(
                Vec::new(),
                Vec::new(),
                vec![SourceRun::new(
                    PackedRange::EMPTY,
                    Address::new(AddressSpaceId::new(1), u64::from(tag)),
                    u32::from(tag),
                    u32::try_from(payload.len()).expect("test payload length should fit"),
                )],
                Vec::new(),
            );

            PCodeBuilder::new(header, common)
                .finish(&BuildStatus::new())
                .expect("test PCode artefact should verify")
                .to_raw_artefact()
                .expect("test PCode artefact should encode")
        }

        fn pcode_body_for(function: FunctionId) -> PCodeBody {
            let header = ArtefactHeader::new(function, IrLevel::PCode, PCODE_SCHEMA_VERSION, 0);

            PCodeBuilder::new(header, CommonBody::default())
                .finish(&BuildStatus::new())
                .expect("empty PCode body should verify")
        }

        fn pcode_body() -> PCodeBody {
            Self::pcode_body_for(FunctionId::default())
        }

        fn llil_body(function: FunctionId, parent: &PCodeBody) -> LlilBody {
            let mut header = ArtefactHeader::new(function, IrLevel::Llil, LLIL_SCHEMA_VERSION, 0);
            header.set_parent_digest(
                parent
                    .to_raw_artefact()
                    .expect("test PCode body should encode")
                    .header()
                    .content_digest(),
            );

            LlilBuilder::new(header, CommonBody::default())
                .finish(&BuildStatus::new())
                .expect("empty LLIL body should verify")
        }

        fn ssa_body(function: FunctionId, parent: &LlilBody) -> SsaBody {
            let mut header =
                ArtefactHeader::new(function, IrLevel::LlilSsa, LLIL_SSA_SCHEMA_VERSION, 0);
            header.set_parent_digest(
                parent
                    .to_raw_artefact()
                    .expect("test LLIL body should encode")
                    .header()
                    .content_digest(),
            );

            SsaBuilder::new(header, CommonBody::default())
                .finish(&BuildStatus::new())
                .expect("empty SSA body should verify")
        }

        fn publish_ssa_chain(
            &mut self,
            function: FunctionId,
        ) -> Result<SsaBody, Box<dyn std::error::Error>> {
            let mut pcode = Self::pcode_body_for(function);
            let mut llil = Self::llil_body(function, &pcode);
            let mut ssa = Self::ssa_body(function, &llil);

            self.publish_ir_body(&mut pcode)?;
            self.publish_ir_body(&mut llil)?;
            self.publish_ir_body(&mut ssa)?;

            Ok(ssa)
        }
    }

    #[test]
    fn test_query_reader_reads_ir_artefact() -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = Fixture::new()?;
        let artefact = Fixture::ir_artefact(vec![7, 8, 9]);

        fixture.publish_ir_artefact(artefact.clone())?;

        let read = fixture
            .reader()
            .ir_artefact(FunctionId::default(), IrLevel::PCode)?
            .expect("artefact should be visible to query reader");

        assert_eq!(read.payload(), artefact.payload());
        Ok(())
    }

    #[test]
    fn test_query_reader_memoises_ir_reads() -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = Fixture::new()?;
        let entry = Address::from(0x1_0000_0000u64);
        let function = fixture.commit_function_with_id(Fixture::function_at(entry))?;
        let mut body = Fixture::pcode_body_for(function);
        fixture.publish_ir_body(&mut body)?;
        fixture.queries.cache.clear_ir();

        let reader = fixture.reader();
        assert_eq!(fixture.queries.cache.ir_len(), 0);

        reader
            .pcode_body(function)?
            .expect("PCode body should be visible");
        assert_eq!(fixture.queries.cache.ir_len(), 1);

        reader
            .ir_artefact(function, IrLevel::PCode)?
            .expect("cached artefact should be visible");
        assert_eq!(fixture.queries.cache.ir_len(), 1);

        fixture.commit_function(Fixture::function_with_len(entry, 2))?;
        assert_eq!(fixture.queries.cache.ir_len(), 0);

        Ok(())
    }

    #[test]
    fn test_query_reader_ir_artefact_snapshot_survives_invalidation()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = Fixture::new()?;
        let entry = Address::from(0x1_0000_0000u64);
        let function = fixture.commit_function_with_id(Fixture::function_at(entry))?;
        let mut body = Fixture::pcode_body_for(function);
        let artefact = body.to_raw_artefact()?;

        fixture.publish_ir_body(&mut body)?;

        let reader = fixture.reader();
        let snapshot = reader
            .ir_artefact(function, IrLevel::PCode)?
            .expect("PCode artefact should be visible to query reader");

        fixture.commit_function(Fixture::function_with_len(entry, 2))?;

        assert!(reader.ir_artefact(function, IrLevel::PCode)?.is_none());
        assert_eq!(snapshot.content_digest(), artefact.content_digest());
        assert_eq!(snapshot.payload(), artefact.payload());

        Ok(())
    }

    #[test]
    fn test_query_reader_reads_typed_ir_body() -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = Fixture::new()?;
        let mut body = Fixture::pcode_body();

        fixture.publish_ir_body(&mut body)?;

        let read = fixture
            .reader()
            .ir_body::<PCodeBody>(FunctionId::default())?
            .expect("PCode body should be visible to query reader");
        let named = fixture
            .reader()
            .pcode_body(FunctionId::default())?
            .expect("PCode body should be visible to named query reader");

        assert_eq!(read.to_raw_artefact()?, body.to_raw_artefact()?);
        assert_eq!(named.to_raw_artefact()?, body.to_raw_artefact()?);
        Ok(())
    }

    #[test]
    fn test_query_reader_recovers_after_corrupt_ir_artefact()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = Fixture::new()?;
        let function = FunctionId::default();
        let pcode = Fixture::pcode_body_for(function);
        let llil = Fixture::llil_body(function, &pcode);
        let ssa = Fixture::ssa_body(function, &llil);
        let valid = [
            pcode.to_raw_artefact()?,
            llil.to_raw_artefact()?,
            ssa.to_raw_artefact()?,
        ];

        let reader = fixture.reader();
        for artefact in valid {
            let level = artefact.header().level();
            let mut header = ArtefactHeader::new(function, level, artefact.header().schema(), 0);
            header.set_parent_digest(artefact.header().parent_digest());
            let corrupt = RawIrArtefact::new(header, CommonBody::default(), vec![1, 2, 3]);

            fixture.insert_ir_artefact_direct(&corrupt)?;

            assert!(matches!(
                reader.ir_artefact(function, level),
                Err(QueryError::Project(ProjectError::Il(
                    IlError::ArtefactDecode { level: found }
                ))) if found == level
            ));

            fixture.insert_ir_artefact_direct(&artefact)?;

            let read = reader
                .ir_artefact(function, level)?
                .expect("valid artefact should be readable after corrupt artefact");

            assert_eq!(read.content_digest(), artefact.content_digest());
        }

        Ok(())
    }

    #[test]
    fn test_query_reader_reads_ssa_derived_tables() -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = Fixture::new()?;
        let function = FunctionId::default();

        fixture.publish_ssa_chain(function)?;

        let reader = fixture.reader();
        let use_index = reader
            .llil_ssa_use_index(function)?
            .expect("SSA use index should be available");
        let dominance = reader
            .llil_ssa_dominance(function)?
            .expect("SSA dominance should be available");
        let frontiers = reader
            .llil_ssa_dominance_frontiers(function)?
            .expect("SSA dominance frontiers should be available");
        let liveness = reader
            .llil_ssa_liveness(function)?
            .expect("SSA liveness should be available");

        let value = ValueId::try_from_index(0)?;
        let block = BlockId::try_from_index(0)?;

        assert!(use_index.uses_for(value).is_empty());
        assert!(!dominance.is_reachable(block));
        assert!(frontiers.frontier(block).is_empty());
        assert!(liveness.live_in(block).is_empty());
        assert!(liveness.live_out(block).is_empty());
        Ok(())
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
    fn test_function_removal_invalidates_cached_flow_graph()
    -> Result<(), Box<dyn std::error::Error>> {
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
    fn test_cached_recomputes_only_on_dependency_change() -> Result<(), Box<dyn std::error::Error>>
    {
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
                kind: FunctionChangeKind::Body,
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
}
