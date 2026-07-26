use std::cmp::Ordering as CmpOrdering;
use std::collections::VecDeque;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use flume::Sender;
use parking_lot::{ArcRwLockReadGuard, ArcRwLockWriteGuard, RawRwLock, RwLock};
use thiserror::Error;

use crate::engine::change::{ChangeKinds, ChangeRecord, ChangeSet, Revision};
use crate::engine::{EngineError, Intake};
use crate::il::common::{IlError, IlLevel};
use crate::il::ecode::ECodeIr;
use crate::il::ecode::ssa::ECodeSsaIr;
use crate::il::pcode::PCodeIr;
use crate::ir::cfg::FlowTargets;
use crate::ir::{
    Address, AddressRangeSet, FunctionId, RawAddress, Reference, ReferenceTarget,
    SegmentProperties, Switch, Symbol, SymbolEntry, SymbolProperties,
};
use crate::project::{Project, ProjectError};
use crate::queries::read::ProjectRead;
use crate::storage::segments::mapping::SegmentMappingId;
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::segments::view::SegmentMappingView;
use crate::types::Confidence;

mod cache;
mod cached;
mod index;
mod read;

use cache::{QueryCache, QueryCachedIl};
pub use cached::{Cached, Dependency};
use index::ChangeIndex;

const MAX_QUERY_PAGE_COUNT: usize = 4096;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryPage<T, C = T> {
    entries: Arc<[T]>,
    next_cursor: Option<C>,
}

impl<T, C> QueryPage<T, C> {
    pub fn new(entries: impl Into<Arc<[T]>>, next_cursor: Option<C>) -> Self {
        Self {
            entries: entries.into(),
            next_cursor,
        }
    }

    pub fn entries(&self) -> &[T] {
        &self.entries
    }

    pub fn next_cursor(&self) -> Option<&C> {
        self.next_cursor.as_ref()
    }
}

#[derive(Debug, Error)]
pub enum QueryError {
    #[error(transparent)]
    Engine(Box<EngineError>),
    #[error(transparent)]
    Project(#[from] ProjectError),
    #[error("analysis engine stopped")]
    Stopped,
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

const WALK_PAGE_COUNT: usize = 256;

pub struct Paged<T, F, C = T> {
    fetch: F,
    buffer: VecDeque<T>,
    cursor: Option<C>,
    exhausted: bool,
}

impl<T, F, C> Paged<T, F, C>
where
    T: Clone,
    C: Clone,
    F: FnMut(Option<C>) -> Result<QueryPage<T, C>, QueryError>,
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

impl<T, F, C> Iterator for Paged<T, F, C>
where
    T: Clone,
    C: Clone,
    F: FnMut(Option<C>) -> Result<QueryPage<T, C>, QueryError>,
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
    source: Address,
    target: Address,
}

impl CallEdge {
    pub fn new(source: impl Into<Address>, target: impl Into<Address>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
        }
    }

    pub fn source(&self) -> Address {
        self.source
    }

    pub fn target(&self) -> Address {
        self.target
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolRow {
    address: Address,
    properties: SymbolProperties,
    symbol: Symbol,
}

impl SymbolRow {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchRow {
    switch: Switch,
}

impl SwitchRow {
    pub fn branch(&self) -> Address {
        self.switch.branch()
    }

    pub fn switch(&self) -> &Switch {
        &self.switch
    }

    pub fn case_count(&self) -> usize {
        self.switch.case_count()
    }

    pub fn has_default(&self) -> bool {
        self.switch.has_default()
    }

    pub fn confidence(&self) -> Confidence {
        self.switch.confidence()
    }
}

impl From<&Switch> for SwitchRow {
    fn from(switch: &Switch) -> Self {
        Self {
            switch: switch.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MappingRow {
    mapping: SegmentMappingId,
    start: Address,
    size: u64,
    properties: SegmentProperties,
}

impl MappingRow {
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

impl PartialOrd for MappingRow {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl Ord for MappingRow {
    fn cmp(&self, other: &Self) -> CmpOrdering {
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
    fn new(
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

    pub fn flow_targets(&self, entry: Address) -> Result<Option<Arc<FlowTargets>>, QueryError> {
        let _query_guard = self.enter_query()?;

        if let Some(cached) = self.cache.flow_targets(entry) {
            return Ok(cached);
        }

        let targets = {
            let project = self.project.read();
            let read = ProjectRead::new(&project);
            read.function(entry)
                .map(|function| read.flow_targets(function))
        };

        self.cache.insert_flow_targets(entry, targets.clone());
        Ok(targets)
    }

    pub fn pcode(&self, function: FunctionId) -> Result<Option<Arc<PCodeIr>>, QueryError> {
        if let Some(cached) = self.cached_il::<PCodeIr>(function)? {
            return Ok(Some(cached));
        }

        if !self.ensure_lifted(function, IlLevel::PCode)? {
            return Ok(None);
        }

        self.cached_il::<PCodeIr>(function)
    }

    pub fn ecode(&self, function: FunctionId) -> Result<Option<Arc<ECodeIr>>, QueryError> {
        if let Some(cached) = self.cached_il::<ECodeIr>(function)? {
            return Ok(Some(cached));
        }

        if !self.ensure_lifted(function, IlLevel::ECode)? {
            return Ok(None);
        }

        self.cached_il::<ECodeIr>(function)
    }

    pub fn ecode_ssa(&self, function: FunctionId) -> Result<Option<Arc<ECodeSsaIr>>, QueryError> {
        if let Some(cached) = self.cached_il::<ECodeSsaIr>(function)? {
            return Ok(Some(cached));
        }

        if !self.ensure_lifted(function, IlLevel::ECodeSsa)? {
            return Ok(None);
        }

        self.cached_il::<ECodeSsaIr>(function)
    }

    fn cached_il<T>(&self, function: FunctionId) -> Result<Option<Arc<T>>, QueryError>
    where
        T: QueryCachedIl,
    {
        let _query_guard = self.enter_query()?;

        if let Some(cached) = T::cached(&self.cache, function) {
            return Ok(cached);
        }

        let ir = { self.project.read().lifted::<T>(function)? }.map(Arc::new);
        T::insert_cached(&self.cache, function, ir.clone());
        Ok(ir)
    }

    fn ensure_lifted(&self, function: FunctionId, level: IlLevel) -> Result<bool, QueryError> {
        let Some(intake) = &self.intake else {
            return Ok(false);
        };

        let (reply_tx, reply_rx) = flume::bounded(1);
        intake
            .send(Intake::EnsureLifted {
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

    pub fn project(&self) -> Result<ProjectHandle, QueryError> {
        let gate = self.enter_query()?;

        Ok(ProjectHandle {
            project: self.project.read_arc(),
            _gate: gate,
        })
    }

    pub fn call_edge_page(
        &self,
        after: Option<CallEdge>,
        limit: usize,
    ) -> Result<QueryPage<CallEdge>, QueryError> {
        self.with_project(|read| read.call_edge_page(after, limit))
    }

    pub fn callee_page(
        &self,
        entry: Address,
        after: Option<Address>,
        limit: usize,
    ) -> Result<QueryPage<Address>, QueryError> {
        self.with_project(|read| read.callee_page(entry, after, limit))
    }

    pub fn function_id_at(&self, entry: Address) -> Result<Option<FunctionId>, QueryError> {
        self.with_project(|read| read.function(entry).map(|function| function.id()))
    }

    pub fn function_page(
        &self,
        space: AddressSpaceId,
        after: Option<RawAddress>,
        limit: usize,
    ) -> Result<QueryPage<Address>, QueryError> {
        self.with_project(|read| read.function_page(space, after, limit))
    }

    pub fn caller_page(
        &self,
        entry: Address,
        after: Option<Address>,
        limit: usize,
    ) -> Result<QueryPage<Address>, QueryError> {
        self.with_project(|read| read.caller_page(entry, after, limit))
    }

    pub fn outgoing_reference_page(
        &self,
        from: Address,
        after: Option<Reference>,
        limit: usize,
    ) -> Result<QueryPage<Reference>, QueryError> {
        self.with_project(|read| read.outgoing_reference_page(from, after, limit))
    }

    pub fn incoming_reference_page(
        &self,
        to: Address,
        after: Option<Reference>,
        limit: usize,
    ) -> Result<QueryPage<Reference>, QueryError> {
        self.with_project(|read| {
            read.incoming_reference_page(ReferenceTarget::from(to), after, limit)
        })
    }

    pub fn mapping_page(
        &self,
        space: AddressSpaceId,
        after: Option<MappingRow>,
        limit: usize,
    ) -> Result<QueryPage<MappingRow>, QueryError> {
        self.with_project(|read| read.mapping_page(space, after, limit))
    }

    pub fn symbol_page(
        &self,
        after: Option<SymbolRow>,
        limit: usize,
    ) -> Result<QueryPage<SymbolRow>, QueryError> {
        self.with_project(|read| read.symbol_page(after, limit))
    }

    pub fn symbol_page_at(
        &self,
        address: Address,
        after: Option<SymbolRow>,
        limit: usize,
    ) -> Result<QueryPage<SymbolRow>, QueryError> {
        self.with_project(|read| read.symbol_page_at(address, after, limit))
    }

    pub fn switch_at(&self, branch: Address) -> Result<Option<SwitchRow>, QueryError> {
        self.with_project(|read| read.switch_at(branch))
    }

    pub fn switch_page(
        &self,
        after: Option<Address>,
        limit: usize,
    ) -> Result<QueryPage<SwitchRow, Address>, QueryError> {
        self.with_project(|read| read.switch_page(after, limit))
    }

    pub fn switches(&self) -> impl Iterator<Item = Result<SwitchRow, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.switch_page(cursor, WALK_PAGE_COUNT))
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
                WALK_PAGE_COUNT,
            )
        })
    }

    pub fn symbols(&self) -> impl Iterator<Item = Result<SymbolRow, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.symbol_page(cursor, WALK_PAGE_COUNT))
    }

    pub fn mappings(
        &self,
        space: AddressSpaceId,
    ) -> impl Iterator<Item = Result<MappingRow, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.mapping_page(space, cursor, WALK_PAGE_COUNT))
    }

    pub fn call_edges(&self) -> impl Iterator<Item = Result<CallEdge, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.call_edge_page(cursor, WALK_PAGE_COUNT))
    }

    pub fn callers(&self, entry: Address) -> impl Iterator<Item = Result<Address, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.caller_page(entry, cursor, WALK_PAGE_COUNT))
    }

    pub fn callees(&self, entry: Address) -> impl Iterator<Item = Result<Address, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.callee_page(entry, cursor, WALK_PAGE_COUNT))
    }

    pub fn outgoing_references(
        &self,
        from: Address,
    ) -> impl Iterator<Item = Result<Reference, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.outgoing_reference_page(from, cursor, WALK_PAGE_COUNT))
    }

    pub fn incoming_references(
        &self,
        to: Address,
    ) -> impl Iterator<Item = Result<Reference, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.incoming_reference_page(to, cursor, WALK_PAGE_COUNT))
    }

    fn with_project<T>(&self, query: impl FnOnce(ProjectRead<'_>) -> T) -> Result<T, QueryError> {
        let _query_guard = self.enter_query()?;
        let project = self.project.read();
        Ok(query(ProjectRead::new(&project)))
    }

    fn enter_query(&self) -> Result<ArcRwLockReadGuard<RawRwLock, ()>, QueryError> {
        let guard = self.gate.read_arc();
        if self.active.load(Ordering::Acquire) {
            Ok(guard)
        } else {
            Err(QueryError::Stopped)
        }
    }
}

pub struct ProjectHandle {
    project: ArcRwLockReadGuard<RawRwLock, Project>,
    _gate: ArcRwLockReadGuard<RawRwLock, ()>,
}

impl Deref for ProjectHandle {
    type Target = Project;

    fn deref(&self) -> &Project {
        &self.project
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
                    self.cache.evict_flow_targets(*entry);
                }
                ChangeRecord::LiftedMaterialised { function, level }
                | ChangeRecord::LiftedRemoved { function, level } => {
                    self.cache.evict_lifted(*function, *level);
                }
                ChangeRecord::Restored { .. } => self.cache.clear(),
                _ => {}
            }

            if record.affects_lifted_inputs() {
                self.cache.clear_lifted();
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

pub(crate) type QueryWriteGuard = ArcRwLockWriteGuard<RawRwLock, ()>;

#[cfg(test)]
mod test {
    use std::error::Error;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use parking_lot::RwLock;

    use super::*;
    use crate::analysis::control::CancellationToken;
    use crate::engine::change::FunctionChangeKind;
    use crate::il::common::{
        IlArtefact, IlBlockId, IlDominance, IlGraph, IlIndexRange, IlMetadata, IlSourceSpan,
        IlValueId,
    };
    use crate::il::ecode::ssa::{
        ECODE_SSA_SCHEMA_VERSION, ECodeSsaBuilder, ECodeSsaLiveness, ECodeSsaUses,
    };
    use crate::il::ecode::{ECODE_SCHEMA_VERSION, ECodeBuilder};
    use crate::il::pcode::{PCODE_SCHEMA_VERSION, PCodeBuilder};
    use crate::il::storage::IlRevert;
    use crate::ir::{AddressRange, IncompleteCodeBlock, IncompleteFunction, ReferenceKind};
    use crate::loader::Loader;
    use crate::project::ProjectTransaction;
    use crate::queries::index::{ChangeIndex, MAX_CHANGE_RUNS};

    #[test]
    fn test_query_page_exposes_entries_and_next_cursor() {
        let page = QueryPage::new([1, 2, 3], Some(3));

        assert_eq!(page.entries(), &[1, 2, 3]);
        assert_eq!(page.next_cursor(), Some(&3));
    }

    struct PublishedIl {
        pcode: PCodeIr,
        ecode: ECodeIr,
        ecode_ssa: ECodeSsaIr,
    }

    struct Fixture {
        project: Arc<RwLock<Project>>,
        queries: QueryEngine,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn Error>> {
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

        fn commit_with<T>(
            &mut self,
            mutate: impl FnOnce(&mut ProjectTransaction<'_>) -> Result<T, ProjectError>,
        ) -> Result<T, Box<dyn Error>> {
            let (changes, value) = {
                let mut project = self.project.write();
                let mut transaction = project.transaction("query fixture");
                let value = match mutate(&mut transaction) {
                    Ok(value) => value,
                    Err(error) => {
                        transaction.rollback()?;
                        return Err(error.into());
                    }
                };
                (transaction.commit()?, value)
            };
            self.queries.apply_changes(&changes);
            Ok(value)
        }

        fn commit_function(&mut self, function: IncompleteFunction) -> Result<(), Box<dyn Error>> {
            self.commit_function_with_id(function).map(drop)
        }

        fn commit_function_with_id(
            &mut self,
            function: IncompleteFunction,
        ) -> Result<FunctionId, Box<dyn Error>> {
            self.commit_with(|transaction| transaction.add_function(function))
        }

        fn remove_function(&mut self, entry: Address) -> Result<(), Box<dyn Error>> {
            self.commit_with(|transaction| transaction.remove_function(entry))
                .map(drop)
        }

        fn materialise_lifted<T>(&mut self, ir: &mut T) -> Result<(), Box<dyn Error>>
        where
            T: IlArtefact,
            IlRevert: From<(FunctionId, Option<T>)>,
        {
            self.commit_with(|transaction| transaction.materialise_lifted(ir))
        }

        fn apply(&mut self, changes: &ChangeSet) {
            self.queries.apply_changes(changes);
        }

        fn function_at(entry: Address) -> IncompleteFunction {
            Self::function_with_len(entry, 1)
        }

        fn function_with_len(entry: Address, len: usize) -> IncompleteFunction {
            let mut function = IncompleteFunction::new(entry);
            function.push_block(
                IncompleteCodeBlock::try_new(entry, len, Vec::new(), Default::default())
                    .expect("test block length must be valid"),
            );
            function
        }

        fn pcode_with_span(&self, function: FunctionId, tag: u8, count: u32) -> PCodeIr {
            let mut builder = PCodeBuilder::new(
                self.project.read().language(),
                IlMetadata::new(function, PCODE_SCHEMA_VERSION, 0),
                IlGraph::default(),
            );

            builder.set_source_spans(vec![IlSourceSpan::new(
                IlIndexRange::EMPTY,
                Address::new(AddressSpaceId::new(1), u64::from(tag)),
                u32::from(tag),
                count,
            )]);

            builder
                .build(&CancellationToken::default())
                .expect("test pcode ir should build")
        }

        fn pcode_for(&self, function: FunctionId) -> PCodeIr {
            PCodeBuilder::new(
                self.project.read().language(),
                IlMetadata::new(function, PCODE_SCHEMA_VERSION, 0),
                IlGraph::default(),
            )
            .build(&CancellationToken::default())
            .expect("empty pcode ir should build")
        }

        fn ecode_for(function: FunctionId) -> ECodeIr {
            ECodeBuilder::new(
                IlMetadata::new(function, ECODE_SCHEMA_VERSION, 0),
                IlGraph::default(),
            )
            .build(&CancellationToken::default())
            .expect("empty ecode ir should build")
        }

        fn ecode_ssa_for(function: FunctionId) -> ECodeSsaIr {
            ECodeSsaBuilder::new(
                IlMetadata::new(function, ECODE_SSA_SCHEMA_VERSION, 0),
                IlGraph::default(),
            )
            .build(&CancellationToken::default())
            .expect("empty ecode ssa ir should build")
        }

        fn materialise_lifted_chain(
            &mut self,
            function: FunctionId,
        ) -> Result<PublishedIl, Box<dyn Error>> {
            let mut pcode = self.pcode_for(function);
            let mut ecode = Self::ecode_for(function);
            let mut ecode_ssa = Self::ecode_ssa_for(function);

            self.materialise_lifted(&mut pcode)?;
            self.materialise_lifted(&mut ecode)?;
            self.materialise_lifted(&mut ecode_ssa)?;

            Ok(PublishedIl {
                pcode,
                ecode,
                ecode_ssa,
            })
        }
    }

    #[test]
    fn test_query_reader_reads_materialised_pcode() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        let mut ir = fixture.pcode_with_span(FunctionId::default(), 7, 3);

        fixture.materialise_lifted(&mut ir)?;

        let read = fixture
            .reader()
            .pcode(FunctionId::default())?
            .expect("pcode should be visible to query reader");

        assert_eq!(read.source_spans(), ir.source_spans());
        Ok(())
    }

    #[test]
    fn test_query_reader_memoises_lifted_reads() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        let entry = Address::from(0x1_0000_0000u64);
        let function = fixture.commit_function_with_id(Fixture::function_at(entry))?;
        let mut ir = fixture.pcode_for(function);
        fixture.materialise_lifted(&mut ir)?;
        fixture.queries.cache.clear_lifted();

        let reader = fixture.reader();
        let first = reader.pcode(function)?.expect("pcode should be visible");
        let second = reader
            .pcode(function)?
            .expect("cached pcode should be visible");
        assert!(Arc::ptr_eq(&first, &second));

        fixture.commit_function(Fixture::function_with_len(entry, 2))?;
        assert!(reader.pcode(function)?.is_none());

        Ok(())
    }

    #[test]
    fn test_query_reader_lifted_snapshot_survives_invalidation() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        let entry = Address::from(0x1_0000_0000u64);
        let function = fixture.commit_function_with_id(Fixture::function_at(entry))?;
        let mut ir = fixture.pcode_for(function);

        fixture.materialise_lifted(&mut ir)?;

        let reader = fixture.reader();
        let snapshot = reader
            .pcode(function)?
            .expect("pcode should be visible to query reader");

        fixture.commit_function(Fixture::function_with_len(entry, 2))?;

        assert!(reader.pcode(function)?.is_none());
        assert_eq!(snapshot.as_ref(), &ir);

        Ok(())
    }

    #[test]
    fn test_query_reader_reads_all_lifted_levels() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        let function = FunctionId::default();

        let materialised = fixture.materialise_lifted_chain(function)?;

        let reader = fixture.reader();
        let pcode = reader
            .pcode(function)?
            .expect("pcode should be visible to query reader");
        let ecode = reader
            .ecode(function)?
            .expect("ecode should be visible to query reader");
        let ecode_ssa = reader
            .ecode_ssa(function)?
            .expect("ecode ssa should be visible to query reader");

        assert_eq!(pcode.as_ref(), &materialised.pcode);
        assert_eq!(ecode.as_ref(), &materialised.ecode);
        assert_eq!(ecode_ssa.as_ref(), &materialised.ecode_ssa);
        Ok(())
    }

    #[test]
    fn test_query_reader_reads_ssa_derived_tables() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        let function = FunctionId::default();

        fixture.materialise_lifted_chain(function)?;

        let reader = fixture.reader();
        let ir = reader
            .ecode_ssa(function)?
            .expect("ssa ir should be available");
        let uses = ir.analyse::<ECodeSsaUses>();
        let dominance = ir.analyse::<IlDominance>();
        let frontiers = dominance.frontiers(ir.graph().blocks(), ir.graph().successors());
        let liveness = ir.analyse::<ECodeSsaLiveness>();

        let value = IlValueId::try_from_index(0)?;
        let block = IlBlockId::try_from_index(0)?;

        assert!(uses.uses_for(value).is_empty());
        assert!(!dominance.is_reachable(block));
        assert!(frontiers.frontier_for(block).is_empty());
        assert!(liveness.live_in(block).is_empty());
        assert!(liveness.live_out(block).is_empty());
        Ok(())
    }

    #[test]
    fn test_flow_graph_cache_is_exact_per_function() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        let edited = Address::from(0x1_0000_0000u64);
        let same_window = Address::new(edited.space(), edited.offset() + 0x10);
        let distant = Address::from(0x9_0000_0000u64);

        fixture.commit_function(Fixture::function_at(edited))?;
        fixture.commit_function(Fixture::function_at(same_window))?;
        fixture.commit_function(Fixture::function_at(distant))?;

        let reader = fixture.reader();
        let edited_before = reader.flow_targets(edited)?.ok_or("edited missing")?;
        let neighbour_before = reader
            .flow_targets(same_window)?
            .ok_or("neighbour missing")?;
        let distant_before = reader.flow_targets(distant)?.ok_or("distant missing")?;

        fixture.commit_function(Fixture::function_with_len(edited, 2))?;

        let edited_after = reader.flow_targets(edited)?.ok_or("edited missing after")?;
        let neighbour_after = reader
            .flow_targets(same_window)?
            .ok_or("neighbour missing after")?;
        let distant_after = reader
            .flow_targets(distant)?
            .ok_or("distant missing after")?;

        assert!(!Arc::ptr_eq(&edited_before, &edited_after));
        assert!(Arc::ptr_eq(&neighbour_before, &neighbour_after));
        assert!(Arc::ptr_eq(&distant_before, &distant_after));

        Ok(())
    }

    #[test]
    fn test_flow_graph_cache_invalidation_property() -> Result<(), Box<dyn Error>> {
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
                .map(|entry| Ok(reader.flow_targets(*entry)?.ok_or("function missing")?))
                .collect::<Result<Vec<_>, Box<dyn Error>>>()?;

            fixture.commit_function(Fixture::function_with_len(
                entries[edited_index],
                2 + edited_index,
            ))?;

            for (index, entry) in entries.iter().enumerate() {
                let after = reader
                    .flow_targets(*entry)?
                    .ok_or("function missing after")?;
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
    fn test_function_removal_invalidates_cached_flow_graph() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        let entry = Address::from(0x1_0000_0000u64);

        fixture.commit_function(Fixture::function_at(entry))?;

        let reader = fixture.reader();
        assert!(reader.flow_targets(entry)?.is_some());

        fixture.remove_function(entry)?;

        assert!(reader.flow_targets(entry)?.is_none());

        Ok(())
    }

    #[test]
    fn test_function_add_invalidates_cached_absence() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        let entry = Address::from(0x1_0000_0000u64);

        let reader = fixture.reader();
        assert!(reader.flow_targets(entry)?.is_none());
        assert!(reader.flow_targets(entry)?.is_none());

        fixture.commit_function(Fixture::function_at(entry))?;

        assert!(reader.flow_targets(entry)?.is_some());

        Ok(())
    }

    #[test]
    fn test_byte_write_leaves_flow_graph_cached() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        let entry = Address::from(0x1_0000_0000u64);

        fixture.commit_function(Fixture::function_at(entry))?;

        let reader = fixture.reader();
        let before = reader.flow_targets(entry)?.ok_or("function missing")?;

        let revision = fixture.next_revision();
        fixture.apply(&ChangeSet::with_records(
            revision,
            [ChangeRecord::BytesWritten {
                range: AddressRange::new(entry.space(), entry.raw_address(), entry.raw_address()),
            }],
        ));

        let after = reader
            .flow_targets(entry)?
            .ok_or("function missing after write")?;

        assert!(Arc::ptr_eq(&before, &after));

        Ok(())
    }

    #[test]
    fn test_cache_is_pure_derived_state() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        let entry = Address::from(0x1_0000_0000u64);

        fixture.commit_function(Fixture::function_with_len(entry, 4))?;

        let reader = fixture.reader();
        let before = reader.flow_targets(entry)?.ok_or("function missing")?;

        fixture.queries.cache.clear();

        let after = reader
            .flow_targets(entry)?
            .ok_or("function missing after clear")?;

        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(before.targets(), after.targets());

        Ok(())
    }

    #[test]
    fn test_latest_change_tracks_region_and_kinds() -> Result<(), Box<dyn Error>> {
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
    fn test_reference_change_is_observable_from_both_endpoints() -> Result<(), Box<dyn Error>> {
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
                kind: ReferenceKind::Flow,
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
    fn test_latest_change_kinds_mask_selects_groups() -> Result<(), Box<dyn Error>> {
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
    fn test_region_less_changes_are_observable() -> Result<(), Box<dyn Error>> {
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
    fn test_region_bearing_precision_survives_region_less_kinds() -> Result<(), Box<dyn Error>> {
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
    fn test_restored_marks_every_region_changed() -> Result<(), Box<dyn Error>> {
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
    fn test_cached_recomputes_only_on_dependency_change() -> Result<(), Box<dyn Error>> {
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
    fn test_cached_composes_across_inputs() -> Result<(), Box<dyn Error>> {
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
    fn test_cached_region_less_dependency() -> Result<(), Box<dyn Error>> {
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
