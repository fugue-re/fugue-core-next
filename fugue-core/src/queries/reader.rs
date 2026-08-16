use std::collections::VecDeque;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use flume::Sender;
use parking_lot::{ArcRwLockReadGuard, RawRwLock, RwLock};
use thiserror::Error;

use crate::engine::{EngineError, Intake};
use crate::il::common::IlError;
use crate::il::ecode::ECodeIr;
use crate::il::mcode::MCodeIr;
use crate::il::pcode::PCodeIr;
use crate::il::registry::IlRegistry;
use crate::ir::cfg::FlowTargets;
use crate::ir::{
    Address, AddressRangeSet, FunctionId, ProblemKey, ProblemKind, Reference, ReferenceTarget,
};
use crate::project::{ChangeKinds, Project, ProjectError};
use crate::queries::cache::{CacheLookup, QueryCache, QueryableIl};
use crate::queries::engine::{IlLookup, QueryEngine};
use crate::queries::entities::{
    CallEdge, MappingEntity, ProblemEntity, QueryPage, SwitchEntity, SymbolEntity,
};
use crate::queries::index::ChangeIndex;
use crate::queries::project::ProjectQuery;
use crate::storage::segments::space::AddressSpaceId;
use crate::types::Revision;

pub(crate) const MAX_QUERY_PAGE_SIZE: usize = 4096;
const QUERY_WALK_PAGE_SIZE: usize = 256;

#[derive(Debug, Error)]
pub enum QueryError {
    #[error(transparent)]
    Engine(Box<EngineError>),
    #[error(transparent)]
    Project(#[from] ProjectError),
    #[error("analysis engine stopped")]
    Stopped,
    #[error("cached computation observed undeclared change kinds: {0:?}")]
    UndeclaredDependency(ChangeKinds),
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

struct Paged<T, F, C = T> {
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

#[derive(Clone)]
pub struct QueryReader {
    active: Arc<AtomicBool>,
    publication_lock: Arc<RwLock<()>>,
    project: Arc<RwLock<Project>>,
    cache: Arc<QueryCache>,
    changes: Arc<RwLock<ChangeIndex>>,
    intake: Option<Sender<Intake>>,
    registry: Arc<IlRegistry>,
}

impl QueryReader {
    pub(crate) fn new(
        active: Arc<AtomicBool>,
        publication_lock: Arc<RwLock<()>>,
        project: Arc<RwLock<Project>>,
        cache: Arc<QueryCache>,
        changes: Arc<RwLock<ChangeIndex>>,
        registry: Arc<IlRegistry>,
    ) -> Self {
        Self {
            active,
            publication_lock,
            project,
            cache,
            changes,
            intake: None,
            registry,
        }
    }

    pub(crate) fn with_intake(mut self, intake: Sender<Intake>) -> Self {
        self.intake = Some(intake);
        self
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub(crate) fn mark_dead(&self) {
        self.active.store(false, Ordering::Release);
    }

    pub(crate) fn into_project_lock(self) -> Arc<RwLock<Project>> {
        self.project
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

        match self.cache.flow_targets(entry) {
            CacheLookup::Hit(cached) => return Ok(Some(cached)),
            CacheLookup::Absent => return Ok(None),
            CacheLookup::Miss => {}
        }

        let targets = {
            let project = self.project.read();
            let read = ProjectQuery::new(&project);
            read.function(entry)
                .map(|function| read.flow_targets(function))
        };

        self.cache.insert_flow_targets(entry, targets.clone());
        Ok(targets)
    }

    pub fn lifted<T>(&self, function: FunctionId) -> Result<Option<Arc<T>>, QueryError>
    where
        T: QueryableIl,
    {
        self.registry
            .registered_form::<T>()
            .map_err(ProjectError::from)?;
        if let Some(cached) = self.cached_il::<T>(function)? {
            return Ok(Some(cached));
        }

        self.request_generated::<T>(function)
    }

    pub fn pcode(&self, function: FunctionId) -> Result<Option<Arc<PCodeIr>>, QueryError> {
        self.lifted::<PCodeIr>(function)
    }

    pub fn ecode(&self, function: FunctionId) -> Result<Option<Arc<ECodeIr>>, QueryError> {
        self.lifted::<ECodeIr>(function)
    }

    pub fn mcode(&self, function: FunctionId) -> Result<Option<Arc<MCodeIr>>, QueryError> {
        self.lifted::<MCodeIr>(function)
    }

    fn cached_il<T>(&self, function: FunctionId) -> Result<Option<Arc<T>>, QueryError>
    where
        T: QueryableIl,
    {
        let _query_guard = self.enter_query()?;

        let project = self.project.read();
        QueryEngine::lookup_lifted(
            &self.cache,
            &self.registry,
            &project,
            function,
            IlLookup::Current,
        )
        .map_err(QueryError::from)
    }

    fn request_generated<T>(&self, function: FunctionId) -> Result<Option<Arc<T>>, QueryError>
    where
        T: QueryableIl,
    {
        let Some(intake) = &self.intake else {
            return Ok(None);
        };

        let (reply_tx, reply_rx) = flume::bounded(1);
        intake
            .send(Intake::GenerateLifted {
                function,
                form: T::FORM,
                reply: reply_tx,
            })
            .map_err(|_| QueryError::Stopped)?;

        match reply_rx.recv().map_err(|_| QueryError::Stopped)? {
            Ok(Some(generated)) => Arc::downcast::<T>(generated)
                .map(Some)
                .map_err(|_| ProjectError::from(IlError::mismatched_artefact(T::FORM)).into()),
            Ok(None) => Ok(None),
            Err(EngineError::Project(ProjectError::Il(IlError::MissingArtefact { .. }))) => {
                Ok(None)
            }
            Err(error) => Err(QueryError::from(error)),
        }
    }

    pub fn project(&self) -> Result<ProjectHandle, QueryError> {
        let publication_guard = self.enter_query()?;

        Ok(ProjectHandle {
            project: self.project.read_arc(),
            _publication_guard: publication_guard,
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
        after: Option<Address>,
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
        after: Option<MappingEntity>,
        limit: usize,
    ) -> Result<QueryPage<MappingEntity>, QueryError> {
        self.with_project(|read| read.mapping_page(space, after, limit))?
            .map_err(QueryError::from)
    }

    pub fn symbol_page(
        &self,
        after: Option<SymbolEntity>,
        limit: usize,
    ) -> Result<QueryPage<SymbolEntity>, QueryError> {
        self.with_project(|read| read.symbol_page(after, limit))
    }

    pub fn symbol_page_at(
        &self,
        address: Address,
        after: Option<SymbolEntity>,
        limit: usize,
    ) -> Result<QueryPage<SymbolEntity>, QueryError> {
        self.with_project(|read| read.symbol_page_at(address, after, limit))
    }

    pub fn switch_at(&self, branch: Address) -> Result<Option<SwitchEntity>, QueryError> {
        self.with_project(|read| read.switch_at(branch))
    }

    pub fn problem_at(
        &self,
        address: Address,
        kind: ProblemKind,
    ) -> Result<Option<ProblemEntity>, QueryError> {
        self.with_project(|read| read.problem_at(address, kind))
    }

    pub fn problem_page(
        &self,
        after: Option<ProblemKey>,
        limit: usize,
    ) -> Result<QueryPage<ProblemEntity, ProblemKey>, QueryError> {
        self.with_project(|read| read.problem_page(after, limit))
    }

    pub fn problems(&self) -> impl Iterator<Item = Result<ProblemEntity, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.problem_page(cursor, QUERY_WALK_PAGE_SIZE))
    }

    pub fn switch_page(
        &self,
        after: Option<Address>,
        limit: usize,
    ) -> Result<QueryPage<SwitchEntity, Address>, QueryError> {
        self.with_project(|read| read.switch_page(after, limit))
    }

    pub fn switches(&self) -> impl Iterator<Item = Result<SwitchEntity, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.switch_page(cursor, QUERY_WALK_PAGE_SIZE))
    }

    pub fn functions(
        &self,
        space: AddressSpaceId,
    ) -> impl Iterator<Item = Result<Address, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.function_page(space, cursor, QUERY_WALK_PAGE_SIZE))
    }

    pub fn symbols(&self) -> impl Iterator<Item = Result<SymbolEntity, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.symbol_page(cursor, QUERY_WALK_PAGE_SIZE))
    }

    pub fn mappings(
        &self,
        space: AddressSpaceId,
    ) -> impl Iterator<Item = Result<MappingEntity, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.mapping_page(space, cursor, QUERY_WALK_PAGE_SIZE))
    }

    pub fn call_edges(&self) -> impl Iterator<Item = Result<CallEdge, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.call_edge_page(cursor, QUERY_WALK_PAGE_SIZE))
    }

    pub fn callers(&self, entry: Address) -> impl Iterator<Item = Result<Address, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.caller_page(entry, cursor, QUERY_WALK_PAGE_SIZE))
    }

    pub fn callees(&self, entry: Address) -> impl Iterator<Item = Result<Address, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.callee_page(entry, cursor, QUERY_WALK_PAGE_SIZE))
    }

    pub fn outgoing_references(
        &self,
        from: Address,
    ) -> impl Iterator<Item = Result<Reference, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.outgoing_reference_page(from, cursor, QUERY_WALK_PAGE_SIZE))
    }

    pub fn incoming_references(
        &self,
        to: Address,
    ) -> impl Iterator<Item = Result<Reference, QueryError>> {
        let reader = self.clone();
        Paged::new(move |cursor| reader.incoming_reference_page(to, cursor, QUERY_WALK_PAGE_SIZE))
    }

    fn with_project<T>(&self, query: impl FnOnce(ProjectQuery<'_>) -> T) -> Result<T, QueryError> {
        let _query_guard = self.enter_query()?;
        let project = self.project.read();
        Ok(query(ProjectQuery::new(&project)))
    }

    fn enter_query(&self) -> Result<ArcRwLockReadGuard<RawRwLock, ()>, QueryError> {
        let guard = self.publication_lock.read_arc();
        if self.active.load(Ordering::Acquire) {
            Ok(guard)
        } else {
            Err(QueryError::Stopped)
        }
    }
}

pub struct ProjectHandle {
    project: ArcRwLockReadGuard<RawRwLock, Project>,
    _publication_guard: ArcRwLockReadGuard<RawRwLock, ()>,
}

impl Deref for ProjectHandle {
    type Target = Project;

    fn deref(&self) -> &Project {
        &self.project
    }
}

#[cfg(test)]
mod test {
    use super::QueryReader;

    #[test]
    fn query_reader_is_send_and_sync() {
        fn assert_send_and_sync<T: Send + Sync>() {}

        assert_send_and_sync::<QueryReader>();
    }
}
