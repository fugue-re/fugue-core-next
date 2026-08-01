use std::collections::BTreeMap;
use std::fmt;
use std::ops::Bound;
use std::sync::Arc;

use crate::ir::problem::{Problem, ProblemId, ProblemKey, ProblemKind, ProblemScope};
use crate::ir::{Address, AddressRange, IdAllocator};
use crate::storage::entities::schema::ENTITY_PROBLEM_TABLE_ID;
use crate::storage::entities::{Entity, EntityId, EntityRef, ProjectEntity, WriteBackWorker};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::{EntityStorage, EntityStorageError};
use crate::types::Revision;
use crate::types::common::cursor_bound;

mod persistent;
mod transient;

use persistent::ProblemTable as PersistentProblemTable;
use transient::ProblemTable as TransientProblemTable;

pub type ProblemRef<'a> = EntityRef<'a, Problem>;

const PROBLEM_TABLE_VERSION: u32 = 1;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct ProblemTableHeader {
    version: u32,
}

impl Entity for ProblemTableHeader {
    const ID: EntityId = ENTITY_PROBLEM_TABLE_ID;
}

struct ProblemIndex {
    allocator: IdAllocator<Problem>,
    problems: BTreeMap<ProblemKey, ProblemId>,
}

impl ProblemIndex {
    fn new() -> Self {
        Self {
            allocator: IdAllocator::new(),
            problems: BTreeMap::new(),
        }
    }

    fn insert(&mut self, id: ProblemId, key: ProblemKey) {
        self.problems.insert(key, id);
    }

    fn remove(&mut self, key: ProblemKey) {
        self.problems.remove(&key);
    }

    fn id(&self, key: ProblemKey) -> Option<ProblemId> {
        self.problems.get(&key).copied()
    }

    fn contains(&self, address: Address) -> bool {
        self.problems
            .range(ProblemKey::new(address, ProblemKind::MIN)..)
            .next()
            .is_some_and(|(key, _)| key.address() == Some(address))
    }

    fn keys(&self) -> impl Iterator<Item = ProblemKey> + '_ {
        self.problems.keys().copied()
    }

    fn for_each_address_key_in(&self, range: AddressRange, mut f: impl FnMut(ProblemKey)) {
        if range.is_empty() {
            return;
        }

        let first = ProblemKey::new(range.start_address(), ProblemKind::MIN);
        let last = ProblemKey::new(range.end_address(), ProblemKind::MAX);
        for (&key, _) in self.problems.range(first..=last) {
            f(key);
        }
    }

    fn entries_after(
        &self,
        after: Option<ProblemKey>,
    ) -> impl Iterator<Item = (ProblemKey, ProblemId)> + '_ {
        let start = cursor_bound(after);
        self.problems
            .range((start, Bound::Unbounded))
            .map(|(&key, &id)| (key, id))
    }

    fn is_empty(&self) -> bool {
        self.problems.is_empty()
    }

    fn len(&self) -> usize {
        self.problems.len()
    }
}

pub enum ProblemTable {
    Persistent(PersistentProblemTable),
    Transient(TransientProblemTable),
}

#[derive(Debug, thiserror::Error)]
pub enum ProblemTableError {
    #[error("problem to insert has a different key than that used for insertion")]
    KeyMismatch,
    #[error(transparent)]
    Other(anyhow::Error),
    #[error(transparent)]
    Storage(#[from] EntityStorageError),
}

impl ProblemTableError {
    pub fn other<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Other(anyhow::Error::new(error))
    }

    pub fn other_with<M>(msg: M) -> Self
    where
        M: fmt::Debug + fmt::Display + Send + Sync + 'static,
    {
        Self::Other(anyhow::Error::msg(msg))
    }
}

impl ProblemTable {
    pub fn new(entities: EntityStorage, cache_bytes: usize) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentProblemTable::new(
            entities,
            cache_bytes,
        )?))
    }

    pub fn with_worker(
        entities: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentProblemTable::with_worker(
            entities,
            worker,
            cache_bytes,
        )?))
    }

    pub fn new_transient() -> Self {
        Self::Transient(TransientProblemTable::new())
    }

    pub(crate) fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent(_))
    }

    pub(crate) fn preview_id(&self, offset: usize) -> ProblemId {
        match self {
            Self::Persistent(table) => table.preview_id(offset),
            Self::Transient(table) => table.preview_id(offset),
        }
    }

    pub(crate) fn publish_upsert(&mut self, problem: Problem, encoded_len: usize, is_new: bool) {
        match self {
            Self::Persistent(table) => table.publish_upsert(problem, encoded_len, is_new),
            Self::Transient(table) => table.publish_upsert(problem, is_new),
        }
    }

    pub(crate) fn publish_remove(&mut self, key: ProblemKey) {
        match self {
            Self::Persistent(table) => table.publish_remove(key),
            Self::Transient(table) => table.publish_remove(key),
        }
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(p) => p.flush(),
            Self::Transient(t) => t.flush(),
        }
    }

    pub fn insert(
        &mut self,
        address: Address,
        kind: ProblemKind,
        observed_revision: Revision,
    ) -> Result<ProblemId, ProblemTableError> {
        self.insert_scoped(ProblemScope::Address(address), kind, observed_revision)
    }

    pub fn insert_scoped(
        &mut self,
        scope: ProblemScope,
        kind: ProblemKind,
        observed_revision: Revision,
    ) -> Result<ProblemId, ProblemTableError> {
        let key = ProblemKey::scoped(scope, kind);
        if let Some(id) = self.try_get_key(key)?.map(|problem| problem.id()) {
            self.try_modify_by_id(id, |problem| {
                problem.record_attempt(observed_revision);
            })?;
            return Ok(id);
        }

        let problem = |id, scope| Ok(Problem::new_scoped(id, scope, kind, observed_revision));
        match self {
            Self::Persistent(table) => table.insert(scope, kind, problem),
            Self::Transient(table) => table.insert(scope, kind, problem),
        }
    }

    pub fn get_by_id(&self, id: ProblemId) -> Option<ProblemRef<'_>> {
        self.try_get_by_id(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_id(
        &self,
        id: ProblemId,
    ) -> Result<Option<ProblemRef<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_by_id(id)?.map(EntityRef::cached)),
            Self::Transient(t) => Ok(t.get_by_id(id).map(EntityRef::borrowed)),
        }
    }

    pub fn get(&self, address: Address, kind: ProblemKind) -> Option<ProblemRef<'_>> {
        self.try_get(address, kind)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get(
        &self,
        address: Address,
        kind: ProblemKind,
    ) -> Result<Option<ProblemRef<'_>>, EntityStorageError> {
        self.try_get_key(ProblemKey::new(address, kind))
    }

    pub fn get_scoped(&self, scope: ProblemScope, kind: ProblemKind) -> Option<ProblemRef<'_>> {
        self.try_get_key(ProblemKey::scoped(scope, kind))
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_key(
        &self,
        key: ProblemKey,
    ) -> Result<Option<ProblemRef<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_key(key)?.map(EntityRef::cached)),
            Self::Transient(t) => Ok(t.get_key(key).map(EntityRef::borrowed)),
        }
    }

    pub fn contains(&self, address: Address) -> bool {
        match self {
            Self::Persistent(p) => p.contains(address),
            Self::Transient(t) => t.contains(address),
        }
    }

    pub fn contains_any(&self, address: Address, kinds: &[ProblemKind]) -> bool {
        kinds.iter().any(|kind| self.get(address, *kind).is_some())
    }

    pub fn try_modify_by_id<R>(
        &mut self,
        id: ProblemId,
        f: impl FnOnce(&mut Problem) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_modify_by_id(id, f),
            Self::Transient(t) => Ok(t.modify_by_id(id, f)),
        }
    }

    pub fn remove(&mut self, address: Address, kind: ProblemKind) -> bool {
        self.try_remove(address, kind)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove(
        &mut self,
        address: Address,
        kind: ProblemKind,
    ) -> Result<bool, EntityStorageError> {
        self.try_remove_key(ProblemKey::new(address, kind))
    }

    pub fn try_remove_key(&mut self, key: ProblemKey) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_remove_key(key),
            Self::Transient(t) => Ok(t.remove_key(key)),
        }
    }

    pub fn keys(&self) -> Box<dyn Iterator<Item = ProblemKey> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.keys()),
            Self::Transient(t) => Box::new(t.keys()),
        }
    }

    pub(crate) fn for_each_address_key_in(
        &self,
        range: AddressRange,
        mut f: impl FnMut(ProblemKey),
    ) {
        match self {
            Self::Persistent(table) => table.for_each_address_key_in(range, &mut f),
            Self::Transient(table) => table.for_each_address_key_in(range, &mut f),
        }
    }

    pub fn entries_after(
        &self,
        after: Option<ProblemKey>,
    ) -> Box<dyn Iterator<Item = ProblemRef<'_>> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.entries_after(after).map(EntityRef::cached)),
            Self::Transient(t) => Box::new(t.entries_after(after).map(EntityRef::borrowed)),
        }
    }

    pub fn iter(&self) -> Box<dyn Iterator<Item = ProblemRef<'_>> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.iter().map(EntityRef::cached)),
            Self::Transient(t) => Box::new(t.iter().map(EntityRef::borrowed)),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Persistent(p) => p.is_empty(),
            Self::Transient(t) => t.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Persistent(p) => p.len(),
            Self::Transient(t) => t.len(),
        }
    }
}

impl PersistableProjectEntity for ProblemTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(_) => storage.insert(
                &ProjectEntity::ProblemTable,
                &ProblemTableHeader {
                    version: PROBLEM_TABLE_VERSION,
                },
            ),
            Self::Transient(_) => Ok(()),
        }
    }
}
