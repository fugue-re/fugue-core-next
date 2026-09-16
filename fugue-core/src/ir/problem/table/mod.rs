use std::collections::BTreeMap;
use std::fmt;
use std::ops::Bound;
use std::sync::Arc;

use crate::ir::problem::{Problem, ProblemId, ProblemKey, ProblemKind, ProblemScope};
use crate::ir::{Address, AddressRange};
use crate::storage::entities::cursor::cursor_bound;
use crate::storage::entities::schema::ENTITY_PROBLEM_TABLE_ID;
use crate::storage::entities::{
    Entity, EntityId, EntityRef, EntityWrite, EntityWriteBatch, ProjectEntity, WriteBackWorker,
};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::{EntityStorage, EntityStorageError};
use crate::types::Revision;

pub(crate) const ATTRIBUTE_PROBLEM_CACHE_SIZE: &str = "storage.entities.problem.cache_size";
pub(crate) const DEFAULT_PROBLEM_CACHE_BYTES: usize = 2 * 1024 * 1024;

mod persistent;
use persistent::ProblemTable as PersistentProblemTable;

mod transient;
use transient::ProblemTable as TransientProblemTable;

pub type ProblemRef<'a> = EntityRef<'a, Problem>;

const PROBLEM_TABLE_VERSION: u32 = 1;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct ProblemTableHeader {
    format_version: u32,
}

impl Entity for ProblemTableHeader {
    const ID: EntityId = ENTITY_PROBLEM_TABLE_ID;
}

struct ProblemIndex {
    problems: BTreeMap<ProblemKey, ProblemId>,
}

impl ProblemIndex {
    fn new() -> Self {
        Self {
            problems: BTreeMap::new(),
        }
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

    fn is_empty(&self) -> bool {
        self.problems.is_empty()
    }

    fn len(&self) -> usize {
        self.problems.len()
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

    fn insert(&mut self, id: ProblemId, key: ProblemKey) {
        self.problems.insert(key, id);
    }

    fn remove(&mut self, key: ProblemKey) {
        self.problems.remove(&key);
    }

    fn for_each_key_in_range(&self, range: AddressRange, mut f: impl FnMut(ProblemKey)) {
        if range.is_empty() {
            return;
        }

        let first = ProblemKey::new(range.start_address(), ProblemKind::MIN);
        let last = ProblemKey::new(range.end_address(), ProblemKind::MAX);
        for (&key, _) in self.problems.range(first..=last) {
            f(key);
        }
    }
}

#[derive(Default)]
pub(crate) struct ProblemTableStaging {
    staged_problems: BTreeMap<ProblemKey, Option<Problem>>,
}

pub(crate) struct PreparedProblemBatch {
    records: Vec<PreparedProblemRecord>,
    reservations: Vec<ProblemId>,
}

struct PreparedProblemRecord {
    encoded_size: usize,
    key: ProblemKey,
    problem: Option<Problem>,
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
    pub fn new_transient() -> Self {
        Self::Transient(TransientProblemTable::new())
    }

    pub fn new_persistent(
        entities: EntityStorage,
        cache_bytes: usize,
        worker: Arc<WriteBackWorker>,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentProblemTable::new(
            entities,
            cache_bytes,
            worker,
        )?))
    }

    pub fn contains(&self, address: Address) -> bool {
        match self {
            Self::Persistent(table) => table.contains(address),
            Self::Transient(table) => table.contains(address),
        }
    }

    pub fn contains_any(&self, address: Address, kinds: &[ProblemKind]) -> bool {
        kinds.iter().any(|kind| self.get(address, *kind).is_some())
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Persistent(table) => table.is_empty(),
            Self::Transient(table) => table.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Persistent(table) => table.len(),
            Self::Transient(table) => table.len(),
        }
    }

    pub(crate) fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent(_))
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
            Self::Persistent(table) => Ok(table.try_get_by_id(id)?.map(EntityRef::cached)),
            Self::Transient(table) => Ok(table.get_by_id(id).map(EntityRef::borrowed)),
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
        self.try_get_by_key(ProblemKey::new(address, kind))
    }

    pub fn get_scoped(&self, scope: ProblemScope, kind: ProblemKind) -> Option<ProblemRef<'_>> {
        self.try_get_by_key(ProblemKey::scoped(scope, kind))
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_key(
        &self,
        key: ProblemKey,
    ) -> Result<Option<ProblemRef<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(table) => Ok(table.try_get_by_key(key)?.map(EntityRef::cached)),
            Self::Transient(table) => Ok(table.get_by_key(key).map(EntityRef::borrowed)),
        }
    }

    pub fn keys(&self) -> Box<dyn Iterator<Item = ProblemKey> + '_> {
        match self {
            Self::Persistent(table) => Box::new(table.keys()),
            Self::Transient(table) => Box::new(table.keys()),
        }
    }

    pub fn entries_after(
        &self,
        after: Option<ProblemKey>,
    ) -> Box<dyn Iterator<Item = ProblemRef<'_>> + '_> {
        match self {
            Self::Persistent(table) => Box::new(table.entries_after(after).map(EntityRef::cached)),
            Self::Transient(table) => Box::new(table.entries_after(after).map(EntityRef::borrowed)),
        }
    }

    pub fn iter(&self) -> Box<dyn Iterator<Item = ProblemRef<'_>> + '_> {
        match self {
            Self::Persistent(table) => Box::new(table.iter().map(EntityRef::cached)),
            Self::Transient(table) => Box::new(table.iter().map(EntityRef::borrowed)),
        }
    }

    pub fn for_each_key_in_range(&self, range: AddressRange, mut f: impl FnMut(ProblemKey)) {
        match self {
            Self::Persistent(table) => table.for_each_key_in_range(range, &mut f),
            Self::Transient(table) => table.for_each_key_in_range(range, &mut f),
        }
    }

    pub(crate) fn pending_id(&self, offset: usize) -> ProblemId {
        match self {
            Self::Persistent(table) => table.pending_id(offset),
            Self::Transient(table) => table.pending_id(offset),
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
        if let Some(id) = self.try_get_by_key(key)?.map(|problem| problem.id()) {
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

    pub fn modify_by_id<R>(
        &mut self,
        id: ProblemId,
        f: impl FnOnce(&mut Problem) -> R,
    ) -> Option<R> {
        self.try_modify_by_id(id, f)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_modify_by_id<R>(
        &mut self,
        id: ProblemId,
        f: impl FnOnce(&mut Problem) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        match self {
            Self::Persistent(table) => table.try_modify_by_id(id, f),
            Self::Transient(table) => Ok(table.modify_by_id(id, f)),
        }
    }

    pub fn remove_by_id(&mut self, id: ProblemId) -> bool {
        self.try_remove_by_id(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove_by_id(&mut self, id: ProblemId) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(table) => table.try_remove_by_id(id),
            Self::Transient(table) => Ok(table.remove_by_id(id)),
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
        self.try_remove_by_key(ProblemKey::new(address, kind))
    }

    pub fn try_remove_by_key(&mut self, key: ProblemKey) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(table) => table.try_remove_by_key(key),
            Self::Transient(table) => Ok(table.remove_by_key(key)),
        }
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(table) => table.flush(),
            Self::Transient(_) => Ok(()),
        }
    }

    pub(crate) fn append_allocation_writes(
        &self,
        reservations: &[ProblemId],
        releases: &[ProblemId],
        added: usize,
        removed: usize,
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        if let Self::Persistent(table) = self {
            table.append_allocation_writes(reservations, releases, added, removed, writes)?;
        }
        Ok(())
    }

    pub(crate) fn publish_allocations(
        &mut self,
        reservations: &[ProblemId],
        added: usize,
        removed: usize,
    ) {
        match self {
            Self::Persistent(table) => table.publish_allocations(reservations, added, removed),
            Self::Transient(table) => table.publish_allocations(reservations),
        }
    }

    pub(crate) fn publish_upsert(&mut self, problem: Problem, encoded_size: usize) {
        match self {
            Self::Persistent(table) => table.publish_upsert(problem, encoded_size),
            Self::Transient(table) => table.publish_upsert(problem),
        }
    }

    pub(crate) fn publish_remove(&mut self, key: ProblemKey) {
        match self {
            Self::Persistent(table) => table.publish_remove(key),
            Self::Transient(table) => table.publish_remove(key),
        }
    }
}

impl ProblemTableStaging {
    pub(crate) fn contains(&self, problems: &ProblemTable, address: Address) -> bool {
        if self
            .staged_problems
            .iter()
            .any(|(key, problem)| key.address() == Some(address) && problem.is_some())
        {
            return true;
        }

        problems
            .keys()
            .filter(|key| key.address() == Some(address))
            .any(|key| !self.staged_problems.contains_key(&key))
    }

    pub(crate) fn contains_key(&self, key: ProblemKey) -> bool {
        self.staged_problems.contains_key(&key)
    }

    pub(crate) fn insert(
        &mut self,
        problems: &ProblemTable,
        scope: ProblemScope,
        kind: ProblemKind,
        observed_revision: Revision,
    ) -> Result<(), EntityStorageError> {
        let key = ProblemKey::scoped(scope, kind);
        let (mut problem, repeated) = match self.staged_problems.get(&key) {
            Some(Some(problem)) => (problem.clone(), true),
            Some(None) | None => match problems.try_get_by_key(key)? {
                Some(problem) => (problem.as_ref().clone(), true),
                None => (
                    Problem::new_scoped(ProblemId::INVALID, scope, kind, observed_revision),
                    false,
                ),
            },
        };

        if repeated {
            problem.record_attempt(observed_revision);
        }
        self.staged_problems.insert(key, Some(problem));
        Ok(())
    }

    pub(crate) fn remove(&mut self, key: ProblemKey) {
        self.staged_problems.insert(key, None);
    }

    pub(crate) fn prepare(
        self,
        problems: &ProblemTable,
    ) -> Result<(PreparedProblemBatch, EntityWriteBatch), EntityStorageError> {
        let persistent = problems.is_persistent();
        let mut inserted = 0usize;
        let mut records = Vec::with_capacity(self.staged_problems.len());
        let mut reservations = Vec::new();
        let mut releases = Vec::new();
        let mut writes = EntityWriteBatch::with_capacity(if persistent {
            self.staged_problems.len()
        } else {
            0
        });

        for (key, problem) in self.staged_problems {
            let previous = problems.try_get_by_key(key)?;
            let is_new = previous.is_none();
            let previous_id = previous.as_ref().map(|problem| problem.id());
            drop(previous);

            match problem {
                Some(problem) => {
                    let problem = if is_new {
                        let id = problems.pending_id(inserted);
                        inserted += 1;
                        reservations.push(id);
                        problem.with_id(id)
                    } else {
                        problem
                    };
                    let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(&problem)
                        .map_err(EntityStorageError::encode)?;
                    let encoded_size = encoded.len();
                    if persistent {
                        writes.push(EntityWrite::insert_archived(
                            Problem::ID.key_for(&problem.id()),
                            encoded,
                        ));
                    }
                    records.push(PreparedProblemRecord {
                        encoded_size,
                        key,
                        problem: Some(problem),
                    });
                }
                None => {
                    let Some(id) = previous_id else {
                        continue;
                    };
                    releases.push(id);
                    if persistent {
                        writes.push(EntityWrite::remove(Problem::ID.key_for(&id)));
                    }
                    records.push(PreparedProblemRecord {
                        encoded_size: 0,
                        key,
                        problem: None,
                    });
                }
            }
        }

        problems.append_allocation_writes(
            &reservations,
            &releases,
            reservations.len(),
            releases.len(),
            &mut writes,
        )?;

        Ok((
            PreparedProblemBatch {
                records,
                reservations,
            },
            writes,
        ))
    }
}

impl PreparedProblemBatch {
    pub(crate) fn changes(&self) -> impl Iterator<Item = (ProblemKey, bool)> + '_ {
        self.records
            .iter()
            .map(|record| (record.key, record.problem.is_some()))
    }

    pub(crate) fn publish(self, problems: &mut ProblemTable) {
        let Self {
            records,
            reservations,
        } = self;
        let removed = records
            .iter()
            .filter(|record| record.problem.is_none())
            .count();
        problems.publish_allocations(&reservations, reservations.len(), removed);
        for record in records {
            match record.problem {
                Some(problem) => problems.publish_upsert(problem, record.encoded_size),
                None => problems.publish_remove(record.key),
            }
        }
    }
}

impl PersistableProjectEntity for ProblemTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(_) => storage.insert(
                &ProjectEntity::ProblemTable,
                &ProblemTableHeader {
                    format_version: PROBLEM_TABLE_VERSION,
                },
            ),
            Self::Transient(_) => Ok(()),
        }
    }
}
