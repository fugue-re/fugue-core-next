use super::{ProblemIndex, ProblemTableError};
use crate::ir::problem::{Problem, ProblemId, ProblemKey, ProblemKind, ProblemScope};
use crate::ir::{Address, AddressRange};

pub struct ProblemTable {
    index: ProblemIndex,
    entries: Vec<Option<Problem>>,
}

impl Default for ProblemTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ProblemTable {
    pub fn new() -> Self {
        Self {
            index: ProblemIndex::new(),
            entries: Vec::new(),
        }
    }

    pub(crate) fn pending_id(&self, offset: usize) -> ProblemId {
        self.index.allocator.pending_id(offset)
    }

    pub fn get_by_id(&self, id: ProblemId) -> Option<&Problem> {
        self.entries
            .get(id.index())?
            .as_ref()
            .filter(|problem| problem.id() == id)
    }

    pub fn get(&self, address: Address, kind: ProblemKind) -> Option<&Problem> {
        self.get_by_key(ProblemKey::new(address, kind))
    }

    pub fn get_by_key(&self, key: ProblemKey) -> Option<&Problem> {
        let id = self.index.id(key)?;
        self.get_by_id(id)
    }

    pub fn contains(&self, address: Address) -> bool {
        self.index.contains(address)
    }

    pub(crate) fn for_each_key_in_range(&self, range: AddressRange, f: impl FnMut(ProblemKey)) {
        self.index.for_each_key_in_range(range, f);
    }

    pub fn keys(&self) -> impl Iterator<Item = ProblemKey> + '_ {
        self.index.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Problem> + '_ {
        self.entries.iter().filter_map(Option::as_ref)
    }

    pub fn entries_after(&self, after: Option<ProblemKey>) -> impl Iterator<Item = &Problem> + '_ {
        self.index
            .entries_after(after)
            .filter_map(|(_, id)| self.get_by_id(id))
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub(crate) fn publish_upsert(&mut self, problem: Problem, is_new: bool) {
        let id = problem.id();
        let key = problem.key();
        let slot = id.index();
        if slot >= self.entries.len() {
            self.entries.resize_with(slot + 1, || None);
        }
        self.entries[slot] = Some(problem);
        self.index.insert(id, key);
        if is_new {
            let allocated = self.index.allocator.allocate();
            debug_assert_eq!(allocated, id);
        }
    }

    pub(crate) fn publish_remove(&mut self, key: ProblemKey) {
        let Some(id) = self.index.id(key) else {
            return;
        };

        self.entries[id.index()] = None;
        self.index.remove(key);
        self.index.allocator.release(id);
    }

    pub fn insert<F>(
        &mut self,
        scope: ProblemScope,
        kind: ProblemKind,
        f: F,
    ) -> Result<ProblemId, ProblemTableError>
    where
        F: FnOnce(ProblemId, ProblemScope) -> Result<Problem, ProblemTableError>,
    {
        let key = ProblemKey::scoped(scope, kind);
        if let Some(existing) = self.index.id(key) {
            let problem = f(existing, scope)?;
            if problem.key() != key {
                return Err(ProblemTableError::KeyMismatch);
            }
            self.index.insert(existing, key);
            self.entries[existing.index()] = Some(problem);
            return Ok(existing);
        }

        let (id, problem) = self.index.allocator.try_allocate(|id| {
            let problem = f(id, scope)?;
            if problem.key() != key {
                return Err(ProblemTableError::KeyMismatch);
            }
            Ok(problem)
        })?;

        self.index.insert(id, key);

        let slot = id.index();
        if slot >= self.entries.len() {
            self.entries.resize_with(slot + 1, || None);
        }
        self.entries[slot] = Some(problem);

        Ok(id)
    }

    pub fn modify_by_id<R>(
        &mut self,
        id: ProblemId,
        f: impl FnOnce(&mut Problem) -> R,
    ) -> Option<R> {
        let problem = self
            .entries
            .get_mut(id.index())?
            .as_mut()
            .filter(|problem| problem.id() == id)?;
        Some(f(problem))
    }

    pub fn remove_by_id(&mut self, id: ProblemId) -> bool {
        let Some(problem) = self
            .entries
            .get_mut(id.index())
            .and_then(|entry| entry.take_if(|problem| problem.id() == id))
        else {
            return false;
        };
        self.index.remove(problem.key());
        self.index.allocator.release(id);
        true
    }

    pub fn remove(&mut self, address: Address, kind: ProblemKind) -> bool {
        self.remove_by_key(ProblemKey::new(address, kind))
    }

    pub fn remove_by_key(&mut self, key: ProblemKey) -> bool {
        let Some(id) = self.index.id(key) else {
            return false;
        };
        self.remove_by_id(id)
    }
}
