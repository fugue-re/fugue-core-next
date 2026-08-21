use super::{SwitchIndex, SwitchTableError};
use crate::ir::switch::{Switch, SwitchId};
use crate::ir::{Address, FunctionId};

pub struct SwitchTable {
    index: SwitchIndex,
    entries: Vec<Option<Switch>>,
}

impl Default for SwitchTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SwitchTable {
    pub fn new() -> Self {
        Self {
            index: SwitchIndex::new(),
            entries: Vec::new(),
        }
    }

    pub fn branches_for_function(
        &self,
        function: FunctionId,
    ) -> impl Iterator<Item = Address> + '_ {
        self.index.branches_for_function(function)
    }

    pub(crate) fn pending_id(&self, offset: usize) -> SwitchId {
        self.index.allocator.pending_id(offset)
    }

    pub fn get_by_id(&self, id: SwitchId) -> Option<&Switch> {
        self.entries
            .get(id.index())?
            .as_ref()
            .filter(|switch| switch.id() == id)
    }

    pub fn contains(&self, branch: Address) -> bool {
        self.index.contains(branch)
    }

    pub fn branches(&self) -> impl Iterator<Item = Address> + '_ {
        self.index.branches()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Switch> + '_ {
        self.entries.iter().filter_map(Option::as_ref)
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub(crate) fn publish_reservation(&mut self, id: SwitchId) {
        let allocated = self.index.allocator.allocate();
        debug_assert_eq!(allocated, id);
    }

    pub(crate) fn publish_release(&mut self, id: SwitchId) {
        self.index.allocator.release(id);
    }

    pub(crate) fn publish_upsert(&mut self, switch: Switch, previous_function: Option<FunctionId>) {
        let id = switch.id();
        let branch = switch.branch();
        if let Some(previous_function) = previous_function {
            self.index.remove(previous_function, branch);
        }
        self.index.insert(id, switch.function(), branch);
        let slot = id.index();
        if slot >= self.entries.len() {
            self.entries.resize_with(slot + 1, || None);
        }
        self.entries[slot] = Some(switch);
    }

    pub(crate) fn publish_remove(&mut self, id: SwitchId, function: FunctionId, branch: Address) {
        self.entries[id.index()] = None;
        self.index.remove(function, branch);
        self.index.allocator.release(id);
    }

    pub fn insert<F>(&mut self, branch: Address, f: F) -> Result<SwitchId, SwitchTableError>
    where
        F: FnOnce(SwitchId, Address) -> Result<Switch, SwitchTableError>,
    {
        if let Some(existing) = self.index.id_by_branch(branch) {
            let switch = f(existing, branch)?;
            if switch.branch() != branch {
                return Err(SwitchTableError::AddressMismatch);
            }
            if let Some(previous) = self.entries[existing.index()].as_ref() {
                self.index.remove(previous.function(), branch);
            }
            self.index.insert(existing, switch.function(), branch);
            self.entries[existing.index()] = Some(switch);
            return Ok(existing);
        }

        let (id, switch) = self.index.allocator.try_allocate(|id| {
            let switch = f(id, branch)?;
            if switch.branch() != branch {
                return Err(SwitchTableError::AddressMismatch);
            }
            Ok(switch)
        })?;

        self.index.insert(id, switch.function(), branch);

        let slot = id.index();
        if slot >= self.entries.len() {
            self.entries.resize_with(slot + 1, || None);
        }
        self.entries[slot] = Some(switch);

        Ok(id)
    }

    pub fn get_by_branch(&self, branch: Address) -> Option<&Switch> {
        let id = self.index.id_by_branch(branch)?;
        self.get_by_id(id)
    }

    pub fn modify_by_id<R>(&mut self, id: SwitchId, f: impl FnOnce(&mut Switch) -> R) -> Option<R> {
        let switch = self
            .entries
            .get_mut(id.index())?
            .as_mut()
            .filter(|switch| switch.id() == id)?;
        let previous_function = switch.function();
        let branch = switch.branch();
        let result = f(switch);
        let function = switch.function();

        if function != previous_function {
            self.index.remove(previous_function, branch);
            self.index.insert(id, function, branch);
        }

        Some(result)
    }

    pub fn modify_by_branch<R>(
        &mut self,
        branch: Address,
        f: impl FnOnce(&mut Switch) -> R,
    ) -> Option<R> {
        let id = self.index.id_by_branch(branch)?;
        self.modify_by_id(id, f)
    }

    pub fn remove_by_id(&mut self, id: SwitchId) -> bool {
        let Some(switch) = self
            .entries
            .get_mut(id.index())
            .and_then(|entry| entry.take_if(|switch| switch.id() == id))
        else {
            return false;
        };
        self.index.remove(switch.function(), switch.branch());
        self.index.allocator.release(id);
        true
    }

    pub fn remove_by_branch(&mut self, branch: Address) -> bool {
        let Some(id) = self.index.id_by_branch(branch) else {
            return false;
        };
        self.remove_by_id(id)
    }

    pub fn entries_after(&self, after: Option<Address>) -> impl Iterator<Item = &Switch> + '_ {
        self.index
            .entries_after(after)
            .filter_map(|(_, id)| self.get_by_id(id))
    }
}
