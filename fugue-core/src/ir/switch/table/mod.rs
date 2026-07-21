use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use thiserror::Error;

use crate::ir::switch::{Switch, SwitchId};
use crate::ir::{Address, FunctionId};
use crate::storage::entities::schema::ENTITY_SWITCH_TABLE_ID;
use crate::storage::entities::{
    Entity, EntityId, EntityMut, EntityRef, ProjectEntity, WriteBackWorker,
};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::{EntityStorage, EntityStorageError};

mod persistent;
mod transient;

pub use persistent::SwitchTable as PersistentSwitchTable;
pub use transient::SwitchTable as TransientSwitchTable;

pub type SwitchRef<'a> = EntityRef<'a, Switch>;
pub type SwitchMut<'a> = EntityMut<'a, Switch>;

const SWITCH_TABLE_VERSION: u32 = 1;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct SwitchTableHeader {
    version: u32,
}

impl Entity for SwitchTableHeader {
    const ID: EntityId = ENTITY_SWITCH_TABLE_ID;
}

struct SwitchIndex {
    branches: BTreeMap<Address, SwitchId>,
    by_function: BTreeMap<FunctionId, BTreeSet<Address>>,
    free_ids: Vec<SwitchId>,
    next_index: usize,
}

impl SwitchIndex {
    fn new() -> Self {
        Self {
            branches: BTreeMap::new(),
            by_function: BTreeMap::new(),
            free_ids: Vec::new(),
            next_index: 0,
        }
    }

    fn link(&mut self, function: FunctionId, branch: Address) {
        self.by_function.entry(function).or_default().insert(branch);
    }

    fn unlink(&mut self, function: FunctionId, branch: Address) {
        if let Some(branches) = self.by_function.get_mut(&function) {
            branches.remove(&branch);
            if branches.is_empty() {
                self.by_function.remove(&function);
            }
        }
    }

    fn branches_of_function(&self, function: FunctionId) -> impl Iterator<Item = Address> + '_ {
        self.by_function
            .get(&function)
            .into_iter()
            .flatten()
            .copied()
    }
}

struct SwitchTableAllocation {
    free_ids_len: usize,
    free_ids_tail: Vec<SwitchId>,
    next_index: usize,
}

impl SwitchTableAllocation {
    fn new(free_ids: &[SwitchId], next_index: usize, max_pops: usize) -> Self {
        let tail_start = free_ids.len().saturating_sub(max_pops);
        Self {
            free_ids_len: free_ids.len(),
            free_ids_tail: free_ids[tail_start..].to_vec(),
            next_index,
        }
    }
}

pub(crate) struct SwitchTableRevert {
    branch: Address,
    allocation: SwitchTableAllocation,
    previous_switch: Option<Switch>,
}

impl SwitchTableRevert {
    pub(crate) fn capture(table: &SwitchTable, branch: Address) -> Self {
        let previous_switch = table
            .get_by_branch(branch)
            .map(|switch| switch.as_ref().clone());

        Self {
            branch,
            allocation: table.allocation_checkpoint(1),
            previous_switch,
        }
    }

    pub(crate) fn restore(self, table: &mut SwitchTable) -> Result<(), EntityStorageError> {
        if let Some(id) = table.get_by_branch(self.branch).map(|switch| switch.id()) {
            table.clear_entry(id)?;
        }

        if let Some(switch) = self.previous_switch {
            table.restore_entry(switch)?;
        }

        table.restore_allocation(self.allocation);
        Ok(())
    }
}

pub enum SwitchTable {
    Persistent(PersistentSwitchTable),
    Transient(TransientSwitchTable),
}

#[derive(Debug, Error)]
pub enum SwitchTableError {
    #[error("switch to insert has a different branch address than that used for insertion")]
    AddressMismatch,
    #[error(transparent)]
    Storage(#[from] EntityStorageError),
}

impl SwitchTable {
    pub fn new(entities: EntityStorage, cache_bytes: usize) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentSwitchTable::new(
            entities,
            cache_bytes,
        )?))
    }

    pub fn new_with(
        entities: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentSwitchTable::new_with(
            entities,
            worker,
            cache_bytes,
        )?))
    }

    pub fn new_transient() -> Self {
        Self::Transient(TransientSwitchTable::new())
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(p) => p.flush(),
            Self::Transient(t) => t.flush(),
        }
    }

    fn allocation_checkpoint(&self, max_pops: usize) -> SwitchTableAllocation {
        match self {
            Self::Persistent(p) => p.allocation_checkpoint(max_pops),
            Self::Transient(t) => t.allocation_checkpoint(max_pops),
        }
    }

    fn restore_allocation(&mut self, allocation: SwitchTableAllocation) {
        match self {
            Self::Persistent(p) => p.restore_allocation(allocation),
            Self::Transient(t) => t.restore_allocation(allocation),
        }
    }

    fn restore_entry(&mut self, switch: Switch) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(p) => p.restore_entry(switch),
            Self::Transient(t) => {
                t.restore_entry(switch);
                Ok(())
            }
        }
    }

    fn clear_entry(&mut self, id: SwitchId) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.clear_entry(id),
            Self::Transient(t) => Ok(t.clear_entry(id)),
        }
    }

    pub fn insert<F>(&mut self, branch: Address, f: F) -> Result<SwitchId, SwitchTableError>
    where
        F: FnOnce(SwitchId, Address) -> Switch,
    {
        match self {
            Self::Persistent(p) => p.insert(branch, f),
            Self::Transient(t) => t.insert(branch, f),
        }
    }

    pub fn get_by_id(&self, id: SwitchId) -> Option<SwitchRef<'_>> {
        match self {
            Self::Persistent(p) => p.get_by_id(id).map(EntityRef::cached),
            Self::Transient(t) => t.get_by_id(id).map(EntityRef::borrowed),
        }
    }

    pub fn try_get_by_id(&self, id: SwitchId) -> Result<Option<SwitchRef<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_by_id(id)?.map(EntityRef::cached)),
            Self::Transient(t) => Ok(t.get_by_id(id).map(EntityRef::borrowed)),
        }
    }

    pub fn get_by_branch(&self, branch: Address) -> Option<SwitchRef<'_>> {
        match self {
            Self::Persistent(p) => p.get_by_branch(branch).map(EntityRef::cached),
            Self::Transient(t) => t.get_by_branch(branch).map(EntityRef::borrowed),
        }
    }

    pub fn branches_of_function(
        &self,
        function: FunctionId,
    ) -> Box<dyn Iterator<Item = Address> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.branches_of_function(function)),
            Self::Transient(t) => Box::new(t.branches_of_function(function)),
        }
    }

    pub fn contains(&self, branch: Address) -> bool {
        match self {
            Self::Persistent(p) => p.contains(branch),
            Self::Transient(t) => t.contains(branch),
        }
    }

    pub fn get_by_id_mut(&mut self, id: SwitchId) -> Option<SwitchMut<'_>> {
        match self {
            Self::Persistent(p) => p.get_by_id_mut(id).map(EntityMut::cached),
            Self::Transient(t) => t.get_by_id_mut(id).map(EntityMut::borrowed),
        }
    }

    pub fn modify_by_id<R>(&mut self, id: SwitchId, f: impl FnOnce(&mut Switch) -> R) -> Option<R> {
        match self {
            Self::Persistent(p) => p.modify_by_id(id, f),
            Self::Transient(t) => t.modify_by_id(id, f),
        }
    }

    pub fn try_modify_by_id<R>(
        &mut self,
        id: SwitchId,
        f: impl FnOnce(&mut Switch) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_modify_by_id(id, f),
            Self::Transient(t) => Ok(t.modify_by_id(id, f)),
        }
    }

    pub fn modify_by_branch<R>(
        &mut self,
        branch: Address,
        f: impl FnOnce(&mut Switch) -> R,
    ) -> Option<R> {
        match self {
            Self::Persistent(p) => p.modify_by_branch(branch, f),
            Self::Transient(t) => t.modify_by_branch(branch, f),
        }
    }

    pub fn remove_by_id(&mut self, id: SwitchId) -> bool {
        match self {
            Self::Persistent(p) => p.remove_by_id(id),
            Self::Transient(t) => t.remove_by_id(id),
        }
    }

    pub fn try_remove_by_id(&mut self, id: SwitchId) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_remove_by_id(id),
            Self::Transient(t) => Ok(t.remove_by_id(id)),
        }
    }

    pub fn remove_by_branch(&mut self, branch: Address) -> bool {
        match self {
            Self::Persistent(p) => p.remove_by_branch(branch),
            Self::Transient(t) => t.remove_by_branch(branch),
        }
    }

    pub fn branches(&self) -> Box<dyn Iterator<Item = Address> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.branches()),
            Self::Transient(t) => Box::new(t.branches()),
        }
    }

    pub fn branches_after(&self, after: Option<Address>) -> Box<dyn Iterator<Item = Address> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.branches_after(after)),
            Self::Transient(t) => Box::new(t.branches_after(after)),
        }
    }

    pub fn iter(&self) -> Box<dyn Iterator<Item = SwitchRef<'_>> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.iter().map(EntityRef::cached)),
            Self::Transient(t) => Box::new(t.iter().map(EntityRef::borrowed)),
        }
    }

    pub fn iter_mut(&mut self) -> Box<dyn Iterator<Item = SwitchMut<'_>> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.iter_mut().map(EntityMut::cached)),
            Self::Transient(t) => Box::new(t.iter_mut().map(EntityMut::borrowed)),
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

impl PersistableProjectEntity for SwitchTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(_) => storage.insert(
                &ProjectEntity::SwitchTable,
                &SwitchTableHeader {
                    version: SWITCH_TABLE_VERSION,
                },
            ),
            Self::Transient(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ir::SwitchModel;

    fn function(index: usize) -> FunctionId {
        FunctionId::from_index(index)
    }

    #[test]
    fn indexes_switches_by_owning_function() {
        let mut table = SwitchTable::new_transient();
        let owner = function(0);
        let other = function(1);
        let placements = [
            (Address::from(0x1000u64), owner),
            (Address::from(0x2000u64), owner),
            (Address::from(0x3000u64), other),
        ];

        for (branch, owning) in placements {
            table
                .insert(branch, |id, branch| {
                    Switch::new(id, branch, SwitchModel::Explicit).with_function(owning)
                })
                .unwrap();
        }

        let mut owned = table.branches_of_function(owner).collect::<Vec<_>>();
        owned.sort();
        assert_eq!(
            owned,
            vec![Address::from(0x1000u64), Address::from(0x2000u64)]
        );
        assert_eq!(
            table.branches_of_function(other).collect::<Vec<_>>(),
            vec![Address::from(0x3000u64)]
        );

        table.remove_by_branch(Address::from(0x1000u64));
        assert_eq!(
            table.branches_of_function(owner).collect::<Vec<_>>(),
            vec![Address::from(0x2000u64)]
        );
    }
}
