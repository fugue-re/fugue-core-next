use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::ops::Bound;
use std::sync::Arc;

use thiserror::Error;

use crate::ir::switch::{Switch, SwitchId};
use crate::ir::{Address, FunctionId, IdAllocator};
use crate::storage::entities::schema::ENTITY_SWITCH_TABLE_ID;
use crate::storage::entities::{Entity, EntityId, EntityRef, ProjectEntity, WriteBackWorker};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::{EntityStorage, EntityStorageError};
use crate::types::common::cursor_bound;

mod persistent;
mod transient;

use persistent::SwitchTable as PersistentSwitchTable;
use transient::SwitchTable as TransientSwitchTable;

pub type SwitchRef<'a> = EntityRef<'a, Switch>;

const SWITCH_TABLE_VERSION: u32 = 1;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct SwitchTableHeader {
    version: u32,
}

impl Entity for SwitchTableHeader {
    const ID: EntityId = ENTITY_SWITCH_TABLE_ID;
}

struct SwitchIndex {
    allocator: IdAllocator<Switch>,
    branches: BTreeMap<Address, SwitchId>,
    by_function: BTreeMap<FunctionId, BTreeSet<Address>>,
}

impl SwitchIndex {
    fn new() -> Self {
        Self {
            allocator: IdAllocator::new(),
            branches: BTreeMap::new(),
            by_function: BTreeMap::new(),
        }
    }

    fn link(&mut self, function: FunctionId, branch: Address) {
        self.by_function.entry(function).or_default().insert(branch);
    }

    fn insert(&mut self, id: SwitchId, function: FunctionId, branch: Address) {
        self.branches.insert(branch, id);
        self.link(function, branch);
    }

    fn remove(&mut self, function: FunctionId, branch: Address) {
        self.branches.remove(&branch);
        self.unlink(function, branch);
    }

    fn id_by_branch(&self, branch: Address) -> Option<SwitchId> {
        self.branches.get(&branch).copied()
    }

    fn contains(&self, branch: Address) -> bool {
        self.branches.contains_key(&branch)
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

    fn branches(&self) -> impl Iterator<Item = Address> + '_ {
        self.branches.keys().copied()
    }

    fn entries_after(
        &self,
        after: Option<Address>,
    ) -> impl Iterator<Item = (Address, SwitchId)> + '_ {
        let start = cursor_bound(after);
        self.branches
            .range((start, Bound::Unbounded))
            .map(|(&address, &id)| (address, id))
    }

    fn is_empty(&self) -> bool {
        self.branches.is_empty()
    }

    fn len(&self) -> usize {
        self.branches.len()
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
    Other(anyhow::Error),
    #[error(transparent)]
    Storage(#[from] EntityStorageError),
}

impl SwitchTableError {
    pub fn other<E>(error: E) -> Self
    where
        E: Error + Send + Sync + 'static,
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

impl SwitchTable {
    pub fn new(entities: EntityStorage, cache_bytes: usize) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentSwitchTable::new(
            entities,
            cache_bytes,
        )?))
    }

    pub fn with_worker(
        entities: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentSwitchTable::with_worker(
            entities,
            worker,
            cache_bytes,
        )?))
    }

    pub fn new_transient() -> Self {
        Self::Transient(TransientSwitchTable::new())
    }

    pub(crate) fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent(_))
    }

    pub(crate) fn preview_id(&self, offset: usize) -> SwitchId {
        match self {
            Self::Persistent(table) => table.preview_id(offset),
            Self::Transient(table) => table.preview_id(offset),
        }
    }

    pub(crate) fn publish_reservations(&mut self, reservations: &[SwitchId]) {
        for &id in reservations {
            match self {
                Self::Persistent(table) => table.publish_reservation(id),
                Self::Transient(table) => table.publish_reservation(id),
            }
        }
    }

    pub(crate) fn publish_release(&mut self, id: SwitchId) {
        match self {
            Self::Persistent(table) => table.publish_release(id),
            Self::Transient(table) => table.publish_release(id),
        }
    }

    pub(crate) fn publish_upsert(
        &mut self,
        switch: Switch,
        previous_function: Option<FunctionId>,
        encoded_len: usize,
    ) {
        match self {
            Self::Persistent(table) => table.publish_upsert(switch, previous_function, encoded_len),
            Self::Transient(table) => table.publish_upsert(switch, previous_function),
        }
    }

    pub(crate) fn publish_remove(&mut self, id: SwitchId, function: FunctionId, branch: Address) {
        match self {
            Self::Persistent(table) => table.publish_remove(id, function, branch),
            Self::Transient(table) => table.publish_remove(id, function, branch),
        }
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(p) => p.flush(),
            Self::Transient(t) => t.flush(),
        }
    }

    pub fn insert<F>(&mut self, branch: Address, f: F) -> Result<SwitchId, SwitchTableError>
    where
        F: FnOnce(SwitchId, Address) -> Result<Switch, SwitchTableError>,
    {
        match self {
            Self::Persistent(p) => p.insert(branch, f),
            Self::Transient(t) => t.insert(branch, f),
        }
    }

    pub fn get_by_id(&self, id: SwitchId) -> Option<SwitchRef<'_>> {
        self.try_get_by_id(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_id(&self, id: SwitchId) -> Result<Option<SwitchRef<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_by_id(id)?.map(EntityRef::cached)),
            Self::Transient(t) => Ok(t.get_by_id(id).map(EntityRef::borrowed)),
        }
    }

    pub fn get_by_branch(&self, branch: Address) -> Option<SwitchRef<'_>> {
        self.try_get_by_branch(branch)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_branch(
        &self,
        branch: Address,
    ) -> Result<Option<SwitchRef<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_by_branch(branch)?.map(EntityRef::cached)),
            Self::Transient(t) => Ok(t.get_by_branch(branch).map(EntityRef::borrowed)),
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

    pub fn modify_by_id<R>(&mut self, id: SwitchId, f: impl FnOnce(&mut Switch) -> R) -> Option<R> {
        self.try_modify_by_id(id, f)
            .unwrap_or_else(|error| error.into_fatal())
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
        self.try_modify_by_branch(branch, f)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_modify_by_branch<R>(
        &mut self,
        branch: Address,
        f: impl FnOnce(&mut Switch) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_modify_by_branch(branch, f),
            Self::Transient(t) => Ok(t.modify_by_branch(branch, f)),
        }
    }

    pub fn remove_by_id(&mut self, id: SwitchId) -> bool {
        self.try_remove_by_id(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove_by_id(&mut self, id: SwitchId) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_remove_by_id(id),
            Self::Transient(t) => Ok(t.remove_by_id(id)),
        }
    }

    pub fn remove_by_branch(&mut self, branch: Address) -> bool {
        self.try_remove_by_branch(branch)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove_by_branch(&mut self, branch: Address) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_remove_by_branch(branch),
            Self::Transient(t) => Ok(t.remove_by_branch(branch)),
        }
    }

    pub fn branches(&self) -> Box<dyn Iterator<Item = Address> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.branches()),
            Self::Transient(t) => Box::new(t.branches()),
        }
    }

    pub fn entries_after(
        &self,
        after: Option<Address>,
    ) -> Box<dyn Iterator<Item = SwitchRef<'_>> + '_> {
        match self {
            Self::Persistent(p) => Box::new(p.entries_after(after).map(EntityRef::cached)),
            Self::Transient(t) => Box::new(t.entries_after(after).map(EntityRef::borrowed)),
        }
    }

    pub fn iter(&self) -> Box<dyn Iterator<Item = SwitchRef<'_>> + '_> {
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
    use crate::storage::entities::InMemoryEntityStorage;

    fn function(index: usize) -> FunctionId {
        FunctionId::from_index(index)
    }

    fn tables() -> [SwitchTable; 2] {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        [
            SwitchTable::new_transient(),
            SwitchTable::new(storage, 64 * 1024).unwrap(),
        ]
    }

    #[test]
    fn indexes_switches_by_owning_function() {
        let owner = function(0);
        let other = function(1);
        let placements = [
            (Address::from(0x1000u64), owner),
            (Address::from(0x2000u64), owner),
            (Address::from(0x3000u64), other),
        ];

        for mut table in tables() {
            for (branch, owning) in placements {
                table
                    .insert(branch, |id, branch| {
                        Ok(Switch::new(id, branch, SwitchModel::Explicit).with_function(owning))
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

            table.modify_by_branch(Address::from(0x2000u64), |switch| {
                switch.set_function(other);
            });
            assert!(table.branches_of_function(owner).next().is_none());
            assert_eq!(
                table.branches_of_function(other).collect::<Vec<_>>(),
                vec![Address::from(0x2000u64), Address::from(0x3000u64)]
            );
        }
    }

    #[test]
    fn entry_iteration_resumes_after_branch() {
        let branches = [
            Address::from(0x1000u64),
            Address::from(0x2000u64),
            Address::from(0x3000u64),
        ];

        for mut table in tables() {
            for branch in branches {
                table
                    .insert(branch, |id, branch| {
                        Ok(Switch::new(id, branch, SwitchModel::Explicit))
                    })
                    .unwrap();
            }

            assert_eq!(
                table
                    .entries_after(Some(branches[0]))
                    .map(|switch| switch.branch())
                    .collect::<Vec<_>>(),
                branches[1..]
            );
        }
    }

    #[test]
    fn stale_id_does_not_remove_reused_slot() {
        let mut table = SwitchTable::new_transient();
        let first_branch = Address::from(0x1000u64);
        let second_branch = Address::from(0x2000u64);
        let first = table
            .insert(first_branch, |id, branch| {
                Ok(Switch::new(id, branch, SwitchModel::Explicit))
            })
            .unwrap();

        assert!(table.remove_by_id(first));

        let second = table
            .insert(second_branch, |id, branch| {
                Ok(Switch::new(id, branch, SwitchModel::Explicit))
            })
            .unwrap();

        assert_eq!(first.index(), second.index());
        assert_ne!(first, second);
        assert!(!table.remove_by_id(first));
        assert_eq!(
            table.get_by_id(second).map(|switch| switch.branch()),
            Some(second_branch)
        );
    }
}
