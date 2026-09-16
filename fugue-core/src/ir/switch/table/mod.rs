use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::ops::Bound;
use std::sync::Arc;

use thiserror::Error;

use crate::ir::switch::{Switch, SwitchId};
use crate::ir::{Address, FunctionId, IdSet};
use crate::storage::entities::cursor::cursor_bound;
use crate::storage::entities::schema::ENTITY_SWITCH_TABLE_ID;
use crate::storage::entities::{
    Entity, EntityId, EntityRef, EntityWrite, EntityWriteBatch, ProjectEntity, WriteBackWorker,
};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::{EntityStorage, EntityStorageError};

pub(crate) const ATTRIBUTE_SWITCH_CACHE_SIZE: &str = "storage.entities.switch.cache_size";
pub(crate) const DEFAULT_SWITCH_CACHE_BYTES: usize = 8 * 1024 * 1024;

mod persistent;
use persistent::SwitchTable as PersistentSwitchTable;

mod transient;
use transient::SwitchTable as TransientSwitchTable;

pub type SwitchRef<'a> = EntityRef<'a, Switch>;

const SWITCH_TABLE_VERSION: u32 = 1;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct SwitchTableHeader {
    format_version: u32,
}

impl Entity for SwitchTableHeader {
    const ID: EntityId = ENTITY_SWITCH_TABLE_ID;
}

struct SwitchIndex {
    branches: BTreeMap<Address, SwitchId>,
    by_function: BTreeMap<FunctionId, BTreeSet<Address>>,
}

impl SwitchIndex {
    fn new() -> Self {
        Self {
            branches: BTreeMap::new(),
            by_function: BTreeMap::new(),
        }
    }

    fn id_by_branch(&self, branch: Address) -> Option<SwitchId> {
        self.branches.get(&branch).copied()
    }

    fn contains(&self, branch: Address) -> bool {
        self.branches.contains_key(&branch)
    }

    fn branches_for_function(&self, function: FunctionId) -> impl Iterator<Item = Address> + '_ {
        self.by_function
            .get(&function)
            .into_iter()
            .flatten()
            .copied()
    }

    fn branches(&self) -> impl Iterator<Item = Address> + '_ {
        self.branches.keys().copied()
    }

    fn is_empty(&self) -> bool {
        self.branches.is_empty()
    }

    fn len(&self) -> usize {
        self.branches.len()
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

    fn unlink(&mut self, function: FunctionId, branch: Address) {
        if let Some(branches) = self.by_function.get_mut(&function) {
            branches.remove(&branch);
            if branches.is_empty() {
                self.by_function.remove(&function);
            }
        }
    }
}

#[derive(Default)]
pub(crate) struct SwitchTableStaging {
    cancelled_switches: IdSet<Switch>,
    staged_switches: BTreeMap<Address, Option<Switch>>,
    switch_reservations: Vec<SwitchId>,
}

pub(crate) struct PreparedSwitchBatch {
    cancelled_switches: IdSet<Switch>,
    records: Vec<PreparedSwitchRecord>,
    switch_reservations: Vec<SwitchId>,
}

struct PreparedSwitchRecord {
    branch: Address,
    encoded_size: usize,
    previous: Option<PreviousSwitch>,
    switch: Option<Switch>,
}

#[derive(Clone, Copy)]
struct PreviousSwitch {
    function: FunctionId,
    id: SwitchId,
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
    pub fn new_transient() -> Self {
        Self::Transient(TransientSwitchTable::new())
    }

    pub fn new_persistent(
        entities: EntityStorage,
        cache_bytes: usize,
        worker: Arc<WriteBackWorker>,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentSwitchTable::new(
            entities,
            cache_bytes,
            worker,
        )?))
    }

    pub fn contains(&self, branch: Address) -> bool {
        match self {
            Self::Persistent(table) => table.contains(branch),
            Self::Transient(table) => table.contains(branch),
        }
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

    pub fn get_by_id(&self, id: SwitchId) -> Option<SwitchRef<'_>> {
        self.try_get_by_id(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_id(&self, id: SwitchId) -> Result<Option<SwitchRef<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(table) => Ok(table.try_get_by_id(id)?.map(EntityRef::cached)),
            Self::Transient(table) => Ok(table.get_by_id(id).map(EntityRef::borrowed)),
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
            Self::Persistent(table) => Ok(table.try_get_by_branch(branch)?.map(EntityRef::cached)),
            Self::Transient(table) => Ok(table.get_by_branch(branch).map(EntityRef::borrowed)),
        }
    }

    pub fn branches_for_function(
        &self,
        function: FunctionId,
    ) -> Box<dyn Iterator<Item = Address> + '_> {
        match self {
            Self::Persistent(table) => Box::new(table.branches_for_function(function)),
            Self::Transient(table) => Box::new(table.branches_for_function(function)),
        }
    }

    pub fn branches(&self) -> Box<dyn Iterator<Item = Address> + '_> {
        match self {
            Self::Persistent(table) => Box::new(table.branches()),
            Self::Transient(table) => Box::new(table.branches()),
        }
    }

    pub fn entries_after(
        &self,
        after: Option<Address>,
    ) -> Box<dyn Iterator<Item = SwitchRef<'_>> + '_> {
        match self {
            Self::Persistent(table) => Box::new(table.entries_after(after).map(EntityRef::cached)),
            Self::Transient(table) => Box::new(table.entries_after(after).map(EntityRef::borrowed)),
        }
    }

    pub fn iter(&self) -> Box<dyn Iterator<Item = SwitchRef<'_>> + '_> {
        match self {
            Self::Persistent(table) => Box::new(table.iter().map(EntityRef::cached)),
            Self::Transient(table) => Box::new(table.iter().map(EntityRef::borrowed)),
        }
    }

    pub(crate) fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent(_))
    }

    pub(crate) fn pending_id(&self, offset: usize) -> SwitchId {
        match self {
            Self::Persistent(table) => table.pending_id(offset),
            Self::Transient(table) => table.pending_id(offset),
        }
    }

    pub fn insert<F>(&mut self, branch: Address, f: F) -> Result<SwitchId, SwitchTableError>
    where
        F: FnOnce(SwitchId, Address) -> Result<Switch, SwitchTableError>,
    {
        match self {
            Self::Persistent(table) => table.insert(branch, f),
            Self::Transient(table) => table.insert(branch, f),
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
            Self::Persistent(table) => table.try_modify_by_id(id, f),
            Self::Transient(table) => Ok(table.modify_by_id(id, f)),
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
            Self::Persistent(table) => table.try_modify_by_branch(branch, f),
            Self::Transient(table) => Ok(table.modify_by_branch(branch, f)),
        }
    }

    pub fn remove_by_id(&mut self, id: SwitchId) -> bool {
        self.try_remove_by_id(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove_by_id(&mut self, id: SwitchId) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(table) => table.try_remove_by_id(id),
            Self::Transient(table) => Ok(table.remove_by_id(id)),
        }
    }

    pub fn remove_by_branch(&mut self, branch: Address) -> bool {
        self.try_remove_by_branch(branch)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove_by_branch(&mut self, branch: Address) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(table) => table.try_remove_by_branch(branch),
            Self::Transient(table) => Ok(table.remove_by_branch(branch)),
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
        reservations: &[SwitchId],
        releases: &[SwitchId],
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
        reservations: &[SwitchId],
        cancelled: &IdSet<Switch>,
        added: usize,
        removed: usize,
    ) {
        match self {
            Self::Persistent(table) => table.publish_allocations(reservations, added, removed),
            Self::Transient(table) => {
                for &id in reservations {
                    table.publish_reservation(id);
                }
                let mut cancelled = cancelled.iter().collect::<Vec<_>>();
                cancelled.sort_unstable();
                for id in cancelled {
                    table.publish_release(id);
                }
            }
        }
    }

    pub(crate) fn publish_upsert(
        &mut self,
        switch: Switch,
        previous_function: Option<FunctionId>,
        encoded_size: usize,
    ) {
        match self {
            Self::Persistent(table) => {
                table.publish_upsert(switch, previous_function, encoded_size)
            }
            Self::Transient(table) => table.publish_upsert(switch, previous_function),
        }
    }

    pub(crate) fn publish_remove(&mut self, id: SwitchId, function: FunctionId, branch: Address) {
        match self {
            Self::Persistent(table) => table.publish_remove(id, function, branch),
            Self::Transient(table) => table.publish_remove(id, function, branch),
        }
    }
}

impl SwitchTableStaging {
    pub(crate) fn get_by_branch<'a>(
        &'a self,
        switches: &'a SwitchTable,
        branch: Address,
    ) -> Result<Option<SwitchRef<'a>>, EntityStorageError> {
        match self.staged_switches.get(&branch) {
            Some(Some(switch)) => Ok(Some(EntityRef::borrowed(switch))),
            Some(None) => Ok(None),
            None => switches.try_get_by_branch(branch),
        }
    }

    pub(crate) fn branches_for_function(
        &self,
        switches: &SwitchTable,
        function: FunctionId,
    ) -> BTreeSet<Address> {
        let mut branches = switches
            .branches_for_function(function)
            .collect::<BTreeSet<_>>();
        for (&branch, switch) in &self.staged_switches {
            match switch {
                Some(switch) if switch.function() == function => {
                    branches.insert(branch);
                }
                Some(_) | None => {
                    branches.remove(&branch);
                }
            }
        }
        branches
    }

    pub(crate) fn insert(&mut self, switch: Switch) {
        self.staged_switches.insert(switch.branch(), Some(switch));
    }

    pub(crate) fn remove(
        &mut self,
        switches: &SwitchTable,
        branch: Address,
    ) -> Result<Option<Switch>, EntityStorageError> {
        let Some(switch) = self
            .get_by_branch(switches, branch)?
            .map(|switch| switch.as_ref().clone())
        else {
            return Ok(None);
        };

        if switches.try_get_by_branch(branch)?.is_some() {
            self.staged_switches.insert(branch, None);
        } else {
            self.staged_switches.remove(&branch);
            self.cancelled_switches.insert(switch.id());
        }
        Ok(Some(switch))
    }

    pub(crate) fn reserve_id(&mut self, switches: &SwitchTable) -> SwitchId {
        let id = switches.pending_id(self.switch_reservations.len());
        self.switch_reservations.push(id);
        id
    }

    pub(crate) fn prepare(
        self,
        switches: &SwitchTable,
    ) -> Result<(PreparedSwitchBatch, EntityWriteBatch), EntityStorageError> {
        let Self {
            cancelled_switches,
            staged_switches,
            switch_reservations,
        } = self;
        let persistent = switches.is_persistent();
        let mut records = Vec::with_capacity(staged_switches.len());
        let mut added = 0usize;
        let mut removed = 0usize;
        let mut releases = cancelled_switches.iter().collect::<Vec<_>>();
        let mut writes =
            EntityWriteBatch::with_capacity(if persistent { staged_switches.len() } else { 0 });

        for (branch, switch) in staged_switches {
            let previous = switches.try_get_by_branch(branch)?;
            if previous
                .as_ref()
                .is_some_and(|previous| switch.as_ref() == Some(previous.as_ref()))
            {
                continue;
            }
            if switch.is_none() && previous.is_none() {
                continue;
            }
            let previous = previous.map(|switch| PreviousSwitch {
                function: switch.function(),
                id: switch.id(),
            });
            match &switch {
                Some(entry) => {
                    if previous.is_none() {
                        added += 1;
                    }
                    let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(entry)
                        .map_err(EntityStorageError::encode)?;
                    let encoded_size = encoded.len();
                    if persistent {
                        writes.push(EntityWrite::insert_archived(
                            Switch::ID.key_for(&entry.id()),
                            encoded,
                        ));
                    }
                    records.push(PreparedSwitchRecord {
                        branch,
                        encoded_size,
                        previous,
                        switch,
                    });
                }
                None => {
                    let id = previous
                        .expect("prepared switch removal has a previous switch")
                        .id;
                    removed += 1;
                    releases.push(id);
                    if persistent {
                        writes.push(EntityWrite::remove(Switch::ID.key_for(&id)));
                    }
                    records.push(PreparedSwitchRecord {
                        branch,
                        encoded_size: 0,
                        previous,
                        switch: None,
                    });
                }
            }
        }

        releases.sort_unstable();
        switches.append_allocation_writes(
            &switch_reservations,
            &releases,
            added,
            removed,
            &mut writes,
        )?;

        Ok((
            PreparedSwitchBatch {
                cancelled_switches,
                records,
                switch_reservations,
            },
            writes,
        ))
    }
}

impl PreparedSwitchBatch {
    pub(crate) fn changes(&self) -> impl Iterator<Item = (Address, bool)> + '_ {
        self.records
            .iter()
            .map(|record| (record.branch, record.switch.is_some()))
    }

    pub(crate) fn publish(self, switches: &mut SwitchTable) {
        let Self {
            cancelled_switches,
            records,
            switch_reservations,
        } = self;
        let added = records
            .iter()
            .filter(|record| record.switch.is_some() && record.previous.is_none())
            .count();
        let removed = records
            .iter()
            .filter(|record| record.switch.is_none())
            .count();
        switches.publish_allocations(&switch_reservations, &cancelled_switches, added, removed);
        for record in records {
            match record.switch {
                Some(switch) => switches.publish_upsert(
                    switch,
                    record.previous.map(|previous| previous.function),
                    record.encoded_size,
                ),
                None => {
                    let previous = record
                        .previous
                        .expect("prepared switch removal has a previous switch");
                    switches.publish_remove(previous.id, previous.function, record.branch);
                }
            }
        }
    }
}

impl PersistableProjectEntity for SwitchTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(_) => storage.insert(
                &ProjectEntity::SwitchTable,
                &SwitchTableHeader {
                    format_version: SWITCH_TABLE_VERSION,
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
        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        [
            SwitchTable::new_transient(),
            SwitchTable::new_persistent(storage, 64 * 1024, worker).unwrap(),
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

            let mut owned = table.branches_for_function(owner).collect::<Vec<_>>();
            owned.sort();
            assert_eq!(
                owned,
                vec![Address::from(0x1000u64), Address::from(0x2000u64)]
            );
            assert_eq!(
                table.branches_for_function(other).collect::<Vec<_>>(),
                vec![Address::from(0x3000u64)]
            );

            table.remove_by_branch(Address::from(0x1000u64));
            assert_eq!(
                table.branches_for_function(owner).collect::<Vec<_>>(),
                vec![Address::from(0x2000u64)]
            );

            table.modify_by_branch(Address::from(0x2000u64), |switch| {
                switch.set_function(other);
            });
            assert!(table.branches_for_function(owner).next().is_none());
            assert_eq!(
                table.branches_for_function(other).collect::<Vec<_>>(),
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
