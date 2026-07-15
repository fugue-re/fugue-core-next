use std::ops::RangeBounds;
use std::sync::Arc;

use super::{SymbolEntry, SymbolIndex, SymbolProperties, SymbolTableSelector};
use crate::ir::{Address, Id, symbol::Symbol};
use crate::storage::entities::schema::ENTITY_SYMBOL_TABLE_ID;
use crate::storage::entities::{Entity, EntityId, EntityRef, ProjectEntity, WriteBackWorker};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::{EntityStorage, EntityStorageError};

mod persistent;
mod transient;

pub use persistent::SymbolTable as PersistentSymbolTable;
pub use transient::SymbolTable as TransientSymbolTable;

pub type SymbolRef<'a> = EntityRef<'a, SymbolEntry>;

const SYMBOL_TABLE_VERSION: u32 = 1;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct SymbolTableHeader {
    version: u32,
}

impl Entity for SymbolTableHeader {
    const ID: EntityId = ENTITY_SYMBOL_TABLE_ID;
}

pub enum SymbolTable {
    Persistent(PersistentSymbolTable),
    Transient(TransientSymbolTable),
}

enum SymbolTableAllocation {
    Persistent(persistent::Allocation),
    Transient(transient::Allocation),
}

pub(crate) struct SymbolTableRevert {
    allocation: SymbolTableAllocation,
    entries: Vec<(Id<Symbol>, SymbolEntry)>,
    touched: Vec<Id<Symbol>>,
}

impl SymbolTableRevert {
    fn new(
        table: &SymbolTable,
        ids: impl IntoIterator<Item = Id<Symbol>>,
        max_pops: usize,
    ) -> Self {
        let mut touched = Vec::new();
        let mut entries = Vec::new();

        for id in ids {
            if touched.contains(&id) {
                continue;
            }

            if let Some(entry) = table.get_by_id(id) {
                entries.push((id, entry.clone()));
            }
            touched.push(id);
        }

        Self {
            allocation: table.allocation_checkpoint(max_pops),
            entries,
            touched,
        }
    }

    pub(crate) fn touch(&mut self, id: Id<Symbol>) {
        if !self.touched.contains(&id) {
            self.touched.push(id);
        }
    }

    pub(crate) fn restore(self, table: &mut SymbolTable) -> Result<(), EntityStorageError> {
        for id in self.touched {
            table.clear_entry(id)?;
        }

        table.restore_allocation(self.allocation);

        for (id, entry) in self.entries {
            table.restore_entry(id, entry)?;
        }

        Ok(())
    }
}

impl SymbolTable {
    pub fn new(entities: EntityStorage, cache_bytes: usize) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentSymbolTable::new(
            entities,
            cache_bytes,
        )?))
    }

    pub fn new_with(
        entities: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentSymbolTable::new_with(
            entities,
            worker,
            cache_bytes,
        )?))
    }

    pub fn new_transient() -> Self {
        Self::Transient(TransientSymbolTable::new())
    }

    pub fn persisted(storage: &EntityStorage) -> Result<bool, EntityStorageError> {
        storage.contains::<ProjectEntity, SymbolTableHeader>(&ProjectEntity::SymbolTable)
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(p) => p.flush(),
            Self::Transient(_) => Ok(()),
        }
    }

    fn allocation_checkpoint(&self, max_pops: usize) -> SymbolTableAllocation {
        match self {
            Self::Persistent(p) => {
                SymbolTableAllocation::Persistent(p.allocation_checkpoint(max_pops))
            }
            Self::Transient(t) => {
                SymbolTableAllocation::Transient(t.allocation_checkpoint(max_pops))
            }
        }
    }

    fn restore_allocation(&mut self, allocation: SymbolTableAllocation) {
        match (self, allocation) {
            (Self::Persistent(p), SymbolTableAllocation::Persistent(allocation)) => {
                p.restore_allocation(allocation)
            }
            (Self::Transient(t), SymbolTableAllocation::Transient(allocation)) => {
                t.restore_allocation(allocation)
            }
            _ => unreachable!("symbol table allocation variant mismatch"),
        }
    }

    fn restore_entry(
        &mut self,
        id: Id<Symbol>,
        entry: SymbolEntry,
    ) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(p) => p.restore_entry(id, entry),
            Self::Transient(t) => {
                t.restore_entry(id, entry);
                Ok(())
            }
        }
    }

    fn clear_entry(&mut self, id: Id<Symbol>) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.clear_entry(id),
            Self::Transient(t) => Ok(t.clear_entry(id)),
        }
    }

    pub(crate) fn insert_revert(
        &self,
        index: SymbolIndex,
        entry: &SymbolEntry,
    ) -> SymbolTableRevert {
        let touched = match self {
            Self::Persistent(p) => p
                .touched_by_insert(index, entry)
                .unwrap_or_else(|error| error.into_fatal()),
            Self::Transient(t) => t.touched_by_insert(index, entry),
        };
        SymbolTableRevert::new(self, touched, 1)
    }

    pub(crate) fn remove_symbol_revert(&self, symbol: impl AsRef<str>) -> SymbolTableRevert {
        let ids = match self {
            Self::Persistent(p) => p.ids_by_symbol(symbol),
            Self::Transient(t) => t.ids_by_symbol(symbol),
        };
        SymbolTableRevert::new(self, ids, 0)
    }

    pub(crate) fn remove_address_revert(&self, address: Address) -> SymbolTableRevert {
        let ids = match self {
            Self::Persistent(p) => p.ids_by_address(address),
            Self::Transient(t) => t.ids_by_address(address),
        };
        SymbolTableRevert::new(self, ids, 0)
    }

    pub(crate) fn remove_id_revert(&self, id: Id<Symbol>) -> SymbolTableRevert {
        SymbolTableRevert::new(self, [id], 0)
    }

    pub(crate) fn remove_index_revert(&self, index: SymbolIndex) -> SymbolTableRevert {
        let id = match self {
            Self::Persistent(p) => p.id_by_index(index),
            Self::Transient(t) => t.id_by_index(index),
        };
        SymbolTableRevert::new(self, id, 0)
    }

    pub fn insert(
        &mut self,
        index: SymbolIndex,
        address: impl Into<Address>,
        symbol: impl Into<Symbol>,
        properties: SymbolProperties,
    ) -> (bool, Id<Symbol>) {
        let address = address.into();
        let symbol = symbol.into();
        match self {
            Self::Persistent(p) => p
                .insert(index, address, symbol, properties)
                .unwrap_or_else(|error| error.into_fatal()),
            Self::Transient(t) => t.insert(index, address, symbol, properties),
        }
    }

    pub fn get(
        &self,
        symbol: impl AsRef<str>,
    ) -> Option<Box<dyn Iterator<Item = (Id<Symbol>, SymbolRef<'_>)> + '_>> {
        match self {
            Self::Persistent(p) => p.get(symbol).map(|iter| {
                Box::new(iter.map(|(id, entry)| (id, EntityRef::cached(entry))))
                    as Box<dyn Iterator<Item = _>>
            }),
            Self::Transient(t) => t.get(symbol).map(|iter| {
                Box::new(iter.map(|(id, entry)| (id, EntityRef::borrowed(entry))))
                    as Box<dyn Iterator<Item = _>>
            }),
        }
    }

    pub fn get_first(&self, symbol: impl AsRef<str>) -> Option<(Id<Symbol>, SymbolRef<'_>)> {
        self.get(symbol).and_then(|mut iter| iter.next())
    }

    pub fn get_by_id(&self, id: Id<Symbol>) -> Option<SymbolRef<'_>> {
        match self {
            Self::Persistent(p) => p.get_by_id(id).map(EntityRef::cached),
            Self::Transient(t) => t.get_by_id(id).map(EntityRef::borrowed),
        }
    }

    pub fn get_by_index(&self, index: SymbolIndex) -> Option<(Id<Symbol>, SymbolRef<'_>)> {
        match self {
            Self::Persistent(p) => p
                .get_by_index(index)
                .map(|(id, entry)| (id, EntityRef::cached(entry))),
            Self::Transient(t) => t
                .get_by_index(index)
                .map(|(id, entry)| (id, EntityRef::borrowed(entry))),
        }
    }

    pub fn get_by_address(
        &self,
        address: impl Into<Address>,
    ) -> Box<dyn Iterator<Item = (Id<Symbol>, SymbolRef<'_>)> + '_> {
        let address = address.into();
        match self {
            Self::Persistent(p) => Box::new(
                p.get_by_address(address)
                    .map(|(id, entry)| (id, EntityRef::cached(entry))),
            ),
            Self::Transient(t) => Box::new(
                t.get_by_address(address)
                    .map(|(id, entry)| (id, EntityRef::borrowed(entry))),
            ),
        }
    }

    pub fn get_first_by_address(
        &self,
        address: impl Into<Address>,
    ) -> Option<(Id<Symbol>, SymbolRef<'_>)> {
        self.get_by_address(address).next()
    }

    pub fn contains(&self, symbol: impl AsRef<str>) -> bool {
        match self {
            Self::Persistent(p) => p.contains(symbol),
            Self::Transient(t) => t.contains(symbol),
        }
    }

    pub fn contains_index(&self, index: SymbolIndex) -> bool {
        match self {
            Self::Persistent(p) => p.contains_index(index),
            Self::Transient(t) => t.contains_index(index),
        }
    }

    pub fn contains_address(&self, address: impl Into<Address>) -> bool {
        let address = address.into();
        match self {
            Self::Persistent(p) => p.contains_address(address),
            Self::Transient(t) => t.contains_address(address),
        }
    }

    pub fn iter(&self) -> Box<dyn Iterator<Item = (Id<Symbol>, SymbolRef<'_>)> + '_> {
        match self {
            Self::Persistent(p) => {
                Box::new(p.iter().map(|(id, entry)| (id, EntityRef::cached(entry))))
            }
            Self::Transient(t) => {
                Box::new(t.iter().map(|(id, entry)| (id, EntityRef::borrowed(entry))))
            }
        }
    }

    pub fn iter_by_selector(
        &self,
        selector: SymbolTableSelector,
    ) -> Box<dyn Iterator<Item = (Id<Symbol>, SymbolRef<'_>)> + '_> {
        match self {
            Self::Persistent(p) => Box::new(
                p.iter_by_selector(selector)
                    .map(|(id, entry)| (id, EntityRef::cached(entry))),
            ),
            Self::Transient(t) => Box::new(
                t.iter_by_selector(selector)
                    .map(|(id, entry)| (id, EntityRef::borrowed(entry))),
            ),
        }
    }

    pub fn iter_by_address(&self) -> Box<dyn Iterator<Item = (Id<Symbol>, SymbolRef<'_>)> + '_> {
        match self {
            Self::Persistent(p) => Box::new(
                p.iter_by_address()
                    .map(|(id, entry)| (id, EntityRef::cached(entry))),
            ),
            Self::Transient(t) => Box::new(
                t.iter_by_address()
                    .map(|(id, entry)| (id, EntityRef::borrowed(entry))),
            ),
        }
    }

    pub fn range_by_address<R>(
        &self,
        range: R,
    ) -> Box<dyn Iterator<Item = (Id<Symbol>, SymbolRef<'_>)> + '_>
    where
        R: RangeBounds<Address>,
    {
        match self {
            Self::Persistent(p) => Box::new(
                p.range_by_address(range)
                    .map(|(id, entry)| (id, EntityRef::cached(entry))),
            ),
            Self::Transient(t) => Box::new(
                t.range_by_address(range)
                    .map(|(id, entry)| (id, EntityRef::borrowed(entry))),
            ),
        }
    }

    pub fn iter_by_index(
        &self,
    ) -> Box<dyn Iterator<Item = (SymbolIndex, Id<Symbol>, SymbolRef<'_>)> + '_> {
        match self {
            Self::Persistent(p) => Box::new(
                p.iter_by_index()
                    .map(|(index, id, entry)| (index, id, EntityRef::cached(entry))),
            ),
            Self::Transient(t) => Box::new(
                t.iter_by_index()
                    .map(|(index, id, entry)| (index, id, EntityRef::borrowed(entry))),
            ),
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

    pub fn remove(&mut self, symbol: impl AsRef<str>) -> usize {
        match self {
            Self::Persistent(p) => p.remove(symbol).unwrap_or_else(|error| error.into_fatal()),
            Self::Transient(t) => t.remove(symbol),
        }
    }

    pub fn remove_by_address(&mut self, address: impl Into<Address>) -> usize {
        let address = address.into();
        match self {
            Self::Persistent(p) => p
                .remove_by_address(address)
                .unwrap_or_else(|error| error.into_fatal()),
            Self::Transient(t) => t.remove_by_address(address),
        }
    }

    pub fn remove_by_id(&mut self, id: Id<Symbol>) -> bool {
        match self {
            Self::Persistent(p) => p
                .remove_by_id(id)
                .unwrap_or_else(|error| error.into_fatal()),
            Self::Transient(t) => t.remove_by_id(id),
        }
    }

    pub fn remove_by_index(&mut self, index: SymbolIndex) -> bool {
        match self {
            Self::Persistent(p) => p
                .remove_by_index(index)
                .unwrap_or_else(|error| error.into_fatal()),
            Self::Transient(t) => t.remove_by_index(index),
        }
    }
}

impl PersistableProjectEntity for SymbolTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(_) => storage.insert(
                &ProjectEntity::SymbolTable,
                &SymbolTableHeader {
                    version: SYMBOL_TABLE_VERSION,
                },
            ),
            Self::Transient(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "sqlite")]
    use tempfile::TempDir;

    use super::*;
    use crate::ir::symbol::SymbolTableSelector;
    #[cfg(feature = "sqlite")]
    use crate::storage::PERSISTENT;
    use crate::storage::entities::InMemoryEntityStorage;
    #[cfg(feature = "sqlite")]
    use crate::storage::entities::SqliteEntityStorage;

    fn persistent_table() -> SymbolTable {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        SymbolTable::new(storage, 64 * 1024).unwrap()
    }

    #[test]
    fn test_persistent_free_list_and_referent_merge() {
        let mut table = persistent_table();
        let sel = SymbolTableSelector::new(0);

        let (inserted1, id1) = table.insert(
            SymbolIndex::new(sel, 1),
            Address::from(0x1000u32),
            "symbol1",
            SymbolProperties::LOCAL,
        );
        assert!(inserted1);

        let (inserted2, _) = table.insert(
            SymbolIndex::new(sel, 2),
            Address::from(0x2000u32),
            "symbol2",
            SymbolProperties::LOCAL,
        );
        assert!(inserted2);
        assert_eq!(table.len(), 2);

        assert!(table.remove_by_id(id1));
        assert_eq!(table.len(), 1);

        let (inserted3, id3) = table.insert(
            SymbolIndex::new(sel, 3),
            Address::from(0x3000u32),
            "symbol3",
            SymbolProperties::LOCAL,
        );
        assert!(inserted3);
        assert_eq!(table.len(), 2);
        assert_eq!(id1.index(), id3.index());
        assert_eq!(id1.generation() + 1, id3.generation());
        assert!(table.get_by_id(id1).is_none());
        assert!(!table.remove_by_id(id1));

        let (inserted4, id4) = table.insert(
            SymbolIndex::new(sel, 4),
            Address::from(0x3000u32),
            "symbol3",
            SymbolProperties::LOCAL,
        );
        assert!(!inserted4);
        assert_eq!(id3, id4);
        assert_eq!(table.len(), 2);

        let (inserted5, _) = table.insert(
            SymbolIndex::new(sel, 5),
            Address::from(0x3000u32),
            "symbol4",
            SymbolProperties::LOCAL,
        );
        assert!(inserted5);
        assert_eq!(table.len(), 3);

        assert_eq!(table.remove("symbol3"), 1);
        assert_eq!(table.len(), 2);
        assert_eq!(table.remove_by_address(Address::from(0x3000u32)), 1);
        assert_eq!(table.len(), 1);
        assert!(table.get_first("symbol2").is_some());
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn test_persistent_reopen_sqlite() {
        let sel = SymbolTableSelector::new(0);
        let dir = TempDir::new().unwrap();

        {
            let storage =
                EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
            let mut table = SymbolTable::new(storage.clone(), 64 * 1024).unwrap();

            let (_, hole) = table.insert(
                SymbolIndex::new(sel, 1),
                Address::from(0x1000u32),
                "alpha",
                SymbolProperties::LOCAL,
            );
            table.insert(
                SymbolIndex::new(sel, 2),
                Address::from(0x2000u32),
                "beta",
                SymbolProperties::LOCAL,
            );
            table.insert(
                SymbolIndex::new(sel, 3),
                Address::from(0x3000u32),
                "gamma",
                SymbolProperties::LOCAL,
            );
            assert!(table.remove_by_id(hole));

            table.persist(&storage).unwrap();
            table.flush().unwrap();
            assert!(SymbolTable::persisted(&storage).unwrap());
        }

        let storage =
            EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
        let reloaded = SymbolTable::new(storage, 64 * 1024).unwrap();

        assert_eq!(reloaded.len(), 2);
        assert!(reloaded.get_first("beta").is_some());
        assert!(reloaded.get_first("alpha").is_none());
        assert!(reloaded.contains_address(Address::from(0x3000u32)));
    }

    #[test]
    fn test_revert_restores_previous_entries() {
        let mut table = persistent_table();
        let sel = SymbolTableSelector::new(0);

        let (_, id) = table.insert(
            SymbolIndex::new(sel, 1),
            Address::from(0x1000u32),
            "alpha",
            SymbolProperties::LOCAL,
        );

        let revert = table.remove_id_revert(id);
        assert!(table.remove_by_id(id));
        assert_eq!(table.len(), 0);

        revert.restore(&mut table).unwrap();
        assert_eq!(table.len(), 1);
        let (restored_id, entry) = table.get_first("alpha").unwrap();
        assert_eq!(restored_id, id);
        assert_eq!(entry.address(), Address::from(0x1000u32));
    }
}
