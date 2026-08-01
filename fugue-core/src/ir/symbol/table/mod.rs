use std::ops::RangeBounds;
use std::sync::Arc;

use smallvec::SmallVec;

use super::{SymbolEntry, SymbolId, SymbolIndex, SymbolProperties, SymbolTableSelector};
use crate::ir::Address;
use crate::ir::symbol::Symbol;
use crate::storage::entities::schema::ENTITY_SYMBOL_TABLE_ID;
use crate::storage::entities::{
    Entity, EntityId, EntityRef, EntityWriteBatch, ProjectEntity, WriteBackWorker,
};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::{EntityStorage, EntityStorageError};

mod persistent;
mod transient;

use persistent::SymbolTable as PersistentSymbolTable;
pub use transient::SymbolTable as TransientSymbolTable;

pub type SymbolRef<'a> = EntityRef<'a, SymbolEntry>;

pub(crate) struct SymbolIndexState {
    address: Address,
    indices: SmallVec<[SymbolIndex; 2]>,
    symbol: Symbol,
}

impl SymbolIndexState {
    pub(crate) fn new(entry: &SymbolEntry) -> Self {
        Self {
            address: entry.address(),
            indices: entry.indices().into(),
            symbol: entry.symbol(),
        }
    }

    pub(crate) fn address(&self) -> Address {
        self.address
    }

    pub(crate) fn symbol(&self) -> Symbol {
        self.symbol
    }

    fn indices(&self) -> &[SymbolIndex] {
        &self.indices
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolInsertion {
    id: SymbolId,
    is_new: bool,
}

impl SymbolInsertion {
    const fn new(id: SymbolId, is_new: bool) -> Self {
        Self { id, is_new }
    }

    pub const fn id(&self) -> SymbolId {
        self.id
    }

    pub const fn is_new(&self) -> bool {
        self.is_new
    }
}

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

impl SymbolTable {
    pub fn new(entities: EntityStorage, cache_bytes: usize) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentSymbolTable::new(
            entities,
            cache_bytes,
        )?))
    }

    pub fn with_worker(
        entities: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentSymbolTable::with_worker(
            entities,
            worker,
            cache_bytes,
        )?))
    }

    pub fn new_transient() -> Self {
        Self::Transient(TransientSymbolTable::new())
    }

    pub(crate) fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent(_))
    }

    pub(crate) fn initialise(
        &mut self,
        symbols: TransientSymbolTable,
    ) -> Result<(), EntityStorageError> {
        assert!(self.is_empty(), "initial symbol table must be empty");
        match self {
            Self::Persistent(table) => table.initialise(symbols),
            Self::Transient(table) => {
                *table = symbols;
                Ok(())
            }
        }
    }

    pub(crate) fn preview_id(&self, offset: usize) -> SymbolId {
        match self {
            Self::Persistent(table) => table.preview_id(offset),
            Self::Transient(table) => table.preview_id(offset),
        }
    }

    pub(crate) fn append_index_writes(
        &self,
        id: SymbolId,
        entry: Option<&SymbolEntry>,
        previous: Option<&SymbolIndexState>,
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        if let Self::Persistent(table) = self {
            table.append_mutation_writes(id, entry, previous, writes)?;
        }
        Ok(())
    }

    pub(crate) fn append_allocator_writes(
        &self,
        reservations: &[SymbolId],
        releases: &[SymbolId],
        added: usize,
        removed: usize,
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        if let Self::Persistent(table) = self {
            table.append_allocator_writes(reservations, releases, added, removed, writes)?;
        }
        Ok(())
    }

    pub(crate) fn publish_prepared(
        &mut self,
        reservations: &[SymbolId],
        cancelled: &[SymbolId],
        added: usize,
        removed: usize,
    ) {
        match self {
            Self::Persistent(table) => table.publish_transition(reservations, added, removed),
            Self::Transient(table) => {
                for &id in reservations {
                    table.publish_reservation(id);
                }
                for &id in cancelled {
                    table.publish_release(id);
                }
            }
        }
    }

    pub(crate) fn publish_upsert(
        &mut self,
        id: SymbolId,
        entry: SymbolEntry,
        previous: Option<&SymbolIndexState>,
        encoded_len: usize,
    ) {
        match self {
            Self::Persistent(table) => table.publish_upsert(id, entry, encoded_len),
            Self::Transient(table) => table.publish_upsert(id, entry, previous),
        }
    }

    pub(crate) fn publish_remove(&mut self, id: SymbolId, previous: &SymbolIndexState) {
        match self {
            Self::Persistent(table) => table.publish_remove(id),
            Self::Transient(table) => table.publish_remove(id, previous),
        }
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

    pub fn insert(
        &mut self,
        index: SymbolIndex,
        address: impl Into<Address>,
        symbol: impl Into<Symbol>,
        properties: SymbolProperties,
    ) -> Result<SymbolInsertion, EntityStorageError> {
        let address = address.into();
        let symbol = symbol.into();
        match self {
            Self::Persistent(p) => p.insert(index, address, symbol, properties),
            Self::Transient(t) => Ok(t.insert(index, address, symbol, properties)),
        }
    }

    pub fn get(
        &self,
        symbol: impl AsRef<str>,
    ) -> Option<Box<dyn Iterator<Item = (SymbolId, SymbolRef<'_>)> + '_>> {
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

    pub fn get_first(&self, symbol: impl AsRef<str>) -> Option<(SymbolId, SymbolRef<'_>)> {
        self.try_get_first(symbol)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_first(
        &self,
        symbol: impl AsRef<str>,
    ) -> Result<Option<(SymbolId, SymbolRef<'_>)>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p
                .try_get_first(symbol)?
                .map(|(id, entry)| (id, EntityRef::cached(entry)))),
            Self::Transient(t) => Ok(t
                .get_first(symbol)
                .map(|(id, entry)| (id, EntityRef::borrowed(entry)))),
        }
    }

    pub fn get_by_id(&self, id: SymbolId) -> Option<SymbolRef<'_>> {
        self.try_get_by_id(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_id(&self, id: SymbolId) -> Result<Option<SymbolRef<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p.try_get_by_id(id)?.map(EntityRef::cached)),
            Self::Transient(t) => Ok(t.get_by_id(id).map(EntityRef::borrowed)),
        }
    }

    pub(crate) fn get_id_by_index(&self, index: SymbolIndex) -> Option<SymbolId> {
        match self {
            Self::Persistent(p) => p.get_id_by_index(index),
            Self::Transient(t) => t.get_id_by_index(index),
        }
    }

    pub fn modify_by_id<R>(
        &mut self,
        id: SymbolId,
        f: impl FnOnce(&mut SymbolEntry) -> R,
    ) -> Option<R> {
        self.try_modify_by_id(id, f)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_modify_by_id<R>(
        &mut self,
        id: SymbolId,
        f: impl FnOnce(&mut SymbolEntry) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.try_modify_by_id(id, f),
            Self::Transient(t) => Ok(t.modify_by_id(id, f)),
        }
    }

    pub fn get_by_index(&self, index: SymbolIndex) -> Option<(SymbolId, SymbolRef<'_>)> {
        self.try_get_by_index(index)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_index(
        &self,
        index: SymbolIndex,
    ) -> Result<Option<(SymbolId, SymbolRef<'_>)>, EntityStorageError> {
        match self {
            Self::Persistent(p) => Ok(p
                .try_get_by_index(index)?
                .map(|(id, entry)| (id, EntityRef::cached(entry)))),
            Self::Transient(t) => Ok(t
                .get_by_index(index)
                .map(|(id, entry)| (id, EntityRef::borrowed(entry)))),
        }
    }

    pub fn get_by_address(
        &self,
        address: impl Into<Address>,
    ) -> Box<dyn Iterator<Item = (SymbolId, SymbolRef<'_>)> + '_> {
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
    ) -> Option<(SymbolId, SymbolRef<'_>)> {
        self.try_get_first_by_address(address)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_first_by_address(
        &self,
        address: impl Into<Address>,
    ) -> Result<Option<(SymbolId, SymbolRef<'_>)>, EntityStorageError> {
        let address = address.into();
        match self {
            Self::Persistent(p) => Ok(p
                .try_get_first_by_address(address)?
                .map(|(id, entry)| (id, EntityRef::cached(entry)))),
            Self::Transient(t) => Ok(t
                .get_first_by_address(address)
                .map(|(id, entry)| (id, EntityRef::borrowed(entry)))),
        }
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

    pub fn iter(&self) -> Box<dyn Iterator<Item = (SymbolId, SymbolRef<'_>)> + '_> {
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
    ) -> Box<dyn Iterator<Item = (SymbolId, SymbolRef<'_>)> + '_> {
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

    pub fn iter_by_address(&self) -> Box<dyn Iterator<Item = (SymbolId, SymbolRef<'_>)> + '_> {
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
    ) -> Box<dyn Iterator<Item = (SymbolId, SymbolRef<'_>)> + '_>
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
    ) -> Box<dyn Iterator<Item = (SymbolIndex, SymbolId, SymbolRef<'_>)> + '_> {
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
        self.try_remove(symbol)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove(&mut self, symbol: impl AsRef<str>) -> Result<usize, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.remove(symbol),
            Self::Transient(t) => Ok(t.remove(symbol)),
        }
    }

    pub fn remove_by_address(&mut self, address: impl Into<Address>) -> usize {
        self.try_remove_by_address(address)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove_by_address(
        &mut self,
        address: impl Into<Address>,
    ) -> Result<usize, EntityStorageError> {
        let address = address.into();
        match self {
            Self::Persistent(p) => p.remove_by_address(address),
            Self::Transient(t) => Ok(t.remove_by_address(address)),
        }
    }

    pub fn remove_by_id(&mut self, id: SymbolId) -> bool {
        self.try_remove_by_id(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove_by_id(&mut self, id: SymbolId) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.remove_by_id(id),
            Self::Transient(t) => Ok(t.remove_by_id(id)),
        }
    }

    pub fn remove_by_index(&mut self, index: SymbolIndex) -> bool {
        self.try_remove_by_index(index)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove_by_index(&mut self, index: SymbolIndex) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(p) => p.remove_by_index(index),
            Self::Transient(t) => Ok(t.remove_by_index(index)),
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

        let insertion = table
            .insert(
                SymbolIndex::new(sel, 1),
                Address::from(0x1000u32),
                "symbol1",
                SymbolProperties::LOCAL,
            )
            .unwrap();
        assert!(insertion.is_new());
        let id1 = insertion.id();

        let insertion = table
            .insert(
                SymbolIndex::new(sel, 2),
                Address::from(0x2000u32),
                "symbol2",
                SymbolProperties::LOCAL,
            )
            .unwrap();
        assert!(insertion.is_new());
        assert_eq!(table.len(), 2);

        assert!(table.remove_by_id(id1));
        assert_eq!(table.len(), 1);

        let insertion = table
            .insert(
                SymbolIndex::new(sel, 3),
                Address::from(0x3000u32),
                "symbol3",
                SymbolProperties::LOCAL,
            )
            .unwrap();
        assert!(insertion.is_new());
        let id3 = insertion.id();
        assert_eq!(table.len(), 2);
        assert_eq!(id1.index(), id3.index());
        assert_eq!(id1.generation() + 1, id3.generation());
        assert!(table.get_by_id(id1).is_none());
        assert!(!table.remove_by_id(id1));

        let insertion = table
            .insert(
                SymbolIndex::new(sel, 4),
                Address::from(0x3000u32),
                "symbol3",
                SymbolProperties::LOCAL,
            )
            .unwrap();
        assert!(!insertion.is_new());
        let id4 = insertion.id();
        assert_eq!(id3, id4);
        assert_eq!(table.len(), 2);

        let insertion = table
            .insert(
                SymbolIndex::new(sel, 5),
                Address::from(0x3000u32),
                "symbol4",
                SymbolProperties::LOCAL,
            )
            .unwrap();
        assert!(insertion.is_new());
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

            let hole = table
                .insert(
                    SymbolIndex::new(sel, 1),
                    Address::from(0x1000u32),
                    "alpha",
                    SymbolProperties::LOCAL,
                )
                .unwrap()
                .id();
            table
                .insert(
                    SymbolIndex::new(sel, 2),
                    Address::from(0x2000u32),
                    "beta",
                    SymbolProperties::LOCAL,
                )
                .unwrap();
            table
                .insert(
                    SymbolIndex::new(sel, 3),
                    Address::from(0x3000u32),
                    "gamma",
                    SymbolProperties::LOCAL,
                )
                .unwrap();
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
}
