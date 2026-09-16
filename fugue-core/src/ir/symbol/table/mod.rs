use std::collections::BTreeMap;
use std::ops::RangeBounds;
use std::sync::Arc;

use smallvec::SmallVec;

use super::{SymbolEntry, SymbolId, SymbolIndex, SymbolProperties, SymbolTableSelector};
use crate::ir::symbol::Symbol;
use crate::ir::{Address, IdSet};
use crate::storage::entities::schema::ENTITY_SYMBOL_TABLE_ID;
use crate::storage::entities::{
    Entity, EntityId, EntityRef, EntityWrite, EntityWriteBatch, ProjectEntity, WriteBackWorker,
};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::{EntityStorage, EntityStorageError};

pub(crate) const ATTRIBUTE_SYMBOL_CACHE_SIZE: &str = "storage.entities.symbol.cache_size";
pub(crate) const DEFAULT_SYMBOL_CACHE_BYTES: usize = 8 * 1024 * 1024;

mod persistent;
use persistent::SymbolTable as PersistentSymbolTable;

mod transient;
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

#[derive(Default)]
pub(crate) struct SymbolTableStaging {
    cancelled_symbols: Vec<SymbolId>,
    staged_indices: BTreeMap<SymbolIndex, Option<SymbolId>>,
    staged_symbols: BTreeMap<SymbolId, Option<SymbolEntry>>,
    symbol_reservations: Vec<SymbolId>,
}

pub(crate) struct PreparedSymbolBatch {
    cancelled_symbols: Vec<SymbolId>,
    records: Vec<PreparedSymbolRecord>,
    symbol_reservations: Vec<SymbolId>,
}

struct PreparedSymbolRecord {
    encoded_size: usize,
    entry: Option<SymbolEntry>,
    id: SymbolId,
    previous: Option<SymbolIndexState>,
}

const SYMBOL_TABLE_VERSION: u32 = 1;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct SymbolTableHeader {
    format_version: u32,
}

impl Entity for SymbolTableHeader {
    const ID: EntityId = ENTITY_SYMBOL_TABLE_ID;
}

pub enum SymbolTable {
    Persistent(PersistentSymbolTable),
    Transient(TransientSymbolTable),
}

impl SymbolTable {
    pub fn new_transient() -> Self {
        Self::Transient(TransientSymbolTable::new())
    }

    pub fn new_persistent(
        entities: EntityStorage,
        cache_bytes: usize,
        worker: Arc<WriteBackWorker>,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentSymbolTable::new(
            entities,
            cache_bytes,
            worker,
        )?))
    }

    pub fn contains(&self, symbol: impl AsRef<str>) -> bool {
        match self {
            Self::Persistent(table) => table.contains(symbol),
            Self::Transient(table) => table.contains(symbol),
        }
    }

    pub fn contains_by_index(&self, index: SymbolIndex) -> bool {
        match self {
            Self::Persistent(table) => table.contains_by_index(index),
            Self::Transient(table) => table.contains_by_index(index),
        }
    }

    pub fn contains_by_address(&self, address: impl Into<Address>) -> bool {
        let address = address.into();
        match self {
            Self::Persistent(table) => table.contains_by_address(address),
            Self::Transient(table) => table.contains_by_address(address),
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

    pub fn get_by_name(
        &self,
        symbol: impl AsRef<str>,
    ) -> Box<dyn Iterator<Item = (SymbolId, SymbolRef<'_>)> + '_> {
        match self {
            Self::Persistent(table) => Box::new(
                table
                    .get(symbol)
                    .map(|(id, entry)| (id, EntityRef::cached(entry))),
            ),
            Self::Transient(table) => Box::new(
                table
                    .get(symbol)
                    .map(|(id, entry)| (id, EntityRef::borrowed(entry))),
            ),
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
            Self::Persistent(table) => Ok(table
                .try_get_first(symbol)?
                .map(|(id, entry)| (id, EntityRef::cached(entry)))),
            Self::Transient(table) => Ok(table
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
            Self::Persistent(table) => Ok(table.try_get_by_id(id)?.map(EntityRef::cached)),
            Self::Transient(table) => Ok(table.get_by_id(id).map(EntityRef::borrowed)),
        }
    }

    pub fn get_id_by_index(&self, index: SymbolIndex) -> Option<SymbolId> {
        match self {
            Self::Persistent(table) => table.get_id_by_index(index),
            Self::Transient(table) => table.get_id_by_index(index),
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
            Self::Persistent(table) => Ok(table
                .try_get_by_index(index)?
                .map(|(id, entry)| (id, EntityRef::cached(entry)))),
            Self::Transient(table) => Ok(table
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
            Self::Persistent(table) => Box::new(
                table
                    .get_by_address(address)
                    .map(|(id, entry)| (id, EntityRef::cached(entry))),
            ),
            Self::Transient(table) => Box::new(
                table
                    .get_by_address(address)
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
            Self::Persistent(table) => Ok(table
                .try_get_first_by_address(address)?
                .map(|(id, entry)| (id, EntityRef::cached(entry)))),
            Self::Transient(table) => Ok(table
                .get_first_by_address(address)
                .map(|(id, entry)| (id, EntityRef::borrowed(entry)))),
        }
    }

    pub fn iter(&self) -> Box<dyn Iterator<Item = (SymbolId, SymbolRef<'_>)> + '_> {
        match self {
            Self::Persistent(table) => Box::new(
                table
                    .iter()
                    .map(|(id, entry)| (id, EntityRef::cached(entry))),
            ),
            Self::Transient(table) => Box::new(
                table
                    .iter()
                    .map(|(id, entry)| (id, EntityRef::borrowed(entry))),
            ),
        }
    }

    pub fn iter_by_selector(
        &self,
        selector: SymbolTableSelector,
    ) -> Box<dyn Iterator<Item = (SymbolId, SymbolRef<'_>)> + '_> {
        match self {
            Self::Persistent(table) => Box::new(
                table
                    .iter_by_selector(selector)
                    .map(|(id, entry)| (id, EntityRef::cached(entry))),
            ),
            Self::Transient(table) => Box::new(
                table
                    .iter_by_selector(selector)
                    .map(|(id, entry)| (id, EntityRef::borrowed(entry))),
            ),
        }
    }

    pub fn iter_by_address(&self) -> Box<dyn Iterator<Item = (SymbolId, SymbolRef<'_>)> + '_> {
        match self {
            Self::Persistent(table) => Box::new(
                table
                    .iter_by_address()
                    .map(|(id, entry)| (id, EntityRef::cached(entry))),
            ),
            Self::Transient(table) => Box::new(
                table
                    .iter_by_address()
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
            Self::Persistent(table) => Box::new(
                table
                    .range_by_address(range)
                    .map(|(id, entry)| (id, EntityRef::cached(entry))),
            ),
            Self::Transient(table) => Box::new(
                table
                    .range_by_address(range)
                    .map(|(id, entry)| (id, EntityRef::borrowed(entry))),
            ),
        }
    }

    pub fn iter_by_index(
        &self,
    ) -> Box<dyn Iterator<Item = (SymbolIndex, SymbolId, SymbolRef<'_>)> + '_> {
        match self {
            Self::Persistent(table) => Box::new(
                table
                    .iter_by_index()
                    .map(|(index, id, entry)| (index, id, EntityRef::cached(entry))),
            ),
            Self::Transient(table) => Box::new(
                table
                    .iter_by_index()
                    .map(|(index, id, entry)| (index, id, EntityRef::borrowed(entry))),
            ),
        }
    }

    pub(crate) fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent(_))
    }

    pub(crate) fn pending_id(&self, offset: usize) -> SymbolId {
        match self {
            Self::Persistent(table) => table.pending_id(offset),
            Self::Transient(table) => table.pending_id(offset),
        }
    }

    pub fn insert(
        &mut self,
        index: SymbolIndex,
        address: impl Into<Address>,
        symbol: impl Into<Symbol>,
        properties: SymbolProperties,
    ) -> Result<SymbolId, EntityStorageError> {
        let address = address.into();
        let symbol = symbol.into();
        match self {
            Self::Persistent(table) => table.insert(index, address, symbol, properties),
            Self::Transient(table) => Ok(table.insert(index, address, symbol, properties)),
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
            Self::Persistent(table) => table.try_modify_by_id(id, f),
            Self::Transient(table) => Ok(table.modify_by_id(id, f)),
        }
    }

    pub fn remove_by_name(&mut self, symbol: impl AsRef<str>) -> usize {
        self.try_remove_by_name(symbol)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove_by_name(
        &mut self,
        symbol: impl AsRef<str>,
    ) -> Result<usize, EntityStorageError> {
        match self {
            Self::Persistent(table) => table.remove(symbol),
            Self::Transient(table) => Ok(table.remove(symbol)),
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
            Self::Persistent(table) => table.remove_by_address(address),
            Self::Transient(table) => Ok(table.remove_by_address(address)),
        }
    }

    pub fn remove_by_id(&mut self, id: SymbolId) -> bool {
        self.try_remove_by_id(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove_by_id(&mut self, id: SymbolId) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(table) => table.remove_by_id(id),
            Self::Transient(table) => Ok(table.remove_by_id(id)),
        }
    }

    pub fn remove_by_index(&mut self, index: SymbolIndex) -> bool {
        self.try_remove_by_index(index)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove_by_index(&mut self, index: SymbolIndex) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(table) => table.remove_by_index(index),
            Self::Transient(table) => Ok(table.remove_by_index(index)),
        }
    }

    pub fn persisted(storage: &EntityStorage) -> Result<bool, EntityStorageError> {
        storage.contains::<ProjectEntity, SymbolTableHeader>(&ProjectEntity::SymbolTable)
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(table) => table.flush(),
            Self::Transient(_) => Ok(()),
        }
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

    pub(crate) fn append_prepared_writes(
        &self,
        id: SymbolId,
        entry: Option<&SymbolEntry>,
        previous: Option<&SymbolIndexState>,
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        if matches!(self, Self::Persistent(_)) {
            PersistentSymbolTable::append_prepared_writes(id, entry, previous, writes)?;
        }
        Ok(())
    }

    pub(crate) fn append_allocation_writes(
        &self,
        reservations: &[SymbolId],
        releases: &[SymbolId],
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
        reservations: &[SymbolId],
        cancelled: &[SymbolId],
        added: usize,
        removed: usize,
    ) {
        match self {
            Self::Persistent(table) => table.publish_allocations(reservations, added, removed),
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
        encoded_size: usize,
    ) {
        match self {
            Self::Persistent(table) => table.publish_upsert(id, entry, encoded_size),
            Self::Transient(table) => table.publish_upsert(id, entry, previous),
        }
    }

    pub(crate) fn publish_remove(&mut self, id: SymbolId, previous: &SymbolIndexState) {
        match self {
            Self::Persistent(table) => table.publish_remove(id),
            Self::Transient(table) => table.publish_remove(id, previous),
        }
    }
}

impl SymbolTableStaging {
    pub(crate) fn set_properties(
        &mut self,
        symbols: &SymbolTable,
        id: SymbolId,
        properties: SymbolProperties,
    ) -> Result<bool, EntityStorageError> {
        let Some(mut entry) = self.symbol(symbols, id)? else {
            return Ok(false);
        };
        if entry.properties() == properties {
            return Ok(false);
        }

        entry.set_properties(properties);
        self.stage(symbols, id, Some(entry))?;
        Ok(true)
    }

    pub(crate) fn add(
        &mut self,
        symbols: &SymbolTable,
        index: SymbolIndex,
        entry: SymbolEntry,
    ) -> Result<SymbolId, EntityStorageError> {
        let entry = entry.with_index(index);
        if let Some(existing_id) = self.symbol_id_by_index(symbols, index) {
            let Some(mut existing) = self.symbol(symbols, existing_id)? else {
                unreachable!("staged symbol index refers to an existing entry");
            };
            if existing == entry {
                return Ok(existing_id);
            }

            if existing.indices().len() > 1 {
                existing.remove_index(index);
                self.stage(symbols, existing_id, Some(existing))?;
            } else {
                self.remove_symbol(symbols, existing_id)?;
            }
        }

        self.add_or_update(symbols, index, entry)
    }

    pub(crate) fn remove_by_address(
        &mut self,
        symbols: &SymbolTable,
        address: Address,
    ) -> Result<usize, EntityStorageError> {
        let ids = self.symbol_ids_matching(symbols, |entry| entry.address() == address)?;
        let count = ids.len();
        for id in ids.iter() {
            self.remove_symbol(symbols, id)?;
        }
        Ok(count)
    }

    pub(crate) fn remove_by_id(
        &mut self,
        symbols: &SymbolTable,
        id: SymbolId,
    ) -> Result<bool, EntityStorageError> {
        if self.symbol(symbols, id)?.is_none() {
            return Ok(false);
        }
        self.remove_symbol(symbols, id)?;
        Ok(true)
    }

    pub(crate) fn remove_by_index(
        &mut self,
        symbols: &SymbolTable,
        index: SymbolIndex,
    ) -> Result<bool, EntityStorageError> {
        let Some(id) = self.symbol_id_by_index(symbols, index) else {
            return Ok(false);
        };
        self.remove_symbol(symbols, id)?;
        Ok(true)
    }

    pub(crate) fn remove_by_name(
        &mut self,
        symbols: &SymbolTable,
        symbol: impl AsRef<str>,
    ) -> Result<usize, EntityStorageError> {
        let Some(symbol) = Symbol::from_existing(symbol.as_ref()) else {
            return Ok(0);
        };
        let ids = self.symbol_ids_matching(symbols, |entry| entry.symbol() == symbol)?;
        let count = ids.len();
        for id in ids.iter() {
            self.remove_symbol(symbols, id)?;
        }
        Ok(count)
    }

    fn add_or_update(
        &mut self,
        symbols: &SymbolTable,
        index: SymbolIndex,
        entry: SymbolEntry,
    ) -> Result<SymbolId, EntityStorageError> {
        if let Some(id) = self.get_referent(symbols, &entry)? {
            let mut existing = self
                .symbol(symbols, id)?
                .expect("symbol referent was resolved from an existing entry");
            existing.add_index(index);
            existing.update_visibility(entry.properties());
            self.stage(symbols, id, Some(existing))?;
            return Ok(id);
        }

        let id = symbols.pending_id(self.symbol_reservations.len());
        self.symbol_reservations.push(id);
        self.stage(symbols, id, Some(entry))?;
        Ok(id)
    }

    fn get_referent(
        &self,
        symbols: &SymbolTable,
        entry: &SymbolEntry,
    ) -> Result<Option<SymbolId>, EntityStorageError> {
        for (id, _) in symbols.get_by_address(entry.address()) {
            if let Some(candidate) = self.symbol(symbols, id)?
                && candidate.has_same_referent(entry)
            {
                return Ok(Some(id));
            }
        }

        Ok(self.staged_symbols.iter().find_map(|(&id, candidate)| {
            candidate
                .as_ref()
                .is_some_and(|candidate| candidate.has_same_referent(entry))
                .then_some(id)
        }))
    }

    fn remove_symbol(
        &mut self,
        symbols: &SymbolTable,
        id: SymbolId,
    ) -> Result<(), EntityStorageError> {
        self.stage(symbols, id, None)?;
        if symbols.try_get_by_id(id)?.is_none() {
            self.staged_symbols.remove(&id);
            self.cancelled_symbols.push(id);
        }
        Ok(())
    }

    fn stage(
        &mut self,
        symbols: &SymbolTable,
        id: SymbolId,
        entry: Option<SymbolEntry>,
    ) -> Result<(), EntityStorageError> {
        if let Some(previous) = self.symbol(symbols, id)? {
            for &index in previous.indices() {
                if self.symbol_id_by_index(symbols, index) == Some(id) {
                    self.staged_indices.insert(index, None);
                }
            }
        }
        if let Some(entry) = &entry {
            for &index in entry.indices() {
                self.staged_indices.insert(index, Some(id));
            }
        }
        self.staged_symbols.insert(id, entry);
        Ok(())
    }

    fn symbol(
        &self,
        symbols: &SymbolTable,
        id: SymbolId,
    ) -> Result<Option<SymbolEntry>, EntityStorageError> {
        match self.staged_symbols.get(&id) {
            Some(entry) => Ok(entry.clone()),
            None => Ok(symbols
                .try_get_by_id(id)?
                .map(|entry| entry.as_ref().clone())),
        }
    }

    fn symbol_id_by_index(&self, symbols: &SymbolTable, index: SymbolIndex) -> Option<SymbolId> {
        match self.staged_indices.get(&index) {
            Some(id) => *id,
            None => symbols.get_id_by_index(index).and_then(|id| {
                self.staged_symbols.get(&id).map_or(Some(id), |entry| {
                    entry
                        .as_ref()
                        .filter(|entry| entry.indices().contains(&index))
                        .map(|_| id)
                })
            }),
        }
    }

    fn symbol_ids_matching(
        &self,
        symbols: &SymbolTable,
        mut predicate: impl FnMut(&SymbolEntry) -> bool,
    ) -> Result<IdSet<Symbol>, EntityStorageError> {
        let mut ids = IdSet::new();
        for (id, _) in symbols.iter() {
            if let Some(entry) = self.symbol(symbols, id)?
                && predicate(&entry)
            {
                ids.insert(id);
            }
        }
        for (&id, entry) in &self.staged_symbols {
            if entry.as_ref().is_some_and(&mut predicate) {
                ids.insert(id);
            } else {
                ids.remove(id);
            }
        }
        Ok(ids)
    }

    pub(crate) fn prepare(
        self,
        symbols: &SymbolTable,
    ) -> Result<(PreparedSymbolBatch, EntityWriteBatch), EntityStorageError> {
        let Self {
            cancelled_symbols,
            staged_indices: _,
            staged_symbols,
            symbol_reservations,
        } = self;
        let persistent = symbols.is_persistent();
        let mut records = Vec::with_capacity(staged_symbols.len());
        let mut writes =
            EntityWriteBatch::with_capacity(if persistent { staged_symbols.len() } else { 0 });

        for (id, entry) in staged_symbols {
            let previous = symbols.try_get_by_id(id)?;
            if previous
                .as_ref()
                .is_some_and(|previous| entry.as_ref() == Some(previous.as_ref()))
            {
                continue;
            }
            if entry.is_none() && previous.is_none() {
                continue;
            }
            let previous = previous.map(|entry| SymbolIndexState::new(&entry));

            match &entry {
                Some(symbol) => {
                    let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(symbol)
                        .map_err(EntityStorageError::encode)?;
                    let encoded_size = encoded.len();
                    if persistent {
                        writes.push(EntityWrite::insert_archived(
                            SymbolEntry::ID.key_for(&id),
                            encoded,
                        ));
                    }
                    records.push(PreparedSymbolRecord {
                        encoded_size,
                        entry,
                        id,
                        previous,
                    });
                }
                None => {
                    if persistent {
                        writes.push(EntityWrite::remove(SymbolEntry::ID.key_for(&id)));
                    }
                    records.push(PreparedSymbolRecord {
                        encoded_size: 0,
                        entry: None,
                        id,
                        previous,
                    });
                }
            }
        }

        let mut added = 0usize;
        let mut removed = 0usize;
        let mut releases = cancelled_symbols.clone();
        for record in &records {
            symbols.append_prepared_writes(
                record.id,
                record.entry.as_ref(),
                record.previous.as_ref(),
                &mut writes,
            )?;
            match (&record.entry, &record.previous) {
                (Some(_), None) => added += 1,
                (None, Some(_)) => {
                    removed += 1;
                    releases.push(record.id);
                }
                _ => {}
            }
        }
        symbols.append_allocation_writes(
            &symbol_reservations,
            &releases,
            added,
            removed,
            &mut writes,
        )?;

        Ok((
            PreparedSymbolBatch {
                cancelled_symbols,
                records,
                symbol_reservations,
            },
            writes,
        ))
    }
}

impl PreparedSymbolBatch {
    pub(crate) fn for_each_change(
        &self,
        mut f: impl FnMut(Option<&SymbolEntry>, Option<&SymbolIndexState>),
    ) {
        for record in &self.records {
            f(record.entry.as_ref(), record.previous.as_ref());
        }
    }

    pub(crate) fn publish(self, symbols: &mut SymbolTable) {
        let Self {
            cancelled_symbols,
            records,
            symbol_reservations,
        } = self;
        let added = records
            .iter()
            .filter(|record| record.entry.is_some() && record.previous.is_none())
            .count();
        let removed = records
            .iter()
            .filter(|record| record.entry.is_none() && record.previous.is_some())
            .count();
        symbols.publish_allocations(&symbol_reservations, &cancelled_symbols, added, removed);

        for record in records.iter().filter(|record| record.entry.is_none()) {
            let previous = record
                .previous
                .as_ref()
                .expect("prepared symbol removal has a previous entry");
            symbols.publish_remove(record.id, previous);
        }

        for record in records.into_iter().filter(|record| record.entry.is_some()) {
            let entry = record
                .entry
                .expect("prepared symbol upsert has a final entry");
            symbols.publish_upsert(
                record.id,
                entry,
                record.previous.as_ref(),
                record.encoded_size,
            );
        }
    }
}

impl PersistableProjectEntity for SymbolTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(_) => storage.insert(
                &ProjectEntity::SymbolTable,
                &SymbolTableHeader {
                    format_version: SYMBOL_TABLE_VERSION,
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
        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        SymbolTable::new_persistent(storage, 64 * 1024, worker).unwrap()
    }

    #[test]
    fn persistent_free_list_and_referent_merge() {
        let mut table = persistent_table();
        let sel = SymbolTableSelector::new(0);

        let id1 = table
            .insert(
                SymbolIndex::new(sel, 1),
                Address::from(0x1000u32),
                "symbol1",
                SymbolProperties::LOCAL,
            )
            .unwrap();

        table
            .insert(
                SymbolIndex::new(sel, 2),
                Address::from(0x2000u32),
                "symbol2",
                SymbolProperties::LOCAL,
            )
            .unwrap();
        assert_eq!(table.len(), 2);

        assert!(table.remove_by_id(id1));
        assert_eq!(table.len(), 1);

        let id3 = table
            .insert(
                SymbolIndex::new(sel, 3),
                Address::from(0x3000u32),
                "symbol3",
                SymbolProperties::LOCAL,
            )
            .unwrap();
        assert_eq!(table.len(), 2);
        assert_eq!(id1.index(), id3.index());
        assert_eq!(id1.generation() + 1, id3.generation());
        assert!(table.get_by_id(id1).is_none());
        assert!(!table.remove_by_id(id1));

        let id4 = table
            .insert(
                SymbolIndex::new(sel, 4),
                Address::from(0x3000u32),
                "symbol3",
                SymbolProperties::LOCAL,
            )
            .unwrap();
        assert_eq!(id3, id4);
        assert_eq!(table.len(), 2);

        table
            .insert(
                SymbolIndex::new(sel, 5),
                Address::from(0x3000u32),
                "symbol4",
                SymbolProperties::LOCAL,
            )
            .unwrap();
        assert_eq!(table.len(), 3);

        assert_eq!(table.remove_by_name("symbol3"), 1);
        assert_eq!(table.len(), 2);
        assert_eq!(table.remove_by_address(Address::from(0x3000u32)), 1);
        assert_eq!(table.len(), 1);
        assert!(table.get_first("symbol2").is_some());
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn persistent_reopen_sqlite() {
        let sel = SymbolTableSelector::new(0);
        let dir = TempDir::new().unwrap();

        {
            let storage =
                EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
            let worker = WriteBackWorker::new(storage.clone()).unwrap();
            let mut table =
                SymbolTable::new_persistent(storage.clone(), 64 * 1024, worker).unwrap();

            let hole = table
                .insert(
                    SymbolIndex::new(sel, 1),
                    Address::from(0x1000u32),
                    "alpha",
                    SymbolProperties::LOCAL,
                )
                .unwrap();
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
        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        let reloaded = SymbolTable::new_persistent(storage, 64 * 1024, worker).unwrap();

        assert_eq!(reloaded.len(), 2);
        assert!(reloaded.get_first("beta").is_some());
        assert!(reloaded.get_first("alpha").is_none());
        assert!(reloaded.contains_by_address(Address::from(0x3000u32)));
    }
}
