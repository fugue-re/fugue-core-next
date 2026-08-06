use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::mem::size_of;
use std::ops::Bound;
use std::sync::Mutex;

use super::Id;
use crate::storage::entities::schema::{
    ENTITY_FREE_ID_RECORD_ID, ENTITY_KEY_FREE_ID, ENTITY_TABLE_INDEX_STATE_ID,
};
use crate::storage::entities::{
    Entity, EntityId, EntityKey, EntityKeyCodec, EntityKeyId, EntityStorage, EntityStorageError,
    EntityWriteBatch, ProjectEntity,
};

const TABLE_INDEX_SCHEMA: u32 = 1;
const FREE_ID_PREVIEW_BATCH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub(crate) enum PersistentTable {
    CodeBlocks = 1,
    Functions = 0,
    Problems = 4,
    Switches = 3,
    Symbols = 2,
}

impl PersistentTable {
    fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::CodeBlocks),
            0 => Some(Self::Functions),
            4 => Some(Self::Problems),
            3 => Some(Self::Switches),
            2 => Some(Self::Symbols),
            _ => None,
        }
    }

    fn project_entity(self) -> ProjectEntity {
        match self {
            Self::CodeBlocks => ProjectEntity::CodeBlockTable,
            Self::Functions => ProjectEntity::FunctionTable,
            Self::Problems => ProjectEntity::ProblemTable,
            Self::Switches => ProjectEntity::SwitchTable,
            Self::Symbols => ProjectEntity::SymbolTable,
        }
    }
}

impl EntityKeyCodec for PersistentTable {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let (&value, rest) = input.split_first()?;
        *input = rest;
        Self::from_byte(value)
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        output.extend([*self as u8]);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FreeIdKey {
    table: PersistentTable,
    index: u32,
}

impl FreeIdKey {
    fn first(table: PersistentTable) -> Self {
        Self { table, index: 0 }
    }
}

impl EntityKeyCodec for FreeIdKey {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let table = PersistentTable::decode(input)?;
        let (index, rest) = input.split_at_checked(size_of::<u32>())?;
        *input = rest;
        Some(Self {
            table,
            index: u32::from_be_bytes(index.try_into().ok()?),
        })
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        self.table.encode(output);
        output.extend(self.index.to_be_bytes());
    }
}

impl EntityKey for FreeIdKey {
    const ID: EntityKeyId = ENTITY_KEY_FREE_ID;
}

#[derive(Debug, Clone, Copy, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct FreeIdRecord {
    generation: u32,
}

impl Entity for FreeIdRecord {
    const ID: EntityId = ENTITY_FREE_ID_RECORD_ID;
}

#[derive(Debug, Clone, Copy, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct TableIndexState {
    schema: u32,
    next_index: u64,
    live: u64,
}

impl TableIndexState {
    fn new(next_index: usize, live: usize) -> Self {
        Self {
            schema: TABLE_INDEX_SCHEMA,
            next_index: next_index as u64,
            live: live as u64,
        }
    }

    fn is_current(self) -> bool {
        self.schema == TABLE_INDEX_SCHEMA
    }

    fn next_index(self) -> usize {
        usize::try_from(self.next_index).expect("persistent entity index fits usize")
    }

    fn live(self) -> usize {
        usize::try_from(self.live).expect("persistent entity count fits usize")
    }
}

impl Entity for TableIndexState {
    const ID: EntityId = ENTITY_TABLE_INDEX_STATE_ID;
}

struct PendingAllocations<T> {
    free_exhausted: bool,
    ids: Vec<Id<T>>,
    last_free: Option<u32>,
    next_index: usize,
}

impl<T> PendingAllocations<T> {
    fn new(next_index: usize) -> Self {
        Self {
            free_exhausted: false,
            ids: Vec::new(),
            last_free: None,
            next_index,
        }
    }

    fn clear(&mut self, next_index: usize) {
        self.free_exhausted = false;
        self.ids.clear();
        self.last_free = None;
        self.next_index = next_index;
    }
}

pub(crate) struct PersistentIdAllocator<T> {
    pending: Mutex<PendingAllocations<T>>,
    state: TableIndexState,
    storage: EntityStorage,
    table: PersistentTable,
    _marker: PhantomData<T>,
}

impl<T> PersistentIdAllocator<T> {
    pub(crate) fn load(
        storage: EntityStorage,
        table: PersistentTable,
    ) -> Result<Option<Self>, EntityStorageError> {
        let Some(state) = storage
            .get::<ProjectEntity, TableIndexState>(&table.project_entity())?
            .filter(|state| state.is_current())
        else {
            return Ok(None);
        };

        Ok(Some(Self::new(storage, table, state)))
    }

    pub(crate) fn initialise(
        storage: EntityStorage,
        table: PersistentTable,
        next_index: usize,
        live: usize,
    ) -> Result<Self, EntityStorageError> {
        let state = TableIndexState::new(next_index, live);
        storage.insert(&table.project_entity(), &state)?;
        Ok(Self::new(storage, table, state))
    }

    fn new(storage: EntityStorage, table: PersistentTable, state: TableIndexState) -> Self {
        Self {
            pending: Mutex::new(PendingAllocations::new(state.next_index())),
            state,
            storage,
            table,
            _marker: PhantomData,
        }
    }

    pub(crate) fn pending_id(&self, offset: usize) -> Result<Id<T>, EntityStorageError> {
        let mut pending = self
            .pending
            .lock()
            .expect("pending allocations lock poisoned");
        if offset >= pending.ids.len() {
            self.extend_pending(&mut pending, offset + 1)?;
        }
        Ok(pending.ids[offset])
    }

    fn extend_pending(
        &self,
        pending: &mut PendingAllocations<T>,
        required: usize,
    ) -> Result<(), EntityStorageError> {
        while !pending.free_exhausted && pending.ids.len() < required {
            let requested = required
                .saturating_sub(pending.ids.len())
                .max(FREE_ID_PREVIEW_BATCH);
            let start = pending.last_free.map_or_else(
                || Bound::Included(FreeIdKey::first(self.table)),
                |index| {
                    Bound::Excluded(FreeIdKey {
                        table: self.table,
                        index,
                    })
                },
            );
            let mut read = 0usize;
            for entry in self
                .storage
                .iter_range::<FreeIdKey, FreeIdRecord>(start.as_ref())?
            {
                let (key, record) = entry?;
                if key.table != self.table || read == requested {
                    break;
                }
                pending
                    .ids
                    .push(Id::with_generation(key.index, record.generation));
                pending.last_free = Some(key.index);
                read += 1;
            }
            if read < requested {
                pending.free_exhausted = true;
            }
        }

        while pending.ids.len() < required {
            pending.ids.push(Id::from_index(pending.next_index));
            pending.next_index += 1;
        }

        Ok(())
    }

    pub(crate) fn append_transition(
        &self,
        reservations: &[Id<T>],
        releases: &[Id<T>],
        added: usize,
        removed: usize,
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        if reservations.is_empty() && releases.is_empty() && added == 0 && removed == 0 {
            return Ok(());
        }

        let mut free = BTreeMap::<u32, Option<u32>>::new();
        let mut next_index = self.state.next_index();
        for id in reservations {
            if id.index() < self.state.next_index() {
                free.insert(id.index() as u32, None);
            }
            next_index = next_index.max(id.index() + 1);
        }
        for id in releases {
            free.insert(id.index() as u32, Some(id.next_generation().generation()));
        }

        for (index, generation) in free {
            let key = FreeIdKey {
                table: self.table,
                index,
            };
            match generation {
                Some(generation) => writes.insert_entity(&key, &FreeIdRecord { generation })?,
                None => writes.remove_entity::<_, FreeIdRecord>(&key),
            }
        }

        let live = self
            .state
            .live()
            .checked_add(added)
            .and_then(|live| live.checked_sub(removed))
            .expect("persistent entity count remains valid");
        writes.insert_entity(
            &self.table.project_entity(),
            &TableIndexState::new(next_index, live),
        )
    }

    pub(crate) fn publish_transition(
        &mut self,
        reservations: &[Id<T>],
        added: usize,
        removed: usize,
    ) {
        let mut next_index = self.state.next_index();
        for id in reservations {
            next_index = next_index.max(id.index() + 1);
        }
        let live = self
            .state
            .live()
            .checked_add(added)
            .and_then(|live| live.checked_sub(removed))
            .expect("persistent entity count remains valid");
        self.state = TableIndexState::new(next_index, live);
        self.pending
            .get_mut()
            .expect("pending allocations lock poisoned")
            .clear(next_index);
    }

    pub(crate) fn len(&self) -> usize {
        self.state.live()
    }
}
