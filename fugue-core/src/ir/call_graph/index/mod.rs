use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::ir::call_graph::CallGraphEdgeKey;
use crate::ir::{Address, CodeBlockTable, FunctionRef};
use crate::storage::EntityStorage;
use crate::storage::entities::schema::{
    ENTITY_CALL_GRAPH_EDGE_ID, ENTITY_KEY_CALL_GRAPH_INVERSE_ID,
};
use crate::storage::entities::{
    Entity, EntityId, EntityKey, EntityKeyCodec, EntityKeyId, EntityStorageError, EntityWriteBatch,
    WriteBackWorker,
};
use crate::types::Revision;

mod persistent;
use persistent::CallGraphIndex as PersistentCallGraphIndex;

mod transient;
use transient::CallGraphIndex as TransientCallGraphIndex;

pub(crate) const ATTRIBUTE_CALL_GRAPH_INDEX_CACHE_SIZE: &str =
    "storage.entities.call_graph.index.cache_size";
pub(crate) const DEFAULT_CALL_GRAPH_INDEX_CACHE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct InverseCallGraphEdgeKey {
    callee: Address,
    caller: Address,
}

impl InverseCallGraphEdgeKey {
    fn new(caller: Address, callee: Address) -> Self {
        Self { callee, caller }
    }

    fn callee(&self) -> Address {
        self.callee
    }

    fn caller(&self) -> Address {
        self.caller
    }
}

impl EntityKeyCodec for InverseCallGraphEdgeKey {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let callee = Address::decode(input)?;
        let caller = Address::decode(input)?;
        Some(Self::new(caller, callee))
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        self.callee.encode(output);
        self.caller.encode(output);
    }
}

impl EntityKey for InverseCallGraphEdgeKey {
    const ID: EntityKeyId = ENTITY_KEY_CALL_GRAPH_INVERSE_ID;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct CallGraphEdgeRecord;

impl Entity for CallGraphEdgeRecord {
    const ID: EntityId = ENTITY_CALL_GRAPH_EDGE_ID;
}

pub enum CallGraphIndex {
    Persistent(PersistentCallGraphIndex),
    Transient(TransientCallGraphIndex),
}

pub type CallGraphAddressIterator<'a> =
    Box<dyn Iterator<Item = Result<Address, EntityStorageError>> + 'a>;
pub type CallGraphEdgeIterator<'a> =
    Box<dyn Iterator<Item = Result<CallGraphEdgeKey, EntityStorageError>> + 'a>;

#[derive(Default)]
pub(crate) struct CallGraphStaging {
    callees_by_caller: BTreeMap<Address, StagedCallees>,
}

struct StagedCallees {
    base_known_empty: bool,
    callees: BTreeSet<Address>,
}

pub(crate) struct PreparedCallGraphBatch {
    edges: Vec<PreparedCallGraphEdgeRecord>,
}

pub(crate) struct PreparedCallGraphEdgeRecord {
    encoded_size: usize,
    key: CallGraphEdgeKey,
    present: bool,
}

impl CallGraphStaging {
    pub(crate) fn callees(&self, caller: Address) -> Option<&BTreeSet<Address>> {
        self.callees_by_caller
            .get(&caller)
            .map(|staged| &staged.callees)
    }

    pub(crate) fn set_callees(
        &mut self,
        caller: Address,
        callees: BTreeSet<Address>,
        base_known_empty: bool,
    ) {
        self.callees_by_caller
            .entry(caller)
            .and_modify(|staged| {
                staged.base_known_empty |= base_known_empty;
                staged.callees = callees.clone();
            })
            .or_insert(StagedCallees {
                base_known_empty,
                callees,
            });
    }

    pub(crate) fn clear_callees(&mut self, caller: Address) {
        self.callees_by_caller
            .entry(caller)
            .and_modify(|staged| staged.callees.clear())
            .or_insert(StagedCallees {
                base_known_empty: false,
                callees: BTreeSet::new(),
            });
    }

    pub(crate) fn prepare(
        self,
        index: &CallGraphIndex,
    ) -> Result<(PreparedCallGraphBatch, EntityWriteBatch), EntityStorageError> {
        let mut edges = Vec::new();

        for (caller, staged) in self.callees_by_caller {
            let current = if staged.base_known_empty {
                BTreeSet::new()
            } else {
                index
                    .callees(caller, None)?
                    .collect::<Result<BTreeSet<_>, _>>()?
            };
            for &callee in current.difference(&staged.callees) {
                edges.push(PreparedCallGraphEdgeRecord {
                    encoded_size: 0,
                    key: CallGraphEdgeKey::new(caller, callee),
                    present: false,
                });
            }
            for &callee in staged.callees.difference(&current) {
                edges.push(PreparedCallGraphEdgeRecord {
                    encoded_size: 0,
                    key: CallGraphEdgeKey::new(caller, callee),
                    present: true,
                });
            }
        }

        let mut writes = EntityWriteBatch::new();
        index.append_prepared_writes(&mut edges, &mut writes)?;
        Ok((PreparedCallGraphBatch { edges }, writes))
    }
}

impl CallGraphIndex {
    pub fn new_transient() -> Self {
        Self::Transient(TransientCallGraphIndex::new())
    }

    pub fn new_persistent(
        storage: EntityStorage,
        cache_bytes: usize,
        worker: Arc<WriteBackWorker>,
    ) -> Self {
        Self::Persistent(PersistentCallGraphIndex::new(storage, cache_bytes, worker))
    }

    pub fn callees(
        &self,
        caller: Address,
        after: Option<Address>,
    ) -> Result<CallGraphAddressIterator<'_>, EntityStorageError> {
        match self {
            Self::Persistent(index) => Ok(Box::new(index.callees(caller, after)?)),
            Self::Transient(index) => Ok(Box::new(index.callees(caller, after))),
        }
    }

    pub fn callers(
        &self,
        callee: Address,
        after: Option<Address>,
    ) -> Result<CallGraphAddressIterator<'_>, EntityStorageError> {
        match self {
            Self::Persistent(index) => Ok(Box::new(index.callers(callee, after)?)),
            Self::Transient(index) => Ok(Box::new(index.callers(callee, after))),
        }
    }

    pub fn edges(
        &self,
        after: Option<CallGraphEdgeKey>,
    ) -> Result<CallGraphEdgeIterator<'_>, EntityStorageError> {
        match self {
            Self::Persistent(index) => Ok(Box::new(index.edges(after)?)),
            Self::Transient(index) => Ok(Box::new(index.edges(after))),
        }
    }

    pub fn set_callees(
        &mut self,
        caller: Address,
        callees: impl IntoIterator<Item = Address>,
    ) -> Result<(), EntityStorageError> {
        let current = self
            .callees(caller, None)?
            .collect::<Result<BTreeSet<_>, _>>()?;
        let next = callees.into_iter().collect::<BTreeSet<_>>();

        for target in current.difference(&next) {
            self.remove_edge(caller, *target)?;
        }

        for target in next.difference(&current) {
            self.insert_edge(caller, *target)?;
        }

        Ok(())
    }

    pub(crate) fn ensure_current<'a>(
        &mut self,
        functions: impl IntoIterator<Item = FunctionRef<'a>>,
        blocks: &CodeBlockTable,
        revision: Revision,
    ) -> Result<(), EntityStorageError> {
        if let Self::Persistent(index) = self
            && index.metadata_revision()? == Some(revision)
        {
            return Ok(());
        }

        self.rebuild(functions, blocks)?;
        if let Self::Persistent(index) = self {
            index.flush()?;
        }
        self.mark_current(revision)
    }

    pub(crate) fn mark_current(&self, revision: Revision) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(index) => index.mark_current(revision),
            Self::Transient(_) => Ok(()),
        }
    }

    fn rebuild<'a>(
        &mut self,
        functions: impl IntoIterator<Item = FunctionRef<'a>>,
        blocks: &CodeBlockTable,
    ) -> Result<(), EntityStorageError> {
        self.clear()?;

        for function in functions {
            let callees = function
                .flow_targets(blocks)
                .filter(|target| target.kind().is_call())
                .map(|target| target.to());
            self.set_callees(function.entry(), callees)?;
        }

        Ok(())
    }

    fn clear(&mut self) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(index) => index.clear(),
            Self::Transient(index) => {
                index.clear();
                Ok(())
            }
        }
    }

    fn insert_edge(&mut self, caller: Address, callee: Address) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(index) => index.insert_edge(caller, callee),
            Self::Transient(index) => {
                index.insert_edge(caller, callee);
                Ok(())
            }
        }
    }

    fn remove_edge(&mut self, caller: Address, callee: Address) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(index) => index.remove_edge(caller, callee),
            Self::Transient(index) => {
                index.remove_edge(caller, callee);
                Ok(())
            }
        }
    }

    fn append_prepared_writes(
        &self,
        edges: &mut [PreparedCallGraphEdgeRecord],
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(_) => persistent::append_prepared_writes(edges, writes),
            Self::Transient(_) => Ok(()),
        }
    }
}

impl PreparedCallGraphBatch {
    pub(crate) fn publish(self, index: &mut CallGraphIndex) {
        match index {
            CallGraphIndex::Persistent(index) => index.publish_batch(self),
            CallGraphIndex::Transient(index) => index.publish_batch(self),
        }
    }
}
