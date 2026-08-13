use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::{ArcRwLockReadGuard, RawRwLock, RwLock};

use crate::ir::{Address, CodeBlockTable, Function, FunctionRef, IndexMetadata};
use crate::storage::EntityStorage;
use crate::storage::entities::schema::{
    ENTITY_CALL_GRAPH_EDGE_ID, ENTITY_KEY_CALL_GRAPH_FORWARD_ID, ENTITY_KEY_CALL_GRAPH_INVERSE_ID,
};
use crate::storage::entities::{
    Entity, EntityCache, EntityId, EntityKey, EntityKeyCodec, EntityKeyId, EntityStorageError,
    EntityWrite, EntityWriteBatch, ProjectEntity, WriteBackWorker,
};
use crate::types::Revision;
use crate::types::common::{cursor_bound, cursor_bound_or_minimum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallGraphEdgeKey {
    source: Address,
    target: Address,
}

impl CallGraphEdgeKey {
    pub fn new(source: Address, target: Address) -> Self {
        Self { source, target }
    }

    pub fn source(&self) -> Address {
        self.source
    }

    pub fn target(&self) -> Address {
        self.target
    }

    fn minimum_for(source: Address) -> Self {
        Self::new(source, Address::MINIMUM)
    }
}

impl EntityKeyCodec for CallGraphEdgeKey {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let source = Address::decode(input)?;
        let target = Address::decode(input)?;
        Some(Self::new(source, target))
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        self.source.encode(output);
        self.target.encode(output);
    }
}

impl EntityKey for CallGraphEdgeKey {
    const ID: EntityKeyId = ENTITY_KEY_CALL_GRAPH_FORWARD_ID;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct InverseCallGraphEdgeKey {
    callee: Address,
    caller: Address,
}

impl InverseCallGraphEdgeKey {
    fn new(callee: Address, caller: Address) -> Self {
        Self { callee, caller }
    }

    fn callee(&self) -> Address {
        self.callee
    }

    fn caller(&self) -> Address {
        self.caller
    }

    fn minimum_for(callee: Address) -> Self {
        Self::new(callee, Address::MINIMUM)
    }
}

impl EntityKeyCodec for InverseCallGraphEdgeKey {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let callee = Address::decode(input)?;
        let caller = Address::decode(input)?;
        Some(Self::new(callee, caller))
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

#[derive(Clone)]
pub struct CallGraphIndex {
    backing: CallGraphIndexBacking,
}

#[derive(Clone)]
enum CallGraphIndexBacking {
    Persistent {
        forward: EntityCache<CallGraphEdgeKey, CallGraphEdgeRecord>,
        inverse: EntityCache<InverseCallGraphEdgeKey, CallGraphEdgeRecord>,
        storage: EntityStorage,
    },
    Transient(Arc<RwLock<TransientCallGraphIndex>>),
}

#[derive(Default)]
struct TransientCallGraphIndex {
    forward: BTreeSet<CallGraphEdgeKey>,
    inverse: BTreeSet<InverseCallGraphEdgeKey>,
}

struct PersistentCallGraphIndex<'a> {
    forward: &'a EntityCache<CallGraphEdgeKey, CallGraphEdgeRecord>,
    inverse: &'a EntityCache<InverseCallGraphEdgeKey, CallGraphEdgeRecord>,
    storage: &'a EntityStorage,
}

struct TransientCallees {
    index: ArcRwLockReadGuard<RawRwLock, TransientCallGraphIndex>,
    caller: Address,
    cursor: Option<CallGraphEdgeKey>,
}

impl Iterator for TransientCallees {
    type Item = Result<Address, EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.cursor.map_or_else(
            || Bound::Included(CallGraphEdgeKey::minimum_for(self.caller)),
            Bound::Excluded,
        );
        let &edge = self.index.forward.range((start, Bound::Unbounded)).next()?;
        if edge.source() != self.caller {
            return None;
        }
        self.cursor = Some(edge);
        Some(Ok(edge.target()))
    }
}

struct TransientCallers {
    index: ArcRwLockReadGuard<RawRwLock, TransientCallGraphIndex>,
    callee: Address,
    cursor: Option<InverseCallGraphEdgeKey>,
}

impl Iterator for TransientCallers {
    type Item = Result<Address, EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.cursor.map_or_else(
            || Bound::Included(InverseCallGraphEdgeKey::minimum_for(self.callee)),
            Bound::Excluded,
        );
        let &edge = self.index.inverse.range((start, Bound::Unbounded)).next()?;
        if edge.callee() != self.callee {
            return None;
        }
        self.cursor = Some(edge);
        Some(Ok(edge.caller()))
    }
}

struct TransientCallGraphEdges {
    index: ArcRwLockReadGuard<RawRwLock, TransientCallGraphIndex>,
    cursor: Option<CallGraphEdgeKey>,
}

impl Iterator for TransientCallGraphEdges {
    type Item = Result<CallGraphEdgeKey, EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.cursor.map_or(Bound::Unbounded, Bound::Excluded);
        let &edge = self.index.forward.range((start, Bound::Unbounded)).next()?;
        self.cursor = Some(edge);
        Some(Ok(edge))
    }
}

#[derive(Default)]
pub(crate) struct CallGraphStaging {
    functions: BTreeMap<Address, StagedFunctionEdgesRecord>,
}

struct StagedFunctionEdgesRecord {
    base_known_empty: bool,
    targets: BTreeSet<Address>,
}

pub(crate) struct PreparedCallGraphBatch {
    edges: Vec<PreparedCallGraphEdgeRecord>,
}

struct PreparedCallGraphEdgeRecord {
    encoded_size: usize,
    key: CallGraphEdgeKey,
    present: bool,
}

impl CallGraphStaging {
    pub(crate) fn set_function_edges(
        &mut self,
        caller: Address,
        targets: BTreeSet<Address>,
        base_known_empty: bool,
    ) {
        self.functions
            .entry(caller)
            .and_modify(|edges| {
                edges.base_known_empty |= base_known_empty;
                edges.targets = targets.clone();
            })
            .or_insert(StagedFunctionEdgesRecord {
                base_known_empty,
                targets,
            });
    }

    pub(crate) fn remove_function_edges(&mut self, caller: Address) {
        self.functions
            .entry(caller)
            .and_modify(|edges| edges.targets.clear())
            .or_insert(StagedFunctionEdgesRecord {
                base_known_empty: false,
                targets: BTreeSet::new(),
            });
    }

    pub(crate) fn function_edges(&self, caller: Address) -> Option<&BTreeSet<Address>> {
        self.functions.get(&caller).map(|edges| &edges.targets)
    }
}

impl CallGraphIndex {
    const CACHE_BYTES: usize = 4 * 1024 * 1024;

    pub(crate) fn new_transient() -> Self {
        Self {
            backing: CallGraphIndexBacking::Transient(Arc::new(RwLock::new(
                TransientCallGraphIndex::default(),
            ))),
        }
    }

    pub(crate) fn new(
        storage: EntityStorage,
        worker: Option<Arc<WriteBackWorker>>,
    ) -> Result<Self, EntityStorageError> {
        let forward =
            EntityCache::from_storage(storage.clone(), worker.clone(), Self::CACHE_BYTES)?;
        let inverse = EntityCache::from_storage(storage.clone(), worker, Self::CACHE_BYTES)?;

        Ok(Self {
            backing: CallGraphIndexBacking::Persistent {
                forward,
                inverse,
                storage,
            },
        })
    }

    pub(crate) fn set_function_edges(
        &self,
        caller: Address,
        targets: impl IntoIterator<Item = Address>,
    ) -> Result<(), EntityStorageError> {
        let current = self.callees_set(caller)?;
        let next = targets.into_iter().collect::<BTreeSet<_>>();

        for target in current.difference(&next) {
            self.remove_edge(caller, *target)?;
        }

        for target in next.difference(&current) {
            self.insert_edge(caller, *target)?;
        }

        Ok(())
    }

    pub(crate) fn prepare(
        &self,
        staging: &CallGraphStaging,
    ) -> Result<(PreparedCallGraphBatch, EntityWriteBatch), EntityStorageError> {
        let encoded = self
            .persistent()
            .map(|_| {
                rkyv::to_bytes::<rkyv::rancor::Error>(&CallGraphEdgeRecord)
                    .map(Bytes::from_owner)
                    .map_err(EntityStorageError::encode)
            })
            .transpose()?;
        let encoded_size = encoded.as_ref().map_or(0, Bytes::len);
        let mut edges = Vec::new();
        let mut writes = EntityWriteBatch::new();

        for (&caller, record) in &staging.functions {
            let current = if record.base_known_empty {
                BTreeSet::new()
            } else {
                self.callees_set(caller)?
            };
            for &target in current.difference(&record.targets) {
                let key = CallGraphEdgeKey::new(caller, target);
                if encoded.is_some() {
                    writes.push(EntityWrite::remove(CallGraphEdgeRecord::ID.key_for(&key)));
                    writes.push(EntityWrite::remove(
                        CallGraphEdgeRecord::ID
                            .key_for(&InverseCallGraphEdgeKey::new(target, caller)),
                    ));
                }
                edges.push(PreparedCallGraphEdgeRecord {
                    encoded_size: 0,
                    key,
                    present: false,
                });
            }
            for &target in record.targets.difference(&current) {
                let key = CallGraphEdgeKey::new(caller, target);
                if let Some(encoded) = &encoded {
                    writes.push(EntityWrite::insert(
                        CallGraphEdgeRecord::ID.key_for(&key),
                        encoded.clone(),
                    ));
                    writes.push(EntityWrite::insert(
                        CallGraphEdgeRecord::ID
                            .key_for(&InverseCallGraphEdgeKey::new(target, caller)),
                        encoded.clone(),
                    ));
                }
                edges.push(PreparedCallGraphEdgeRecord {
                    encoded_size,
                    key,
                    present: true,
                });
            }
        }

        Ok((PreparedCallGraphBatch { edges }, writes))
    }

    pub(crate) fn publish(&self, batch: PreparedCallGraphBatch) {
        match &self.backing {
            CallGraphIndexBacking::Persistent {
                forward, inverse, ..
            } => {
                for edge in batch.edges {
                    let inverse_key =
                        InverseCallGraphEdgeKey::new(edge.key.target(), edge.key.source());
                    if edge.present {
                        forward.publish_insert(edge.key, CallGraphEdgeRecord, edge.encoded_size);
                        inverse.publish_insert(inverse_key, CallGraphEdgeRecord, edge.encoded_size);
                    } else {
                        forward.publish_remove(&edge.key);
                        inverse.publish_remove(&inverse_key);
                    }
                }
            }
            CallGraphIndexBacking::Transient(index) => {
                let mut index = index.write();
                for edge in batch.edges {
                    let inverse =
                        InverseCallGraphEdgeKey::new(edge.key.target(), edge.key.source());
                    if edge.present {
                        index.forward.insert(edge.key);
                        index.inverse.insert(inverse);
                    } else {
                        index.forward.remove(&edge.key);
                        index.inverse.remove(&inverse);
                    }
                }
            }
        }
    }

    pub(crate) fn ensure_current<'a>(
        &self,
        functions: impl IntoIterator<Item = FunctionRef<'a>>,
        blocks: &CodeBlockTable,
        revision: Revision,
    ) -> Result<(), EntityStorageError> {
        let Some(persistent) = self.persistent() else {
            return self.rebuild(functions, blocks);
        };
        let metadata = persistent
            .storage
            .get::<ProjectEntity, IndexMetadata>(&ProjectEntity::CallGraphIndex)?;
        if metadata.is_some_and(|metadata| metadata.revision() == revision) {
            return Ok(());
        }

        self.rebuild(functions, blocks)?;
        persistent.forward.flush()?;
        persistent.inverse.flush()?;
        self.mark_current(revision)
    }

    pub(crate) fn mark_current(&self, revision: Revision) -> Result<(), EntityStorageError> {
        let Some(persistent) = self.persistent() else {
            return Ok(());
        };
        persistent.storage.insert(
            &ProjectEntity::CallGraphIndex,
            &IndexMetadata::new(revision),
        )
    }

    pub(crate) fn callees(
        &self,
        caller: Address,
        after: Option<Address>,
    ) -> Result<
        Box<dyn Iterator<Item = Result<Address, EntityStorageError>> + '_>,
        EntityStorageError,
    > {
        match &self.backing {
            CallGraphIndexBacking::Persistent { forward, .. } => {
                let after = after.map(|after| CallGraphEdgeKey::new(caller, after));
                let start = cursor_bound_or_minimum(after, CallGraphEdgeKey::minimum_for(caller));
                Ok(Box::new(
                    forward
                        .try_iter_range(start.as_ref())?
                        .take_while(move |result| {
                            result
                                .as_ref()
                                .map_or(true, |(key, _)| key.source() == caller)
                        })
                        .map(|result| result.map(|(key, _)| key.target())),
                ))
            }
            CallGraphIndexBacking::Transient(index) => Ok(Box::new(TransientCallees {
                index: index.read_arc(),
                caller,
                cursor: after.map(|after| CallGraphEdgeKey::new(caller, after)),
            })),
        }
    }

    pub(crate) fn callers(
        &self,
        callee: Address,
        after: Option<Address>,
    ) -> Result<
        Box<dyn Iterator<Item = Result<Address, EntityStorageError>> + '_>,
        EntityStorageError,
    > {
        match &self.backing {
            CallGraphIndexBacking::Persistent { inverse, .. } => {
                let after = after.map(|after| InverseCallGraphEdgeKey::new(callee, after));
                let start =
                    cursor_bound_or_minimum(after, InverseCallGraphEdgeKey::minimum_for(callee));
                Ok(Box::new(
                    inverse
                        .try_iter_range(start.as_ref())?
                        .take_while(move |result| {
                            result
                                .as_ref()
                                .map_or(true, |(key, _)| key.callee() == callee)
                        })
                        .map(|result| result.map(|(key, _)| key.caller())),
                ))
            }
            CallGraphIndexBacking::Transient(index) => Ok(Box::new(TransientCallers {
                index: index.read_arc(),
                callee,
                cursor: after.map(|after| InverseCallGraphEdgeKey::new(callee, after)),
            })),
        }
    }

    pub(crate) fn edges(
        &self,
        after: Option<CallGraphEdgeKey>,
    ) -> Result<
        Box<dyn Iterator<Item = Result<CallGraphEdgeKey, EntityStorageError>> + '_>,
        EntityStorageError,
    > {
        match &self.backing {
            CallGraphIndexBacking::Persistent { forward, .. } => {
                let start = cursor_bound(after);
                Ok(Box::new(
                    forward
                        .try_iter_range(start.as_ref())?
                        .map(|result| result.map(|(key, _)| key)),
                ))
            }
            CallGraphIndexBacking::Transient(index) => Ok(Box::new(TransientCallGraphEdges {
                index: index.read_arc(),
                cursor: after,
            })),
        }
    }

    pub(crate) fn function_call_targets(
        function: &Function,
        blocks: &CodeBlockTable,
    ) -> BTreeSet<Address> {
        function
            .flow_targets(blocks)
            .filter(|target| target.kind().is_call())
            .map(|target| target.to())
            .collect()
    }

    fn callees_set(&self, caller: Address) -> Result<BTreeSet<Address>, EntityStorageError> {
        self.callees(caller, None)?.collect()
    }

    fn rebuild<'a>(
        &self,
        functions: impl IntoIterator<Item = FunctionRef<'a>>,
        blocks: &CodeBlockTable,
    ) -> Result<(), EntityStorageError> {
        self.clear()?;

        for function in functions {
            self.set_function_edges(
                function.entry(),
                Self::function_call_targets(&function, blocks),
            )?;
        }

        Ok(())
    }

    fn clear(&self) -> Result<(), EntityStorageError> {
        match &self.backing {
            CallGraphIndexBacking::Persistent {
                forward, inverse, ..
            } => {
                forward.try_clear()?;
                inverse.try_clear()
            }
            CallGraphIndexBacking::Transient(index) => {
                let mut index = index.write();
                index.forward.clear();
                index.inverse.clear();
                Ok(())
            }
        }
    }

    fn insert_edge(&self, caller: Address, callee: Address) -> Result<(), EntityStorageError> {
        let forward_key = CallGraphEdgeKey::new(caller, callee);
        let inverse_key = InverseCallGraphEdgeKey::new(callee, caller);
        match &self.backing {
            CallGraphIndexBacking::Persistent {
                forward, inverse, ..
            } => {
                forward.try_insert(forward_key, CallGraphEdgeRecord)?;
                inverse.try_insert(inverse_key, CallGraphEdgeRecord)?;
            }
            CallGraphIndexBacking::Transient(index) => {
                let mut index = index.write();
                index.forward.insert(forward_key);
                index.inverse.insert(inverse_key);
            }
        }
        Ok(())
    }

    fn remove_edge(&self, caller: Address, callee: Address) -> Result<(), EntityStorageError> {
        let forward_key = CallGraphEdgeKey::new(caller, callee);
        let inverse_key = InverseCallGraphEdgeKey::new(callee, caller);
        match &self.backing {
            CallGraphIndexBacking::Persistent {
                forward, inverse, ..
            } => {
                forward.try_remove(&forward_key)?;
                inverse.try_remove(&inverse_key)
            }
            CallGraphIndexBacking::Transient(index) => {
                let mut index = index.write();
                index.forward.remove(&forward_key);
                index.inverse.remove(&inverse_key);
                Ok(())
            }
        }
    }

    fn persistent(&self) -> Option<PersistentCallGraphIndex<'_>> {
        match &self.backing {
            CallGraphIndexBacking::Persistent {
                forward,
                inverse,
                storage,
            } => Some(PersistentCallGraphIndex {
                forward,
                inverse,
                storage,
            }),
            CallGraphIndexBacking::Transient(_) => None,
        }
    }
}

#[cfg(test)]
mod test {
    use std::io;

    use fugue_lifter::runtime::pcode::Inputs;

    use super::*;
    use crate::ir::{
        FunctionId, FunctionTable, FunctionTableStaging, IncompleteCodeBlock, IncompleteFunction,
        Insn, InsnEntry,
    };
    use crate::lifter::{ContextSet, Language, Op, RawPCodeOp, Varnode, resolve_language};
    use crate::storage::entities::InMemoryEntityStorage;
    use crate::storage::segments::space::AddressSpaceId;

    fn graph() -> Result<CallGraphIndex, EntityStorageError> {
        CallGraphIndex::new(EntityStorage::new(InMemoryEntityStorage::new()), None)
    }

    struct TransientInverseCallGraphEdges {
        index: ArcRwLockReadGuard<RawRwLock, TransientCallGraphIndex>,
        cursor: Option<InverseCallGraphEdgeKey>,
    }

    impl Iterator for TransientInverseCallGraphEdges {
        type Item = Result<CallGraphEdgeKey, EntityStorageError>;

        fn next(&mut self) -> Option<Self::Item> {
            let start = self.cursor.map_or(Bound::Unbounded, Bound::Excluded);
            let &edge = self.index.inverse.range((start, Bound::Unbounded)).next()?;
            self.cursor = Some(edge);
            Some(Ok(CallGraphEdgeKey::new(edge.caller(), edge.callee())))
        }
    }

    fn inverse_edges(
        graph: &CallGraphIndex,
    ) -> Result<
        Box<dyn Iterator<Item = Result<CallGraphEdgeKey, EntityStorageError>> + '_>,
        EntityStorageError,
    > {
        match &graph.backing {
            CallGraphIndexBacking::Persistent { inverse, .. } => Ok(Box::new(
                inverse.try_iter_range(Bound::Unbounded)?.map(|result| {
                    result.map(|(key, _)| CallGraphEdgeKey::new(key.caller(), key.callee()))
                }),
            )),
            CallGraphIndexBacking::Transient(index) => {
                Ok(Box::new(TransientInverseCallGraphEdges {
                    index: index.read_arc(),
                    cursor: None,
                }))
            }
        }
    }

    struct CallGraphMismatch {
        missing: Vec<CallGraphEdgeKey>,
        extra: Vec<CallGraphEdgeKey>,
        inverse_missing: Vec<CallGraphEdgeKey>,
        inverse_extra: Vec<CallGraphEdgeKey>,
    }

    fn mismatch<'a>(
        graph: &CallGraphIndex,
        functions: impl IntoIterator<Item = FunctionRef<'a>>,
        blocks: &CodeBlockTable,
    ) -> Result<Option<CallGraphMismatch>, EntityStorageError> {
        let expected = functions
            .into_iter()
            .flat_map(|function| {
                CallGraphIndex::function_call_targets(&function, blocks)
                    .into_iter()
                    .map(move |target| CallGraphEdgeKey::new(function.entry(), target))
            })
            .collect::<BTreeSet<_>>();
        let forward = graph.edges(None)?.collect::<Result<BTreeSet<_>, _>>()?;
        let inverse = inverse_edges(graph)?.collect::<Result<BTreeSet<_>, _>>()?;

        let mismatch = CallGraphMismatch {
            missing: expected.difference(&forward).copied().collect(),
            extra: forward.difference(&expected).copied().collect(),
            inverse_missing: expected.difference(&inverse).copied().collect(),
            inverse_extra: inverse.difference(&expected).copied().collect(),
        };
        if mismatch.missing.is_empty()
            && mismatch.extra.is_empty()
            && mismatch.inverse_missing.is_empty()
            && mismatch.inverse_extra.is_empty()
        {
            Ok(None)
        } else {
            Ok(Some(mismatch))
        }
    }

    fn assert_consistent<'a>(
        graph: &CallGraphIndex,
        functions: impl IntoIterator<Item = FunctionRef<'a>>,
        blocks: &CodeBlockTable,
    ) -> Result<(), EntityStorageError> {
        assert!(mismatch(graph, functions, blocks)?.is_none());
        Ok(())
    }

    fn call_insn(
        language: &'static Language,
        address: Address,
        target: Address,
    ) -> Result<Insn, Box<dyn std::error::Error>> {
        let operations = [RawPCodeOp {
            op: Op::Call,
            inputs: Inputs::one(Varnode::new(language.default_space(), target.offset(), 8)),
            output: Varnode::INVALID,
        }];

        Ok(Insn::from_resolved_flow(language, address, 1, &operations)?)
    }

    fn insert_function(
        functions: &mut FunctionTable,
        blocks: &mut CodeBlockTable,
        language: &'static Language,
        entry: Address,
        targets: &[Address],
    ) -> Result<FunctionId, Box<dyn std::error::Error>> {
        let mut function = IncompleteFunction::new(entry);
        let mut insns = Vec::with_capacity(targets.len());

        for (index, target) in targets.iter().enumerate() {
            let insn = call_insn(language, entry + index, *target)?;
            let id = match function.insn_entry(insn.address()) {
                InsnEntry::Vacant(entry) => entry.insert(insn),
                InsnEntry::Occupied(entry) => entry.id(),
            };
            insns.push(id);
        }

        let size = insns.len().max(1);
        let block = IncompleteCodeBlock::try_new(entry, size, insns, ContextSet::default())
            .ok_or_else(|| io::Error::other("block construction failed"))?;
        function.push_block(block);

        let mut staging = FunctionTableStaging::default();
        let function = function.normalise()?;
        let record = functions.stage_materialisation(blocks, &mut staging, function)?;
        let id = record.id();
        let (batch, writes) = staging.prepare(functions, blocks)?;
        assert!(writes.is_empty());
        batch.publish(functions, blocks);
        Ok(id)
    }

    fn update_function(
        functions: &mut FunctionTable,
        blocks: &mut CodeBlockTable,
        language: &'static Language,
        function_id: FunctionId,
        entry: Address,
        targets: &[Address],
    ) -> Result<(), Box<dyn std::error::Error>> {
        insert_function(functions, blocks, language, entry, targets)?;
        assert_eq!(
            functions
                .get_by_address(entry)
                .map(|function| function.id()),
            Some(function_id)
        );
        Ok(())
    }

    fn remove_function(
        functions: &mut FunctionTable,
        blocks: &mut CodeBlockTable,
        function_id: FunctionId,
    ) -> Result<Option<Address>, EntityStorageError> {
        let Some(function) = functions.get_by_id(function_id) else {
            return Ok(None);
        };

        let entry = function.entry();
        drop(function);

        let mut staging = FunctionTableStaging::default();
        functions
            .stage_removal(blocks, &mut staging, function_id)
            .map_err(EntityStorageError::backing)?;
        let (batch, writes) = staging.prepare(functions, blocks)?;
        assert!(writes.is_empty());
        batch.publish(functions, blocks);
        Ok(Some(entry))
    }

    fn update_graph_for_function(
        graph: &CallGraphIndex,
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
        function_id: FunctionId,
    ) -> Result<(), EntityStorageError> {
        let Some(function) = functions.get_by_id(function_id) else {
            return Ok(());
        };

        graph.set_function_edges(
            function.entry(),
            CallGraphIndex::function_call_targets(&function, blocks),
        )
    }

    #[test]
    fn cross_space_edges_are_scanned_and_removed() -> Result<(), Box<dyn std::error::Error>> {
        let graph = graph()?;
        let base_caller = Address::new(AddressSpaceId::from(0u16), 0x1000u64);
        let base_callee = Address::new(AddressSpaceId::from(0u16), 0x1100u64);
        let overlay_caller = Address::new(AddressSpaceId::from(1u16), 0x2000u64);
        let overlay_callee = Address::new(AddressSpaceId::from(1u16), 0x2100u64);

        graph.set_function_edges(overlay_caller, [base_callee])?;
        graph.set_function_edges(base_caller, [overlay_callee])?;

        let overlay_callees = graph
            .callees(overlay_caller, None)?
            .collect::<Result<Vec<_>, _>>()?;
        let overlay_callers = graph
            .callers(base_callee, None)?
            .collect::<Result<Vec<_>, _>>()?;
        let base_callees = graph
            .callees(base_caller, None)?
            .collect::<Result<Vec<_>, _>>()?;
        let base_callers = graph
            .callers(overlay_callee, None)?
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(overlay_callees, vec![base_callee]);
        assert_eq!(overlay_callers, vec![overlay_caller]);
        assert_eq!(base_callees, vec![overlay_callee]);
        assert_eq!(base_callers, vec![base_caller]);

        graph.set_function_edges(overlay_caller, [])?;

        assert!(
            graph
                .callees(overlay_caller, None)?
                .collect::<Result<Vec<_>, _>>()?
                .is_empty()
        );
        assert!(
            graph
                .callers(base_callee, None)?
                .collect::<Result<Vec<_>, _>>()?
                .is_empty()
        );

        Ok(())
    }

    #[test]
    fn verifier_reports_forward_and_inverse_mismatches() -> Result<(), Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let graph = graph()?;
        let mut functions = FunctionTable::new_transient();
        let mut blocks = CodeBlockTable::new_transient();
        let caller = Address::new(AddressSpaceId::from(1u16), 0x1000u64);
        let expected_callee = Address::new(AddressSpaceId::from(1u16), 0x2000u64);
        let extra_callee = Address::new(AddressSpaceId::from(1u16), 0x3000u64);

        insert_function(
            &mut functions,
            &mut blocks,
            language,
            caller,
            &[expected_callee],
        )?;
        graph.set_function_edges(caller, [extra_callee])?;

        let error =
            mismatch(&graph, functions.iter(), &blocks)?.expect("call graph should mismatch");

        assert_eq!(
            error.missing,
            vec![CallGraphEdgeKey::new(caller, expected_callee)]
        );
        assert_eq!(
            error.extra,
            vec![CallGraphEdgeKey::new(caller, extra_callee)]
        );
        assert_eq!(
            error.inverse_missing,
            vec![CallGraphEdgeKey::new(caller, expected_callee)]
        );
        assert_eq!(
            error.inverse_extra,
            vec![CallGraphEdgeKey::new(caller, extra_callee)]
        );

        Ok(())
    }

    #[test]
    fn ensure_current_rebuilds_when_marker_is_stale() -> Result<(), Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let graph = graph()?;
        let mut functions = FunctionTable::new_transient();
        let mut blocks = CodeBlockTable::new_transient();
        let caller = Address::new(AddressSpaceId::from(2u16), 0x1000u64);
        let expected_callee = Address::new(AddressSpaceId::from(2u16), 0x2000u64);
        let stale_callee = Address::new(AddressSpaceId::from(2u16), 0x3000u64);

        insert_function(
            &mut functions,
            &mut blocks,
            language,
            caller,
            &[expected_callee],
        )?;
        graph.set_function_edges(caller, [stale_callee])?;
        graph.mark_current(Revision::new(6))?;

        graph.ensure_current(functions.iter(), &blocks, Revision::new(7))?;

        assert_consistent(&graph, functions.iter(), &blocks)?;
        assert_eq!(
            graph
                .callees(caller, None)?
                .collect::<Result<Vec<_>, _>>()?,
            vec![expected_callee]
        );

        Ok(())
    }

    #[test]
    fn ensure_current_trusts_matching_marker_without_rebuild()
    -> Result<(), Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let graph = graph()?;
        let mut functions = FunctionTable::new_transient();
        let mut blocks = CodeBlockTable::new_transient();
        let caller = Address::new(AddressSpaceId::from(2u16), 0x4000u64);
        let expected_callee = Address::new(AddressSpaceId::from(2u16), 0x5000u64);
        let indexed_callee = Address::new(AddressSpaceId::from(2u16), 0x6000u64);

        insert_function(
            &mut functions,
            &mut blocks,
            language,
            caller,
            &[expected_callee],
        )?;
        graph.set_function_edges(caller, [indexed_callee])?;
        graph.mark_current(Revision::new(7))?;

        graph.ensure_current(functions.iter(), &blocks, Revision::new(7))?;

        assert_eq!(
            graph
                .callees(caller, None)?
                .collect::<Result<Vec<_>, _>>()?,
            vec![indexed_callee]
        );
        assert!(mismatch(&graph, functions.iter(), &blocks)?.is_some());

        Ok(())
    }

    #[test]
    fn call_graph_incremental_maintenance_holds_for_multispace_updates()
    -> Result<(), Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let graph = graph()?;
        let mut functions = FunctionTable::new_transient();
        let mut blocks = CodeBlockTable::new_transient();
        let entries = (0..16)
            .map(|index| {
                let space = AddressSpaceId::from((index % 4) as u16);
                Address::new(space, 0x1000u64 + (index as u64 * 0x100u64))
            })
            .collect::<Vec<_>>();
        let mut function_ids = vec![None; entries.len()];
        let mut state = 0x5eed_u64;

        for step in 0..2048 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;

            let index = (state as usize + step) % entries.len();
            let entry = entries[index];
            let op = (state >> 11) % 5;

            if function_ids[index].is_none() || op == 0 {
                if function_ids[index].is_none() {
                    let targets = generated_targets(state, entry, &entries);
                    let function_id =
                        insert_function(&mut functions, &mut blocks, language, entry, &targets)?;
                    function_ids[index] = Some(function_id);
                    update_graph_for_function(&graph, &functions, &blocks, function_id)?;
                }
            } else if op == 1 {
                let function_id = function_ids[index].take().unwrap();
                if let Some(entry) = remove_function(&mut functions, &mut blocks, function_id)? {
                    graph.set_function_edges(entry, [])?;
                }
            } else {
                let function_id = function_ids[index].unwrap();
                let targets =
                    generated_targets(state.rotate_left((op * 7) as u32), entry, &entries);
                update_function(
                    &mut functions,
                    &mut blocks,
                    language,
                    function_id,
                    entry,
                    &targets,
                )?;
                update_graph_for_function(&graph, &functions, &blocks, function_id)?;
            }

            assert_consistent(&graph, functions.iter(), &blocks)?;
        }

        Ok(())
    }

    fn generated_targets(state: u64, entry: Address, entries: &[Address]) -> Vec<Address> {
        let mut targets = BTreeSet::new();
        let count = ((state & 0x7) as usize).min(5);

        for offset in 0..count {
            let raw = state.rotate_left((offset * 9) as u32) as usize;
            let target = entries[raw % entries.len()];
            targets.insert(Address::new(entry.space(), target.offset()));
        }

        if state & 0x20 != 0 {
            targets.insert(entry);
        }

        targets.into_iter().collect()
    }
}
