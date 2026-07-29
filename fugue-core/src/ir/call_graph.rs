use std::collections::BTreeSet;
use std::ops::Bound;
use std::sync::Arc;

use bytes::BytesMut;

use crate::ir::{Address, CodeBlockTable, Function, FunctionRef, IndexHeader};
use crate::storage::EntityStorage;
use crate::storage::entities::schema::{
    ENTITY_CALL_GRAPH_EDGE_ID, ENTITY_KEY_CALL_GRAPH_FORWARD_ID, ENTITY_KEY_CALL_GRAPH_INVERSE_ID,
};
use crate::storage::entities::{
    CachedRef, Entity, EntityCache, EntityId, EntityIterator, EntityKey, EntityKeyId,
    EntityStorageError, ProjectEntity, WriteBackWorker,
};
use crate::types::Revision;
use crate::types::common::{cursor_bound, cursor_bound_or_minimum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallGraphEdgeKey {
    source: Address,
    target: Address,
}

impl CallGraphEdgeKey {
    const KEY_SIZE: usize = Address::ENCODED_SIZE * 2;

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

impl EntityKey for CallGraphEdgeKey {
    const ID: EntityKeyId = ENTITY_KEY_CALL_GRAPH_FORWARD_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != Self::KEY_SIZE {
            return None;
        }

        let source = Address::decode(&buf[..Address::ENCODED_SIZE])?;
        let target = Address::decode(&buf[Address::ENCODED_SIZE..])?;

        Some(Self::new(source, target))
    }

    fn encode(&self, buf: &mut BytesMut) {
        self.source.encode(buf);
        self.target.encode(buf);
    }
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

impl EntityKey for InverseCallGraphEdgeKey {
    const ID: EntityKeyId = ENTITY_KEY_CALL_GRAPH_INVERSE_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != CallGraphEdgeKey::KEY_SIZE {
            return None;
        }

        let callee = Address::decode(&buf[..Address::ENCODED_SIZE])?;
        let caller = Address::decode(&buf[Address::ENCODED_SIZE..])?;

        Some(Self::new(callee, caller))
    }

    fn encode(&self, buf: &mut BytesMut) {
        self.callee.encode(buf);
        self.caller.encode(buf);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct CallGraphEdgeRecord;

impl Entity for CallGraphEdgeRecord {
    const ID: EntityId = ENTITY_CALL_GRAPH_EDGE_ID;
}

#[derive(Clone)]
pub struct CallGraphIndex {
    forward: EntityCache<CallGraphEdgeKey, CallGraphEdgeRecord>,
    inverse: EntityCache<InverseCallGraphEdgeKey, CallGraphEdgeRecord>,
    storage: EntityStorage,
}

impl CallGraphIndex {
    const CACHE_BYTES: usize = 4 * 1024 * 1024;

    pub(crate) fn new(
        storage: EntityStorage,
        worker: Option<Arc<WriteBackWorker>>,
    ) -> Result<Self, EntityStorageError> {
        let forward =
            EntityCache::from_storage(storage.clone(), worker.clone(), Self::CACHE_BYTES)?;
        let inverse = EntityCache::from_storage(storage.clone(), worker, Self::CACHE_BYTES)?;

        Ok(Self {
            forward,
            inverse,
            storage,
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

    pub(crate) fn remove_function_edges(&self, entry: Address) -> Result<(), EntityStorageError> {
        let targets = self.callees_set(entry)?;

        for target in targets {
            self.remove_edge(entry, target)?;
        }

        Ok(())
    }

    pub(crate) fn ensure_current<'a>(
        &self,
        functions: impl IntoIterator<Item = FunctionRef<'a>>,
        blocks: &CodeBlockTable,
        revision: Revision,
    ) -> Result<(), EntityStorageError> {
        let header = self
            .storage
            .get::<ProjectEntity, IndexHeader>(&ProjectEntity::CallGraphIndex)?;
        if header.is_some_and(|header| header.revision() == revision) {
            return Ok(());
        }

        self.rebuild(functions, blocks)?;
        self.forward.flush()?;
        self.inverse.flush()?;
        self.mark_current(revision)
    }

    pub(crate) fn mark_current(&self, revision: Revision) -> Result<(), EntityStorageError> {
        self.storage
            .insert(&ProjectEntity::CallGraphIndex, &IndexHeader::new(revision))
    }

    pub(crate) fn callees(
        &self,
        caller: Address,
        after: Option<Address>,
    ) -> Result<impl Iterator<Item = Result<Address, EntityStorageError>> + '_, EntityStorageError>
    {
        let after = after.map(|after| CallGraphEdgeKey::new(caller, after));
        let start = cursor_bound_or_minimum(after, CallGraphEdgeKey::minimum_for(caller));

        Ok(self
            .forward_range(start.as_ref())?
            .take_while(move |result| {
                result
                    .as_ref()
                    .map_or(true, |(key, _)| key.source() == caller)
            })
            .map(|result| result.map(|(key, _)| key.target())))
    }

    pub(crate) fn callers(
        &self,
        callee: Address,
        after: Option<Address>,
    ) -> Result<impl Iterator<Item = Result<Address, EntityStorageError>> + '_, EntityStorageError>
    {
        let after = after.map(|after| InverseCallGraphEdgeKey::new(callee, after));
        let start = cursor_bound_or_minimum(after, InverseCallGraphEdgeKey::minimum_for(callee));

        Ok(self
            .inverse_range(start.as_ref())?
            .take_while(move |result| {
                result
                    .as_ref()
                    .map_or(true, |(key, _)| key.callee() == callee)
            })
            .map(|result| result.map(|(key, _)| key.caller())))
    }

    pub(crate) fn edges(
        &self,
        after: Option<CallGraphEdgeKey>,
    ) -> Result<
        impl Iterator<Item = Result<CallGraphEdgeKey, EntityStorageError>> + '_,
        EntityStorageError,
    > {
        let start = cursor_bound(after);

        Ok(self
            .forward_range(start.as_ref())?
            .map(|result| result.map(|(key, _)| key)))
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
        self.forward.try_clear()?;
        self.inverse.try_clear()
    }

    fn insert_edge(&self, caller: Address, callee: Address) -> Result<(), EntityStorageError> {
        self.forward
            .try_put(CallGraphEdgeKey::new(caller, callee), CallGraphEdgeRecord)?;
        self.inverse.try_put(
            InverseCallGraphEdgeKey::new(callee, caller),
            CallGraphEdgeRecord,
        )?;

        Ok(())
    }

    fn remove_edge(&self, caller: Address, callee: Address) -> Result<(), EntityStorageError> {
        self.forward
            .try_remove(&CallGraphEdgeKey::new(caller, callee))?;
        self.inverse
            .try_remove(&InverseCallGraphEdgeKey::new(callee, caller))
    }

    fn forward_range(
        &self,
        start: Bound<&CallGraphEdgeKey>,
    ) -> Result<
        EntityIterator<'_, CallGraphEdgeKey, CachedRef<'_, CallGraphEdgeRecord>>,
        EntityStorageError,
    > {
        self.forward.try_iter_range(start)
    }

    fn inverse_range(
        &self,
        start: Bound<&InverseCallGraphEdgeKey>,
    ) -> Result<
        EntityIterator<'_, InverseCallGraphEdgeKey, CachedRef<'_, CallGraphEdgeRecord>>,
        EntityStorageError,
    > {
        self.inverse.try_iter_range(start)
    }
}

#[cfg(test)]
mod test {
    use fugue_lifter::runtime::pcode::Inputs;

    use super::*;
    use crate::ir::{CodeBlock, CodeBlockTableError, FunctionId, FunctionTable, Insn};
    use crate::lifter::{Language, Op, RawPCodeOp, Varnode, resolve_language};
    use crate::storage::entities::InMemoryEntityStorage;
    use crate::storage::segments::space::AddressSpaceId;

    fn graph() -> Result<CallGraphIndex, EntityStorageError> {
        CallGraphIndex::new(EntityStorage::new(InMemoryEntityStorage::new()), None)
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
        let inverse = graph
            .inverse_range(Bound::Unbounded)?
            .map(|result| result.map(|(key, _)| CallGraphEdgeKey::new(key.caller(), key.callee())))
            .collect::<Result<BTreeSet<_>, _>>()?;

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
        let instructions = targets
            .iter()
            .enumerate()
            .map(|(index, target)| call_insn(language, entry + index, *target))
            .collect::<Result<Vec<_>, _>>()?;

        let block_id = blocks.insert(entry, |id, address| {
            CodeBlock::try_new(id, address, instructions.len().max(1), instructions)
                .ok_or_else(|| CodeBlockTableError::other_with("block construction failed"))
        })?;

        let function_id = functions.insert(entry, |id, address| {
            Ok(Function::new(id, address).with_blocks([(address, block_id)]))
        })?;

        Ok(function_id)
    }

    fn update_function(
        functions: &mut FunctionTable,
        blocks: &mut CodeBlockTable,
        language: &'static Language,
        function_id: FunctionId,
        entry: Address,
        targets: &[Address],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(function) = functions.get_by_id(function_id) {
            for (_, block_id) in function.blocks() {
                blocks.try_remove_by_id(block_id)?;
            }
        }

        let instructions = targets
            .iter()
            .enumerate()
            .map(|(index, target)| call_insn(language, entry + index, *target))
            .collect::<Result<Vec<_>, _>>()?;

        let block_id = blocks.insert(entry, |id, address| {
            CodeBlock::try_new(id, address, instructions.len().max(1), instructions)
                .ok_or_else(|| CodeBlockTableError::other_with("block construction failed"))
        })?;

        functions.try_modify_by_id(function_id, |function| {
            function.clear_blocks();
            function.add_block(entry, block_id);
        })?;

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
        let block_ids = function
            .blocks()
            .map(|(_, block_id)| block_id)
            .collect::<Vec<_>>();
        drop(function);

        for block_id in block_ids {
            blocks.try_remove_by_id(block_id)?;
        }

        functions.try_remove_by_id(function_id)?;

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
        let mut seed = 0x5eed_u64;

        for step in 0..2048 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;

            let index = (seed as usize + step) % entries.len();
            let entry = entries[index];
            let op = (seed >> 11) % 5;

            if function_ids[index].is_none() || op == 0 {
                if function_ids[index].is_none() {
                    let targets = generated_targets(seed, entry, &entries);
                    let function_id =
                        insert_function(&mut functions, &mut blocks, language, entry, &targets)?;
                    function_ids[index] = Some(function_id);
                    update_graph_for_function(&graph, &functions, &blocks, function_id)?;
                }
            } else if op == 1 {
                let function_id = function_ids[index].take().unwrap();
                if let Some(entry) = remove_function(&mut functions, &mut blocks, function_id)? {
                    graph.remove_function_edges(entry)?;
                }
            } else {
                let function_id = function_ids[index].unwrap();
                let targets = generated_targets(seed.rotate_left((op * 7) as u32), entry, &entries);
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

    fn generated_targets(seed: u64, entry: Address, entries: &[Address]) -> Vec<Address> {
        let mut targets = BTreeSet::new();
        let count = ((seed & 0x7) as usize).min(5);

        for offset in 0..count {
            let raw = seed.rotate_left((offset * 9) as u32) as usize;
            let target = entries[raw % entries.len()];
            targets.insert(Address::new(entry.space(), target.offset()));
        }

        if seed & 0x20 != 0 {
            targets.insert(entry);
        }

        targets.into_iter().collect()
    }
}
