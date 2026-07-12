use std::collections::BTreeSet;
use std::mem::size_of;
use std::ops::Bound;
use std::sync::Arc;

use bytes::BytesMut;
use thiserror::Error;

use crate::ir::block::table::CodeBlockRef;
use crate::ir::function::table::FunctionRef;
use crate::ir::{Address, CodeBlockTable, FlowTarget, Function, InsnTargetKind, RawAddress};
use crate::storage::EntityStorage;
use crate::storage::entities::schema::{
    ENTITY_CALL_GRAPH_FORWARD_EDGE_ID, ENTITY_CALL_GRAPH_INDEX_HEADER_ID,
    ENTITY_CALL_GRAPH_INVERSE_EDGE_ID, ENTITY_KEY_CALL_GRAPH_EDGE_ID,
};
use crate::storage::entities::{
    CachedRef, Entity, EntityCache, EntityId, EntityIterator, EntityKey, EntityKeyId,
    EntityStorageError, ProjectEntity, WriteBackWorker,
};
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallGraphEdgeKey {
    source: Address,
    target: Address,
}

impl CallGraphEdgeKey {
    const ADDRESS_KEY_SIZE: usize = size_of::<AddressSpaceId>() + size_of::<RawAddress>();
    const KEY_SIZE: usize = Self::ADDRESS_KEY_SIZE * 2;

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
        Self::new(source, Address::zero(source.space()))
    }
}

impl EntityKey for CallGraphEdgeKey {
    const ID: EntityKeyId = ENTITY_KEY_CALL_GRAPH_EDGE_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != Self::KEY_SIZE {
            return None;
        }

        let source = Address::decode(&buf[..Self::ADDRESS_KEY_SIZE])?;
        let target = Address::decode(&buf[Self::ADDRESS_KEY_SIZE..])?;

        Some(Self::new(source, target))
    }

    fn encode(&self, buf: &mut BytesMut) {
        self.source.encode(buf);
        self.target.encode(buf);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct CallGraphForwardEdge;

impl Entity for CallGraphForwardEdge {
    const ID: EntityId = ENTITY_CALL_GRAPH_FORWARD_EDGE_ID;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct CallGraphInverseEdge;

impl Entity for CallGraphInverseEdge {
    const ID: EntityId = ENTITY_CALL_GRAPH_INVERSE_EDGE_ID;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct CallGraphIndexHeader {
    revision: u64,
}

impl CallGraphIndexHeader {
    fn new(revision: u64) -> Self {
        Self { revision }
    }

    fn revision(&self) -> u64 {
        self.revision
    }
}

impl Entity for CallGraphIndexHeader {
    const ID: EntityId = ENTITY_CALL_GRAPH_INDEX_HEADER_ID;
}

#[derive(Clone)]
pub struct CallGraphIndex {
    forward: EntityCache<CallGraphEdgeKey, CallGraphForwardEdge>,
    inverse: EntityCache<CallGraphEdgeKey, CallGraphInverseEdge>,
    storage: EntityStorage,
}

#[derive(Debug, Error)]
pub enum CallGraphVerificationError {
    #[error("call graph storage error: {0}")]
    Storage(#[from] EntityStorageError),
    #[error(
        "call graph mismatch: missing={missing:?}, extra={extra:?}, inverse_missing={inverse_missing:?}, inverse_extra={inverse_extra:?}"
    )]
    Mismatch {
        missing: Vec<CallGraphEdgeKey>,
        extra: Vec<CallGraphEdgeKey>,
        inverse_missing: Vec<CallGraphEdgeKey>,
        inverse_extra: Vec<CallGraphEdgeKey>,
    },
}

impl CallGraphIndex {
    const CACHE_BYTES: usize = 4 * 1024 * 1024;
    const CLEAR_BATCH_LEN: usize = 256;

    pub(crate) fn new(storage: EntityStorage) -> Result<Self, EntityStorageError> {
        let forward = EntityCache::new(storage.clone(), Self::CACHE_BYTES)?;
        let inverse = EntityCache::new(storage.clone(), Self::CACHE_BYTES)?;

        Ok(Self {
            forward,
            inverse,
            storage,
        })
    }

    pub(crate) fn new_with(storage: EntityStorage, worker: Arc<WriteBackWorker>) -> Self {
        let forward = EntityCache::with_worker(storage.clone(), worker.clone(), Self::CACHE_BYTES);
        let inverse = EntityCache::with_worker(storage.clone(), worker, Self::CACHE_BYTES);

        Self {
            forward,
            inverse,
            storage,
        }
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
        revision: u64,
    ) -> Result<(), EntityStorageError> {
        let header = self
            .storage
            .get::<ProjectEntity, CallGraphIndexHeader>(&ProjectEntity::CallGraphIndex)?;

        if header.is_some_and(|header| header.revision() == revision) {
            return Ok(());
        }

        self.rebuild(functions, blocks)?;
        self.forward.flush()?;
        self.inverse.flush()?;
        self.mark_current(revision)
    }

    pub(crate) fn mark_current(&self, revision: u64) -> Result<(), EntityStorageError> {
        self.storage.insert(
            &ProjectEntity::CallGraphIndex,
            &CallGraphIndexHeader::new(revision),
        )
    }

    pub fn verify<'a>(
        &self,
        functions: impl IntoIterator<Item = FunctionRef<'a>>,
        blocks: &CodeBlockTable,
    ) -> Result<(), CallGraphVerificationError> {
        let expected = Self::expected_edges(functions, blocks);
        let forward = self.edges(None)?.collect::<Result<BTreeSet<_>, _>>()?;
        let inverse = self
            .inverse_range(Bound::Unbounded)?
            .map(|result| result.map(|(key, _)| CallGraphEdgeKey::new(key.target(), key.source())))
            .collect::<Result<BTreeSet<_>, _>>()?;

        let missing = expected.difference(&forward).copied().collect::<Vec<_>>();
        let extra = forward.difference(&expected).copied().collect::<Vec<_>>();
        let inverse_missing = expected.difference(&inverse).copied().collect::<Vec<_>>();
        let inverse_extra = inverse.difference(&expected).copied().collect::<Vec<_>>();

        if missing.is_empty()
            && extra.is_empty()
            && inverse_missing.is_empty()
            && inverse_extra.is_empty()
        {
            return Ok(());
        }

        Err(CallGraphVerificationError::Mismatch {
            missing,
            extra,
            inverse_missing,
            inverse_extra,
        })
    }

    pub(crate) fn callees(
        &self,
        caller: Address,
        after: Option<Address>,
    ) -> Result<impl Iterator<Item = Result<Address, EntityStorageError>> + '_, EntityStorageError>
    {
        let start_key;
        let start = match after {
            Some(after) => {
                start_key = CallGraphEdgeKey::new(caller, after);
                Bound::Excluded(&start_key)
            }
            None => {
                start_key = CallGraphEdgeKey::minimum_for(caller);
                Bound::Included(&start_key)
            }
        };

        Ok(self
            .forward_range(start)?
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
        let start_key;
        let start = match after {
            Some(after) => {
                start_key = CallGraphEdgeKey::new(callee, after);
                Bound::Excluded(&start_key)
            }
            None => {
                start_key = CallGraphEdgeKey::minimum_for(callee);
                Bound::Included(&start_key)
            }
        };

        Ok(self
            .inverse_range(start)?
            .take_while(move |result| {
                result
                    .as_ref()
                    .map_or(true, |(key, _)| key.source() == callee)
            })
            .map(|result| result.map(|(key, _)| key.target())))
    }

    pub(crate) fn edges(
        &self,
        after: Option<CallGraphEdgeKey>,
    ) -> Result<
        impl Iterator<Item = Result<CallGraphEdgeKey, EntityStorageError>> + '_,
        EntityStorageError,
    > {
        let start = after.as_ref().map_or(Bound::Unbounded, Bound::Excluded);

        Ok(self
            .forward_range(start)?
            .map(|result| result.map(|(key, _)| key)))
    }

    pub(crate) fn function_call_targets(
        function: &Function,
        blocks: &CodeBlockTable,
    ) -> BTreeSet<Address> {
        Self::block_call_targets(function.blocks().filter_map(|(_, id)| blocks.get_by_id(id)))
    }

    fn block_call_targets<'a>(
        blocks: impl IntoIterator<Item = CodeBlockRef<'a>>,
    ) -> BTreeSet<Address> {
        let mut targets = BTreeSet::new();

        for block in blocks {
            for insn in block.instructions().iter() {
                for (target, kind, to) in insn.iter_targets() {
                    let is_call = kind == InsnTargetKind::Global
                        && FlowTarget::from_insn_target(insn, target, to)
                            .is_some_and(|flow_target| flow_target.kind().is_call());

                    if is_call {
                        targets.insert(to);
                    }
                }
            }
        }

        targets
    }

    fn expected_edges<'a>(
        functions: impl IntoIterator<Item = FunctionRef<'a>>,
        blocks: &CodeBlockTable,
    ) -> BTreeSet<CallGraphEdgeKey> {
        functions
            .into_iter()
            .flat_map(|function| {
                Self::function_call_targets(&function, blocks)
                    .into_iter()
                    .map(move |target| CallGraphEdgeKey::new(function.entry(), target))
            })
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
        self.clear_forward_edges()?;
        self.clear_inverse_edges()
    }

    fn clear_forward_edges(&self) -> Result<(), EntityStorageError> {
        loop {
            let edges = self
                .edges(None)?
                .take(Self::CLEAR_BATCH_LEN)
                .collect::<Result<Vec<_>, _>>()?;

            if edges.is_empty() {
                return Ok(());
            }

            for edge in edges {
                self.forward.try_remove(&edge)?;
            }
        }
    }

    fn clear_inverse_edges(&self) -> Result<(), EntityStorageError> {
        loop {
            let edges = self
                .inverse_range(Bound::Unbounded)?
                .map(|result| result.map(|(key, _)| key))
                .take(Self::CLEAR_BATCH_LEN)
                .collect::<Result<Vec<_>, _>>()?;

            if edges.is_empty() {
                return Ok(());
            }

            for edge in edges {
                self.inverse.try_remove(&edge)?;
            }
        }
    }

    fn insert_edge(&self, caller: Address, callee: Address) -> Result<(), EntityStorageError> {
        self.forward
            .try_put(CallGraphEdgeKey::new(caller, callee), CallGraphForwardEdge)?;
        self.inverse
            .try_put(CallGraphEdgeKey::new(callee, caller), CallGraphInverseEdge)?;

        Ok(())
    }

    fn remove_edge(&self, caller: Address, callee: Address) -> Result<(), EntityStorageError> {
        self.forward
            .try_remove(&CallGraphEdgeKey::new(caller, callee))?;
        self.inverse
            .try_remove(&CallGraphEdgeKey::new(callee, caller))
    }

    fn forward_range(
        &self,
        start: Bound<&CallGraphEdgeKey>,
    ) -> Result<
        EntityIterator<'_, CallGraphEdgeKey, CachedRef<'_, CallGraphForwardEdge>>,
        EntityStorageError,
    > {
        self.forward.try_scan_range(start)
    }

    fn inverse_range(
        &self,
        start: Bound<&CallGraphEdgeKey>,
    ) -> Result<
        EntityIterator<'_, CallGraphEdgeKey, CachedRef<'_, CallGraphInverseEdge>>,
        EntityStorageError,
    > {
        self.inverse.try_scan_range(start)
    }
}

#[cfg(test)]
mod tests {
    use fugue_lifter::runtime::pcode::Inputs;
    use fugue_lifter::{Op, PCodeOp, Varnode};

    use super::*;
    use crate::ir::{CodeBlock, FunctionId, FunctionTable, Insn};
    use crate::lifter::{Language, resolve_language};
    use crate::storage::entities::InMemoryEntityStorage;

    fn graph() -> Result<CallGraphIndex, EntityStorageError> {
        CallGraphIndex::new(EntityStorage::new(InMemoryEntityStorage::new()))
    }

    fn call_insn(language: &'static Language, address: Address, target: Address) -> Insn {
        Insn::from_lifted(
            language,
            address,
            1,
            vec![PCodeOp {
                op: Op::Call,
                inputs: Inputs::one(Varnode::new(language.default_space(), target.offset(), 8)),
                output: Varnode::INVALID,
            }],
        )
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
            .collect::<Vec<_>>();

        let block_id = blocks.insert(entry, |id, address| {
            Ok(CodeBlock::try_new(id, address, instructions.len().max(1), instructions).unwrap())
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
            .collect::<Vec<_>>();

        let block_id = blocks.insert(entry, |id, address| {
            Ok(CodeBlock::try_new(id, address, instructions.len().max(1), instructions).unwrap())
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

        graph.set_function_edges(overlay_caller, [overlay_callee])?;
        graph.set_function_edges(base_caller, [base_callee])?;

        let overlay_callees = graph
            .callees(overlay_caller, None)?
            .collect::<Result<Vec<_>, _>>()?;
        let overlay_callers = graph
            .callers(overlay_callee, None)?
            .collect::<Result<Vec<_>, _>>()?;
        let base_callees = graph
            .callees(base_caller, None)?
            .collect::<Result<Vec<_>, _>>()?;
        let base_callers = graph
            .callers(base_callee, None)?
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(overlay_callees, vec![overlay_callee]);
        assert_eq!(overlay_callers, vec![overlay_caller]);
        assert_eq!(base_callees, vec![base_callee]);
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
                .callers(overlay_callee, None)?
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

        let error = graph.verify(functions.iter(), &blocks).unwrap_err();

        match error {
            CallGraphVerificationError::Mismatch {
                missing,
                extra,
                inverse_missing,
                inverse_extra,
            } => {
                assert_eq!(
                    missing,
                    vec![CallGraphEdgeKey::new(caller, expected_callee)]
                );
                assert_eq!(extra, vec![CallGraphEdgeKey::new(caller, extra_callee)]);
                assert_eq!(
                    inverse_missing,
                    vec![CallGraphEdgeKey::new(caller, expected_callee)]
                );
                assert_eq!(
                    inverse_extra,
                    vec![CallGraphEdgeKey::new(caller, extra_callee)]
                );
            }
            CallGraphVerificationError::Storage(error) => return Err(error.into()),
        }

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
        graph.mark_current(6)?;

        graph.ensure_current(functions.iter(), &blocks, 7)?;

        graph.verify(functions.iter(), &blocks)?;
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
        graph.mark_current(7)?;

        graph.ensure_current(functions.iter(), &blocks, 7)?;

        assert_eq!(
            graph
                .callees(caller, None)?
                .collect::<Result<Vec<_>, _>>()?,
            vec![indexed_callee]
        );
        assert!(matches!(
            graph.verify(functions.iter(), &blocks),
            Err(CallGraphVerificationError::Mismatch { .. })
        ));

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

            graph.verify(functions.iter(), &blocks)?;
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
