use std::collections::hash_map::Iter as HashMapIter;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;
use std::{fmt, mem, slice};

use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::ir::function::NormalisedFunctionRecord;
use crate::ir::{
    Address, AddressRange, AddressRangeSet, CodeBlock, CodeBlockId, CodeBlockIdsByStart,
    CodeBlockTable, Function, FunctionId, FunctionProperties, Id, IdAllocator, IdSet,
    IncompleteFunctionError, NormalisedCodeBlockRecord, PreparedCodeBlockRecord, RawAddress,
    Reference, ReferenceOrigin,
};
use crate::storage::entities::schema::ENTITY_FUNCTION_TABLE_ID;
use crate::storage::entities::{
    Entity, EntityId, EntityMut, EntityRef, EntityWrite, EntityWriteBatch, ProjectEntity,
    WriteBackWorker,
};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::{EntityStorage, EntityStorageError};
use crate::types::Revision;
use crate::types::common::cursor_bound;

pub(crate) const ATTRIBUTE_FUNCTION_CACHE_SIZE: &str = "storage.entities.function.cache_size";
pub(crate) const DEFAULT_FUNCTION_CACHE_BYTES: usize = 8 * 1024 * 1024;

mod persistent;
mod transient;

use persistent::FunctionTable as PersistentFunctionTable;
use transient::FunctionTable as TransientFunctionTable;

pub type FunctionRef<'a> = EntityRef<'a, Function>;
pub type FunctionMut<'a> = EntityMut<'a, Function>;

const FUNCTION_TABLE_VERSION: u32 = 1;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct FunctionTableHeader {
    version: u32,
}

impl Entity for FunctionTableHeader {
    const ID: EntityId = ENTITY_FUNCTION_TABLE_ID;
}

struct FunctionIndex {
    allocator: IdAllocator<Function>,
    addresses: BTreeMap<Address, Id<Function>>,
    by_block: FxHashMap<CodeBlockId, IdSet<Function>>,
}

impl FunctionIndex {
    fn new(allocator: IdAllocator<Function>, addresses: BTreeMap<Address, FunctionId>) -> Self {
        Self {
            allocator,
            addresses,
            by_block: FxHashMap::default(),
        }
    }

    fn insert_membership(&mut self, function: &Function) {
        self.insert_memberships(function.id(), function.blocks().map(|(_, block)| block));
    }

    fn insert_memberships(
        &mut self,
        function: FunctionId,
        blocks: impl IntoIterator<Item = CodeBlockId>,
    ) {
        for block in blocks {
            self.by_block.entry(block).or_default().insert(function);
        }
    }

    fn remove_membership(&mut self, function: &Function) {
        self.remove_memberships(function.id(), function.blocks().map(|(_, block)| block));
    }

    fn remove_memberships(
        &mut self,
        function: FunctionId,
        blocks: impl IntoIterator<Item = CodeBlockId>,
    ) {
        for block in blocks {
            let remove = self.by_block.get_mut(&block).is_some_and(|functions| {
                functions.remove(function);
                functions.is_empty()
            });

            if remove {
                self.by_block.remove(&block);
            }
        }
    }

    fn get_by_block_id(&self, block: CodeBlockId) -> IdSet<Function> {
        self.by_block.get(&block).cloned().unwrap_or_default()
    }

    fn publish_membership(&mut self, mut by_block: FxHashMap<CodeBlockId, IdSet<Function>>) {
        if self.by_block.is_empty() {
            by_block.retain(|_, functions| !functions.is_empty());
            self.by_block = by_block;
            return;
        }

        for (block, functions) in by_block {
            if functions.is_empty() {
                self.by_block.remove(&block);
            } else {
                self.by_block.insert(block, functions);
            }
        }
    }
}

enum StagedEntityRecords<T, V> {
    Empty {
        capacity: usize,
    },
    Ordered {
        first: Id<T>,
        entries: Vec<(Id<T>, V)>,
    },
    Sparse(FxHashMap<Id<T>, V>),
}

impl<T, V> Default for StagedEntityRecords<T, V> {
    fn default() -> Self {
        Self::Empty { capacity: 0 }
    }
}

impl<T, V> StagedEntityRecords<T, V> {
    fn reserve(&mut self, additional: usize) {
        match self {
            Self::Empty { capacity } => {
                *capacity = capacity.saturating_add(additional);
            }
            Self::Ordered { entries, .. } => entries.reserve(additional),
            Self::Sparse(entries) => entries.reserve(additional),
        }
    }

    fn insert(&mut self, id: Id<T>, value: V) -> Option<V> {
        match self {
            Self::Empty { capacity } => {
                let mut entries = Vec::with_capacity((*capacity).max(1));
                entries.push((id, value));
                *self = Self::Ordered { first: id, entries };
                None
            }
            Self::Ordered { first, entries }
                if first.generation() == id.generation() && id.index() >= first.index() =>
            {
                let offset = id.index() - first.index();
                if let Some((entry_id, entry)) = entries.get_mut(offset)
                    && *entry_id == id
                {
                    return Some(mem::replace(entry, value));
                }
                if offset == entries.len() {
                    entries.push((id, value));
                    return None;
                }
                self.promote_to_sparse();
                self.insert(id, value)
            }
            Self::Ordered { .. } => {
                self.promote_to_sparse();
                self.insert(id, value)
            }
            Self::Sparse(entries) => entries.insert(id, value),
        }
    }

    fn get(&self, id: &Id<T>) -> Option<&V> {
        match self {
            Self::Empty { .. } => None,
            Self::Ordered { first, entries } => {
                let offset = Self::ordered_offset(*first, *id)?;
                entries
                    .get(offset)
                    .filter(|(entry_id, _)| entry_id == id)
                    .map(|(_, value)| value)
            }
            Self::Sparse(entries) => entries.get(id),
        }
    }

    fn remove(&mut self, id: &Id<T>) -> Option<V> {
        if matches!(self, Self::Ordered { .. }) {
            self.promote_to_sparse();
        }
        match self {
            Self::Empty { .. } => None,
            Self::Ordered { .. } => unreachable!("ordered entries must be promoted before removal"),
            Self::Sparse(entries) => entries.remove(id),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Empty { .. } => 0,
            Self::Ordered { entries, .. } => entries.len(),
            Self::Sparse(entries) => entries.len(),
        }
    }

    fn iter(&self) -> StagedEntityRecordIter<'_, T, V> {
        match self {
            Self::Empty { .. } => StagedEntityRecordIter::Empty,
            Self::Ordered { entries, .. } => StagedEntityRecordIter::Ordered(entries.iter()),
            Self::Sparse(entries) => StagedEntityRecordIter::Sparse(entries.iter()),
        }
    }

    fn into_entries(self) -> (Vec<(Id<T>, V)>, bool) {
        match self {
            Self::Empty { .. } => (Vec::new(), true),
            Self::Ordered { entries, .. } => (entries, true),
            Self::Sparse(entries) => (entries.into_iter().collect(), false),
        }
    }

    fn ordered_offset(first: Id<T>, id: Id<T>) -> Option<usize> {
        (first.generation() == id.generation() && id.index() >= first.index())
            .then(|| id.index() - first.index())
    }

    fn promote_to_sparse(&mut self) {
        let Self::Ordered { entries, .. } = mem::replace(self, Self::Empty { capacity: 0 }) else {
            return;
        };
        *self = Self::Sparse(entries.into_iter().collect());
    }
}

enum StagedEntityRecordIter<'a, T, V> {
    Empty,
    Ordered(slice::Iter<'a, (Id<T>, V)>),
    Sparse(HashMapIter<'a, Id<T>, V>),
}

impl<'a, T, V> Iterator for StagedEntityRecordIter<'a, T, V> {
    type Item = (Id<T>, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Empty => None,
            Self::Ordered(entries) => entries.next().map(|(id, value)| (*id, value)),
            Self::Sparse(entries) => entries.next().map(|(&id, value)| (id, value)),
        }
    }
}

#[derive(Default)]
pub(crate) struct FunctionTableStaging {
    staged_functions: StagedEntityRecords<Function, StagedFunctionRecord>,
    function_addresses: FxHashMap<Address, Option<FunctionId>>,
    function_reservations: Vec<FunctionId>,
    cancelled_functions: BTreeSet<FunctionId>,
    staged_code_blocks: StagedEntityRecords<CodeBlock, StagedCodeBlockRecord>,
    block_locations: CodeBlockIdsByStart,
    block_reservations: Vec<CodeBlockId>,
    cancelled_blocks: BTreeSet<CodeBlockId>,
    by_block: FxHashMap<CodeBlockId, IdSet<Function>>,
    original_by_block: FxHashMap<CodeBlockId, IdSet<Function>>,
}

struct StagedFunctionRecord {
    function: Option<Function>,
    is_new: bool,
}

struct StagedCodeBlockRecord {
    block: Option<CodeBlock>,
    is_new: bool,
}

pub(crate) struct PreparedFunctionBatch {
    block_reservations: Vec<CodeBlockId>,
    blocks: Vec<PreparedCodeBlockRecord>,
    blocks_are_new: bool,
    cancelled_blocks: BTreeSet<CodeBlockId>,
    cancelled_functions: BTreeSet<FunctionId>,
    function_reservations: Vec<FunctionId>,
    functions: Vec<PreparedFunctionRecord>,
    by_block: FxHashMap<CodeBlockId, IdSet<Function>>,
}

pub(crate) struct StagedFunctionChangeRecord {
    affected_blocks: SmallVec<[CodeBlockId; 16]>,
    call_targets: BTreeSet<Address>,
    coverage: AddressRangeSet,
    id: FunctionId,
    previous_coverage: AddressRangeSet,
    references: Vec<Reference>,
    replaces_existing: bool,
}

pub(crate) struct StagedFunctionRemovalRecord {
    coverage: AddressRangeSet,
    function: Function,
}

impl StagedFunctionRemovalRecord {
    fn new(function: Function, coverage: AddressRangeSet) -> Self {
        Self { coverage, function }
    }

    pub(crate) fn take_coverage(&mut self) -> AddressRangeSet {
        mem::take(&mut self.coverage)
    }

    pub(crate) fn into_function(self) -> Function {
        self.function
    }
}

impl StagedFunctionChangeRecord {
    pub(crate) fn take_call_targets(&mut self) -> BTreeSet<Address> {
        mem::take(&mut self.call_targets)
    }

    pub(crate) fn id(&self) -> FunctionId {
        self.id
    }

    pub(crate) fn take_coverage(&mut self) -> AddressRangeSet {
        mem::take(&mut self.coverage)
    }

    pub(crate) fn take_previous_coverage(&mut self) -> AddressRangeSet {
        mem::take(&mut self.previous_coverage)
    }

    pub(crate) fn take_references(&mut self) -> Vec<Reference> {
        mem::take(&mut self.references)
    }

    pub(crate) fn replaces_existing(&self) -> bool {
        self.replaces_existing
    }
}

pub(crate) struct PreparedFunctionRecord {
    encoded_size: usize,
    function: Option<Function>,
    id: FunctionId,
    previous: Option<Address>,
}

impl FunctionTableStaging {
    fn reserve_blocks(&mut self, additional: usize) {
        self.block_locations.reserve(additional);
        self.staged_code_blocks.reserve(additional);
        self.block_reservations.reserve(additional);
        self.by_block.reserve(additional);
    }

    pub(crate) fn reserve_functions(&mut self, additional: usize) {
        self.staged_functions.reserve(additional);
        self.function_addresses.reserve(additional);
        self.function_reservations.reserve(additional);
    }

    fn stage_materialisation(
        &mut self,
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
        mut function: NormalisedFunctionRecord,
    ) -> Result<StagedFunctionChangeRecord, IncompleteFunctionError> {
        self.reserve_blocks(function.block_count());
        self.load_existing_block_locations(blocks, &function)?;
        let entry = function.entry();
        let previous = self.function_by_address(functions, entry)?;
        let (id, is_new) = match previous.as_ref() {
            Some(previous) => (previous.id(), self.new_function(previous.id())),
            None => {
                let id = functions.pending_id(self.function_reservations.len());
                self.function_reservations.push(id);
                (id, true)
            }
        };
        let call_targets = function.take_call_targets();
        let coverage = function.take_coverage();
        let references = function.take_references();
        let function = function.materialise(id, |block| self.resolve_block(blocks, block))?;
        let record = StagedFunctionChangeRecord {
            affected_blocks: SmallVec::new(),
            call_targets,
            coverage,
            id,
            previous_coverage: AddressRangeSet::new(),
            references,
            replaces_existing: !is_new,
        };
        self.stage_change(functions, blocks, function, previous, is_new, record)
    }

    fn stage_membership(
        &mut self,
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
        mut function: Function,
    ) -> Result<StagedFunctionChangeRecord, IncompleteFunctionError> {
        let entry = function.entry();
        let previous = self.function_by_address(functions, entry)?;
        let (id, is_new) = match previous.as_ref() {
            Some(previous) => (previous.id(), self.new_function(previous.id())),
            None => {
                let id = functions.pending_id(self.function_reservations.len());
                self.function_reservations.push(id);
                (id, true)
            }
        };
        function.set_id(id);

        let mut coverage = AddressRangeSet::new();
        let mut targets = Vec::new();
        for (address, block_id) in function.blocks() {
            let found = self.with_block(blocks, block_id, |block| {
                assert_eq!(
                    block.address(),
                    address,
                    "function block address must match its code block"
                );
                block.coverage_into(&mut coverage);
                targets.extend(
                    block
                        .flow_targets()
                        .map(|target| function.classify_flow_target(target)),
                );
            })?;
            if found.is_none() {
                return Err(IncompleteFunctionError::missing_code_block(block_id));
            }
        }

        let call_targets = targets
            .iter()
            .filter(|target| target.kind().is_call())
            .map(|target| target.to())
            .collect();
        let references = Function::flow_references_from(targets);
        let record = StagedFunctionChangeRecord {
            affected_blocks: SmallVec::new(),
            call_targets,
            coverage,
            id,
            previous_coverage: AddressRangeSet::new(),
            references,
            replaces_existing: !is_new,
        };
        self.stage_change(functions, blocks, function, previous, is_new, record)
    }

    fn stage_change(
        &mut self,
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
        function: Function,
        previous: Option<Function>,
        is_new: bool,
        mut record: StagedFunctionChangeRecord,
    ) -> Result<StagedFunctionChangeRecord, IncompleteFunctionError> {
        let entry = function.entry();
        let id = function.id();

        let replaces_existing = previous.is_some();
        if let Some(previous) = &previous {
            for (_, block) in previous.blocks() {
                record.affected_blocks.push(block);
                self.with_block(blocks, block, |block| {
                    block.coverage_into(&mut record.previous_coverage);
                })?;
                self.by_block_mut(functions, block).remove(id);
            }
            if previous.entry() != entry {
                self.function_addresses.insert(previous.entry(), None);
            }
        }

        for (_, block) in function.blocks() {
            record.affected_blocks.push(block);
            self.by_block_mut(functions, block).insert(id);
            if self
                .staged_code_blocks
                .get(&block)
                .is_some_and(|record| record.block.is_none())
            {
                self.staged_code_blocks.remove(&block);
            }
        }

        record.affected_blocks.sort_unstable();
        record.affected_blocks.dedup();
        if replaces_existing {
            for &block in &record.affected_blocks {
                if self.by_block_mut(functions, block).is_empty() {
                    self.stage_block_removal(blocks, block)?;
                }
            }
        }

        self.function_addresses.insert(entry, Some(id));
        self.staged_functions.insert(
            id,
            StagedFunctionRecord {
                function: Some(function),
                is_new,
            },
        );

        Ok(record)
    }

    fn set_properties(
        &mut self,
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
        entry: Address,
        properties: FunctionProperties,
        input_revision: Revision,
    ) -> Result<Option<AddressRangeSet>, IncompleteFunctionError> {
        let Some(mut function) = self.function_by_address(functions, entry)? else {
            return Ok(None);
        };
        if function.properties() == properties {
            return Ok(None);
        }

        let coverage = self.coverage(blocks, function.blocks().map(|(_, block)| block))?;
        let id = function.id();
        function.set_properties(properties);
        function.set_input_revision(input_revision);
        self.stage_function(functions, blocks, id, Some(function))?;
        Ok(Some(coverage))
    }

    fn remove(
        &mut self,
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
        id: FunctionId,
    ) -> Result<Option<StagedFunctionRemovalRecord>, IncompleteFunctionError> {
        let Some(function) = self.function_by_id(functions, id)? else {
            return Ok(None);
        };
        let coverage = self.coverage(blocks, function.blocks().map(|(_, block)| block))?;
        self.stage_function(functions, blocks, id, None)?;
        if self.new_function(id) {
            self.staged_functions.remove(&id);
            self.cancelled_functions.insert(id);
        }
        Ok(Some(StagedFunctionRemovalRecord::new(function, coverage)))
    }

    fn function_by_address(
        &self,
        functions: &FunctionTable,
        entry: Address,
    ) -> Result<Option<Function>, IncompleteFunctionError> {
        match self.function_addresses.get(&entry) {
            Some(Some(id)) => self.function_by_id(functions, *id),
            Some(None) => Ok(None),
            None => functions
                .try_get_by_address(entry)
                .map(|function| function.map(|function| function.as_ref().clone()))
                .map_err(IncompleteFunctionError::function_creation),
        }
    }

    fn function_by_id(
        &self,
        functions: &FunctionTable,
        id: FunctionId,
    ) -> Result<Option<Function>, IncompleteFunctionError> {
        match self.staged_functions.get(&id) {
            Some(record) => Ok(record.function.clone()),
            None => functions
                .try_get_by_id(id)
                .map(|function| function.map(|function| function.as_ref().clone()))
                .map_err(IncompleteFunctionError::function_creation),
        }
    }

    fn function_origin(
        &self,
        functions: &FunctionTable,
        id: FunctionId,
    ) -> Result<Option<ReferenceOrigin>, IncompleteFunctionError> {
        match self.staged_functions.get(&id) {
            Some(record) => Ok(record.function.as_ref().map(Function::origin)),
            None => functions
                .try_get_by_id(id)
                .map(|function| function.map(|function| function.origin()))
                .map_err(IncompleteFunctionError::function_creation),
        }
    }

    fn resolve_block(
        &mut self,
        blocks: &CodeBlockTable,
        materialisation: NormalisedCodeBlockRecord,
    ) -> Result<CodeBlockId, IncompleteFunctionError> {
        if self.block_locations.contains(materialisation.address()) {
            for id in self.block_locations.ids(materialisation.address()) {
                let matches = match self.staged_code_blocks.get(&id) {
                    Some(StagedCodeBlockRecord {
                        block: Some(block), ..
                    }) => materialisation.matches(block),
                    Some(StagedCodeBlockRecord { block: None, .. }) | None => blocks
                        .try_get_by_id(id)
                        .map_err(IncompleteFunctionError::block_creation)?
                        .is_some_and(|block| materialisation.matches(&block)),
                };
                if matches {
                    if self
                        .staged_code_blocks
                        .get(&id)
                        .is_some_and(|record| record.block.is_none())
                    {
                        self.staged_code_blocks.remove(&id);
                    }
                    return Ok(id);
                }
            }
        }

        if !blocks.is_persistent()
            && !blocks.is_empty()
            && let Some(block) = blocks.find_by_range_and_context(
                materialisation.address_range(),
                materialisation.context(),
                |block| match self.staged_code_blocks.get(&block.id()) {
                    Some(StagedCodeBlockRecord {
                        block: Some(staged),
                        ..
                    }) => materialisation.matches(staged),
                    Some(StagedCodeBlockRecord { block: None, .. }) | None => {
                        materialisation.matches(block)
                    }
                },
            )
        {
            let id = block.id();
            if self
                .staged_code_blocks
                .get(&id)
                .is_some_and(|record| record.block.is_none())
            {
                self.staged_code_blocks.remove(&id);
            }
            return Ok(id);
        }

        let id = blocks.pending_id(self.block_reservations.len());
        self.block_reservations.push(id);
        let address = materialisation.address();
        let block = materialisation.materialise(id);
        self.staged_code_blocks.insert(
            id,
            StagedCodeBlockRecord {
                block: Some(block),
                is_new: true,
            },
        );
        self.block_locations.insert(address, id);
        Ok(id)
    }

    fn load_existing_block_locations(
        &mut self,
        blocks: &CodeBlockTable,
        function: &NormalisedFunctionRecord,
    ) -> Result<(), IncompleteFunctionError> {
        if !blocks.is_persistent() {
            return Ok(());
        }

        let mut starts = function
            .block_addresses()
            .filter(|address| !self.block_locations.contains(*address))
            .collect::<Vec<_>>();
        starts.sort_unstable();
        starts.dedup();
        let locations = blocks
            .try_ids_at_starts(&starts)
            .map_err(IncompleteFunctionError::block_creation)?;
        self.block_locations.append(locations);
        Ok(())
    }

    fn stage_function(
        &mut self,
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
        id: FunctionId,
        function: Option<Function>,
    ) -> Result<(), IncompleteFunctionError> {
        let previous = self.function_by_id(functions, id)?;
        if let Some(previous) = &previous {
            for (_, block) in previous.blocks() {
                self.by_block_mut(functions, block).remove(id);
            }
            if function
                .as_ref()
                .is_none_or(|function| function.entry() != previous.entry())
            {
                self.function_addresses.insert(previous.entry(), None);
            }
        }
        if let Some(function) = &function {
            for (_, block) in function.blocks() {
                self.by_block_mut(functions, block).insert(id);
            }
            self.function_addresses
                .insert(function.entry(), Some(function.id()));
        }
        let is_new = self.new_function(id);
        self.staged_functions.insert(
            id,
            StagedFunctionRecord {
                function: function.clone(),
                is_new,
            },
        );

        if let Some(previous) = previous {
            for (_, block) in previous.blocks() {
                if self.by_block_mut(functions, block).is_empty() {
                    self.stage_block_removal(blocks, block)?;
                }
            }
        }
        if let Some(function) = function {
            for (_, block) in function.blocks() {
                if !self.by_block_mut(functions, block).is_empty()
                    && self
                        .staged_code_blocks
                        .get(&block)
                        .is_some_and(|record| record.block.is_none())
                {
                    self.staged_code_blocks.remove(&block);
                }
            }
        }
        Ok(())
    }

    fn stage_block_removal(
        &mut self,
        blocks: &CodeBlockTable,
        id: CodeBlockId,
    ) -> Result<(), IncompleteFunctionError> {
        if self.new_block(id) {
            if let Some(StagedCodeBlockRecord {
                block: Some(block), ..
            }) = self.staged_code_blocks.remove(&id)
            {
                self.remove_block_location(block.address(), id);
            }
            self.cancelled_blocks.insert(id);
            return Ok(());
        }

        if blocks
            .try_get_by_id(id)
            .map_err(IncompleteFunctionError::block_creation)?
            .is_some()
        {
            self.staged_code_blocks.insert(
                id,
                StagedCodeBlockRecord {
                    block: None,
                    is_new: false,
                },
            );
        }
        Ok(())
    }

    fn remove_block_location(&mut self, address: Address, id: CodeBlockId) {
        self.block_locations.remove(address, id);
    }

    fn coverage(
        &self,
        blocks: &CodeBlockTable,
        ids: impl IntoIterator<Item = CodeBlockId>,
    ) -> Result<AddressRangeSet, IncompleteFunctionError> {
        let mut coverage = AddressRangeSet::new();
        for id in ids {
            self.with_block(blocks, id, |block| block.coverage_into(&mut coverage))?;
        }
        Ok(coverage)
    }

    fn with_block<R>(
        &self,
        blocks: &CodeBlockTable,
        id: CodeBlockId,
        f: impl FnOnce(&CodeBlock) -> R,
    ) -> Result<Option<R>, IncompleteFunctionError> {
        match self.staged_code_blocks.get(&id) {
            Some(StagedCodeBlockRecord {
                block: Some(block), ..
            }) => Ok(Some(f(block))),
            Some(StagedCodeBlockRecord { block: None, .. }) => Ok(None),
            None => blocks
                .try_get_by_id(id)
                .map(|block| block.map(|block| f(&block)))
                .map_err(IncompleteFunctionError::block_creation),
        }
    }

    fn functions_containing(
        &self,
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
        address: Address,
    ) -> Result<SmallVec<[FunctionId; 4]>, IncompleteFunctionError> {
        let mut containing = SmallVec::new();
        for id in functions.functions_containing(blocks, address) {
            let contains = match self.staged_functions.get(&id) {
                Some(StagedFunctionRecord {
                    function: Some(function),
                    ..
                }) => self.function_contains(blocks, function, address)?,
                Some(StagedFunctionRecord { function: None, .. }) => false,
                None => true,
            };
            if contains {
                containing.push(id);
            }
        }
        for (id, record) in self.staged_functions.iter() {
            let Some(function) = &record.function else {
                continue;
            };
            if containing.binary_search(&id).is_ok()
                || !self.function_contains(blocks, function, address)?
            {
                continue;
            }
            let index = containing.binary_search(&id).unwrap_err();
            containing.insert(index, id);
        }
        Ok(containing)
    }

    pub(crate) fn supported_backing_flow_reference(
        &self,
        table: &FunctionTable,
        blocks: &CodeBlockTable,
        reference: Reference,
    ) -> Result<Option<Reference>, IncompleteFunctionError> {
        let mut supported = None::<Reference>;
        for block in blocks.overlaps(reference.from()) {
            let functions = self
                .by_block
                .get(&block.id())
                .cloned()
                .unwrap_or_else(|| table.get_by_block_id(block.id()));
            for function in functions.iter() {
                let Some(function) = self.function_by_id(table, function)? else {
                    continue;
                };
                for target in block.flow_targets() {
                    let target = function.classify_flow_target(target);
                    if !target.kind().is_global()
                        || target.from() != reference.from()
                        || Some(target.to()) != reference.target().address()
                    {
                        continue;
                    }
                    let candidate = Reference::from_flow(target.from(), target.to(), target.kind())
                        .with_origin(ReferenceOrigin::Derived);
                    supported = Some(match supported {
                        Some(reference) => reference.with_merged_properties(candidate.properties()),
                        None => candidate,
                    });
                }
            }
        }
        Ok(supported)
    }

    fn functions_overlapping(
        &self,
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
        range: &AddressRange,
    ) -> Result<SmallVec<[FunctionId; 8]>, IncompleteFunctionError> {
        let mut overlapping = functions.overlaps(blocks, range).collect::<SmallVec<_>>();

        for (id, record) in self.staged_functions.iter() {
            let intersects = match &record.function {
                Some(function) => self.function_intersects(blocks, function, range)?,
                None => false,
            };
            match overlapping.binary_search(&id) {
                Ok(index) if !intersects => {
                    overlapping.remove(index);
                }
                Err(index) if intersects => overlapping.insert(index, id),
                _ => {}
            }
        }

        Ok(overlapping)
    }

    fn unique_function_containing_address(
        &self,
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
        address: Address,
    ) -> Result<Option<FunctionId>, IncompleteFunctionError> {
        if let Some(function) = self.function_by_address(functions, address)? {
            return Ok(Some(function.id()));
        }

        let containing = self.functions_containing(functions, blocks, address)?;
        Ok(match containing.as_slice() {
            [function] => Some(*function),
            _ => None,
        })
    }

    fn function_contains(
        &self,
        blocks: &CodeBlockTable,
        function: &Function,
        address: Address,
    ) -> Result<bool, IncompleteFunctionError> {
        for (_, id) in function.blocks() {
            if self
                .with_block(blocks, id, |block| {
                    block.address_range().contains_address(address)
                })?
                .unwrap_or(false)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn function_intersects(
        &self,
        blocks: &CodeBlockTable,
        function: &Function,
        range: &AddressRange,
    ) -> Result<bool, IncompleteFunctionError> {
        for (_, id) in function.blocks() {
            if self
                .with_block(blocks, id, |block| block.address_range().intersects(range))?
                .unwrap_or(false)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn by_block_mut<'a>(
        &'a mut self,
        functions: &FunctionTable,
        block: CodeBlockId,
    ) -> &'a mut IdSet<Function> {
        let is_new = self.new_block(block);
        let original_by_block = &mut self.original_by_block;
        self.by_block.entry(block).or_insert_with(|| {
            if is_new {
                IdSet::new()
            } else {
                let current = functions.get_by_block_id(block);
                original_by_block.insert(block, current.clone());
                current
            }
        })
    }

    fn new_function(&self, id: FunctionId) -> bool {
        self.staged_functions
            .get(&id)
            .is_some_and(|record| record.is_new)
    }

    fn new_block(&self, id: CodeBlockId) -> bool {
        self.staged_code_blocks
            .get(&id)
            .is_some_and(|record| record.is_new)
    }

    pub(crate) fn prepare(
        self,
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
    ) -> Result<(PreparedFunctionBatch, EntityWriteBatch), EntityStorageError> {
        let Self {
            staged_code_blocks,
            block_reservations,
            cancelled_blocks,
            cancelled_functions,
            staged_functions,
            function_reservations,
            by_block,
            original_by_block,
            ..
        } = self;
        let mut block_records = Vec::with_capacity(staged_code_blocks.len());
        let mut function_records = Vec::with_capacity(staged_functions.len());
        let mut writes = EntityWriteBatch::with_capacity(
            staged_code_blocks
                .len()
                .saturating_add(staged_functions.len()),
        );

        let blocks_are_new = staged_code_blocks
            .iter()
            .all(|(_, record)| record.is_new && record.block.is_some());
        let (mut staged_code_blocks, staged_code_blocks_ordered) =
            staged_code_blocks.into_entries();
        if blocks_are_new {
            staged_code_blocks.sort_unstable_by_key(|(id, record)| {
                let block = record
                    .block
                    .as_ref()
                    .expect("new block batch contains only insertions");
                (
                    block.space(),
                    block.address().raw_address(),
                    block.last_address().raw_address(),
                    *id,
                )
            });
        } else if !staged_code_blocks_ordered {
            staged_code_blocks.sort_unstable_by_key(|(id, _)| *id);
        }
        for (id, record) in staged_code_blocks {
            let StagedCodeBlockRecord { block, is_new } = record;
            let previous = if is_new {
                None
            } else {
                blocks.try_get_by_id(id)?
            };
            if previous
                .as_ref()
                .is_some_and(|previous| block.as_ref() == Some(previous.as_ref()))
            {
                continue;
            }
            if block.is_none() && previous.is_none() {
                continue;
            }
            let previous = previous.map(|block| block.address_range());
            let encoded_size = match &block {
                Some(block) if blocks.is_persistent() => {
                    let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(block)
                        .map_err(EntityStorageError::encode)?;
                    let encoded_size = encoded.len();
                    writes.push(EntityWrite::insert_archived(
                        CodeBlock::ID.key_for(&id),
                        encoded,
                    ));
                    encoded_size
                }
                Some(_) => 0,
                None => {
                    if previous.is_some() && blocks.is_persistent() {
                        writes.push(EntityWrite::remove(CodeBlock::ID.key_for(&id)));
                    }
                    0
                }
            };
            block_records.push(PreparedCodeBlockRecord::new(
                id,
                block,
                previous,
                encoded_size,
            ));
        }

        let (mut staged_functions, staged_functions_ordered) = staged_functions.into_entries();
        if !staged_functions_ordered {
            staged_functions.sort_unstable_by_key(|(id, _)| *id);
        }
        for (id, record) in staged_functions {
            let StagedFunctionRecord { function, is_new } = record;
            let previous = if is_new {
                None
            } else {
                functions.try_get_by_id(id)?
            };
            if previous
                .as_ref()
                .is_some_and(|previous| function.as_ref() == Some(previous.as_ref()))
            {
                continue;
            }
            if function.is_none() && previous.is_none() {
                continue;
            }
            let previous = previous.map(|function| function.entry());
            let encoded_size = match &function {
                Some(function) if functions.is_persistent() => {
                    let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(function)
                        .map_err(EntityStorageError::encode)?;
                    let encoded_size = encoded.len();
                    writes.push(EntityWrite::insert_archived(
                        Function::ID.key_for(&id),
                        encoded,
                    ));
                    encoded_size
                }
                Some(_) => 0,
                None => {
                    if previous.is_some() && functions.is_persistent() {
                        writes.push(EntityWrite::remove(Function::ID.key_for(&id)));
                    }
                    0
                }
            };
            function_records.push(PreparedFunctionRecord {
                encoded_size,
                function,
                id,
                previous,
            });
        }

        if let FunctionTable::Persistent(table) = functions {
            table.append_prepared_writes(
                &function_records,
                &function_reservations,
                &cancelled_functions,
                &by_block,
                &original_by_block,
                &mut writes,
            )?;
        }
        if let CodeBlockTable::Persistent(table) = blocks {
            table.append_prepared_writes(
                &block_records,
                &block_reservations,
                &cancelled_blocks,
                &mut writes,
            )?;
        }

        Ok((
            PreparedFunctionBatch {
                block_reservations,
                blocks: block_records,
                blocks_are_new,
                cancelled_blocks,
                cancelled_functions,
                function_reservations,
                functions: function_records,
                by_block,
            },
            writes,
        ))
    }
}

impl PreparedFunctionBatch {
    pub(crate) fn publish(self, functions: &mut FunctionTable, blocks: &mut CodeBlockTable) {
        let Self {
            block_reservations,
            blocks: block_entries,
            blocks_are_new,
            cancelled_blocks,
            cancelled_functions,
            function_reservations,
            functions: function_entries,
            by_block,
        } = self;

        let functions_added = function_entries
            .iter()
            .filter(|entry| entry.function.is_some() && entry.previous.is_none())
            .count();
        let functions_removed = function_entries
            .iter()
            .filter(|entry| entry.function.is_none() && entry.previous.is_some())
            .count();
        functions.publish_prepared(
            &function_reservations,
            &cancelled_functions,
            functions_added,
            functions_removed,
        );
        let blocks_added = block_entries
            .iter()
            .filter(|entry| entry.is_addition())
            .count();
        let blocks_removed = block_entries
            .iter()
            .filter(|entry| entry.is_removal())
            .count();
        blocks.publish_prepared(
            &block_reservations,
            &cancelled_blocks,
            blocks_added,
            blocks_removed,
        );

        if blocks_are_new {
            blocks.publish_new_batch(block_entries.into_iter().map(|entry| {
                entry
                    .into_block()
                    .expect("new block batch contains only insertions")
            }));
        } else {
            for entry in block_entries {
                blocks.publish_record(entry);
            }
        }
        for entry in function_entries {
            match entry.function {
                Some(function) => {
                    functions.publish_upsert(function, entry.previous, entry.encoded_size)
                }
                None => functions.publish_remove(
                    entry.id,
                    entry
                        .previous
                        .expect("prepared function removal has a previous entry"),
                ),
            }
        }
        functions.publish_membership(by_block);
    }
}

pub enum FunctionTable {
    Persistent(PersistentFunctionTable),
    Transient(TransientFunctionTable),
}

#[derive(Debug, thiserror::Error)]
pub enum FunctionTableError {
    #[error("function to insert has a different address than that used for insertion")]
    AddressMismatch,
    #[error(transparent)]
    Other(anyhow::Error),
    #[error(transparent)]
    Storage(#[from] EntityStorageError),
}

impl FunctionTableError {
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

impl FunctionTable {
    pub fn new(entities: EntityStorage, cache_bytes: usize) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentFunctionTable::new(
            entities,
            cache_bytes,
        )?))
    }

    pub fn with_worker(
        entities: EntityStorage,
        worker: Arc<WriteBackWorker>,
        cache_bytes: usize,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentFunctionTable::with_worker(
            entities,
            worker,
            cache_bytes,
        )?))
    }

    pub fn new_transient() -> Self {
        Self::Transient(TransientFunctionTable::new())
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(table) => table.flush(),
            Self::Transient(table) => table.flush(),
        }
    }

    pub(crate) fn pending_id(&self, offset: usize) -> FunctionId {
        match self {
            Self::Persistent(table) => table.pending_id(offset),
            Self::Transient(table) => table.pending_id(offset),
        }
    }

    pub(crate) fn stage_materialisation(
        &self,
        blocks: &CodeBlockTable,
        staging: &mut FunctionTableStaging,
        function: NormalisedFunctionRecord,
    ) -> Result<StagedFunctionChangeRecord, IncompleteFunctionError> {
        staging.stage_materialisation(self, blocks, function)
    }

    pub(crate) fn stage_membership(
        &self,
        blocks: &CodeBlockTable,
        staging: &mut FunctionTableStaging,
        function: Function,
    ) -> Result<StagedFunctionChangeRecord, IncompleteFunctionError> {
        staging.stage_membership(self, blocks, function)
    }

    pub(crate) fn stage_properties(
        &self,
        blocks: &CodeBlockTable,
        staging: &mut FunctionTableStaging,
        entry: Address,
        properties: FunctionProperties,
        input_revision: Revision,
    ) -> Result<Option<AddressRangeSet>, IncompleteFunctionError> {
        staging.set_properties(self, blocks, entry, properties, input_revision)
    }

    pub(crate) fn stage_removal(
        &self,
        blocks: &CodeBlockTable,
        staging: &mut FunctionTableStaging,
        id: FunctionId,
    ) -> Result<Option<StagedFunctionRemovalRecord>, IncompleteFunctionError> {
        staging.remove(self, blocks, id)
    }

    pub(crate) fn staged_by_address(
        &self,
        staging: &FunctionTableStaging,
        entry: Address,
    ) -> Result<Option<Function>, IncompleteFunctionError> {
        staging.function_by_address(self, entry)
    }

    pub(crate) fn staged_by_id(
        &self,
        staging: &FunctionTableStaging,
        id: FunctionId,
    ) -> Result<Option<Function>, IncompleteFunctionError> {
        staging.function_by_id(self, id)
    }

    pub(crate) fn staged_origin(
        &self,
        staging: &FunctionTableStaging,
        id: FunctionId,
    ) -> Result<Option<ReferenceOrigin>, IncompleteFunctionError> {
        staging.function_origin(self, id)
    }

    pub(crate) fn staged_overlaps(
        &self,
        blocks: &CodeBlockTable,
        staging: &FunctionTableStaging,
        range: &AddressRange,
    ) -> Result<SmallVec<[FunctionId; 8]>, IncompleteFunctionError> {
        staging.functions_overlapping(self, blocks, range)
    }

    pub(crate) fn staged_unique_function_containing_address(
        &self,
        blocks: &CodeBlockTable,
        staging: &FunctionTableStaging,
        address: Address,
    ) -> Result<Option<FunctionId>, IncompleteFunctionError> {
        staging.unique_function_containing_address(self, blocks, address)
    }

    pub(crate) fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent(_))
    }

    fn publish_prepared(
        &mut self,
        reservations: &[FunctionId],
        cancelled: &BTreeSet<FunctionId>,
        added: usize,
        removed: usize,
    ) {
        match self {
            Self::Persistent(table) => table.publish_transition(reservations, added, removed),
            Self::Transient(table) => {
                table.publish_reservations(reservations);
                for &id in cancelled {
                    table.publish_release(id);
                }
            }
        }
    }

    fn publish_upsert(
        &mut self,
        function: Function,
        previous_entry: Option<Address>,
        encoded_size: usize,
    ) {
        match self {
            Self::Persistent(table) => table.publish_upsert(function, encoded_size),
            Self::Transient(table) => table.publish_upsert(function, previous_entry),
        }
    }

    fn publish_remove(&mut self, id: FunctionId, entry: Address) {
        match self {
            Self::Persistent(table) => table.publish_remove(id),
            Self::Transient(table) => table.publish_remove(id, entry),
        }
    }

    fn publish_membership(&mut self, by_block: FxHashMap<CodeBlockId, IdSet<Function>>) {
        match self {
            Self::Persistent(_) => {}
            Self::Transient(table) => table.publish_membership(by_block),
        }
    }

    pub fn insert<F>(&mut self, addr: Address, f: F) -> Result<Id<Function>, FunctionTableError>
    where
        F: FnOnce(Id<Function>, Address) -> Result<Function, FunctionTableError>,
    {
        self.insert_with(addr, |id, address| {
            f(id, address).map(|function| (function, ()))
        })
        .map(|(id, ())| id)
    }

    pub(crate) fn insert_with<R, F>(
        &mut self,
        addr: Address,
        f: F,
    ) -> Result<(FunctionId, R), FunctionTableError>
    where
        F: FnOnce(Id<Function>, Address) -> Result<(Function, R), FunctionTableError>,
    {
        match self {
            Self::Persistent(table) => table.insert_with(addr, f),
            Self::Transient(table) => table.insert_with(addr, f),
        }
    }

    pub fn get_by_id(&self, id: Id<Function>) -> Option<FunctionRef<'_>> {
        self.try_get_by_id(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_id(
        &self,
        id: Id<Function>,
    ) -> Result<Option<FunctionRef<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(table) => Ok(table.try_get_by_id(id)?.map(EntityRef::cached)),
            Self::Transient(table) => Ok(table.get_by_id(id).map(EntityRef::borrowed)),
        }
    }

    pub fn get_by_address(&self, addr: Address) -> Option<FunctionRef<'_>> {
        self.try_get_by_address(addr)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_address(
        &self,
        addr: Address,
    ) -> Result<Option<FunctionRef<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(table) => Ok(table.try_get_by_address(addr)?.map(EntityRef::cached)),
            Self::Transient(table) => Ok(table.get_by_address(addr).map(EntityRef::borrowed)),
        }
    }

    pub fn get_by_id_mut(&mut self, id: Id<Function>) -> Option<FunctionMut<'_>> {
        self.try_get_by_id_mut(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_id_mut(
        &mut self,
        id: Id<Function>,
    ) -> Result<Option<FunctionMut<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(table) => Ok(table.try_get_by_id_mut(id)?.map(EntityMut::cached)),
            Self::Transient(table) => Ok(table.get_by_id_mut(id).map(EntityMut::borrowed)),
        }
    }

    pub fn get_by_address_mut(&mut self, addr: Address) -> Option<FunctionMut<'_>> {
        self.try_get_by_address_mut(addr)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_get_by_address_mut(
        &mut self,
        addr: Address,
    ) -> Result<Option<FunctionMut<'_>>, EntityStorageError> {
        match self {
            Self::Persistent(table) => {
                Ok(table.try_get_by_address_mut(addr)?.map(EntityMut::cached))
            }
            Self::Transient(table) => Ok(table.get_by_address_mut(addr).map(EntityMut::borrowed)),
        }
    }

    pub fn modify_by_id<R>(
        &mut self,
        id: Id<Function>,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Option<R> {
        self.try_modify_by_id(id, f)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_modify_by_id<R>(
        &mut self,
        id: Id<Function>,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        match self {
            Self::Persistent(table) => table.try_modify_by_id(id, f),
            Self::Transient(table) => Ok(table.modify_by_id(id, f)),
        }
    }

    pub fn modify_by_address<R>(
        &mut self,
        addr: Address,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Option<R> {
        self.try_modify_by_address(addr, f)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_modify_by_address<R>(
        &mut self,
        addr: Address,
        f: impl FnOnce(&mut Function) -> R,
    ) -> Result<Option<R>, EntityStorageError> {
        match self {
            Self::Persistent(table) => table.try_modify_by_address(addr, f),
            Self::Transient(table) => Ok(table.modify_by_address(addr, f)),
        }
    }

    pub fn remove_by_id(&mut self, id: Id<Function>) -> bool {
        self.try_remove_by_id(id)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove_by_id(&mut self, id: Id<Function>) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(table) => table.try_remove_by_id(id),
            Self::Transient(table) => Ok(table.remove_by_id(id)),
        }
    }

    pub fn remove_by_address(&mut self, addr: Address) -> bool {
        self.try_remove_by_address(addr)
            .unwrap_or_else(|error| error.into_fatal())
    }

    pub fn try_remove_by_address(&mut self, addr: Address) -> Result<bool, EntityStorageError> {
        match self {
            Self::Persistent(table) => table.try_remove_by_address(addr),
            Self::Transient(table) => Ok(table.remove_by_address(addr)),
        }
    }

    pub fn contains(&self, addr: Address) -> bool {
        match self {
            Self::Persistent(table) => table.contains(addr),
            Self::Transient(table) => table.contains(addr),
        }
    }

    pub fn addresses(&self) -> Box<dyn Iterator<Item = Address> + '_> {
        match self {
            Self::Persistent(table) => Box::new(table.addresses()),
            Self::Transient(table) => Box::new(table.addresses()),
        }
    }

    pub fn addresses_in_range<R>(
        &self,
        space: AddressSpaceId,
        range: R,
    ) -> Box<dyn Iterator<Item = Address> + '_>
    where
        R: RangeBounds<RawAddress>,
    {
        match self {
            Self::Persistent(table) => Box::new(table.addresses_in_range(space, range)),
            Self::Transient(table) => Box::new(table.addresses_in_range(space, range)),
        }
    }

    pub fn addresses_in_space_after(
        &self,
        space: AddressSpaceId,
        after: Option<RawAddress>,
    ) -> Box<dyn Iterator<Item = Address> + '_> {
        let start = cursor_bound(after);
        self.addresses_in_range(space, (start, Bound::Unbounded))
    }

    pub fn overlaps<'a>(
        &'a self,
        blocks: &'a CodeBlockTable,
        range: &'a AddressRange,
    ) -> impl Iterator<Item = Id<Function>> + 'a {
        let mut functions = SmallVec::<[FunctionId; 8]>::new();
        for block in blocks.overlaps_range(range) {
            for function in self.get_by_block_id(block.id()).iter() {
                if let Err(index) = functions.binary_search(&function) {
                    functions.insert(index, function);
                }
            }
        }
        functions.into_iter()
    }

    pub fn get_by_block_id(&self, block: CodeBlockId) -> IdSet<Function> {
        match self {
            Self::Persistent(table) => table.get_by_block_id(block),
            Self::Transient(table) => table.get_by_block_id(block),
        }
    }

    pub(crate) fn functions_containing(
        &self,
        blocks: &CodeBlockTable,
        address: Address,
    ) -> SmallVec<[FunctionId; 4]> {
        let mut functions = SmallVec::new();

        for block in blocks.overlaps(address) {
            for function in self.get_by_block_id(block.id()).iter() {
                if let Err(index) = functions.binary_search(&function) {
                    functions.insert(index, function);
                }
            }
        }

        functions
    }
    pub fn iter(&self) -> Box<dyn Iterator<Item = FunctionRef<'_>> + '_> {
        match self {
            Self::Persistent(table) => Box::new(table.iter().map(EntityRef::cached)),
            Self::Transient(table) => Box::new(table.iter().map(EntityRef::borrowed)),
        }
    }

    pub fn iter_mut(&mut self) -> Box<dyn Iterator<Item = FunctionMut<'_>> + '_> {
        match self {
            Self::Persistent(table) => Box::new(table.iter_mut().map(EntityMut::cached)),
            Self::Transient(table) => Box::new(table.iter_mut().map(EntityMut::borrowed)),
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
}

impl PersistableProjectEntity for FunctionTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(_) => storage.insert(
                &ProjectEntity::FunctionTable,
                &FunctionTableHeader {
                    version: FUNCTION_TABLE_VERSION,
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
    #[cfg(feature = "sqlite")]
    use crate::storage::PERSISTENT;
    use crate::storage::entities::InMemoryEntityStorage;
    #[cfg(feature = "sqlite")]
    use crate::storage::entities::SqliteEntityStorage;

    fn table() -> FunctionTable {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        FunctionTable::new(storage, 64 * 1024).unwrap()
    }

    #[test]
    fn staged_entities_retain_contiguous_order() {
        let mut entries = StagedEntityRecords::<Function, _>::default();
        let first = FunctionId::from_index(7);
        let second = FunctionId::from_index(8);

        entries.reserve(2);
        assert_eq!(entries.insert(first, 11), None);
        assert_eq!(entries.insert(second, 12), None);
        assert_eq!(entries.insert(first, 13), Some(11));
        assert_eq!(entries.get(&first), Some(&13));

        let (entries, ordered) = entries.into_entries();
        assert!(ordered);
        assert_eq!(entries, [(first, 13), (second, 12)]);
    }

    #[test]
    fn staged_entities_promote_discontinuous_ids() {
        let mut entries = StagedEntityRecords::<Function, _>::default();
        let first = FunctionId::from_index(7);
        let third = FunctionId::from_index(9);

        entries.insert(first, 11);
        entries.insert(third, 13);

        let (mut entries, ordered) = entries.into_entries();
        assert!(!ordered);
        entries.sort_unstable_by_key(|(id, _)| *id);
        assert_eq!(entries, [(first, 11), (third, 13)]);
    }

    #[test]
    fn staged_entities_promote_before_removal() {
        let mut entries = StagedEntityRecords::<Function, _>::default();
        let first = FunctionId::from_index(7);
        let second = FunctionId::from_index(8);

        entries.insert(first, 11);
        entries.insert(second, 12);

        assert_eq!(entries.remove(&first), Some(11));
        assert_eq!(entries.get(&first), None);
        assert_eq!(entries.get(&second), Some(&12));
        assert_eq!(entries.len(), 1);
        assert!(!entries.into_entries().1);
    }

    #[test]
    fn basic_operations() {
        let mut table = table();

        let addr = Address::from(0x1000);
        let func_id = table
            .insert(addr, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();

        assert_eq!(table.len(), 1);

        let func = table.get_by_address(addr).unwrap();
        assert_eq!(func.id(), func_id);
        drop(func);

        assert!(table.remove_by_id(func_id));
        assert_eq!(table.len(), 0);

        assert!(table.get_by_address(addr).is_none());
    }

    #[test]
    fn removal_operations() {
        let mut table = table();

        let addr1 = Address::from(0x1000);
        let addr2 = Address::from(0x2000);
        let addr3 = Address::from(0x3000);

        let func_id1 = table
            .insert(addr1, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();

        let func_id2 = table
            .insert(addr2, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();

        assert_eq!(table.len(), 2);

        assert!(table.remove_by_address(addr1));
        assert_eq!(table.len(), 1);

        assert!(table.get_by_address(addr1).is_none());
        assert!(table.get_by_address(addr2).is_some());

        let func_id3 = table
            .insert(addr3, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();

        assert_eq!(table.len(), 2);

        assert_eq!(func_id1.index(), func_id3.index());
        assert_eq!(func_id1.generation() + 1, func_id3.generation());
        assert!(table.get_by_id(func_id1).is_none());
        assert_eq!(table.get_by_id(func_id3).unwrap().entry(), addr3);

        let func_id4 = table
            .insert(addr1, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();

        assert_eq!(table.len(), 3);
        assert_ne!(func_id4.index(), func_id1.index());

        assert!(table.remove_by_id(func_id2));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn index_rebuild_on_open() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());

        {
            let mut table = FunctionTable::new(storage.clone(), 64 * 1024).unwrap();
            table
                .insert(Address::from(0x1000), |id, entry| {
                    Ok(Function::new(id, entry))
                })
                .unwrap();
            table
                .insert(Address::from(0x2000), |id, entry| {
                    Ok(Function::new(id, entry))
                })
                .unwrap();
        }

        let table = FunctionTable::new(storage, 64 * 1024).unwrap();
        assert_eq!(table.len(), 2);
        assert!(table.get_by_address(Address::from(0x1000)).is_some());
        assert!(table.get_by_address(Address::from(0x2000)).is_some());
    }

    #[test]
    fn worker_round_trip() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());

        {
            let worker = WriteBackWorker::new(storage.clone()).unwrap();
            let mut table = FunctionTable::with_worker(storage.clone(), worker, 64 * 1024).unwrap();
            table
                .insert(Address::from(0x1000), |id, entry| {
                    Ok(Function::new(id, entry))
                })
                .unwrap();
            table
                .insert(Address::from(0x2000), |id, entry| {
                    Ok(Function::new(id, entry))
                })
                .unwrap();
            table.flush().unwrap();
        }

        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        let table = FunctionTable::with_worker(storage, worker, 64 * 1024).unwrap();
        assert_eq!(table.len(), 2);
        assert!(table.get_by_address(Address::from(0x1000)).is_some());
        assert!(table.get_by_address(Address::from(0x2000)).is_some());
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn free_id_reuse_after_reopen_sqlite() {
        let dir = TempDir::new().unwrap();

        {
            let storage =
                EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
            let worker = WriteBackWorker::new(storage.clone()).unwrap();
            let mut table = FunctionTable::with_worker(storage, worker, 64 * 1024).unwrap();

            for base in 1..=5u64 {
                table
                    .insert(Address::from(base * 0x1000), |id, entry| {
                        Ok(Function::new(id, entry))
                    })
                    .unwrap();
            }

            assert!(table.remove_by_address(Address::from(0x2000)));
            assert!(table.remove_by_address(Address::from(0x4000)));

            table.flush().unwrap();
        }

        let storage =
            EntityStorage::new(SqliteEntityStorage::<PERSISTENT>::new(dir.path()).unwrap());
        let worker = WriteBackWorker::new(storage.clone()).unwrap();
        let mut table = FunctionTable::with_worker(storage, worker, 64 * 1024).unwrap();

        assert_eq!(table.len(), 3);

        let first = table
            .insert(Address::from(0x6000), |id, entry| {
                Ok(Function::new(id, entry))
            })
            .unwrap();
        let second = table
            .insert(Address::from(0x7000), |id, entry| {
                Ok(Function::new(id, entry))
            })
            .unwrap();
        let third = table
            .insert(Address::from(0x8000), |id, entry| {
                Ok(Function::new(id, entry))
            })
            .unwrap();

        assert_eq!(
            [
                (first.index(), first.generation()),
                (second.index(), second.generation()),
                (third.index(), third.generation()),
            ],
            [(1, 1), (3, 1), (5, 0)]
        );
    }

    #[test]
    fn transient_basic_operations() {
        let mut table = FunctionTable::new_transient();

        let addr = Address::from(0x1000);
        let func_id = table
            .insert(addr, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();

        assert_eq!(table.len(), 1);

        let func = table.get_by_address(addr).unwrap();
        assert_eq!(func.id(), func_id);
        drop(func);

        assert!(table.remove_by_id(func_id));
        assert_eq!(table.len(), 0);
        assert!(table.get_by_address(addr).is_none());
    }

    #[test]
    fn stale_id_does_not_remove_reused_slot() {
        let mut table = FunctionTable::new_transient();
        let first_entry = Address::from(0x1000u64);
        let second_entry = Address::from(0x2000u64);
        let first = table
            .insert(first_entry, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();
        assert!(table.remove_by_id(first));

        let second = table
            .insert(second_entry, |id, entry| Ok(Function::new(id, entry)))
            .unwrap();
        assert_eq!(first.index(), second.index());
        assert_ne!(first, second);
        assert!(!table.remove_by_id(first));
        assert_eq!(
            table.get_by_id(second).map(|function| function.entry()),
            Some(second_entry)
        );
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn transient_iter_mut_mutate_reload() {
        let mut table = FunctionTable::new_transient();

        let addrs = [0x1000u64, 0x2000, 0x3000].map(Address::from);
        let ids = addrs
            .iter()
            .map(|&addr| {
                table
                    .insert(addr, |id, entry| Ok(Function::new(id, entry)))
                    .unwrap()
            })
            .collect::<Vec<_>>();

        for mut function in table.iter_mut() {
            function.set_name("renamed");
        }

        for &id in &ids {
            let function = table.get_by_id(id).unwrap();
            assert_eq!(function.name().as_deref(), Some("renamed"));
        }
    }
}
