use std::collections::hash_map::Iter as HashMapIter;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;
use std::{fmt, mem, slice};

use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::ir::function::FunctionMaterialisation;
use crate::ir::{
    Address, AddressRange, AddressRangeSet, CodeBlock, CodeBlockId, CodeBlockMaterialisation,
    CodeBlockTable, Function, FunctionId, FunctionProperties, Id, IdAllocator,
    IncompleteFunctionError, PreparedCodeBlockMutation, RawAddress, Reference, ReferenceOrigin,
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
    owners: FxHashMap<CodeBlockId, SmallVec<[FunctionId; 2]>>,
}

impl FunctionIndex {
    fn new(allocator: IdAllocator<Function>, addresses: BTreeMap<Address, FunctionId>) -> Self {
        Self {
            allocator,
            addresses,
            owners: FxHashMap::default(),
        }
    }

    fn insert_membership(&mut self, function: &Function) {
        self.insert_members(function.id(), function.blocks().map(|(_, block)| block));
    }

    fn insert_members(
        &mut self,
        function: FunctionId,
        blocks: impl IntoIterator<Item = CodeBlockId>,
    ) {
        for block in blocks {
            let owners = self.owners.entry(block).or_default();
            if let Err(index) = owners.binary_search(&function) {
                owners.insert(index, function);
            }
        }
    }

    fn remove_membership(&mut self, function: &Function) {
        self.remove_members(function.id(), function.blocks().map(|(_, block)| block));
    }

    fn remove_members(
        &mut self,
        function: FunctionId,
        blocks: impl IntoIterator<Item = CodeBlockId>,
    ) {
        for block in blocks {
            let remove = self.owners.get_mut(&block).is_some_and(|owners| {
                if let Ok(index) = owners.binary_search(&function) {
                    owners.remove(index);
                }
                owners.is_empty()
            });

            if remove {
                self.owners.remove(&block);
            }
        }
    }

    fn owners(&self, block: CodeBlockId) -> &[FunctionId] {
        self.owners.get(&block).map_or(&[], SmallVec::as_slice)
    }

    fn publish_owners(&mut self, mut staged: FxHashMap<CodeBlockId, SmallVec<[FunctionId; 2]>>) {
        if self.owners.is_empty() {
            staged.retain(|_, owners| !owners.is_empty());
            self.owners = staged;
            return;
        }

        for (block, owners) in staged {
            if owners.is_empty() {
                self.owners.remove(&block);
            } else {
                self.owners.insert(block, owners);
            }
        }
    }
}

enum StagedEntities<T, V> {
    Empty {
        capacity: usize,
    },
    Ordered {
        first: Id<T>,
        entries: Vec<(Id<T>, V)>,
    },
    Sparse(FxHashMap<Id<T>, V>),
}

impl<T, V> Default for StagedEntities<T, V> {
    fn default() -> Self {
        Self::Empty { capacity: 0 }
    }
}

impl<T, V> StagedEntities<T, V> {
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

    fn iter(&self) -> StagedEntityIter<'_, T, V> {
        match self {
            Self::Empty { .. } => StagedEntityIter::Empty,
            Self::Ordered { entries, .. } => StagedEntityIter::Ordered(entries.iter()),
            Self::Sparse(entries) => StagedEntityIter::Sparse(entries.iter()),
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

enum StagedEntityIter<'a, T, V> {
    Empty,
    Ordered(slice::Iter<'a, (Id<T>, V)>),
    Sparse(HashMapIter<'a, Id<T>, V>),
}

impl<'a, T, V> Iterator for StagedEntityIter<'a, T, V> {
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
pub(crate) struct FunctionTableStage {
    function_mutations: StagedEntities<Function, StagedFunction>,
    function_addresses: FxHashMap<Address, Option<FunctionId>>,
    function_reservations: Vec<FunctionId>,
    cancelled_functions: BTreeSet<FunctionId>,
    block_mutations: StagedEntities<CodeBlock, StagedBlock>,
    block_locations: FxHashMap<Address, SmallVec<[CodeBlockId; 2]>>,
    block_reservations: Vec<CodeBlockId>,
    cancelled_blocks: BTreeSet<CodeBlockId>,
    owners: FxHashMap<CodeBlockId, SmallVec<[FunctionId; 2]>>,
    original_owners: FxHashMap<CodeBlockId, SmallVec<[FunctionId; 2]>>,
}

struct StagedFunction {
    function: Option<Function>,
    is_new: bool,
}

struct StagedBlock {
    block: Option<CodeBlock>,
    is_new: bool,
}

pub(crate) struct PreparedFunctionTables {
    block_reservations: Vec<CodeBlockId>,
    blocks: Vec<PreparedCodeBlockMutation>,
    blocks_are_new: bool,
    cancelled_blocks: BTreeSet<CodeBlockId>,
    cancelled_functions: BTreeSet<FunctionId>,
    function_reservations: Vec<FunctionId>,
    functions: Vec<PreparedFunctionEntry>,
    owners: FxHashMap<CodeBlockId, SmallVec<[FunctionId; 2]>>,
}

pub(crate) struct PreparedFunctionMutation {
    affected_blocks: SmallVec<[CodeBlockId; 16]>,
    call_targets: BTreeSet<Address>,
    coverage: AddressRangeSet,
    id: FunctionId,
    previous_coverage: AddressRangeSet,
    references: Vec<Reference>,
    replaces_existing: bool,
}

pub(crate) struct RemovedFunction {
    coverage: AddressRangeSet,
    function: Function,
}

impl RemovedFunction {
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

impl PreparedFunctionMutation {
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

struct PreparedFunctionEntry {
    encoded_size: usize,
    function: Option<Function>,
    id: FunctionId,
    previous: Option<Address>,
}

impl FunctionTableStage {
    pub(crate) fn reserve_functions(&mut self, additional: usize) {
        self.function_mutations.reserve(additional);
        self.function_addresses.reserve(additional);
        self.function_reservations.reserve(additional);
    }

    fn stage_materialisation(
        &mut self,
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
        mut function: FunctionMaterialisation,
    ) -> Result<PreparedFunctionMutation, IncompleteFunctionError> {
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
        let mutation = PreparedFunctionMutation {
            affected_blocks: SmallVec::new(),
            call_targets,
            coverage,
            id,
            previous_coverage: AddressRangeSet::new(),
            references,
            replaces_existing: !is_new,
        };
        self.stage_mutation(functions, blocks, function, previous, is_new, mutation)
    }

    fn stage_membership(
        &mut self,
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
        mut function: Function,
    ) -> Result<PreparedFunctionMutation, IncompleteFunctionError> {
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
        let mutation = PreparedFunctionMutation {
            affected_blocks: SmallVec::new(),
            call_targets,
            coverage,
            id,
            previous_coverage: AddressRangeSet::new(),
            references,
            replaces_existing: !is_new,
        };
        self.stage_mutation(functions, blocks, function, previous, is_new, mutation)
    }

    fn stage_mutation(
        &mut self,
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
        function: Function,
        previous: Option<Function>,
        is_new: bool,
        mut mutation: PreparedFunctionMutation,
    ) -> Result<PreparedFunctionMutation, IncompleteFunctionError> {
        let entry = function.entry();
        let id = function.id();

        let replaces_existing = previous.is_some();
        if let Some(previous) = &previous {
            for (_, block) in previous.blocks() {
                mutation.affected_blocks.push(block);
                self.with_block(blocks, block, |block| {
                    block.coverage_into(&mut mutation.previous_coverage);
                })?;
                Self::remove_owner(self.owners_mut(functions, block), id);
            }
            if previous.entry() != entry {
                self.function_addresses.insert(previous.entry(), None);
            }
        }

        for (_, block) in function.blocks() {
            mutation.affected_blocks.push(block);
            Self::insert_owner(self.owners_mut(functions, block), id);
            if self
                .block_mutations
                .get(&block)
                .is_some_and(|mutation| mutation.block.is_none())
            {
                self.block_mutations.remove(&block);
            }
        }

        mutation.affected_blocks.sort_unstable();
        mutation.affected_blocks.dedup();
        if replaces_existing {
            for &block in &mutation.affected_blocks {
                if self.owners_mut(functions, block).is_empty() {
                    self.stage_block_removal(blocks, block)?;
                }
            }
        }

        self.function_addresses.insert(entry, Some(id));
        self.function_mutations.insert(
            id,
            StagedFunction {
                function: Some(function),
                is_new,
            },
        );

        Ok(mutation)
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
    ) -> Result<Option<RemovedFunction>, IncompleteFunctionError> {
        let Some(function) = self.function_by_id(functions, id)? else {
            return Ok(None);
        };
        let coverage = self.coverage(blocks, function.blocks().map(|(_, block)| block))?;
        self.stage_function(functions, blocks, id, None)?;
        if self.new_function(id) {
            self.function_mutations.remove(&id);
            self.cancelled_functions.insert(id);
        }
        Ok(Some(RemovedFunction::new(function, coverage)))
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
        match self.function_mutations.get(&id) {
            Some(mutation) => Ok(mutation.function.clone()),
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
        match self.function_mutations.get(&id) {
            Some(mutation) => Ok(mutation.function.as_ref().map(Function::origin)),
            None => functions
                .try_get_by_id(id)
                .map(|function| function.map(|function| function.origin()))
                .map_err(IncompleteFunctionError::function_creation),
        }
    }

    fn resolve_block(
        &mut self,
        blocks: &CodeBlockTable,
        materialisation: CodeBlockMaterialisation,
    ) -> Result<CodeBlockId, IncompleteFunctionError> {
        if let Some(locations) = self.block_locations.get(&materialisation.address()) {
            for &id in locations {
                let matches = match self.block_mutations.get(&id) {
                    Some(StagedBlock {
                        block: Some(block), ..
                    }) => materialisation.matches(block),
                    Some(StagedBlock { block: None, .. }) | None => blocks
                        .try_get_by_id(id)
                        .map_err(IncompleteFunctionError::block_creation)?
                        .is_some_and(|block| materialisation.matches(&block)),
                };
                if matches {
                    if self
                        .block_mutations
                        .get(&id)
                        .is_some_and(|mutation| mutation.block.is_none())
                    {
                        self.block_mutations.remove(&id);
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
                |block| match self.block_mutations.get(&block.id()) {
                    Some(StagedBlock {
                        block: Some(staged),
                        ..
                    }) => materialisation.matches(staged),
                    Some(StagedBlock { block: None, .. }) | None => materialisation.matches(block),
                },
            )
        {
            let id = block.id();
            if self
                .block_mutations
                .get(&id)
                .is_some_and(|mutation| mutation.block.is_none())
            {
                self.block_mutations.remove(&id);
            }
            return Ok(id);
        }

        let id = blocks.pending_id(self.block_reservations.len());
        self.block_reservations.push(id);
        let address = materialisation.address();
        let block = materialisation.into_block(id);
        self.block_mutations.insert(
            id,
            StagedBlock {
                block: Some(block),
                is_new: true,
            },
        );
        self.block_locations.entry(address).or_default().push(id);
        Ok(id)
    }

    fn load_existing_block_locations(
        &mut self,
        blocks: &CodeBlockTable,
        function: &FunctionMaterialisation,
    ) -> Result<(), IncompleteFunctionError> {
        if !blocks.is_persistent() {
            return Ok(());
        }

        let mut starts = function
            .block_addresses()
            .filter(|address| !self.block_locations.contains_key(address))
            .collect::<Vec<_>>();
        starts.sort_unstable();
        starts.dedup();
        let locations = blocks
            .try_ids_at_starts(&starts)
            .map_err(IncompleteFunctionError::block_creation)?;
        self.block_locations.extend(locations);
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
                Self::remove_owner(self.owners_mut(functions, block), id);
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
                Self::insert_owner(self.owners_mut(functions, block), id);
            }
            self.function_addresses
                .insert(function.entry(), Some(function.id()));
        }
        let is_new = self.new_function(id);
        self.function_mutations.insert(
            id,
            StagedFunction {
                function: function.clone(),
                is_new,
            },
        );

        if let Some(previous) = previous {
            for (_, block) in previous.blocks() {
                if self.owners_mut(functions, block).is_empty() {
                    self.stage_block_removal(blocks, block)?;
                }
            }
        }
        if let Some(function) = function {
            for (_, block) in function.blocks() {
                if !self.owners_mut(functions, block).is_empty()
                    && self
                        .block_mutations
                        .get(&block)
                        .is_some_and(|mutation| mutation.block.is_none())
                {
                    self.block_mutations.remove(&block);
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
            if let Some(StagedBlock {
                block: Some(block), ..
            }) = self.block_mutations.remove(&id)
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
            self.block_mutations.insert(
                id,
                StagedBlock {
                    block: None,
                    is_new: false,
                },
            );
        }
        Ok(())
    }

    fn remove_block_location(&mut self, address: Address, id: CodeBlockId) {
        let remove = self.block_locations.get_mut(&address).is_some_and(|ids| {
            ids.retain(|candidate| *candidate != id);
            ids.is_empty()
        });
        if remove {
            self.block_locations.remove(&address);
        }
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
        match self.block_mutations.get(&id) {
            Some(StagedBlock {
                block: Some(block), ..
            }) => Ok(Some(f(block))),
            Some(StagedBlock { block: None, .. }) => Ok(None),
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
            let contains = match self.function_mutations.get(&id) {
                Some(StagedFunction {
                    function: Some(function),
                    ..
                }) => self.function_contains(blocks, function, address)?,
                Some(StagedFunction { function: None, .. }) => false,
                None => true,
            };
            if contains {
                containing.push(id);
            }
        }
        for (id, mutation) in self.function_mutations.iter() {
            let Some(function) = &mutation.function else {
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
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
        reference: Reference,
    ) -> Result<Option<Reference>, IncompleteFunctionError> {
        let mut supported = None::<Reference>;
        for block in blocks.overlaps(reference.from()) {
            let owners = self
                .owners
                .get(&block.id())
                .cloned()
                .unwrap_or_else(|| functions.block_owners(block.id()));
            for owner in owners {
                let Some(function) = self.function_by_id(functions, owner)? else {
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

        for (id, mutation) in self.function_mutations.iter() {
            let intersects = match &mutation.function {
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

    fn function_owning_address(
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

    fn owners_mut<'a>(
        &'a mut self,
        functions: &FunctionTable,
        block: CodeBlockId,
    ) -> &'a mut SmallVec<[FunctionId; 2]> {
        let is_new = self.new_block(block);
        let original_owners = &mut self.original_owners;
        self.owners.entry(block).or_insert_with(|| {
            if is_new {
                SmallVec::new()
            } else {
                let owners = functions.block_owners(block);
                original_owners.insert(block, owners.clone());
                owners
            }
        })
    }

    fn insert_owner(owners: &mut SmallVec<[FunctionId; 2]>, function: FunctionId) {
        if let Err(index) = owners.binary_search(&function) {
            owners.insert(index, function);
        }
    }

    fn remove_owner(owners: &mut SmallVec<[FunctionId; 2]>, function: FunctionId) {
        if let Ok(index) = owners.binary_search(&function) {
            owners.remove(index);
        }
    }

    fn new_function(&self, id: FunctionId) -> bool {
        self.function_mutations
            .get(&id)
            .is_some_and(|mutation| mutation.is_new)
    }

    fn new_block(&self, id: CodeBlockId) -> bool {
        self.block_mutations
            .get(&id)
            .is_some_and(|mutation| mutation.is_new)
    }

    pub(crate) fn prepare(
        self,
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
    ) -> Result<(PreparedFunctionTables, EntityWriteBatch), EntityStorageError> {
        let Self {
            block_mutations,
            block_reservations,
            cancelled_blocks,
            cancelled_functions,
            function_mutations,
            function_reservations,
            owners,
            original_owners,
            ..
        } = self;
        let mut prepared_blocks = Vec::with_capacity(block_mutations.len());
        let mut prepared_functions = Vec::with_capacity(function_mutations.len());
        let mut writes = EntityWriteBatch::with_capacity(
            block_mutations
                .len()
                .saturating_add(function_mutations.len()),
        );

        let blocks_are_new = block_mutations
            .iter()
            .all(|(_, mutation)| mutation.is_new && mutation.block.is_some());
        let (mut block_mutations, block_mutations_ordered) = block_mutations.into_entries();
        if blocks_are_new {
            block_mutations.sort_unstable_by_key(|(id, mutation)| {
                let block = mutation
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
        } else if !block_mutations_ordered {
            block_mutations.sort_unstable_by_key(|(id, _)| *id);
        }
        for (id, mutation) in block_mutations {
            let StagedBlock { block, is_new } = mutation;
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
                    writes.push(EntityWrite::insert_archive(
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
            prepared_blocks.push(PreparedCodeBlockMutation::new(
                id,
                block,
                previous,
                encoded_size,
            ));
        }

        let (mut function_mutations, function_mutations_ordered) =
            function_mutations.into_entries();
        if !function_mutations_ordered {
            function_mutations.sort_unstable_by_key(|(id, _)| *id);
        }
        for (id, mutation) in function_mutations {
            let StagedFunction { function, is_new } = mutation;
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
                    writes.push(EntityWrite::insert_archive(
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
            prepared_functions.push(PreparedFunctionEntry {
                encoded_size,
                function,
                id,
                previous,
            });
        }

        if let FunctionTable::Persistent(table) = functions {
            table.append_stage_writes(
                &prepared_functions,
                &function_reservations,
                &cancelled_functions,
                &owners,
                &original_owners,
                &mut writes,
            )?;
        }
        if let CodeBlockTable::Persistent(table) = blocks {
            table.append_stage_writes(
                &prepared_blocks,
                &block_reservations,
                &cancelled_blocks,
                &mut writes,
            )?;
        }

        Ok((
            PreparedFunctionTables {
                block_reservations,
                blocks: prepared_blocks,
                blocks_are_new,
                cancelled_blocks,
                cancelled_functions,
                function_reservations,
                functions: prepared_functions,
                owners,
            },
            writes,
        ))
    }
}

impl PreparedFunctionTables {
    pub(crate) fn publish(self, functions: &mut FunctionTable, blocks: &mut CodeBlockTable) {
        let Self {
            block_reservations,
            blocks: block_entries,
            blocks_are_new,
            cancelled_blocks,
            cancelled_functions,
            function_reservations,
            functions: function_entries,
            owners,
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
                blocks.publish_mutation(entry);
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
        functions.publish_owners(owners);
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
        stage: &mut FunctionTableStage,
        function: FunctionMaterialisation,
    ) -> Result<PreparedFunctionMutation, IncompleteFunctionError> {
        stage.stage_materialisation(self, blocks, function)
    }

    pub(crate) fn stage_membership(
        &self,
        blocks: &CodeBlockTable,
        stage: &mut FunctionTableStage,
        function: Function,
    ) -> Result<PreparedFunctionMutation, IncompleteFunctionError> {
        stage.stage_membership(self, blocks, function)
    }

    pub(crate) fn stage_properties(
        &self,
        blocks: &CodeBlockTable,
        stage: &mut FunctionTableStage,
        entry: Address,
        properties: FunctionProperties,
        input_revision: Revision,
    ) -> Result<Option<AddressRangeSet>, IncompleteFunctionError> {
        stage.set_properties(self, blocks, entry, properties, input_revision)
    }

    pub(crate) fn stage_removal(
        &self,
        blocks: &CodeBlockTable,
        stage: &mut FunctionTableStage,
        id: FunctionId,
    ) -> Result<Option<RemovedFunction>, IncompleteFunctionError> {
        stage.remove(self, blocks, id)
    }

    pub(crate) fn staged_by_address(
        &self,
        stage: &FunctionTableStage,
        entry: Address,
    ) -> Result<Option<Function>, IncompleteFunctionError> {
        stage.function_by_address(self, entry)
    }

    pub(crate) fn staged_by_id(
        &self,
        stage: &FunctionTableStage,
        id: FunctionId,
    ) -> Result<Option<Function>, IncompleteFunctionError> {
        stage.function_by_id(self, id)
    }

    pub(crate) fn staged_origin(
        &self,
        stage: &FunctionTableStage,
        id: FunctionId,
    ) -> Result<Option<ReferenceOrigin>, IncompleteFunctionError> {
        stage.function_origin(self, id)
    }

    pub(crate) fn staged_overlaps(
        &self,
        blocks: &CodeBlockTable,
        stage: &FunctionTableStage,
        range: &AddressRange,
    ) -> Result<SmallVec<[FunctionId; 8]>, IncompleteFunctionError> {
        stage.functions_overlapping(self, blocks, range)
    }

    pub(crate) fn staged_function_owning_address(
        &self,
        blocks: &CodeBlockTable,
        stage: &FunctionTableStage,
        address: Address,
    ) -> Result<Option<FunctionId>, IncompleteFunctionError> {
        stage.function_owning_address(self, blocks, address)
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

    fn publish_owners(&mut self, owners: FxHashMap<CodeBlockId, SmallVec<[FunctionId; 2]>>) {
        match self {
            Self::Persistent(_) => {}
            Self::Transient(table) => table.publish_owners(owners),
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
            for function in self.block_owners(block.id()) {
                if let Err(index) = functions.binary_search(&function) {
                    functions.insert(index, function);
                }
            }
        }
        functions.into_iter()
    }

    pub fn functions_containing_block(
        &self,
        block: CodeBlockId,
    ) -> impl ExactSizeIterator<Item = FunctionId> + '_ {
        self.block_owners(block).into_iter()
    }

    pub(crate) fn functions_containing(
        &self,
        blocks: &CodeBlockTable,
        address: Address,
    ) -> SmallVec<[FunctionId; 4]> {
        let mut functions = SmallVec::new();

        for block in blocks.overlaps(address) {
            for function in self.block_owners(block.id()) {
                if let Err(index) = functions.binary_search(&function) {
                    functions.insert(index, function);
                }
            }
        }

        functions
    }

    fn block_owners(&self, block: CodeBlockId) -> SmallVec<[FunctionId; 2]> {
        match self {
            Self::Persistent(table) => table.block_owners(block),
            Self::Transient(table) => table.block_owners(block).into(),
        }
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
        let mut entries = StagedEntities::<Function, _>::default();
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
        let mut entries = StagedEntities::<Function, _>::default();
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
        let mut entries = StagedEntities::<Function, _>::default();
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
