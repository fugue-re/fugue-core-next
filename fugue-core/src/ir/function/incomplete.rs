use std::collections::{BTreeMap, BTreeSet};
use std::mem::{self, size_of};
use std::num::NonZeroUsize;
use std::vec::IntoIter;

use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use thiserror::Error;

use crate::ir::{
    Address, AddressRange, AddressRangeSet, AddressWithContext, CodeBlock, CodeBlockId,
    CodeBlockProperties, CodeBlockTable, FlowKind, FlowTarget, Function, FunctionId,
    FunctionProperties, IncompleteCodeBlock, IncompleteCodeBlockId, Insn, InsnId, InsnList,
    Reference, ReferenceOrigin, Switch, SwitchCase, Symbol,
};
use crate::lifter::ContextSet;
use crate::types::{Confidence, Revision};

pub(crate) struct CodeBlockMaterialisation {
    address: Address,
    context: ContextSet,
    instructions: InsnList,
    len: NonZeroUsize,
    properties: CodeBlockProperties,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FunctionInsnIndex {
    additional: FxHashMap<Address, SmallVec<[InsnId; 1]>>,
    first: FxHashMap<Address, InsnId>,
}

impl FunctionInsnIndex {
    fn clear(&mut self) {
        self.additional.clear();
        self.first.clear();
    }

    fn contains(&self, address: Address) -> bool {
        self.first.contains_key(&address)
    }

    fn first(&self, address: Address) -> Option<InsnId> {
        self.first.get(&address).copied()
    }

    fn ids(&self, address: Address) -> impl Iterator<Item = InsnId> + '_ {
        self.first(address)
            .into_iter()
            .chain(self.additional.get(&address).into_iter().flatten().copied())
    }

    fn insert(&mut self, address: Address, id: InsnId) {
        use std::collections::hash_map::Entry;

        match self.first.entry(address) {
            Entry::Vacant(entry) => {
                entry.insert(id);
            }
            Entry::Occupied(_) => {
                self.additional.entry(address).or_default().push(id);
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.first.is_empty()
    }

    fn estimated_retained_bytes(&self) -> usize {
        let mut size = self
            .first
            .capacity()
            .saturating_mul(size_of::<(Address, InsnId)>())
            .saturating_add(
                self.additional
                    .capacity()
                    .saturating_mul(size_of::<(Address, SmallVec<[InsnId; 1]>)>()),
            );
        for ids in self.additional.values().filter(|ids| ids.spilled()) {
            size = size.saturating_add(ids.capacity().saturating_mul(size_of::<InsnId>()));
        }
        size
    }
}

pub(crate) struct FunctionMaterialisation {
    blocks: Vec<CodeBlockMaterialisation>,
    call_targets: BTreeSet<Address>,
    confidence: Confidence,
    coverage: AddressRangeSet,
    edges: Vec<(usize, usize)>,
    entry: Address,
    entry_block: Option<usize>,
    input_revision: Revision,
    name: Option<Symbol>,
    origin: ReferenceOrigin,
    properties: FunctionProperties,
    references: Vec<Reference>,
    tail_call_sites: SmallVec<[Address; 1]>,
}

enum BlockInstructionSource {
    Ordered(IntoIter<Insn>),
    Shared {
        instructions: Vec<Option<Insn>>,
        remaining_uses: Vec<usize>,
    },
}

impl BlockInstructionSource {
    fn take(&mut self, ids: &[InsnId]) -> InsnList {
        match self {
            Self::Ordered(instructions) => instructions.by_ref().take(ids.len()).collect(),
            Self::Shared {
                instructions,
                remaining_uses,
            } => ids
                .iter()
                .map(|id| {
                    let remaining = &mut remaining_uses[id.index()];
                    *remaining -= 1;
                    if *remaining == 0 {
                        instructions[id.index()]
                            .take()
                            .expect("validated instruction must remain available")
                    } else {
                        instructions[id.index()]
                            .as_ref()
                            .expect("validated instruction must remain available")
                            .clone()
                    }
                })
                .collect(),
        }
    }
}

impl FunctionMaterialisation {
    pub(crate) fn block_addresses(&self) -> impl Iterator<Item = Address> + '_ {
        self.blocks.iter().map(CodeBlockMaterialisation::address)
    }

    pub(crate) fn entry(&self) -> Address {
        self.entry
    }

    pub(crate) fn take_call_targets(&mut self) -> BTreeSet<Address> {
        mem::take(&mut self.call_targets)
    }

    pub(crate) fn take_coverage(&mut self) -> AddressRangeSet {
        mem::take(&mut self.coverage)
    }

    pub(crate) fn take_references(&mut self) -> Vec<Reference> {
        mem::take(&mut self.references)
    }

    pub(crate) fn materialise(
        self,
        id: FunctionId,
        mut resolve_block: impl FnMut(
            CodeBlockMaterialisation,
        ) -> Result<CodeBlockId, IncompleteFunctionError>,
    ) -> Result<Function, IncompleteFunctionError> {
        let mut members = Vec::with_capacity(self.blocks.len());
        for block in self.blocks {
            let address = block.address();
            members.push((address, resolve_block(block)?));
        }

        let entry_block = self.entry_block.map(|entry| members[entry].1);
        let mut edges = self
            .edges
            .into_iter()
            .map(|(source, target)| (members[source].1, members[target].1))
            .collect::<Vec<_>>();
        edges.sort_unstable();
        edges.dedup();

        let mut function =
            Function::new_with(id, self.entry, self.name).with_body(members, edges, entry_block);
        function.set_properties(self.properties);
        function.set_origin(self.origin);
        function.set_confidence(self.confidence);
        function.set_input_revision(self.input_revision);
        function.set_tail_call_sites(self.tail_call_sites);
        Ok(function)
    }
}

impl CodeBlockMaterialisation {
    pub(crate) fn address(&self) -> Address {
        self.address
    }

    pub(crate) fn context(&self) -> &ContextSet {
        &self.context
    }

    pub(crate) fn address_range(&self) -> AddressRange {
        AddressRange::new(
            self.address.space(),
            self.address.raw_address(),
            (self.address + self.len.get() - 1usize).raw_address(),
        )
    }

    pub(crate) fn flow_targets(&self) -> impl Iterator<Item = FlowTarget> + '_ {
        self.instructions.iter().flat_map(Insn::flow_targets)
    }

    pub(crate) fn matches(&self, block: &CodeBlock) -> bool {
        block.start() == self.address
            && block.len() == self.len.get()
            && block.context() == &self.context
            && block.instructions() == &self.instructions
            && block.is_call() == self.properties.contains(CodeBlockProperties::CALL)
            && block.has_unresolved() == self.properties.contains(CodeBlockProperties::UNRESOLVED)
    }

    pub(crate) fn into_block(self, id: CodeBlockId) -> CodeBlock {
        let mut block =
            CodeBlock::new_with(id, self.address, self.len, self.instructions, self.context);
        if self.properties.contains(CodeBlockProperties::CALL) {
            block.mark_call();
        }
        if self.properties.contains(CodeBlockProperties::UNRESOLVED) {
            block.mark_unresolved();
        }
        block
    }
}

#[derive(Debug, Error)]
pub enum IncompleteFunctionError {
    #[error("failed to create block: {0}")]
    BlockCreation(anyhow::Error),
    #[error("failed to create function: {0}")]
    FunctionCreation(anyhow::Error),
    #[error("invalid block id: {0:?}")]
    InvalidBlockId(IncompleteCodeBlockId),
    #[error("invalid zero-length block: {address}")]
    InvalidBlockLength { address: Address },
    #[error("invalid instruction id: {0:?}")]
    InvalidInstructionId(InsnId),
}

impl IncompleteFunctionError {
    pub(crate) fn block_creation<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::BlockCreation(error.into())
    }

    pub(crate) fn function_creation<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::FunctionCreation(error.into())
    }

    fn invalid_block_id(id: IncompleteCodeBlockId) -> Self {
        Self::InvalidBlockId(id)
    }

    fn invalid_block_length(address: Address) -> Self {
        Self::InvalidBlockLength { address }
    }

    fn invalid_instruction_id(id: InsnId) -> Self {
        Self::InvalidInstructionId(id)
    }
}

pub enum InsnEntry<'a> {
    Occupied(OccupiedInsnEntry<'a>),
    Vacant(VacantInsnEntry<'a>),
}

pub struct VacantInsnEntry<'a> {
    address: Address,
    generation: u32,
    insns: &'a mut Vec<Insn>,
    insn_index: &'a mut FunctionInsnIndex,
    unsorted: &'a mut bool,
}

impl<'a> VacantInsnEntry<'a> {
    pub fn insert(self, insn: Insn) -> InsnId {
        assert!(
            self.address == insn.address(),
            "instruction address must match entry address",
        );
        if self
            .insns
            .last()
            .is_some_and(|previous| previous.address() > insn.address())
        {
            *self.unsorted = true;
        }
        let id = InsnId::with_generation(
            self.insns.len().try_into().expect("too many instructions"),
            self.generation,
        );
        self.insns.push(insn);
        self.insn_index.insert(self.address, id);
        id
    }
}

pub struct OccupiedInsnEntry<'a> {
    id: InsnId,
    insns: &'a mut Vec<Insn>,
}

impl OccupiedInsnEntry<'_> {
    pub fn id(&self) -> InsnId {
        self.id
    }

    pub(crate) fn get_mut(&mut self) -> &mut Insn {
        let id = self.id();
        self.insns
            .get_mut(id.index())
            .expect("instruction must exist")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IncompleteFunction {
    name: Option<Symbol>,
    entry: Address,
    entry_block: IncompleteCodeBlockId,
    blocks: Vec<IncompleteCodeBlock>,
    block_generation: u32,
    insns: Vec<Insn>,
    insn_generation: u32,
    insn_index: FunctionInsnIndex,
    insns_unsorted: bool,
    properties: FunctionProperties,
    origin: ReferenceOrigin,
    confidence: Confidence,
    input_revision: Revision,
    pending_switches: Vec<Switch>,
    tail_call_sites: SmallVec<[Address; 1]>,
}

impl IncompleteFunction {
    pub fn new(entry: Address) -> Self {
        Self::new_with(None, entry)
    }

    pub fn new_with(name: impl Into<Option<Symbol>>, entry: Address) -> Self {
        Self {
            name: name.into(),
            entry,
            entry_block: IncompleteCodeBlockId::INVALID,
            blocks: Vec::new(),
            block_generation: 0,
            insns: Vec::new(),
            insn_generation: 0,
            insn_index: FunctionInsnIndex::default(),
            insns_unsorted: false,
            properties: FunctionProperties::NONE,
            origin: ReferenceOrigin::Derived,
            confidence: Confidence::certain(),
            input_revision: Revision::default(),
            pending_switches: Vec::new(),
            tail_call_sites: SmallVec::new(),
        }
    }

    pub(crate) fn with_recycled_insn_index(entry: Address, insn_index: FunctionInsnIndex) -> Self {
        debug_assert!(insn_index.is_empty());
        let mut function = Self::new(entry);
        function.insn_index = insn_index;
        function
    }

    pub(crate) fn recycle_insn_index(&mut self) -> FunctionInsnIndex {
        let mut index = mem::take(&mut self.insn_index);
        index.clear();
        index
    }

    pub fn add_pending_switch(&mut self, switch: Switch) {
        if let Some(pending) = self
            .pending_switches
            .iter_mut()
            .find(|pending| pending.branch() == switch.branch())
        {
            *pending = switch;
        } else {
            self.pending_switches.push(switch);
        }
    }

    pub fn sibling_successor_from_incoming(
        &self,
        block: IncompleteCodeBlockId,
    ) -> Option<AddressWithContext> {
        let branch = self.block(block)?;
        for predecessor in branch.predecessors().iter() {
            let Some(guard) = self.block(predecessor) else {
                continue;
            };
            let mut successors = guard.successors().iter();
            let (Some(first), Some(second), None) =
                (successors.next(), successors.next(), successors.next())
            else {
                continue;
            };
            let sibling = match (first == block, second == block) {
                (true, false) => second,
                (false, true) => first,
                _ => continue,
            };
            let Some(sibling) = self.block(sibling) else {
                continue;
            };
            return Some(AddressWithContext::new(
                sibling.address(),
                sibling.context().clone(),
            ));
        }
        None
    }

    pub(crate) fn has_pending_switch(&self, branch: Address) -> bool {
        self.pending_switches
            .iter()
            .any(|pending| pending.branch() == branch)
    }

    pub fn take_pending_switches(&mut self) -> Vec<Switch> {
        mem::take(&mut self.pending_switches)
    }

    pub fn update_name(&mut self, name: impl Into<Symbol>) {
        self.name = Some(name.into());
    }

    pub fn clear_name(&mut self) {
        self.name = None;
    }

    pub fn name(&self) -> Option<Symbol> {
        self.name
    }

    pub fn entry(&self) -> Address {
        self.entry
    }

    pub fn entry_block(&self) -> &IncompleteCodeBlock {
        self.block(self.entry_block)
            .expect("entry block should always exist")
    }

    pub(crate) fn from_committed(
        entry: Address,
        blocks: &[(Address, CodeBlockId)],
        edges: impl IntoIterator<Item = (CodeBlockId, CodeBlockId)>,
        tail_call_sites: impl IntoIterator<Item = Address>,
        block_table: &CodeBlockTable,
    ) -> Option<Self> {
        let mut function = Self::new(entry);
        let mut block_ids = BTreeMap::new();

        for &(address, id) in blocks {
            if function
                .blocks
                .last()
                .is_some_and(|previous| previous.address() > address)
            {
                return None;
            }

            let block = block_table.get_by_id(id)?;

            let mut insns = Vec::with_capacity(block.instructions().len());
            for insn in block.instructions() {
                insns.push(function.insert_distinct_insn(insn.clone()));
            }

            let incomplete =
                IncompleteCodeBlock::try_new(address, block.len(), insns, block.context().clone())?;

            let incomplete = function.push_block(incomplete);
            block_ids.insert(id, incomplete);
        }

        for (source, target) in edges {
            let (Some(&source), Some(&target)) = (block_ids.get(&source), block_ids.get(&target))
            else {
                continue;
            };
            function.add_block_edge(source, target).ok()?;
        }
        let tail_call_sites = tail_call_sites
            .into_iter()
            .filter(|site| function.contains_insn(*site))
            .collect::<SmallVec<[_; 1]>>();
        function.set_tail_call_sites(tail_call_sites);

        Some(function)
    }

    pub fn push_block(&mut self, block: IncompleteCodeBlock) -> IncompleteCodeBlockId {
        debug_assert!(
            self.blocks.is_empty() || self.blocks.last().unwrap().address() <= block.address(),
            "blocks must be inserted in order",
        );
        let id = IncompleteCodeBlockId::with_generation(
            self.blocks.len().try_into().expect("too many blocks"),
            self.block_generation,
        );
        if self.entry_block.is_invalid() && block.address() == self.entry {
            self.entry_block = id;
        }
        self.blocks.push(block);
        id
    }

    pub fn blocks(&self) -> &[IncompleteCodeBlock] {
        &self.blocks
    }

    pub(crate) fn estimated_retained_bytes(&self) -> usize {
        let mut size = size_of::<Self>()
            .saturating_add(
                self.blocks
                    .capacity()
                    .saturating_mul(size_of::<IncompleteCodeBlock>()),
            )
            .saturating_add(self.insns.capacity().saturating_mul(size_of::<Insn>()))
            .saturating_add(self.insn_index.estimated_retained_bytes())
            .saturating_add(
                self.pending_switches
                    .capacity()
                    .saturating_mul(size_of::<Switch>()),
            );
        if self.tail_call_sites.spilled() {
            size = size.saturating_add(
                self.tail_call_sites
                    .capacity()
                    .saturating_mul(size_of::<Address>()),
            );
        }

        for block in &self.blocks {
            size = size.saturating_add(block.insns().len().saturating_mul(size_of::<InsnId>()));
        }
        for switch in &self.pending_switches {
            size = size.saturating_add(switch.case_count().saturating_mul(size_of::<SwitchCase>()));
        }

        size
    }

    pub(crate) fn set_tail_call_sites(&mut self, sites: impl IntoIterator<Item = Address>) {
        self.tail_call_sites.clear();
        self.tail_call_sites.extend(sites);
        self.tail_call_sites.sort_unstable();
        self.tail_call_sites.dedup();
    }

    pub fn block(&self, id: IncompleteCodeBlockId) -> Option<&IncompleteCodeBlock> {
        self.block_index(id).map(|index| &self.blocks[index])
    }

    pub fn block_mut(&mut self, id: IncompleteCodeBlockId) -> Option<&mut IncompleteCodeBlock> {
        self.block_index(id).map(|index| &mut self.blocks[index])
    }

    pub fn add_block_edge(
        &mut self,
        source: IncompleteCodeBlockId,
        target: IncompleteCodeBlockId,
    ) -> Result<(), IncompleteFunctionError> {
        let source_index = self
            .block_index(source)
            .ok_or_else(|| IncompleteFunctionError::invalid_block_id(source))?;
        let target_index = self
            .block_index(target)
            .ok_or_else(|| IncompleteFunctionError::invalid_block_id(target))?;
        self.blocks[source_index].add_successor(target);
        self.blocks[target_index].add_predecessor(source);
        Ok(())
    }

    pub fn remove_block_edge(
        &mut self,
        source: IncompleteCodeBlockId,
        target: IncompleteCodeBlockId,
    ) -> Result<(), IncompleteFunctionError> {
        let source_index = self
            .block_index(source)
            .ok_or_else(|| IncompleteFunctionError::invalid_block_id(source))?;
        let target_index = self
            .block_index(target)
            .ok_or_else(|| IncompleteFunctionError::invalid_block_id(target))?;
        self.blocks[source_index].remove_successor(target);
        self.blocks[target_index].remove_predecessor(source);
        Ok(())
    }

    pub fn blocks_at(
        &self,
        address: Address,
    ) -> impl ExactSizeIterator<Item = &IncompleteCodeBlock> {
        let start = self
            .blocks
            .partition_point(|block| block.address() < address);
        let end = self
            .blocks
            .partition_point(|block| block.address() <= address);
        self.blocks[start..end].iter()
    }

    pub fn contains_insn(&self, address: Address) -> bool {
        self.insn_index.contains(address)
            || (self.insn_index.is_empty()
                && self.insns.iter().any(|insn| insn.address() == address))
    }

    pub(crate) fn first_insn_id_at(&mut self, address: Address) -> Option<InsnId> {
        self.ensure_insn_index();
        self.insn_index.first(address)
    }

    pub fn insn_entry(&mut self, address: Address) -> InsnEntry<'_> {
        let append = !self.insn_index.is_empty()
            && !self.insns_unsorted
            && self
                .insns
                .last()
                .is_some_and(|insn| insn.address() < address);

        let existing = if append {
            None
        } else {
            self.ensure_insn_index();
            self.insn_index.first(address)
        };

        match existing {
            Some(id) => InsnEntry::Occupied(OccupiedInsnEntry {
                id,
                insns: &mut self.insns,
            }),
            None => InsnEntry::Vacant(VacantInsnEntry {
                address,
                generation: self.insn_generation,
                insns: &mut self.insns,
                insn_index: &mut self.insn_index,
                unsorted: &mut self.insns_unsorted,
            }),
        }
    }

    fn insert_distinct_insn(&mut self, insn: Insn) -> InsnId {
        self.ensure_insn_index();
        let address = insn.address();
        if let Some(id) = self
            .insn_index
            .ids(address)
            .find(|&id| self.insn(id) == Some(&insn))
        {
            return id;
        }

        if self
            .insns
            .last()
            .is_some_and(|previous| previous.address() > address)
        {
            self.insns_unsorted = true;
        }
        let id = InsnId::with_generation(
            self.insns.len().try_into().expect("too many instructions"),
            self.insn_generation,
        );
        self.insns.push(insn);
        self.insn_index.insert(address, id);
        id
    }

    pub fn indirect_branches(&self) -> impl Iterator<Item = (IncompleteCodeBlockId, Address)> + '_ {
        self.blocks
            .iter()
            .enumerate()
            .flat_map(move |(block_index, block)| {
                block.insns().iter().filter_map(move |&instruction| {
                    let insn = self.insn(instruction)?;
                    (insn.is_branch() && insn.is_indirect() && !insn.is_call() && !insn.is_return())
                        .then_some((
                            IncompleteCodeBlockId::with_generation(
                                block_index.try_into().expect("too many blocks"),
                                self.block_generation,
                            ),
                            insn.address(),
                        ))
                })
            })
    }

    pub fn insn(&self, id: InsnId) -> Option<&Insn> {
        (!id.is_invalid() && id.generation() == self.insn_generation)
            .then(|| id.index())
            .and_then(|index| self.insns.get(index))
    }

    pub(crate) fn insn_mut(&mut self, id: InsnId) -> Option<&mut Insn> {
        (!id.is_invalid() && id.generation() == self.insn_generation)
            .then(|| id.index())
            .and_then(|index| self.insns.get_mut(index))
    }

    pub fn insns_at(&self, address: Address) -> Box<dyn Iterator<Item = &Insn> + '_> {
        if self.insn_index.is_empty() && !self.insns.is_empty() {
            Box::new(
                self.insns
                    .iter()
                    .filter(move |insn| insn.address() == address),
            )
        } else {
            Box::new(self.insn_index.ids(address).filter_map(|id| self.insn(id)))
        }
    }

    pub fn has_insns(&self) -> bool {
        !self.insns.is_empty()
    }

    pub fn insns(&self) -> &[Insn] {
        &self.insns
    }

    pub fn properties(&self) -> FunctionProperties {
        self.properties
    }

    pub fn origin(&self) -> ReferenceOrigin {
        self.origin
    }

    pub fn set_origin(&mut self, origin: ReferenceOrigin) {
        self.origin = origin;
    }

    pub fn with_origin(mut self, origin: ReferenceOrigin) -> Self {
        self.origin = origin;
        self
    }

    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    pub fn set_confidence(&mut self, confidence: Confidence) {
        self.confidence = confidence;
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn input_revision(&self) -> Revision {
        self.input_revision
    }

    pub fn set_input_revision(&mut self, input_revision: Revision) {
        self.input_revision = input_revision;
    }

    pub fn with_input_revision(mut self, input_revision: Revision) -> Self {
        self.set_input_revision(input_revision);
        self
    }

    pub fn is_non_returning(&self) -> bool {
        self.properties.contains(FunctionProperties::NON_RETURNING)
    }

    pub fn mark_non_returning(&mut self) {
        self.properties.insert(FunctionProperties::NON_RETURNING);
    }

    pub fn is_thunk(&self) -> bool {
        self.properties.contains(FunctionProperties::THUNK)
    }

    pub fn mark_thunk(&mut self) {
        self.properties.insert(FunctionProperties::THUNK);
    }

    pub fn is_external(&self) -> bool {
        self.properties.contains(FunctionProperties::EXTERNAL)
    }

    pub fn mark_external(&mut self) {
        self.properties.insert(FunctionProperties::EXTERNAL);
    }

    pub(crate) fn clear_blocks(&mut self) {
        self.blocks.clear();
        self.entry_block = IncompleteCodeBlockId::INVALID;
        self.block_generation = self
            .block_generation
            .checked_add(1)
            .filter(|&generation| generation < u32::MAX)
            .expect("incomplete block generation exhausted");
    }

    pub(crate) fn reserve_blocks(&mut self, additional: usize) {
        self.blocks.reserve(additional);
    }

    pub(crate) fn sort_insns_by_address(&mut self) {
        if !self.insns_unsorted {
            return;
        }

        self.insns.sort_unstable_by_key(Insn::address);
        self.insn_generation = self
            .insn_generation
            .checked_add(1)
            .filter(|&generation| generation < u32::MAX)
            .expect("incomplete instruction generation exhausted");
        self.insn_index.clear();
        for (index, insn) in self.insns.iter().enumerate() {
            let id = InsnId::with_generation(
                index.try_into().expect("too many instructions"),
                self.insn_generation,
            );
            self.insn_index.insert(insn.address(), id);
        }
        self.insns_unsorted = false;
    }

    fn ensure_insn_index(&mut self) {
        if !self.insn_index.is_empty() || self.insns.is_empty() {
            return;
        }

        for (index, insn) in self.insns.iter().enumerate() {
            let id = InsnId::with_generation(
                index.try_into().expect("too many instructions"),
                self.insn_generation,
            );
            self.insn_index.insert(insn.address(), id);
        }
    }

    pub(crate) fn insn_id(&self, index: usize) -> Option<InsnId> {
        (index < self.insns.len()).then(|| {
            InsnId::with_generation(
                index.try_into().expect("too many instructions"),
                self.insn_generation,
            )
        })
    }

    pub(crate) fn prepare_materialisation(
        mut self,
    ) -> Result<FunctionMaterialisation, IncompleteFunctionError> {
        let mut expected_index = 0usize;
        let mut ordered = true;
        for block in &self.blocks {
            if block.is_empty() {
                return Err(IncompleteFunctionError::invalid_block_length(
                    block.address(),
                ));
            }
            for &insn in block.insns() {
                if self.insn(insn).is_none() {
                    return Err(IncompleteFunctionError::invalid_instruction_id(insn));
                }
                ordered &= insn.index() == expected_index;
                expected_index += 1;
            }
        }
        ordered &= expected_index == self.insns.len();

        let mut instructions = if ordered {
            BlockInstructionSource::Ordered(mem::take(&mut self.insns).into_iter())
        } else {
            let mut remaining_uses = vec![0usize; self.insns.len()];
            for block in &self.blocks {
                for &insn in block.insns() {
                    remaining_uses[insn.index()] += 1;
                }
            }
            BlockInstructionSource::Shared {
                instructions: mem::take(&mut self.insns).into_iter().map(Some).collect(),
                remaining_uses,
            }
        };
        let mut blocks = Vec::with_capacity(self.blocks.len());
        let mut call_targets = BTreeSet::new();
        let mut coverage = AddressRangeSet::new();
        let mut pending_coverage = None::<AddressRange>;
        let mut references = Vec::with_capacity(self.blocks.len());
        for block in &self.blocks {
            let len = NonZeroUsize::new(block.len())
                .ok_or_else(|| IncompleteFunctionError::invalid_block_length(block.address()))?;
            let instructions = instructions.take(block.insns());
            let mut properties = block.properties();
            if let Some(terminator) = instructions.last() {
                if terminator.is_call() {
                    properties |= CodeBlockProperties::CALL;
                }
                if terminator.is_branch()
                    && terminator.is_indirect()
                    && !terminator.is_call()
                    && !terminator.is_return()
                    && terminator.iter_targets().next().is_none()
                {
                    properties |= CodeBlockProperties::UNRESOLVED;
                }
            }
            let materialisation = CodeBlockMaterialisation {
                address: block.address(),
                context: block.context().clone(),
                instructions,
                len,
                properties,
            };
            let block_range = materialisation.address_range();
            match pending_coverage.as_mut() {
                Some(current)
                    if current.space() == block_range.space()
                        && current
                            .end()
                            .checked_add(1usize)
                            .is_some_and(|next| block_range.start() <= next) =>
                {
                    *current = AddressRange::new(
                        current.space(),
                        current.start(),
                        current.end().max(block_range.end()),
                    );
                }
                Some(current) => {
                    coverage.insert_range(*current);
                    *current = block_range;
                }
                None => pending_coverage = Some(block_range),
            }
            for mut target in materialisation.flow_targets() {
                if target.kind() == FlowKind::Branch
                    && self.tail_call_sites.binary_search(&target.from()).is_ok()
                {
                    target = FlowTarget::new(target.from(), target.to(), FlowKind::TailCallBranch);
                }
                if target.kind().is_call() {
                    call_targets.insert(target.to());
                }
                if !target.kind().is_global() {
                    continue;
                }
                references.push(
                    Reference::from_flow(target.from(), target.to(), target.kind())
                        .with_origin(ReferenceOrigin::Derived),
                );
            }
            blocks.push(materialisation);
        }
        if let Some(range) = pending_coverage {
            coverage.insert_range(range);
        }

        references.sort_unstable();
        let mut output = 0usize;
        for input in 0..references.len() {
            let reference = references[input];
            if output != 0 && references[output - 1] == reference {
                references[output - 1] =
                    references[output - 1].with_merged_properties(reference.properties());
            } else {
                references[output] = reference;
                output += 1;
            }
        }
        references.truncate(output);

        let mut edges = Vec::with_capacity(self.blocks.len());
        for (index, block) in self.blocks.iter().enumerate() {
            for successor in block.successors().iter() {
                let successor = self
                    .block_index(successor)
                    .ok_or_else(|| IncompleteFunctionError::invalid_block_id(successor))?;
                edges.push((index, successor));
            }
        }

        Ok(FunctionMaterialisation {
            blocks,
            call_targets,
            confidence: self.confidence,
            coverage,
            edges,
            entry: self.entry,
            entry_block: self
                .entry_block
                .is_valid()
                .then(|| self.entry_block.index()),
            input_revision: self.input_revision,
            name: self.name,
            origin: self.origin,
            properties: self.properties,
            references,
            tail_call_sites: self.tail_call_sites,
        })
    }

    #[inline]
    fn block_index(&self, id: IncompleteCodeBlockId) -> Option<usize> {
        if id.is_invalid() || id.generation() != self.block_generation {
            return None;
        }
        let index = id.index();
        (index < self.blocks.len()).then_some(index)
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod test {
    use fugue_lifter::runtime::pcode::Inputs;

    use super::*;
    use crate::ir::CodeBlock;
    use crate::lifter::{ContextSet, Op, RawPCodeOp, Varnode, resolve_language};
    use crate::storage::entities::SqliteEntityStorage;
    use crate::storage::{EntityStorage, TRANSIENT};

    fn block_table() -> CodeBlockTable {
        CodeBlockTable::new(
            EntityStorage::new(SqliteEntityStorage::<TRANSIENT>::new().unwrap()),
            64 * 1024,
        )
        .unwrap()
    }

    fn call_insn(
        language: &'static crate::lifter::Language,
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

    fn block_with(
        blocks: &mut CodeBlockTable,
        start: Address,
        len: usize,
        insn: Insn,
    ) -> CodeBlockId {
        blocks
            .insert(start, |id, address| {
                Ok(CodeBlock::new_with(
                    id,
                    address,
                    len.try_into().unwrap(),
                    vec![insn],
                    ContextSet::default(),
                ))
            })
            .unwrap()
    }

    #[test]
    fn overlapping_blocks_at_one_address_survive() -> Result<(), Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let mut blocks = block_table();
        let start = Address::in_default_space(0x1000u64);
        let target = Address::in_default_space(0x9000u64);

        let insn = call_insn(language, start, target)?;
        let a = block_with(&mut blocks, start, 1, insn.clone());
        let b = block_with(&mut blocks, start, 1, insn);

        let entries = [(start, a), (start, b)];

        let function = IncompleteFunction::from_committed(start, &entries, [], [], &blocks)
            .expect("blocks at one address must remain distinct");
        assert_eq!(function.blocks().len(), 2);
        assert_eq!(function.blocks_at(start).count(), 2);
        assert_eq!(function.insns_at(start).count(), 1);

        Ok(())
    }

    #[test]
    fn blocks_with_distinct_decoding_at_one_address_survive()
    -> Result<(), Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let mut blocks = block_table();
        let start = Address::in_default_space(0x2000u64);

        let a = block_with(
            &mut blocks,
            start,
            1,
            call_insn(language, start, Address::in_default_space(0x9000u64))?,
        );
        let b = block_with(
            &mut blocks,
            start,
            1,
            call_insn(language, start, Address::in_default_space(0xa000u64))?,
        );

        let entries = [(start, a), (start, b)];

        let function = IncompleteFunction::from_committed(start, &entries, [], [], &blocks)
            .expect("context- or state-distinct decoding must remain representable");
        assert_eq!(function.blocks().len(), 2);
        assert_eq!(function.blocks_at(start).count(), 2);
        assert_eq!(function.insns_at(start).count(), 2);

        Ok(())
    }
}
