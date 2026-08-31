use std::collections::BTreeSet;
use std::collections::hash_map::Entry;
use std::mem::{self, size_of};
use std::num::NonZeroUsize;

use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use thiserror::Error;

use crate::ir::{
    Address, AddressRange, AddressRangeSet, AddressWithContext, CodeBlockId, CodeBlockRecord,
    FlowKind, FlowTarget, Function, FunctionId, FunctionProperties, IncompleteCodeBlock,
    IncompleteCodeBlockId, Insn, InsnId, Reference, ReferenceOrigin, Switch, SwitchCase, Symbol,
};
use crate::types::{Confidence, EstimateSize, Revision};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FunctionInsnIndex {
    additional: FxHashMap<Address, SmallVec<[InsnId; 1]>>,
    first: FxHashMap<Address, InsnId>,
}

impl FunctionInsnIndex {
    fn contains(&self, address: Address) -> bool {
        self.first.contains_key(&address)
    }

    fn first(&self, address: Address) -> Option<InsnId> {
        self.first.get(&address).copied()
    }

    fn is_empty(&self) -> bool {
        self.first.is_empty()
    }

    fn ids(&self, address: Address) -> impl Iterator<Item = InsnId> + '_ {
        self.first(address)
            .into_iter()
            .chain(self.additional.get(&address).into_iter().flatten().copied())
    }

    fn clear(&mut self) {
        self.additional.clear();
        self.first.clear();
    }

    fn insert(&mut self, address: Address, id: InsnId) {
        match self.first.entry(address) {
            Entry::Vacant(entry) => {
                entry.insert(id);
            }
            Entry::Occupied(_) => {
                self.additional.entry(address).or_default().push(id);
            }
        }
    }
}

impl EstimateSize for FunctionInsnIndex {
    fn estimate_size(&self) -> usize {
        let mut size = size_of::<Self>().saturating_add(
            self.first
                .capacity()
                .saturating_mul(size_of::<(Address, InsnId)>())
                .saturating_add(
                    self.additional
                        .capacity()
                        .saturating_mul(size_of::<(Address, SmallVec<[InsnId; 1]>)>()),
                ),
        );
        for ids in self.additional.values().filter(|ids| ids.spilled()) {
            size = size.saturating_add(ids.capacity().saturating_mul(size_of::<InsnId>()));
        }
        size
    }
}

pub(crate) struct FunctionRecord {
    blocks: Vec<CodeBlockRecord>,
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

impl FunctionRecord {
    pub(crate) fn block_addresses(&self) -> impl Iterator<Item = Address> + '_ {
        self.blocks.iter().map(CodeBlockRecord::address)
    }

    pub(crate) fn block_count(&self) -> usize {
        self.blocks.len()
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
        mut resolve_block: impl FnMut(CodeBlockRecord) -> Result<CodeBlockId, IncompleteFunctionError>,
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
            Function::new_with(id, self.entry, self.name).with_blocks(members, edges, entry_block);
        function.set_properties(self.properties);
        function.set_origin(self.origin);
        function.set_confidence(self.confidence);
        function.set_input_revision(self.input_revision);
        function.set_tail_call_sites(self.tail_call_sites);
        Ok(function)
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
    #[error("invalid zero-size block: {address}")]
    InvalidBlockSize { address: Address },
    #[error("invalid insn id: {0:?}")]
    InvalidInsnId(InsnId),
    #[error("committed code block does not exist: {0:?}")]
    MissingCodeBlock(CodeBlockId),
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

    fn invalid_block_size(address: Address) -> Self {
        Self::InvalidBlockSize { address }
    }

    fn invalid_insn_id(id: InsnId) -> Self {
        Self::InvalidInsnId(id)
    }

    pub(crate) fn missing_code_block(id: CodeBlockId) -> Self {
        Self::MissingCodeBlock(id)
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
        if !self.insn_index.is_empty() {
            self.insn_index.insert(self.address, id);
        }
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

impl EstimateSize for IncompleteFunction {
    fn estimate_size(&self) -> usize {
        let insn_size = self
            .insns
            .iter()
            .map(EstimateSize::estimate_size)
            .fold(size_of::<Vec<Insn>>(), usize::saturating_add)
            .saturating_add(
                self.insns
                    .capacity()
                    .saturating_sub(self.insns.len())
                    .saturating_mul(size_of::<Insn>()),
            );
        let mut size = size_of::<Self>()
            .saturating_sub(size_of::<Vec<Insn>>())
            .saturating_sub(size_of::<FunctionInsnIndex>())
            .saturating_add(
                self.blocks
                    .capacity()
                    .saturating_mul(size_of::<IncompleteCodeBlock>()),
            )
            .saturating_add(insn_size)
            .saturating_add(self.insn_index.estimate_size())
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
            size = size.saturating_add(block.insn_ids().len().saturating_mul(size_of::<InsnId>()));
        }
        for switch in &self.pending_switches {
            size = size.saturating_add(switch.case_count().saturating_mul(size_of::<SwitchCase>()));
        }

        size
    }
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

    pub(crate) fn has_pending_switch(&self, branch: Address) -> bool {
        self.pending_switches
            .iter()
            .any(|pending| pending.branch() == branch)
    }

    pub fn set_name(&mut self, name: impl Into<Symbol>) {
        self.name = Some(name.into());
    }

    pub fn name(&self) -> Option<Symbol> {
        self.name
    }

    pub fn entry(&self) -> Address {
        self.entry
    }

    pub fn blocks(&self) -> &[IncompleteCodeBlock] {
        &self.blocks
    }

    pub fn block(&self, id: IncompleteCodeBlockId) -> Option<&IncompleteCodeBlock> {
        self.block_index(id).map(|index| &self.blocks[index])
    }

    pub fn block_mut(&mut self, id: IncompleteCodeBlockId) -> Option<&mut IncompleteCodeBlock> {
        self.block_index(id).map(|index| &mut self.blocks[index])
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

    pub fn entry_block(&self) -> &IncompleteCodeBlock {
        self.block(self.entry_block)
            .expect("entry block should always exist")
    }

    pub(crate) fn set_tail_call_sites(&mut self, sites: impl IntoIterator<Item = Address>) {
        self.tail_call_sites.clear();
        self.tail_call_sites.extend(sites);
        self.tail_call_sites.sort_unstable();
        self.tail_call_sites.dedup();
    }

    pub fn contains_insn(&self, address: Address) -> bool {
        if !self.insn_index.is_empty() {
            return self.insn_index.contains(address);
        }
        if self.insns_unsorted {
            return self.insns.iter().any(|insn| insn.address() == address);
        }
        self.insns
            .binary_search_by_key(&address, Insn::address)
            .is_ok()
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

    pub fn has_insns(&self) -> bool {
        !self.insns.is_empty()
    }

    pub fn insns(&self) -> &[Insn] {
        &self.insns
    }

    pub fn insns_at(&self, address: Address) -> Box<dyn Iterator<Item = &Insn> + '_> {
        if !self.insn_index.is_empty() {
            return Box::new(self.insn_index.ids(address).filter_map(|id| self.insn(id)));
        }
        if self.insns_unsorted {
            return Box::new(
                self.insns
                    .iter()
                    .filter(move |insn| insn.address() == address),
            );
        }

        let start = self.insns.partition_point(|insn| insn.address() < address);
        let end = self.insns.partition_point(|insn| insn.address() <= address);
        Box::new(self.insns[start..end].iter())
    }

    pub fn indirect_branches(&self) -> impl Iterator<Item = (IncompleteCodeBlockId, Address)> + '_ {
        self.blocks
            .iter()
            .enumerate()
            .flat_map(move |(block_index, block)| {
                block.insn_ids().iter().filter_map(move |&instruction| {
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

    pub fn block_flow_targets<'a>(
        &'a self,
        block: &'a IncompleteCodeBlock,
    ) -> impl Iterator<Item = FlowTarget> + 'a {
        let start = block.address();
        let end = start + block.size();
        block
            .insn_ids()
            .iter()
            .filter_map(|id| self.insn(*id))
            .flat_map(Insn::flow_targets)
            .filter(move |target| !target.kind().is_fall_through() || target.to() == end)
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

    pub fn is_thunk(&self) -> bool {
        self.properties.contains(FunctionProperties::THUNK)
    }

    pub fn is_external(&self) -> bool {
        self.properties.contains(FunctionProperties::EXTERNAL)
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

    pub fn take_pending_switches(&mut self) -> Vec<Switch> {
        mem::take(&mut self.pending_switches)
    }

    pub fn clear_name(&mut self) {
        self.name = None;
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

    pub(crate) fn first_insn_id_at(&mut self, address: Address) -> Option<InsnId> {
        if self.insn_index.is_empty() && !self.insns_unsorted {
            let index = self.insns.partition_point(|insn| insn.address() < address);
            return self
                .insns
                .get(index)
                .filter(|insn| insn.address() == address)
                .map(|_| {
                    InsnId::with_generation(
                        index.try_into().expect("too many instructions"),
                        self.insn_generation,
                    )
                });
        }
        self.ensure_insn_index();
        self.insn_index.first(address)
    }

    pub fn insn_entry(&mut self, address: Address) -> InsnEntry<'_> {
        let append = !self.insns_unsorted
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

    pub fn mark_non_returning(&mut self) {
        self.properties.insert(FunctionProperties::NON_RETURNING);
    }

    pub fn mark_thunk(&mut self) {
        self.properties.insert(FunctionProperties::THUNK);
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

    pub(crate) fn normalise(self) -> Result<FunctionRecord, IncompleteFunctionError> {
        for block in &self.blocks {
            if block.is_empty() {
                return Err(IncompleteFunctionError::invalid_block_size(block.address()));
            }
            for &insn in block.insn_ids() {
                if self.insn(insn).is_none() {
                    return Err(IncompleteFunctionError::invalid_insn_id(insn));
                }
            }
        }
        let mut blocks = Vec::with_capacity(self.blocks.len());
        let mut call_targets = BTreeSet::new();
        let mut coverage = AddressRangeSet::new();
        let mut pending_coverage = None::<AddressRange>;
        let mut references = Vec::with_capacity(self.blocks.len());
        for block in &self.blocks {
            let size = NonZeroUsize::new(block.size())
                .ok_or_else(|| IncompleteFunctionError::invalid_block_size(block.address()))?;
            let block_insns = block.insn_ids().iter().map(|&id| {
                self.insn(id)
                    .expect("validated instruction must remain available")
            });
            let normalised =
                CodeBlockRecord::new(block.address(), size, block_insns, block.context().clone());
            let block_range = normalised.address_range();
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
            for mut target in normalised.flow_targets() {
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
            blocks.push(normalised);
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

        Ok(FunctionRecord {
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::ir::{InsnError, InsnProperties};

    fn fall_through(address: Address) -> Result<Insn, InsnError> {
        Insn::from_disassembly(address, 1, InsnProperties::FALL_THROUGH)
    }

    #[test]
    fn sorted_insns_do_not_materialise_an_index() -> Result<(), InsnError> {
        let first = Address::from(0x1000u64);
        let second = first + 1u64;
        let mut function = IncompleteFunction::new(first);

        let InsnEntry::Vacant(entry) = function.insn_entry(first) else {
            panic!("new function must not contain an instruction");
        };
        let first_id = entry.insert(fall_through(first)?);
        let InsnEntry::Vacant(entry) = function.insn_entry(second) else {
            panic!("new function must not contain the next instruction");
        };
        entry.insert(fall_through(second)?);

        assert!(function.insn_index.is_empty());
        assert!(function.contains_insn(first));
        assert_eq!(function.first_insn_id_at(first), Some(first_id));
        assert_eq!(function.insns_at(second).count(), 1);
        assert!(function.insn_index.is_empty());
        Ok(())
    }

    #[test]
    fn out_of_order_insns_materialise_an_index() -> Result<(), InsnError> {
        let first = Address::from(0x1000u64);
        let second = first + 1u64;
        let mut function = IncompleteFunction::new(first);

        let InsnEntry::Vacant(entry) = function.insn_entry(second) else {
            panic!("new function must not contain an instruction");
        };
        entry.insert(fall_through(second)?);
        let InsnEntry::Vacant(entry) = function.insn_entry(first) else {
            panic!("new function must not contain the preceding instruction");
        };
        entry.insert(fall_through(first)?);

        assert!(!function.insn_index.is_empty());
        assert!(function.insns_unsorted);
        assert!(function.contains_insn(first));
        assert!(function.contains_insn(second));
        function.sort_insns_by_address();
        assert_eq!(function.insns()[0].address(), first);
        assert_eq!(function.insns()[1].address(), second);
        Ok(())
    }
}
