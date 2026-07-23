use std::collections::BTreeMap;
use std::collections::btree_map::{Entry, OccupiedEntry, VacantEntry};
use std::error::Error as StdError;
use std::mem;

use thiserror::Error;

use crate::ir::{
    Address, CodeBlock, CodeBlockProperties, CodeBlockTable, Function, FunctionId,
    FunctionProperties, FunctionTable, IncompleteCodeBlock, IncompleteCodeBlockId, Insn, InsnId,
    InsnList, Switch, Symbol,
};

#[derive(Debug, Error)]
pub enum IncompleteFunctionError {
    #[error("failed to create block: {0}")]
    BlockCreation(anyhow::Error),
    #[error("failed to create function: {0}")]
    FunctionCreation(anyhow::Error),
    #[error("invalid block id: {0:?}")]
    InvalidBlockId(IncompleteCodeBlockId),
    #[error("invalid instruction id: {0:?}")]
    InvalidInstructionId(InsnId),
}

impl IncompleteFunctionError {
    fn block_creation<E>(error: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::BlockCreation(error.into())
    }

    fn function_creation<E>(error: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::FunctionCreation(error.into())
    }

    fn invalid_block_id(id: IncompleteCodeBlockId) -> Self {
        Self::InvalidBlockId(id)
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
    entry: VacantEntry<'a, Address, InsnId>,
    generation: u32,
    insns: &'a mut Vec<Insn>,
    unsorted: &'a mut bool,
}

impl<'a> VacantInsnEntry<'a> {
    pub fn insert(self, insn: Insn) -> InsnId {
        assert!(
            *self.entry.key() == insn.address(),
            "instruction address must match entry address",
        );
        if self
            .insns
            .last()
            .is_some_and(|previous| previous.address() >= insn.address())
        {
            *self.unsorted = true;
        }
        let id = InsnId::with_generation(
            self.insns.len().try_into().expect("too many instructions"),
            self.generation,
        );
        self.insns.push(insn);
        self.entry.insert(id);
        id
    }
}

pub struct OccupiedInsnEntry<'a> {
    entry: OccupiedEntry<'a, Address, InsnId>,
    insns: &'a mut Vec<Insn>,
}

impl OccupiedInsnEntry<'_> {
    pub fn id(&self) -> InsnId {
        *self.entry.get()
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
    blocks: Vec<IncompleteCodeBlock>,
    block_generation: u32,
    insns: Vec<Insn>,
    insn_generation: u32,
    insn_map: BTreeMap<Address, InsnId>,
    insns_unsorted: bool,
    properties: FunctionProperties,
    pending_switches: Vec<Switch>,
}

impl IncompleteFunction {
    pub fn new(entry: Address) -> Self {
        Self::new_with(None, entry)
    }

    pub fn new_with(name: impl Into<Option<Symbol>>, entry: Address) -> Self {
        Self {
            name: name.into(),
            entry,
            blocks: Vec::new(),
            block_generation: 0,
            insns: Vec::new(),
            insn_generation: 0,
            insn_map: BTreeMap::new(),
            insns_unsorted: false,
            properties: FunctionProperties::NONE,
            pending_switches: Vec::new(),
        }
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
        self.block_at(self.entry)
            .expect("entry block should always exist")
    }

    pub fn push_block(&mut self, block: IncompleteCodeBlock) -> IncompleteCodeBlockId {
        debug_assert!(
            self.blocks.is_empty() || self.blocks.last().unwrap().address() < block.address(),
            "blocks must be inserted in order",
        );
        let id = IncompleteCodeBlockId::with_generation(
            self.blocks.len().try_into().expect("too many blocks"),
            self.block_generation,
        );
        self.blocks.push(block);
        id
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

    pub fn block_at(&self, address: Address) -> Option<&IncompleteCodeBlock> {
        self.blocks
            .binary_search_by_key(&address, |block| block.address())
            .ok()
            .map(|index| &self.blocks[index])
    }

    pub fn contains_insn(&self, address: Address) -> bool {
        self.insn_map.contains_key(&address)
    }

    pub fn insn_entry(&mut self, address: Address) -> InsnEntry<'_> {
        match self.insn_map.entry(address) {
            Entry::Vacant(entry) => InsnEntry::Vacant(VacantInsnEntry {
                entry,
                generation: self.insn_generation,
                insns: &mut self.insns,
                unsorted: &mut self.insns_unsorted,
            }),
            Entry::Occupied(entry) => InsnEntry::Occupied(OccupiedInsnEntry {
                entry,
                insns: &mut self.insns,
            }),
        }
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

    pub fn insn_at(&self, address: Address) -> Option<&Insn> {
        self.insn_map.get(&address).and_then(|&id| self.insn(id))
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
        self.block_generation = self
            .block_generation
            .checked_add(1)
            .filter(|&generation| generation < u32::MAX)
            .expect("incomplete block generation exhausted");
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
        self.insn_map.clear();
        self.insn_map
            .extend(self.insns.iter().enumerate().map(|(index, insn)| {
                let id = InsnId::with_generation(
                    index.try_into().expect("too many instructions"),
                    self.insn_generation,
                );
                (insn.address(), id)
            }));
        self.insns_unsorted = false;
    }

    pub(crate) fn insn_id(&self, index: usize) -> Option<InsnId> {
        (index < self.insns.len()).then(|| {
            InsnId::with_generation(
                index.try_into().expect("too many instructions"),
                self.insn_generation,
            )
        })
    }

    pub(crate) fn commit(
        self,
        function_table: &mut FunctionTable,
        block_table: &mut CodeBlockTable,
    ) -> Result<FunctionId, IncompleteFunctionError> {
        for block in &self.blocks {
            for &insn in block.insns() {
                if self.insn(insn).is_none() {
                    return Err(IncompleteFunctionError::invalid_instruction_id(insn));
                }
            }
        }

        let mut block_ids = Vec::with_capacity(self.blocks.len());
        for block in &self.blocks {
            let block_id = block_table
                .insert(block.address(), |id, address| {
                    let insns = InsnList::from_iter(
                        block
                            .insns()
                            .iter()
                            .map(|&insn_id| self.insns[insn_id.index()].clone()),
                    );

                    let mut stored = CodeBlock::try_new_with(
                        id,
                        address,
                        block.len(),
                        insns,
                        block.context().clone(),
                    )
                    .expect("code block has non-zero length");
                    if block.properties().contains(CodeBlockProperties::ENTRY) {
                        stored.mark_entry();
                    }
                    if block.properties().contains(CodeBlockProperties::EXIT) {
                        stored.mark_exit();
                    }
                    Ok(stored)
                })
                .map_err(IncompleteFunctionError::block_creation)?;
            block_ids.push(block_id);
        }

        for (index, block) in self.blocks.iter().enumerate() {
            let block_id = block_ids[index];
            let mut stored = block_table
                .get_by_id_mut(block_id)
                .expect("code block exists");

            for successor in block.successors().iter() {
                let successor = self
                    .block_index(successor)
                    .ok_or_else(|| IncompleteFunctionError::invalid_block_id(successor))?;
                stored.add_successor(block_ids[successor]);
            }
            for predecessor in block.predecessors().iter() {
                let predecessor = self
                    .block_index(predecessor)
                    .ok_or_else(|| IncompleteFunctionError::invalid_block_id(predecessor))?;
                stored.add_predecessor(block_ids[predecessor]);
            }
        }

        function_table
            .insert(self.entry, |id, address| {
                let mut function = Function::new_with(id, address, self.name);
                function.add_blocks(
                    self.blocks
                        .iter()
                        .map(IncompleteCodeBlock::address)
                        .zip(block_ids.iter().copied()),
                );
                function.set_properties(self.properties);
                Ok(function)
            })
            .map_err(IncompleteFunctionError::function_creation)
    }

    fn block_index(&self, id: IncompleteCodeBlockId) -> Option<usize> {
        if id.is_invalid() || id.generation() != self.block_generation {
            return None;
        }
        let index = id.index();
        (index < self.blocks.len()).then_some(index)
    }
}
