use std::collections::BTreeMap;
use std::collections::btree_map::{Entry, OccupiedEntry, VacantEntry};

use range_set_blaze::RangeSetBlaze;
use tinyset::SetUsize;
use ustr::Ustr;

use crate::analysis::function::recovery::FunctionBuilderError;
use crate::entities::{BasicBlockProperties, FunctionProperties, Insn};
use crate::lifter::{ContextSet, LifterError};
use crate::project::Project;
use crate::types::Address;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InsnRanges(RangeSetBlaze<usize>);

impl InsnRanges {
    pub fn new() -> Self {
        Self(RangeSetBlaze::new())
    }

    pub fn insert(&mut self, id: usize) {
        self.0.insert(id);
    }

    pub fn iter(&self) -> impl Iterator<Item = usize> {
        self.0.iter()
    }

    pub fn contains(&self, id: usize) -> bool {
        self.0.contains(id)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartialBasicBlock {
    start: Address,
    len: usize,
    context: ContextSet,
    properties: BasicBlockProperties,
    successors: SetUsize,
    predecessors: SetUsize,
    instructions: InsnRanges,
}

impl PartialBasicBlock {
    pub fn new(start: Address, len: usize, instructions: InsnRanges) -> Self {
        Self::new_with(start, len, instructions, ContextSet::default())
    }

    pub fn new_with(
        start: Address,
        len: usize,
        instructions: InsnRanges,
        context: ContextSet,
    ) -> Self {
        Self {
            start,
            len,
            context,
            properties: BasicBlockProperties::NONE,
            successors: SetUsize::new(),
            predecessors: SetUsize::new(),
            instructions,
        }
    }

    pub fn start(&self) -> Address {
        self.start
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn instructions(&self) -> &InsnRanges {
        &self.instructions
    }

    pub fn mark_entry(&mut self) {
        self.properties.insert(BasicBlockProperties::ENTRY);
    }

    pub fn mark_exit(&mut self) {
        self.properties.insert(BasicBlockProperties::EXIT);
    }

    pub fn mark_non_returning(&mut self) {
        self.properties.insert(BasicBlockProperties::NON_RETURNING);
    }

    pub fn mark_call(&mut self) {
        self.properties.insert(BasicBlockProperties::CALL);
    }

    pub fn mark_tail_call(&mut self) {
        self.properties
            .insert(BasicBlockProperties::TAIL_CALL | BasicBlockProperties::CALL);
    }

    pub fn mark_unresolved(&mut self) {
        self.properties.insert(BasicBlockProperties::UNRESOLVED);
    }

    pub fn is_entry(&self) -> bool {
        self.properties.contains(BasicBlockProperties::ENTRY)
    }

    pub fn is_exit(&self) -> bool {
        self.properties.contains(BasicBlockProperties::EXIT)
    }

    pub fn is_non_returning(&self) -> bool {
        self.properties
            .contains(BasicBlockProperties::NON_RETURNING)
    }

    pub fn is_call(&self) -> bool {
        self.properties.contains(BasicBlockProperties::CALL)
    }

    pub fn is_tail_call(&self) -> bool {
        self.properties.contains(BasicBlockProperties::TAIL_CALL)
    }

    pub fn has_unresolved(&self) -> bool {
        self.properties.contains(BasicBlockProperties::UNRESOLVED)
    }

    pub fn context(&self) -> &ContextSet {
        &self.context
    }

    pub fn add_successor(&mut self, target: usize) {
        self.successors.insert(target);
    }

    pub fn add_predecessor(&mut self, source: usize) {
        self.predecessors.insert(source);
    }

    pub fn successors(&self) -> &SetUsize {
        &self.successors
    }

    pub fn predecessors(&self) -> &SetUsize {
        &self.predecessors
    }
}

#[derive(Default)]
pub struct PartialFunction {
    name: Option<Ustr>,
    entry: Address,
    blocks: Vec<PartialBasicBlock>,
    instructions: Vec<Insn>,
    instructions_map: BTreeMap<Address, usize>,
    properties: FunctionProperties,
}

impl PartialFunction {
    fn new(entry: Address) -> Self {
        Self::new_with(None, entry)
    }

    fn new_with(name: impl Into<Option<Ustr>>, entry: Address) -> Self {
        Self {
            name: name.into(),
            entry,
            blocks: Vec::new(),
            instructions: Vec::new(),
            instructions_map: BTreeMap::new(),
            properties: FunctionProperties::NONE,
        }
    }

    pub fn update_name(&mut self, name: impl Into<Ustr>) {
        self.name = Some(name.into());
    }

    pub fn clear_name(&mut self) {
        self.name = None;
    }

    pub fn name(&self) -> Option<Ustr> {
        self.name
    }

    pub fn entry(&self) -> Address {
        self.entry
    }

    pub fn entry_block(&self) -> &PartialBasicBlock {
        self.block_at(self.entry)
            .expect("entry block should always exist")
    }

    pub(crate) fn push_block(&mut self, block: PartialBasicBlock) {
        debug_assert!(
            self.blocks.is_empty() || self.blocks.last().unwrap().start() < block.start(),
            "blocks must be inserted in order",
        );
        self.blocks.push(block);
    }

    pub fn blocks(&self) -> &[PartialBasicBlock] {
        &self.blocks
    }

    pub fn block_at(&self, address: Address) -> Option<&PartialBasicBlock> {
        self.blocks
            .binary_search_by_key(&address, |blk| blk.start())
            .ok()
            .map(|idx| &self.blocks[idx])
    }

    pub fn contains_insn(&self, address: Address) -> bool {
        self.instructions_map.contains_key(&address)
    }

    pub(crate) fn insn_entry(&mut self, address: Address) -> InsnEntry {
        match self.instructions_map.entry(address) {
            Entry::Vacant(entry) => InsnEntry::Vacant(VacantInsnEntry {
                entry,
                insns: &mut self.instructions,
            }),
            Entry::Occupied(entry) => InsnEntry::Occupied(OccupiedInsnEntry {
                entry,
                insns: &mut self.instructions,
            }),
        }
    }

    pub fn lift_block(
        &mut self,
        id: usize,
        project: &mut Project,
    ) -> Result<(), FunctionBuilderError> {
        let block = self
            .blocks
            .get(id)
            .ok_or_else(|| FunctionBuilderError::InvalidBlockId(id))?;

        let start = block.start();
        let bytes = project
            .storage
            .segments
            .view_segment_bytes_from(block.start())?;

        for insn_id in block.instructions().iter() {
            let insn = &mut self.instructions[insn_id];

            if insn.is_lifted() {
                continue;
            }

            let offset = usize::from(insn.address() - start);

            let view = bytes
                .get(offset..)
                .ok_or_else(|| LifterError::InvalidInstruction(insn.address()))?;

            *insn = project.lifter.lift_insn(insn.address(), view)?;
        }

        Ok(())
    }

    pub fn lift_all_blocks(&mut self, project: &mut Project) -> Result<(), FunctionBuilderError> {
        let mut segment = project
            .storage
            .segments
            .find_segment_containing(self.entry)?;

        for block in self.blocks.iter_mut() {
            if !segment.contains_address(block.start()) {
                segment = project
                    .storage
                    .segments
                    .find_segment_containing(block.start())?;
            }

            let bytes = segment
                .view_bytes_from_address(block.start())
                .expect("block start must be in segment");

            for insn_id in block.instructions().iter() {
                let insn = &mut self.instructions[insn_id];

                if insn.is_lifted() {
                    continue;
                }

                let offset = usize::from(insn.address() - block.start());

                let view = bytes
                    .get(offset..)
                    .ok_or_else(|| LifterError::InvalidInstruction(insn.address()))?;

                *insn = project.lifter.lift_insn(insn.address(), view)?;
            }
        }

        Ok(())
    }

    pub fn lift_insn(
        &mut self,
        id: usize,
        project: &mut Project,
    ) -> Result<Option<&mut Insn>, FunctionBuilderError> {
        let insn = self
            .instructions
            .get_mut(id)
            .ok_or_else(|| FunctionBuilderError::InvalidInstructionId(id))?;

        if insn.is_lifted() {
            return Ok(Some(insn));
        }

        let address = insn.address();
        let mut bytes = [0u8; 32];

        project
            .storage
            .segments
            .read_bytes(address, &mut bytes)
            .expect("storage should be consistent");

        // TODO: should we use Rc<RefCell<...>>/Arc for Insn?

        *insn = project.lifter_mut().lift_insn(address, bytes)?;

        Ok(Some(insn))
    }

    pub fn insn(&self, address: Address) -> Option<&Insn> {
        self.instructions_map
            .get(&address)
            .and_then(|&id| self.instructions.get(id))
    }

    pub fn insn_mut(&mut self, address: Address) -> Option<&mut Insn> {
        self.instructions_map
            .get(&address)
            .and_then(|&id| self.instructions.get_mut(id))
    }

    pub fn has_insns(&self) -> bool {
        !self.instructions.is_empty()
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

    /*
    pub fn into_function(
        mut self,
        project: &mut Project,
    ) -> Result<Function, FunctionBuilderError> {
        self.lift_all_blocks(project)?;

        Ok(Function::new_with(self.name, self.entry)
            .with_blocks(self.blocks, self.instructions)
            .with_properties(self.properties))
    }

    pub fn from_function(function: &Function) -> Self {
        let instructions = function.instructions().to_vec();
        let instructions_map = instructions
            .iter()
            .enumerate()
            .map(|(i, insn)| (insn.address(), i))
            .collect::<BTreeMap<_, _>>();

        PartialFunction {
            name: function.name(),
            entry: function.entry(),
            blocks: function.blocks().to_vec(),
            instructions,
            instructions_map,
            properties: function.properties(),
        }
    }
    */
}

pub struct VacantInsnEntry<'a> {
    entry: VacantEntry<'a, Address, usize>,
    insns: &'a mut Vec<Insn>,
}

impl<'a> VacantInsnEntry<'a> {
    pub fn insert(self, insn: Insn) -> &'a mut Insn {
        let id = self.insns.len();
        self.insns.push(insn);
        let id = self.entry.insert(id);
        &mut self.insns[*id]
    }
}

pub struct OccupiedInsnEntry<'a> {
    entry: OccupiedEntry<'a, Address, usize>,
    insns: &'a mut Vec<Insn>,
}

impl<'a> OccupiedInsnEntry<'a> {
    pub fn get_mut(&mut self) -> &mut Insn {
        let id = *self.entry.get();
        self.insns.get_mut(id).expect("instruction must exist")
    }
}

pub enum InsnEntry<'a> {
    Vacant(VacantInsnEntry<'a>),
    Occupied(OccupiedInsnEntry<'a>),
}
