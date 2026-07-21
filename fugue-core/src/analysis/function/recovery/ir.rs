use std::collections::BTreeMap;
use std::collections::btree_map::{Entry, OccupiedEntry, VacantEntry};
use std::mem;

use super::{FunctionRecoveryError, Translator};
use crate::analysis::function::recovery::builder::CodeBlockStructuringContext;
use crate::analysis::function::recovery::{FunctionBuilderContext, FunctionRecoveryConfig};
use crate::ir::{
    Address, CodeBlock, CodeBlockProperties, CodeBlockTable, Function, FunctionId,
    FunctionProperties, FunctionTable, Insn, InsnList, Switch, Symbol,
};
use crate::lifter::{ContextSet, LifterError, PCodeOp};
use crate::storage::SegmentStorage;
use crate::storage::segments::SegmentReader;

pub enum InsnEntry<'a> {
    Occupied(OccupiedInsnEntry<'a>),
    Vacant(VacantInsnEntry<'a>),
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartialCodeBlock {
    start: Address,
    len: usize,
    context: ContextSet,
    properties: CodeBlockProperties,
    successors: Vec<usize>,
    predecessors: Vec<usize>,
    insns: Vec<usize>,
}

impl PartialCodeBlock {
    pub fn new(start: Address, len: usize, insns: Vec<usize>, context: ContextSet) -> Self {
        Self {
            start,
            len,
            insns,
            properties: CodeBlockProperties::NONE,
            predecessors: Vec::new(),
            successors: Vec::new(),
            context,
        }
    }

    pub fn address(&self) -> Address {
        self.start
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn insns(&self) -> &[usize] {
        &self.insns
    }

    pub fn insns_mut(&mut self) -> &mut Vec<usize> {
        &mut self.insns
    }

    pub fn push_insn(&mut self, insn_id: usize) {
        self.insns.push(insn_id);
    }

    pub fn context(&self) -> &ContextSet {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut ContextSet {
        &mut self.context
    }

    pub fn properties(&self) -> CodeBlockProperties {
        self.properties
    }

    pub fn mark_entry(&mut self) {
        self.properties.insert(CodeBlockProperties::ENTRY);
    }

    pub fn mark_exit(&mut self) {
        self.properties.insert(CodeBlockProperties::EXIT);
    }

    pub fn predecessors(&self) -> &[usize] {
        &self.predecessors
    }

    pub fn add_predecessor(&mut self, block_id: usize) {
        if !self.predecessors.contains(&block_id) {
            self.predecessors.push(block_id);
        }
    }

    pub fn remove_predecessor(&mut self, block_id: usize) {
        if let Some(pos) = self.predecessors.iter().position(|&id| id == block_id) {
            self.predecessors.remove(pos);
        }
    }

    pub fn successors(&self) -> &[usize] {
        &self.successors
    }

    pub fn add_successor(&mut self, block_id: usize) {
        if !self.successors.contains(&block_id) {
            self.successors.push(block_id);
        }
    }

    pub fn remove_successor(&mut self, block_id: usize) {
        if let Some(pos) = self.successors.iter().position(|&id| id == block_id) {
            self.successors.remove(pos);
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartialFunction {
    name: Option<Symbol>,
    entry: Address,
    blocks: Vec<PartialCodeBlock>,
    insns: Vec<Insn>,
    insn_map: BTreeMap<Address, usize>,
    properties: FunctionProperties,
    pending_switches: Vec<Switch>,
}

impl PartialFunction {
    pub fn new(entry: Address) -> Self {
        Self::new_with(None, entry)
    }

    pub fn new_with(name: impl Into<Option<Symbol>>, entry: Address) -> Self {
        Self {
            name: name.into(),
            entry,
            blocks: Vec::new(),
            insns: Vec::new(),
            insn_map: BTreeMap::new(),
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

    pub fn entry_block(&self) -> &PartialCodeBlock {
        self.block_at(self.entry)
            .expect("entry block should always exist")
    }

    pub fn push_block(&mut self, block: PartialCodeBlock) {
        debug_assert!(
            self.blocks.is_empty() || self.blocks.last().unwrap().address() < block.address(),
            "blocks must be inserted in order",
        );
        self.blocks.push(block);
    }

    pub fn blocks(&self) -> &[PartialCodeBlock] {
        &self.blocks
    }

    pub fn block_at(&self, address: Address) -> Option<&PartialCodeBlock> {
        self.blocks
            .binary_search_by_key(&address, |blk| blk.address())
            .ok()
            .map(|idx| &self.blocks[idx])
    }

    pub fn contains_insn(&self, address: Address) -> bool {
        self.insn_map.contains_key(&address)
    }

    pub fn insn_entry(&mut self, address: Address) -> InsnEntry {
        match self.insn_map.entry(address) {
            Entry::Vacant(entry) => InsnEntry::Vacant(VacantInsnEntry {
                entry,
                insns: &mut self.insns,
            }),
            Entry::Occupied(entry) => InsnEntry::Occupied(OccupiedInsnEntry {
                entry,
                insns: &mut self.insns,
            }),
        }
    }

    pub fn lift_block(
        &mut self,
        id: usize,
        segments: &SegmentStorage,
        translator: &mut Translator,
    ) -> Result<(), FunctionRecoveryError> {
        let block = self
            .blocks
            .get(id)
            .ok_or_else(|| FunctionRecoveryError::invalid_block_id(id))?;

        let start = block.address();
        block.context().apply(start, translator.context_mut());
        let segment = segments.view_at(start)?;
        let window = segment
            .bytes_from(start)
            .expect("block start must be in segment");
        let Some(bytes) = window.as_contiguous() else {
            return Ok(());
        };

        for insn_id in block.insns().iter().copied() {
            let insn = &mut self.insns[insn_id];

            if insn.has_resolved_flow() {
                continue;
            }

            let offset = insn
                .address()
                .checked_offset_from(start)
                .ok_or_else(|| LifterError::invalid_instruction(insn.address()))?
                as usize;

            let view = bytes
                .get(offset..)
                .ok_or_else(|| LifterError::invalid_instruction(insn.address()))?;

            *insn = translator.lift(insn.address(), view)?;
        }

        Ok(())
    }

    pub(crate) fn append_block_pcode(
        &self,
        id: usize,
        reader: &mut SegmentReader,
        translator: &mut Translator,
        operations: &mut Vec<PCodeOp>,
    ) -> Result<(), FunctionRecoveryError> {
        let block = self
            .blocks
            .get(id)
            .ok_or_else(|| FunctionRecoveryError::invalid_block_id(id))?;

        let start = block.address();
        let Some(window) = reader.view(start).and_then(|view| view.bytes_from(start)) else {
            return Err(LifterError::invalid_instruction(start).into());
        };
        let Some(bytes) = window.as_contiguous() else {
            return Err(LifterError::invalid_instruction(start).into());
        };

        block.context().apply(start, translator.context_mut());

        let operation_start = operations.len();
        for insn_id in block.insns().iter().copied() {
            let insn = &self.insns[insn_id];

            let Some(offset) = insn.address().checked_offset_from(start) else {
                operations.truncate(operation_start);
                return Err(LifterError::invalid_instruction(insn.address()).into());
            };
            let Some(view) = bytes.get(offset as usize..) else {
                operations.truncate(operation_start);
                return Err(LifterError::invalid_instruction(insn.address()).into());
            };

            if let Err(error) = translator.lift_into(insn.address(), view, operations) {
                operations.truncate(operation_start);
                return Err(error);
            }
        }

        Ok(())
    }

    pub fn lift_all_blocks(
        &mut self,
        segments: &SegmentStorage,
        translator: &mut Translator,
    ) -> Result<(), FunctionRecoveryError> {
        let mut segment = segments.view_at(self.entry)?;

        for block in self.blocks.iter_mut() {
            block
                .context()
                .apply(block.address(), translator.context_mut());
            if !segment.contains(block.address()) {
                segment = segments.view_at(block.address())?;
            }

            let window = segment
                .bytes_from(block.address())
                .expect("block start must be in segment");
            let Some(bytes) = window.as_contiguous() else {
                continue;
            };

            for insn_id in block.insns().iter().copied() {
                let insn = &mut self.insns[insn_id];

                if insn.has_resolved_flow() {
                    continue;
                }

                let offset = insn
                    .address()
                    .checked_offset_from(block.address())
                    .ok_or_else(|| LifterError::invalid_instruction(insn.address()))?
                    as usize;

                let view = bytes
                    .get(offset..)
                    .ok_or_else(|| LifterError::invalid_instruction(insn.address()))?;

                *insn = translator.lift(insn.address(), view)?;
            }
        }

        Ok(())
    }

    pub fn lift_insn(
        &mut self,
        id: usize,
        segments: &SegmentStorage,
        translator: &mut Translator,
    ) -> Result<Option<&mut Insn>, FunctionRecoveryError> {
        let context = self
            .blocks
            .iter()
            .find(|block| block.insns().contains(&id))
            .map(|block| block.context().clone());
        let insn = self
            .insns
            .get_mut(id)
            .ok_or_else(|| FunctionRecoveryError::invalid_instruction_id(id))?;

        if insn.has_resolved_flow() {
            return Ok(Some(insn));
        }

        let address = insn.address();
        if let Some(context) = context {
            context.apply(address, translator.context_mut());
        }
        let mut bytes = [0u8; 32];

        segments
            .read_bytes(address, &mut bytes)
            .expect("storage should be consistent");

        *insn = translator.lift(address, bytes)?;

        Ok(Some(insn))
    }

    pub fn indirect_branches(&self) -> impl Iterator<Item = (usize, Address)> + '_ {
        self.blocks
            .iter()
            .enumerate()
            .flat_map(move |(block_index, block)| {
                block.insns().iter().filter_map(move |&instruction| {
                    let insn = self.insns.get(instruction)?;
                    (insn.is_branch() && insn.is_indirect() && !insn.is_call() && !insn.is_return())
                        .then_some((block_index, insn.address()))
                })
            })
    }

    pub fn insn(&self, address: Address) -> Option<&Insn> {
        self.insn_map
            .get(&address)
            .and_then(|&id| self.insns.get(id))
    }

    pub fn insn_mut(&mut self, address: Address) -> Option<&mut Insn> {
        self.insn_map
            .get(&address)
            .and_then(|&id| self.insns.get_mut(id))
    }

    pub fn has_insns(&self) -> bool {
        !self.insns.is_empty()
    }

    pub fn insns(&self) -> &[Insn] {
        &self.insns
    }

    pub fn insns_mut(&mut self) -> &mut Vec<Insn> {
        &mut self.insns
    }

    fn rebuild_insn_mappings(&mut self, context: &mut CodeBlockStructuringContext) {
        self.blocks.clear();
        self.insns.sort_by_key(|insn| insn.address());
        self.insn_map.clear();

        context.clear();

        for (id, insn) in self.insns.iter_mut().enumerate() {
            let addr = insn.address();

            self.insn_map.insert(addr, id);

            if context.is_flow_target(addr) {
                context.mark_cut_point(id);
                insn.mark_maybe_taken();
            } else {
                insn.unmark_maybe_taken();
            }
        }
    }

    pub fn structure_blocks(
        &mut self,
        config: &FunctionRecoveryConfig,
        context: &mut FunctionBuilderContext,
    ) -> Result<(), FunctionRecoveryError> {
        let mut ctxt = context.structuring_context();

        self.rebuild_insn_mappings(&mut ctxt);

        let num_insns = self.insns.len();
        let num_blocks = ctxt.cut_points.len();
        let max_blocks = config.max_function_blocks();
        let max_insns = config.max_block_insns();

        if num_blocks > max_blocks {
            tracing::debug!(
                "number of blocks ({num_blocks}) exceeds limit ({max_blocks}); skipping",
            );
            return Err(FunctionRecoveryError::invalid_function_size(
                self.entry(),
                num_blocks,
                max_blocks,
            ));
        }

        let next_cut_point = |next_idx: usize| -> usize {
            ctxt.cut_points.get(next_idx).copied().unwrap_or(num_insns)
        };

        'cuts: for (cut_idx, cut) in ctxt.cut_points.iter().enumerate() {
            let start = *cut;
            let address = self.insns[start].address();

            let block_idx = self.blocks.len();
            let block_ctx = ctxt.contexts.get(&address).cloned().unwrap_or_default();

            let mut next_cut_idx = cut_idx + 1;
            let mut next_cut = next_cut_point(next_cut_idx);

            let mut expected = address;
            let mut length = 0usize;

            let mut points = Vec::<usize>::new();

            tracing::trace!("structuring block at {address}; start: {start}");

            for curr in start..num_insns {
                let insn = &self.insns[curr];
                let next = curr + 1;

                if points.len() >= max_insns {
                    tracing::debug!(
                        "block at {address} exceeds maximum instruction count ({max_insns})",
                    );
                    return Err(FunctionRecoveryError::invalid_block_size(
                        address,
                        points.len(),
                        max_insns,
                    ));
                }

                if curr == next_cut {
                    // potential end of block
                    if !insn.is_flow()
                        && matches!(self.insns.get(next), Some(insn) if expected > insn.address())
                    {
                        next_cut_idx += 1;
                        next_cut = next_cut_point(next_cut_idx);
                    } else {
                        let last_insn =
                            &self.insns[points.last().copied().expect("points must not be empty")];
                        let last_address = last_insn.address();

                        debug_assert!(ctxt.block_starts.insert(address, block_idx).is_none());
                        debug_assert!(ctxt.block_ends.insert(last_address, block_idx).is_none());

                        self.push_block(PartialCodeBlock::new(address, length, points, block_ctx));
                        continue 'cuts;
                    }
                }

                if insn.address() == expected {
                    tracing::trace!(
                        "adding instruction at {} to block: {} (id: {curr})",
                        insn.address(),
                        address
                    );
                    points.push(curr);
                    expected = insn.next_address();
                    length += insn.len();
                }
            }

            // NOTE: we should refactor this--we have a bit of duplication and we can
            // probably reduce lookups.
            let last_insn = &self.insns[points.last().copied().expect("points must not be empty")];
            let last_address = last_insn.address();

            debug_assert!(ctxt.block_starts.insert(address, block_idx).is_none());
            debug_assert!(ctxt.block_ends.insert(last_address, block_idx).is_none());

            self.push_block(PartialCodeBlock::new(address, length, points, block_ctx));
        }

        for target in context.local_targets().iter() {
            let Some(from) = context.block_ends().get(&target.from()).copied() else {
                tracing::trace!(
                    "skipping local target: {} -> {} ({:?}): no block end",
                    target.from(),
                    target.to(),
                    target.kind()
                );
                continue;
            };

            let Some(to) = context.block_starts().get(&target.to()).copied() else {
                tracing::trace!(
                    "skipping local target: {} -> {} ({:?}): no block start",
                    target.from(),
                    target.to(),
                    target.kind()
                );
                continue;
            };

            tracing::trace!("adding local target: {from} -> {to} ({:?})", target.kind());

            self.blocks[from].add_successor(to);
            self.blocks[to].add_predecessor(from);
        }

        for index in 0..self.blocks.len() {
            let Some(&last) = self.blocks[index].insns().last() else {
                continue;
            };
            let insn = &self.insns[last];
            if !insn.has_fall() {
                continue;
            }
            let Some(&next) = context.block_starts().get(&insn.next_address()) else {
                continue;
            };

            self.blocks[index].add_successor(next);
            self.blocks[next].add_predecessor(index);
        }

        Ok(())
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

    pub fn commit(
        self,
        ftable: &mut FunctionTable,
        cbtable: &mut CodeBlockTable,
    ) -> Result<FunctionId, FunctionRecoveryError> {
        // first we create the code blocks
        let mut bids = Vec::with_capacity(self.blocks.len());
        for block in self.blocks.iter() {
            let bid = cbtable
                .insert(block.address(), |id, addr| {
                    let len = block.len();
                    let insns = InsnList::from_iter(
                        block
                            .insns()
                            .iter()
                            .map(|&insn_id| self.insns[insn_id].clone()),
                    );

                    Ok(
                        CodeBlock::try_new_with(id, addr, len, insns, block.context().clone())
                            .expect("code block has non-zero length"),
                    )
                })
                .map_err(FunctionRecoveryError::block_creation)?;
            bids.push(bid);
        }

        for (i, block) in self.blocks.iter().enumerate() {
            let bid = bids[i];

            let mut cb = cbtable.get_by_id_mut(bid).expect("code block exists");

            for &succ_idx in block.successors().iter() {
                cb.add_successor(bids[succ_idx]);
            }

            for &pred_idx in block.predecessors().iter() {
                cb.add_predecessor(bids[pred_idx]);
            }
        }

        // now we create the function
        let fid = ftable
            .insert(self.entry(), |id, addr| {
                let mut function = Function::new(id, addr);

                function.add_blocks(
                    self.blocks
                        .iter()
                        .map(|blk| blk.address())
                        .zip(bids.iter().copied()),
                );

                function.set_properties(self.properties);

                Ok(function)
            })
            .map_err(FunctionRecoveryError::function_creation)?;

        Ok(fid)
    }
}
