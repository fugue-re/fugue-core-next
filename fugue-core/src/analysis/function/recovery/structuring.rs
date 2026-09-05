use indexmap::IndexSet;
use rustc_hash::{FxBuildHasher, FxHashMap};

use crate::analysis::function::recovery::{FunctionRecoveryConfig, FunctionRecoveryError};
use crate::ir::{
    Address, FlowTarget, IncompleteCodeBlock, IncompleteCodeBlockId, IncompleteFunction, InsnId,
};
use crate::lifter::ContextSet;

#[derive(Default)]
pub(crate) struct FunctionStructurer {
    block_starts: FxHashMap<Address, IncompleteCodeBlockId>,
    block_ends: FxHashMap<Address, IncompleteCodeBlockId>,
    cut_positions: Vec<usize>,
}

impl FunctionStructurer {
    pub(crate) fn block_starts(
        &self,
    ) -> impl ExactSizeIterator<Item = (Address, IncompleteCodeBlockId)> {
        self.block_starts
            .iter()
            .map(|(address, block)| (*address, *block))
    }

    pub(crate) fn block_start_at(&self, address: Address) -> Option<IncompleteCodeBlockId> {
        self.block_starts.get(&address).copied()
    }

    pub(crate) fn block_ends(
        &self,
    ) -> impl ExactSizeIterator<Item = (Address, IncompleteCodeBlockId)> {
        self.block_ends
            .iter()
            .map(|(address, block)| (*address, *block))
    }

    pub(crate) fn block_end_at(&self, address: Address) -> Option<IncompleteCodeBlockId> {
        self.block_ends.get(&address).copied()
    }

    fn next_cut_point(&self, index: usize, num_insns: usize) -> usize {
        self.cut_positions.get(index).copied().unwrap_or(num_insns)
    }

    pub(crate) fn clear(&mut self) {
        self.block_starts.clear();
        self.block_ends.clear();
        self.cut_positions.clear();
    }

    pub(crate) fn structure<'a>(
        &mut self,
        function: &mut IncompleteFunction,
        config: &FunctionRecoveryConfig,
        block_starts: impl ExactSizeIterator<Item = Address>,
        context_at: impl Fn(Address) -> Option<&'a ContextSet>,
        local_targets: &IndexSet<FlowTarget, FxBuildHasher>,
    ) -> Result<(), FunctionRecoveryError> {
        function.clear_blocks();
        function.sort_insns_by_address();
        for &address in self.block_starts.keys() {
            let Some(insn_id) = function.first_insn_id_at(address) else {
                continue;
            };
            function
                .insn_mut(insn_id)
                .expect("instruction must exist")
                .unmark_maybe_taken();
        }
        self.clear();
        self.cut_positions.reserve(block_starts.len());

        for address in block_starts {
            let Some(insn_id) = function.first_insn_id_at(address) else {
                continue;
            };
            function
                .insn_mut(insn_id)
                .expect("instruction must exist")
                .mark_maybe_taken();
            self.cut_positions.push(insn_id.index());
        }
        self.cut_positions.sort_unstable();

        let num_insns = function.insns().len();
        let num_blocks = self.cut_positions.len();
        let max_blocks = config.max_function_blocks();
        let max_insns = config.max_block_insns();

        if num_blocks > max_blocks {
            tracing::debug!(
                "number of blocks ({num_blocks}) exceeds limit ({max_blocks}); skipping",
            );
            return Err(FunctionRecoveryError::invalid_function_block_count(
                function.entry(),
                num_blocks,
                max_blocks,
            ));
        }

        function.reserve_blocks(num_blocks);
        self.block_starts.reserve(num_blocks);
        self.block_ends.reserve(num_blocks);

        'cuts: for cut_index in 0..self.cut_positions.len() {
            let start = self.cut_positions[cut_index];
            let address = function.insns()[start].address();
            let block_context = context_at(address).cloned().unwrap_or_default();
            let mut next_cut_index = cut_index + 1;
            let mut next_cut = self.next_cut_point(next_cut_index, num_insns);
            let mut expected = address;
            let mut size = 0usize;
            let mut insns = Vec::with_capacity(next_cut.saturating_sub(start).min(max_insns));

            tracing::trace!("structuring block at {address}; start: {start}");

            for current in start..num_insns {
                let insn = &function.insns()[current];
                let next = current + 1;

                if insns.len() >= max_insns {
                    tracing::debug!(
                        "block at {address} exceeds maximum instruction count ({max_insns})",
                    );
                    return Err(FunctionRecoveryError::invalid_block_insn_count(
                        address,
                        insns.len(),
                        max_insns,
                    ));
                }

                if current == next_cut {
                    if !insn.is_flow()
                        && function
                            .insns()
                            .get(next)
                            .is_some_and(|next| expected > next.address())
                    {
                        next_cut_index += 1;
                        next_cut = self.next_cut_point(next_cut_index, num_insns);
                    } else {
                        self.push_block(function, address, size, insns, block_context);
                        continue 'cuts;
                    }
                }

                if insn.address() == expected {
                    tracing::trace!(
                        "adding instruction at {} to block: {} (id: {current})",
                        insn.address(),
                        address,
                    );
                    insns.push(function.insn_id(current).expect("instruction must exist"));
                    expected = insn.next_address();
                    size = size.checked_add(insn.size()).ok_or_else(|| {
                        FunctionRecoveryError::invalid_block_size(address, usize::MAX)
                    })?;
                    if size > u16::MAX as usize {
                        return Err(FunctionRecoveryError::invalid_block_size(address, size));
                    }
                }
            }

            self.push_block(function, address, size, insns, block_context);
        }

        self.connect_local_targets(function, local_targets);
        self.connect_fall_throughs(function);

        Ok(())
    }

    fn push_block(
        &mut self,
        function: &mut IncompleteFunction,
        address: Address,
        size: usize,
        insns: Vec<InsnId>,
        context: ContextSet,
    ) {
        let last = *insns.last().expect("block must contain an instruction");
        let last_address = function
            .insn(last)
            .expect("instruction must exist")
            .address();
        let block = function.push_block(
            IncompleteCodeBlock::try_new(address, size, insns, context)
                .expect("block size must be validated"),
        );

        let previous_start = self.block_starts.insert(address, block);
        let previous_end = self.block_ends.insert(last_address, block);
        debug_assert!(previous_start.is_none());
        debug_assert!(previous_end.is_none());
    }

    fn connect_local_targets(
        &self,
        function: &mut IncompleteFunction,
        local_targets: &IndexSet<FlowTarget, FxBuildHasher>,
    ) {
        for target in local_targets {
            let Some(&from) = self.block_ends.get(&target.from()) else {
                tracing::trace!(
                    "skipping local target: {} -> {} ({:?}): no block end",
                    target.from(),
                    target.to(),
                    target.kind(),
                );
                continue;
            };
            let Some(&to) = self.block_starts.get(&target.to()) else {
                tracing::trace!(
                    "skipping local target: {} -> {} ({:?}): no block start",
                    target.from(),
                    target.to(),
                    target.kind(),
                );
                continue;
            };

            tracing::trace!(
                "adding local target: {from:?} -> {to:?} ({:?})",
                target.kind()
            );

            function
                .add_block_edge(from, to)
                .expect("local target blocks must exist");
        }
    }

    fn connect_fall_throughs(&self, function: &mut IncompleteFunction) {
        for index in 0..function.blocks().len() {
            let block = &function.blocks()[index];
            let from = self.block_starts[&block.address()];
            let Some(last) = function.blocks()[index].insn_ids().last().copied() else {
                continue;
            };
            let insn = function.insn(last).expect("instruction must exist");
            if !insn.has_fall_through() {
                continue;
            }
            let Some(&next) = self.block_starts.get(&insn.next_address()) else {
                continue;
            };

            function
                .add_block_edge(from, next)
                .expect("fall-through blocks must exist");
        }
    }
}
