use std::collections::btree_map::{Entry, OccupiedEntry, VacantEntry};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::mem;

use thiserror::Error;
use ustr::Ustr;

use crate::analysis::{AnalysisError, AnalysisGroup, AnalysisPass};
use crate::entities::flow_graph::{FlowKind, FlowTarget};
use crate::entities::function::FunctionProperties;
use crate::entities::instruction::InsnList;
use crate::entities::{BasicBlock, Function, Insn};
use crate::lifter::{ContextSet, LifterError};
use crate::project::Project;
use crate::types::address::{Address, AddressMap};

pub struct FunctionRecoveryConfig {
    pub max_blocks: usize,
}

impl Default for FunctionRecoveryConfig {
    fn default() -> Self {
        FunctionRecoveryConfig {
            max_blocks: 0x10000,
        }
    }
}

pub struct FunctionRecovery<'a> {
    candidates: VecDeque<(Address, ContextSet)>,
    builder: FunctionBuilder<'a>,
}

#[derive(Default)]
pub struct FunctionBuilderContext {
    entry: Address,
    candidates: VecDeque<(Address, ContextSet)>,
    contexts: BTreeMap<Address, ContextSet>,
    local_targets: BTreeSet<FlowTarget>,
    global_targets: BTreeSet<(Address, ContextSet)>,
    // These are used to structure the blocks after lifting; we keep them here
    // to avoid having to reallocate on each function analysis. They refer to
    // the partial function being constructed.
    block_starts: AddressMap<usize>,
    block_ends: AddressMap<usize>,
    cuts: Vec<usize>,
}

#[derive(Default)]
pub struct PartialFunction {
    name: Option<Ustr>,
    entry: Address,
    blocks: Vec<BasicBlock>,
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

    pub fn entry_block(&self) -> &BasicBlock {
        self.block_at(self.entry)
            .expect("entry block should always exist")
    }

    pub(crate) fn push_block(&mut self, block: BasicBlock) {
        debug_assert!(
            self.blocks.is_empty() || self.blocks.last().unwrap().start() < block.start(),
            "blocks must be inserted in order",
        );
        self.blocks.push(block);
    }

    pub fn blocks(&self) -> &[BasicBlock] {
        &self.blocks
    }

    pub fn block_at(&self, address: Address) -> Option<&BasicBlock> {
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

    pub fn into_function(
        mut self,
        project: &mut Project,
    ) -> Result<Function, FunctionBuilderError> {
        self.lift_all_blocks(project)?;

        Ok(Function::new_with(self.name, self.entry)
            .with_blocks(self.blocks, self.instructions)
            .with_properties(self.properties))
    }
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

pub struct PartialFunctionWithContext {
    pub context: FunctionBuilderContext,
    pub function: PartialFunction,
}

pub struct FunctionBuilder<'a> {
    // The configuration for the function recovery process.
    config: FunctionRecoveryConfig,
    // The context of the function being built.
    context: FunctionBuilderContext,
    // These passes run once per function prior to the main lifting loop.
    initialisation_passes: AnalysisGroup<'a, FunctionBuilderContext>,
    // These passes run each iteration of the main lifting loop after all candidates within the
    // pass have been lifted and the function's control-flow has been structured based on the
    // identified blocks and flows.
    post_lifting_passes: AnalysisGroup<'a, PartialFunctionWithContext>,
}

#[derive(Debug, Error)]
pub enum FunctionBuilderError {
    #[error("initialisation pass failed: {0}")]
    InitialisationPass(AnalysisError),
    #[error("post-lifting pass failed: {0}")]
    PostLiftingPass(AnalysisError),
    #[error("failed to lift any instructions")]
    NoInstructions,
    #[error("failed to create function; number of blocks ({0}) exceeds limit ({1})")]
    ExceededBlockLimit(usize, usize),
    #[error(transparent)]
    Lifter(#[from] LifterError),
    #[error("failed persist function: {0}")]
    EntityStorage(#[from] crate::storage::EntityStorageError),
    #[error(transparent)]
    SegmentStorage(#[from] crate::storage::SegmentStorageError),
    #[error("invalid block index: {0}")]
    InvalidBlockId(usize),
    #[error("invalid instruction index: {0}")]
    InvalidInstructionId(usize),
}

impl<'a> FunctionRecovery<'a> {
    pub fn new() -> Self {
        FunctionRecovery::new_with(FunctionRecoveryConfig::default())
    }

    pub fn new_with(config: FunctionRecoveryConfig) -> Self {
        FunctionRecovery {
            candidates: VecDeque::new(),
            builder: FunctionBuilder::new(config),
        }
    }

    pub fn add_candidate(&mut self, address: impl Into<Address>) {
        self.add_candidate_with_context(address, ContextSet::new());
    }

    pub fn add_candidate_with_context(&mut self, address: impl Into<Address>, context: ContextSet) {
        self.candidates.push_back((address.into(), context));
    }

    pub fn add_candidates(&mut self, addresses: impl IntoIterator<Item = impl Into<Address>>) {
        self.add_candidates_with_context(
            addresses
                .into_iter()
                .zip(std::iter::repeat(ContextSet::new())),
        );
    }

    pub fn add_candidates_with_context(
        &mut self,
        candidates: impl IntoIterator<Item = (impl Into<Address>, ContextSet)>,
    ) {
        self.candidates.extend(
            candidates
                .into_iter()
                .map(|(addr, context)| (addr.into(), context)),
        );
    }

    pub fn add_function_builder_initialisation_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<'a, FunctionBuilderContext> + 'a,
    ) {
        self.builder.add_initialisation_pass(name, pass);
    }

    pub fn add_function_builder_post_lifting_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<'a, PartialFunctionWithContext> + 'a,
    ) {
        self.builder.add_post_lifting_pass(name, pass);
    }
}

impl<'a> AnalysisPass<'a> for FunctionRecovery<'a> {
    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        if let Some(entry) = project.entry() {
            tracing::debug!("entry point: {entry}");
            self.add_candidate(entry);
        }

        for symbol in project.iter_local_symbols().filter(|s| s.is_function()) {
            tracing::debug!(
                "local function: {} (name: {:?})",
                symbol.address(),
                symbol.symbol()
            );
            self.add_candidate(symbol.address());
        }

        for symbol in project.iter_extern_symbols().filter(|s| s.is_function()) {
            tracing::debug!(
                "external function: {} (name: {:?})",
                symbol.address(),
                symbol.symbol()
            );
            self.add_candidate(symbol.address());
        }

        let mut functions = BTreeSet::new();
        let mut failures = BTreeSet::new();

        while let Some((address, context)) = self.candidates.pop_front() {
            if !project.storage.segments.contains_segment(address) {
                tracing::trace!("skipping {address}: not mapped");
                continue;
            }

            if failures.contains(&address) {
                tracing::trace!("skipping {address}: already failed");
                continue;
            }

            if functions.contains(&address) {
                tracing::trace!("skipping {address}: already analysed");
                continue;
            }

            let function = match self.builder.analyse(project, address, context) {
                Ok(f) => f,
                Err(e) => {
                    failures.insert(address);
                    tracing::trace!("failed to analyse {address}: {e}");
                    continue;
                }
            };

            functions.insert(address);

            if let Err(e) = project.functions().insert(address, function) {
                tracing::debug!("failed to persist function at {address}: {e}");
                return Err(AnalysisError::pass_failed("function-recovery", e));
            }

            self.candidates.extend(
                self.builder
                    .global_targets()
                    .iter()
                    .filter(|(start, _)| !functions.contains(start) && !failures.contains(start))
                    .cloned(),
            );
        }

        for f in functions {
            tracing::debug!("function: {f}");
        }

        Ok(())
    }
}

impl<'a> FunctionBuilder<'a> {
    pub fn new(config: FunctionRecoveryConfig) -> Self {
        FunctionBuilder {
            config,
            context: FunctionBuilderContext::new(),
            initialisation_passes: AnalysisGroup::new(),
            post_lifting_passes: AnalysisGroup::new(),
        }
    }

    pub fn initialisation_passes(&self) -> &AnalysisGroup<'a, FunctionBuilderContext> {
        &self.initialisation_passes
    }

    pub fn initialisation_passes_mut(&mut self) -> &mut AnalysisGroup<'a, FunctionBuilderContext> {
        &mut self.initialisation_passes
    }

    pub fn post_lifting_passes(&self) -> &AnalysisGroup<'a, PartialFunctionWithContext> {
        &self.post_lifting_passes
    }

    pub fn post_lifting_passes_mut(
        &mut self,
    ) -> &mut AnalysisGroup<'a, PartialFunctionWithContext> {
        &mut self.post_lifting_passes
    }

    pub fn context(&self) -> &FunctionBuilderContext {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut FunctionBuilderContext {
        &mut self.context
    }

    pub fn add_initialisation_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<'a, FunctionBuilderContext> + 'a,
    ) {
        self.initialisation_passes.add_pass(name, pass);
    }

    pub fn add_post_lifting_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<'a, PartialFunctionWithContext> + 'a,
    ) {
        self.post_lifting_passes.add_pass(name, pass);
    }

    pub fn analyse(
        &mut self,
        project: &mut Project,
        address: impl Into<Address>,
        context: ContextSet,
    ) -> Result<Function, FunctionBuilderError> {
        self.context.analyse(
            project,
            address,
            context,
            &self.config,
            &mut self.initialisation_passes,
            &mut self.post_lifting_passes,
        )
    }

    pub fn local_targets(&self) -> &BTreeSet<FlowTarget> {
        &self.context.local_targets
    }

    pub fn global_targets(&self) -> &BTreeSet<(Address, ContextSet)> {
        &self.context.global_targets
    }
}

impl FunctionBuilderContext {
    pub fn new() -> Self {
        Self {
            entry: Address::zero(),
            candidates: VecDeque::new(),
            contexts: BTreeMap::new(),
            local_targets: BTreeSet::new(),
            global_targets: BTreeSet::new(),
            // These are used to structure the blocks after lifting; we keep them here
            // to avoid having to reallocate on each function analysis.
            block_starts: AddressMap::new(),
            block_ends: AddressMap::new(),
            cuts: Vec::new(),
        }
    }

    pub fn entry(&self) -> Address {
        self.entry
    }

    pub fn add_candidate(&mut self, address: impl Into<Address>) {
        self.add_candidate_with_context(address, ContextSet::new());
    }

    pub fn add_candidate_with_context(&mut self, address: impl Into<Address>, context: ContextSet) {
        self.candidates.push_back((address.into(), context));
    }

    pub fn add_candidates(&mut self, addresses: impl IntoIterator<Item = impl Into<Address>>) {
        self.add_candidates_with_context(
            addresses
                .into_iter()
                .zip(std::iter::repeat(ContextSet::new())),
        );
    }

    pub fn add_candidates_with_context(
        &mut self,
        candidates: impl IntoIterator<Item = (impl Into<Address>, ContextSet)>,
    ) {
        self.candidates.extend(
            candidates
                .into_iter()
                .map(|(addr, context)| (addr.into(), context)),
        );
    }

    pub fn add_local_target(
        &mut self,
        from: impl Into<Address>,
        to: impl Into<Address>,
        kind: FlowKind,
    ) {
        self.local_targets
            .insert(FlowTarget::new(from.into(), to.into(), kind));
    }

    pub fn clear(&mut self) {
        self.entry = Address::zero();
        self.candidates.clear();
        self.contexts.clear();
        self.local_targets.clear();
        self.global_targets.clear();
    }

    fn lift_insns(&mut self, project: &mut Project, f: &mut PartialFunction) {
        // NOTE: as opposed to reading bytes from the storage, for all existing backends we can
        // create a "cheap" view over the containing segment and use that to avoid lookups for each
        // address read from.

        // We assume that most (all?) of a function's blocks will be in the same segment.
        let mut segment = project
            .storage
            .segments
            .find_segment_containing(self.entry())
            .expect("function entry is valid");

        // This is the stage where we build blocks by collecting instructions and marking them.
        'outer: while let Some((block, mut context)) = self.candidates.pop_front() {
            // This ensures correct alignment, to address is correctly wrapped with respect to
            // the address space, and also extracts context updates indicated by the address,
            // e.g., if we are in Thumb context or not for ARM.
            let Some((block, ncontext)) = project
                .arch
                .canonicalise_address_with(block, project.lifter.context())
            else {
                tracing::trace!("skipping {block}: not a viable block start address");
                continue 'outer;
            };

            if !segment.contains_address(block) {
                if let Ok(nsegment) = project.storage.segments.find_segment_containing(block) {
                    tracing::debug!("switching segment for {block} to segment {nsegment}");
                    segment = nsegment;
                } else {
                    tracing::trace!("skipping {block}: not mapped in any segment");
                    continue 'outer;
                }
            }

            tracing::trace!("lifting new block {block}");

            // Merge the context updates with the specified context taking precedence.
            context.merge(ncontext);

            // Applies the context updates to the lifter context.
            context.apply(block, project.lifter.context_mut());

            // Save the context so we can associate it with a block later.
            self.contexts.entry(block).or_insert(context);

            let mut offset = 0usize;

            '_inner: loop {
                let address = block + offset;

                tracing::trace!("lifting at {address}");

                // If we've already disassembled this instruction select the next candidate,
                // otherwise get the entry ready for update.
                let entry = match f.insn_entry(address) {
                    InsnEntry::Vacant(entry) => entry,
                    InsnEntry::Occupied(mut entry) => {
                        // If two blocks overlap, then they may share a common suffix to account
                        // for this we mark instructions that appear in multiple blocks as starts
                        // so they're considered cut points when performing block structuring.
                        entry.get_mut().mark_maybe_taken();
                        self.contexts
                            .entry(address)
                            .or_insert_with(ContextSet::default);
                        continue 'outer;
                    }
                };

                let Some(bytes) = segment.view_bytes_from_address(address) else {
                    tracing::trace!("skipping {address}: not mapped in segment");
                    continue 'outer;
                };

                let size = bytes.len();

                tracing::trace!("lifting {address} ({size} bytes available)");

                match project.lifter.disassemble_insn(address, bytes) {
                    Ok(insn) => {
                        let insn = entry.insert(insn);

                        // Explicit control-flow
                        if insn.is_flow() {
                            // We're done with this block; we schedule the next bit of work

                            // These targets are what we can statically compute by scanning the
                            // instruction's PCode branch operations--we will miss things like PC
                            // relative jumps; these constructs will be handled in post lifting
                            // passes.
                            for (target, kind, addr) in insn.iter_targets() {
                                let Some((addr, context)) = project.arch.canonicalise_address(addr)
                                else {
                                    continue;
                                };

                                if kind.is_local() {
                                    let Some(target) =
                                        FlowTarget::from_insn_target(insn, target, addr)
                                    else {
                                        continue;
                                    };

                                    if self.local_targets.insert(target) {
                                        self.candidates.push_back((addr, context));
                                    }
                                } else {
                                    self.global_targets.insert((addr, context));
                                }
                            }

                            continue 'outer;
                        }

                        // Implicit control-flow (it is a halt, etc.)
                        if !insn.has_fall() {
                            // We're done with this block
                            continue 'outer;
                        }

                        offset += insn.len();
                    }
                    Err(e) => {
                        // Flows into bad data; we skip this block and remove its context
                        tracing::debug!("skipping {address}; lifting failed: {e}");
                        self.contexts.remove(&address);
                        continue 'outer;
                    }
                }
            }
        }
    }

    fn structure_blocks(
        &mut self,
        config: &FunctionRecoveryConfig,
        f: &mut PartialFunction,
    ) -> Result<(), FunctionBuilderError> {
        self.block_starts.clear();
        self.block_ends.clear();
        self.cuts.clear();

        f.instructions.sort_by_key(|insn| insn.address());
        f.instructions_map.clear();

        // valid contexts contain all cut points; we mark all instructions that
        // are flow targets as maybe taken.
        for (i, insn) in f.instructions.iter_mut().enumerate() {
            let addr = insn.address();

            tracing::trace!("checking insn {i}: {addr}");

            f.instructions_map.insert(addr, i);

            if self.contexts.contains_key(&addr) {
                tracing::trace!("found cut at {addr} ({i})");
                self.cuts.push(i);
            }

            insn.mark_maybe_taken();
        }

        let num_blocks = self.cuts.len();
        let max_blocks = config.max_blocks;

        if num_blocks > max_blocks {
            tracing::debug!(
                "number of blocks ({num_blocks}) exceeds limit ({max_blocks}); skipping",
            );
            return Err(FunctionBuilderError::ExceededBlockLimit(
                num_blocks, max_blocks,
            ));
        }

        let num_insns = f.instructions.len();

        let get_next_cut = |idx: usize| self.cuts.get(idx).copied().unwrap_or(num_insns);
        let emit_block = |address, length, points| {
            let context = self.contexts.get(&address).cloned().unwrap_or_default();
            BasicBlock::new_with(address, length, points, context)
        };

        'cuts: for (cut_idx, cut) in self.cuts.iter().enumerate() {
            let start = *cut;
            let address = f.instructions[start].address();
            let block_idx = f.blocks.len();

            let mut next_cut_idx = cut_idx + 1;
            let mut next_cut = get_next_cut(next_cut_idx);

            let mut expected = address;
            let mut length = 0usize;

            let mut points = InsnList::new();

            tracing::trace!("structuring block at {address}; start: {start}");

            for curr in start..num_insns {
                let insn = &f.instructions[curr];
                let next = curr + 1;

                if curr == next_cut {
                    // potential end of block
                    if !insn.is_flow()
                        && matches!(f.instructions.get(next), Some(insn) if expected > insn.address())
                    {
                        next_cut_idx += 1;
                        next_cut = get_next_cut(next_cut_idx);
                    } else {
                        let last_insn =
                            &f.instructions[points.last().expect("points must not be empty")];
                        let last_address = last_insn.address();

                        debug_assert!(self.block_starts.insert(address, block_idx).is_none());
                        debug_assert!(self.block_ends.insert(last_address, block_idx).is_none());

                        f.push_block(emit_block(address, length, points));
                        continue 'cuts;
                    }
                }

                if insn.address() == expected {
                    tracing::trace!(
                        "adding instruction at {} to block: {} (id: {curr})",
                        insn.address(),
                        address
                    );
                    points.insert(curr);
                    expected = insn.next_address();
                    length += insn.len();
                }
            }

            // NOTE: we should refactor this--we have a bit of duplication and we can
            // probably reduce lookups.
            let last_insn = &f.instructions[points.last().expect("points must not be empty")];
            let last_address = last_insn.address();

            debug_assert!(self.block_starts.insert(address, block_idx).is_none());
            debug_assert!(self.block_ends.insert(last_address, block_idx).is_none());

            f.push_block(emit_block(address, length, points));
        }

        for target in self.local_targets.iter() {
            let Some(from) = self.block_ends.get(target.from()).copied() else {
                tracing::trace!(
                    "skipping local target: {} -> {} ({:?}): no block end",
                    target.from(),
                    target.to(),
                    target.kind()
                );
                continue;
            };

            let Some(to) = self.block_starts.get(target.to()).copied() else {
                tracing::trace!(
                    "skipping local target: {} -> {} ({:?}): no block start",
                    target.from(),
                    target.to(),
                    target.kind()
                );
                continue;
            };

            tracing::trace!("adding local target: {from} -> {to} ({:?})", target.kind());

            f.blocks[from].add_successor(to);
            f.blocks[to].add_predecessor(from);
        }

        Ok(())
    }

    pub fn analyse(
        &mut self,
        project: &mut Project,
        address: impl Into<Address>,
        context: ContextSet,
        config: &FunctionRecoveryConfig,
        initialisation_passes: &mut AnalysisGroup<'_, FunctionBuilderContext>,
        post_lifting_passes: &mut AnalysisGroup<'_, PartialFunctionWithContext>,
    ) -> Result<Function, FunctionBuilderError> {
        // We have three main stages:
        //
        // 1. We first initialise the function builder with the entry point and the context
        //    of the entry block.
        // 2. We enter the main loop where we lift instructions block by block, and add newly
        //    discovered blocks (and edges) to the candidates queue.
        // 3. We structure the blocks into a basic function-like structure; we use this
        //    structure as input to resolve jump tables, indirect jumps, etc. this part of
        //    the analysis provides new candidates and new edges.
        //
        // Stage 1 and 3 are hookable; we may register analysis passes to be run prior to the
        // main loop and after each block discovery pass has completed within the main loop.
        //
        // By default these passes are added via `add_XXX_pass` methods during `FunctionRecovery`
        // initialisation.

        let candidate = address.into();

        tracing::debug!("exploring from {candidate}");

        self.clear();
        self.entry = candidate;
        self.candidates.push_back((candidate, context));

        // Run the initialisation passes
        initialisation_passes
            .analyse_with(project, self)
            .map_err(FunctionBuilderError::InitialisationPass)?;

        let mut partial = PartialFunction::new(self.entry);

        loop {
            self.lift_insns(project, &mut partial);

            if !partial.has_insns() {
                tracing::debug!("no instructions lifted; invalid function");
                return Err(FunctionBuilderError::NoInstructions);
            }

            tracing::trace!("{:?}", self.local_targets);

            self.structure_blocks(config, &mut partial)?;

            for block in partial.blocks.iter() {
                tracing::debug!("blk@{}", block.start());
                for insn in block
                    .instructions()
                    .iter()
                    .map(|i| &partial.instructions[i])
                {
                    tracing::debug!("{}: {}", insn.address(), insn.display(project.language));
                }
            }

            let num_local_targets = self.local_targets.len();

            let mut function_with_context = PartialFunctionWithContext {
                context: mem::take(self),
                function: mem::take(&mut partial),
            };

            // Run post-lifting passes
            let result = post_lifting_passes.analyse_with(project, &mut function_with_context);

            *self = function_with_context.context;
            partial = function_with_context.function;

            result.map_err(FunctionBuilderError::PostLiftingPass)?;

            if self.candidates.is_empty() && self.local_targets.len() == num_local_targets {
                // No new candidates were added, and no new local targets were discovered.
                // We can stop here.
                tracing::debug!("no new candidates or local targets; stopping");
                break;
            }
        }

        partial.into_function(project)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::analysis::AnalysisPass;
    use crate::attributes;
    use crate::loader::Shellcode;
    use crate::storage::TransientStorageProvider;
    use crate::types::attributes::*;

    #[test]
    fn test_control_flow_recovery() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let mut project = Project::from_file_with::<TransientStorageProvider>(
                "tests/ls.elf",
                attributes![
                    ATTRIBUTE_PROJECT_PATH => "/tmp/ls.fudb",
                ],
            )?;
            let mut cfr = FunctionRecovery::new();

            cfr.add_candidate(0x4da0u64);
            cfr.add_candidate(0x6dd0u64);
            cfr.analyse(&mut project)?;

            Ok(())
        })
    }

    #[test]
    fn test_control_flow_recovery_overlap() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let shellcode = [
                0x55, 0x8B, 0xEC, 0x51, 0x51, 0x56, 0x8B, 0x75, 0x0C, 0x57, 0x33, 0xFF, 0x39, 0x3D,
                0x6C, 0x50, 0x40, 0x00, 0x75, 0x26, 0x56, 0xFF, 0x75, 0x08, 0x68, 0x18, 0x12, 0x40,
                0x00, 0xFF, 0x15, 0xF0, 0x10, 0x40, 0x00, 0x85, 0xC0, 0x74, 0x13, 0x68, 0xE0, 0x12,
                0x40, 0x00, 0xFF, 0x75, 0x08, 0xFF, 0x15, 0xEC, 0x10, 0x40, 0x00, 0x33, 0xC0, 0x40,
                0xEB, 0x43, 0x8D, 0x45, 0x0C, 0x50, 0x68, 0x28, 0x13, 0x40, 0x00, 0x68, 0x02, 0x00,
                0x00, 0x80, 0xFF, 0x15, 0x08, 0x10, 0x40, 0x00, 0x85, 0xC0, 0x75, 0x29, 0x8D, 0x45,
                0xFC, 0x50, 0xFF, 0x75, 0x08, 0x8D, 0x45, 0xF8, 0x50, 0x57, 0x57, 0xFF, 0x75, 0x0C,
                0x89, 0x75, 0xFC, 0xFF, 0x15, 0x00, 0x10, 0x40, 0x00, 0x85, 0xC0, 0x75, 0x03, 0x33,
                0xFF, 0x47, 0xFF, 0x75, 0x0C, 0xFF, 0x15, 0x24, 0x10, 0x40, 0x00, 0x8B, 0xC7, 0x5F,
                0x5E, 0xC9, 0xC2, 0x08, 0x00,
            ];

            let mut project = Project::new::<TransientStorageProvider>(&Shellcode::new(
                "x86:LE:64",
                0x4EB14u64,
                &shellcode,
            )?)?;
            let mut cfr = FunctionRecovery::new();

            cfr.add_candidate(0x4EB14u64);
            cfr.analyse(&mut project)?;

            Ok(())
        })
    }
}
