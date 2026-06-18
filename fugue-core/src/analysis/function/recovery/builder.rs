use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::mem;

use super::{
    FunctionRecoveryConfig, FunctionRecoveryError, InsnEntry, PartialFunction, Translator,
};
use crate::analysis::{AnalysisGroup, AnalysisPass};
use crate::arch::Arch;
use crate::ir::{Address, AddressWithContext, FlowKind, FlowTarget, RawAddressRangeSet};
use crate::lifter::ContextSet;
use crate::project::Project;
use crate::storage::SegmentStorage;

pub struct PartialFunctionWithContext {
    pub config: FunctionRecoveryConfig,
    pub context: FunctionBuilderContext,
    pub function: PartialFunction,
}

pub(crate) struct CodeBlockStructuringContext<'a> {
    pub(crate) block_starts: &'a mut BTreeMap<Address, usize>,
    pub(crate) block_ends: &'a mut BTreeMap<Address, usize>,
    pub(crate) cut_points: &'a mut Vec<usize>,
    pub(crate) contexts: &'a BTreeMap<Address, ContextSet>,
}

#[derive(Default)]
pub struct FunctionBuilderContext {
    entry: Address,
    avoids: RawAddressRangeSet,
    candidates: VecDeque<AddressWithContext>,
    contexts: BTreeMap<Address, ContextSet>,
    local_targets: BTreeSet<FlowTarget>,
    global_targets: BTreeSet<AddressWithContext>,
    // These are used to structure the blocks after lifting; we keep them here
    // to avoid having to reallocate on each function analysis. They refer to
    // the partial function being constructed.
    block_starts: BTreeMap<Address, usize>,
    block_ends: BTreeMap<Address, usize>,
    cut_points: Vec<usize>,
}

pub struct FunctionBuilder {
    // The configuration for the function recovery process.
    config: FunctionRecoveryConfig,
    // The context of the function being built.
    context: FunctionBuilderContext,
    // These passes run once per function prior to the main lifting loop.
    initialisation_passes: AnalysisGroup<FunctionBuilderContext>,
    // These passes run each iteration of the main lifting loop after all candidates within the
    // pass have been lifted and the function's control-flow has been structured based on the
    // identified blocks and flows.
    post_lifting_passes: AnalysisGroup<PartialFunctionWithContext>,
}

impl FunctionBuilder {
    pub fn new(config: FunctionRecoveryConfig) -> Self {
        FunctionBuilder {
            config,
            context: FunctionBuilderContext::new(),
            initialisation_passes: AnalysisGroup::new(),
            post_lifting_passes: AnalysisGroup::new(),
        }
    }

    pub fn config(&self) -> &FunctionRecoveryConfig {
        &self.config
    }

    pub fn initialisation_passes(&self) -> &AnalysisGroup<FunctionBuilderContext> {
        &self.initialisation_passes
    }

    pub fn initialisation_passes_mut(&mut self) -> &mut AnalysisGroup<FunctionBuilderContext> {
        &mut self.initialisation_passes
    }

    pub fn post_lifting_passes(&self) -> &AnalysisGroup<PartialFunctionWithContext> {
        &self.post_lifting_passes
    }

    pub fn post_lifting_passes_mut(&mut self) -> &mut AnalysisGroup<PartialFunctionWithContext> {
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
        pass: impl AnalysisPass<FunctionBuilderContext> + 'static,
    ) {
        self.initialisation_passes.add_pass(name, pass);
    }

    pub fn add_post_lifting_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<PartialFunctionWithContext> + 'static,
    ) {
        self.post_lifting_passes.add_pass(name, pass);
    }

    pub fn analyse(
        &mut self,
        project: &mut Project,
        translator: &mut Translator,
        candidate: impl Into<AddressWithContext>,
    ) -> Result<PartialFunction, FunctionRecoveryError> {
        self.context.analyse(
            project,
            translator,
            candidate,
            &self.config,
            &mut self.initialisation_passes,
            &mut self.post_lifting_passes,
        )
    }

    pub fn avoids(&self) -> &RawAddressRangeSet {
        &self.context.avoids
    }

    pub fn avoids_mut(&mut self) -> &mut RawAddressRangeSet {
        &mut self.context.avoids
    }

    pub fn local_targets(&self) -> &BTreeSet<FlowTarget> {
        &self.context.local_targets
    }

    pub fn global_targets(&self) -> &BTreeSet<AddressWithContext> {
        &self.context.global_targets
    }
}

impl<'a> CodeBlockStructuringContext<'a> {
    pub fn mark_cut_point(&mut self, insn_idx: usize) {
        self.cut_points.push(insn_idx);
    }

    pub fn is_flow_target(&self, address: Address) -> bool {
        self.contexts.contains_key(&address)
    }

    pub fn clear(&mut self) {
        self.block_starts.clear();
        self.block_ends.clear();
        self.cut_points.clear();
    }
}

impl PartialFunctionWithContext {
    pub fn config(&self) -> &FunctionRecoveryConfig {
        &self.config
    }

    pub fn context(&self) -> &FunctionBuilderContext {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut FunctionBuilderContext {
        &mut self.context
    }

    pub fn function(&self) -> &PartialFunction {
        &self.function
    }

    pub fn function_mut(&mut self) -> &mut PartialFunction {
        &mut self.function
    }

    pub fn structure_blocks(&mut self) -> Result<(), FunctionRecoveryError> {
        self.function
            .structure_blocks(&self.config, &mut self.context)
    }
}

impl FunctionBuilderContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entry(&self) -> Address {
        self.entry
    }

    pub fn candidates(&self) -> &VecDeque<AddressWithContext> {
        &self.candidates
    }

    pub fn add_candidate(&mut self, address: impl Into<Address>) {
        self.add_candidate_with_context(address, ContextSet::new());
    }

    pub fn add_candidate_with_context(&mut self, address: impl Into<Address>, context: ContextSet) {
        self.candidates
            .push_back(AddressWithContext::new(address, context));
    }

    pub fn add_candidates(&mut self, addresses: impl IntoIterator<Item = impl Into<Address>>) {
        self.add_candidates_with_context(addresses.into_iter().map(|addr| addr.into()));
    }

    pub fn add_candidates_with_context(
        &mut self,
        candidates: impl IntoIterator<Item = impl Into<AddressWithContext>>,
    ) {
        self.candidates
            .extend(candidates.into_iter().map(|candidate| candidate.into()));
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
        self.entry = Address::default();
        self.candidates.clear();
        self.contexts.clear();
        self.local_targets.clear();
        self.global_targets.clear();
    }

    fn lift_insns(
        &mut self,
        arch: &Arch,
        segments: &SegmentStorage,
        translator: &mut Translator,
        f: &mut PartialFunction,
    ) {
        // NOTE: as opposed to reading bytes from the storage, for all existing backends we can
        // create a "cheap" view over the containing segment and use that to avoid lookups for each
        // address read from.

        // We assume that most (all?) of a function's blocks will be in the same segment.
        let mut view = segments
            .view_at(self.entry())
            .expect("function entry is valid");

        // This is the stage where we build blocks by collecting instructions and marking them.
        'outer: while let Some(candidate) = self.candidates.pop_front() {
            let (block, mut context) = candidate.into_parts();

            // This ensures correct alignment, to address is correctly wrapped with respect to
            // the address space, and also extracts context updates indicated by the address,
            // e.g., if we are in Thumb context or not for ARM.
            let Some((block, ncontext)) =
                arch.canonicalise_address_with(block.into(), translator.context())
            else {
                tracing::trace!("skipping {block}: not a viable block start address");
                continue 'outer;
            };

            if !view.contains(block) {
                if let Ok(nview) = segments.view_at(block) {
                    tracing::debug!("switching segment for {block} to segment {}", nview.name());
                    view = nview;
                } else {
                    tracing::trace!("skipping {block}: not mapped in any segment");
                    continue 'outer;
                }
            }

            if self.avoids.contains(block) {
                tracing::trace!("skipping {block}: in avoidance set");
                continue 'outer;
            }

            tracing::trace!("lifting new block {block}");

            // Merge the context updates with the specified context taking precedence.
            context.merge(&ncontext);

            // Applies the context updates to the lifter context.
            context.apply(block, translator.context_mut());

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
                        self.contexts.entry(address).or_default();
                        continue 'outer;
                    }
                };

                let Some(bytes) = view.bytes_from(address) else {
                    // NOTE: we should not reach this point if we're following a local flow, since
                    // we check segment membership when adding local targets.
                    tracing::trace!("skipping {address}: not mapped in segment");
                    continue 'outer;
                };

                if self.avoids.contains(address) {
                    tracing::trace!("skipping {address}: in avoidance set");
                    continue 'outer;
                }

                let size = bytes.len();

                tracing::trace!("lifting {address} ({size} bytes available)");

                match translator.disassemble(address, bytes) {
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
                                let Some((addr, context)) = arch.canonicalise_address(addr) else {
                                    tracing::trace!(
                                        "skipping target {target} of instruction at {address}: \
                                         not a viable target address"
                                    );
                                    continue;
                                };

                                if kind.is_local() && view.contains(addr) {
                                    let Some(target) =
                                        FlowTarget::from_insn_target(insn, target, addr)
                                    else {
                                        continue;
                                    };

                                    if self.local_targets.insert(target) {
                                        self.candidates
                                            .push_back(AddressWithContext::new(addr, context));
                                    }
                                } else if !self.avoids.contains(addr) {
                                    self.global_targets
                                        .insert(AddressWithContext::new(addr, context));
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
                        self.avoids.insert(address);
                        continue 'outer;
                    }
                }
            }
        }
    }

    pub fn contexts(&self) -> &BTreeMap<Address, ContextSet> {
        &self.contexts
    }

    pub fn is_flow_target(&self, address: Address) -> bool {
        self.contexts.contains_key(&address)
    }

    pub fn local_targets(&self) -> &BTreeSet<FlowTarget> {
        &self.local_targets
    }

    pub fn global_targets(&self) -> &BTreeSet<AddressWithContext> {
        &self.global_targets
    }

    pub fn block_starts(&self) -> &BTreeMap<Address, usize> {
        &self.block_starts
    }

    pub fn block_ends(&self) -> &BTreeMap<Address, usize> {
        &self.block_ends
    }

    pub fn cut_points(&self) -> &Vec<usize> {
        &self.cut_points
    }

    pub fn mark_cut_point(&mut self, insn_idx: usize) {
        self.cut_points.push(insn_idx);
    }

    pub(crate) fn structuring_context(&mut self) -> CodeBlockStructuringContext {
        CodeBlockStructuringContext {
            block_starts: &mut self.block_starts,
            block_ends: &mut self.block_ends,
            cut_points: &mut self.cut_points,
            contexts: &self.contexts,
        }
    }

    pub fn analyse(
        &mut self,
        project: &mut Project,
        translator: &mut Translator,
        candidate: impl Into<AddressWithContext>,
        config: &FunctionRecoveryConfig,
        initialisation_passes: &mut AnalysisGroup<FunctionBuilderContext>,
        post_lifting_passes: &mut AnalysisGroup<PartialFunctionWithContext>,
    ) -> Result<PartialFunction, FunctionRecoveryError> {
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

        let mut candidate = candidate.into();

        tracing::debug!("exploring from {candidate}");

        self.clear();
        self.entry = candidate.address().into();

        if config.use_segment_mapping_hints() {
            // NOTE: this expect is safe because the entry address must be valid to reach this
            // point under normal usage.
            let view = project.segments().view_at(self.entry).expect("valid entry");

            if let Some(hint) = view.mapping_hints().get(&self.entry) {
                if hint.is_data() {
                    tracing::debug!(
                        "entry {candidate} is marked as data in segment mapping hints; skipping"
                    );
                    return Err(FunctionRecoveryError::InvalidFunction);
                }

                if let Some(ctxt) = hint.context() {
                    candidate.merge_context(ctxt);
                }
            }
        }

        self.candidates.push_back(candidate);

        // Run the initialisation passes
        initialisation_passes
            .analyse_with(project, self)
            .map_err(FunctionRecoveryError::InitialisationPass)?;

        let mut partial = PartialFunction::new(self.entry);

        loop {
            let arch = project.arch();
            let segments = project.segments();

            self.lift_insns(arch, segments, translator, &mut partial);

            if !partial.has_insns() {
                tracing::debug!("no instructions lifted; invalid function");
                return Err(FunctionRecoveryError::InvalidFunction);
            }

            partial.structure_blocks(config, self)?;

            let num_local_targets = self.local_targets.len();

            let mut function_with_context = PartialFunctionWithContext {
                config: *config,
                context: mem::take(self),
                function: mem::take(&mut partial),
            };

            // Run post-lifting passes
            let result = post_lifting_passes.analyse_with(project, &mut function_with_context);

            *self = function_with_context.context;
            partial = function_with_context.function;

            result.map_err(FunctionRecoveryError::PostLiftingPass)?;

            if self.candidates.is_empty() && self.local_targets.len() == num_local_targets {
                // No new candidates were added, and no new local targets were discovered.
                // We can stop here.
                tracing::debug!("no new candidates or local targets; stopping");
                break;
            }
        }

        Ok(partial)
    }
}
