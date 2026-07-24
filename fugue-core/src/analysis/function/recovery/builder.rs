use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::mem;
use std::ops::ControlFlow;

use super::structuring::CodeBlockStructurer;
use super::{FunctionRecoveryConfig, FunctionRecoveryError, InsnResolver};
use crate::analysis::control::{CancellationToken, Cancelled};
use crate::analysis::{AnalysisGroup, AnalysisPass};
use crate::arch::Arch;
use crate::ir::{
    Address, AddressWithContext, FlowKind, FlowTarget, IncompleteCodeBlockId, IncompleteFunction,
    InsnEntry, RawAddressRangeSet,
};
use crate::lifter::ContextSet;
use crate::project::ProjectTransaction;
use crate::storage::SegmentStorage;
use crate::storage::segments::SegmentMappingCache;

pub struct FunctionRecoveryState {
    cancellation: CancellationToken,
    config: FunctionRecoveryConfig,
    context: FunctionBuilderContext,
    function: IncompleteFunction,
}

struct FunctionBuilderAnalysis<'a, 'p> {
    transaction: &'a mut ProjectTransaction<'p>,
    resolver: &'a mut InsnResolver,
    candidate: AddressWithContext,
    token: &'a CancellationToken,
    config: &'a FunctionRecoveryConfig,
    initialisation_passes: &'a mut AnalysisGroup<FunctionBuilderContext>,
    post_structuring_passes: &'a mut AnalysisGroup<FunctionRecoveryState>,
}

#[derive(Default)]
pub struct FunctionBuilderContext {
    entry: Address,
    avoids: RawAddressRangeSet,
    candidates: VecDeque<AddressWithContext>,
    contexts: BTreeMap<Address, ContextSet>,
    local_targets: BTreeSet<FlowTarget>,
    global_targets: BTreeSet<AddressWithContext>,
    structurer: CodeBlockStructurer,
}

pub struct FunctionBuilder {
    config: FunctionRecoveryConfig,
    context: FunctionBuilderContext,
    initialisation_passes: AnalysisGroup<FunctionBuilderContext>,
    post_structuring_passes: AnalysisGroup<FunctionRecoveryState>,
}

impl FunctionBuilder {
    pub fn new(config: FunctionRecoveryConfig) -> Self {
        FunctionBuilder {
            config,
            context: FunctionBuilderContext::new(),
            initialisation_passes: AnalysisGroup::new(),
            post_structuring_passes: AnalysisGroup::new(),
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

    pub fn post_structuring_passes(&self) -> &AnalysisGroup<FunctionRecoveryState> {
        &self.post_structuring_passes
    }

    pub fn post_structuring_passes_mut(&mut self) -> &mut AnalysisGroup<FunctionRecoveryState> {
        &mut self.post_structuring_passes
    }

    pub fn context(&self) -> &FunctionBuilderContext {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut FunctionBuilderContext {
        &mut self.context
    }

    pub fn analyse(
        &mut self,
        transaction: &mut ProjectTransaction<'_>,
        resolver: &mut InsnResolver,
        candidate: impl Into<AddressWithContext>,
        token: &CancellationToken,
    ) -> Result<ControlFlow<Cancelled, IncompleteFunction>, FunctionRecoveryError> {
        self.context.analyse(FunctionBuilderAnalysis {
            transaction,
            resolver,
            candidate: candidate.into(),
            token,
            config: &self.config,
            initialisation_passes: &mut self.initialisation_passes,
            post_structuring_passes: &mut self.post_structuring_passes,
        })
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

    pub fn add_initialisation_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<FunctionBuilderContext> + 'static,
    ) {
        self.initialisation_passes.add_pass(name, pass);
    }

    pub fn add_post_structuring_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<FunctionRecoveryState> + 'static,
    ) {
        self.post_structuring_passes.add_pass(name, pass);
    }
}

impl FunctionRecoveryState {
    pub fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    pub fn config(&self) -> &FunctionRecoveryConfig {
        &self.config
    }

    pub fn context(&self) -> &FunctionBuilderContext {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut FunctionBuilderContext {
        &mut self.context
    }

    pub fn function(&self) -> &IncompleteFunction {
        &self.function
    }

    pub fn function_mut(&mut self) -> &mut IncompleteFunction {
        &mut self.function
    }

    pub fn structure_blocks(&mut self) -> Result<(), FunctionRecoveryError> {
        self.context
            .structure_blocks(&mut self.function, &self.config)
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
        self.add_local_target_with_context(from, AddressWithContext::from(to.into()), kind);
    }

    pub fn add_local_target_with_context(
        &mut self,
        from: impl Into<Address>,
        to: AddressWithContext,
        kind: FlowKind,
    ) {
        let from = from.into();
        let address = to.address();
        if self
            .local_targets
            .insert(FlowTarget::new(from, address, kind))
        {
            self.candidates.push_back(to);
        }
    }

    pub fn clear(&mut self) {
        self.entry = Address::default();
        self.candidates.clear();
        self.contexts.clear();
        self.local_targets.clear();
        self.global_targets.clear();
        self.structurer.clear();
    }

    fn resolve_insns(
        &mut self,
        arch: &Arch,
        segments: &SegmentStorage,
        resolver: &mut InsnResolver,
        f: &mut IncompleteFunction,
        token: &CancellationToken,
        use_mapping_hints: bool,
    ) -> Result<(), Cancelled> {
        let mut mapping_cache = SegmentMappingCache::new(segments);
        mapping_cache
            .view_containing(self.entry())
            .expect("function entry is valid");

        'outer: while let Some(candidate) = self.candidates.pop_front() {
            token.check()?;

            let (block, mut context) = candidate.into_parts();

            // This ensures correct alignment, to address is correctly wrapped with respect to
            // the address space, and also extracts context updates indicated by the address,
            // e.g., if we are in Thumb context or not for ARM.
            let block_space = block.space();
            let Some((block, ncontext)) = arch.canonicalise_address_with(block, resolver.context())
            else {
                tracing::trace!("skipping {block}: not a viable block start address");
                continue 'outer;
            };
            let block = Address::new(block_space, block);

            let Some(view) = mapping_cache.view_containing(block).cloned() else {
                tracing::trace!("skipping {block}: not mapped in any segment");
                continue 'outer;
            };

            if use_mapping_hints && let Some(hint) = view.mapping_hint_at(block) {
                if hint.is_data() {
                    tracing::trace!("skipping {block}: marked as data in segment mapping hints");
                    continue 'outer;
                }
                if let Some(hinted) = hint.context() {
                    context.merge(hinted);
                }
            }

            if self.avoids.contains(block) {
                tracing::trace!("skipping {block}: in avoidance set");
                continue 'outer;
            }

            tracing::trace!("resolving new block {block}");

            // Merge the context updates with the specified context taking precedence.
            context.merge(&ncontext);

            // Applies the context updates to the lifter context.
            context.apply(block, resolver.context_mut());

            // Save the context so we can associate it with a block later.
            self.contexts.entry(block).or_insert(context.clone());

            let mut offset = 0usize;

            '_inner: loop {
                token.check()?;

                let address = block + offset;

                if use_mapping_hints
                    && offset != 0
                    && let Some(hint) = view.mapping_hint_at(address)
                {
                    if hint.is_data() {
                        tracing::trace!(
                            "stopping at {address}: marked as data in segment mapping hints"
                        );
                        continue 'outer;
                    }

                    let mut boundary_context = context.clone();
                    if let Some(hinted) = hint.context() {
                        boundary_context.merge(hinted);
                    }
                    self.candidates
                        .push_front(AddressWithContext::new(address, boundary_context));
                    continue 'outer;
                }

                tracing::trace!("resolving instruction at {address}");

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

                let Ok(bytes) = mapping_cache.contiguous_bytes_from(address) else {
                    tracing::trace!("skipping {address}: not mapped in segment");
                    continue 'outer;
                };

                if self.avoids.contains(address) {
                    tracing::trace!("skipping {address}: in avoidance set");
                    continue 'outer;
                }

                let size = bytes.len();

                tracing::trace!("resolving {address} ({size} bytes available)");

                match resolver.resolve(address, bytes) {
                    Ok(insn) => {
                        let insn = entry.insert(insn);
                        let insn = f.insn(insn).expect("inserted instruction must exist");

                        // Explicit control-flow
                        if insn.is_flow() {
                            // We're done with this block; we schedule the next bit of work

                            // These targets are what we can statically compute by scanning the
                            // instruction's PCode branch operations--we will miss things like PC
                            // relative jumps; these constructs will be handled in post-structuring
                            // passes.
                            for (target, kind, addr) in insn.iter_targets() {
                                let addr_space = addr.space();
                                let Some((addr, context)) = arch.canonicalise_address(addr) else {
                                    tracing::trace!(
                                        "skipping target {target} of instruction at {address}: \
                                         not a viable target address"
                                    );
                                    continue;
                                };
                                let addr = Address::new(addr_space, addr);

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
                        tracing::debug!("skipping {address}; instruction resolution failed: {e}");
                        self.contexts.remove(&address);
                        self.avoids.insert(address);
                        continue 'outer;
                    }
                }
            }
        }

        Ok(())
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

    pub fn block_starts(&self) -> &BTreeMap<Address, IncompleteCodeBlockId> {
        self.structurer.block_starts()
    }

    pub fn block_ends(&self) -> &BTreeMap<Address, IncompleteCodeBlockId> {
        self.structurer.block_ends()
    }

    fn structure_blocks(
        &mut self,
        function: &mut IncompleteFunction,
        config: &FunctionRecoveryConfig,
    ) -> Result<(), FunctionRecoveryError> {
        self.structurer
            .structure(function, config, &self.contexts, &self.local_targets)
    }

    fn analyse(
        &mut self,
        analysis: FunctionBuilderAnalysis<'_, '_>,
    ) -> Result<ControlFlow<Cancelled, IncompleteFunction>, FunctionRecoveryError> {
        // We have three main stages:
        //
        // 1. We first initialise the function builder with the entry point and the context
        //    of the entry block.
        // 2. We enter the main loop where we resolve instructions block by block, and add newly
        //    discovered blocks (and edges) to the candidates queue.
        // 3. We structure the blocks into a basic function-like structure; we use this
        //    structure as input to resolve jump tables, indirect jumps, etc. this part of
        //    the analysis provides new candidates and new edges.
        //
        // Stage 1 and 3 are hookable; we may register analysis passes to be run prior to the
        // main loop and after each block discovery pass has completed within the main loop.
        //
        let mut candidate = analysis.candidate;

        tracing::debug!("exploring from {candidate}");

        self.clear();
        self.entry = candidate.address();

        if analysis.config.use_segment_mapping_hints() {
            // NOTE: this expect is safe because the entry address must be valid to reach this
            // point under normal usage.
            let view = analysis
                .transaction
                .project()
                .segments()
                .view_containing(self.entry)
                .expect("valid entry");

            if let Some(hint) = view.mapping_hint_at(self.entry) {
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
        analysis
            .transaction
            .analyse_with(analysis.initialisation_passes, self)
            .map_err(FunctionRecoveryError::InitialisationPass)?;

        let mut incomplete = IncompleteFunction::new(self.entry);

        loop {
            if let Err(cancelled) = analysis.token.check() {
                return Ok(ControlFlow::Break(cancelled));
            }

            let arch = analysis.transaction.project().arch();
            let segments = analysis.transaction.project().segments();

            if let Err(cancelled) = self.resolve_insns(
                arch,
                segments,
                analysis.resolver,
                &mut incomplete,
                analysis.token,
                analysis.config.use_segment_mapping_hints(),
            ) {
                return Ok(ControlFlow::Break(cancelled));
            }

            if !incomplete.has_insns() {
                tracing::debug!("no instructions resolved; invalid function");
                return Err(FunctionRecoveryError::InvalidFunction);
            }

            self.structure_blocks(&mut incomplete, analysis.config)?;

            let num_local_targets = self.local_targets.len();

            let mut state = FunctionRecoveryState {
                cancellation: analysis.token.clone(),
                config: *analysis.config,
                context: mem::take(self),
                function: mem::take(&mut incomplete),
            };

            // Run post-structuring passes
            let result = analysis
                .transaction
                .analyse_with(analysis.post_structuring_passes, &mut state);

            *self = state.context;
            incomplete = state.function;

            result.map_err(FunctionRecoveryError::PostStructuringPass)?;

            if let Err(cancelled) = analysis.token.check() {
                return Ok(ControlFlow::Break(cancelled));
            }

            if self.candidates.is_empty() && self.local_targets.len() == num_local_targets {
                tracing::debug!("no new candidates or local targets; stopping");
                break;
            }
        }

        Ok(ControlFlow::Continue(incomplete))
    }
}
