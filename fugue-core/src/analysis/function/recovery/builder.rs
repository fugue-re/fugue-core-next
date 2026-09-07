use std::collections::VecDeque;
use std::mem;

use indexmap::{IndexMap, IndexSet};
use itertools::Either;
use rustc_hash::FxBuildHasher;
use smallvec::SmallVec;

use crate::analysis::function::recovery::analysis::FunctionRecoveryContext;
use crate::analysis::function::recovery::structuring::FunctionStructurer;
use crate::analysis::function::recovery::{FunctionRecoveryConfig, FunctionRecoveryError};
use crate::analysis::{AnalysisGroup, AnalysisPass};
use crate::arch::Arch;
use crate::engine::{AnalysisContext, ProjectView};
use crate::ir::function::FunctionInsnIndex;
use crate::ir::{
    Address, AddressRangeSet, AddressWithContext, FlowKind, FlowTarget, IncompleteCodeBlockId,
    IncompleteFunction, InsnEntry, ProblemKind,
};
use crate::lifter::{ContextSet, InsnResolver};
use crate::storage::{SegmentMappingCache, SegmentStorage};
use crate::types::Confidence;

pub struct StructuredFunctionContext {
    config: FunctionRecoveryConfig,
    context: FunctionBuilderContext,
    function: IncompleteFunction,
    resolver: Option<InsnResolver>,
}

struct FunctionCandidateAnalysis<'a, 'b, 'p> {
    analysis: &'a mut AnalysisContext<'b, 'p>,
    context: &'a FunctionRecoveryContext,
    resolver_slot: &'a mut Option<InsnResolver>,
    candidate: AddressWithContext,
    config: &'a FunctionRecoveryConfig,
    pre_resolution_passes: &'a mut AnalysisGroup<FunctionBuilderContext>,
    post_structuring_passes: &'a mut AnalysisGroup<StructuredFunctionContext>,
}

struct InsnResolution<'a, 'p> {
    avoidance_baseline: Option<&'a AddressRangeSet>,
    config: &'a FunctionRecoveryConfig,
    context: &'a FunctionRecoveryContext,
    project: &'a ProjectView<'p>,
}

pub(crate) struct FunctionCandidateOutcome {
    address: Address,
    avoids: AddressRangeSet,
    confidence: Confidence,
    problems: SmallVec<[(Address, ProblemKind); 4]>,
    result: Option<Result<IncompleteFunction, FunctionRecoveryError>>,
    targets: SmallVec<[AddressWithContext; 4]>,
}

impl FunctionCandidateOutcome {
    fn from_result(
        address: Address,
        confidence: Confidence,
        problems: SmallVec<[(Address, ProblemKind); 4]>,
        result: Result<IncompleteFunction, FunctionRecoveryError>,
        targets: SmallVec<[AddressWithContext; 4]>,
    ) -> Self {
        Self {
            address,
            avoids: AddressRangeSet::new(),
            confidence,
            problems,
            result: Some(result),
            targets,
        }
    }

    pub(crate) fn address(&self) -> Address {
        self.address
    }

    pub(crate) fn confidence(&self) -> Confidence {
        self.confidence
    }

    pub(crate) fn avoids(&self) -> &AddressRangeSet {
        &self.avoids
    }

    pub(crate) fn drain_problems(&mut self) -> impl Iterator<Item = (Address, ProblemKind)> + '_ {
        self.problems.drain(..)
    }

    pub(crate) fn drain_targets(&mut self) -> impl Iterator<Item = AddressWithContext> + '_ {
        self.targets.drain(..)
    }

    pub(crate) fn take_result(&mut self) -> Result<IncompleteFunction, FunctionRecoveryError> {
        self.result
            .take()
            .expect("candidate result must only be taken once")
    }
}

pub(crate) struct FunctionCandidateState<'p> {
    address: Address,
    candidate: AddressWithContext,
    confidence: Confidence,
    context: FunctionBuilderContext,
    function: IncompleteFunction,
    phase: FunctionCandidatePhase,
    view: ProjectView<'p>,
}

enum FunctionCandidatePhase {
    Resolving,
    Structured(usize),
    Finished,
    Failed(FunctionRecoveryError),
}

enum BlockContexts {
    Addresses(IndexSet<Address, FxBuildHasher>),
    Contexts(IndexMap<Address, ContextSet, FxBuildHasher>),
}

impl Default for BlockContexts {
    fn default() -> Self {
        Self::Addresses(IndexSet::default())
    }
}

impl BlockContexts {
    fn contains(&self, address: &Address) -> bool {
        match self {
            Self::Addresses(addresses) => addresses.contains(address),
            Self::Contexts(contexts) => contexts.contains_key(address),
        }
    }

    fn context(&self, address: &Address) -> Option<&ContextSet> {
        match self {
            Self::Addresses(_) => None,
            Self::Contexts(contexts) => contexts.get(address),
        }
    }

    fn get<'a>(&'a self, address: &Address, empty: &'a ContextSet) -> Option<&'a ContextSet> {
        match self {
            Self::Addresses(addresses) => addresses.contains(address).then_some(empty),
            Self::Contexts(contexts) => contexts.get(address),
        }
    }

    fn addresses(&self) -> impl ExactSizeIterator<Item = &Address> {
        match self {
            Self::Addresses(addresses) => Either::Left(addresses.iter()),
            Self::Contexts(contexts) => Either::Right(contexts.keys()),
        }
    }

    fn iter<'a>(
        &'a self,
        empty: &'a ContextSet,
    ) -> impl ExactSizeIterator<Item = (Address, &'a ContextSet)> + 'a {
        match self {
            Self::Addresses(addresses) => {
                Either::Left(addresses.iter().map(move |address| (*address, empty)))
            }
            Self::Contexts(contexts) => Either::Right(
                contexts
                    .iter()
                    .map(|(address, context)| (*address, context)),
            ),
        }
    }

    fn insert(&mut self, address: Address, context: &ContextSet) {
        match self {
            Self::Addresses(addresses) if context.is_empty() => {
                addresses.insert(address);
            }
            Self::Addresses(addresses) => {
                let addresses = mem::take(addresses);
                let mut contexts =
                    IndexMap::with_capacity_and_hasher(addresses.len() + 1, FxBuildHasher);
                contexts.extend(
                    addresses
                        .into_iter()
                        .map(|address| (address, ContextSet::new())),
                );
                contexts.insert(address, context.clone());
                *self = Self::Contexts(contexts);
            }
            Self::Contexts(contexts) => {
                contexts.entry(address).or_insert_with(|| context.clone());
            }
        }
    }

    fn remove(&mut self, address: &Address) {
        match self {
            Self::Addresses(addresses) => {
                addresses.swap_remove(address);
            }
            Self::Contexts(contexts) => {
                contexts.swap_remove(address);
            }
        }
    }

    fn clear(&mut self) {
        match self {
            Self::Addresses(addresses) => addresses.clear(),
            Self::Contexts(contexts) => contexts.clear(),
        }
    }
}

#[derive(Default)]
pub struct FunctionBuilderContext {
    entry: Address,
    avoids: AddressRangeSet,
    candidates: VecDeque<AddressWithContext>,
    block_contexts: BlockContexts,
    empty_context: ContextSet,
    local_targets: IndexSet<FlowTarget, FxBuildHasher>,
    global_targets: IndexSet<AddressWithContext, FxBuildHasher>,
    insn_index: FunctionInsnIndex,
    mapping_cache: SegmentMappingCache,
    structurer: FunctionStructurer,
    problems: SmallVec<[(Address, ProblemKind); 4]>,
}

pub(crate) struct FunctionBuilder {
    config: FunctionRecoveryConfig,
    context: FunctionBuilderContext,
    pre_resolution_passes: AnalysisGroup<FunctionBuilderContext>,
    post_structuring_passes: AnalysisGroup<StructuredFunctionContext>,
}

impl FunctionBuilder {
    pub fn new(config: FunctionRecoveryConfig) -> Self {
        FunctionBuilder {
            config,
            context: FunctionBuilderContext::new(),
            pre_resolution_passes: AnalysisGroup::new(),
            post_structuring_passes: AnalysisGroup::new(),
        }
    }

    pub fn config(&self) -> &FunctionRecoveryConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut FunctionRecoveryConfig {
        &mut self.config
    }

    pub(crate) fn pre_resolution_passes(&self) -> &AnalysisGroup<FunctionBuilderContext> {
        &self.pre_resolution_passes
    }

    pub(crate) fn pre_resolution_passes_mut(
        &mut self,
    ) -> &mut AnalysisGroup<FunctionBuilderContext> {
        &mut self.pre_resolution_passes
    }

    pub(crate) fn post_structuring_passes(&self) -> &AnalysisGroup<StructuredFunctionContext> {
        &self.post_structuring_passes
    }

    pub(crate) fn post_structuring_passes_mut(
        &mut self,
    ) -> &mut AnalysisGroup<StructuredFunctionContext> {
        &mut self.post_structuring_passes
    }

    pub fn context_mut(&mut self) -> &mut FunctionBuilderContext {
        &mut self.context
    }

    pub fn avoids(&self) -> &AddressRangeSet {
        &self.context.avoids
    }

    pub fn avoids_mut(&mut self) -> &mut AddressRangeSet {
        &mut self.context.avoids
    }

    fn analyse(
        &mut self,
        analysis: &mut AnalysisContext<'_, '_>,
        context: &FunctionRecoveryContext,
        resolver_slot: &mut Option<InsnResolver>,
        candidate: impl Into<AddressWithContext>,
    ) -> Result<IncompleteFunction, FunctionRecoveryError> {
        self.context.analyse(FunctionCandidateAnalysis {
            analysis,
            context,
            resolver_slot,
            candidate: candidate.into(),
            config: &self.config,
            pre_resolution_passes: &mut self.pre_resolution_passes,
            post_structuring_passes: &mut self.post_structuring_passes,
        })
    }

    pub(super) fn analyse_candidate(
        &mut self,
        analysis: &mut AnalysisContext<'_, '_>,
        context: &FunctionRecoveryContext,
        resolver_slot: &mut Option<InsnResolver>,
        candidate: AddressWithContext,
    ) -> FunctionCandidateOutcome {
        let address = candidate.address();
        let confidence = candidate.confidence();
        let result = self.analyse(analysis, context, resolver_slot, candidate);
        FunctionCandidateOutcome::from_result(
            address,
            confidence,
            self.context.problems.drain(..).collect(),
            result,
            self.context.global_targets.drain(..).collect(),
        )
    }

    pub(crate) fn add_pre_resolution_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<FunctionBuilderContext> + 'static,
    ) {
        self.pre_resolution_passes.add_pass(name, pass);
    }

    pub fn add_post_structuring_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<StructuredFunctionContext> + 'static,
    ) {
        self.post_structuring_passes.add_pass(name, pass);
    }
}

impl StructuredFunctionContext {
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

    pub(in crate::analysis) fn function_and_resolver(
        &mut self,
        arch: &Arch,
    ) -> (&IncompleteFunction, &mut InsnResolver) {
        let resolver = self.resolver.get_or_insert_with(|| InsnResolver::new(arch));
        (&self.function, resolver)
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

    pub fn candidates(&self) -> impl ExactSizeIterator<Item = &AddressWithContext> {
        self.candidates.iter()
    }

    pub fn is_flow_target(&self, address: Address) -> bool {
        self.block_contexts.contains(&address)
    }

    pub fn local_targets(&self) -> impl ExactSizeIterator<Item = &FlowTarget> {
        self.local_targets.iter()
    }

    pub fn global_targets(&self) -> impl ExactSizeIterator<Item = &AddressWithContext> {
        self.global_targets.iter()
    }

    pub fn block_starts(&self) -> impl ExactSizeIterator<Item = (Address, IncompleteCodeBlockId)> {
        self.structurer.block_starts()
    }

    pub fn block_ends(&self) -> impl ExactSizeIterator<Item = (Address, IncompleteCodeBlockId)> {
        self.structurer.block_ends()
    }

    pub fn block_start_at(&self, address: Address) -> Option<IncompleteCodeBlockId> {
        self.structurer.block_start_at(address)
    }

    pub fn block_end_at(&self, address: Address) -> Option<IncompleteCodeBlockId> {
        self.structurer.block_end_at(address)
    }

    pub fn context_at(&self, address: Address) -> Option<&ContextSet> {
        self.block_contexts.get(&address, &self.empty_context)
    }

    pub fn contexts(&self) -> impl ExactSizeIterator<Item = (Address, &ContextSet)> {
        self.block_contexts.iter(&self.empty_context)
    }

    pub fn add_candidate(&mut self, candidate: impl Into<AddressWithContext>) {
        let candidate = candidate.into();
        let address = candidate.address();
        let index = self
            .candidates
            .partition_point(|queued| queued.address() <= address);
        self.candidates.insert(index, candidate);
    }

    pub fn add_candidate_with_context(&mut self, address: impl Into<Address>, context: ContextSet) {
        self.add_candidate(AddressWithContext::new(address, context));
    }

    pub fn add_candidates(&mut self, addresses: impl IntoIterator<Item = impl Into<Address>>) {
        for address in addresses {
            self.add_candidate(address.into());
        }
    }

    pub fn add_candidates_with_context(
        &mut self,
        candidates: impl IntoIterator<Item = impl Into<AddressWithContext>>,
    ) {
        for candidate in candidates {
            self.add_candidate(candidate);
        }
    }

    pub fn add_problem(&mut self, address: impl Into<Address>, kind: ProblemKind) {
        self.problems.push((address.into(), kind));
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
            self.add_candidate(to);
        }
    }

    pub fn clear(&mut self) {
        self.entry = Address::default();
        self.candidates.clear();
        self.block_contexts.clear();
        self.local_targets.clear();
        self.global_targets.clear();
        self.structurer.clear();
    }

    pub(crate) fn function_entry_after_padding(
        &mut self,
        segments: &SegmentStorage,
        arch: &Arch,
        resolver: &InsnResolver,
        address: Address,
    ) -> Option<Address> {
        let mut address = address;

        loop {
            let view = self.mapping_cache.view_containing(segments, address)?;
            if !view.properties().is_executable() {
                return None;
            }
            let bytes_view = view.bytes_from(address)?;
            let bytes = bytes_view.as_contiguous()?;
            if bytes.is_empty() {
                return None;
            }
            let (size, properties) =
                arch.classify_contiguous_bytes(address.raw_address(), resolver.context(), bytes);
            if size == 0 || !properties.is_padding() {
                return Some(address);
            }

            address += size;
        }
    }

    fn resolve_insns(
        &mut self,
        resolution: &InsnResolution<'_, '_>,
        resolver: &mut InsnResolver,
        f: &mut IncompleteFunction,
    ) -> Result<(), FunctionRecoveryError> {
        let InsnResolution {
            avoidance_baseline,
            config,
            context,
            project,
        } = resolution;

        let is_avoided = |additions: &AddressRangeSet, address| {
            additions.contains(address)
                || avoidance_baseline.is_some_and(|baseline| baseline.contains(address))
        };

        let function_entries = context.function_entries();
        let non_returning_targets = context.non_returning_targets();

        let arch = project.arch();
        let segments = project.segments();
        let use_mapping_hints = config.segment_mapping_hints();

        self.mapping_cache
            .view_containing(segments, self.entry())
            .expect("function entry is valid");

        'outer: while let Some(candidate) = self.candidates.pop_front() {
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

            if block != self.entry && function_entries.binary_search(&block).is_ok() {
                tracing::trace!("stopping at function boundary {block}");
                continue 'outer;
            }

            let Some(view) = self.mapping_cache.view_containing(segments, block) else {
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

            if is_avoided(&self.avoids, block) {
                tracing::trace!("skipping {block}: in avoidance set");
                continue 'outer;
            }

            tracing::trace!("resolving new block {block}");

            // Merge the context updates with the specified context taking precedence.
            context.merge(&ncontext);

            // Applies the context updates to the lifter context.
            context.apply(block, resolver.context_mut());

            // Save the context so we can associate it with a block later.
            self.block_contexts.insert(block, &context);

            let Some(bytes_view) = view.bytes_from(block) else {
                tracing::trace!("skipping {block}: not mapped in segment");
                continue 'outer;
            };
            let Some(bytes) = bytes_view.as_contiguous().filter(|bytes| !bytes.is_empty()) else {
                tracing::trace!("skipping {block}: no contiguous bytes in segment");
                continue 'outer;
            };
            let remaining = usize::try_from(
                view.range()
                    .remaining_from(block)
                    .expect("mapping view contains the block address"),
            )
            .unwrap_or(usize::MAX);
            let bytes = &bytes[..bytes.len().min(remaining)];
            let mut offset = 0usize;
            let mut mapping_hints = view.mapping_hints_from(block);
            let mut next_mapping_hint = mapping_hints.next();
            let next_function_entry = function_entries
                .get(function_entries.partition_point(|entry| *entry <= block))
                .copied()
                .filter(|entry| entry.space() == block.space());

            while offset < bytes.len() {
                let address = block + offset;

                if next_function_entry.is_some_and(|entry| address >= entry) {
                    tracing::trace!("stopping at function boundary {address}");
                    continue 'outer;
                }

                if use_mapping_hints && offset != 0 {
                    while next_mapping_hint
                        .as_ref()
                        .is_some_and(|(hint_address, _)| *hint_address < address)
                    {
                        next_mapping_hint = mapping_hints.next();
                    }
                    if let Some((hint_address, hint)) = next_mapping_hint
                        && hint_address == address
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
                        self.add_candidate(AddressWithContext::new(address, boundary_context));
                        continue 'outer;
                    }
                }

                // If we've already disassembled this instruction select the next candidate,
                // otherwise get the entry ready for update.
                let entry = match f.insn_entry(address) {
                    InsnEntry::Vacant(entry) => entry,
                    InsnEntry::Occupied(mut entry) => {
                        // If two blocks overlap, then they may share a common suffix to account
                        // for this we mark instructions that appear in multiple blocks as starts
                        // so they're considered cut points when performing block structuring.
                        entry.get_mut().mark_maybe_taken();
                        self.block_contexts.insert(address, &context);
                        continue 'outer;
                    }
                };

                if is_avoided(&self.avoids, address) {
                    tracing::trace!("skipping {address}: in avoidance set");
                    continue 'outer;
                }

                let bytes = &bytes[offset..];

                match resolver.resolve(address, bytes) {
                    Ok(resolved) => {
                        let insn = resolved.as_ref();
                        let indirect = (insn.is_call() && insn.is_indirect())
                            .then(|| {
                                resolved.resolve_indirect_target(|address, bytes| {
                                    self.mapping_cache
                                        .read_bytes_exact(segments, address, bytes)
                                        .is_ok()
                                })
                            })
                            .flatten();
                        let insn_id = entry.insert(resolved.into_insn());
                        let num_insns = f.insns().len();
                        let max_insns = config.max_function_insns();
                        if num_insns > max_insns {
                            return Err(FunctionRecoveryError::invalid_function_insn_count(
                                self.entry, num_insns, max_insns,
                            ));
                        }
                        if let Some(target) = indirect {
                            f.insn_mut(insn_id)
                                .expect("inserted instruction must exist")
                                .set_call_target(target);
                        }

                        let insn = f.insn(insn_id).expect("inserted instruction must exist");

                        let orphaned_fall_through = if config.non_returning_analysis()
                            && insn.call_target().is_some_and(|target| {
                                non_returning_targets.binary_search(&target).is_ok()
                            }) {
                            tracing::trace!(
                                "suppressing fall-through of non-returning call at {address}"
                            );

                            let fall_through = insn.iter_targets().find_map(|(target, _, addr)| {
                                target.is_fall_through().then_some(addr)
                            });

                            f.insn_mut(insn_id)
                                .expect("inserted instruction must exist")
                                .remove_fall_through();

                            fall_through
                        } else {
                            None
                        };

                        if let Some(fall_through) = orphaned_fall_through
                            && let Some((fall_through, context)) =
                                arch.canonicalise_address(fall_through)
                        {
                            let fall_through = Address::new(address.space(), fall_through);
                            if !is_avoided(&self.avoids, fall_through) {
                                self.global_targets
                                    .insert(AddressWithContext::new(fall_through, context));
                            }
                        }

                        let insn = f.insn(insn_id).expect("inserted instruction must exist");

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

                                let tail_call = kind.is_local()
                                    && addr != self.entry
                                    && !insn.is_call()
                                    && function_entries.binary_search(&addr).is_ok();

                                if tail_call {
                                    if let Some(target) =
                                        FlowTarget::from_insn_target(insn, target, addr)
                                    {
                                        self.local_targets.insert(FlowTarget::new(
                                            target.from(),
                                            addr,
                                            FlowKind::TailCallBranch,
                                        ));
                                    }
                                    if !is_avoided(&self.avoids, addr) {
                                        self.global_targets
                                            .insert(AddressWithContext::new(addr, context));
                                    }
                                } else if kind.is_local() && view.contains(addr) {
                                    let Some(target) =
                                        FlowTarget::from_insn_target(insn, target, addr)
                                    else {
                                        continue;
                                    };

                                    if self.local_targets.insert(target) {
                                        self.add_candidate(AddressWithContext::new(addr, context));
                                    }
                                } else if !is_avoided(&self.avoids, addr) {
                                    self.global_targets
                                        .insert(AddressWithContext::new(addr, context));
                                }
                            }

                            continue 'outer;
                        }

                        // Implicit control-flow (it is a halt, etc.)
                        if !insn.has_fall_through() {
                            // We're done with this block
                            continue 'outer;
                        }

                        offset += insn.size();
                    }
                    Err(e) => {
                        // Flows into bad data; we skip this block and remove its context
                        tracing::debug!("skipping {address}; instruction resolution failed: {e}");
                        self.block_contexts.remove(&address);
                        self.avoids.insert(address);
                        continue 'outer;
                    }
                }
            }

            let boundary = block + offset;
            self.add_candidate(AddressWithContext::new(boundary, context));
        }

        Ok(())
    }

    fn structure_blocks(
        &mut self,
        function: &mut IncompleteFunction,
        config: &FunctionRecoveryConfig,
    ) -> Result<(), FunctionRecoveryError> {
        let contexts = &self.block_contexts;
        self.structurer.structure(
            function,
            config,
            contexts.addresses().copied(),
            |address| contexts.context(&address),
            &self.local_targets,
        )
    }

    fn analyse(
        &mut self,
        analysis: FunctionCandidateAnalysis<'_, '_, '_>,
    ) -> Result<IncompleteFunction, FunctionRecoveryError> {
        // We have three main stages:
        //
        // 1. We first prepare the function builder with the entry point and the context
        //    of the entry block.
        // 2. We enter the main loop where we resolve instructions block by block, and add newly
        //    discovered blocks (and edges) to the pending candidates.
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

        if analysis.config.segment_mapping_hints() {
            // NOTE: this expect is safe because the entry address must be valid to reach this
            // point under normal usage.
            let view = analysis
                .analysis
                .project
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

        self.add_candidate(candidate);

        // Apply the pre-resolution passes
        if let Err(error) = analysis
            .pre_resolution_passes
            .analyse_with(analysis.analysis, self)
        {
            return Err(FunctionRecoveryError::PreResolutionPass(error));
        }

        let mut incomplete = IncompleteFunction::with_recycled_insn_index(
            self.entry,
            mem::take(&mut self.insn_index),
        );

        loop {
            let resolver = analysis
                .resolver_slot
                .as_mut()
                .expect("function builder resolver must be available");

            {
                let project = &analysis.analysis.project;
                self.resolve_insns(
                    &InsnResolution {
                        avoidance_baseline: None,
                        config: analysis.config,
                        context: analysis.context,
                        project,
                    },
                    resolver,
                    &mut incomplete,
                )?;
            }

            if !incomplete.has_insns() {
                tracing::debug!("no instructions resolved; invalid function");
                return Err(FunctionRecoveryError::InvalidFunction);
            }

            self.structure_blocks(&mut incomplete, analysis.config)?;

            let num_local_targets = self.local_targets.len();

            let mut structured = StructuredFunctionContext {
                config: *analysis.config,
                context: mem::take(self),
                function: mem::take(&mut incomplete),
                resolver: analysis.resolver_slot.take(),
            };

            // Run post-structuring passes
            let result = analysis
                .post_structuring_passes
                .analyse_with(analysis.analysis, &mut structured);

            *self = structured.context;
            incomplete = structured.function;
            *analysis.resolver_slot = structured.resolver;

            if let Err(error) = result {
                return Err(FunctionRecoveryError::PostStructuringPass(error));
            }

            if self.candidates.is_empty() && self.local_targets.len() == num_local_targets {
                tracing::debug!("no new candidates or local targets; stopping");
                break;
            }
        }

        incomplete.set_tail_call_sites(
            self.local_targets
                .iter()
                .filter(|target| target.kind() == FlowKind::TailCallBranch)
                .map(|target| target.from()),
        );
        self.insn_index = incomplete.recycle_insn_index();

        Ok(incomplete)
    }
}

impl<'p> FunctionCandidateState<'p> {
    pub(crate) fn new(
        view: ProjectView<'p>,
        mut candidate: AddressWithContext,
        config: &FunctionRecoveryConfig,
    ) -> Self {
        let mut context = FunctionBuilderContext::new();
        context.entry = candidate.address();
        let confidence = candidate.confidence();

        let mut phase = FunctionCandidatePhase::Resolving;
        if config.segment_mapping_hints() {
            let mapping = view
                .segments()
                .view_containing(context.entry)
                .expect("valid function entry");
            if let Some(hint) = mapping.mapping_hint_at(context.entry) {
                if hint.is_data() {
                    phase = FunctionCandidatePhase::Failed(FunctionRecoveryError::InvalidFunction);
                } else if let Some(hinted) = hint.context() {
                    candidate.merge_context(hinted);
                }
            }
        }
        if matches!(phase, FunctionCandidatePhase::Resolving) {
            context.add_candidate(candidate.clone());
        }

        let function = IncompleteFunction::new(context.entry);
        Self {
            address: context.entry,
            candidate,
            confidence,
            context,
            function,
            phase,
            view,
        }
    }

    pub(super) fn view(&self) -> &ProjectView<'p> {
        &self.view
    }

    pub(crate) fn is_finished(&self) -> bool {
        matches!(
            self.phase,
            FunctionCandidatePhase::Finished | FunctionCandidatePhase::Failed(_)
        )
    }

    pub(super) fn resolve(
        &mut self,
        config: &FunctionRecoveryConfig,
        context: &FunctionRecoveryContext,
        resolver: &mut InsnResolver,
        avoidance_baseline: &AddressRangeSet,
    ) {
        if !matches!(self.phase, FunctionCandidatePhase::Resolving) {
            return;
        }
        if let Err(error) = self.context.resolve_insns(
            &InsnResolution {
                avoidance_baseline: Some(avoidance_baseline),
                config,
                context,
                project: &self.view,
            },
            resolver,
            &mut self.function,
        ) {
            self.phase = FunctionCandidatePhase::Failed(error);
            return;
        }
        if !self.function.has_insns() {
            self.phase = FunctionCandidatePhase::Failed(FunctionRecoveryError::InvalidFunction);
            return;
        }
        if let Err(error) = self.context.structure_blocks(&mut self.function, config) {
            self.phase = FunctionCandidatePhase::Failed(error);
            return;
        }

        self.phase = FunctionCandidatePhase::Structured(self.context.local_targets.len());
    }

    pub(crate) fn apply_post_structuring_passes(
        &mut self,
        analysis: &mut AnalysisContext<'_, 'p>,
        config: &FunctionRecoveryConfig,
        passes: &mut AnalysisGroup<StructuredFunctionContext>,
    ) {
        let FunctionCandidatePhase::Structured(previous_local_targets) = self.phase else {
            return;
        };

        let mut structured = StructuredFunctionContext {
            config: *config,
            context: mem::take(&mut self.context),
            function: mem::take(&mut self.function),
            resolver: None,
        };
        let result = analysis.with_project(&mut self.view, |analysis| {
            passes.analyse_with(analysis, &mut structured)
        });
        self.context = structured.context;
        self.function = structured.function;

        if let Err(error) = result {
            self.phase =
                FunctionCandidatePhase::Failed(FunctionRecoveryError::PostStructuringPass(error));
            return;
        }
        if self.context.candidates.is_empty()
            && self.context.local_targets.len() == previous_local_targets
        {
            self.phase = FunctionCandidatePhase::Finished;
        } else {
            self.phase = FunctionCandidatePhase::Resolving;
        }
    }

    pub(crate) fn finish(mut self) -> FunctionCandidateOutcome {
        if matches!(self.phase, FunctionCandidatePhase::Finished) {
            self.function.set_tail_call_sites(
                self.context
                    .local_targets
                    .iter()
                    .filter(|target| target.kind() == FlowKind::TailCallBranch)
                    .map(|target| target.from()),
            );
            self.context.insn_index = self.function.recycle_insn_index();
        }
        let result = match self.phase {
            FunctionCandidatePhase::Finished => Ok(self.function),
            FunctionCandidatePhase::Failed(error) => Err(error),
            FunctionCandidatePhase::Resolving | FunctionCandidatePhase::Structured(_) => {
                unreachable!("candidate must be finished before producing its outcome")
            }
        };
        FunctionCandidateOutcome {
            address: self.address,
            avoids: self.context.avoids,
            confidence: self.confidence,
            problems: self.context.problems,
            result: Some(result),
            targets: self.context.global_targets.into_iter().collect(),
        }
    }

    pub(crate) fn into_candidate(self) -> AddressWithContext {
        self.candidate
    }
}
