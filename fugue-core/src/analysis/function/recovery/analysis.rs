use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::mem;
use std::ops::{ControlFlow, RangeInclusive};
use std::time::Instant;

use itertools::{Itertools, MinMaxResult};
use tracing::Level;

use super::{
    FunctionBuilder, FunctionBuilderContext, FunctionRecoveryCommitContext,
    FunctionRecoveryCommitHook, FunctionRecoveryConfig, FunctionRecoveryError,
    FunctionRecoveryState, InsnResolver,
};
use crate::analysis::control::{CancellationToken, Progress};
use crate::analysis::{AnalysisError, AnalysisGroup, AnalysisPass};
use crate::engine::{Analyser, AnalyserProvider, AnalysisContext, Priority, Trigger};
use crate::ir::{
    Address, AddressRangeSet, AddressWithContext, CodeBlockTable, FunctionProperties,
    FunctionTable, IncompleteFunction, RawAddress, RawAddressRangeSet,
};
use crate::project::{Project, ProjectTransaction};
use crate::registry::{self, Registration, submit};
use crate::storage::{AddressSpaceId, SegmentStorage};
use crate::types::Confidence;

pub const DEFAULT_FUNCTION_RECOVERY_CHUNK_FUNCTIONS: usize = 128;
pub const DEFAULT_FUNCTION_RECOVERY_CHUNK_CANDIDATES: usize = 512;

pub struct FunctionRecovery {
    candidates: VecDeque<AddressWithContext>,
    builder: FunctionBuilder,
    discovery_passes: AnalysisGroup<FunctionDiscoveryContext>,
    structuring_passes: AnalysisGroup<FunctionStructuringContext>,
    commit_hook: Option<Box<dyn FunctionRecoveryCommitHook + 'static>>,
    chunk_candidate_limit: Option<usize>,
    chunk_function_limit: Option<usize>,
    pending_functions: BTreeMap<Address, IncompleteFunction>,
    discovered_targets: Vec<AddressWithContext>,
    cancellation: CancellationToken,
    progress: Progress,
}

type FunctionRecoveryExtensionFn = fn(&Project, &mut FunctionRecovery) -> Result<(), AnalysisError>;

pub struct FunctionRecoveryExtension {
    apply: FunctionRecoveryExtensionFn,
    name: &'static str,
}

impl FunctionRecoveryExtension {
    pub const fn new(name: &'static str, apply: FunctionRecoveryExtensionFn) -> Self {
        Self { apply, name }
    }

    pub fn apply(
        &self,
        project: &Project,
        recovery: &mut FunctionRecovery,
    ) -> Result<(), AnalysisError> {
        (self.apply)(project, recovery)
    }
}

impl Registration for FunctionRecoveryExtension {
    fn name(&self) -> &'static str {
        self.name
    }
}

registry::collect!(FunctionRecoveryExtension);

#[derive(Default)]
pub struct FunctionDiscoveryContext {
    config: FunctionRecoveryConfig,
    candidates: VecDeque<AddressWithContext>,
    avoids: RawAddressRangeSet,
    failures: BTreeSet<Address>,
    functions: BTreeMap<Address, Confidence>,
    new_functions: BTreeMap<Address, Confidence>,
}

#[derive(Default)]
pub struct FunctionStructuringContext {
    config: FunctionRecoveryConfig,
    avoids: RawAddressRangeSet,
    candidates: VecDeque<AddressWithContext>,
    failures: BTreeSet<Address>,
    functions: BTreeMap<Address, Confidence>,
    new_functions: BTreeMap<Address, Confidence>,
    pending_functions: BTreeMap<Address, IncompleteFunction>,
    committed_functions: BTreeSet<Address>,
    changed_functions: BTreeMap<Address, FunctionProperties>,
    removed_functions: BTreeSet<Address>,
}

impl FunctionDiscoveryContext {
    pub fn config(&self) -> &FunctionRecoveryConfig {
        &self.config
    }

    pub fn candidates(&self) -> &VecDeque<AddressWithContext> {
        &self.candidates
    }

    pub fn add_candidate(&mut self, candidate: impl Into<AddressWithContext>) {
        self.candidates.push_back(candidate.into());
    }

    pub fn add_candidates(
        &mut self,
        candidates: impl IntoIterator<Item = impl Into<AddressWithContext>>,
    ) {
        self.candidates
            .extend(candidates.into_iter().map(|candidate| candidate.into()));
    }

    pub fn avoids(&self) -> &RawAddressRangeSet {
        &self.avoids
    }

    pub fn avoids_mut(&mut self) -> &mut RawAddressRangeSet {
        &mut self.avoids
    }

    pub fn add_avoid(&mut self, address: impl Into<Address>) {
        self.avoids.insert(address.into());
    }

    pub fn add_avoid_range(&mut self, range: impl Into<RangeInclusive<RawAddress>>) {
        self.avoids.insert_range(range);
    }

    pub fn failures(&self) -> &BTreeSet<Address> {
        &self.failures
    }

    pub fn add_failure(&mut self, address: impl Into<Address>) {
        self.failures.insert(address.into());
    }

    pub fn functions(&self) -> &BTreeMap<Address, Confidence> {
        &self.functions
    }

    pub fn new_functions(&self) -> &BTreeMap<Address, Confidence> {
        &self.new_functions
    }

    fn covered_by_minmax_block_bounds(
        &self,
        ftable: &FunctionTable,
        cbtable: &CodeBlockTable,
    ) -> RawAddressRangeSet {
        let mut covered = RawAddressRangeSet::new();

        for function in ftable.iter() {
            let mm = function.blocks().minmax_by_key(|&(addr, _)| addr);

            match mm {
                MinMaxResult::OneElement((_, bid)) => {
                    if let Some(block) = cbtable.get_by_id(bid) {
                        covered.insert_meta_range(block.range());
                    }
                }
                MinMaxResult::MinMax((_, min_bid), (_, max_bid)) => {
                    if let (Some(min_block), Some(max_block)) =
                        (cbtable.get_by_id(min_bid), cbtable.get_by_id(max_bid))
                    {
                        covered.insert_meta_range(min_block.address()..=max_block.last_address());
                    }
                }
                _ => {}
            }
        }

        covered
    }

    fn covered_by_all_block_bounds(
        &self,
        ftable: &FunctionTable,
        cbtable: &CodeBlockTable,
    ) -> RawAddressRangeSet {
        let mut covered = RawAddressRangeSet::new();

        for function in ftable.iter() {
            for block in function
                .blocks()
                .filter_map(|(_, bid)| cbtable.get_by_id(bid))
            {
                covered.insert_meta_range(block.range());
            }
        }

        covered
    }

    pub fn covered(&self, ftable: &FunctionTable, cbtable: &CodeBlockTable) -> RawAddressRangeSet {
        if self.config.use_fine_grained_block_coverage() {
            self.covered_by_all_block_bounds(ftable, cbtable)
        } else {
            self.covered_by_minmax_block_bounds(ftable, cbtable)
        }
    }

    pub fn gaps(
        &self,
        ftable: &FunctionTable,
        cbtable: &CodeBlockTable,
        segments: &SegmentStorage,
        space_id: AddressSpaceId,
    ) -> Result<RawAddressRangeSet, FunctionRecoveryError> {
        let covered = self.covered(ftable, cbtable);

        let avail = segments
            .iter_views(space_id)?
            .filter(|segm| segm.properties().is_executable() && !segm.properties().is_external())
            .map(|segm| segm.start()..=segm.last())
            .collect::<RawAddressRangeSet>();

        Ok(avail.difference(&covered))
    }

    fn insert_function(
        functions: &mut BTreeMap<Address, Confidence>,
        address: Address,
        confidence: Confidence,
    ) -> bool {
        use std::collections::btree_map::Entry;
        let Entry::Vacant(entry) = functions
            .entry(address)
            .and_modify(|c| c.merge_max(confidence))
        else {
            return false;
        };
        entry.insert(confidence);
        true
    }

    fn candidate_known(
        project: &Project,
        pending_functions: &BTreeMap<Address, IncompleteFunction>,
        functions: &BTreeMap<Address, Confidence>,
        new_functions: &BTreeMap<Address, Confidence>,
        address: Address,
    ) -> bool {
        project.functions().get_by_address(address).is_some()
            || pending_functions.contains_key(&address)
            || functions.contains_key(&address)
            || new_functions.contains_key(&address)
    }
}

impl FunctionStructuringContext {
    pub fn config(&self) -> &FunctionRecoveryConfig {
        &self.config
    }

    pub fn add_candidate(&mut self, candidate: impl Into<AddressWithContext>) {
        self.candidates.push_back(candidate.into());
    }

    pub fn avoids(&self) -> &RawAddressRangeSet {
        &self.avoids
    }

    pub fn avoids_mut(&mut self) -> &mut RawAddressRangeSet {
        &mut self.avoids
    }

    pub fn add_avoid(&mut self, address: impl Into<Address>) {
        self.avoids.insert(address.into().offset());
    }

    pub fn add_avoid_range(&mut self, range: RangeInclusive<Address>) {
        self.avoids.insert_meta_range(range);
    }

    pub fn failures(&self) -> &BTreeSet<Address> {
        &self.failures
    }

    pub fn add_failure(&mut self, address: impl Into<Address>) {
        self.failures.insert(address.into());
    }

    pub fn functions(&self) -> &BTreeMap<Address, Confidence> {
        &self.functions
    }

    pub fn new_functions(&self) -> &BTreeMap<Address, Confidence> {
        &self.new_functions
    }

    pub fn pending_functions(&self) -> &BTreeMap<Address, IncompleteFunction> {
        &self.pending_functions
    }

    pub fn add_function(
        &mut self,
        address: impl Into<Address>,
        function: IncompleteFunction,
        confidence: Confidence,
    ) -> bool {
        let address = address.into();
        let mut inserted = false;

        inserted |=
            FunctionDiscoveryContext::insert_function(&mut self.functions, address, confidence);
        inserted |=
            FunctionDiscoveryContext::insert_function(&mut self.new_functions, address, confidence);

        if inserted {
            self.committed_functions.remove(&address);
            self.removed_functions.remove(&address);
        }

        self.pending_functions.insert(address, function);

        inserted
    }

    pub fn modify_pending_function<F>(
        &mut self,
        address: impl Into<Address>,
        f: F,
    ) -> Result<(), FunctionRecoveryError>
    where
        F: FnOnce(&mut IncompleteFunction) -> Result<(), FunctionRecoveryError>,
    {
        let address = address.into();
        let Some(function) = self.pending_functions.get_mut(&address) else {
            return Ok(());
        };
        f(function)
    }

    pub fn set_function_properties(
        &mut self,
        address: impl Into<Address>,
        properties: FunctionProperties,
    ) {
        let address = address.into();

        if self.removed_functions.contains(&address) {
            return;
        }

        self.changed_functions.insert(address, properties);
    }

    pub fn remove_function(&mut self, address: impl Into<Address>) {
        let address = address.into();
        self.functions.remove(&address);
        self.new_functions.remove(&address);
        self.changed_functions.remove(&address);

        if self.pending_functions.remove(&address).is_none() {
            self.removed_functions.insert(address);
        } else {
            self.committed_functions.remove(&address);
        }
    }

    pub fn reanalyse_function(&mut self, candidate: impl Into<AddressWithContext>) {
        let candidate = candidate.into();
        self.remove_function(candidate.address());
        self.add_candidate(candidate);
    }

    pub fn commit_function(&mut self, address: impl Into<Address>) {
        let address = address.into();

        if self.pending_functions.contains_key(&address) {
            self.committed_functions.insert(address);
        }
    }
}

impl Default for FunctionRecovery {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionRecovery {
    pub fn new() -> Self {
        FunctionRecovery::new_with(FunctionRecoveryConfig::default())
    }

    pub fn new_with(config: FunctionRecoveryConfig) -> Self {
        FunctionRecovery {
            candidates: VecDeque::new(),
            builder: FunctionBuilder::new(config),
            discovery_passes: AnalysisGroup::new(),
            structuring_passes: AnalysisGroup::new(),
            commit_hook: None,
            chunk_candidate_limit: None,
            chunk_function_limit: None,
            pending_functions: BTreeMap::new(),
            discovered_targets: Vec::new(),
            cancellation: CancellationToken::default(),
            progress: Progress::default(),
        }
    }

    pub fn config(&self) -> &FunctionRecoveryConfig {
        self.builder.config()
    }

    pub fn add_candidate(&mut self, candidate: impl Into<AddressWithContext>) {
        self.candidates.push_back(candidate.into());
    }

    pub fn add_candidates(
        &mut self,
        candidates: impl IntoIterator<Item = impl Into<AddressWithContext>>,
    ) {
        self.candidates
            .extend(candidates.into_iter().map(|candidate| candidate.into()));
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn set_cancellation_token(&mut self, token: CancellationToken) {
        self.cancellation = token;
    }

    pub fn progress(&self) -> Progress {
        self.progress.clone()
    }

    pub fn chunk_function_limit(&self) -> Option<usize> {
        self.chunk_function_limit
    }

    pub fn set_chunk_function_limit(&mut self, limit: Option<usize>) {
        self.chunk_function_limit = limit.filter(|limit| *limit > 0);
    }

    pub fn chunk_candidate_limit(&self) -> Option<usize> {
        self.chunk_candidate_limit
    }

    pub fn set_chunk_candidate_limit(&mut self, limit: Option<usize>) {
        self.chunk_candidate_limit = limit.filter(|limit| *limit > 0);
    }

    pub fn candidate_discovery_passes(&self) -> &AnalysisGroup<FunctionDiscoveryContext> {
        &self.discovery_passes
    }

    pub fn candidate_discovery_passes_mut(
        &mut self,
    ) -> &mut AnalysisGroup<FunctionDiscoveryContext> {
        &mut self.discovery_passes
    }

    pub fn inter_function_structuring_passes(&self) -> &AnalysisGroup<FunctionStructuringContext> {
        &self.structuring_passes
    }

    pub fn inter_function_structuring_passes_mut(
        &mut self,
    ) -> &mut AnalysisGroup<FunctionStructuringContext> {
        &mut self.structuring_passes
    }

    pub fn add_candidate_discovery_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<FunctionDiscoveryContext> + 'static,
    ) {
        self.discovery_passes.add_pass(name, pass);
    }

    pub fn add_inter_function_structuring_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<FunctionStructuringContext> + 'static,
    ) {
        self.structuring_passes.add_pass(name, pass);
    }

    pub fn add_builder_initialisation_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<FunctionBuilderContext> + 'static,
    ) {
        self.builder.add_initialisation_pass(name, pass);
    }

    pub fn add_builder_post_structuring_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<FunctionRecoveryState> + 'static,
    ) {
        self.builder.add_post_structuring_pass(name, pass);
    }

    pub fn set_commit_hook(&mut self, hook: impl FunctionRecoveryCommitHook + 'static) {
        self.commit_hook = Some(Box::new(hook));
    }

    fn add_project_candidates(&mut self, project: &Project) -> Result<(), AnalysisError> {
        self.cancellation.check()?;

        if let Some(entry) = project.entry() {
            tracing::debug!("entry point: {entry}");
            self.add_candidate(entry);
        }

        if self.config().use_symbol_table_function_hints() {
            for (_, entry) in project
                .symbols()
                .iter_by_address()
                .filter(|(_, s)| s.is_function())
            {
                self.cancellation.check()?;
                tracing::debug!(
                    source = "symbol-table",
                    "function hint: {} (name: {})",
                    entry.address(),
                    entry.symbol(),
                );
                self.add_candidate(entry.address());
            }
        }

        if self.config().use_segment_function_hints() {
            for hint in project.segments().function_hints() {
                self.cancellation.check()?;
                tracing::debug!(source = "segment", "function hint: {hint}");
                self.add_candidate(hint);
            }
        }

        Ok(())
    }

    fn add_region_candidates(
        &mut self,
        project: &Project,
        regions: &AddressRangeSet,
    ) -> Result<(), AnalysisError> {
        for range in regions.ranges() {
            self.cancellation.check()?;
            self.add_candidate(range.start_address());
        }

        if self.config().use_symbol_table_function_hints() {
            for (_, entry) in project
                .symbols()
                .iter_by_address()
                .filter(|(_, s)| s.is_function())
                .filter(|(_, entry)| regions.contains(entry.address()))
            {
                self.cancellation.check()?;
                tracing::debug!(
                    source = "symbol-table",
                    "function hint: {} (name: {})",
                    entry.address(),
                    entry.symbol(),
                );
                self.add_candidate(entry.address());
            }
        }

        if self.config().use_segment_function_hints() {
            for hint in project
                .segments()
                .function_hints()
                .filter(|hint| regions.contains(*hint))
            {
                self.cancellation.check()?;
                tracing::debug!(source = "segment", "function hint: {hint}");
                self.add_candidate(hint);
            }
        }

        Ok(())
    }
    pub fn analyse_transaction(
        &mut self,
        transaction: &mut ProjectTransaction<'_>,
    ) -> Result<(), AnalysisError> {
        self.add_project_candidates(transaction.project())?;
        self.analyse_candidates(transaction, None, None)
    }

    fn analyse_regions(
        &mut self,
        transaction: &mut ProjectTransaction<'_>,
        regions: &AddressRangeSet,
    ) -> Result<(), AnalysisError> {
        if transaction.project().functions().is_empty() {
            self.add_project_candidates(transaction.project())?;
        } else {
            self.add_region_candidates(transaction.project(), regions)?;
        }

        self.analyse_candidates(
            transaction,
            self.chunk_function_limit,
            self.chunk_candidate_limit,
        )
    }

    fn function_chunk_exhausted(function_limit: Option<usize>, chunk_functions: usize) -> bool {
        function_limit.is_some_and(|limit| chunk_functions >= limit)
    }

    fn commit_pending_function(
        transaction: &mut ProjectTransaction<'_>,
        address: Address,
        mut function: IncompleteFunction,
    ) -> Result<(), AnalysisError> {
        tracing::debug!("committing pending function at {address}");

        let switches = function.take_pending_switches();

        match transaction.add_function(function) {
            Ok(_) => {}
            Err(e) => {
                tracing::debug!("failed to commit function at {address}: {e}");
                return Err(AnalysisError::pass_failed("function-recovery", e));
            }
        }

        for switch in switches {
            let branch = switch.branch();
            transaction
                .add_switch(branch, move |id, _| switch.with_id(id))
                .map_err(|e| AnalysisError::pass_failed("function-recovery", e))?;
        }

        Ok(())
    }

    fn commit_pending_functions(
        &mut self,
        transaction: &mut ProjectTransaction<'_>,
        chunk_function_limit: Option<usize>,
        chunk_functions: &mut usize,
    ) -> Result<(), AnalysisError> {
        while !Self::function_chunk_exhausted(chunk_function_limit, *chunk_functions) {
            let Some((address, function)) = self.pending_functions.pop_first() else {
                return Ok(());
            };

            Self::commit_pending_function(transaction, address, function)?;
            *chunk_functions += 1;
        }

        Ok(())
    }

    fn analyse_candidates(
        &mut self,
        transaction: &mut ProjectTransaction<'_>,
        chunk_function_limit: Option<usize>,
        chunk_candidate_limit: Option<usize>,
    ) -> Result<(), AnalysisError> {
        tracing::debug!("starting function recovery");

        let span = tracing::span!(Level::TRACE, "function-recovery");
        let function_recovery_span = span.enter();

        let t = Instant::now();
        self.progress.reset();
        self.progress.set_message("recovering functions");
        self.progress.set_total(self.candidates.len() as u64);
        let mut chunk_functions = 0usize;
        let mut chunk_candidates = 0usize;
        let chunk_limit_reached =
            |chunk_functions: usize, chunk_candidates: usize, has_more_candidates: bool| {
                has_more_candidates
                    && (chunk_function_limit.is_some_and(|limit| chunk_functions >= limit)
                        || chunk_candidate_limit.is_some_and(|limit| chunk_candidates >= limit))
            };

        // global state
        let mut failures = BTreeSet::new();
        let mut functions = BTreeMap::new();
        let mut resolver_slot = Some(InsnResolver::new(transaction.project()));
        // per pass state
        let mut new_functions = BTreeMap::new();

        tracing::debug!(
            "existing functions: {}",
            transaction.project().functions().len()
        );

        loop {
            self.cancellation.check()?;
            let mut yield_after_pass = false;

            while let Some(candidate) = self.candidates.pop_front() {
                self.cancellation.check()?;
                self.progress.advance(1);
                chunk_candidates += 1;

                let candidate = match resolver_slot.as_mut() {
                    Some(resolver) => {
                        let project = transaction.project();
                        let (address, context) = candidate.into_parts();
                        let address = self.builder.context_mut().skip_padding(
                            project.segments(),
                            project.arch(),
                            resolver,
                            address,
                        );
                        AddressWithContext::new(address, context)
                    }
                    None => candidate,
                };

                let address = candidate.address();
                let confidence = Confidence::certain();

                if !transaction
                    .project()
                    .segments()
                    .contains_segment_in_space(address.space(), address)
                {
                    tracing::trace!("skipping {address}: not mapped");
                    if chunk_limit_reached(
                        chunk_functions,
                        chunk_candidates,
                        !self.candidates.is_empty(),
                    ) {
                        yield_after_pass = true;
                        break;
                    }
                    continue;
                }

                if self.builder.avoids().contains(address) {
                    tracing::trace!("skipping {address}: in avoidance set");
                    if chunk_limit_reached(
                        chunk_functions,
                        chunk_candidates,
                        !self.candidates.is_empty(),
                    ) {
                        yield_after_pass = true;
                        break;
                    }
                    continue;
                }

                if failures.contains(&address) {
                    tracing::trace!("skipping {address}: already failed");
                    if chunk_limit_reached(
                        chunk_functions,
                        chunk_candidates,
                        !self.candidates.is_empty(),
                    ) {
                        yield_after_pass = true;
                        break;
                    }
                    continue;
                }

                if FunctionDiscoveryContext::candidate_known(
                    transaction.project(),
                    &self.pending_functions,
                    &functions,
                    &new_functions,
                    address,
                ) {
                    tracing::trace!("skipping {address}: already analysed");
                    if chunk_limit_reached(
                        chunk_functions,
                        chunk_candidates,
                        !self.candidates.is_empty(),
                    ) {
                        yield_after_pass = true;
                        break;
                    }
                    continue;
                }

                tracing::debug!(
                    "analysing function candidate at {candidate} (confidence: {confidence})"
                );

                let function = match self.builder.analyse(
                    transaction,
                    &mut resolver_slot,
                    candidate,
                    &self.cancellation,
                ) {
                    Ok(ControlFlow::Continue(f)) => f,
                    Ok(ControlFlow::Break(cancelled)) => return Err(cancelled.into()),
                    Err(e) => {
                        failures.insert(address);
                        tracing::trace!("failed to analyse {address}: {e}");
                        if chunk_limit_reached(
                            chunk_functions,
                            chunk_candidates,
                            !self.candidates.is_empty(),
                        ) {
                            yield_after_pass = true;
                            break;
                        }
                        continue;
                    }
                };

                let commit_context = FunctionRecoveryCommitContext::new(function, confidence);

                if self
                    .commit_hook
                    .should_commit(transaction.project(), &commit_context)
                    .map_err(|e| AnalysisError::pass_failed("function-recovery", e))?
                {
                    tracing::debug!("committing function at {address}");

                    let function = commit_context.into_function();

                    Self::commit_pending_function(transaction, address, function).inspect_err(
                        |error| tracing::debug!("failed to commit function at {address}: {error}"),
                    )?;
                    chunk_functions += 1;
                } else {
                    tracing::debug!("deferring commit of function at {address}");

                    self.pending_functions
                        .insert(address, commit_context.into_function());
                }

                new_functions.insert(address, confidence);

                // avoids shouldn't make it into the candidate set
                self.discovered_targets.clear();
                for candidate in self.builder.global_targets() {
                    let start = candidate.address();
                    if !FunctionDiscoveryContext::candidate_known(
                        transaction.project(),
                        &self.pending_functions,
                        &functions,
                        &new_functions,
                        start,
                    ) && !failures.contains(&start)
                    {
                        self.discovered_targets.push(candidate.clone());
                    }
                }
                self.candidates.extend(self.discovered_targets.drain(..));

                if chunk_limit_reached(
                    chunk_functions,
                    chunk_candidates,
                    !self.candidates.is_empty(),
                ) {
                    yield_after_pass = true;
                    break;
                }
            }

            // flush pass functions
            new_functions.iter().for_each(|(&address, &confidence)| {
                FunctionDiscoveryContext::insert_function(&mut functions, address, confidence);
            });

            // perform a restructuring pass over existing functions, which may split
            // or merge functions, check for overlaps and/or conflicts, etc.

            tracing::debug!(
                "performing {} function restructuring pass(es)",
                self.structuring_passes.len()
            );

            let mut context = FunctionStructuringContext {
                config: *self.builder.config(),
                avoids: mem::take(self.builder.avoids_mut()),
                candidates: VecDeque::new(),
                failures: mem::take(&mut failures),
                functions: mem::take(&mut functions),
                new_functions: mem::take(&mut new_functions),
                pending_functions: mem::take(&mut self.pending_functions),
                committed_functions: BTreeSet::new(),
                changed_functions: BTreeMap::new(),
                removed_functions: BTreeSet::new(),
            };

            let result = transaction
                .analyse_with(&mut self.structuring_passes, &mut context)
                .map_err(|e| AnalysisError::pass_failed("function-recovery", e));

            if let Err(e) = result {
                // restore state
                *self.builder.avoids_mut() = context.avoids;
                return Err(e);
            }

            self.candidates.append(&mut context.candidates);

            // remove any functions that were removed during restructuring
            for f in context.removed_functions {
                if context.pending_functions.remove(&f).is_some() {
                    continue;
                }

                transaction
                    .remove_function(f)
                    .map_err(|e| AnalysisError::pass_failed("function-recovery", e))?;
            }

            for (f, properties) in context.changed_functions {
                transaction
                    .set_function_properties(f, properties)
                    .map_err(|e| AnalysisError::pass_failed("function-recovery", e))?;
            }

            // commit any functions that were forced during restructuring
            for f in context.committed_functions {
                if Self::function_chunk_exhausted(chunk_function_limit, chunk_functions) {
                    break;
                }

                let function = match context.pending_functions.remove(&f) {
                    Some(func) => func,
                    None => continue,
                };

                Self::commit_pending_function(transaction, f, function)?;
                chunk_functions += 1;
            }
            self.pending_functions = mem::take(&mut context.pending_functions);

            if Self::function_chunk_exhausted(chunk_function_limit, chunk_functions)
                && !self.pending_functions.is_empty()
            {
                *self.builder.avoids_mut() = context.avoids;
                tracing::debug!(
                    "yielding function recovery after {chunk_functions} committed functions and {chunk_candidates} processed candidates"
                );
                return Ok(());
            }

            // perform a candidate discovery pass
            tracing::debug!(
                "performing {} candidate discovery pass(es)",
                self.discovery_passes.len()
            );
            self.cancellation.check()?;

            let mut context = FunctionDiscoveryContext {
                config: context.config,
                candidates: mem::take(&mut self.candidates),
                avoids: context.avoids,
                failures: context.failures,
                functions: context.functions,
                new_functions: context.new_functions,
            };

            let result = transaction
                .analyse_with(&mut self.discovery_passes, &mut context)
                .map_err(|e| AnalysisError::pass_failed("function-recovery", e));

            self.candidates = context.candidates;
            *self.builder.avoids_mut() = context.avoids;

            failures = context.failures;
            functions = context.functions;

            result?;

            if yield_after_pass && !self.candidates.is_empty() {
                tracing::debug!(
                    "yielding function recovery after {chunk_functions} committed functions and {chunk_candidates} processed candidates"
                );
                return Ok(());
            }

            if self.candidates.is_empty() {
                break;
            }
            self.progress
                .set_total(self.progress.done() + self.candidates.len() as u64);
        }

        if self.config().commit_pending_functions() {
            self.commit_pending_functions(transaction, chunk_function_limit, &mut chunk_functions)?;
            if !self.pending_functions.is_empty() {
                tracing::debug!(
                    "yielding function recovery after {chunk_functions} committed functions and {chunk_candidates} processed candidates"
                );
                return Ok(());
            }
        }

        let elapsed = t.elapsed();

        drop(function_recovery_span);
        drop(span);

        let num_functions = transaction.project().functions().len();

        tracing::debug!(
            "function recovery completed in {}s ({}ms) with {num_functions} functions",
            elapsed.as_secs(),
            elapsed.as_millis(),
        );
        self.progress.clear_message();

        Ok(())
    }

    pub fn build_analyser(project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
        let mut recovery = Self::new();
        recovery.set_chunk_candidate_limit(Some(DEFAULT_FUNCTION_RECOVERY_CHUNK_CANDIDATES));
        recovery.set_chunk_function_limit(Some(DEFAULT_FUNCTION_RECOVERY_CHUNK_FUNCTIONS));
        for extension in registry::iter::<FunctionRecoveryExtension>() {
            extension.apply(project, &mut recovery)?;
        }

        Ok(Box::new(recovery))
    }
}

impl AnalysisPass for FunctionRecovery {
    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let mut transaction = project.transaction("function recovery");
        let result = self.analyse_transaction(&mut transaction);
        match result {
            Ok(()) => {
                transaction
                    .commit()
                    .map_err(|error| AnalysisError::pass_failed("function-recovery", error))?;
                Ok(())
            }
            Err(AnalysisError::Cancelled(cancelled)) => {
                transaction
                    .commit()
                    .map_err(|error| AnalysisError::pass_failed("function-recovery", error))?;
                Err(AnalysisError::Cancelled(cancelled))
            }
            Err(error) => {
                transaction.rollback().map_err(|rollback| {
                    AnalysisError::pass_failed("function-recovery", rollback)
                })?;
                Err(error)
            }
        }
    }
}

impl Analyser for FunctionRecovery {
    fn name(&self) -> &'static str {
        "function-recovery"
    }

    fn triggers(&self) -> &'static [Trigger] {
        &[Trigger::BytesMapped, Trigger::SymbolChanged]
    }

    fn priority(&self) -> Priority {
        Priority::DISCOVERY
    }

    fn can_analyse(&self, project: &Project) -> bool {
        let _ = project;
        true
    }

    fn analyse(
        &mut self,
        transaction: &mut ProjectTransaction<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisContext,
    ) -> Result<(), AnalysisError> {
        self.set_cancellation_token(cx.cancellation().clone());
        self.progress = cx.progress().clone();

        self.analyse_regions(transaction, regions)
    }

    fn has_pending_work(&self) -> bool {
        !self.candidates.is_empty()
            || (self.config().commit_pending_functions() && !self.pending_functions.is_empty())
    }
}

submit! {
    AnalyserProvider::new("function-recovery", FunctionRecovery::build_analyser)
}

#[cfg(test)]
mod test {
    use super::*;

    fn incomplete(entry: Address) -> IncompleteFunction {
        IncompleteFunction::new(entry)
    }

    #[test]
    fn test_adding_a_removed_function_clears_its_removal() {
        let entry = Address::from(0x4000u64);
        let mut context = FunctionStructuringContext::default();

        context.remove_function(entry);

        assert!(context.removed_functions.contains(&entry));

        assert!(context.add_function(entry, incomplete(entry), Confidence::default()));

        assert!(!context.removed_functions.contains(&entry));
        assert!(context.pending_functions.contains_key(&entry));
    }

    #[test]
    fn test_adding_a_known_function_keeps_its_commit() {
        let entry = Address::from(0x4000u64);
        let mut context = FunctionStructuringContext::default();

        context.add_function(entry, incomplete(entry), Confidence::default());
        context.commit_function(entry);

        assert!(!context.add_function(entry, incomplete(entry), Confidence::default()));
        assert!(context.committed_functions.contains(&entry));
    }

    #[test]
    fn test_reanalysing_a_function_removes_it_and_queues_it() {
        let entry = Address::from(0x4000u64);
        let mut context = FunctionStructuringContext::default();

        context.add_function(entry, incomplete(entry), Confidence::default());
        context.set_function_properties(entry, FunctionProperties::NON_RETURNING);
        context.reanalyse_function(entry);

        assert!(!context.pending_functions.contains_key(&entry));
        assert!(!context.changed_functions.contains_key(&entry));
        assert_eq!(
            context.candidates.front().map(AddressWithContext::address),
            Some(entry)
        );
    }
}
