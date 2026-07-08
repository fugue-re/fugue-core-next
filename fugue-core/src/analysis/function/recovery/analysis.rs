use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::iter::repeat;
use std::mem;
use std::ops::RangeInclusive;
use std::time::Instant;

use itertools::{Itertools, MinMaxResult};
use tracing::Level;

use super::{
    FunctionBuilder, FunctionBuilderContext, FunctionRecoveryCommitContext,
    FunctionRecoveryCommitHook, FunctionRecoveryConfig, FunctionRecoveryError, PartialFunction,
    PartialFunctionWithContext, Translator,
};
use crate::analysis::{AnalysisError, AnalysisGroup, AnalysisPass};
use crate::ir::{
    Address, AddressWithContext, CodeBlockTable, FunctionTable, RawAddress, RawAddressRangeSet,
};
use crate::project::{Project, ProjectMut};
use crate::storage::SegmentStorage;
use crate::storage::segments::space::AddressSpaceId;
use crate::types::Confidence;

pub struct FunctionRecovery {
    candidates: VecDeque<AddressWithContext>,
    builder: FunctionBuilder,
    discovery_passes: AnalysisGroup<FunctionDiscoveryContext>,
    structuring_passes: AnalysisGroup<FunctionStructuringContext>,
    commit_hook: Option<Box<dyn FunctionRecoveryCommitHook + 'static>>,
    pending_functions: BTreeMap<Address, PartialFunction>,
}

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
    failures: BTreeSet<Address>,
    functions: BTreeMap<Address, Confidence>,
    new_functions: BTreeMap<Address, Confidence>,
    pending_functions: BTreeMap<Address, PartialFunction>,
    committed_functions: BTreeSet<Address>,
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
                    let block = cbtable
                        .get_by_id(bid)
                        .expect("block should exist in code block table");
                    covered.insert_meta_range(block.range());
                }
                MinMaxResult::MinMax((_, min_bid), (_, max_bid)) => {
                    let min_block = cbtable
                        .get_by_id(min_bid)
                        .expect("block should exist in code block table");
                    let max_block = cbtable
                        .get_by_id(max_bid)
                        .expect("block should exist in code block table");
                    // we should probably have a threshold here to avoid huge ranges, where
                    // we have a function that has non-contiguous blocks
                    covered.insert_meta_range(min_block.address()..=max_block.last_address());
                }
                _ => { /* no blocks, skip */ }
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
            for (_, bid) in function.blocks() {
                let block = cbtable
                    .get_by_id(bid)
                    .expect("block should exist in code block table");
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
}

impl FunctionStructuringContext {
    pub fn config(&self) -> &FunctionRecoveryConfig {
        &self.config
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

    pub fn pending_functions(&self) -> &BTreeMap<Address, PartialFunction> {
        &self.pending_functions
    }

    pub fn add_function(
        &mut self,
        address: impl Into<Address>,
        function: PartialFunction,
        confidence: Confidence,
    ) -> bool {
        let address = address.into();
        let mut existing = false;

        existing |= insert_function(&mut self.functions, address, confidence);
        existing |= insert_function(&mut self.new_functions, address, confidence);

        if !existing {
            // in case we have previously marked this function as committed or for removal
            self.committed_functions.remove(&address);
            self.removed_functions.remove(&address);
        }

        self.pending_functions.insert(address, function);

        existing
    }

    pub fn modify_pending_function<F>(
        &mut self,
        address: impl Into<Address>,
        f: F,
    ) -> Result<(), FunctionRecoveryError>
    where
        F: FnOnce(&mut PartialFunction) -> Result<(), FunctionRecoveryError>,
    {
        let address = address.into();
        let Some(function) = self.pending_functions.get_mut(&address) else {
            return Ok(());
        };
        f(function)
    }

    pub fn remove_function(&mut self, address: impl Into<Address>) {
        let address = address.into();
        let mut removed = false;

        removed |= self.functions.remove(&address).is_some();
        removed |= self.new_functions.remove(&address).is_some();

        if !removed {
            return;
        }

        if self.pending_functions.remove(&address).is_none() {
            self.removed_functions.insert(address);
        } else {
            self.committed_functions.remove(&address);
        }
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
            pending_functions: BTreeMap::new(),
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

    // global passes

    pub fn add_candidate_discovery_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<FunctionDiscoveryContext> + 'static,
    ) {
        self.discovery_passes.add_pass(name, pass);
    }

    pub fn candidate_discovery_passes(&self) -> &AnalysisGroup<FunctionDiscoveryContext> {
        &self.discovery_passes
    }

    pub fn candidate_discovery_passes_mut(
        &mut self,
    ) -> &mut AnalysisGroup<FunctionDiscoveryContext> {
        &mut self.discovery_passes
    }

    pub fn add_inter_function_structuring_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<FunctionStructuringContext> + 'static,
    ) {
        self.structuring_passes.add_pass(name, pass);
    }

    pub fn inter_function_structuring_passes(&self) -> &AnalysisGroup<FunctionStructuringContext> {
        &self.structuring_passes
    }

    pub fn inter_function_structuring_passes_mut(
        &mut self,
    ) -> &mut AnalysisGroup<FunctionStructuringContext> {
        &mut self.structuring_passes
    }

    // function creation passes

    pub fn add_builder_initialisation_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<FunctionBuilderContext> + 'static,
    ) {
        self.builder.add_initialisation_pass(name, pass);
    }

    pub fn add_builder_post_lifting_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<PartialFunctionWithContext> + 'static,
    ) {
        self.builder.add_post_lifting_pass(name, pass);
    }

    // hooks

    pub fn set_commit_hook(&mut self, hook: impl FunctionRecoveryCommitHook + 'static) {
        self.commit_hook = Some(Box::new(hook));
    }
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

fn update_function(
    functions: &mut BTreeMap<Address, Confidence>,
    address: Address,
    confidence: Confidence,
) -> bool {
    use std::collections::btree_map::Entry;
    matches!(
        functions
            .entry(address)
            .and_modify(|c| c.merge_max(confidence)),
        Entry::Occupied(_)
    )
}

impl AnalysisPass for FunctionRecovery {
    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        tracing::debug!("starting function recovery");

        let span = tracing::span!(Level::TRACE, "function-recovery");
        let function_recovery_span = span.enter();

        let t = Instant::now();

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
            // FIXME: function hints should be a view over the hints of a given
            // mapping within a given address space, not the segment as a whole.
        }

        // global state
        let mut failures = BTreeSet::new();
        let mut functions = project
            .functions()
            .addresses()
            .zip(repeat(Confidence::certain()))
            .collect::<BTreeMap<_, _>>();
        let mut translator = Translator::new(project);

        // per pass state
        let mut new_functions = BTreeMap::new();

        tracing::debug!("existing functions: {}", functions.len());

        loop {
            while let Some(candidate) = self.candidates.pop_front() {
                let address = candidate.address();
                let confidence = Confidence::certain();

                if !project
                    .segments()
                    .space_contains_segment(address.space(), address)
                {
                    tracing::trace!("skipping {address}: not mapped");
                    continue;
                }

                if self.builder.avoids().contains(address) {
                    tracing::trace!("skipping {address}: in avoidance set");
                    continue;
                }

                if failures.contains(&address) {
                    tracing::trace!("skipping {address}: already failed");
                    continue;
                }

                if update_function(&mut functions, address, confidence)
                    || update_function(&mut new_functions, address, confidence)
                {
                    tracing::trace!("skipping {address}: already analysed");
                    continue;
                }

                tracing::debug!(
                    "analysing function candidate at {candidate} (confidence: {confidence})"
                );

                let function = match self.builder.analyse(project, &mut translator, candidate) {
                    Ok(f) => f,
                    Err(e) => {
                        failures.insert(address);
                        tracing::trace!("failed to analyse {address}: {e}");
                        continue;
                    }
                };

                let commit_context = FunctionRecoveryCommitContext::new(function, confidence);

                if self
                    .commit_hook
                    .should_commit(project, &commit_context)
                    .map_err(|e| AnalysisError::pass_failed("function-recovery", e))?
                {
                    tracing::debug!("committing function at {address}");

                    let ProjectMut {
                        functions: ftable,
                        blocks: cbtable,
                        ..
                    } = project.fields_mut();

                    let function = commit_context.into_function();

                    if let Err(e) = function.commit(ftable, cbtable) {
                        tracing::debug!("failed to commit function at {address}: {e}");

                        new_functions.into_iter().for_each(|(function, address)| {
                            insert_function(&mut functions, function, address);
                        });

                        return Err(AnalysisError::pass_failed("function-recovery", e));
                    }
                } else {
                    tracing::debug!("deferring commit of function at {address}");

                    self.pending_functions
                        .insert(address, commit_context.into_function());
                }

                new_functions.insert(address, confidence);

                // avoids shouldn't make it into the candidate set
                self.candidates.extend(
                    self.builder
                        .global_targets()
                        .iter()
                        .filter(|candidate| {
                            let start = candidate.address();
                            let confidence = Confidence::certain();
                            !update_function(&mut functions, start, confidence)
                                && !update_function(&mut functions, start, confidence)
                                && !failures.contains(&start)
                        })
                        .cloned(),
                );
            }

            // flush pass functions
            new_functions.iter().for_each(|(&address, &confidence)| {
                insert_function(&mut functions, address, confidence);
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
                failures: mem::take(&mut failures),
                functions: mem::take(&mut functions),
                new_functions: mem::take(&mut new_functions),
                pending_functions: mem::take(&mut self.pending_functions),
                committed_functions: BTreeSet::new(),
                removed_functions: BTreeSet::new(),
            };

            let result = self
                .structuring_passes
                .analyse_with(project, &mut context)
                .map_err(|e| AnalysisError::pass_failed("function-recovery", e));

            if let Err(e) = result {
                // restore state
                *self.builder.avoids_mut() = context.avoids;
                return Err(e);
            }

            // remove any functions that were removed during restructuring
            for f in context.removed_functions {
                if context.pending_functions.remove(&f).is_some() {
                    continue;
                }

                let ProjectMut {
                    functions: ftable,
                    blocks: cbtable,
                    ..
                } = project.fields_mut();

                let Some(f) = ftable.get_by_address(f) else {
                    continue;
                };

                for (_addr, bid) in f.blocks() {
                    cbtable.remove_by_id(bid);
                }

                let fid = f.id();

                let _ = f;

                ftable.remove_by_id(fid);
            }

            // commit any functions that were forced during restructuring
            for f in context.committed_functions {
                let function = match context.pending_functions.remove(&f) {
                    Some(func) => func,
                    None => continue,
                };

                tracing::debug!("committing pending function at {f}");

                let ProjectMut {
                    functions: ftable,
                    blocks: cbtable,
                    ..
                } = project.fields_mut();

                if let Err(e) = function.commit(ftable, cbtable) {
                    tracing::debug!("failed to commit function at {f}: {e}");

                    return Err(AnalysisError::pass_failed("function-recovery", e));
                }
            }

            // perform a candidate discovery pass
            tracing::debug!(
                "performing {} candidate discovery pass(es)",
                self.discovery_passes.len()
            );

            let mut context = FunctionDiscoveryContext {
                config: context.config,
                candidates: mem::take(&mut self.candidates),
                avoids: context.avoids,
                failures: context.failures,
                functions: context.functions,
                new_functions: context.new_functions,
            };

            let result = self
                .discovery_passes
                .analyse_with(project, &mut context)
                .map_err(|e| AnalysisError::pass_failed("function-recovery", e));

            self.candidates = context.candidates;
            *self.builder.avoids_mut() = context.avoids;

            failures = context.failures;
            functions = context.functions;

            result?;

            if self.candidates.is_empty() {
                break;
            }
        }

        if self.config().commit_pending_functions() {
            let ProjectMut {
                functions: ftable,
                blocks: cbtable,
                ..
            } = project.fields_mut();

            for (address, function) in mem::take(&mut self.pending_functions) {
                tracing::debug!("committing pending function at {address}");

                if let Err(e) = function.commit(ftable, cbtable) {
                    tracing::debug!("failed to commit function at {address}: {e}");

                    return Err(AnalysisError::pass_failed("function-recovery", e));
                }
            }
        }

        let elapsed = t.elapsed();

        drop(function_recovery_span);
        drop(span);

        let num_functions = functions.len();

        tracing::debug!(
            "function recovery completed in {}s ({}ms) with {num_functions} functions",
            elapsed.as_secs(),
            elapsed.as_millis(),
        );

        Ok(())
    }
}
