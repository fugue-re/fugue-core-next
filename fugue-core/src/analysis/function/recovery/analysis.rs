use std::collections::{BTreeSet, VecDeque};
use std::mem;
use std::ops::RangeInclusive;
use std::time::Instant;

use itertools::{Itertools, MinMaxResult};
use tracing::Level;

use crate::analysis::{AnalysisError, AnalysisGroup, AnalysisPass};
use crate::ir::traits::{CodeBlockTable, FunctionTable, SymbolTable};
use crate::ir::{Address, AddressRangeSet, AddressWithContext};
use crate::lifter::ContextSet;
use crate::project::{Project, ProjectMut};
use crate::storage::project::InMemoryProvider;
use crate::storage::{ProjectStorageProvider, SegmentStorage};

use super::{
    FunctionBuilder, FunctionBuilderContext, FunctionRecoveryConfig, FunctionRecoveryError,
    PartialFunctionWithContext, Translator,
};

pub struct FunctionRecovery<'a, P = InMemoryProvider>
where
    P: ProjectStorageProvider,
{
    candidates: VecDeque<AddressWithContext>,
    builder: FunctionBuilder<'a, P>,
    discovery_passes: AnalysisGroup<'a, P, FunctionDiscoveryContext>,
    structuring_passes: AnalysisGroup<'a, P, FunctionStructuringContext>,
}

#[derive(Default)]
pub struct FunctionDiscoveryContext {
    config: FunctionRecoveryConfig,
    candidates: VecDeque<AddressWithContext>,
    avoids: AddressRangeSet,
    failures: BTreeSet<Address>,
    functions: BTreeSet<Address>,
    new_functions: BTreeSet<Address>,
}

#[derive(Default)]
pub struct FunctionStructuringContext {
    config: FunctionRecoveryConfig,
    avoids: AddressRangeSet,
    failures: BTreeSet<Address>,
    functions: BTreeSet<Address>,
    new_functions: BTreeSet<Address>,
}

impl FunctionDiscoveryContext {
    pub fn config(&self) -> &FunctionRecoveryConfig {
        &self.config
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

    pub fn avoids(&self) -> &AddressRangeSet {
        &self.avoids
    }

    pub fn avoids_mut(&mut self) -> &mut AddressRangeSet {
        &mut self.avoids
    }

    pub fn add_avoid(&mut self, address: impl Into<Address>) {
        self.avoids.insert(address.into());
    }

    pub fn add_avoid_range(&mut self, range: impl Into<RangeInclusive<Address>>) {
        self.avoids.insert_range(range);
    }

    pub fn failures(&self) -> &BTreeSet<Address> {
        &self.failures
    }

    pub fn add_failure(&mut self, address: impl Into<Address>) {
        self.failures.insert(address.into());
    }

    pub fn functions(&self) -> &BTreeSet<Address> {
        &self.functions
    }

    pub fn new_functions(&self) -> &BTreeSet<Address> {
        &self.new_functions
    }

    fn covered_by_minmax_block_bounds(
        &self,
        ftable: &impl FunctionTable,
        cbtable: &impl CodeBlockTable,
    ) -> AddressRangeSet {
        let mut covered = AddressRangeSet::new();

        for function in ftable.iter() {
            let mm = function.blocks().minmax_by_key(|&(addr, _)| addr);

            match mm {
                MinMaxResult::OneElement((_, bid)) => {
                    let block = cbtable
                        .get_by_id(bid)
                        .expect("block should exist in code block table");
                    covered.insert_range(block.range_inclusive());
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
                    covered.insert_range(min_block.address()..=max_block.last_address());
                }
                _ => { /* no blocks, skip */ }
            }
        }

        covered
    }

    fn covered_by_all_block_bounds(
        &self,
        ftable: &impl FunctionTable,
        cbtable: &impl CodeBlockTable,
    ) -> AddressRangeSet {
        let mut covered = AddressRangeSet::new();

        for function in ftable.iter() {
            for (_, bid) in function.blocks() {
                let block = cbtable
                    .get_by_id(bid)
                    .expect("block should exist in code block table");
                covered.insert_range(block.range_inclusive());
            }
        }

        covered
    }

    pub fn covered(
        &self,
        ftable: &impl FunctionTable,
        cbtable: &impl CodeBlockTable,
    ) -> AddressRangeSet {
        if self.config.use_fine_grained_block_coverage() {
            self.covered_by_all_block_bounds(ftable, cbtable)
        } else {
            self.covered_by_minmax_block_bounds(ftable, cbtable)
        }
    }

    pub fn gaps(
        &self,
        ftable: &impl FunctionTable,
        cbtable: &impl CodeBlockTable,
        segments: &SegmentStorage,
    ) -> Result<AddressRangeSet, FunctionRecoveryError> {
        let covered = self.covered(ftable, cbtable);

        let avail = segments
            .metadata()?
            .filter_map(|segm| {
                (segm.properties().is_executable() && !segm.properties().is_external())
                    .then(|| segm.range_inclusive())
            })
            .collect::<AddressRangeSet>();

        Ok(avail.difference(&covered))
    }
}

impl FunctionStructuringContext {
    pub fn config(&self) -> &FunctionRecoveryConfig {
        &self.config
    }

    pub fn avoids(&self) -> &AddressRangeSet {
        &self.avoids
    }

    pub fn avoids_mut(&mut self) -> &mut AddressRangeSet {
        &mut self.avoids
    }

    pub fn add_avoid(&mut self, address: impl Into<Address>) {
        self.avoids.insert(address.into());
    }

    pub fn add_avoid_range(&mut self, range: impl Into<RangeInclusive<Address>>) {
        self.avoids.insert_range(range);
    }

    pub fn failures(&self) -> &BTreeSet<Address> {
        &self.failures
    }

    pub fn add_failure(&mut self, address: impl Into<Address>) {
        self.failures.insert(address.into());
    }

    pub fn functions(&self) -> &BTreeSet<Address> {
        &self.functions
    }

    pub fn new_functions(&self) -> &BTreeSet<Address> {
        &self.new_functions
    }

    pub fn add_function(&mut self, address: impl Into<Address>) {
        let address = address.into();
        self.new_functions.insert(address);
        self.functions.insert(address);
    }

    pub fn remove_function(&mut self, address: impl Into<Address>) {
        let address = address.into();
        self.functions.remove(&address);
        self.new_functions.remove(&address);
    }
}

impl<'a, P> FunctionRecovery<'a, P>
where
    P: ProjectStorageProvider,
{
    pub fn new() -> Self {
        FunctionRecovery::new_with(FunctionRecoveryConfig::default())
    }

    pub fn new_with(config: FunctionRecoveryConfig) -> Self {
        FunctionRecovery {
            candidates: VecDeque::new(),
            builder: FunctionBuilder::new(config),
            discovery_passes: AnalysisGroup::new(),
            structuring_passes: AnalysisGroup::new(),
        }
    }

    pub fn config(&self) -> &FunctionRecoveryConfig {
        self.builder.config()
    }

    pub fn add_candidate(&mut self, address: impl Into<Address>) {
        self.add_candidate_with_context(address, ContextSet::new());
    }

    pub fn add_candidate_with_context(&mut self, address: impl Into<Address>, context: ContextSet) {
        self.candidates
            .push_back(AddressWithContext::new(address, context));
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
        candidates: impl IntoIterator<Item = impl Into<AddressWithContext>>,
    ) {
        self.candidates
            .extend(candidates.into_iter().map(|candidate| candidate.into()));
    }

    // global passes

    pub fn add_candidate_discovery_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<'a, P, FunctionDiscoveryContext> + 'a,
    ) {
        self.discovery_passes.add_pass(name, pass);
    }

    pub fn candidate_discovery_passes(&self) -> &AnalysisGroup<'a, P, FunctionDiscoveryContext> {
        &self.discovery_passes
    }

    pub fn candidate_discovery_passes_mut(
        &mut self,
    ) -> &mut AnalysisGroup<'a, P, FunctionDiscoveryContext> {
        &mut self.discovery_passes
    }

    pub fn add_inter_function_structuring_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<'a, P, FunctionStructuringContext> + 'a,
    ) {
        self.structuring_passes.add_pass(name, pass);
    }

    pub fn inter_function_structuring_passes(
        &self,
    ) -> &AnalysisGroup<'a, P, FunctionStructuringContext> {
        &self.structuring_passes
    }

    pub fn inter_function_structuring_passes_mut(
        &mut self,
    ) -> &mut AnalysisGroup<'a, P, FunctionStructuringContext> {
        &mut self.structuring_passes
    }

    // function creation passes

    pub fn add_builder_initialisation_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<'a, P, FunctionBuilderContext> + 'a,
    ) {
        self.builder.add_initialisation_pass(name, pass);
    }

    pub fn add_builder_post_lifting_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<'a, P, PartialFunctionWithContext> + 'a,
    ) {
        self.builder.add_post_lifting_pass(name, pass);
    }
}

impl<'a, P> AnalysisPass<'a, P> for FunctionRecovery<'a, P>
where
    P: ProjectStorageProvider,
{
    fn analyse(&mut self, project: &mut Project<P>) -> Result<(), AnalysisError> {
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
            for segm in project.segments().metadata().map_err(|e| {
                AnalysisError::pass_failed("function-recovery", FunctionRecoveryError::from(e))
            })? {
                for addr in segm.function_hints().iter() {
                    tracing::debug!(source = "segment", "function hint: {addr}");
                    self.add_candidate(*addr);
                }
            }
        }

        let mut failures = BTreeSet::new();
        let mut functions = project.functions().addresses().collect::<BTreeSet<_>>();
        let mut new_functions = BTreeSet::new();
        let mut translator = Translator::new(project);

        tracing::debug!("existing functions: {}", functions.len());

        loop {
            while let Some(candidate) = self.candidates.pop_front() {
                let address = candidate.address();

                if !project.segments().contains_segment(address) {
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

                if functions.contains(&address) || new_functions.contains(&address) {
                    tracing::trace!("skipping {address}: already analysed");
                    continue;
                }

                tracing::debug!("analysing function candidate at {candidate}");

                let function = match self.builder.analyse(project, &mut translator, candidate) {
                    Ok(f) => f,
                    Err(e) => {
                        failures.insert(address);
                        tracing::trace!("failed to analyse {address}: {e}");
                        continue;
                    }
                };

                let ProjectMut {
                    functions: ftable,
                    blocks: cbtable,
                    ..
                } = project.fields_mut();

                if let Err(e) = function.commit(ftable, cbtable) {
                    tracing::debug!("failed to commit function at {address}: {e}");

                    // flush pass functions
                    functions.extend(new_functions);

                    return Err(AnalysisError::pass_failed("function-recovery", e));
                }

                new_functions.insert(address);

                self.candidates.extend(
                    self.builder
                        .global_targets()
                        .iter()
                        .filter(|candidate| {
                            let start = candidate.address();
                            !functions.contains(&start) && !failures.contains(&start)
                        })
                        .cloned(),
                );
            }

            // flush pass functions
            functions.extend(new_functions.iter().copied());

            // perform a restructuring pass over existing functions, which may split
            // or merge functions, check for overlaps and/or conflicts, etc.
            let mut context = FunctionStructuringContext {
                config: *self.builder.config(),
                avoids: mem::take(self.builder.avoids_mut()),
                failures: mem::take(&mut failures),
                functions: mem::take(&mut functions),
                new_functions: mem::take(&mut new_functions),
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

            // perform a candidate discovery pass
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

            let _ = result?;

            if self.candidates.is_empty() {
                break;
            }
        }

        let elapsed = t.elapsed();
        let num_functions = functions.len();

        drop(function_recovery_span);
        drop(span);

        tracing::debug!(
            "function recovery completed in {}s ({}ms) with {num_functions} functions",
            elapsed.as_secs(),
            elapsed.as_millis(),
        );

        Ok(())
    }
}
