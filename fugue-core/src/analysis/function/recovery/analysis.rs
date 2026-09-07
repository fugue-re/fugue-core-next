use std::cmp::Ordering;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::mem;
use std::ops::RangeInclusive;
use std::time::Instant;

use rustc_hash::FxHashSet;
use tracing::Level;

use crate::analysis::function::recovery::builder::{FunctionBuilder, FunctionCandidateOutcome};
use crate::analysis::function::recovery::executor::{
    FunctionCandidateBatch, FunctionRecoveryExecutor,
};
use crate::analysis::function::recovery::{
    FunctionBuilderContext, FunctionCommitContext, FunctionCommitPolicy, FunctionRecoveryConfig,
    FunctionRecoveryError, StructuredFunctionContext,
};
use crate::analysis::{AnalysisError, AnalysisGroup, AnalysisPass};
use crate::engine::{
    Analyser, AnalyserProvider, AnalysisContext, Priority, ProjectUpdates, ProjectView,
};
use crate::extension::{self, Registration, submit};
use crate::ir::{
    Address, AddressRange, AddressRangeExt, AddressRangeSet, AddressWithContext, CodeBlockTable,
    FunctionProperties, FunctionTable, IncompleteFunction, ProblemKind, RawAddressRangeSet,
};
use crate::lifter::InsnResolver;
use crate::project::{AnalysisPhase, ChangeKinds, Project};
use crate::storage::{AddressSpaceId, SegmentMappingProvenance, SegmentStorage};
use crate::types::{Confidence, EstimateSize};

pub(crate) const FUNCTION_RECOVERY_ANALYSER: &str = "function-recovery";

pub(crate) struct FunctionRecoveryContext {
    excluded_candidates: FxHashSet<Address>,
    function_entries: Vec<Address>,
    non_returning_targets: Vec<Address>,
}

impl FunctionRecoveryContext {
    fn new(project: &ProjectView<'_>, function_entries: Vec<Address>) -> Self {
        let mut non_returning_targets = project
            .functions()
            .iter()
            .filter(|function| function.is_non_returning())
            .map(|function| function.entry())
            .collect::<Vec<_>>();
        non_returning_targets.extend(
            project
                .symbols()
                .iter_by_address()
                .filter(|(_, symbol)| symbol.is_non_returning())
                .map(|(_, symbol)| symbol.address()),
        );
        non_returning_targets.sort_unstable();
        non_returning_targets.dedup();

        let excluded_candidates = project
            .problems()
            .iter()
            .filter_map(|problem| {
                if matches!(
                    problem.kind(),
                    ProblemKind::HinderedByAssertedFact
                        | ProblemKind::AvoidedBytes
                        | ProblemKind::CannotCreateFunction
                        | ProblemKind::DecodeFailed
                        | ProblemKind::FunctionTooLarge
                        | ProblemKind::PassFailed
                        | ProblemKind::Unknown
                ) {
                    problem.address()
                } else {
                    None
                }
            })
            .collect();

        Self {
            excluded_candidates,
            function_entries,
            non_returning_targets,
        }
    }

    pub(crate) fn excluded_candidates(&self) -> &FxHashSet<Address> {
        &self.excluded_candidates
    }

    pub(crate) fn function_entries(&self) -> &[Address] {
        &self.function_entries
    }

    pub(crate) fn non_returning_targets(&self) -> &[Address] {
        &self.non_returning_targets
    }
}

pub struct FunctionRecovery {
    boundaries: Option<FunctionBoundaries>,
    boundary_update_pending: bool,
    candidates: VecDeque<AddressWithContext>,
    builder: FunctionBuilder,
    candidate_discovery_passes: AnalysisGroup<FunctionDiscoveryContext>,
    inter_function_structuring_passes: AnalysisGroup<InterFunctionStructuringContext>,
    commit_policy: Option<Box<dyn FunctionCommitPolicy + 'static>>,
    continuation_coverage: Option<FunctionCoverage>,
    project_candidates_added: bool,
    pending_functions: BTreeMap<Address, IncompleteFunction>,
    reanalysis_candidates: FxHashSet<Address>,
    discovered_targets: Vec<AddressWithContext>,
    executor: FunctionRecoveryExecutor,
    context: Option<FunctionRecoveryContext>,
}

type FunctionRecoveryExtensionFn = fn(&Project, &mut FunctionRecovery) -> Result<(), AnalysisError>;

pub struct FunctionRecoveryExtension {
    configure: FunctionRecoveryExtensionFn,
    name: &'static str,
    priority: Priority,
}

impl FunctionRecoveryExtension {
    pub const fn new(name: &'static str, configure: FunctionRecoveryExtensionFn) -> Self {
        Self {
            configure,
            name,
            priority: Priority::DISCOVERY,
        }
    }

    pub fn priority(&self) -> Priority {
        self.priority
    }

    pub const fn set_priority(&mut self, priority: Priority) {
        self.priority = priority;
    }

    pub const fn with_priority(mut self, priority: Priority) -> Self {
        self.set_priority(priority);
        self
    }

    pub fn configure(
        &self,
        project: &Project,
        recovery: &mut FunctionRecovery,
    ) -> Result<(), AnalysisError> {
        (self.configure)(project, recovery)
    }
}

impl Registration for FunctionRecoveryExtension {
    fn name(&self) -> &'static str {
        self.name
    }
}

extension::collect!(FunctionRecoveryExtension);

#[derive(Default)]
pub struct FunctionDiscoveryContext {
    config: FunctionRecoveryConfig,
    candidates: VecDeque<AddressWithContext>,
    avoids: AddressRangeSet,
    coverage: FunctionCoverage,
    functions: FunctionConfidenceMap,
    new_functions: FunctionConfidenceMap,
}

pub struct FunctionDiscoveryRanges<'a, Ranges> {
    ranges: Ranges,
    avoids: &'a AddressRangeSet,
    candidates: &'a mut VecDeque<AddressWithContext>,
}

impl<Ranges> FunctionDiscoveryRanges<'_, Ranges> {
    pub fn is_avoided(&self, address: impl Into<Address>) -> bool {
        self.avoids.contains(address.into())
    }

    pub fn add_candidate(&mut self, candidate: impl Into<AddressWithContext>) {
        self.candidates.push_back(candidate.into());
    }
}

impl<Ranges> Iterator for FunctionDiscoveryRanges<'_, Ranges>
where
    Ranges: Iterator<Item = AddressRange>,
{
    type Item = AddressRange;

    fn next(&mut self) -> Option<Self::Item> {
        self.ranges.next()
    }
}

#[derive(Default)]
struct FunctionConfidenceMap {
    entries: BTreeMap<Address, Confidence>,
}

impl FunctionConfidenceMap {
    fn contains(&self, address: Address) -> bool {
        self.entries.contains_key(&address)
    }

    fn iter(&self) -> impl Iterator<Item = (&Address, &Confidence)> {
        self.entries.iter()
    }

    fn entries(&self) -> &BTreeMap<Address, Confidence> {
        &self.entries
    }

    fn insert(&mut self, address: Address, confidence: Confidence) -> bool {
        let Entry::Vacant(entry) = self
            .entries
            .entry(address)
            .and_modify(|current| current.merge_max(confidence))
        else {
            return false;
        };
        entry.insert(confidence);
        true
    }

    fn remove(&mut self, address: Address) {
        self.entries.remove(&address);
    }

    fn candidate_known(
        project_functions: &FunctionTable,
        pending_functions: &BTreeMap<Address, IncompleteFunction>,
        functions: &Self,
        new_functions: &Self,
        address: Address,
    ) -> bool {
        pending_functions.contains_key(&address)
            || functions.contains(address)
            || new_functions.contains(address)
            || project_functions.contains(address)
    }
}

#[derive(Default)]
struct FunctionCoverage {
    available: BTreeMap<AddressSpaceId, RawAddressRangeSet>,
    covered: AddressRangeSet,
    fine_grained: bool,
    pending: Vec<AddressRange>,
}

struct FunctionRecoveryBudget {
    candidate_limit: usize,
    processed_candidates: usize,
    function_limit: usize,
    staged_functions: usize,
    output_byte_limit: usize,
    staged_output_bytes: usize,
}

impl FunctionRecoveryBudget {
    fn new(config: &FunctionRecoveryConfig) -> Self {
        Self {
            candidate_limit: config.max_candidates_per_invocation(),
            processed_candidates: 0,
            function_limit: config.max_functions_per_invocation(),
            staged_functions: 0,
            output_byte_limit: config.max_output_bytes_per_invocation(),
            staged_output_bytes: 0,
        }
    }

    fn is_exhausted(&self) -> bool {
        self.remaining_candidates() == 0
            || self.remaining_functions() == 0
            || self.staged_output_bytes >= self.output_byte_limit
    }

    fn remaining_candidates(&self) -> usize {
        self.candidate_limit
            .saturating_sub(self.processed_candidates)
    }

    fn remaining_functions(&self) -> usize {
        self.function_limit.saturating_sub(self.staged_functions)
    }

    fn consume_candidate(&mut self) {
        self.processed_candidates += 1;
    }

    fn try_consume_function(&mut self, output_bytes: usize) -> bool {
        if self.remaining_functions() == 0
            || (self.staged_output_bytes != 0
                && output_bytes
                    > self
                        .output_byte_limit
                        .saturating_sub(self.staged_output_bytes))
        {
            return false;
        }

        self.staged_output_bytes = self.staged_output_bytes.saturating_add(output_bytes);
        self.staged_functions += 1;
        true
    }
}

#[derive(Default)]
struct FunctionBoundaries {
    entries: Vec<Address>,
    scratch: Vec<Address>,
}

#[derive(Default)]
struct FunctionBoundaryChanges {
    added: Vec<Address>,
    removed: Vec<Address>,
}

#[derive(Default)]
pub struct InterFunctionStructuringContext {
    config: FunctionRecoveryConfig,
    avoids: AddressRangeSet,
    candidates: VecDeque<AddressWithContext>,
    functions: FunctionConfidenceMap,
    new_functions: FunctionConfidenceMap,
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

    pub fn avoids(&self) -> &AddressRangeSet {
        &self.avoids
    }

    pub fn avoids_mut(&mut self) -> &mut AddressRangeSet {
        &mut self.avoids
    }

    pub fn functions(&self) -> &BTreeMap<Address, Confidence> {
        self.functions.entries()
    }

    pub fn new_functions(&self) -> &BTreeMap<Address, Confidence> {
        self.new_functions.entries()
    }

    pub fn covered(&self) -> &AddressRangeSet {
        &self.coverage.covered
    }

    pub fn unclaimed_ranges(
        &mut self,
        space_id: AddressSpaceId,
    ) -> FunctionDiscoveryRanges<'_, impl Iterator<Item = AddressRange> + use<'_>> {
        FunctionDiscoveryRanges {
            ranges: self.coverage.unclaimed_ranges(space_id),
            avoids: &self.avoids,
            candidates: &mut self.candidates,
        }
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

    pub fn add_avoid(&mut self, address: impl Into<Address>) {
        self.avoids.insert(address.into());
    }

    pub fn add_avoid_range(&mut self, range: impl Into<RangeInclusive<Address>>) {
        self.avoids.insert_meta_range(range.into());
    }
}

impl FunctionCoverage {
    fn new(
        config: &FunctionRecoveryConfig,
        ftable: &FunctionTable,
        cbtable: &CodeBlockTable,
        segments: &SegmentStorage,
    ) -> Result<Self, FunctionRecoveryError> {
        let mut coverage = Self {
            available: BTreeMap::new(),
            covered: AddressRangeSet::new(),
            fine_grained: config.fine_grained_block_coverage(),
            pending: Vec::new(),
        };

        for space_id in segments.spaces().map(|space| space.id()) {
            let mut available = RawAddressRangeSet::new();
            for view in segments.iter_views(space_id)?.filter(|view| {
                view.properties().is_executable()
                    && view.provenance() != SegmentMappingProvenance::External
            }) {
                available.insert_range(view.start().raw_address()..=view.last().raw_address());
            }
            coverage.available.insert(space_id, available);
        }

        for function in ftable.iter() {
            if coverage.fine_grained {
                for block in function
                    .blocks()
                    .filter_map(|(_, block)| cbtable.get_by_id(block))
                {
                    coverage.insert_range(block.address_range());
                }
                continue;
            }

            let mut blocks = function.blocks();
            let Some((first, first_block)) = blocks.next() else {
                continue;
            };
            let last = blocks
                .next_back()
                .map(|(_, block)| block)
                .unwrap_or(first_block);
            if let Some(last) = cbtable.get_by_id(last) {
                coverage.insert_range(AddressRange::new(
                    first.space(),
                    first.raw_address(),
                    last.last_address().raw_address(),
                ));
            }
        }
        coverage.flush();

        Ok(coverage)
    }

    fn unclaimed_ranges(
        &self,
        space_id: AddressSpaceId,
    ) -> impl Iterator<Item = AddressRange> + use<'_> {
        let available = self
            .available
            .get(&space_id)
            .into_iter()
            .flat_map(|ranges| ranges.ranges());
        let covered = self
            .covered
            .spaces()
            .find_map(|(space, ranges)| (space == space_id).then_some(ranges));
        available
            .flat_map(move |range| {
                let excluded = covered
                    .map(|covered| covered.overlapping_ranges(range.clone()))
                    .into_iter()
                    .flatten();
                range.difference(excluded)
            })
            .map(move |range| AddressRange::new(space_id, *range.start(), *range.end()))
    }

    fn insert(&mut self, function: &IncompleteFunction) {
        if self.fine_grained {
            for block in function.blocks() {
                if let Some(range) = AddressRange::from_size(block.address(), block.size() as u64) {
                    self.insert_range(range);
                }
            }
            return;
        }

        let Some(first) = function.blocks().first() else {
            return;
        };
        let last = function
            .blocks()
            .last()
            .expect("function has a first block");
        let Some(last) = AddressRange::from_size(last.address(), last.size() as u64) else {
            return;
        };
        self.insert_range(AddressRange::new(
            first.address().space(),
            first.address().raw_address(),
            last.end(),
        ));
    }

    fn insert_range(&mut self, range: AddressRange) {
        self.pending.push(range);
    }

    fn flush(&mut self) {
        self.pending.sort_unstable();

        let mut output = 0usize;
        for input in 0..self.pending.len() {
            let range = self.pending[input];
            if output != 0 {
                let previous = &mut self.pending[output - 1];
                let adjacent = previous
                    .end()
                    .checked_add(1usize)
                    .is_some_and(|next| range.start() <= next);
                if previous.space() == range.space() && (previous.intersects(&range) || adjacent) {
                    *previous = AddressRange::new(
                        previous.space(),
                        previous.start(),
                        previous.end().max(range.end()),
                    );
                    continue;
                }
            }
            self.pending[output] = range;
            output += 1;
        }

        for index in 0..output {
            self.covered.insert_range(self.pending[index]);
        }
        self.pending.clear();
    }
}

fn stage_function_updates(
    updates: &mut ProjectUpdates,
    address: Address,
    function: IncompleteFunction,
) {
    tracing::debug!("staging recovered function at {address}");
    updates.add_function(function);
}

impl FunctionBoundaries {
    fn new(functions: &FunctionTable) -> Self {
        Self {
            entries: functions.addresses().collect(),
            scratch: Vec::new(),
        }
    }

    fn entries(&self) -> &[Address] {
        &self.entries
    }

    fn update(&mut self, functions: &FunctionTable) -> FunctionBoundaryChanges {
        self.scratch.clear();
        self.scratch.extend(functions.addresses());
        debug_assert!(self.scratch.is_sorted());

        let mut changes = FunctionBoundaryChanges::default();
        let mut previous = self.entries.iter().copied().peekable();
        let mut current = self.scratch.iter().copied().peekable();

        while let (Some(&old), Some(&new)) = (previous.peek(), current.peek()) {
            match old.cmp(&new) {
                Ordering::Less => {
                    changes.removed.push(old);
                    previous.next();
                }
                Ordering::Equal => {
                    previous.next();
                    current.next();
                }
                Ordering::Greater => {
                    changes.added.push(new);
                    current.next();
                }
            }
        }
        changes.removed.extend(previous);
        changes.added.extend(current);

        mem::swap(&mut self.entries, &mut self.scratch);
        changes
    }
}

impl InterFunctionStructuringContext {
    pub fn config(&self) -> &FunctionRecoveryConfig {
        &self.config
    }

    pub fn avoids(&self) -> &AddressRangeSet {
        &self.avoids
    }

    pub fn avoids_mut(&mut self) -> &mut AddressRangeSet {
        &mut self.avoids
    }

    pub fn functions(&self) -> &BTreeMap<Address, Confidence> {
        self.functions.entries()
    }

    pub fn new_functions(&self) -> &BTreeMap<Address, Confidence> {
        self.new_functions.entries()
    }

    pub fn pending_functions(&self) -> &BTreeMap<Address, IncompleteFunction> {
        &self.pending_functions
    }

    pub fn add_candidate(&mut self, candidate: impl Into<AddressWithContext>) {
        self.candidates.push_back(candidate.into());
    }

    pub fn add_avoid(&mut self, address: impl Into<Address>) {
        self.avoids.insert(address.into());
    }

    pub fn add_avoid_range(&mut self, range: impl Into<RangeInclusive<Address>>) {
        self.avoids.insert_meta_range(range.into());
    }

    pub fn add_function(
        &mut self,
        address: impl Into<Address>,
        function: IncompleteFunction,
        confidence: Confidence,
    ) -> bool {
        let address = address.into();
        let mut inserted = false;

        inserted |= self.functions.insert(address, confidence);
        inserted |= self.new_functions.insert(address, confidence);

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

    pub fn update_function_properties(
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
        self.functions.remove(address);
        self.new_functions.remove(address);
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
            boundaries: None,
            boundary_update_pending: false,
            candidates: VecDeque::new(),
            builder: FunctionBuilder::new(config),
            candidate_discovery_passes: AnalysisGroup::new(),
            inter_function_structuring_passes: AnalysisGroup::new(),
            commit_policy: None,
            continuation_coverage: None,
            project_candidates_added: false,
            pending_functions: BTreeMap::new(),
            reanalysis_candidates: FxHashSet::default(),
            discovered_targets: Vec::new(),
            executor: FunctionRecoveryExecutor::new(),
            context: None,
        }
    }

    pub fn config(&self) -> &FunctionRecoveryConfig {
        self.builder.config()
    }

    pub fn config_mut(&mut self) -> &mut FunctionRecoveryConfig {
        self.builder.config_mut()
    }

    pub fn candidate_discovery_passes(&self) -> &AnalysisGroup<FunctionDiscoveryContext> {
        &self.candidate_discovery_passes
    }

    pub fn candidate_discovery_passes_mut(
        &mut self,
    ) -> &mut AnalysisGroup<FunctionDiscoveryContext> {
        &mut self.candidate_discovery_passes
    }

    pub fn pre_resolution_passes(&self) -> &AnalysisGroup<FunctionBuilderContext> {
        self.builder.pre_resolution_passes()
    }

    pub fn pre_resolution_passes_mut(&mut self) -> &mut AnalysisGroup<FunctionBuilderContext> {
        self.builder.pre_resolution_passes_mut()
    }

    pub fn post_structuring_passes(&self) -> &AnalysisGroup<StructuredFunctionContext> {
        self.builder.post_structuring_passes()
    }

    pub fn post_structuring_passes_mut(&mut self) -> &mut AnalysisGroup<StructuredFunctionContext> {
        self.builder.post_structuring_passes_mut()
    }

    pub fn inter_function_structuring_passes(
        &self,
    ) -> &AnalysisGroup<InterFunctionStructuringContext> {
        &self.inter_function_structuring_passes
    }

    pub fn inter_function_structuring_passes_mut(
        &mut self,
    ) -> &mut AnalysisGroup<InterFunctionStructuringContext> {
        &mut self.inter_function_structuring_passes
    }

    pub fn set_commit_policy(&mut self, policy: impl FunctionCommitPolicy + 'static) {
        self.commit_policy = Some(Box::new(policy));
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

    pub fn add_candidate_discovery_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<FunctionDiscoveryContext> + 'static,
    ) {
        self.candidate_discovery_passes.add_pass(name, pass);
    }

    pub fn add_inter_function_structuring_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<InterFunctionStructuringContext> + 'static,
    ) {
        self.inter_function_structuring_passes.add_pass(name, pass);
    }

    pub fn add_pre_resolution_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<FunctionBuilderContext> + 'static,
    ) {
        self.builder.add_pre_resolution_pass(name, pass);
    }

    pub fn add_post_structuring_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<StructuredFunctionContext> + 'static,
    ) {
        self.builder.add_post_structuring_pass(name, pass);
    }

    fn update_function_boundaries(
        &mut self,
        project: &ProjectView<'_>,
    ) -> Result<(), AnalysisError> {
        let Some(boundaries) = self.boundaries.as_mut() else {
            self.boundaries = Some(FunctionBoundaries::new(project.functions()));
            return Ok(());
        };
        let changes = boundaries.update(project.functions());
        if changes.added.is_empty() && changes.removed.is_empty() {
            return Ok(());
        }

        let blocks = project.blocks();
        let functions = project.functions();
        let mut callers = BTreeSet::new();

        for boundary in changes.added {
            for function in functions.functions_containing(blocks, boundary) {
                let Some(function) = functions.get_by_id(function) else {
                    continue;
                };
                if function.entry() != boundary {
                    callers.insert(function.entry());
                }
            }
        }

        for boundary in changes.removed {
            let references = project
                .references()
                .references_to(boundary.into(), None)
                .map_err(|error| AnalysisError::pass_failed(FUNCTION_RECOVERY_ANALYSER, error))?;
            for reference in references {
                let reference = reference.map_err(|error| {
                    AnalysisError::pass_failed(FUNCTION_RECOVERY_ANALYSER, error)
                })?;
                if !(reference.is_call() && reference.is_jump() && reference.is_terminal()) {
                    continue;
                }
                for function in functions.functions_containing(blocks, reference.from()) {
                    let Some(function) = functions.get_by_id(function) else {
                        continue;
                    };
                    callers.insert(function.entry());
                }
            }
        }

        for caller in callers {
            if self.reanalysis_candidates.insert(caller) {
                self.candidates.push_back(caller.into());
            }
        }

        Ok(())
    }

    fn add_project_candidates(&mut self, project: &ProjectView<'_>) {
        let mut candidates = BTreeSet::new();

        if let Some(entry) = project.entry_point() {
            tracing::debug!("entry point: {entry}");
            candidates.insert(entry.into());
        }

        if self.config().symbol_table_function_hints() {
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
                candidates.insert(entry.address().into());
            }
        }

        if self.config().segment_function_hints() {
            for hint in project.segments().function_hints() {
                tracing::debug!(source = "segment", "function hint: {hint}");
                candidates.insert(hint.into());
            }
        }

        let arch = project.arch();
        let blocks = project.blocks();
        let functions = project.functions();
        for function in functions.iter() {
            for target in function
                .flow_targets(blocks)
                .filter(|target| target.kind().is_global())
            {
                let target = target.to();
                let Some((address, context)) = arch.canonicalise_address(target.raw_address())
                else {
                    continue;
                };
                let address = Address::new(target.space(), address);
                if functions.get_by_address(address).is_none() {
                    candidates.insert(AddressWithContext::new(address, context));
                }
            }
        }

        for queued in &self.candidates {
            candidates.remove(queued);
        }
        self.candidates.extend(candidates);
        self.project_candidates_added = true;
    }

    fn add_region_candidates(&mut self, context: &AnalysisContext) {
        let project = &context.project;
        let regions = context.regions();
        for address in context
            .causes()
            .iter()
            .filter(|cause| {
                cause
                    .kind()
                    .intersects(ChangeKinds::FUNCTION_REMOVED | ChangeKinds::SEGMENT_MAPPED)
            })
            .filter_map(|cause| cause.range().map(|range| range.start_address()))
            .filter(|address| regions.contains(*address))
        {
            self.add_candidate(address);
        }

        if self.config().symbol_table_function_hints() {
            for (_, entry) in project
                .symbols()
                .iter_by_address()
                .filter(|(_, s)| s.is_function())
                .filter(|(_, entry)| regions.contains(entry.address()))
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

        if self.config().segment_function_hints() {
            for hint in project
                .segments()
                .function_hints()
                .filter(|hint| regions.contains(*hint))
            {
                tracing::debug!(source = "segment", "function hint: {hint}");
                self.add_candidate(hint);
            }
        }
    }

    fn add_analysis_candidates(&mut self, context: &AnalysisContext) {
        let project = &context.project;
        let functions_empty = project.functions().is_empty();
        let first_project_scan = !self.project_candidates_added;
        if first_project_scan {
            self.add_project_candidates(project);
        }
        if !functions_empty || !first_project_scan {
            self.add_region_candidates(context);
        }
    }

    fn stage_pending_functions(
        &mut self,
        updates: &mut ProjectUpdates,
        budget: &mut FunctionRecoveryBudget,
    ) {
        loop {
            let Some((_, function)) = self.pending_functions.first_key_value() else {
                return;
            };
            let function_bytes = function.estimate_size();
            if !budget.try_consume_function(function_bytes) {
                return;
            }
            let Some((address, function)) = self.pending_functions.pop_first() else {
                return;
            };

            stage_function_updates(updates, address, function);
        }
    }

    fn structure_functions(
        &mut self,
        analysis: &mut AnalysisContext<'_, '_>,
        budget: &mut FunctionRecoveryBudget,
        functions: &mut FunctionConfidenceMap,
        new_functions: &mut FunctionConfidenceMap,
    ) -> Result<bool, AnalysisError> {
        tracing::debug!(
            "performing {} function restructuring pass(es)",
            self.inter_function_structuring_passes.len()
        );
        let mut state = InterFunctionStructuringContext {
            config: *self.builder.config(),
            avoids: mem::take(self.builder.avoids_mut()),
            candidates: VecDeque::new(),
            functions: mem::take(functions),
            new_functions: mem::take(new_functions),
            pending_functions: mem::take(&mut self.pending_functions),
            committed_functions: BTreeSet::new(),
            changed_functions: BTreeMap::new(),
            removed_functions: BTreeSet::new(),
        };
        let updates_before = analysis.updates.len();
        let functions_before = budget.staged_functions;
        let result = self
            .inter_function_structuring_passes
            .analyse_with(analysis, &mut state)
            .map_err(|error| match error {
                error @ AnalysisError::AnalysisData(_) => error,
                error => AnalysisError::pass_failed(FUNCTION_RECOVERY_ANALYSER, error),
            });
        if let Err(error) = result {
            *self.builder.avoids_mut() = state.avoids;
            return Err(error);
        }

        if let Some(coverage) = self.continuation_coverage.as_mut() {
            for function in state.pending_functions.values() {
                coverage.insert(function);
            }
            coverage.flush();
        }
        self.candidates.append(&mut state.candidates);
        for entry in state.removed_functions {
            if state.pending_functions.remove(&entry).is_none() {
                analysis.updates.remove_function(entry);
            }
        }
        for (entry, properties) in state.changed_functions {
            analysis
                .updates
                .update_function_properties(entry, properties);
        }
        for entry in state.committed_functions {
            let Some(function) = state.pending_functions.get(&entry) else {
                continue;
            };
            let function_bytes = function.estimate_size();
            if !budget.try_consume_function(function_bytes) {
                break;
            }
            let Some(function) = state.pending_functions.remove(&entry) else {
                continue;
            };
            stage_function_updates(&mut analysis.updates, entry, function);
        }

        self.pending_functions = state.pending_functions;
        *self.builder.avoids_mut() = state.avoids;
        *functions = state.functions;
        *new_functions = state.new_functions;
        Ok(analysis.updates.len() != updates_before
            || budget.staged_functions != functions_before
            || !self.pending_functions.is_empty())
    }

    fn discover_candidates(
        &mut self,
        analysis: &mut AnalysisContext<'_, '_>,
        functions: &mut FunctionConfidenceMap,
        new_functions: &mut FunctionConfidenceMap,
    ) -> Result<(), AnalysisError> {
        if self.candidate_discovery_passes.is_empty() {
            return Ok(());
        }
        tracing::debug!(
            "performing {} candidate discovery pass(es)",
            self.candidate_discovery_passes.len()
        );
        let mut state = FunctionDiscoveryContext {
            config: *self.builder.config(),
            candidates: mem::take(&mut self.candidates),
            avoids: mem::take(self.builder.avoids_mut()),
            coverage: self
                .continuation_coverage
                .take()
                .expect("function coverage must be available"),
            functions: mem::take(functions),
            new_functions: mem::take(new_functions),
        };
        let result = self
            .candidate_discovery_passes
            .analyse_with(analysis, &mut state)
            .map_err(|error| match error {
                error @ AnalysisError::AnalysisData(_) => error,
                error => AnalysisError::pass_failed(FUNCTION_RECOVERY_ANALYSER, error),
            });
        self.candidates = state.candidates;
        *self.builder.avoids_mut() = state.avoids;
        self.continuation_coverage = Some(state.coverage);
        *functions = state.functions;
        *new_functions = state.new_functions;
        result
    }

    fn analyse_candidates(
        &mut self,
        analysis: &mut AnalysisContext<'_, '_>,
        worker_limit: usize,
        budget: &mut FunctionRecoveryBudget,
        functions: &FunctionConfidenceMap,
        new_functions: &mut FunctionConfidenceMap,
    ) -> Result<(bool, bool), AnalysisError> {
        let mut function_changes = false;
        let context = self
            .context
            .as_ref()
            .expect("function recovery context must be available");
        let mut resolver_slot = Some(InsnResolver::new(analysis.project.arch()));
        let coverage = &mut self.continuation_coverage;
        let mut yield_after_pass = false;

        while !self.candidates.is_empty() {
            let batch_capacity = budget.remaining_candidates().min(self.candidates.len());
            if batch_capacity == 0 {
                yield_after_pass = true;
                break;
            }
            let mut batch = Vec::with_capacity(batch_capacity);
            let mut batch_addresses = FxHashSet::default();
            let mut replacements = BTreeMap::new();
            batch_addresses.reserve(batch_capacity);
            while batch.len() < batch_capacity {
                let Some(candidate) = self.candidates.pop_front() else {
                    break;
                };
                let original_address = candidate.address();
                let replacing = self.reanalysis_candidates.contains(&original_address);
                budget.consume_candidate();
                let at_limit = !self.candidates.is_empty() && budget.is_exhausted();
                let candidate = match resolver_slot.as_mut() {
                    Some(resolver) => {
                        let confidence = candidate.confidence();
                        let (address, context) = candidate.into_parts();
                        self.builder
                            .context_mut()
                            .function_entry_after_padding(
                                analysis.project.segments(),
                                analysis.project.arch(),
                                resolver,
                                address,
                            )
                            .map(|address| {
                                AddressWithContext::new_with(address, context, confidence)
                            })
                    }
                    None => Some(candidate),
                };

                let Some(candidate) = candidate else {
                    tracing::trace!("skipping candidate: not executable");
                    if replacing {
                        self.reanalysis_candidates.remove(&original_address);
                        analysis.updates.remove_function(original_address);
                        function_changes = true;
                    }
                    if at_limit {
                        yield_after_pass = true;
                        break;
                    }
                    continue;
                };
                let address = candidate.address();

                if self.builder.avoids().contains(address) {
                    tracing::trace!("skipping {address}: in avoidance set");
                    if replacing {
                        self.reanalysis_candidates.remove(&original_address);
                        analysis.updates.remove_function(original_address);
                        function_changes = true;
                    }
                } else if context.excluded_candidates().contains(&address) {
                    tracing::trace!("skipping {address}: blocked by a recorded problem");
                    if replacing {
                        self.reanalysis_candidates.remove(&original_address);
                        analysis.updates.remove_function(original_address);
                        function_changes = true;
                    }
                } else if (!replacing
                    && FunctionConfidenceMap::candidate_known(
                        analysis.project.functions(),
                        &self.pending_functions,
                        functions,
                        new_functions,
                        address,
                    ))
                    || !batch_addresses.insert(address)
                {
                    tracing::trace!("skipping {address}: already analysed");
                } else {
                    if replacing {
                        replacements.insert(address, original_address);
                    }
                    batch.push(candidate);
                }

                if at_limit {
                    yield_after_pass = true;
                    break;
                }
            }

            if batch.is_empty() {
                if yield_after_pass {
                    break;
                }
                continue;
            }

            let builder = &mut self.builder;
            let commit_policy = &self.commit_policy;
            let pending_functions = &mut self.pending_functions;
            let reanalysis_candidates = &mut self.reanalysis_candidates;
            let candidates = &mut self.candidates;
            let discovered_targets = &mut self.discovered_targets;
            let mut handle_outcome = |analysis: &mut AnalysisContext<'_, '_>,
                                      mut outcome: FunctionCandidateOutcome,
                                      discovered_targets: &mut Vec<AddressWithContext>|
             -> Result<bool, AnalysisError> {
                let project = &analysis.project;
                let address = outcome.address();
                let confidence = outcome.confidence();
                let replacement = replacements.remove(&address);
                if let Some(replacement) = replacement {
                    reanalysis_candidates.remove(&replacement);
                }
                for (problem_address, kind) in outcome.drain_problems() {
                    analysis.updates.add_problem(problem_address, kind);
                }

                let function = match outcome.take_result() {
                    Ok(function) => function,
                    Err(
                        FunctionRecoveryError::PreResolutionPass(
                            error @ AnalysisError::AnalysisData(_),
                        )
                        | FunctionRecoveryError::PostStructuringPass(
                            error @ AnalysisError::AnalysisData(_),
                        ),
                    ) => return Err(error),
                    Err(error) => {
                        let kind = error.problem_kind();
                        tracing::trace!("failed to analyse {address}: {error}");
                        analysis.updates.add_problem(address, kind);
                        if let Some(replacement) = replacement {
                            analysis.updates.remove_function(replacement);
                            function_changes = true;
                        }
                        return Ok(false);
                    }
                };
                if let Some(coverage) = coverage.as_mut() {
                    coverage.insert(&function);
                }
                let commit_context = FunctionCommitContext::new(function, confidence);
                let should_commit = commit_policy
                    .should_commit_immediately(project, &commit_context)
                    .map_err(|error| {
                        AnalysisError::pass_failed(FUNCTION_RECOVERY_ANALYSER, error)
                    })?;
                let function = commit_context.into_function();
                let function_bytes = function.estimate_size();
                if let Some(replacement) = replacement.filter(|&entry| entry != address) {
                    analysis.updates.remove_function(replacement);
                    function_changes = true;
                }
                let budget_reached = should_commit && !budget.try_consume_function(function_bytes);
                if should_commit && !budget_reached {
                    stage_function_updates(&mut analysis.updates, address, function);
                    function_changes = true;
                } else {
                    tracing::debug!("deferring commit of function at {address}");
                    pending_functions.insert(address, function);
                }
                new_functions.insert(address, confidence);

                discovered_targets.clear();
                for candidate in outcome.drain_targets() {
                    let start = candidate.address();
                    if !FunctionConfidenceMap::candidate_known(
                        project.functions(),
                        pending_functions,
                        functions,
                        new_functions,
                        start,
                    ) && !context.excluded_candidates().contains(&start)
                    {
                        discovered_targets.push(candidate);
                    }
                }
                discovered_targets.sort_unstable();
                Ok(budget_reached)
            };

            let batch = FunctionCandidateBatch::new(context, batch, worker_limit);
            let remaining = self.executor.analyse_candidates(
                analysis,
                builder,
                &mut resolver_slot,
                batch,
                |analysis, outcome| {
                    let budget_reached = handle_outcome(analysis, outcome, discovered_targets)?;
                    candidates.extend(discovered_targets.drain(..));
                    Ok(budget_reached)
                },
            )?;
            if !remaining.is_empty() {
                for candidate in remaining.into_iter().rev() {
                    candidates.push_front(candidate);
                }
                yield_after_pass = true;
            }

            if yield_after_pass || (!self.candidates.is_empty() && budget.is_exhausted()) {
                yield_after_pass = true;
                break;
            }
        }

        Ok((function_changes, yield_after_pass))
    }

    pub fn new_analyser(project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
        let mut recovery = Self::new();
        let mut extensions = extension::iter::<FunctionRecoveryExtension>().collect::<Vec<_>>();
        extensions.sort_unstable_by_key(|extension| (extension.priority(), extension.name()));

        for extension in extensions {
            extension.configure(project, &mut recovery)?;
        }

        Ok(Box::new(recovery))
    }
}

impl Analyser for FunctionRecovery {
    fn name(&self) -> &'static str {
        FUNCTION_RECOVERY_ANALYSER
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::SEGMENT_MAPPED
            | ChangeKinds::BYTES_WRITTEN
            | ChangeKinds::FUNCTION_REMOVED
            | ChangeKinds::SYMBOL_CHANGED
    }

    fn phase(&self) -> AnalysisPhase {
        AnalysisPhase::Partition
    }

    fn produces(&self) -> ChangeKinds {
        ChangeKinds::FUNCTIONS
            | ChangeKinds::SWITCHES
            | ChangeKinds::REFERENCES
            | ChangeKinds::PROBLEMS
    }

    fn priority(&self) -> Priority {
        Priority::DISCOVERY
    }

    fn can_analyse(&self, _project: &Project) -> bool {
        true
    }

    fn analyse(&mut self, context: &mut AnalysisContext<'_, '_>) -> Result<(), AnalysisError> {
        if !context.is_continuation() {
            self.continuation_coverage = None;
            self.context = None;
            self.update_function_boundaries(&context.project)?;
            self.add_analysis_candidates(context);
        } else if self.boundary_update_pending {
            self.update_function_boundaries(&context.project)?;
            self.boundary_update_pending = false;
        }
        if self.context.is_none() {
            let function_entries = self
                .boundaries
                .as_ref()
                .expect("function boundaries must be established before recovery")
                .entries()
                .to_vec();
            self.context = Some(FunctionRecoveryContext::new(
                &context.project,
                function_entries,
            ));
        }
        let mut budget = FunctionRecoveryBudget::new(self.config());
        let expected_functions = budget.remaining_functions().min(
            self.candidates
                .len()
                .saturating_add(self.pending_functions.len()),
        );
        context.updates.reserve(expected_functions);
        if !self.candidate_discovery_passes.is_empty() && self.continuation_coverage.is_none() {
            self.continuation_coverage = Some(
                FunctionCoverage::new(
                    self.builder.config(),
                    context.project.functions(),
                    context.project.blocks(),
                    context.project.segments(),
                )
                .map_err(|error| AnalysisError::pass_failed(FUNCTION_RECOVERY_ANALYSER, error))?,
            );
        }
        if let Some(coverage) = self.continuation_coverage.as_mut() {
            coverage.pending.reserve(expected_functions);
        }

        tracing::debug!("starting function recovery");
        let span = tracing::span!(Level::TRACE, "function-recovery");
        let function_recovery_span = span.enter();
        let started = Instant::now();

        let function_changes = 'recovery: {
            if self.config().commit_pending_functions() {
                self.stage_pending_functions(&mut context.updates, &mut budget);
                if budget.staged_functions != 0 {
                    break 'recovery true;
                }
            }

            let mut functions = FunctionConfidenceMap::default();
            let mut new_functions = FunctionConfidenceMap::default();
            tracing::debug!("existing functions: {}", context.project.functions().len());
            loop {
                let worker_limit = context.worker_limit();
                let (function_changes, budget_reached) = self.analyse_candidates(
                    context,
                    worker_limit,
                    &mut budget,
                    &functions,
                    &mut new_functions,
                )?;
                if function_changes || budget_reached {
                    break 'recovery function_changes;
                }

                new_functions.iter().for_each(|(&address, &confidence)| {
                    functions.insert(address, confidence);
                });
                if self.structure_functions(
                    context,
                    &mut budget,
                    &mut functions,
                    &mut new_functions,
                )? {
                    break 'recovery true;
                }
                self.discover_candidates(context, &mut functions, &mut new_functions)?;
                if self.candidates.is_empty() {
                    break;
                }
            }

            if self.config().commit_pending_functions() {
                self.stage_pending_functions(&mut context.updates, &mut budget);
                if budget.staged_functions != 0 {
                    break 'recovery true;
                }
            }

            let elapsed = started.elapsed();
            drop(function_recovery_span);
            drop(span);
            let num_functions = context.project.functions().len() + budget.staged_functions;
            tracing::debug!(
                "function recovery completed in {}s ({}ms) with {num_functions} functions",
                elapsed.as_secs(),
                elapsed.as_millis(),
            );
            self.continuation_coverage = None;
            self.boundary_update_pending = false;
            self.context = None;
            return Ok(());
        };

        if function_changes && self.candidates.is_empty() && self.pending_functions.is_empty() {
            self.boundary_update_pending = true;
            self.context = None;
        }

        tracing::debug!(
            "yielding function recovery after {} committed functions and {} processed candidates",
            budget.staged_functions,
            budget.processed_candidates,
        );

        Ok(())
    }

    fn has_pending_work(&self) -> bool {
        self.boundary_update_pending
            || !self.candidates.is_empty()
            || (self.config().commit_pending_functions() && !self.pending_functions.is_empty())
    }
}

submit! {
    AnalyserProvider::new::<FunctionRecovery>(
        FUNCTION_RECOVERY_ANALYSER,
        FunctionRecovery::new_analyser,
    )
}
