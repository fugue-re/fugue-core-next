use std::cmp::Ordering;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Display, Formatter};
use std::mem;
use std::ops::{ControlFlow, RangeInclusive};
use std::time::Instant;

use rustc_hash::{FxHashMap, FxHashSet};
use tracing::Level;

use super::builder::{FunctionBuilderInputs, FunctionCandidateOutcome};
use super::executor::{FunctionCandidateBatch, FunctionRecoveryExecutor};
use super::{
    FUNCTION_RECOVERY_BLOCKING_PROBLEMS, FunctionBuilder, FunctionBuilderContext,
    FunctionRecoveryCommitContext, FunctionRecoveryCommitHook, FunctionRecoveryConfig,
    FunctionRecoveryError, FunctionRecoveryState,
};
use crate::analysis::control::{CancellationToken, Progress};
use crate::analysis::{AnalysisError, AnalysisGroup, AnalysisPass};
use crate::engine::{
    Analyser, AnalyserProvider, AnalysisContext, Priority, ProjectUpdate, ProjectView,
};
use crate::extension::{self, Registration, submit};
use crate::ir::{
    Address, AddressRange, AddressRangeSet, AddressWithContext, CodeBlockTable, FunctionProperties,
    FunctionTable, IncompleteFunction, ProblemKind, RawAddress, RawAddressRangeSet,
};
use crate::lifter::InsnResolver;
use crate::project::{AnalysisPhase, ChangeKinds, Project};
use crate::storage::{AddressSpaceId, SegmentStorage};
use crate::types::{Confidence, EstimateSize};

pub const DEFAULT_FUNCTION_RECOVERY_CHUNK_FUNCTIONS: usize = 8192;
pub const DEFAULT_FUNCTION_RECOVERY_CHUNK_CANDIDATES: usize = 8192;
pub const DEFAULT_FUNCTION_RECOVERY_CHUNK_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
pub const DEFAULT_FUNCTION_RECOVERY_MAX_ATTEMPTS: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateExclusionReason {
    AssertedFact,
    ProblemCurrent(ProblemKind),
    RetriesExhausted(ProblemKind),
}

impl Display for CandidateExclusionReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::AssertedFact => f.write_str("a user assertion forbids a function here"),
            Self::ProblemCurrent(kind) => write!(f, "recorded {kind:?} problem is still current"),
            Self::RetriesExhausted(kind) => {
                write!(f, "retry budget for {kind:?} is exhausted")
            }
        }
    }
}

pub(crate) const FUNCTION_RECOVERY_ANALYSER: &str = "function-recovery";

pub struct FunctionRecovery {
    boundaries: FunctionBoundaries,
    boundary_reconciliation_pending: bool,
    candidates: VecDeque<AddressWithContext>,
    builder: FunctionBuilder,
    discovery_passes: AnalysisGroup<FunctionDiscoveryContext>,
    structuring_passes: AnalysisGroup<FunctionStructuringContext>,
    commit_hook: Option<Box<dyn FunctionRecoveryCommitHook + 'static>>,
    chunk_output_byte_limit: Option<usize>,
    chunk_candidate_limit: Option<usize>,
    chunk_function_limit: Option<usize>,
    continuation_coverage: Option<FunctionCoverage>,
    project_candidates_added: bool,
    pending_functions: BTreeMap<Address, IncompleteFunction>,
    reanalysis_candidates: FxHashSet<Address>,
    recovery_active: bool,
    discovered_targets: Vec<AddressWithContext>,
    executor: FunctionRecoveryExecutor,
    cancellation: CancellationToken,
    progress: Progress,
    wave_active: bool,
    wave_inputs: Option<FunctionRecoveryInputs>,
}

type FunctionRecoveryExtensionFn = fn(&Project, &mut FunctionRecovery) -> Result<(), AnalysisError>;

pub struct FunctionRecoveryExtension {
    apply: FunctionRecoveryExtensionFn,
    name: &'static str,
    priority: Priority,
}

impl FunctionRecoveryExtension {
    pub const fn new(name: &'static str, apply: FunctionRecoveryExtensionFn) -> Self {
        Self {
            apply,
            name,
            priority: Priority::DISCOVERY,
        }
    }

    pub const fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    pub fn priority(&self) -> Priority {
        self.priority
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

#[derive(Default)]
struct FunctionConfidenceMap {
    entries: BTreeMap<Address, Confidence>,
}

impl FunctionConfidenceMap {
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

    fn contains(&self, address: Address) -> bool {
        self.entries.contains_key(&address)
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

    fn iter(&self) -> impl Iterator<Item = (&Address, &Confidence)> {
        self.entries.iter()
    }

    fn remove(&mut self, address: Address) {
        self.entries.remove(&address);
    }

    fn entries(&self) -> &BTreeMap<Address, Confidence> {
        &self.entries
    }
}

#[derive(Default)]
struct FunctionCoverage {
    available: BTreeMap<AddressSpaceId, RawAddressRangeSet>,
    covered: AddressRangeSet,
    fine_grained: bool,
    pending: Vec<AddressRange>,
}

#[derive(Default)]
struct FunctionRecoveryProblems {
    exclusions: FxHashMap<Address, (usize, CandidateExclusionReason)>,
}

struct FunctionRecoveryInputs {
    function_entries: Vec<Address>,
    non_returning_targets: Vec<Address>,
    problems: FunctionRecoveryProblems,
}

#[derive(Default)]
struct FunctionBoundaries {
    entries: Vec<Address>,
    initialised: bool,
    scratch: Vec<Address>,
}

#[derive(Default)]
struct FunctionBoundaryChanges {
    added: Vec<Address>,
    removed: Vec<Address>,
}

#[derive(Default)]
pub struct FunctionStructuringContext {
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
        self.avoids.insert_meta_range(range.into());
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

    pub fn gaps(&self, space_id: AddressSpaceId) -> AddressRangeSet {
        self.coverage.gaps(space_id)
    }

    pub(crate) fn available_ranges(
        &self,
        space_id: AddressSpaceId,
    ) -> impl Iterator<Item = RangeInclusive<RawAddress>> + '_ {
        self.coverage.available_ranges(space_id)
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
            fine_grained: config.use_fine_grained_block_coverage(),
            pending: Vec::new(),
        };

        for space_id in segments.spaces().map(|space| space.id()) {
            let mut gaps = RawAddressRangeSet::new();
            for view in segments.iter_views(space_id)?.filter(|view| {
                view.properties().is_executable() && !view.properties().is_external()
            }) {
                gaps.insert_range(view.start().raw_address()..=view.last().raw_address());
            }
            coverage.available.insert(space_id, gaps);
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

    fn gaps(&self, space_id: AddressSpaceId) -> AddressRangeSet {
        let mut gaps = AddressRangeSet::new();
        if let Some(available) = self.available.get(&space_id) {
            let covered = self
                .covered
                .spaces()
                .find_map(|(space, ranges)| (space == space_id).then_some(ranges));
            let ranges = covered
                .map(|covered| available.difference(covered))
                .unwrap_or_else(|| available.clone());
            for range in ranges.ranges() {
                gaps.insert_raw_range(space_id, range);
            }
        }
        gaps
    }

    fn available_ranges(
        &self,
        space_id: AddressSpaceId,
    ) -> impl Iterator<Item = RangeInclusive<RawAddress>> + '_ {
        self.available
            .get(&space_id)
            .into_iter()
            .flat_map(RawAddressRangeSet::ranges)
    }
}

impl FunctionRecoveryProblems {
    fn new(project: &ProjectView<'_>) -> Self {
        let mut problems = Self::default();

        for problem in project.problems().iter() {
            let kind = problem.kind();
            let Some(priority) = FUNCTION_RECOVERY_BLOCKING_PROBLEMS
                .iter()
                .position(|candidate| *candidate == kind)
            else {
                continue;
            };
            let Some(address) = problem.address() else {
                continue;
            };
            let exclusion = if kind == ProblemKind::HinderedByAssertedFact {
                CandidateExclusionReason::AssertedFact
            } else if problem.attempts() >= DEFAULT_FUNCTION_RECOVERY_MAX_ATTEMPTS {
                CandidateExclusionReason::RetriesExhausted(kind)
            } else {
                CandidateExclusionReason::ProblemCurrent(kind)
            };

            let entry = problems
                .exclusions
                .entry(address)
                .or_insert((priority, exclusion));
            if priority < entry.0 {
                *entry = (priority, exclusion);
            }
        }

        problems
    }

    fn exclusion_at(&self, address: Address) -> Option<CandidateExclusionReason> {
        self.exclusions
            .get(&address)
            .map(|(_, exclusion)| *exclusion)
    }
}

impl FunctionBoundaries {
    fn entries(&self) -> &[Address] {
        &self.entries
    }

    fn synchronise(&mut self, functions: &FunctionTable) -> FunctionBoundaryChanges {
        self.scratch.clear();
        self.scratch.extend(functions.addresses());
        debug_assert!(self.scratch.is_sorted());

        if !self.initialised {
            mem::swap(&mut self.entries, &mut self.scratch);
            self.initialised = true;
            return FunctionBoundaryChanges::default();
        }

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

impl FunctionStructuringContext {
    pub fn config(&self) -> &FunctionRecoveryConfig {
        &self.config
    }

    pub fn add_candidate(&mut self, candidate: impl Into<AddressWithContext>) {
        self.candidates.push_back(candidate.into());
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
        self.avoids.insert_meta_range(range.into());
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
            boundaries: FunctionBoundaries::default(),
            boundary_reconciliation_pending: false,
            candidates: VecDeque::new(),
            builder: FunctionBuilder::new(config),
            discovery_passes: AnalysisGroup::new(),
            structuring_passes: AnalysisGroup::new(),
            commit_hook: None,
            chunk_output_byte_limit: None,
            chunk_candidate_limit: None,
            chunk_function_limit: None,
            continuation_coverage: None,
            project_candidates_added: false,
            pending_functions: BTreeMap::new(),
            reanalysis_candidates: FxHashSet::default(),
            recovery_active: false,
            discovered_targets: Vec::new(),
            executor: FunctionRecoveryExecutor::new(),
            cancellation: CancellationToken::default(),
            progress: Progress::default(),
            wave_active: false,
            wave_inputs: None,
        }
    }

    pub fn config(&self) -> &FunctionRecoveryConfig {
        self.builder.config()
    }

    pub fn config_mut(&mut self) -> &mut FunctionRecoveryConfig {
        self.builder.config_mut()
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

    pub fn chunk_output_byte_limit(&self) -> Option<usize> {
        self.chunk_output_byte_limit
    }

    pub fn set_chunk_output_byte_limit(&mut self, limit: Option<usize>) {
        self.chunk_output_byte_limit = limit.filter(|limit| *limit > 0);
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

    fn start_recovery(&mut self, project: &ProjectView<'_>) -> Result<(), AnalysisError> {
        self.synchronise_boundaries(project)?;
        self.recovery_active = true;
        Ok(())
    }

    fn start_wave(&mut self, project: &ProjectView<'_>) {
        if self.wave_active {
            return;
        }

        let mut targets = project
            .functions()
            .iter()
            .filter(|function| function.is_non_returning())
            .map(|function| function.entry())
            .collect::<Vec<_>>();
        targets.extend(
            project
                .symbols()
                .iter_by_address()
                .filter(|(_, symbol)| symbol.is_non_returning())
                .map(|(_, symbol)| symbol.address()),
        );
        targets.sort_unstable();
        targets.dedup();

        self.wave_inputs = Some(FunctionRecoveryInputs {
            function_entries: self.boundaries.entries().to_vec(),
            non_returning_targets: targets,
            problems: FunctionRecoveryProblems::new(project),
        });
        self.wave_active = true;
    }

    fn finish_wave_after_admission(&mut self) {
        if self.candidates.is_empty() && self.pending_functions.is_empty() {
            self.boundary_reconciliation_pending = true;
            self.wave_active = false;
        }
    }

    fn synchronise_boundaries(&mut self, project: &ProjectView<'_>) -> Result<(), AnalysisError> {
        let changes = self.boundaries.synchronise(project.functions());
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

    fn add_project_candidates(&mut self, project: &ProjectView<'_>) -> Result<(), AnalysisError> {
        self.cancellation.check()?;
        let mut candidates = BTreeSet::new();

        if let Some(entry) = project.entry_point() {
            tracing::debug!("entry point: {entry}");
            candidates.insert(entry.into());
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
                candidates.insert(entry.address().into());
            }
        }

        if self.config().use_segment_function_hints() {
            for hint in project.segments().function_hints() {
                self.cancellation.check()?;
                tracing::debug!(source = "segment", "function hint: {hint}");
                candidates.insert(hint.into());
            }
        }

        let arch = project.arch();
        let blocks = project.blocks();
        let functions = project.functions();
        for function in functions.iter() {
            self.cancellation.check()?;
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

        Ok(())
    }

    fn add_region_candidates(
        &mut self,
        project: &ProjectView<'_>,
        regions: &AddressRangeSet,
        context: &AnalysisContext,
    ) -> Result<(), AnalysisError> {
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
            self.cancellation.check()?;
            self.add_candidate(address);
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

    pub fn analyse_view(
        &mut self,
        project: &ProjectView<'_>,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        if !self.recovery_active {
            self.start_recovery(project)?;
        }
        if !self.project_candidates_added {
            self.add_project_candidates(project)?;
        }
        self.analyse_candidates(project, updates, 1)
    }

    fn analyse_regions(
        &mut self,
        project: &ProjectView<'_>,
        updates: &mut Vec<ProjectUpdate>,
        regions: &AddressRangeSet,
        context: &AnalysisContext,
    ) -> Result<(), AnalysisError> {
        let functions_empty = project.functions().is_empty();
        let first_project_scan = !self.project_candidates_added;
        if first_project_scan {
            self.add_project_candidates(project)?;
        }
        if !functions_empty || !first_project_scan {
            self.add_region_candidates(project, regions, context)?;
        }

        self.analyse_candidates(project, updates, context.worker_limit())
    }

    fn chunk_exhausted(
        output_byte_limit: Option<usize>,
        function_limit: Option<usize>,
        output_bytes: usize,
        chunk_functions: usize,
    ) -> bool {
        output_byte_limit.is_some_and(|limit| output_bytes >= limit)
            || function_limit.is_some_and(|limit| chunk_functions >= limit)
    }

    fn exceeds_remaining_output(
        output_byte_limit: Option<usize>,
        output_bytes: usize,
        function_bytes: usize,
    ) -> bool {
        output_bytes != 0
            && output_byte_limit
                .is_some_and(|limit| function_bytes > limit.saturating_sub(output_bytes))
    }

    fn stage_function_updates(
        updates: &mut Vec<ProjectUpdate>,
        address: Address,
        mut function: IncompleteFunction,
    ) {
        tracing::debug!("staging recovered function at {address}");
        let switches = function.take_pending_switches();
        updates.push(ProjectUpdate::add_function(function));
        updates.extend(switches.into_iter().map(ProjectUpdate::add_derived_switch));
    }

    fn stage_pending_functions(
        &mut self,
        updates: &mut Vec<ProjectUpdate>,
        chunk_output_byte_limit: Option<usize>,
        chunk_function_limit: Option<usize>,
        chunk_output_bytes: &mut usize,
        chunk_functions: &mut usize,
    ) {
        while !Self::chunk_exhausted(
            chunk_output_byte_limit,
            chunk_function_limit,
            *chunk_output_bytes,
            *chunk_functions,
        ) {
            let Some((_, function)) = self.pending_functions.first_key_value() else {
                return;
            };
            let function_bytes = function.estimate_size();
            if Self::exceeds_remaining_output(
                chunk_output_byte_limit,
                *chunk_output_bytes,
                function_bytes,
            ) {
                return;
            }
            let Some((address, function)) = self.pending_functions.pop_first() else {
                return;
            };

            Self::stage_function_updates(updates, address, function);
            *chunk_output_bytes = chunk_output_bytes.saturating_add(function_bytes);
            *chunk_functions += 1;
        }
    }

    fn analyse_candidates(
        &mut self,
        project: &ProjectView<'_>,
        updates: &mut Vec<ProjectUpdate>,
        worker_limit: usize,
    ) -> Result<(), AnalysisError> {
        tracing::debug!("starting function recovery");

        let chunk_output_byte_limit = self.chunk_output_byte_limit;
        let chunk_function_limit = self.chunk_function_limit;
        let chunk_candidate_limit = self.chunk_candidate_limit;

        if self.boundary_reconciliation_pending {
            self.synchronise_boundaries(project)?;
            self.boundary_reconciliation_pending = false;
        }
        self.start_wave(project);

        let span = tracing::span!(Level::TRACE, "function-recovery");
        let function_recovery_span = span.enter();

        let t = Instant::now();
        self.progress.reset();
        self.progress.set_message("recovering functions");
        self.progress.set_total(self.candidates.len() as u64);
        let mut chunk_output_bytes = 0usize;
        let mut chunk_functions = 0usize;
        let mut chunk_candidates = 0usize;
        let mut function_changes = false;
        let expected_functions = self
            .candidates
            .len()
            .saturating_add(self.pending_functions.len())
            .min(chunk_function_limit.unwrap_or(DEFAULT_FUNCTION_RECOVERY_CHUNK_FUNCTIONS));
        updates.reserve(expected_functions);
        let chunk_limit_reached = |chunk_output_bytes: usize,
                                   chunk_functions: usize,
                                   chunk_candidates: usize,
                                   has_more_candidates: bool| {
            has_more_candidates
                && (Self::chunk_exhausted(
                    chunk_output_byte_limit,
                    chunk_function_limit,
                    chunk_output_bytes,
                    chunk_functions,
                ) || chunk_candidate_limit.is_some_and(|limit| chunk_candidates >= limit))
        };

        if self.config().commit_pending_functions() {
            self.stage_pending_functions(
                updates,
                chunk_output_byte_limit,
                chunk_function_limit,
                &mut chunk_output_bytes,
                &mut chunk_functions,
            );
            if chunk_functions != 0 {
                self.finish_wave_after_admission();
                tracing::debug!(
                    "yielding function recovery after {chunk_functions} committed functions and {chunk_candidates} processed candidates"
                );
                return Ok(());
            }
        }

        // global state
        let mut functions = FunctionConfidenceMap::default();
        let inputs = self
            .wave_inputs
            .as_mut()
            .expect("function recovery inputs must be initialised");
        let mut resolver_slot = Some(InsnResolver::new(project.arch()));
        let project_functions = project.functions();
        let project_blocks = project.blocks();
        if !self.discovery_passes.is_empty() && self.continuation_coverage.is_none() {
            self.continuation_coverage = Some(
                FunctionCoverage::new(
                    self.builder.config(),
                    project_functions,
                    project_blocks,
                    project.segments(),
                )
                .map_err(|error| AnalysisError::pass_failed(FUNCTION_RECOVERY_ANALYSER, error))?,
            );
        }
        let coverage = &mut self.continuation_coverage;
        if let Some(coverage) = coverage.as_mut() {
            coverage.pending.reserve(expected_functions);
        }
        // per pass state
        let mut new_functions = FunctionConfidenceMap::default();

        tracing::debug!("existing functions: {}", project_functions.len());

        loop {
            self.cancellation.check()?;
            let mut yield_after_pass = false;

            while !self.candidates.is_empty() {
                let batch_capacity = self
                    .candidates
                    .len()
                    .min(DEFAULT_FUNCTION_RECOVERY_CHUNK_CANDIDATES);
                let mut batch = Vec::with_capacity(batch_capacity);
                let mut batch_addresses = FxHashSet::default();
                let mut replacements = BTreeMap::new();
                batch_addresses.reserve(batch_capacity);
                while batch.len() < DEFAULT_FUNCTION_RECOVERY_CHUNK_CANDIDATES {
                    let Some(candidate) = self.candidates.pop_front() else {
                        break;
                    };
                    let original_address = candidate.address();
                    let replacing = self.reanalysis_candidates.contains(&original_address);
                    self.cancellation.check()?;
                    self.progress.advance(1);
                    chunk_candidates += 1;

                    let at_limit = chunk_limit_reached(
                        chunk_output_bytes,
                        chunk_functions,
                        chunk_candidates,
                        !self.candidates.is_empty(),
                    );
                    let candidate = match resolver_slot.as_mut() {
                        Some(resolver) => {
                            let confidence = candidate.confidence();
                            let (address, context) = candidate.into_parts();
                            self.builder
                                .context_mut()
                                .function_entry_after_padding(
                                    project.segments(),
                                    project.arch(),
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
                            updates.push(ProjectUpdate::remove_function(original_address));
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
                            updates.push(ProjectUpdate::remove_function(original_address));
                            function_changes = true;
                        }
                    } else if let Some(reason) = inputs.problems.exclusion_at(address) {
                        tracing::trace!("skipping {address}: {reason}");
                        if replacing {
                            self.reanalysis_candidates.remove(&original_address);
                            updates.push(ProjectUpdate::remove_function(original_address));
                            function_changes = true;
                        }
                    } else if (!replacing
                        && FunctionConfidenceMap::candidate_known(
                            project_functions,
                            &self.pending_functions,
                            &functions,
                            &new_functions,
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
                let cancellation = &self.cancellation;
                let commit_hook = &self.commit_hook;
                let pending_functions = &mut self.pending_functions;
                let reanalysis_candidates = &mut self.reanalysis_candidates;
                let candidates = &mut self.candidates;
                let discovered_targets = &mut self.discovered_targets;
                let mut handle_outcome = |mut outcome: FunctionCandidateOutcome,
                                          discovered_targets: &mut Vec<AddressWithContext>|
                 -> Result<bool, AnalysisError> {
                    let address = outcome.address();
                    let confidence = outcome.confidence();
                    let replacement = replacements.remove(&address);
                    if let Some(replacement) = replacement {
                        reanalysis_candidates.remove(&replacement);
                    }
                    for (problem_address, kind) in outcome.drain_problems() {
                        updates.push(ProjectUpdate::add_problem(problem_address, kind));
                    }

                    let function = match outcome.take_result() {
                        Ok(ControlFlow::Continue(function)) => function,
                        Ok(ControlFlow::Break(cancelled)) => return Err(cancelled.into()),
                        Err(error) => {
                            let kind = error.problem_kind();
                            tracing::trace!("failed to analyse {address}: {error}");
                            updates.push(ProjectUpdate::add_problem(address, kind));
                            if let Some(replacement) = replacement {
                                updates.push(ProjectUpdate::remove_function(replacement));
                                function_changes = true;
                            }
                            return Ok(false);
                        }
                    };
                    if let Some(coverage) = coverage.as_mut() {
                        coverage.insert(&function);
                    }
                    let commit_context = FunctionRecoveryCommitContext::new(function, confidence);
                    let should_commit = commit_hook
                        .should_commit(project, &commit_context)
                        .map_err(|error| {
                            AnalysisError::pass_failed(FUNCTION_RECOVERY_ANALYSER, error)
                        })?;
                    let function = commit_context.into_function();
                    let function_bytes = function.estimate_size();
                    if let Some(replacement) = replacement.filter(|&entry| entry != address) {
                        updates.push(ProjectUpdate::remove_function(replacement));
                        function_changes = true;
                    }
                    let should_yield = should_commit
                        && Self::exceeds_remaining_output(
                            chunk_output_byte_limit,
                            chunk_output_bytes,
                            function_bytes,
                        );
                    if should_commit && !should_yield {
                        Self::stage_function_updates(updates, address, function);
                        chunk_output_bytes = chunk_output_bytes.saturating_add(function_bytes);
                        chunk_functions += 1;
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
                            project_functions,
                            pending_functions,
                            &functions,
                            &new_functions,
                            start,
                        ) && inputs.problems.exclusion_at(start).is_none()
                        {
                            discovered_targets.push(candidate);
                        }
                    }
                    discovered_targets.sort_unstable();
                    Ok(should_yield)
                };

                let builder_inputs = FunctionBuilderInputs::new(
                    &inputs.function_entries,
                    &inputs.non_returning_targets,
                );
                let batch = FunctionCandidateBatch::new(
                    project,
                    builder_inputs,
                    batch,
                    cancellation,
                    worker_limit,
                );
                let remaining = self.executor.analyse_candidates(
                    builder,
                    &mut resolver_slot,
                    batch,
                    |outcome| {
                        let should_yield = handle_outcome(outcome, discovered_targets)?;
                        candidates.extend(discovered_targets.drain(..));
                        Ok(should_yield)
                    },
                )?;
                if !remaining.is_empty() {
                    for candidate in remaining.into_iter().rev() {
                        candidates.push_front(candidate);
                    }
                    yield_after_pass = true;
                }

                if yield_after_pass
                    || chunk_limit_reached(
                        chunk_output_bytes,
                        chunk_functions,
                        chunk_candidates,
                        !self.candidates.is_empty(),
                    )
                {
                    yield_after_pass = true;
                    break;
                }
            }

            if function_changes || yield_after_pass {
                if function_changes {
                    self.finish_wave_after_admission();
                }
                tracing::debug!(
                    "yielding function recovery after {chunk_functions} committed functions and {chunk_candidates} processed candidates"
                );
                return Ok(());
            }

            // flush pass functions
            new_functions.iter().for_each(|(&address, &confidence)| {
                functions.insert(address, confidence);
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
                functions: mem::take(&mut functions),
                new_functions: mem::take(&mut new_functions),
                pending_functions: mem::take(&mut self.pending_functions),
                committed_functions: BTreeSet::new(),
                changed_functions: BTreeMap::new(),
                removed_functions: BTreeSet::new(),
            };

            let updates_before_structuring = updates.len();
            let result = self
                .structuring_passes
                .analyse_with(project, &mut context)
                .map_err(|error| match error {
                    error @ AnalysisError::Cancelled(_) => error,
                    error => AnalysisError::pass_failed(FUNCTION_RECOVERY_ANALYSER, error),
                });

            if let Err(e) = result {
                // restore state
                *self.builder.avoids_mut() = context.avoids;
                return Err(e);
            }

            if let Some(coverage) = coverage.as_mut() {
                for function in context.pending_functions.values() {
                    coverage.insert(function);
                }
                coverage.flush();
            }

            self.candidates.append(&mut context.candidates);

            // remove any functions that were removed during restructuring
            for f in context.removed_functions {
                if context.pending_functions.remove(&f).is_some() {
                    continue;
                }

                updates.push(ProjectUpdate::remove_function(f));
            }

            for (f, properties) in context.changed_functions {
                updates.push(ProjectUpdate::set_function_properties(f, properties));
            }

            // commit any functions that were forced during restructuring
            for f in context.committed_functions {
                if Self::chunk_exhausted(
                    chunk_output_byte_limit,
                    chunk_function_limit,
                    chunk_output_bytes,
                    chunk_functions,
                ) {
                    break;
                }

                let Some(function) = context.pending_functions.get(&f) else {
                    continue;
                };
                let function_bytes = function.estimate_size();
                if Self::exceeds_remaining_output(
                    chunk_output_byte_limit,
                    chunk_output_bytes,
                    function_bytes,
                ) {
                    break;
                }
                let function = match context.pending_functions.remove(&f) {
                    Some(func) => func,
                    None => continue,
                };

                Self::stage_function_updates(updates, f, function);
                chunk_output_bytes = chunk_output_bytes.saturating_add(function_bytes);
                chunk_functions += 1;
            }
            self.pending_functions = mem::take(&mut context.pending_functions);

            if updates.len() != updates_before_structuring
                || chunk_functions != 0
                || !self.pending_functions.is_empty()
            {
                self.finish_wave_after_admission();
                *self.builder.avoids_mut() = context.avoids;
                tracing::debug!(
                    "yielding function recovery after {chunk_functions} committed functions and {chunk_candidates} processed candidates"
                );
                return Ok(());
            }

            if self.discovery_passes.is_empty() {
                *self.builder.avoids_mut() = context.avoids;
                functions = context.functions;
            } else {
                tracing::debug!(
                    "performing {} candidate discovery pass(es)",
                    self.discovery_passes.len()
                );
                self.cancellation.check()?;

                let mut context = FunctionDiscoveryContext {
                    config: context.config,
                    candidates: mem::take(&mut self.candidates),
                    avoids: context.avoids,
                    coverage: coverage
                        .take()
                        .expect("function coverage must be initialised"),
                    functions: context.functions,
                    new_functions: context.new_functions,
                };

                let result = self
                    .discovery_passes
                    .analyse_with(project, &mut context)
                    .map_err(|error| match error {
                        error @ AnalysisError::Cancelled(_) => error,
                        error => AnalysisError::pass_failed(FUNCTION_RECOVERY_ANALYSER, error),
                    });

                self.candidates = context.candidates;
                *self.builder.avoids_mut() = context.avoids;

                *coverage = Some(context.coverage);
                functions = context.functions;

                result?;
            }

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
            self.stage_pending_functions(
                updates,
                chunk_output_byte_limit,
                chunk_function_limit,
                &mut chunk_output_bytes,
                &mut chunk_functions,
            );
            if chunk_functions != 0 {
                self.finish_wave_after_admission();
                tracing::debug!(
                    "yielding function recovery after {chunk_functions} committed functions and {chunk_candidates} processed candidates"
                );
                return Ok(());
            }
        }

        let elapsed = t.elapsed();

        drop(function_recovery_span);
        drop(span);

        let num_functions = project_functions.len() + chunk_functions;

        tracing::debug!(
            "function recovery completed in {}s ({}ms) with {num_functions} functions",
            elapsed.as_secs(),
            elapsed.as_millis(),
        );
        self.progress.clear_message();
        self.continuation_coverage = None;
        self.boundary_reconciliation_pending = false;
        self.recovery_active = false;
        self.wave_active = false;
        self.wave_inputs = None;

        Ok(())
    }

    pub fn build_analyser(project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
        let mut recovery = Self::new();
        recovery.set_chunk_output_byte_limit(Some(DEFAULT_FUNCTION_RECOVERY_CHUNK_OUTPUT_BYTES));
        recovery.set_chunk_candidate_limit(Some(DEFAULT_FUNCTION_RECOVERY_CHUNK_CANDIDATES));
        recovery.set_chunk_function_limit(Some(DEFAULT_FUNCTION_RECOVERY_CHUNK_FUNCTIONS));
        let mut extensions = extension::iter::<FunctionRecoveryExtension>().collect::<Vec<_>>();
        extensions.sort_unstable_by_key(|extension| (extension.priority(), extension.name()));

        for extension in extensions {
            extension.apply(project, &mut recovery)?;
        }

        Ok(Box::new(recovery))
    }
}

impl FunctionRecovery {
    pub fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        loop {
            let (result, reads, updates) = {
                let view = ProjectView::new(project);
                let mut updates = Vec::new();
                let result = self.analyse_view(&view, &mut updates);
                let reads = view.into_reads();
                (result, reads, updates)
            };
            if let Err(error) = &result
                && !matches!(error, AnalysisError::Cancelled(_))
            {
                return result;
            }

            let mut transaction = project.transaction("function recovery");
            transaction.absorb_reads(&reads);
            ProjectUpdate::apply_all(updates, &mut transaction)
                .map_err(|error| AnalysisError::pass_failed(FUNCTION_RECOVERY_ANALYSER, error))?;
            transaction
                .commit()
                .map_err(|error| AnalysisError::pass_failed(FUNCTION_RECOVERY_ANALYSER, error))?;
            result?;

            let bounded = self.chunk_output_byte_limit.is_some()
                || self.chunk_function_limit.is_some()
                || self.chunk_candidate_limit.is_some();
            if bounded || !Analyser::has_pending_work(self) {
                return Ok(());
            }
        }
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

    fn can_analyse(&self, project: &Project) -> bool {
        let _ = project;
        true
    }

    fn analyse(
        &mut self,
        project: &ProjectView<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        self.set_cancellation_token(cx.cancellation().clone());
        self.progress = cx.progress().clone();

        if cx.is_continuation() {
            self.analyse_candidates(project, updates, cx.worker_limit())
        } else {
            self.continuation_coverage = None;
            self.boundary_reconciliation_pending = false;
            self.recovery_active = false;
            self.wave_active = false;
            self.wave_inputs = None;
            self.start_recovery(project)?;
            self.analyse_regions(project, updates, regions, cx)
        }
    }

    fn has_pending_work(&self) -> bool {
        self.boundary_reconciliation_pending
            || !self.candidates.is_empty()
            || (self.config().commit_pending_functions() && !self.pending_functions.is_empty())
    }
}

submit! {
    AnalyserProvider::new(FUNCTION_RECOVERY_ANALYSER, FunctionRecovery::build_analyser)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::storage::TransientStorageProvider;

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

    #[test]
    fn observing_an_exhausted_candidate_does_not_increment_attempts()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project =
            Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;
        let address = project
            .entry_point()
            .ok_or("fixture must have an entry point")?;

        for _ in 0..DEFAULT_FUNCTION_RECOVERY_MAX_ATTEMPTS {
            let mut transaction = project.transaction("test");
            transaction.add_problem(address, ProblemKind::DecodeFailed)?;
            transaction.commit()?;
        }

        for _ in 0..3 {
            let view = ProjectView::new(&project);
            assert_eq!(
                FunctionRecoveryProblems::new(&view).exclusion_at(address),
                Some(CandidateExclusionReason::RetriesExhausted(
                    ProblemKind::DecodeFailed
                ))
            );
        }

        assert_eq!(
            project
                .problems()
                .get(address, ProblemKind::DecodeFailed)
                .ok_or("problem must remain current")?
                .attempts(),
            DEFAULT_FUNCTION_RECOVERY_MAX_ATTEMPTS
        );

        Ok(())
    }
}
