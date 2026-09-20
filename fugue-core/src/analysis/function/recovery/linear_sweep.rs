use std::mem;

use crate::analysis::function::recovery::analysis::FunctionDiscoveryContext;
use crate::analysis::function::recovery::{FunctionRecovery, FunctionRecoveryExtension};
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::arch::Arch;
use crate::engine::{AnalysisContext, ProjectView};
use crate::ir::{Address, AddressRange, AddressWithContext};
use crate::lifter::{ContextSet, InsnResolver, LiftingContext};
use crate::project::Project;
use crate::storage::{
    AddressSpaceId, SegmentMappingCache, SegmentMappingProvenance, SegmentMappingView,
};
use crate::types::Confidence;

const LINEAR_SWEEP_ANALYSER: &str = "linear-sweep";

const DEFAULT_MIN_ZERO_FILL_BYTES: usize = 16;
const DEFAULT_MAX_TRIAL_INSNS: usize = 16;
const DEFAULT_MIN_POST_BOUNDARY_INSNS: usize = 4;
const DEFAULT_MIN_ENTRY_MARKER_INSNS: usize = 2;
const DEFAULT_MIN_CALL_TARGET_INSNS: usize = 2;
const DEFAULT_CALL_TARGET_CORROBORATION_INSNS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinearSweepConfig {
    min_zero_fill_bytes: usize,
    max_trial_insns: usize,
    min_post_boundary_insns: usize,
    min_entry_marker_insns: usize,
    min_call_target_insns: usize,
    call_target_corroboration_insns: usize,
}

struct FunctionRecoveryLinearSweep {
    candidates: Vec<AddressWithContext>,
    config: LinearSweepConfig,
    scan_context: LiftingContext,
    scan_mappings: SegmentMappingCache,
    scan_resolver: InsnResolver,
    spaces: Vec<AddressSpaceId>,
    use_mapping_hints: bool,
    validation_context: LiftingContext,
    validation_mappings: SegmentMappingCache,
    validation_resolver: InsnResolver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinearSweepEvidence {
    EntryMarker,
    PostBoundary,
}

enum LinearSweepPrefix {
    Data(usize),
    Padding(usize),
    Unknown { entry_marker: bool },
}

impl Default for LinearSweepConfig {
    fn default() -> Self {
        Self {
            min_zero_fill_bytes: DEFAULT_MIN_ZERO_FILL_BYTES,
            max_trial_insns: DEFAULT_MAX_TRIAL_INSNS,
            min_post_boundary_insns: DEFAULT_MIN_POST_BOUNDARY_INSNS,
            min_entry_marker_insns: DEFAULT_MIN_ENTRY_MARKER_INSNS,
            min_call_target_insns: DEFAULT_MIN_CALL_TARGET_INSNS,
            call_target_corroboration_insns: DEFAULT_CALL_TARGET_CORROBORATION_INSNS,
        }
    }
}

impl LinearSweepConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn min_zero_fill_bytes(&self) -> usize {
        self.min_zero_fill_bytes
    }

    pub fn set_min_zero_fill_bytes(&mut self, size: usize) {
        self.min_zero_fill_bytes = size.max(1);
    }

    pub fn with_min_zero_fill_bytes(mut self, size: usize) -> Self {
        self.set_min_zero_fill_bytes(size);
        self
    }

    pub fn max_trial_insns(&self) -> usize {
        self.max_trial_insns
    }

    pub fn set_max_trial_insns(&mut self, count: usize) {
        self.max_trial_insns = count.max(1);
    }

    pub fn with_max_trial_insns(mut self, count: usize) -> Self {
        self.set_max_trial_insns(count);
        self
    }

    pub fn min_post_boundary_insns(&self) -> usize {
        self.min_post_boundary_insns
    }

    pub fn set_min_post_boundary_insns(&mut self, count: usize) {
        self.min_post_boundary_insns = count.max(1);
    }

    pub fn with_min_post_boundary_insns(mut self, count: usize) -> Self {
        self.set_min_post_boundary_insns(count);
        self
    }

    pub fn min_entry_marker_insns(&self) -> usize {
        self.min_entry_marker_insns
    }

    pub fn set_min_entry_marker_insns(&mut self, count: usize) {
        self.min_entry_marker_insns = count.max(1);
    }

    pub fn with_min_entry_marker_insns(mut self, count: usize) -> Self {
        self.set_min_entry_marker_insns(count);
        self
    }

    pub fn min_call_target_insns(&self) -> usize {
        self.min_call_target_insns
    }

    pub fn set_min_call_target_insns(&mut self, count: usize) {
        self.min_call_target_insns = count.max(1);
    }

    pub fn with_min_call_target_insns(mut self, count: usize) -> Self {
        self.set_min_call_target_insns(count);
        self
    }

    pub fn call_target_corroboration_insns(&self) -> usize {
        self.call_target_corroboration_insns
    }

    pub fn set_call_target_corroboration_insns(&mut self, count: usize) {
        self.call_target_corroboration_insns = count.max(1);
    }

    pub fn with_call_target_corroboration_insns(mut self, count: usize) -> Self {
        self.set_call_target_corroboration_insns(count);
        self
    }
}

impl LinearSweepEvidence {
    fn confidence(&self) -> Confidence {
        match self {
            Self::EntryMarker => Confidence::somewhat_certain(),
            Self::PostBoundary => Confidence::uncertain(),
        }
    }

    fn minimum_insns(&self, config: &LinearSweepConfig) -> usize {
        match self {
            Self::EntryMarker => config.min_entry_marker_insns(),
            Self::PostBoundary => config.min_post_boundary_insns(),
        }
    }
}

impl FunctionRecoveryLinearSweep {
    fn new(arch: &Arch, config: LinearSweepConfig, use_mapping_hints: bool) -> Self {
        let scan_resolver = InsnResolver::new(arch);
        let scan_context = scan_resolver.context().clone();
        let validation_resolver = InsnResolver::new(arch);
        let validation_context = validation_resolver.context().clone();

        Self {
            candidates: Vec::new(),
            config,
            scan_context,
            scan_mappings: SegmentMappingCache::new(),
            scan_resolver,
            spaces: Vec::new(),
            use_mapping_hints,
            validation_context,
            validation_mappings: SegmentMappingCache::new(),
            validation_resolver,
        }
    }

    fn classify(
        &mut self,
        arch: &Arch,
        view: &SegmentMappingView<'_>,
        address: Address,
        bytes: &[u8],
        use_mapping_hints: bool,
    ) -> LinearSweepPrefix {
        if use_mapping_hints
            && let Some(hint) = view
                .mapping_hints()
                .take_while(|(hint_address, _)| *hint_address <= address)
                .last()
                .map(|(_, hint)| hint)
        {
            if hint.is_data() {
                let size = view
                    .mapping_hints()
                    .map(|(hint_address, _)| hint_address)
                    .find(|hint_address| *hint_address > address)
                    .map_or_else(
                        || {
                            view.range()
                                .remaining_from(address)
                                .and_then(|size| usize::try_from(size).ok())
                                .unwrap_or(usize::MAX)
                        },
                        |boundary| {
                            usize::try_from(
                                boundary
                                    .raw_address()
                                    .checked_offset_from(address.raw_address())
                                    .expect("mapping hint follows the current address"),
                            )
                            .unwrap_or(usize::MAX)
                        },
                    );
                return LinearSweepPrefix::Data(size.max(1));
            }

            if let Some(context) = hint.context() {
                context.apply(address, self.scan_resolver.context_mut());
            }
        }

        let (size, properties) = arch.classify_contiguous_bytes(
            address.raw_address(),
            self.scan_resolver.context(),
            bytes,
        );
        if size != 0 && size <= bytes.len() && properties.is_padding() {
            return LinearSweepPrefix::Padding(size);
        }

        let zero_fill = bytes.iter().take_while(|byte| **byte == 0).count();
        if zero_fill >= self.config.min_zero_fill_bytes() {
            return LinearSweepPrefix::Data(zero_fill);
        }

        LinearSweepPrefix::Unknown {
            entry_marker: size != 0 && size <= bytes.len() && properties.is_entry_insn(),
        }
    }

    fn scan_space(
        &mut self,
        project: &ProjectView<'_>,
        discovery: &mut FunctionDiscoveryContext,
        space_id: AddressSpaceId,
    ) -> usize {
        let mut emitted = 0usize;
        let mut ranges = discovery.unclaimed_ranges(space_id);

        while let Some(range) = ranges.next() {
            self.scan_range(project, range);
            for candidate in self.candidates.drain(..) {
                if ranges.is_avoided(candidate.address()) {
                    continue;
                }
                tracing::debug!("adding linear sweep candidate at {}", candidate.address(),);
                ranges.add_candidate(candidate);
                emitted += 1;
            }
        }

        emitted
    }

    fn scan_range(&mut self, project: &ProjectView<'_>, range: AddressRange) {
        let arch = project.arch();
        let alignment = project.language().address_alignment().max(1);
        let segments = project.segments();
        let mut cursor = range.start().align(alignment);
        let mut after_non_code = false;

        while cursor <= range.end() {
            let address = Address::new(range.space(), cursor);
            let Some(view) = self.scan_mappings.view_containing(segments, address) else {
                break;
            };
            let region_end = view.last().raw_address().min(range.end());
            let Some(bytes_view) = view.bytes_from(address) else {
                break;
            };
            let Some(all_bytes) = bytes_view.as_contiguous().filter(|bytes| !bytes.is_empty())
            else {
                break;
            };
            let region_size = AddressRange::new(range.space(), cursor, region_end).size();
            let region_size = usize::try_from(region_size).unwrap_or(usize::MAX);
            let bytes = &all_bytes[..all_bytes.len().min(region_size)];
            if bytes.is_empty() {
                break;
            }

            self.scan_resolver
                .context_mut()
                .clone_from(&self.scan_context);

            let mut offset = 0usize;
            while offset < bytes.len() {
                let address = Address::new(range.space(), cursor + offset);
                let remaining = &bytes[offset..];
                let prefix = self.classify(arch, &view, address, remaining, self.use_mapping_hints);

                let step = match prefix {
                    LinearSweepPrefix::Data(size) | LinearSweepPrefix::Padding(size) => {
                        after_non_code = true;
                        size
                    }
                    LinearSweepPrefix::Unknown { entry_marker } => {
                        let evidence = entry_marker
                            .then_some(LinearSweepEvidence::EntryMarker)
                            .or_else(|| {
                                after_non_code.then_some(LinearSweepEvidence::PostBoundary)
                            });
                        after_non_code = false;

                        if let Some(evidence) = evidence
                            && let Some(candidate) =
                                self.validate_candidate(project, address, evidence)
                        {
                            self.candidates.push(candidate);
                        }

                        self.scan_resolver
                            .resolve(address, remaining)
                            .ok()
                            .map(|resolved| resolved.as_ref().size())
                            .filter(|size| *size != 0 && *size <= remaining.len())
                            .unwrap_or(alignment)
                    }
                }
                .max(1)
                .min(remaining.len());

                offset += step;
            }

            let Some(next) = region_end.checked_add(1usize) else {
                break;
            };
            cursor = next.align(alignment);
        }
    }

    fn validate_candidate(
        &mut self,
        project: &ProjectView<'_>,
        address: Address,
        evidence: LinearSweepEvidence,
    ) -> Option<AddressWithContext> {
        let arch = project.arch();
        let (canonical, derived) = arch.canonicalise_address(address.raw_address())?;
        let address = Address::new(address.space(), canonical);
        let mut contexts = Vec::with_capacity(3);
        contexts.push(derived);

        if let Some(previous) = address.raw_address().checked_sub(1usize)
            && let Some(block) = project
                .blocks()
                .overlaps_address(Address::new(address.space(), previous))
                .find(|block| block.last_address().raw_address() == previous)
        {
            let context = block.context().clone();
            if !contexts.contains(&context) {
                contexts.push(context);
            }
        }

        if !contexts.iter().any(ContextSet::is_empty) {
            contexts.push(ContextSet::new());
        }

        let minimum_insns = evidence.minimum_insns(&self.config);
        contexts.into_iter().find_map(|context| {
            self.validate_with_context(project, address, context, minimum_insns)
                .map(|(address, context)| {
                    AddressWithContext::new_with(address, context, evidence.confidence())
                })
        })
    }

    fn validate_with_context(
        &mut self,
        project: &ProjectView<'_>,
        address: Address,
        mut context: ContextSet,
        minimum_insns: usize,
    ) -> Option<(Address, ContextSet)> {
        let arch = project.arch();
        let segments = project.segments();
        let use_mapping_hints = self.use_mapping_hints;

        self.validation_resolver
            .context_mut()
            .clone_from(&self.validation_context);
        context.apply(address, self.validation_resolver.context_mut());
        let (canonical, derived) = arch
            .canonicalise_address_with(address.raw_address(), self.validation_resolver.context())?;
        let address = Address::new(address.space(), canonical);
        context.merge(&derived);
        context.apply(address, self.validation_resolver.context_mut());

        let view = self
            .validation_mappings
            .view_containing(segments, address)?;
        if !view.properties().is_executable() {
            return None;
        }

        if use_mapping_hints
            && let Some(hint) = view
                .mapping_hints()
                .take_while(|(hint_address, _)| *hint_address <= address)
                .last()
                .map(|(_, hint)| hint)
        {
            if hint.is_data() {
                return None;
            }
            if let Some(hinted) = hint.context() {
                context.merge(hinted);
                context.apply(address, self.validation_resolver.context_mut());
            }
        }

        let bytes_view = view.bytes_from(address)?;
        let all_bytes = bytes_view
            .as_contiguous()
            .filter(|bytes| !bytes.is_empty())?;
        let bytes_size = view.range().remaining_from(address)?;
        let bytes_size = usize::try_from(bytes_size).unwrap_or(usize::MAX);
        let bytes = &all_bytes[..all_bytes.len().min(bytes_size)];
        let mut mapping_hints = view
            .mapping_hints()
            .filter(|(hint_address, _)| *hint_address > address)
            .peekable();
        let mut offset = 0usize;
        let mut resolved_insns = 0usize;
        let mut terminated = false;

        while resolved_insns < self.config.max_trial_insns() && offset < bytes.len() {
            let insn_address = address + offset;

            if use_mapping_hints
                && let Some((hint_address, hint)) = mapping_hints.peek().copied()
                && hint_address == insn_address
            {
                if hint.is_data() {
                    break;
                }
                if let Some(hinted) = hint.context() {
                    hinted.apply(insn_address, self.validation_resolver.context_mut());
                }
                mapping_hints.next();
            }

            let resolved = self
                .validation_resolver
                .resolve(insn_address, &bytes[offset..])
                .ok()?;
            let insn = resolved.as_ref();
            if insn.size() == 0
                || insn.size() > bytes.len() - offset
                || insn.is_invalid()
                || insn.is_nonsense()
            {
                break;
            }

            let insn_bytes = &bytes[offset..offset + insn.size()];
            let properties = arch.classify_bytes(insn_bytes);
            if properties.is_nonsense() || properties.is_padding() {
                break;
            }

            if use_mapping_hints
                && mapping_hints.peek().is_some_and(|(hint_address, hint)| {
                    hint.is_data() && *hint_address < insn.next_address()
                })
            {
                break;
            }

            let escapes_executable_mappings = insn.is_flow()
                && insn.iter_targets().any(|(target, _, target_address)| {
                    if target.is_fall_through() {
                        return false;
                    }
                    let Some((canonical, _)) =
                        arch.canonicalise_address(target_address.raw_address())
                    else {
                        return true;
                    };
                    let target_address = Address::new(target_address.space(), canonical);
                    self.validation_mappings
                        .view_containing(segments, target_address)
                        .is_none_or(|view| {
                            !view.properties().is_executable()
                                && view.provenance() != SegmentMappingProvenance::External
                        })
                });
            if escapes_executable_mappings {
                break;
            }

            resolved_insns += 1;
            if !insn.has_fall_through() {
                terminated = true;
                break;
            }
            offset += insn.size();
        }

        ((terminated || resolved_insns == self.config.max_trial_insns())
            && resolved_insns >= minimum_insns)
            .then_some((address, context))
    }
}

impl AnalysisPass<FunctionDiscoveryContext> for FunctionRecoveryLinearSweep {
    fn analyse_with(
        &mut self,
        context: &mut AnalysisContext<'_, '_>,
        discovery: &mut FunctionDiscoveryContext,
    ) -> Result<(), AnalysisError> {
        let project = &context.project;
        self.spaces.clear();
        self.spaces
            .extend(project.segments().spaces().map(|space| space.id()));

        let spaces = mem::take(&mut self.spaces);
        for space_id in spaces.iter().copied() {
            self.scan_space(project, discovery, space_id);
        }
        self.spaces = spaces;

        Ok(())
    }
}

#[fugue_core::extension]
impl FunctionRecoveryExtension {
    const NAME: &str = "linear-sweep";

    fn configure(project: &Project, recovery: &mut FunctionRecovery) -> Result<(), AnalysisError> {
        let Some(config) = recovery.config().linear_sweep().copied() else {
            return Ok(());
        };

        recovery.add_candidate_discovery_pass(
            LINEAR_SWEEP_ANALYSER,
            FunctionRecoveryLinearSweep::new(
                project.arch(),
                config,
                recovery.config().segment_mapping_hints(),
            ),
        );

        Ok(())
    }
}
