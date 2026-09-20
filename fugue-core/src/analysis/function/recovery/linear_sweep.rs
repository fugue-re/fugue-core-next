use crate::analysis::function::recovery::analysis::FunctionDiscoveryContext;
use crate::analysis::function::recovery::{FunctionRecovery, FunctionRecoveryExtension};
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::arch::Arch;
use crate::engine::{AnalysisContext, ProjectView};
use crate::ir::{Address, AddressRange, AddressWithContext, Insn};
use crate::lifter::{ContextSet, InsnResolver, InsnResolverError, LiftingContext};
use crate::project::Project;
use crate::storage::{
    AddressSpaceId, SegmentMappingCache, SegmentMappingProvenance, SegmentMappingView,
    SegmentStorage,
};
use crate::types::Confidence;

const LINEAR_SWEEP_ANALYSER: &str = "linear-sweep";

const DEFAULT_MIN_ZERO_FILL_BYTES: usize = 16;
const DEFAULT_MAX_TRIAL_INSNS: usize = 16;
const DEFAULT_MIN_POST_BOUNDARY_INSNS: usize = 4;
const DEFAULT_MIN_ENTRY_MARKER_INSNS: usize = 2;
const DEFAULT_MIN_CALL_TARGET_INSNS: usize = 2;
const DEFAULT_MIN_CALL_SITE_INSNS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinearSweepConfig {
    min_zero_fill_bytes: usize,
    max_trial_insns: usize,
    min_post_boundary_insns: usize,
    min_entry_marker_insns: usize,
    min_call_target_insns: usize,
    min_call_site_insns: usize,
}

struct FunctionRecoveryLinearSweep {
    candidates: Vec<AddressWithContext>,
    config: LinearSweepConfig,
    use_mapping_hints: bool,
    scan: LinearSweepResolver,
    validation: LinearSweepResolver,
}

struct LinearSweepResolver {
    initial_context: LiftingContext,
    mapping_cache: SegmentMappingCache,
    resolver: InsnResolver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinearSweepEvidence {
    CallTarget,
    EntryMarker,
    EstablishedCallSite,
    PostBoundary,
}

enum LinearSweepProperties {
    Data(usize),
    Padding(usize),
    Unknown { entry_marker: bool },
}

enum LinearSweepScan {
    Boundaries { after_non_code: bool },
    CallTargets { consecutive_insns: usize },
}

impl Default for LinearSweepConfig {
    fn default() -> Self {
        Self {
            min_zero_fill_bytes: DEFAULT_MIN_ZERO_FILL_BYTES,
            max_trial_insns: DEFAULT_MAX_TRIAL_INSNS,
            min_post_boundary_insns: DEFAULT_MIN_POST_BOUNDARY_INSNS,
            min_entry_marker_insns: DEFAULT_MIN_ENTRY_MARKER_INSNS,
            min_call_target_insns: DEFAULT_MIN_CALL_TARGET_INSNS,
            min_call_site_insns: DEFAULT_MIN_CALL_SITE_INSNS,
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

    pub fn min_call_site_insns(&self) -> usize {
        self.min_call_site_insns
    }

    pub fn set_min_call_site_insns(&mut self, count: usize) {
        self.min_call_site_insns = count.max(1);
    }

    pub fn with_min_call_site_insns(mut self, count: usize) -> Self {
        self.set_min_call_site_insns(count);
        self
    }
}

impl LinearSweepEvidence {
    fn confidence(&self) -> Confidence {
        match self {
            Self::CallTarget => Confidence::somewhat_uncertain(),
            Self::EntryMarker | Self::EstablishedCallSite => Confidence::somewhat_certain(),
            Self::PostBoundary => Confidence::uncertain(),
        }
    }

    fn minimum_insns(&self, config: &LinearSweepConfig) -> usize {
        match self {
            Self::EntryMarker => config.min_entry_marker_insns(),
            Self::PostBoundary => config.min_post_boundary_insns(),
            Self::CallTarget | Self::EstablishedCallSite => config.min_call_target_insns(),
        }
    }
}

impl LinearSweepResolver {
    fn new(arch: &Arch) -> Self {
        let resolver = InsnResolver::new(arch);
        let initial_context = resolver.context().clone();

        Self {
            initial_context,
            mapping_cache: SegmentMappingCache::new(),
            resolver,
        }
    }

    fn context(&self) -> &LiftingContext {
        self.resolver.context()
    }

    fn reset_context(&mut self) {
        self.resolver
            .context_mut()
            .clone_from(&self.initial_context);
    }

    fn apply_context(&mut self, address: Address, context: &ContextSet) {
        context.apply(address, self.resolver.context_mut());
    }

    fn resolve(&mut self, address: Address, bytes: &[u8]) -> Result<Insn, InsnResolverError> {
        self.resolver
            .resolve(address, bytes)
            .map(|resolved| resolved.into_insn())
    }

    fn view_containing<'a>(
        &mut self,
        segments: &'a SegmentStorage,
        address: Address,
    ) -> Option<SegmentMappingView<'a>> {
        self.mapping_cache.view_containing(segments, address)
    }
}

impl LinearSweepScan {
    fn new_boundaries() -> Self {
        Self::Boundaries {
            after_non_code: false,
        }
    }

    fn new_call_targets() -> Self {
        Self::CallTargets {
            consecutive_insns: 0,
        }
    }
}

impl FunctionRecoveryLinearSweep {
    fn new(arch: &Arch, config: LinearSweepConfig, use_mapping_hints: bool) -> Self {
        Self {
            candidates: Vec::new(),
            config,
            scan: LinearSweepResolver::new(arch),
            use_mapping_hints,
            validation: LinearSweepResolver::new(arch),
        }
    }

    fn classify(
        &mut self,
        arch: &Arch,
        view: &SegmentMappingView<'_>,
        address: Address,
        bytes: &[u8],
    ) -> LinearSweepProperties {
        if self.use_mapping_hints
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
                return LinearSweepProperties::Data(size.max(1));
            }

            if let Some(context) = hint.context() {
                self.scan.apply_context(address, context);
            }
        }

        let (size, insn_properties) =
            arch.classify_contiguous_bytes(address.raw_address(), self.scan.context(), bytes);
        if size != 0 && size <= bytes.len() && insn_properties.is_padding() {
            return LinearSweepProperties::Padding(size);
        }

        let zero_fill = bytes.iter().take_while(|byte| **byte == 0).count();
        if zero_fill >= self.config.min_zero_fill_bytes() {
            return LinearSweepProperties::Data(zero_fill);
        }

        LinearSweepProperties::Unknown {
            entry_marker: size != 0 && size <= bytes.len() && insn_properties.is_entry_insn(),
        }
    }

    fn scan_boundaries(
        &mut self,
        project: &ProjectView<'_>,
        space_id: AddressSpaceId,
        discovery: &mut FunctionDiscoveryContext,
    ) -> usize {
        let mut found = 0usize;
        let mut ranges = discovery.unclaimed_ranges(space_id);

        while let Some(range) = ranges.next() {
            let mut scan = LinearSweepScan::new_boundaries();
            self.scan_range(project, range, &mut scan);
            for candidate in self.candidates.drain(..) {
                if ranges.is_avoided(candidate.address()) {
                    continue;
                }
                tracing::debug!("adding linear sweep candidate at {}", candidate.address(),);
                ranges.add_candidate(candidate);
                found += 1;
            }
        }

        found
    }

    fn scan_range(
        &mut self,
        project: &ProjectView<'_>,
        range: AddressRange,
        scan: &mut LinearSweepScan,
    ) {
        let arch = project.arch();
        let alignment = project.language().address_alignment().max(1);
        let segments = project.segments();
        let mut cursor = range.start().align(alignment);

        while cursor <= range.end() {
            let address = Address::new(range.space(), cursor);
            let Some(view) = self.scan.view_containing(segments, address) else {
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

            self.scan.reset_context();

            let mut offset = 0usize;
            while offset < bytes.len() {
                let address = Address::new(range.space(), cursor + offset);
                let remaining = &bytes[offset..];
                let properties = self.classify(arch, &view, address, remaining);
                let step = match scan {
                    LinearSweepScan::Boundaries { after_non_code } => self.scan_boundary_candidate(
                        project,
                        address,
                        remaining,
                        properties,
                        after_non_code,
                    ),
                    LinearSweepScan::CallTargets { consecutive_insns } => self
                        .scan_call_target_candidate(
                            project,
                            address,
                            remaining,
                            properties,
                            consecutive_insns,
                        ),
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

    fn scan_call_targets(
        &mut self,
        project: &ProjectView<'_>,
        space_id: AddressSpaceId,
        discovery: &mut FunctionDiscoveryContext,
    ) {
        {
            let ranges = discovery.unclaimed_ranges(space_id);
            for range in ranges {
                let mut scan = LinearSweepScan::new_call_targets();
                self.scan_range(project, range, &mut scan);
            }
        }

        for candidate in self.candidates.drain(..) {
            if discovery.covered().contains(candidate.address())
                || discovery.avoids().contains(candidate.address())
            {
                continue;
            }
            tracing::debug!("adding linear sweep candidate at {}", candidate.address(),);
            discovery.add_candidate(candidate);
        }
    }

    fn scan_boundary_candidate(
        &mut self,
        project: &ProjectView<'_>,
        address: Address,
        bytes: &[u8],
        properties: LinearSweepProperties,
        after_non_code: &mut bool,
    ) -> usize {
        let alignment = project.language().address_alignment().max(1);
        match properties {
            LinearSweepProperties::Data(size) | LinearSweepProperties::Padding(size) => {
                *after_non_code = true;
                size
            }
            LinearSweepProperties::Unknown { entry_marker } => {
                let evidence = entry_marker
                    .then_some(LinearSweepEvidence::EntryMarker)
                    .or_else(|| after_non_code.then_some(LinearSweepEvidence::PostBoundary));
                *after_non_code = false;

                if let Some(evidence) = evidence
                    && let Some(candidate) = self.validate_candidate(project, address, evidence)
                {
                    self.candidates.push(candidate);
                }

                self.scan
                    .resolve(address, bytes)
                    .ok()
                    .map(|insn| insn.size())
                    .filter(|size| *size != 0 && *size <= bytes.len())
                    .unwrap_or(alignment)
            }
        }
    }

    fn scan_call_target_candidate(
        &mut self,
        project: &ProjectView<'_>,
        address: Address,
        bytes: &[u8],
        properties: LinearSweepProperties,
        consecutive_insns: &mut usize,
    ) -> usize {
        let arch = project.arch();
        let alignment = project.language().address_alignment().max(1);
        let LinearSweepProperties::Unknown { entry_marker } = properties else {
            *consecutive_insns = 0;
            return match properties {
                LinearSweepProperties::Data(size) | LinearSweepProperties::Padding(size) => size,
                LinearSweepProperties::Unknown { .. } => {
                    unreachable!("properties were matched above")
                }
            };
        };
        let Ok(insn) = self.scan.resolve(address, bytes) else {
            *consecutive_insns = 0;
            return alignment;
        };

        if insn.size() == 0 || insn.size() > bytes.len() || insn.is_invalid() || insn.is_nonsense()
        {
            *consecutive_insns = 0;
            return alignment;
        }

        let properties = arch.classify_bytes(&bytes[..insn.size()]);
        if properties.is_nonsense() || properties.is_padding() {
            *consecutive_insns = 0;
            return insn.size();
        }

        *consecutive_insns += 1;

        if entry_marker
            && let Some(candidate) =
                self.validate_candidate(project, address, LinearSweepEvidence::EntryMarker)
        {
            self.candidates.push(candidate);
        }

        if !insn.is_indirect()
            && let Some(target) = insn.call_target()
            && let Some((canonical, _)) = arch.canonicalise_address(target.raw_address())
        {
            let target = Address::new(target.space(), canonical);
            if target.space() == address.space() {
                let evidence = if *consecutive_insns >= self.config.min_call_site_insns() {
                    LinearSweepEvidence::EstablishedCallSite
                } else {
                    LinearSweepEvidence::CallTarget
                };
                if let Some(candidate) = self.validate_candidate(project, target, evidence) {
                    self.candidates.push(candidate);
                }
            }
        }

        if !insn.has_fall_through() {
            *consecutive_insns = 0;
        }
        insn.size()
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
        self.validation.reset_context();
        self.validation.apply_context(address, &context);
        let (canonical, derived) =
            arch.canonicalise_address_with(address.raw_address(), self.validation.context())?;
        let address = Address::new(address.space(), canonical);
        context.merge(&derived);
        self.validation.apply_context(address, &context);

        let view = self.validation.view_containing(segments, address)?;
        if !view.properties().is_executable() {
            return None;
        }

        if self.use_mapping_hints
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
                self.validation.apply_context(address, &context);
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

            if self.use_mapping_hints
                && let Some((hint_address, hint)) = mapping_hints.peek().copied()
                && hint_address == insn_address
            {
                if hint.is_data() {
                    break;
                }
                if let Some(hinted) = hint.context() {
                    self.validation.apply_context(insn_address, hinted);
                }
                mapping_hints.next();
            }

            let insn = self
                .validation
                .resolve(insn_address, &bytes[offset..])
                .ok()?;
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

            if self.use_mapping_hints
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
                    self.validation
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
        let found = project
            .segments()
            .spaces()
            .map(|space| self.scan_boundaries(project, space.id(), discovery))
            .sum::<usize>();
        if found == 0 {
            for space in project.segments().spaces() {
                self.scan_call_targets(project, space.id(), discovery);
            }
        }

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
