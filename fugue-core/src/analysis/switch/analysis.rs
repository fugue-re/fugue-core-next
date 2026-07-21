use fugue_bv::BitVec;
use fugue_bytes::Endian;
use fugue_specs::Confidence;

use crate::analysis::control::Cancelled;
use crate::analysis::function::recovery::{PartialFunctionWithContext, Translator};
use crate::analysis::switch::idiom::{OffsetBase, SwitchIdiomMatcher};
use crate::analysis::switch::slice::SwitchSliceEvaluator;
use crate::analysis::switch::{RecoveredSwitch, SwitchRecoveryConfig, SwitchTargetResolver};
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::arch::Arch;
use crate::il::common::IlError;
use crate::il::ecode::ssa::ECodeToSsa;
use crate::il::pcode::PCodeError;
use crate::ir::{
    Address, AddressTable, FlowKind, FunctionId, SwitchCase, SwitchCaseLabel, SwitchEvidence,
    SwitchId, SwitchModel,
};
use crate::lifter::{LiftingContext, PCodeOp};
use crate::project::Project;
use crate::storage::SegmentStorage;
use crate::storage::segments::SegmentReader;

#[derive(Default)]
pub struct SwitchRecovery {
    config: SwitchRecoveryConfig,
}

impl SwitchRecovery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with(config: SwitchRecoveryConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &SwitchRecoveryConfig {
        &self.config
    }

    fn switches_agree(a: &RecoveredSwitch, b: &RecoveredSwitch) -> bool {
        let table = |switch: &RecoveredSwitch| {
            switch
                .model()
                .table()
                .map(|table| (table.address(), table.element_size()))
        };
        table(a) == table(b)
    }

    fn reconcile(existing: RecoveredSwitch, candidate: RecoveredSwitch) -> Option<RecoveredSwitch> {
        if !Self::switches_agree(&existing, &candidate) {
            return None;
        }
        if candidate.cases().len() > existing.cases().len() {
            Some(candidate)
        } else {
            Some(existing)
        }
    }

    fn prefer_semantic(existing: &RecoveredSwitch, candidate: &RecoveredSwitch) -> bool {
        let guarded =
            |switch: &RecoveredSwitch| switch.evidence().contains(SwitchEvidence::GUARD_FOUND);
        match (guarded(existing), guarded(candidate)) {
            (false, true) => true,
            (true, false) => false,
            _ => candidate.cases().len() > existing.cases().len(),
        }
    }

    fn recover_syntactic(
        &self,
        arch: &Arch,
        segments: &SegmentStorage,
        branch: Address,
        operations: &[PCodeOp],
        context: &LiftingContext,
    ) -> Option<RecoveredSwitch> {
        let shape =
            SwitchIdiomMatcher::new(operations, self.config.max_trace_depth())?.recover()?;
        let element_size = shape.element_size();
        if element_size == 0 || element_size > self.config.max_element_size() {
            return None;
        }

        let space = branch.space();
        let mut table = AddressTable::new(Address::new(space, shape.table()), element_size)
            .with_shift(shape.shift());
        let mut resolver = SwitchTargetResolver::new(arch, segments, space);
        let mut entries = SegmentReader::new(segments);
        let endian = arch.endian();
        let limit = self.entry_limit(shape.bound());

        let mut cases = Vec::new();
        let mut buffer = vec![0u8; element_size as usize];

        for index in 0..limit {
            if entries
                .read_bytes_exact(table.entry_address(index as u32), &mut buffer)
                .is_err()
            {
                break;
            }

            let value = Self::decode_entry(&table, &buffer, endian);
            let target_value = Self::relative_target(&value, shape.base());
            let Some(target) = resolver.resolve(&target_value, context) else {
                break;
            };

            let mut case = SwitchCase::new(target);
            case.add_label(SwitchCaseLabel::new(
                (index as i64).wrapping_add(shape.label_offset()) as u64,
            ));
            cases.push(case);
        }

        if cases.is_empty() {
            return None;
        }

        table.set_element_count(cases.len() as u32);
        let guarded = shape.bound().is_some();
        let truncated = shape
            .bound()
            .and_then(BitVec::to_u64)
            .is_some_and(|bound| (cases.len() as u64) <= bound);
        let table_start = Address::new(space, shape.table());
        let mut evidence = Self::evidence(guarded, truncated);
        if entries
            .properties(table_start)
            .is_some_and(|props| props.is_readable() && !props.is_writable())
        {
            evidence |= SwitchEvidence::TABLE_IN_READ_ONLY;
        }
        let alignment = arch.language().address_alignment() as u64;
        if alignment <= 1
            || cases
                .iter()
                .all(|case| case.target().address().offset() % alignment == 0)
        {
            evidence |= SwitchEvidence::TARGETS_ALIGNED;
        }
        let model = match shape.base() {
            Some(base) => SwitchModel::OffsetRelative {
                table,
                base: base.address(),
                signed: base.is_signed(),
            },
            None => SwitchModel::Absolute(table),
        };

        Some(RecoveredSwitch::new(
            model,
            cases,
            Self::confidence(guarded, truncated),
            evidence,
        ))
    }

    fn entry_limit(&self, bound: Option<&BitVec>) -> u64 {
        let cap = self.config.max_cases() as u64;
        bound
            .and_then(BitVec::to_u64)
            .map_or(cap, |bound| bound.saturating_add(1).min(cap))
    }

    fn decode_entry(table: &AddressTable, bytes: &[u8], endian: Endian) -> BitVec {
        let raw = match endian {
            Endian::Big => BitVec::from_be_bytes(bytes),
            Endian::Little => BitVec::from_le_bytes(bytes),
        };
        if table.shift() == 0 {
            return raw;
        }
        let bits = bytes.len() as u32 * 8 + table.shift() as u32;
        raw.unsigned_cast(bits) << BitVec::from_u64(table.shift() as u64, bits)
    }

    fn relative_target(value: &BitVec, base: Option<OffsetBase>) -> BitVec {
        match base {
            Some(base) => {
                let offset = if base.is_signed() {
                    value.signed_cast(u64::BITS)
                } else {
                    value.unsigned_cast(u64::BITS)
                };
                BitVec::from_u64(base.address().offset(), u64::BITS) + offset
            }
            None => value.unsigned_cast(u64::BITS),
        }
    }

    fn confidence(guarded: bool, truncated: bool) -> Confidence {
        if guarded && !truncated {
            Confidence::somewhat_certain()
        } else {
            Confidence::somewhat_uncertain()
        }
    }

    fn evidence(guarded: bool, truncated: bool) -> SwitchEvidence {
        let mut evidence =
            SwitchEvidence::TARGETS_IN_EXECUTABLE | SwitchEvidence::CONTIGUOUS_ENTRIES;
        if guarded {
            evidence |= SwitchEvidence::GUARD_FOUND;
        }
        if truncated {
            evidence |= SwitchEvidence::TRUNCATED;
        }
        evidence
    }

    fn map_pcode_error(error: PCodeError) -> AnalysisError {
        match error {
            PCodeError::Common(IlError::Cancelled) => AnalysisError::Cancelled(Cancelled),
            error => AnalysisError::pass_failed("switch-recovery", error),
        }
    }
}

impl AnalysisPass<PartialFunctionWithContext> for SwitchRecovery {
    fn analyse_with(
        &mut self,
        project: &mut Project,
        state: &mut PartialFunctionWithContext,
    ) -> Result<(), AnalysisError> {
        let mut resolved = Vec::new();
        {
            let arch = project.arch();
            let segments = project.segments();
            let mut translator = Translator::new(project);
            let mut reader = SegmentReader::new(segments);
            let function = state.function();
            let mut branches = function.indirect_branches().peekable();
            if branches.peek().is_none() {
                return Ok(());
            }
            let mut ops = Vec::new();
            let mut unresolved = Vec::new();
            let mut retry = Vec::new();

            for (block_index, site) in branches {
                let Some(block) = function.blocks().get(block_index) else {
                    continue;
                };
                let predecessors = block.predecessors();

                let mut outcome = None;
                let mut ambiguous = false;

                let sources = predecessors
                    .iter()
                    .copied()
                    .map(Some)
                    .chain(predecessors.is_empty().then_some(None));
                for source in sources {
                    ops.clear();
                    if let Some(predecessor) = source
                        && function
                            .append_block_pcode(predecessor, &mut reader, &mut translator, &mut ops)
                            .is_err()
                    {
                        continue;
                    }
                    if function
                        .append_block_pcode(block_index, &mut reader, &mut translator, &mut ops)
                        .is_err()
                    {
                        continue;
                    }

                    let Some(candidate) =
                        self.recover_syntactic(arch, segments, site, &ops, translator.context())
                    else {
                        continue;
                    };
                    outcome = match outcome.take() {
                        None => Some(candidate),
                        Some(existing) => match Self::reconcile(existing, candidate) {
                            Some(recovered) => Some(recovered),
                            None => {
                                ambiguous = true;
                                break;
                            }
                        },
                    };
                }

                match (ambiguous, outcome) {
                    (false, Some(recovered)) => {
                        tracing::debug!(
                            "recovered switch at {} with {} cases (confidence {})",
                            site,
                            recovered.cases().len(),
                            recovered.confidence(),
                        );
                        if !recovered.evidence().contains(SwitchEvidence::GUARD_FOUND) {
                            retry.push((block_index, site));
                        }
                        resolved.push((site, recovered));
                    }
                    _ => unresolved.push((block_index, site)),
                }
            }

            if !unresolved.is_empty() || !retry.is_empty() {
                match ECodeToSsa
                    .build_partial_function_tolerant(
                        project.language(),
                        function,
                        project.segments(),
                        0,
                        state.cancellation(),
                    )
                    .map_err(Self::map_pcode_error)
                {
                    Ok(local) => {
                        if let Some(ssa) = local.ir() {
                            let evaluator =
                                SwitchSliceEvaluator::new(ssa, arch, segments, self.config);

                            for (block_index, site) in unresolved {
                                let block = &function.blocks()[block_index];
                                if local.omits(block.address()) {
                                    continue;
                                }
                                if let Some(recovered) =
                                    evaluator.recover(site, block.context(), &mut translator)
                                {
                                    tracing::debug!(
                                        "recovered switch at {} with {} cases (confidence {})",
                                        site,
                                        recovered.cases().len(),
                                        recovered.confidence(),
                                    );
                                    resolved.push((site, recovered));
                                }
                            }

                            for (block_index, site) in retry {
                                let block = &function.blocks()[block_index];
                                if local.omits(block.address()) {
                                    continue;
                                }
                                let Some(recovered) =
                                    evaluator.recover(site, block.context(), &mut translator)
                                else {
                                    continue;
                                };
                                if let Some((_, existing)) =
                                    resolved.iter_mut().find(|(existing, _)| *existing == site)
                                    && Self::prefer_semantic(existing, &recovered)
                                {
                                    *existing = recovered;
                                }
                            }
                        }
                    }
                    Err(error @ AnalysisError::Cancelled(_)) => return Err(error),
                    Err(error) => {
                        tracing::debug!(
                            "skipping semantic switch recovery for function at {}: {error}",
                            function.entry(),
                        );
                    }
                }
            }
        }

        for (site, recovered) in resolved {
            if let Some(existing) = project.switches().get_by_branch(site)
                && (existing.is_override()
                    || existing.is_assisted()
                    || (existing
                        .provenance()
                        .evidence()
                        .contains(SwitchEvidence::GUARD_FOUND)
                        && !recovered.evidence().contains(SwitchEvidence::GUARD_FOUND)))
            {
                continue;
            }

            for case in recovered.cases() {
                state.context_mut().add_local_target_with_context(
                    site,
                    case.target().clone(),
                    FlowKind::SwitchBranch,
                );
            }

            let switch = recovered.into_switch(SwitchId::default(), FunctionId::INVALID, site);
            state.function_mut().add_pending_switch(switch);
        }

        Ok(())
    }
}
