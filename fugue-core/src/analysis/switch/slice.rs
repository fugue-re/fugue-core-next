use std::collections::VecDeque;

use fugue_bv::BitVec;
use fugue_bytes::Endian;
use fugue_specs::Confidence;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::analysis::function::recovery::Translator;
use crate::analysis::switch::{RecoveredSwitch, SwitchRecoveryConfig, SwitchTargetResolver};
use crate::analysis::value::StridedInterval;
use crate::arch::Arch;
use crate::il::common::{IlBlockId, IlDominance, IlValueId};
use crate::il::ecode::ssa::{ECodeSsaIr, ECodeSsaOp, ECodeSsaOpcode, StridedIntervals};
use crate::ir::{
    Address, AddressTable, AddressWithContext, RawAddress, SwitchCase, SwitchCaseLabel,
    SwitchEvidence, SwitchModel,
};
use crate::lifter::ContextSet;
use crate::storage::SegmentStorage;
use crate::storage::segments::SegmentReader;
use crate::storage::segments::space::AddressSpaceId;

mod guard;

struct TableLayout {
    address: RawAddress,
    element_size: u32,
}

struct InlineTableLayout {
    address: RawAddress,
    stride: u32,
    index: IlValueId,
}

struct TargetEvaluation<'a> {
    space: AddressSpaceId,
    reader: SegmentReader<'a>,
    memo: FxHashMap<usize, BitVec>,
    stack: Vec<(IlValueId, bool)>,
    operands: Vec<BitVec>,
    buffer: Vec<u8>,
}

impl<'a> TargetEvaluation<'a> {
    fn new(space: AddressSpaceId, segments: &'a SegmentStorage) -> Self {
        Self {
            space,
            reader: SegmentReader::new(segments),
            memo: FxHashMap::default(),
            stack: Vec::new(),
            operands: Vec::new(),
            buffer: Vec::new(),
        }
    }
}

pub(crate) struct SwitchSliceEvaluator<'a> {
    ssa: &'a ECodeSsaIr,
    arch: &'a Arch,
    segments: &'a SegmentStorage,
    config: SwitchRecoveryConfig,
    intervals: StridedIntervals,
    dominance: IlDominance,
    operation_blocks: Vec<Option<IlBlockId>>,
    block_argument_sources: FxHashMap<IlValueId, Vec<IlValueId>>,
}

impl<'a> SwitchSliceEvaluator<'a> {
    pub(crate) fn new(
        ssa: &'a ECodeSsaIr,
        arch: &'a Arch,
        segments: &'a SegmentStorage,
        config: SwitchRecoveryConfig,
    ) -> Self {
        Self {
            ssa,
            arch,
            segments,
            config,
            intervals: StridedIntervals::build(ssa),
            dominance: ssa.dominance(),
            operation_blocks: Self::operation_blocks(ssa),
            block_argument_sources: ssa.block_argument_sources(),
        }
    }

    fn single_source_feeder(&self, value: IlValueId) -> Option<IlValueId> {
        let feeders = self.block_argument_sources.get(&value)?;
        let first = *feeders.first()?;
        feeders
            .iter()
            .all(|&feeder| feeder == first)
            .then_some(first)
    }

    fn operation_blocks(ssa: &ECodeSsaIr) -> Vec<Option<IlBlockId>> {
        let mut blocks = vec![None; ssa.operations().len()];
        for (block_index, block) in ssa.graph().blocks().iter().enumerate() {
            let block_id =
                IlBlockId::try_from_index(block_index).expect("block count fits the id space");
            blocks[block.operations().start()..block.operations().end()].fill(Some(block_id));
        }
        blocks
    }

    fn block_of_source(&self, address: Address) -> Option<IlBlockId> {
        let (operation, _) = self.ssa.operations_for_source(address).next()?;
        self.operation_blocks.get(operation).copied().flatten()
    }

    pub(crate) fn recover(
        &self,
        branch: Address,
        context: &ContextSet,
        translator: &mut Translator,
    ) -> Option<RecoveredSwitch> {
        let target = self.ssa.indirect_branch_input(branch)?;
        context.apply(branch, translator.context_mut());
        if let (Some(index), Some(layout)) = (self.scaled_index(target), self.table_layout(target))
        {
            return self.recover_loaded(branch, target, index, layout, context, translator);
        }
        if let Some(layout) = self.inline_table_layout(target) {
            return self.recover_inline(branch, layout, context, translator);
        }
        tracing::trace!("switch slice at {branch}: no idiom");
        None
    }

    fn recover_loaded(
        &self,
        branch: Address,
        target: IlValueId,
        index: IlValueId,
        layout: TableLayout,
        context: &ContextSet,
        translator: &mut Translator,
    ) -> Option<RecoveredSwitch> {
        let interval = self.index_interval(index, branch)?;

        let space = branch.space();
        let guarded = interval.upper() != StridedInterval::full(interval.width()).upper();
        let limit = interval
            .count()
            .map_or(self.config.max_cases() as usize, |count| {
                count.min(self.config.max_cases() as usize)
            });

        let mut resolver = SwitchTargetResolver::new(self.arch, self.segments, space);
        let mut evaluation = TargetEvaluation::new(space, self.segments);
        let mut cases = Vec::new();
        let label_offset = self.label_offset(index);

        for value in interval.iter().take(limit) {
            let Some(target_value) = self.evaluate_target(target, index, &value, &mut evaluation)
            else {
                break;
            };
            let Some(destination) = resolver.resolve(&target_value, translator.context()) else {
                break;
            };
            let mut case = SwitchCase::new(destination);
            if let Some(raw) = value.to_u64() {
                case.add_label(SwitchCaseLabel::new(raw.wrapping_add(label_offset as u64)));
            }
            cases.push(case);
        }

        if cases.is_empty() {
            tracing::trace!("switch slice at {branch}: slice not closed");
            return None;
        }

        let truncated = interval.count().is_some_and(|count| cases.len() < count);
        let table_address = Address::new(space, layout.address);
        let table = AddressTable::new(table_address, layout.element_size)
            .with_element_count(cases.len() as u32);
        let evidence = Self::evidence(guarded, truncated)
            | self.table_evidence(table_address, &cases, &mut evaluation.reader);
        let recovered = RecoveredSwitch::new(
            SwitchModel::Absolute(table),
            cases,
            Self::confidence(guarded, truncated),
            evidence,
        );
        Some(
            match self.guard_default(index, branch, context, translator) {
                Some(default) => recovered.with_default(default),
                None => recovered,
            },
        )
    }

    fn recover_inline(
        &self,
        branch: Address,
        layout: InlineTableLayout,
        context: &ContextSet,
        translator: &mut Translator,
    ) -> Option<RecoveredSwitch> {
        let interval = self.index_interval(layout.index, branch)?;
        let guarded = interval.upper() != StridedInterval::full(interval.width()).upper();
        let limit = interval
            .count()
            .map_or(self.config.max_cases() as usize, |count| {
                count.min(self.config.max_cases() as usize)
            });
        let space = branch.space();
        let table_address = Address::new(space, layout.address);
        let mut table = AddressTable::new(table_address, layout.stride);
        let mut entries = SegmentReader::new(self.segments);
        let mut resolver = SwitchTargetResolver::new(self.arch, self.segments, space);
        let mut cases = Vec::new();
        let label_offset = self.label_offset(layout.index);

        for value in interval.iter().take(limit) {
            let entry = u32::try_from(value.to_u64()?).ok()?;
            let address = table.entry_address(entry);
            let Some(destination) = self.decode_direct_branch(
                address,
                Some(layout.stride as usize),
                context,
                translator,
                &mut entries,
                &mut resolver,
            ) else {
                break;
            };
            let mut case = SwitchCase::new(destination);
            case.add_label(SwitchCaseLabel::new(
                u64::from(entry).wrapping_add(label_offset as u64),
            ));
            cases.push(case);
        }

        if cases.is_empty() {
            tracing::trace!("switch slice at {branch}: inline table is not closed");
            return None;
        }

        table.set_element_count(cases.len() as u32);
        let truncated = interval.count().is_some_and(|count| cases.len() < count);
        let evidence = Self::evidence(guarded, truncated)
            | SwitchEvidence::CONTIGUOUS_ENTRIES
            | self.target_alignment_evidence(&cases);
        let recovered = RecoveredSwitch::new(
            SwitchModel::InlineBranchTable(table),
            cases,
            Self::confidence(guarded, truncated),
            evidence,
        );
        Some(
            match self.guard_default(layout.index, branch, context, translator) {
                Some(default) => recovered.with_default(default),
                None => recovered,
            },
        )
    }

    fn decode_direct_branch(
        &self,
        address: Address,
        expected_length: Option<usize>,
        context: &ContextSet,
        translator: &mut Translator,
        entries: &mut SegmentReader,
        resolver: &mut SwitchTargetResolver,
    ) -> Option<AddressWithContext> {
        let window = entries
            .view(address)
            .and_then(|view| view.bytes_from(address))?;
        let bytes = window.as_contiguous()?;
        context.apply(address, translator.context_mut());
        let instruction = translator.disassemble(address, bytes).ok()?;
        if expected_length.is_some_and(|length| instruction.len() != length)
            || !instruction.is_branch()
            || instruction.is_call()
            || instruction.is_return()
            || instruction.is_indirect()
            || instruction.has_fall()
        {
            return None;
        }
        let mut targets = instruction.iter_targets();
        let (_, _, target) = targets.next()?;
        if targets.next().is_some() {
            return None;
        }
        resolver.resolve_address(target.raw_address(), translator.context())
    }

    fn confidence(guarded: bool, truncated: bool) -> Confidence {
        if guarded && !truncated {
            Confidence::somewhat_certain()
        } else {
            Confidence::uncertain()
        }
    }

    fn evidence(guarded: bool, truncated: bool) -> SwitchEvidence {
        let mut evidence = SwitchEvidence::TARGETS_IN_EXECUTABLE;
        if guarded {
            evidence |= SwitchEvidence::GUARD_FOUND;
        }
        if truncated {
            evidence |= SwitchEvidence::TRUNCATED;
        }
        evidence
    }

    fn table_evidence(
        &self,
        table: Address,
        cases: &[SwitchCase],
        reader: &mut SegmentReader,
    ) -> SwitchEvidence {
        let mut evidence = SwitchEvidence::empty();
        if reader
            .properties(table)
            .is_some_and(|props| props.is_readable() && !props.is_writable())
        {
            evidence |= SwitchEvidence::TABLE_IN_READ_ONLY;
        }
        evidence | self.target_alignment_evidence(cases)
    }

    fn target_alignment_evidence(&self, cases: &[SwitchCase]) -> SwitchEvidence {
        let alignment = self.arch.language().address_alignment() as u64;
        if alignment <= 1
            || cases
                .iter()
                .all(|case| case.target().address().offset() % alignment == 0)
        {
            SwitchEvidence::TARGETS_ALIGNED
        } else {
            SwitchEvidence::empty()
        }
    }

    fn scaled_index(&self, target: IlValueId) -> Option<IlValueId> {
        let mut stack = vec![(target, 0u32)];
        let mut visited = FxHashSet::default();
        let mut best = None;
        let mut steps = 0usize;

        while let Some((value, depth)) = stack.pop() {
            steps += 1;
            if steps > self.config.max_trace_steps() {
                break;
            }
            if !visited.insert(value.index()) {
                continue;
            }
            let Some(op) = self.ssa.defining_operation(value) else {
                continue;
            };
            let operands = self.ssa.operation_operands(op);
            match op.opcode() {
                ECodeSsaOpcode::Mul | ECodeSsaOpcode::LeftShift => {
                    if let Some(variable) = self.ssa.first_non_constant_operand(op) {
                        if best.is_none_or(|(_, best_depth)| depth > best_depth) {
                            best = Some((self.ssa.underlying_value(variable), depth));
                        }
                        stack.push((variable, depth + 1));
                    }
                }
                ECodeSsaOpcode::Load => {
                    if let Some(&pointer) = operands.first() {
                        stack.push((pointer, depth + 1));
                    }
                }
                ECodeSsaOpcode::Add | ECodeSsaOpcode::Sub => {
                    for &operand in operands {
                        stack.push((operand, depth + 1));
                    }
                }
                ECodeSsaOpcode::Copy
                | ECodeSsaOpcode::ZeroExtend
                | ECodeSsaOpcode::SignExtend
                | ECodeSsaOpcode::Truncate => {
                    if let Some(&operand) = operands.first() {
                        stack.push((operand, depth + 1));
                    }
                }
                _ => {}
            }
        }

        best.map(|(value, _)| value)
    }

    fn table_layout(&self, target: IlValueId) -> Option<TableLayout> {
        let mut queue = VecDeque::from([target]);
        let mut visited = FxHashSet::default();
        let mut steps = 0usize;

        while let Some(value) = queue.pop_front() {
            steps += 1;
            if steps > self.config.max_trace_steps() {
                break;
            }
            if !visited.insert(value.index()) {
                continue;
            }
            let Some(op) = self.ssa.defining_operation(value) else {
                continue;
            };
            let operands = self.ssa.operation_operands(op);
            match op.opcode() {
                ECodeSsaOpcode::Load => {
                    if let Some(&pointer) = operands.first() {
                        if let Some(address) = self.table_address(pointer) {
                            return Some(TableLayout {
                                address,
                                element_size: op.width().div_ceil(8),
                            });
                        }
                        queue.push_back(pointer);
                    }
                }
                ECodeSsaOpcode::Add
                | ECodeSsaOpcode::Sub
                | ECodeSsaOpcode::Copy
                | ECodeSsaOpcode::ZeroExtend
                | ECodeSsaOpcode::SignExtend
                | ECodeSsaOpcode::Truncate
                | ECodeSsaOpcode::Mul
                | ECodeSsaOpcode::LeftShift => {
                    for &operand in operands {
                        queue.push_back(operand);
                    }
                }
                _ => {}
            }
        }

        None
    }

    fn table_address(&self, pointer: IlValueId) -> Option<RawAddress> {
        let op = self.ssa.defining_operation(pointer)?;
        if !matches!(op.opcode(), ECodeSsaOpcode::Add) {
            return None;
        }
        let operands = self.ssa.operation_operands(op);
        let a = *operands.first()?;
        let b = *operands.get(1)?;
        let address = self
            .ssa
            .constant_value(a)
            .or_else(|| self.ssa.constant_value(b))?;
        Some(RawAddress::from(address.to_u64()?))
    }

    fn inline_table_layout(&self, target: IlValueId) -> Option<InlineTableLayout> {
        let mut target = self.canonical(target);
        if let Some(operation) = self.ssa.defining_operation(target)
            && operation.opcode() == ECodeSsaOpcode::And
        {
            let operands = self.ssa.operation_operands(operation);
            let (&a, &b) = (operands.first()?, operands.get(1)?);
            let (mask, unmasked) = self.constant_and_variable(a, b)?;
            let width = self.ssa.value_width(target)?;
            let expected = BitVec::max_value_with(width, false) - BitVec::one(width);
            if mask.unsigned_cast(width) != expected {
                return None;
            }
            target = self.canonical(unmasked);
        }

        let operation = self.ssa.defining_operation(target)?;
        if operation.opcode() != ECodeSsaOpcode::Add {
            return None;
        }
        let operands = self.ssa.operation_operands(operation);
        let (&a, &b) = (operands.first()?, operands.get(1)?);
        let (address, scaled) = self.constant_and_variable(a, b)?;
        let address = RawAddress::from(address.to_u64()?);
        let scaled = self.canonical(scaled);
        let operation = self.ssa.defining_operation(scaled)?;
        let operands = self.ssa.operation_operands(operation);
        let (&a, &b) = (operands.first()?, operands.get(1)?);
        let (scale, index) = self.constant_and_variable(a, b)?;
        let scale = scale.to_u64()?;
        let stride = match operation.opcode() {
            ECodeSsaOpcode::Mul => scale,
            ECodeSsaOpcode::LeftShift => 1u64.checked_shl(u32::try_from(scale).ok()?)?,
            _ => return None,
        };
        let stride = u32::try_from(stride).ok()?;
        if stride == 0 || stride > self.config.max_element_size() {
            return None;
        }

        Some(InlineTableLayout {
            address,
            stride,
            index: self.canonical(index),
        })
    }

    fn constant_and_variable(&self, a: IlValueId, b: IlValueId) -> Option<(BitVec, IlValueId)> {
        match (self.ssa.constant_value(a), self.ssa.constant_value(b)) {
            (Some(constant), None) => Some((constant, b)),
            (None, Some(constant)) => Some((constant, a)),
            _ => None,
        }
    }

    fn index_interval(&self, index: IlValueId, branch: Address) -> Option<StridedInterval> {
        let width = self.ssa.value_width(index)?;
        let mut interval = self
            .intervals
            .interval(index)
            .filter(|interval| !interval.is_empty())
            .cloned()
            .unwrap_or_else(|| StridedInterval::full(width));
        if let Some(bound) = self.guard_bound(index, width, branch) {
            interval = interval.meet(&StridedInterval::range(
                BitVec::zero(width),
                bound,
                BitVec::one(width),
            ));
        }
        Some(interval)
    }

    fn label_offset(&self, index: IlValueId) -> i64 {
        let Some(op) = self.ssa.defining_operation(index) else {
            return 0;
        };
        let Some(constant) = self
            .ssa
            .operation_operands(op)
            .iter()
            .find_map(|&operand| self.ssa.constant_value(operand))
            .and_then(|constant| constant.to_u64())
        else {
            return 0;
        };
        match op.opcode() {
            ECodeSsaOpcode::Sub => constant as i64,
            ECodeSsaOpcode::Add => (constant as i64).wrapping_neg(),
            _ => 0,
        }
    }

    fn evaluate_target(
        &self,
        target: IlValueId,
        index: IlValueId,
        assignment: &BitVec,
        evaluation: &mut TargetEvaluation,
    ) -> Option<BitVec> {
        evaluation.memo.clear();
        evaluation.stack.clear();
        evaluation.stack.push((target, false));
        let mut steps = 0usize;

        evaluation.memo.insert(index.index(), assignment.clone());

        while let Some(&(value, expanded)) = evaluation.stack.last() {
            steps += 1;
            if steps > self.config.max_trace_steps() {
                return None;
            }
            if evaluation.memo.contains_key(&value.index()) {
                evaluation.stack.pop();
                continue;
            }

            let Some(op) = self.ssa.defining_operation(value) else {
                match self.single_source_feeder(value) {
                    Some(feeder) if expanded => {
                        evaluation.stack.pop();
                        let result = evaluation.memo.get(&feeder.index()).cloned()?;
                        evaluation.memo.insert(value.index(), result);
                    }
                    Some(feeder) => {
                        evaluation.stack.last_mut()?.1 = true;
                        if !evaluation.memo.contains_key(&feeder.index()) {
                            evaluation.stack.push((feeder, false));
                        }
                    }
                    None => {
                        evaluation.stack.pop();
                    }
                }
                continue;
            };
            let operands = self.ssa.operation_operands(op);

            if expanded {
                evaluation.stack.pop();
                let result = self.apply(value, op, operands, evaluation)?;
                evaluation.memo.insert(value.index(), result);
            } else {
                evaluation.stack.last_mut()?.1 = true;
                let inputs = match op.opcode() {
                    ECodeSsaOpcode::Load => &operands[..operands.len().min(1)],
                    _ => operands,
                };
                for &operand in inputs {
                    if !evaluation.memo.contains_key(&operand.index()) {
                        evaluation.stack.push((operand, false));
                    }
                }
            }
        }

        evaluation.memo.remove(&target.index())
    }

    fn apply(
        &self,
        value: IlValueId,
        op: &ECodeSsaOp,
        operands: &[IlValueId],
        evaluation: &mut TargetEvaluation,
    ) -> Option<BitVec> {
        match op.opcode() {
            ECodeSsaOpcode::Constant => self.ssa.constant_value(value),
            ECodeSsaOpcode::Load => {
                let pointer = operands
                    .first()
                    .and_then(|value| evaluation.memo.get(&value.index()).cloned())?;
                self.load_entry(
                    op,
                    &pointer,
                    evaluation.space,
                    &mut evaluation.reader,
                    &mut evaluation.buffer,
                )
            }
            opcode => {
                evaluation.operands.clear();
                for value in operands {
                    evaluation
                        .operands
                        .push(evaluation.memo.get(&value.index())?.clone());
                }
                opcode.evaluate(op.width(), &evaluation.operands)
            }
        }
    }

    fn load_entry(
        &self,
        op: &ECodeSsaOp,
        pointer: &BitVec,
        space: AddressSpaceId,
        reader: &mut SegmentReader,
        buffer: &mut Vec<u8>,
    ) -> Option<BitVec> {
        let bytes = op.width().div_ceil(8) as usize;
        if bytes == 0 {
            return None;
        }
        let space = op.address_space().unwrap_or(space);
        let address = Address::new(space, RawAddress::from(pointer.to_u64()?));
        buffer.clear();
        buffer.resize(bytes, 0);
        reader.read_bytes_exact(address, buffer).ok()?;

        let value = match self.arch.endian() {
            Endian::Big => BitVec::from_be_bytes(buffer),
            Endian::Little => BitVec::from_le_bytes(buffer),
        };
        Some(value.cast(op.width()))
    }
}
