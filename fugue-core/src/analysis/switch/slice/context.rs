use fugue_bv::BitVec;
use fugue_bytes::Endian;
use rustc_hash::FxHashMap;

use super::SwitchSliceEvaluator;
use crate::il::common::IlValueId;
use crate::il::ecode::ssa::{ECodeSsaOp, ECodeSsaOpcode};
use crate::ir::{Address, RawAddress};
use crate::storage::segments::SegmentMappingCache;
use crate::storage::segments::space::AddressSpaceId;

pub(crate) struct SwitchTargetEvaluatorContext<'context, 'analysis> {
    analysis: &'context SwitchSliceEvaluator<'analysis>,
    space: AddressSpaceId,
    mapping_cache: SegmentMappingCache<'analysis>,
    memo: FxHashMap<IlValueId, BitVec>,
    stack: Vec<EvaluationStep>,
    operands: Vec<BitVec>,
    buffer: Vec<u8>,
}

#[derive(Clone, Copy)]
enum EvaluationStep {
    Apply(IlValueId),
    Evaluate(IlValueId),
    Forward { value: IlValueId, input: IlValueId },
}

impl EvaluationStep {
    const fn apply(value: IlValueId) -> Self {
        Self::Apply(value)
    }

    const fn evaluate(value: IlValueId) -> Self {
        Self::Evaluate(value)
    }

    const fn forward(value: IlValueId, input: IlValueId) -> Self {
        Self::Forward { value, input }
    }
}

impl<'context, 'analysis> SwitchTargetEvaluatorContext<'context, 'analysis> {
    pub(crate) fn new(
        analysis: &'context SwitchSliceEvaluator<'analysis>,
        space: AddressSpaceId,
    ) -> Self {
        Self {
            analysis,
            space,
            mapping_cache: SegmentMappingCache::new(analysis.segments),
            memo: FxHashMap::default(),
            stack: Vec::new(),
            operands: Vec::new(),
            buffer: Vec::new(),
        }
    }

    pub(crate) fn evaluate(
        &mut self,
        target: IlValueId,
        index: IlValueId,
        assignment: &BitVec,
    ) -> Option<BitVec> {
        self.memo.clear();
        self.stack.clear();
        self.stack.push(EvaluationStep::evaluate(target));
        self.memo.insert(index, assignment.clone());
        let mut steps = 0usize;

        while let Some(step) = self.stack.pop() {
            steps += 1;
            if steps > self.analysis.config.max_trace_steps() {
                return None;
            }

            match step {
                EvaluationStep::Evaluate(value) => {
                    if self.memo.contains_key(&value) {
                        continue;
                    }

                    let Some(operation) = self.analysis.ssa.defining_operation(value) else {
                        if let Some(input) = self.analysis.common_block_argument_input(value) {
                            self.stack.push(EvaluationStep::forward(value, input));
                            if !self.memo.contains_key(&input) {
                                self.stack.push(EvaluationStep::evaluate(input));
                            }
                        }
                        continue;
                    };

                    self.stack.push(EvaluationStep::apply(value));
                    let operands = self.analysis.ssa.operation_operands(operation);
                    let inputs = match operation.opcode() {
                        ECodeSsaOpcode::Load => &operands[..operands.len().min(1)],
                        _ => operands,
                    };
                    for &operand in inputs {
                        if !self.memo.contains_key(&operand) {
                            self.stack.push(EvaluationStep::evaluate(operand));
                        }
                    }
                }
                EvaluationStep::Apply(value) => {
                    let operation = self.analysis.ssa.defining_operation(value)?;
                    let result = self.apply(value, operation)?;
                    self.memo.insert(value, result);
                }
                EvaluationStep::Forward { value, input } => {
                    let result = self.memo.get(&input).cloned()?;
                    self.memo.insert(value, result);
                }
            }
        }

        self.memo.remove(&target)
    }

    fn apply(&mut self, value: IlValueId, operation: &ECodeSsaOp) -> Option<BitVec> {
        match operation.opcode() {
            ECodeSsaOpcode::Constant => self.analysis.ssa.constant_value(value),
            ECodeSsaOpcode::Load => {
                let pointer = self
                    .analysis
                    .ssa
                    .operation_operands(operation)
                    .first()
                    .and_then(|value| self.memo.get(value).cloned())?;
                self.load(operation, &pointer)
            }
            opcode => {
                self.operands.clear();
                for value in self.analysis.ssa.operation_operands(operation) {
                    self.operands.push(self.memo.get(value)?.clone());
                }
                opcode.evaluate(operation.width(), &self.operands)
            }
        }
    }

    fn load(&mut self, operation: &ECodeSsaOp, pointer: &BitVec) -> Option<BitVec> {
        let bytes = operation.width().div_ceil(8) as usize;
        if bytes == 0 {
            return None;
        }
        let space = operation.address_space().unwrap_or(self.space);
        let address = Address::new(space, RawAddress::from(pointer.to_u64()?));
        self.buffer.clear();
        self.buffer.resize(bytes, 0);
        self.mapping_cache
            .read_bytes_exact(address, &mut self.buffer)
            .ok()?;

        let value = match self.analysis.arch.endian() {
            Endian::Big => BitVec::from_be_bytes(&self.buffer),
            Endian::Little => BitVec::from_le_bytes(&self.buffer),
        };
        Some(value.cast(operation.width()))
    }
}
