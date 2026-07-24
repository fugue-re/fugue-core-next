use fugue_bv::BitVec;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use super::SwitchIntervalContext;
use crate::il::common::IlValueId;
use crate::il::ecode::ssa::{ECodeSsaOp, ECodeSsaOpcode};
use crate::ir::{Address, RawAddress};
use crate::storage::segments::SegmentMappingCache;
use crate::storage::segments::space::AddressSpaceId;

pub(crate) struct SwitchTargetEvaluator<'context, 'analysis> {
    context: &'context SwitchIntervalContext<'analysis>,
    space: AddressSpaceId,
    mapping_cache: SegmentMappingCache<'analysis>,
    memo: FxHashMap<IlValueId, BitVec>,
    stack: Vec<EvaluationStep>,
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

impl<'context, 'analysis> SwitchTargetEvaluator<'context, 'analysis> {
    pub(crate) fn new(
        context: &'context SwitchIntervalContext<'analysis>,
        space: AddressSpaceId,
    ) -> Self {
        Self {
            context,
            space,
            mapping_cache: SegmentMappingCache::new(context.segments),
            memo: FxHashMap::default(),
            stack: Vec::new(),
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
            if steps > self.context.config.max_trace_steps() {
                return None;
            }

            match step {
                EvaluationStep::Evaluate(value) => {
                    if self.memo.contains_key(&value) {
                        continue;
                    }

                    let Some(operation) = self.context.ssa.defining_operation(value) else {
                        if let Some(input) = self.context.common_block_argument_input(value) {
                            self.stack.push(EvaluationStep::forward(value, input));
                            if !self.memo.contains_key(&input) {
                                self.stack.push(EvaluationStep::evaluate(input));
                            }
                        }
                        continue;
                    };

                    self.stack.push(EvaluationStep::apply(value));
                    if operation.opcode() == ECodeSsaOpcode::Load {
                        let pointer = self.context.ssa.pointer_operand(operation)?;
                        if !self.memo.contains_key(&pointer) {
                            self.stack.push(EvaluationStep::evaluate(pointer));
                        }
                        continue;
                    }
                    for &operand in self.context.ssa.operation_operands(operation) {
                        if !self.memo.contains_key(&operand) {
                            self.stack.push(EvaluationStep::evaluate(operand));
                        }
                    }
                }
                EvaluationStep::Apply(value) => {
                    let operation = self.context.ssa.defining_operation(value)?;
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
            ECodeSsaOpcode::Constant => self.context.ssa.constant_value(value),
            ECodeSsaOpcode::Load => {
                let pointer = self
                    .context
                    .ssa
                    .pointer_operand(operation)
                    .and_then(|pointer| self.memo.get(&pointer).cloned())?;
                self.load(operation, &pointer)
            }
            opcode => {
                let mut operands = SmallVec::<[&BitVec; 4]>::new();
                for value in self.context.ssa.operation_operands(operation) {
                    operands.push(self.memo.get(value)?);
                }
                opcode.evaluate(operation.width(), &operands)
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
        let value = self
            .mapping_cache
            .read_bitvec(address, bytes, self.context.arch.endian())
            .ok()?;
        Some(value.cast(operation.width()))
    }
}
