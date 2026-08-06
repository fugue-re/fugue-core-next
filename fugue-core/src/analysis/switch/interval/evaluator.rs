use fugue_bv::BitVec;
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;

use super::SwitchIntervalRecovery;
use crate::il::common::IlValueId;
use crate::il::ecode::ssa::{ECodeSsaOp, ECodeSsaOpcode};
use crate::ir::{Address, RawAddress};
use crate::storage::AddressSpaceId;

pub(crate) struct SwitchTargetEvaluator<'context, 'analysis> {
    context: &'context SwitchIntervalRecovery<'analysis>,
    space: AddressSpaceId,
    memo: FxHashMap<IlValueId, BitVec>,
    dependent: FxHashSet<IlValueId>,
    stack: Vec<EvaluationStep>,
}

#[derive(Clone, Copy)]
enum EvaluationStep {
    Apply(IlValueId),
    Evaluate(IlValueId),
    Forward { value: IlValueId, input: IlValueId },
}

impl<'context, 'analysis> SwitchTargetEvaluator<'context, 'analysis> {
    pub(crate) fn new(
        context: &'context SwitchIntervalRecovery<'analysis>,
        space: AddressSpaceId,
    ) -> Self {
        Self {
            context,
            space,
            memo: FxHashMap::default(),
            dependent: FxHashSet::default(),
            stack: Vec::new(),
        }
    }

    pub(crate) fn evaluate(
        &mut self,
        target: IlValueId,
        index: IlValueId,
        assignment: &BitVec,
        mut read_memory: impl FnMut(Address, usize) -> Option<BitVec>,
    ) -> Option<BitVec> {
        self.dependent.clear();
        self.stack.clear();
        self.stack.push(EvaluationStep::Evaluate(target));
        self.memo.insert(index, assignment.clone());
        self.dependent.insert(index);
        let mut steps = 0usize;

        let result = (|| {
            while let Some(step) = self.stack.pop() {
                steps = steps.checked_add(1)?;
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
                                self.stack.push(EvaluationStep::Forward { value, input });
                                if !self.memo.contains_key(&input) {
                                    self.stack.push(EvaluationStep::Evaluate(input));
                                }
                            }
                            continue;
                        };

                        self.stack.push(EvaluationStep::Apply(value));
                        if operation.opcode() == ECodeSsaOpcode::Load {
                            let pointer = self.context.ssa.pointer_operand(operation)?;
                            if !self.memo.contains_key(&pointer) {
                                self.stack.push(EvaluationStep::Evaluate(pointer));
                            }
                            continue;
                        }
                        for &operand in self.context.ssa.operation_operands_for(operation) {
                            if !self.memo.contains_key(&operand) {
                                self.stack.push(EvaluationStep::Evaluate(operand));
                            }
                        }
                    }
                    EvaluationStep::Apply(value) => {
                        let operation = self.context.ssa.defining_operation(value)?;
                        let result = self.apply(value, operation, &mut read_memory)?;
                        if self
                            .context
                            .ssa
                            .operation_operands_for(operation)
                            .iter()
                            .any(|operand| self.dependent.contains(operand))
                        {
                            self.dependent.insert(value);
                        }
                        self.memo.insert(value, result);
                    }
                    EvaluationStep::Forward { value, input } => {
                        let result = self.memo.get(&input).cloned()?;
                        if self.dependent.contains(&input) {
                            self.dependent.insert(value);
                        }
                        self.memo.insert(value, result);
                    }
                }
            }

            self.memo.get(&target).cloned()
        })();
        self.memo.retain(|value, _| !self.dependent.contains(value));
        result
    }

    fn apply(
        &mut self,
        value: IlValueId,
        operation: &ECodeSsaOp,
        read_memory: &mut impl FnMut(Address, usize) -> Option<BitVec>,
    ) -> Option<BitVec> {
        match operation.opcode() {
            ECodeSsaOpcode::Constant => self.context.ssa.constant_value(value),
            ECodeSsaOpcode::Load => {
                let pointer = self
                    .context
                    .ssa
                    .pointer_operand(operation)
                    .and_then(|pointer| self.memo.get(&pointer).cloned())?;
                self.load(operation, &pointer, read_memory)
            }
            opcode => {
                let mut operands = SmallVec::<[&BitVec; 4]>::new();
                for value in self.context.ssa.operation_operands_for(operation) {
                    operands.push(self.memo.get(value)?);
                }
                opcode.evaluate(operation.width(), &operands)
            }
        }
    }

    fn load(
        &mut self,
        operation: &ECodeSsaOp,
        pointer: &BitVec,
        read_memory: &mut impl FnMut(Address, usize) -> Option<BitVec>,
    ) -> Option<BitVec> {
        let bytes = operation.width().div_ceil(8) as usize;
        if bytes == 0 {
            return None;
        }
        let space = operation.address_space().unwrap_or(self.space);
        let address = Address::new(space, RawAddress::from(pointer.to_u64()?));
        let value = read_memory(address, bytes)?;
        Some(value.cast(operation.width()))
    }
}
