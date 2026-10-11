use fugue_bv::BitVec;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use super::ThunkTargetRecoveryConfig;
use crate::il::common::{IlValueId, RegisterId};
use crate::il::ecode::analysis::ECodeBlockArgInputs;
use crate::il::ecode::{ECodeDomain, ECodeIr, ECodeOp, ECodeOpcode};
use crate::ir::{Address, RawAddress};
use crate::lifter::TrackedContext;
use crate::storage::AddressSpaceId;

pub(crate) struct ThunkTargetEvaluator<'a> {
    ssa: &'a ECodeIr,
    block_arg_inputs: &'a ECodeBlockArgInputs,
    seeds: &'a FxHashMap<RegisterId, TrackedContext>,
    space: AddressSpaceId,
    config: ThunkTargetRecoveryConfig,
    memo: FxHashMap<IlValueId, BitVec>,
    stack: Vec<EvaluationStep>,
}

#[derive(Clone, Copy)]
enum EvaluationStep {
    Apply(IlValueId),
    Evaluate(IlValueId),
    Forward { value: IlValueId, input: IlValueId },
}

impl<'a> ThunkTargetEvaluator<'a> {
    pub(crate) fn new(
        ssa: &'a ECodeIr,
        block_arg_inputs: &'a ECodeBlockArgInputs,
        seeds: &'a FxHashMap<RegisterId, TrackedContext>,
        space: AddressSpaceId,
        config: ThunkTargetRecoveryConfig,
    ) -> Self {
        Self {
            ssa,
            block_arg_inputs,
            seeds,
            space,
            config,
            memo: FxHashMap::default(),
            stack: Vec::new(),
        }
    }

    pub(crate) fn evaluate(
        &mut self,
        target: IlValueId,
        mut read_memory: impl FnMut(Address, usize) -> Option<BitVec>,
    ) -> Option<BitVec> {
        self.stack.clear();
        self.stack.push(EvaluationStep::Evaluate(target));
        let mut steps = 0usize;

        while let Some(step) = self.stack.pop() {
            steps += 1;
            if steps > self.config.max_trace_steps() {
                return None;
            }

            match step {
                EvaluationStep::Evaluate(value) => {
                    if self.memo.contains_key(&value) {
                        continue;
                    }

                    let Some(operation) = self.ssa.defining_op(value) else {
                        let input = self.block_arg_inputs.common_input_for(value)?;
                        self.stack.push(EvaluationStep::Forward { value, input });
                        if !self.memo.contains_key(&input) {
                            self.stack.push(EvaluationStep::Evaluate(input));
                        }
                        continue;
                    };

                    self.stack.push(EvaluationStep::Apply(value));
                    if operation.opcode() == ECodeOpcode::Load {
                        let pointer = self.ssa.pointer_operand(operation)?;
                        if !self.memo.contains_key(&pointer) {
                            self.stack.push(EvaluationStep::Evaluate(pointer));
                        }
                        continue;
                    }
                    for &operand in self.ssa.op_operands_for(operation) {
                        if !self.memo.contains_key(&operand) {
                            self.stack.push(EvaluationStep::Evaluate(operand));
                        }
                    }
                }
                EvaluationStep::Apply(value) => {
                    let operation = self.ssa.defining_op(value)?;
                    let result = self.apply(value, operation, &mut read_memory)?;
                    self.memo.insert(value, result);
                }
                EvaluationStep::Forward { value, input } => {
                    let result = self.memo.get(&input).cloned()?;
                    self.memo.insert(value, result);
                }
            }
        }

        self.memo.get(&target).cloned()
    }

    fn apply(
        &self,
        value: IlValueId,
        operation: &ECodeOp,
        read_memory: &mut impl FnMut(Address, usize) -> Option<BitVec>,
    ) -> Option<BitVec> {
        match operation.opcode() {
            ECodeOpcode::Constant => self.ssa.constant_value(value),
            ECodeOpcode::Undefined => {
                let ECodeDomain::Register(register) = self.ssa.value_domain(value)? else {
                    return None;
                };
                let seed = self
                    .seeds
                    .get(&register)
                    .filter(|seed| seed.location().size() * 8 == operation.width() as usize)?;
                Some(BitVec::from_u64(seed.value(), operation.width()))
            }
            ECodeOpcode::Load => {
                let pointer = self
                    .ssa
                    .pointer_operand(operation)
                    .and_then(|pointer| self.memo.get(&pointer))?;
                let bytes = operation.width().div_ceil(8) as usize;
                if bytes == 0 {
                    return None;
                }
                let space = operation.address_space().unwrap_or(self.space);
                let address = Address::new(space, RawAddress::from(pointer.to_u64()?));
                Some(read_memory(address, bytes)?.cast(operation.width()))
            }
            ECodeOpcode::WriteFlag | ECodeOpcode::WriteRegister => {
                let input = self.ssa.op_operands_for(operation).first()?;
                Some(self.memo.get(input)?.clone().cast(operation.width()))
            }
            opcode => {
                let mut operands = SmallVec::<[&BitVec; 4]>::new();
                for value in self.ssa.op_operands_for(operation) {
                    operands.push(self.memo.get(value)?);
                }
                opcode.evaluate(operation.width(), &operands)
            }
        }
    }
}
