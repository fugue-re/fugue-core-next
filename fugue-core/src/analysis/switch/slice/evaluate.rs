use fugue_bv::BitVec;
use fugue_bytes::Endian;
use rustc_hash::FxHashMap;

use super::SwitchSliceEvaluator;
use crate::il::common::IlValueId;
use crate::il::ecode::ssa::{ECodeSsaOp, ECodeSsaOpcode};
use crate::ir::{Address, RawAddress};
use crate::storage::segments::SegmentReader;
use crate::storage::segments::space::AddressSpaceId;

pub(crate) struct SwitchTargetEvaluatorContext<'context, 'analysis> {
    analysis: &'context SwitchSliceEvaluator<'analysis>,
    space: AddressSpaceId,
    reader: SegmentReader<'analysis>,
    memo: FxHashMap<usize, BitVec>,
    stack: Vec<(IlValueId, bool)>,
    operands: Vec<BitVec>,
    buffer: Vec<u8>,
}

impl<'context, 'analysis> SwitchTargetEvaluatorContext<'context, 'analysis> {
    pub(crate) fn new(
        analysis: &'context SwitchSliceEvaluator<'analysis>,
        space: AddressSpaceId,
    ) -> Self {
        Self {
            analysis,
            space,
            reader: SegmentReader::new(analysis.segments),
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
        self.stack.push((target, false));
        self.memo.insert(index.index(), assignment.clone());
        let mut steps = 0usize;

        while let Some(&(value, expanded)) = self.stack.last() {
            steps += 1;
            if steps > self.analysis.config.max_trace_steps() {
                return None;
            }
            if self.memo.contains_key(&value.index()) {
                self.stack.pop();
                continue;
            }

            let Some(operation) = self.analysis.ssa.defining_operation(value) else {
                match self.analysis.common_block_argument_source(value) {
                    Some(source) if expanded => {
                        self.stack.pop();
                        let result = self.memo.get(&source.index()).cloned()?;
                        self.memo.insert(value.index(), result);
                    }
                    Some(source) => {
                        self.stack.last_mut()?.1 = true;
                        if !self.memo.contains_key(&source.index()) {
                            self.stack.push((source, false));
                        }
                    }
                    None => {
                        self.stack.pop();
                    }
                }
                continue;
            };

            if expanded {
                self.stack.pop();
                let result = self.apply(value, operation)?;
                self.memo.insert(value.index(), result);
                continue;
            }

            self.stack.last_mut()?.1 = true;
            let operands = self.analysis.ssa.operation_operands(operation);
            let inputs = match operation.opcode() {
                ECodeSsaOpcode::Load => &operands[..operands.len().min(1)],
                _ => operands,
            };
            for &operand in inputs {
                if !self.memo.contains_key(&operand.index()) {
                    self.stack.push((operand, false));
                }
            }
        }

        self.memo.remove(&target.index())
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
                    .and_then(|value| self.memo.get(&value.index()).cloned())?;
                self.load(operation, &pointer)
            }
            opcode => {
                self.operands.clear();
                for value in self.analysis.ssa.operation_operands(operation) {
                    self.operands.push(self.memo.get(&value.index())?.clone());
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
        self.reader
            .read_bytes_exact(address, &mut self.buffer)
            .ok()?;

        let value = match self.analysis.arch.endian() {
            Endian::Big => BitVec::from_be_bytes(&self.buffer),
            Endian::Little => BitVec::from_le_bytes(&self.buffer),
        };
        Some(value.cast(operation.width()))
    }
}
