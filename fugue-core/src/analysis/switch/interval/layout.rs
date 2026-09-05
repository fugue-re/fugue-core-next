use std::collections::VecDeque;

use fugue_bv::BitVec;
use rustc_hash::FxHashSet;

use crate::analysis::switch::SwitchRecoveryConfig;
use crate::il::common::IlValueId;
use crate::il::ecode::{ECodeBlockArgInputs, ECodeIr, ECodeOpcode};
use crate::ir::RawAddress;

pub(crate) enum SwitchTableLayout {
    Inline {
        address: RawAddress,
        index: IlValueId,
        stride: u32,
    },
    Loaded {
        address: RawAddress,
        element_size: u32,
        index: IlValueId,
        target: IlValueId,
    },
}

impl SwitchTableLayout {
    pub(crate) fn index(&self) -> IlValueId {
        match self {
            Self::Inline { index, .. } | Self::Loaded { index, .. } => *index,
        }
    }
}

pub(crate) struct SwitchLayoutAnalysis<'analysis> {
    block_arg_inputs: &'analysis ECodeBlockArgInputs,
    config: SwitchRecoveryConfig,
    ssa: &'analysis ECodeIr,
}

struct BaseScaleIndex {
    base: RawAddress,
    scale: Option<u64>,
    index: IlValueId,
}

impl BaseScaleIndex {
    fn new(base: RawAddress, scale: Option<u64>, index: IlValueId) -> Self {
        Self { base, scale, index }
    }

    fn stride(&self) -> u64 {
        self.scale.unwrap_or(1)
    }
}

impl<'analysis> SwitchLayoutAnalysis<'analysis> {
    pub(crate) fn new(
        ssa: &'analysis ECodeIr,
        block_arg_inputs: &'analysis ECodeBlockArgInputs,
        config: SwitchRecoveryConfig,
    ) -> Self {
        Self {
            block_arg_inputs,
            config,
            ssa,
        }
    }

    pub(crate) fn discover(&self, target: IlValueId) -> Option<SwitchTableLayout> {
        if let Some((address, element_size, index)) = self.table_layout(target) {
            return Some(SwitchTableLayout::Loaded {
                address,
                element_size,
                index,
                target,
            });
        }
        let (address, stride, index) = self.inline_table_layout(target)?;
        Some(SwitchTableLayout::Inline {
            address,
            index,
            stride,
        })
    }

    fn table_layout(&self, target: IlValueId) -> Option<(RawAddress, u32, IlValueId)> {
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
            let Some(operation) = self.ssa.defining_op(value) else {
                continue;
            };
            let operands = self.ssa.op_operands_for(operation);
            match operation.opcode() {
                ECodeOpcode::Load => {
                    if let Some(pointer) = self.ssa.pointer_operand(operation) {
                        let element_size = operation.width().div_ceil(8);
                        if let Some((address, index)) = self.table_pointer(pointer, element_size) {
                            return Some((address, element_size, index));
                        }
                        queue.push_back(pointer);
                    }
                }
                ECodeOpcode::Add
                | ECodeOpcode::Sub
                | ECodeOpcode::Copy
                | ECodeOpcode::WriteFlag
                | ECodeOpcode::WriteRegister
                | ECodeOpcode::ZeroExtend
                | ECodeOpcode::SignExtend
                | ECodeOpcode::Truncate
                | ECodeOpcode::Mul
                | ECodeOpcode::LeftShift => {
                    queue.extend(operands.iter().copied());
                }
                _ => {}
            }
        }

        None
    }

    fn table_pointer(
        &self,
        pointer: IlValueId,
        element_size: u32,
    ) -> Option<(RawAddress, IlValueId)> {
        let indexed = self.base_scale_index(pointer)?;
        (indexed.stride() == u64::from(element_size)).then_some((indexed.base, indexed.index))
    }

    fn inline_table_layout(&self, target: IlValueId) -> Option<(RawAddress, u32, IlValueId)> {
        let mut target = self.canonical_value(target);
        if let Some(operation) = self.ssa.defining_op(target)
            && operation.opcode() == ECodeOpcode::And
        {
            let operands = self.ssa.op_operands_for(operation);
            let (&a, &b) = (operands.first()?, operands.get(1)?);
            let (mask, unmasked) = self.constant_and_value(a, b)?;
            let width = self.ssa.value_width(target)?;
            let expected = BitVec::max_value_with(width, false) - BitVec::one(width);
            if mask.unsigned_cast(width) != expected {
                return None;
            }
            target = self.canonical_value(unmasked);
        }

        let indexed = self.base_scale_index(target)?;
        let stride = u32::try_from(indexed.scale?).ok()?;
        if stride == 0 || stride > self.config.max_element_size() {
            return None;
        }

        Some((indexed.base, stride, indexed.index))
    }

    fn base_scale_index(&self, value: IlValueId) -> Option<BaseScaleIndex> {
        let value = self.canonical_value(value);
        let operation = self.ssa.defining_op(value)?;
        if operation.opcode() != ECodeOpcode::Add {
            return None;
        }
        let operands = self.ssa.op_operands_for(operation);
        let (&a, &b) = (operands.first()?, operands.get(1)?);
        let (base, scaled) = self.constant_and_value(a, b)?;
        let base = RawAddress::from(base.to_u64()?);
        let scaled = self.canonical_value(scaled);
        let Some(operation) = self.ssa.defining_op(scaled) else {
            return Some(BaseScaleIndex::new(base, None, scaled));
        };
        if !matches!(
            operation.opcode(),
            ECodeOpcode::Mul | ECodeOpcode::LeftShift
        ) {
            return Some(BaseScaleIndex::new(base, None, scaled));
        }
        let operands = self.ssa.op_operands_for(operation);
        let (&a, &b) = (operands.first()?, operands.get(1)?);
        let (scale, index) = match operation.opcode() {
            ECodeOpcode::Mul => self.constant_and_value(a, b)?,
            ECodeOpcode::LeftShift => (self.ssa.constant_value(b)?, a),
            _ => unreachable!(),
        };
        let scale = scale.to_u64()?;
        let scale = match operation.opcode() {
            ECodeOpcode::Mul => scale,
            ECodeOpcode::LeftShift => 1u64.checked_shl(u32::try_from(scale).ok()?)?,
            _ => unreachable!(),
        };
        Some(BaseScaleIndex::new(
            base,
            Some(scale),
            self.canonical_value(index),
        ))
    }

    fn canonical_value(&self, value: IlValueId) -> IlValueId {
        let mut current = self.ssa.underlying_value(value);
        for _ in 0..self.config.max_trace_depth() {
            let Some(inputs) = self.block_arg_inputs.inputs_for(current) else {
                break;
            };
            let Some(&first) = inputs.first() else {
                break;
            };
            if inputs.iter().any(|&input| input != first) {
                break;
            }
            let next = self.ssa.underlying_value(first);
            if next == current {
                break;
            }
            current = next;
        }
        current
    }

    fn constant_and_value(&self, a: IlValueId, b: IlValueId) -> Option<(BitVec, IlValueId)> {
        match (self.ssa.constant_value(a), self.ssa.constant_value(b)) {
            (Some(constant), None) => Some((constant, b)),
            (None, Some(constant)) => Some((constant, a)),
            _ => None,
        }
    }
}
