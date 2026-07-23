use std::collections::VecDeque;

use fugue_bv::BitVec;
use rustc_hash::FxHashSet;

use super::SwitchSliceEvaluator;
use crate::il::common::IlValueId;
use crate::il::ecode::ssa::ECodeSsaOpcode;
use crate::ir::RawAddress;

pub(crate) struct SwitchTableLayout {
    address: RawAddress,
    element_size: u32,
    index: IlValueId,
}

pub(crate) struct SwitchInlineTableLayout {
    address: RawAddress,
    stride: u32,
    index: IlValueId,
}

impl SwitchTableLayout {
    pub(crate) fn address(&self) -> RawAddress {
        self.address
    }

    pub(crate) fn element_size(&self) -> u32 {
        self.element_size
    }

    pub(crate) fn index(&self) -> IlValueId {
        self.index
    }
}

impl SwitchInlineTableLayout {
    pub(crate) fn address(&self) -> RawAddress {
        self.address
    }

    pub(crate) fn stride(&self) -> u32 {
        self.stride
    }

    pub(crate) fn index(&self) -> IlValueId {
        self.index
    }
}

impl SwitchSliceEvaluator<'_> {
    pub(crate) fn table_layout(&self, target: IlValueId) -> Option<SwitchTableLayout> {
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
            let Some(operation) = self.ssa.defining_operation(value) else {
                continue;
            };
            let operands = self.ssa.operation_operands(operation);
            match operation.opcode() {
                ECodeSsaOpcode::Load => {
                    if let Some(&pointer) = operands.first() {
                        let element_size = operation.width().div_ceil(8);
                        if let Some((address, index)) = self.table_pointer(pointer, element_size) {
                            return Some(SwitchTableLayout {
                                address,
                                element_size,
                                index,
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
        let pointer = self.canonical_value(pointer);
        let operation = self.ssa.defining_operation(pointer)?;
        if operation.opcode() != ECodeSsaOpcode::Add {
            return None;
        }
        let operands = self.ssa.operation_operands(operation);
        let (&a, &b) = (operands.first()?, operands.get(1)?);
        let (address, scaled) = self.constant_and_value(a, b)?;
        let address = RawAddress::from(address.to_u64()?);
        let scaled = self.canonical_value(scaled);
        let Some(operation) = self.ssa.defining_operation(scaled) else {
            return (element_size == 1).then_some((address, scaled));
        };
        if !matches!(
            operation.opcode(),
            ECodeSsaOpcode::Mul | ECodeSsaOpcode::LeftShift
        ) {
            return (element_size == 1).then_some((address, scaled));
        }
        let operands = self.ssa.operation_operands(operation);
        let (&a, &b) = (operands.first()?, operands.get(1)?);
        let (scale, index) = self.constant_and_value(a, b)?;
        let scale = scale.to_u64()?;
        let stride = match operation.opcode() {
            ECodeSsaOpcode::Mul => scale,
            ECodeSsaOpcode::LeftShift => 1u64.checked_shl(u32::try_from(scale).ok()?)?,
            _ => unreachable!(),
        };
        if stride != u64::from(element_size) {
            return None;
        }
        Some((address, self.canonical_value(index)))
    }

    pub(crate) fn inline_table_layout(&self, target: IlValueId) -> Option<SwitchInlineTableLayout> {
        let mut target = self.canonical_value(target);
        if let Some(operation) = self.ssa.defining_operation(target)
            && operation.opcode() == ECodeSsaOpcode::And
        {
            let operands = self.ssa.operation_operands(operation);
            let (&a, &b) = (operands.first()?, operands.get(1)?);
            let (mask, unmasked) = self.constant_and_value(a, b)?;
            let width = self.ssa.value_width(target)?;
            let expected = BitVec::max_value_with(width, false) - BitVec::one(width);
            if mask.unsigned_cast(width) != expected {
                return None;
            }
            target = self.canonical_value(unmasked);
        }

        let operation = self.ssa.defining_operation(target)?;
        if operation.opcode() != ECodeSsaOpcode::Add {
            return None;
        }
        let operands = self.ssa.operation_operands(operation);
        let (&a, &b) = (operands.first()?, operands.get(1)?);
        let (address, scaled) = self.constant_and_value(a, b)?;
        let address = RawAddress::from(address.to_u64()?);
        let scaled = self.canonical_value(scaled);
        let operation = self.ssa.defining_operation(scaled)?;
        let operands = self.ssa.operation_operands(operation);
        let (&a, &b) = (operands.first()?, operands.get(1)?);
        let (scale, index) = self.constant_and_value(a, b)?;
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

        Some(SwitchInlineTableLayout {
            address,
            stride,
            index: self.canonical_value(index),
        })
    }

    fn constant_and_value(&self, a: IlValueId, b: IlValueId) -> Option<(BitVec, IlValueId)> {
        match (self.ssa.constant_value(a), self.ssa.constant_value(b)) {
            (Some(constant), None) => Some((constant, b)),
            (None, Some(constant)) => Some((constant, a)),
            _ => None,
        }
    }
}
