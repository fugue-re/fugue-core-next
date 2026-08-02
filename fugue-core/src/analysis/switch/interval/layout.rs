use std::collections::VecDeque;

use fugue_bv::BitVec;
use rustc_hash::FxHashSet;

use super::SwitchIntervalRecovery;
use crate::il::common::IlValueId;
use crate::il::ecode::ssa::ECodeSsaOpcode;
use crate::ir::RawAddress;

pub(super) struct SwitchTableLayout {
    address: RawAddress,
    element_size: u32,
    index: IlValueId,
}

pub(super) struct SwitchInlineTableLayout {
    address: RawAddress,
    stride: u32,
    index: IlValueId,
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

    fn base(&self) -> RawAddress {
        self.base
    }

    fn index(&self) -> IlValueId {
        self.index
    }

    fn scale(&self) -> Option<u64> {
        self.scale
    }

    fn stride(&self) -> u64 {
        self.scale.unwrap_or(1)
    }
}

impl SwitchTableLayout {
    pub(super) fn address(&self) -> RawAddress {
        self.address
    }

    pub(super) fn element_size(&self) -> u32 {
        self.element_size
    }

    pub(super) fn index(&self) -> IlValueId {
        self.index
    }
}

impl SwitchInlineTableLayout {
    pub(super) fn address(&self) -> RawAddress {
        self.address
    }

    pub(super) fn stride(&self) -> u32 {
        self.stride
    }

    pub(super) fn index(&self) -> IlValueId {
        self.index
    }
}

impl SwitchIntervalRecovery<'_> {
    pub(super) fn table_layout(&self, target: IlValueId) -> Option<SwitchTableLayout> {
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
            let operands = self.ssa.operation_operands_for(operation);
            match operation.opcode() {
                ECodeSsaOpcode::Load => {
                    if let Some(pointer) = self.ssa.pointer_operand(operation) {
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
        let indexed = self.base_scale_index(pointer)?;
        (indexed.stride() == u64::from(element_size)).then_some((indexed.base(), indexed.index()))
    }

    pub(super) fn inline_table_layout(&self, target: IlValueId) -> Option<SwitchInlineTableLayout> {
        let mut target = self.canonical_value(target);
        if let Some(operation) = self.ssa.defining_operation(target)
            && operation.opcode() == ECodeSsaOpcode::And
        {
            let operands = self.ssa.operation_operands_for(operation);
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
        let stride = u32::try_from(indexed.scale()?).ok()?;
        if stride == 0 || stride > self.config.max_element_size() {
            return None;
        }

        Some(SwitchInlineTableLayout {
            address: indexed.base(),
            stride,
            index: indexed.index(),
        })
    }

    fn base_scale_index(&self, value: IlValueId) -> Option<BaseScaleIndex> {
        let value = self.canonical_value(value);
        let operation = self.ssa.defining_operation(value)?;
        if operation.opcode() != ECodeSsaOpcode::Add {
            return None;
        }
        let operands = self.ssa.operation_operands_for(operation);
        let (&a, &b) = (operands.first()?, operands.get(1)?);
        let (base, scaled) = self.constant_and_value(a, b)?;
        let base = RawAddress::from(base.to_u64()?);
        let scaled = self.canonical_value(scaled);
        let Some(operation) = self.ssa.defining_operation(scaled) else {
            return Some(BaseScaleIndex::new(base, None, scaled));
        };
        if !matches!(
            operation.opcode(),
            ECodeSsaOpcode::Mul | ECodeSsaOpcode::LeftShift
        ) {
            return Some(BaseScaleIndex::new(base, None, scaled));
        }
        let operands = self.ssa.operation_operands_for(operation);
        let (&a, &b) = (operands.first()?, operands.get(1)?);
        let (scale, index) = match operation.opcode() {
            ECodeSsaOpcode::Mul => self.constant_and_value(a, b)?,
            ECodeSsaOpcode::LeftShift => (self.ssa.constant_value(b)?, a),
            _ => unreachable!(),
        };
        let scale = scale.to_u64()?;
        let scale = match operation.opcode() {
            ECodeSsaOpcode::Mul => scale,
            ECodeSsaOpcode::LeftShift => 1u64.checked_shl(u32::try_from(scale).ok()?)?,
            _ => unreachable!(),
        };
        Some(BaseScaleIndex::new(
            base,
            Some(scale),
            self.canonical_value(index),
        ))
    }

    fn constant_and_value(&self, a: IlValueId, b: IlValueId) -> Option<(BitVec, IlValueId)> {
        match (self.ssa.constant_value(a), self.ssa.constant_value(b)) {
            (Some(constant), None) => Some((constant, b)),
            (None, Some(constant)) => Some((constant, a)),
            _ => None,
        }
    }
}
