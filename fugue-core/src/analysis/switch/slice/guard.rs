use fugue_bv::BitVec;

use super::SwitchSliceEvaluator;
use crate::analysis::function::recovery::Translator;
use crate::analysis::switch::SwitchTargetResolver;
use crate::analysis::value::StridedInterval;
use crate::il::common::{IlBlockId, IlValueId};
use crate::il::ecode::ssa::{ECodeSsaOp, ECodeSsaOpcode};
use crate::ir::{Address, AddressWithContext};
use crate::lifter::ContextSet;

#[derive(Clone, Copy)]
enum SwitchGuardDefault {
    Block(IlBlockId),
    DirectBranch(Address),
}

pub(crate) struct SwitchGuard {
    interval: StridedInterval,
    default: SwitchGuardDefault,
}

#[derive(Debug, Clone, Copy)]
enum Relation {
    Equal,
    Greater,
    GreaterEqual,
    Less,
    LessEqual,
    NotEqual,
}

impl Relation {
    const fn invert_operands(self) -> Self {
        match self {
            Self::Less => Self::Greater,
            Self::LessEqual => Self::GreaterEqual,
            Self::Greater => Self::Less,
            Self::GreaterEqual => Self::LessEqual,
            Self::Equal => Self::Equal,
            Self::NotEqual => Self::NotEqual,
        }
    }

    const fn negate(self) -> Self {
        match self {
            Self::Less => Self::GreaterEqual,
            Self::LessEqual => Self::Greater,
            Self::Greater => Self::LessEqual,
            Self::GreaterEqual => Self::Less,
            Self::Equal => Self::NotEqual,
            Self::NotEqual => Self::Equal,
        }
    }

    fn interval(self, bound: &BitVec, width: u32) -> StridedInterval {
        let zero = BitVec::zero(width);
        let one = BitVec::one(width);
        let ceiling = BitVec::max_value_with(width, false);
        let range = |lower: BitVec, upper: BitVec| {
            if lower > upper {
                StridedInterval::empty(width)
            } else {
                StridedInterval::range(lower, upper, one.clone())
            }
        };
        match self {
            Self::Less if bound.is_zero() => StridedInterval::empty(width),
            Self::Less => range(zero, bound - &one),
            Self::LessEqual => range(zero, bound.clone()),
            Self::Greater if *bound >= ceiling => StridedInterval::empty(width),
            Self::Greater => range(bound + &one, ceiling),
            Self::GreaterEqual => range(bound.clone(), ceiling),
            Self::Equal => StridedInterval::single(bound.clone()),
            Self::NotEqual => StridedInterval::full(width),
        }
    }
}

impl SwitchGuard {
    pub(crate) fn upper_bound(&self, width: u32) -> Option<BitVec> {
        Some(self.interval.upper()?.unsigned_cast(width))
    }
}

impl<'a> SwitchSliceEvaluator<'a> {
    pub(crate) fn find_guard(&self, index: IlValueId, branch: Address) -> Option<SwitchGuard> {
        if let Some(guard) = self.find_intra_instruction_guard(index, branch) {
            return Some(guard);
        }
        let switch_block = self.block_of_source(branch)?;
        let width = self.ssa.value_width(index)?;
        let ceiling = BitVec::max_value_with(width, false);
        for (operation_index, operation) in self.ssa.operations().iter().enumerate() {
            if operation.opcode() != ECodeSsaOpcode::ConditionalBranch {
                continue;
            }
            let Some(&condition) = self.ssa.operation_operands(operation).first() else {
                continue;
            };
            let Some(guard_block) = self.operation_blocks[operation_index] else {
                continue;
            };
            if !self.dominates(guard_block, switch_block) {
                continue;
            }
            let Some(taken) = operation
                .address()
                .and_then(|taken| self.block_of_source(taken))
            else {
                continue;
            };
            let Some(fallthrough) = self.alternate_successor(guard_block, taken) else {
                continue;
            };

            let taken_is_switch = self.dominates(taken, switch_block);
            let fallthrough_is_switch = self.dominates(fallthrough, switch_block);
            let (switch_taken, default_block) = if taken_is_switch && !fallthrough_is_switch {
                (true, fallthrough)
            } else if fallthrough_is_switch && !taken_is_switch {
                (false, taken)
            } else {
                continue;
            };

            let Some(interval) = self.index_interval_for_condition(
                condition,
                index,
                switch_taken,
                self.config.max_trace_depth(),
            ) else {
                continue;
            };
            let Some(upper) = interval.upper() else {
                continue;
            };
            if *upper >= ceiling {
                continue;
            }
            return Some(SwitchGuard {
                interval,
                default: SwitchGuardDefault::Block(default_block),
            });
        }
        None
    }

    fn find_intra_instruction_guard(
        &self,
        index: IlValueId,
        branch: Address,
    ) -> Option<SwitchGuard> {
        let width = self.ssa.value_width(index)?;
        let ceiling = BitVec::max_value_with(width, false);
        let operation = self.find_intra_instruction_conditional_branch(branch)?;
        let condition = *self.ssa.operation_operands(operation).first()?;
        let interval = self.index_interval_for_condition(
            condition,
            index,
            false,
            self.config.max_trace_depth(),
        )?;
        if interval.upper()? >= &ceiling {
            return None;
        }
        Some(SwitchGuard {
            interval,
            default: SwitchGuardDefault::DirectBranch(operation.address()?),
        })
    }

    fn find_intra_instruction_conditional_branch(&self, branch: Address) -> Option<&ECodeSsaOp> {
        let mut conditional = None;
        for (_, operation) in self.ssa.operations_for_source(branch) {
            match operation.opcode() {
                ECodeSsaOpcode::ConditionalBranch => conditional = Some(operation),
                ECodeSsaOpcode::BranchIndirect => break,
                _ => {}
            }
        }
        conditional
    }

    fn index_interval_for_condition(
        &self,
        condition: IlValueId,
        index: IlValueId,
        taken: bool,
        depth: u32,
    ) -> Option<StridedInterval> {
        if depth == 0 {
            return None;
        }
        let operation = self.ssa.defining_operation(condition)?;
        let operands = self.ssa.operation_operands(operation);
        match operation.opcode() {
            ECodeSsaOpcode::BoolNot => {
                let inner = *operands.first()?;
                self.index_interval_for_condition(inner, index, !taken, depth - 1)
            }
            ECodeSsaOpcode::BoolAnd | ECodeSsaOpcode::BoolOr => {
                let a =
                    self.index_interval_for_condition(*operands.first()?, index, taken, depth - 1);
                let b =
                    self.index_interval_for_condition(*operands.get(1)?, index, taken, depth - 1);
                let conjunction = (operation.opcode() == ECodeSsaOpcode::BoolAnd) == taken;
                if conjunction {
                    match (a, b) {
                        (Some(a), Some(b)) => Some(a.meet(&b)),
                        (Some(interval), None) | (None, Some(interval)) => Some(interval),
                        (None, None) => None,
                    }
                } else {
                    match (a, b) {
                        (Some(a), Some(b)) => Some(a.join(&b)),
                        _ => None,
                    }
                }
            }
            _ => self.index_interval_for_comparison(operation, index, taken),
        }
    }

    fn index_interval_for_comparison(
        &self,
        operation: &ECodeSsaOp,
        index: IlValueId,
        taken: bool,
    ) -> Option<StridedInterval> {
        let width = self.ssa.value_width(index)?;
        let relation = match operation.opcode() {
            ECodeSsaOpcode::IntLess | ECodeSsaOpcode::IntSignedLess => Relation::Less,
            ECodeSsaOpcode::IntLessEqual | ECodeSsaOpcode::IntSignedLessEqual => {
                Relation::LessEqual
            }
            ECodeSsaOpcode::IntEqual => Relation::Equal,
            ECodeSsaOpcode::IntNotEqual => Relation::NotEqual,
            _ => return None,
        };
        let operands = self.ssa.operation_operands(operation);
        let (&a, &b) = (operands.first()?, operands.get(1)?);

        let (relation, offset, constant) = if let Some(offset) = self.index_offset(a, index, width)
        {
            (relation, offset, self.ssa.constant_value(b)?)
        } else if let Some(offset) = self.index_offset(b, index, width) {
            (
                relation.invert_operands(),
                offset,
                self.ssa.constant_value(a)?,
            )
        } else {
            return None;
        };
        let constant = constant.unsigned_cast(width);

        let bound = match relation {
            Relation::Equal | Relation::NotEqual => &constant - &offset,
            _ if offset.is_zero() => constant,
            _ => return None,
        };
        let effective = if taken { relation } else { relation.negate() };
        Some(effective.interval(&bound, width))
    }

    fn index_offset(&self, value: IlValueId, index: IlValueId, width: u32) -> Option<BitVec> {
        let value = self.underlying_value(value);
        if self.matches_index(value, index) {
            return Some(BitVec::zero(width));
        }
        let operation = self.ssa.defining_operation(value)?;
        let operands = self.ssa.operation_operands(operation);
        let (&a, &b) = (operands.first()?, operands.get(1)?);
        match operation.opcode() {
            ECodeSsaOpcode::Sub if self.matches_index(a, index) => {
                Some(&BitVec::zero(width) - &self.ssa.constant_value(b)?.unsigned_cast(width))
            }
            ECodeSsaOpcode::Add if self.matches_index(a, index) => {
                Some(self.ssa.constant_value(b)?.unsigned_cast(width))
            }
            ECodeSsaOpcode::Add if self.matches_index(b, index) => {
                Some(self.ssa.constant_value(a)?.unsigned_cast(width))
            }
            _ => None,
        }
    }

    fn matches_index(&self, operand: IlValueId, index: IlValueId) -> bool {
        let a = self.canonical(operand);
        let b = self.canonical(index);
        if a == b {
            return true;
        }
        let (Some(oa), Some(ob)) = (
            self.ssa.defining_operation(a),
            self.ssa.defining_operation(b),
        ) else {
            return false;
        };
        oa.opcode() == ECodeSsaOpcode::Undefined
            && ob.opcode() == ECodeSsaOpcode::Undefined
            && oa.immediate() == ob.immediate()
    }

    pub(crate) fn resolve_guard_default_target(
        &self,
        guard: &SwitchGuard,
        context: &ContextSet,
        translator: &mut Translator,
    ) -> Option<AddressWithContext> {
        let address = match guard.default {
            SwitchGuardDefault::Block(block) => {
                let address = self.block_address(block)?;
                context.apply(address, translator.context_mut());
                let mut resolver =
                    SwitchTargetResolver::new(self.arch, self.segments, address.space());
                return resolver.resolve_address(address.raw_address(), translator.context());
            }
            SwitchGuardDefault::DirectBranch(address) => address,
        };
        let mut resolver = SwitchTargetResolver::new(self.arch, self.segments, address.space());
        resolver.resolve_direct_branch(address, None, context, translator)
    }

    fn alternate_successor(&self, block: IlBlockId, exclude: IlBlockId) -> Option<IlBlockId> {
        let graph = self.ssa.graph();
        let range = graph.blocks().get(block.index())?.successors();
        graph.successors()[range.start()..range.end()]
            .iter()
            .copied()
            .find(|&successor| successor != exclude)
    }

    fn block_address(&self, block: IlBlockId) -> Option<Address> {
        let range = self.ssa.graph().blocks().get(block.index())?.operations();
        self.ssa
            .source_span_for(range.start() as u32)
            .map(|span| span.address())
    }

    fn dominates(&self, dominator: IlBlockId, block: IlBlockId) -> bool {
        dominator == block || self.dominance.dominates(dominator, block)
    }
}
