use fugue_bv::BitVec;

use crate::analysis::function::recovery::Translator;
use crate::analysis::switch::SwitchTargetResolver;
use crate::analysis::value::StridedInterval;
use crate::il::common::{IlBlockId, IlValueId};
use crate::il::ecode::ssa::{ECodeSsaOp, ECodeSsaOpcode};
use crate::ir::{Address, AddressWithContext};
use crate::lifter::ContextSet;
use crate::storage::segments::SegmentReader;

use super::SwitchSliceEvaluator;

enum GuardDefault {
    Block(IlBlockId),
    Staging(Address),
}

struct GuardMatch {
    interval: StridedInterval,
    default: GuardDefault,
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
}

impl<'a> SwitchSliceEvaluator<'a> {
    fn find_guard(&self, index: IlValueId, branch: Address) -> Option<GuardMatch> {
        if let Some(guard) = self.same_source_guard(index, branch) {
            return Some(guard);
        }
        let switch_block = self.block_of_source(branch)?;
        let width = self.ssa.value_width(index)?;
        let ceiling = BitVec::max_value_with(width, false);
        for (op_index, op) in self.ssa.operations().iter().enumerate() {
            if op.opcode() != ECodeSsaOpcode::ConditionalBranch {
                continue;
            }
            let Some(&condition) = self.ssa.operation_operands(op).first() else {
                continue;
            };
            let Some(guard_block) = self.operation_blocks[op_index] else {
                continue;
            };
            if !self.dominates(guard_block, switch_block) {
                continue;
            }
            let Some(taken) = op.address().and_then(|taken| self.block_of_source(taken)) else {
                continue;
            };
            let Some(fallthrough) = self.other_successor(guard_block, taken) else {
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

            let Some(interval) = self.guard_interval(
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
            return Some(GuardMatch {
                interval,
                default: GuardDefault::Block(default_block),
            });
        }
        None
    }

    fn same_source_guard(&self, index: IlValueId, branch: Address) -> Option<GuardMatch> {
        let width = self.ssa.value_width(index)?;
        let ceiling = BitVec::max_value_with(width, false);
        let operation = self.same_source_conditional(branch)?;
        let condition = *self.ssa.operation_operands(operation).first()?;
        let interval =
            self.guard_interval(condition, index, false, self.config.max_trace_depth())?;
        if interval.upper()? >= &ceiling {
            return None;
        }
        Some(GuardMatch {
            interval,
            default: GuardDefault::Staging(operation.address()?),
        })
    }

    fn same_source_conditional(&self, branch: Address) -> Option<&ECodeSsaOp> {
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

    fn guard_interval(
        &self,
        condition: IlValueId,
        index: IlValueId,
        taken: bool,
        depth: u32,
    ) -> Option<StridedInterval> {
        if depth == 0 {
            return None;
        }
        let op = self.ssa.defining_operation(condition)?;
        let operands = self.ssa.operation_operands(op);
        match op.opcode() {
            ECodeSsaOpcode::BoolNot => {
                let inner = *operands.first()?;
                self.guard_interval(inner, index, !taken, depth - 1)
            }
            ECodeSsaOpcode::BoolAnd | ECodeSsaOpcode::BoolOr => {
                let a = self.guard_interval(*operands.first()?, index, taken, depth - 1);
                let b = self.guard_interval(*operands.get(1)?, index, taken, depth - 1);
                let conjunction = (op.opcode() == ECodeSsaOpcode::BoolAnd) == taken;
                if conjunction {
                    Self::intersect(a, b)
                } else {
                    Self::unite(a, b)
                }
            }
            _ => self.comparison_interval(op, index, taken),
        }
    }

    fn intersect(
        a: Option<StridedInterval>,
        b: Option<StridedInterval>,
    ) -> Option<StridedInterval> {
        match (a, b) {
            (Some(a), Some(b)) => Some(a.meet(&b)),
            (Some(interval), None) | (None, Some(interval)) => Some(interval),
            (None, None) => None,
        }
    }

    fn unite(a: Option<StridedInterval>, b: Option<StridedInterval>) -> Option<StridedInterval> {
        match (a, b) {
            (Some(a), Some(b)) => Some(a.join(&b)),
            _ => None,
        }
    }

    fn comparison_interval(
        &self,
        op: &ECodeSsaOp,
        index: IlValueId,
        taken: bool,
    ) -> Option<StridedInterval> {
        let width = self.ssa.value_width(index)?;
        let relation = match op.opcode() {
            ECodeSsaOpcode::IntLess | ECodeSsaOpcode::IntSignedLess => Relation::Less,
            ECodeSsaOpcode::IntLessEqual | ECodeSsaOpcode::IntSignedLessEqual => {
                Relation::LessEqual
            }
            ECodeSsaOpcode::IntEqual => Relation::Equal,
            ECodeSsaOpcode::IntNotEqual => Relation::NotEqual,
            _ => return None,
        };
        let operands = self.ssa.operation_operands(op);
        let (&a, &b) = (operands.first()?, operands.get(1)?);

        let (relation, offset, constant) = if let Some(offset) = self.index_affine(a, index, width)
        {
            (relation, offset, self.ssa.constant_value(b)?)
        } else if let Some(offset) = self.index_affine(b, index, width) {
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
        Some(self.relation_interval(effective, &bound, width))
    }

    fn relation_interval(&self, relation: Relation, bound: &BitVec, width: u32) -> StridedInterval {
        let zero = BitVec::zero(width);
        let one = BitVec::one(width);
        let ceiling = BitVec::max_value_with(width, false);
        let range = |lo: BitVec, hi: BitVec| {
            if lo > hi {
                StridedInterval::empty(width)
            } else {
                StridedInterval::range(lo, hi, one.clone())
            }
        };
        match relation {
            Relation::Less if bound.is_zero() => StridedInterval::empty(width),
            Relation::Less => range(zero, bound - &one),
            Relation::LessEqual => range(zero, bound.clone()),
            Relation::Greater if *bound >= ceiling => StridedInterval::empty(width),
            Relation::Greater => range(bound + &one, ceiling),
            Relation::GreaterEqual => range(bound.clone(), ceiling),
            Relation::Equal => StridedInterval::single(bound.clone()),
            Relation::NotEqual => StridedInterval::full(width),
        }
    }

    fn index_affine(&self, value: IlValueId, index: IlValueId, width: u32) -> Option<BitVec> {
        let value = self.ssa.underlying_value(value);
        if self.same_index(value, index) {
            return Some(BitVec::zero(width));
        }
        let op = self.ssa.defining_operation(value)?;
        let operands = self.ssa.operation_operands(op);
        let (&a, &b) = (operands.first()?, operands.get(1)?);
        match op.opcode() {
            ECodeSsaOpcode::Sub if self.same_index(a, index) => {
                Some(&BitVec::zero(width) - &self.ssa.constant_value(b)?.unsigned_cast(width))
            }
            ECodeSsaOpcode::Add if self.same_index(a, index) => {
                Some(self.ssa.constant_value(b)?.unsigned_cast(width))
            }
            ECodeSsaOpcode::Add if self.same_index(b, index) => {
                Some(self.ssa.constant_value(a)?.unsigned_cast(width))
            }
            _ => None,
        }
    }

    pub(super) fn canonical(&self, value: IlValueId) -> IlValueId {
        let mut current = self.ssa.underlying_value(value);
        for _ in 0..self.config.max_trace_depth() {
            let Some(feeder) = self.single_source_feeder(current) else {
                break;
            };
            let next = self.ssa.underlying_value(feeder);
            if next == current {
                break;
            }
            current = next;
        }
        current
    }

    fn same_index(&self, operand: IlValueId, index: IlValueId) -> bool {
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

    pub(super) fn guard_bound(
        &self,
        index: IlValueId,
        width: u32,
        branch: Address,
    ) -> Option<BitVec> {
        let guard = self.find_guard(index, branch)?;
        Some(guard.interval.upper()?.unsigned_cast(width))
    }

    pub(super) fn guard_default(
        &self,
        index: IlValueId,
        branch: Address,
        context: &ContextSet,
        translator: &mut Translator,
    ) -> Option<AddressWithContext> {
        if let Some(address) = self
            .same_source_conditional(branch)
            .and_then(ECodeSsaOp::address)
        {
            let mut entries = SegmentReader::new(self.segments);
            let mut resolver = SwitchTargetResolver::new(self.arch, self.segments, address.space());
            return self.decode_direct_branch(
                address,
                None,
                context,
                translator,
                &mut entries,
                &mut resolver,
            );
        }
        let guard = self.find_guard(index, branch)?;
        let address = match guard.default {
            GuardDefault::Block(block) => {
                let address = self.block_address(block)?;
                context.apply(address, translator.context_mut());
                let mut resolver =
                    SwitchTargetResolver::new(self.arch, self.segments, address.space());
                return resolver.resolve_address(address.raw_address(), translator.context());
            }
            GuardDefault::Staging(address) => address,
        };
        let mut entries = SegmentReader::new(self.segments);
        let mut resolver = SwitchTargetResolver::new(self.arch, self.segments, address.space());
        self.decode_direct_branch(
            address,
            None,
            context,
            translator,
            &mut entries,
            &mut resolver,
        )
    }

    fn other_successor(&self, block: IlBlockId, exclude: IlBlockId) -> Option<IlBlockId> {
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
