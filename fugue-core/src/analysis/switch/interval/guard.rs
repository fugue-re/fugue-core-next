use fugue_bv::BitVec;
use rustc_hash::FxHashSet;

use super::SwitchIntervalRecovery;
use crate::analysis::switch::SwitchTargetResolver;
use crate::analysis::value::StridedInterval;
use crate::il::common::{IlBlockId, IlValueId};
use crate::il::ecode::ssa::{ECodeSsaOp, ECodeSsaOpcode};
use crate::ir::{Address, AddressRange, AddressWithContext};
use crate::lifter::{ContextSet, InsnResolver};

pub(crate) struct SwitchGuard {
    interval: StridedInterval,
    default_block: Option<IlBlockId>,
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

enum ConditionStep {
    Evaluate {
        condition: IlValueId,
        taken: bool,
        depth: u32,
    },
    Merge {
        conjunction: bool,
    },
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
    pub(crate) fn interval(&self) -> &StridedInterval {
        &self.interval
    }
}

impl<'analysis> SwitchIntervalRecovery<'analysis> {
    pub(crate) fn guard_for_index(&self, index: IlValueId, branch: Address) -> Option<SwitchGuard> {
        if let Some(guard) = self.guard_within_branch_instruction(index, branch) {
            tracing::trace!("switch at {branch}: using intra-instruction guard");
            return Some(guard);
        }
        let switch_block = self.block_for_source(branch)?;
        let width = self.ssa.value_width(index)?;
        let ceiling = BitVec::max_value_with(width, false);
        let mut guard_block = Some(switch_block);
        while let Some(block) = guard_block {
            for (_, operation) in self.ssa.operations_for_block(block).rev() {
                if operation.opcode() != ECodeSsaOpcode::ConditionalBranch {
                    continue;
                }
                let Some(&condition) = self.ssa.operation_operands_for(operation).first() else {
                    continue;
                };
                let Some(taken) = operation
                    .address()
                    .and_then(|taken| self.block_for_source(taken))
                else {
                    continue;
                };
                let Some(fall_through) = self
                    .ssa
                    .graph()
                    .successors_for(block)
                    .iter()
                    .copied()
                    .find(|&successor| successor != taken)
                else {
                    continue;
                };

                let taken_is_switch = self.dominance.dominates(taken, switch_block);
                let fall_through_is_switch = self.dominance.dominates(fall_through, switch_block);
                let (switch_taken, default_block) = if taken_is_switch && !fall_through_is_switch {
                    (true, fall_through)
                } else if fall_through_is_switch && !taken_is_switch {
                    (false, taken)
                } else {
                    continue;
                };
                let Some(interval) = self.index_interval_from_condition(
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
                tracing::trace!(
                    "switch at {branch}: using guard in block {block:?} with default block {default_block:?}"
                );
                return Some(SwitchGuard {
                    interval,
                    default_block: Some(default_block),
                });
            }
            guard_block = self.dominance.immediate_dominator(block);
        }
        None
    }

    fn guard_within_branch_instruction(
        &self,
        index: IlValueId,
        branch: Address,
    ) -> Option<SwitchGuard> {
        let width = self.ssa.value_width(index)?;
        let ceiling = BitVec::max_value_with(width, false);
        let operation = self.conditional_branch_within_instruction(branch)?;
        let condition = *self.ssa.operation_operands_for(operation).first()?;
        let interval = self.index_interval_from_condition(
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
            default_block: None,
        })
    }

    fn conditional_branch_within_instruction(&self, branch: Address) -> Option<&ECodeSsaOp> {
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

    fn index_interval_from_condition(
        &self,
        condition: IlValueId,
        index: IlValueId,
        taken: bool,
        depth: u32,
    ) -> Option<StridedInterval> {
        let mut steps = vec![ConditionStep::Evaluate {
            condition,
            taken,
            depth,
        }];
        let mut intervals = Vec::new();

        while let Some(step) = steps.pop() {
            match step {
                ConditionStep::Evaluate {
                    condition,
                    taken,
                    depth,
                } => {
                    let Some(operation) = (depth > 0)
                        .then(|| self.ssa.defining_operation(condition))
                        .flatten()
                    else {
                        intervals.push(None);
                        continue;
                    };
                    let operands = self.ssa.operation_operands_for(operation);

                    match operation.opcode() {
                        ECodeSsaOpcode::BoolNot => {
                            let Some(&inner) = operands.first() else {
                                intervals.push(None);
                                continue;
                            };
                            steps.push(ConditionStep::Evaluate {
                                condition: inner,
                                taken: !taken,
                                depth: depth - 1,
                            });
                        }
                        ECodeSsaOpcode::BoolAnd | ECodeSsaOpcode::BoolOr => {
                            let (Some(&left), Some(&right)) = (operands.first(), operands.get(1))
                            else {
                                intervals.push(None);
                                continue;
                            };
                            steps.push(ConditionStep::Merge {
                                conjunction: (operation.opcode() == ECodeSsaOpcode::BoolAnd)
                                    == taken,
                            });
                            steps.push(ConditionStep::Evaluate {
                                condition: right,
                                taken,
                                depth: depth - 1,
                            });
                            steps.push(ConditionStep::Evaluate {
                                condition: left,
                                taken,
                                depth: depth - 1,
                            });
                        }
                        _ => intervals
                            .push(self.index_interval_from_comparison(operation, index, taken)),
                    }
                }
                ConditionStep::Merge { conjunction } => {
                    let right = intervals.pop().flatten();
                    let left = intervals.pop().flatten();
                    let interval = if conjunction {
                        match (left, right) {
                            (Some(left), Some(right)) => Some(left.meet(&right)),
                            (Some(interval), None) | (None, Some(interval)) => Some(interval),
                            (None, None) => None,
                        }
                    } else {
                        match (left, right) {
                            (Some(left), Some(right)) => Some(left.join(&right)),
                            _ => None,
                        }
                    };
                    intervals.push(interval);
                }
            }
        }

        intervals.pop().flatten()
    }

    fn index_interval_from_comparison(
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
        let operands = self.ssa.operation_operands_for(operation);
        let (&a, &b) = (operands.first()?, operands.get(1)?);

        let (relation, offset, constant) =
            if let Some(offset) = self.offset_from_index(a, index, width) {
                (relation, offset, self.ssa.constant_value(b)?)
            } else {
                let offset = self.offset_from_index(b, index, width)?;
                (
                    relation.invert_operands(),
                    offset,
                    self.ssa.constant_value(a)?,
                )
            };

        let narrowed = constant.unsigned_cast(width);
        if narrowed.unsigned_cast(constant.bits()) != constant.clone().unsigned() {
            return None;
        }
        let constant = narrowed;

        let bound = match relation {
            Relation::Equal | Relation::NotEqual => &constant - &offset,
            _ if offset.is_zero() => constant,
            _ => return None,
        };
        let effective = if taken { relation } else { relation.negate() };
        Some(effective.interval(&bound, width))
    }

    fn offset_from_index(&self, value: IlValueId, index: IlValueId, width: u32) -> Option<BitVec> {
        let value = self.ssa.underlying_value(value);
        if self.matches_index(value, index) {
            return Some(BitVec::zero(width));
        }
        let operation = self.ssa.defining_operation(value)?;
        let operands = self.ssa.operation_operands_for(operation);
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
        let mut pending = vec![(operand, index, 0u32)];
        let mut visited = FxHashSet::default();
        let mut steps = 0usize;

        while let Some((a, b, depth)) = pending.pop() {
            let a = self.comparison_value(a);
            let b = self.comparison_value(b);
            if a == b || !visited.insert((a, b)) {
                continue;
            }
            if steps >= self.config.max_trace_steps() {
                return false;
            }
            steps += 1;

            let (Some(oa), Some(ob)) = (
                self.ssa.defining_operation(a),
                self.ssa.defining_operation(b),
            ) else {
                return false;
            };
            if oa.opcode() == ECodeSsaOpcode::Undefined && ob.opcode() == ECodeSsaOpcode::Undefined
            {
                if oa.width() == ob.width() && oa.immediate() == ob.immediate() {
                    continue;
                }
                return false;
            }
            if oa.opcode() != ob.opcode() || oa.width() != ob.width() {
                return false;
            }
            if oa.opcode() == ECodeSsaOpcode::Constant {
                if self.ssa.constant_value(a) == self.ssa.constant_value(b) {
                    continue;
                }
                return false;
            }
            if oa.opcode() == ECodeSsaOpcode::Load {
                if oa.immediate() != ob.immediate()
                    || oa.address() != ob.address()
                    || oa.address_space() != ob.address_space()
                    || depth >= self.config.max_trace_depth()
                {
                    return false;
                }
                let (Some(a_pointer), Some(b_pointer)) =
                    (self.ssa.pointer_operand(oa), self.ssa.pointer_operand(ob))
                else {
                    return false;
                };
                if self.ssa.memory_operand(oa) != self.ssa.memory_operand(ob)
                    && !self.observes_same_memory(oa, ob)
                {
                    return false;
                }
                pending.push((a_pointer, b_pointer, depth + 1));
                continue;
            }
            if depth >= self.config.max_trace_depth()
                || oa.opcode().has_side_effect()
                || oa.immediate() != ob.immediate()
                || oa.address() != ob.address()
                || oa.address_space() != ob.address_space()
            {
                return false;
            }

            let a_operands = self.ssa.operation_operands_for(oa);
            let b_operands = self.ssa.operation_operands_for(ob);
            if a_operands.len() != b_operands.len() {
                return false;
            }
            pending.extend(
                a_operands
                    .iter()
                    .copied()
                    .zip(b_operands.iter().copied())
                    .map(|(a, b)| (a, b, depth + 1)),
            );
        }

        true
    }

    fn observes_same_memory(&self, a: &ECodeSsaOp, b: &ECodeSsaOp) -> bool {
        let (Some(a_range), Some(b_range)) = (
            self.ssa.memory_access_range(a),
            self.ssa.memory_access_range(b),
        ) else {
            return false;
        };
        if a_range != b_range {
            return false;
        }
        let (Some(a_memory), Some(b_memory)) =
            (self.ssa.memory_operand(a), self.ssa.memory_operand(b))
        else {
            return false;
        };
        self.memory_preserved_for_range(a_memory, b_memory, &a_range)
            || self.memory_preserved_for_range(b_memory, a_memory, &a_range)
    }

    fn memory_preserved_for_range(
        &self,
        from: IlValueId,
        to: IlValueId,
        range: &AddressRange,
    ) -> bool {
        let mut state = from;
        for _ in 0..self.config.max_trace_steps() {
            if state == to {
                return true;
            }
            let Some(operation) = self.ssa.defining_operation(state) else {
                return false;
            };
            if operation.opcode() != ECodeSsaOpcode::Store {
                return false;
            }
            if let Some(stored) = self.ssa.memory_access_range(operation)
                && stored.intersects(range)
            {
                return false;
            }
            let Some(previous) = self.ssa.memory_operand(operation) else {
                return false;
            };
            state = previous;
        }
        false
    }

    fn comparison_value(&self, value: IlValueId) -> IlValueId {
        let mut current = self.canonical_value(value);
        for _ in 0..self.config.max_trace_depth() {
            let Some(inner) = self.ssa.extract_source(current) else {
                break;
            };
            let next = self.canonical_value(inner);
            if next == current {
                break;
            }
            current = next;
        }
        current
    }

    pub(crate) fn resolve_default_branch_target(
        &self,
        guard: Option<&SwitchGuard>,
        branch: Address,
        context: &ContextSet,
        insn_resolver: &mut InsnResolver,
        target_resolver: &mut SwitchTargetResolver<'_>,
    ) -> Option<AddressWithContext> {
        if let Some(address) = self
            .conditional_branch_within_instruction(branch)
            .and_then(ECodeSsaOp::address)
        {
            tracing::trace!(
                "switch at {branch}: resolving intra-instruction default branch at {address}"
            );
            target_resolver.set_space(address.space());
            return target_resolver
                .resolve_branch_target(address, None, context, insn_resolver)
                .or_else(|| {
                    context.apply(address, insn_resolver.context_mut());
                    target_resolver.resolve_address(address.raw_address(), insn_resolver.context())
                });
        }

        let block = guard?.default_block?;
        let address = self.ssa.block_address(block)?;
        tracing::trace!("switch at {branch}: resolving guard default block {block:?} at {address}");
        context.apply(address, insn_resolver.context_mut());
        target_resolver.set_space(address.space());
        target_resolver.resolve_address(address.raw_address(), insn_resolver.context())
    }
}
