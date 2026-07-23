use crate::analysis::value::StridedInterval;
use crate::il::common::{IlAnalysis, IlArtefact, IlValueId};
use crate::il::ecode::ssa::{
    ECodeSsaBlockArgumentInputs, ECodeSsaIr, ECodeSsaOpcode, ECodeSsaUses,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ECodeSsaStridedIntervals {
    intervals: Vec<StridedInterval>,
}

impl IlAnalysis<ECodeSsaIr> for ECodeSsaStridedIntervals {
    fn analyse(body: &ECodeSsaIr) -> Self {
        let block_argument_inputs = body.analyse::<ECodeSsaBlockArgumentInputs>();
        let mut this = Self {
            intervals: body
                .values()
                .iter()
                .map(|value| StridedInterval::empty(value.width()))
                .collect(),
        };

        let mut dependents = vec![Vec::new(); body.values().len()];
        for (argument, inputs) in block_argument_inputs.iter() {
            for input in inputs {
                dependents[input.index()].push(argument.index());
            }
        }

        let uses = body.analyse::<ECodeSsaUses>();
        let mut worklist = (0..body.values().len()).rev().collect::<Vec<_>>();

        while let Some(index) = worklist.pop() {
            let value = IlValueId::try_from_index(index).expect("value id is representable");
            let next = match block_argument_inputs.get(value) {
                Some([]) => StridedInterval::full(body.value_width(value).unwrap_or(0)),
                Some(inputs) => {
                    let joined = inputs.iter().fold(
                        StridedInterval::empty(body.value_width(value).unwrap_or(0)),
                        |accumulated, input| accumulated.join(&this.intervals[input.index()]),
                    );
                    this.intervals[index].widen(&joined)
                }
                None => this.evaluate(body, value),
            };

            if next == this.intervals[index] {
                continue;
            }
            this.intervals[index] = next;

            for use_site in uses.uses_for(value) {
                let user = &body.operations()[use_site.user().index()];
                if user.results().len() == 1 {
                    worklist.push(user.results().start());
                }
            }
            worklist.extend(&dependents[index]);
        }

        this
    }
}

impl ECodeSsaStridedIntervals {
    pub fn get(&self, value: IlValueId) -> Option<&StridedInterval> {
        self.intervals.get(value.index())
    }

    fn evaluate(&self, body: &ECodeSsaIr, value: IlValueId) -> StridedInterval {
        let width = body.value_width(value).unwrap_or(0);
        if width == 0 {
            return StridedInterval::empty(0);
        }
        if let Some(constant) = body.constant_value(value) {
            return StridedInterval::single(constant);
        }

        let Some(operation) = body.defining_operation(value) else {
            return StridedInterval::full(width);
        };
        let operands = body.operation_operands(operation);
        let operand = |index: usize| {
            operands
                .get(index)
                .map(|value| &self.intervals[value.index()])
        };
        let unary = |argument: Option<&StridedInterval>,
                     transfer: fn(&StridedInterval, u32) -> StridedInterval| {
            argument.map(|argument| transfer(argument, width))
        };
        let binary =
            |left: Option<&StridedInterval>,
             right: Option<&StridedInterval>,
             transfer: fn(&StridedInterval, &StridedInterval) -> StridedInterval| {
                Some(transfer(&left?.cast_to(width), &right?.cast_to(width)))
            };

        let result = match operation.opcode() {
            ECodeSsaOpcode::Copy => unary(operand(0), StridedInterval::cast_to),
            ECodeSsaOpcode::ZeroExtend => unary(operand(0), StridedInterval::zero_extend),
            ECodeSsaOpcode::SignExtend => unary(operand(0), StridedInterval::sign_extend),
            ECodeSsaOpcode::Truncate => unary(operand(0), StridedInterval::truncate),
            ECodeSsaOpcode::Add => binary(operand(0), operand(1), StridedInterval::add),
            ECodeSsaOpcode::Sub => binary(operand(0), operand(1), StridedInterval::sub),
            ECodeSsaOpcode::Mul => binary(operand(0), operand(1), StridedInterval::mul),
            ECodeSsaOpcode::LeftShift => {
                binary(operand(0), operand(1), StridedInterval::shift_left)
            }
            ECodeSsaOpcode::And => binary(operand(0), operand(1), StridedInterval::and),
            ECodeSsaOpcode::Or => binary(operand(0), operand(1), StridedInterval::or),
            ECodeSsaOpcode::LogicalRightShift => {
                binary(operand(0), operand(1), StridedInterval::shift_right)
            }
            _ => None,
        };

        result.unwrap_or_else(|| StridedInterval::full(width))
    }
}

#[cfg(test)]
mod test {
    use fugue_bv::BitVec;

    use super::*;
    use crate::analysis::control::CancellationToken;
    use crate::il::common::{
        IlBlock, IlBlockId, IlBlockProperties, IlGraph, IlHeader, IlIndexRange,
    };
    use crate::il::ecode::ssa::{
        ECODE_SSA_SCHEMA_VERSION, ECodeSsaBuilder, ECodeSsaOp, ECodeSsaOpcode,
    };
    use crate::ir::FunctionId;

    fn builder() -> ECodeSsaBuilder {
        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        ECodeSsaBuilder::new(header, IlGraph::default())
    }

    #[test]
    fn masking_bounds_an_unknown_index() {
        let mut builder = builder();
        let (unknown, unknown_results) = builder.push_result_value(32).unwrap();
        builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::Undefined,
                unknown_results,
                IlIndexRange::EMPTY,
                32,
            ))
            .unwrap();

        let (mask, mask_results) = builder.push_result_value(32).unwrap();
        builder
            .push_operation(
                ECodeSsaOp::new(
                    ECodeSsaOpcode::Constant,
                    mask_results,
                    IlIndexRange::EMPTY,
                    32,
                )
                .with_immediate(0xff),
            )
            .unwrap();

        let operands = builder.push_value_operands([unknown, mask]).unwrap();
        let (index, index_results) = builder.push_result_value(32).unwrap();
        builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::And,
                index_results,
                operands,
                32,
            ))
            .unwrap();

        let body = builder.build(&CancellationToken::default()).unwrap();
        let intervals = body.analyse::<ECodeSsaStridedIntervals>();

        assert_eq!(
            intervals.get(index),
            Some(&StridedInterval::masked(&BitVec::from_u64(0xff, 32)))
        );
    }

    #[test]
    fn arithmetic_propagates_through_operations() {
        let mut builder = builder();
        let (left, left_results) = builder.push_result_value(32).unwrap();
        builder
            .push_operation(
                ECodeSsaOp::new(
                    ECodeSsaOpcode::Constant,
                    left_results,
                    IlIndexRange::EMPTY,
                    32,
                )
                .with_immediate(10),
            )
            .unwrap();

        let (right, right_results) = builder.push_result_value(32).unwrap();
        builder
            .push_operation(
                ECodeSsaOp::new(
                    ECodeSsaOpcode::Constant,
                    right_results,
                    IlIndexRange::EMPTY,
                    32,
                )
                .with_immediate(5),
            )
            .unwrap();

        let operands = builder.push_value_operands([left, right]).unwrap();
        let (sum, sum_results) = builder.push_result_value(32).unwrap();
        builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::Add,
                sum_results,
                operands,
                32,
            ))
            .unwrap();

        let body = builder.build(&CancellationToken::default()).unwrap();
        let intervals = body.analyse::<ECodeSsaStridedIntervals>();

        assert_eq!(
            intervals.get(sum),
            Some(&StridedInterval::single(BitVec::from_u64(15, 32)))
        );
    }

    #[test]
    fn loop_carried_value_widens_to_termination() {
        let block1 = IlBlockId::try_from_index(1).unwrap();
        let block2 = IlBlockId::try_from_index(2).unwrap();
        let mut builder = builder();

        builder.replace_graph(IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::new(0, 1).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::new(1, 3).unwrap(),
                    IlIndexRange::new(1, 3).unwrap(),
                    IlBlockProperties::empty(),
                ),
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            vec![block1, block1, block2],
        ));

        let (seed, seed_results) = builder.push_result_value(32).unwrap();
        builder
            .push_operation(
                ECodeSsaOp::new(
                    ECodeSsaOpcode::Constant,
                    seed_results,
                    IlIndexRange::EMPTY,
                    32,
                )
                .with_immediate(0),
            )
            .unwrap();

        let counter = builder.push_block_argument_value(block1, 32).unwrap();

        let (one, one_results) = builder.push_result_value(32).unwrap();
        builder
            .push_operation(
                ECodeSsaOp::new(
                    ECodeSsaOpcode::Constant,
                    one_results,
                    IlIndexRange::EMPTY,
                    32,
                )
                .with_immediate(1),
            )
            .unwrap();

        let operands = builder.push_value_operands([counter, one]).unwrap();
        let (next, next_results) = builder.push_result_value(32).unwrap();
        builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::Add,
                next_results,
                operands,
                32,
            ))
            .unwrap();

        builder.push_edge_arguments([seed]).unwrap();
        builder.push_edge_arguments([next]).unwrap();
        builder.push_edge_arguments([]).unwrap();

        let body = builder.build(&CancellationToken::default()).unwrap();
        let intervals = body.analyse::<ECodeSsaStridedIntervals>();

        assert_eq!(intervals.get(counter), Some(&StridedInterval::full(32)));
    }
}
