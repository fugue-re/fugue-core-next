use crate::analysis::value::StridedInterval;
use crate::il::common::{IlAnalysis, IlArtefact, IlCsr, IlValueId};
use crate::il::ecode::{ECodeBlockArgInputs, ECodeIr, ECodeOpcode, ECodeUses};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ECodeStridedIntervals {
    intervals: Vec<StridedInterval>,
}

impl IlAnalysis<ECodeIr> for ECodeStridedIntervals {
    fn analyse(ir: &ECodeIr) -> Self {
        let block_arg_inputs = ir.analyse::<ECodeBlockArgInputs>();
        let mut this = Self {
            intervals: ir
                .values()
                .iter()
                .map(|value| StridedInterval::empty(value.width()))
                .collect(),
        };

        let dependents = IlCsr::from_entries(
            ir.values().len(),
            block_arg_inputs.iter().flat_map(|(arg, inputs)| {
                inputs.iter().map(move |input| (input.index(), arg.index()))
            }),
        );

        let uses = ir.analyse::<ECodeUses>();
        let mut worklist = (0..ir.values().len()).rev().collect::<Vec<_>>();

        while let Some(index) = worklist.pop() {
            let value = IlValueId::try_from_index(index).expect("value id is representable");
            let next = match block_arg_inputs.inputs_for(value) {
                Some([]) => StridedInterval::full(ir.value_width(value).unwrap_or(0)),
                Some(inputs) => {
                    let joined = inputs.iter().fold(
                        StridedInterval::empty(ir.value_width(value).unwrap_or(0)),
                        |accumulated, input| accumulated.join(&this.intervals[input.index()]),
                    );
                    this.intervals[index].widen(&joined)
                }
                None => this.evaluate(ir, value),
            };

            if next == this.intervals[index] {
                continue;
            }
            this.intervals[index] = next;

            for use_site in uses.uses_for(value) {
                let user = &ir.ops()[use_site.user().index()];
                worklist.extend(user.results().start()..user.results().end());
            }
            worklist.extend(dependents.row(index));
        }

        this
    }
}

impl ECodeStridedIntervals {
    pub fn interval_for(&self, value: IlValueId) -> Option<&StridedInterval> {
        self.intervals.get(value.index())
    }

    fn evaluate(&self, ir: &ECodeIr, value: IlValueId) -> StridedInterval {
        let width = ir.value_width(value).unwrap_or(0);
        if width == 0 {
            return StridedInterval::empty(0);
        }
        if let Some(constant) = ir.constant_value(value) {
            return StridedInterval::single(constant);
        }

        let Some(operation) = ir.defining_op(value) else {
            return StridedInterval::full(width);
        };
        let operands = ir.op_operands_for(operation);
        let operand = |index: usize| {
            operands
                .get(index)
                .map(|value| &self.intervals[value.index()])
        };
        let unary = |arg: Option<&StridedInterval>,
                     transfer: fn(&StridedInterval, u32) -> StridedInterval| {
            arg.map(|arg| transfer(arg, width))
        };
        let binary =
            |left: Option<&StridedInterval>,
             right: Option<&StridedInterval>,
             transfer: fn(&StridedInterval, &StridedInterval) -> StridedInterval| {
                Some(transfer(&left?.cast_to(width), &right?.cast_to(width)))
            };

        let result = match operation.opcode() {
            ECodeOpcode::Copy | ECodeOpcode::WriteFlag | ECodeOpcode::WriteRegister => {
                unary(operand(0), StridedInterval::cast_to)
            }
            ECodeOpcode::ZeroExtend => unary(operand(0), StridedInterval::zero_extend),
            ECodeOpcode::SignExtend => unary(operand(0), StridedInterval::sign_extend),
            ECodeOpcode::Truncate => unary(operand(0), StridedInterval::truncate),
            ECodeOpcode::Add => binary(operand(0), operand(1), |left, right| left + right),
            ECodeOpcode::Sub => binary(operand(0), operand(1), |left, right| left - right),
            ECodeOpcode::Mul => binary(operand(0), operand(1), |left, right| left * right),
            ECodeOpcode::LeftShift => binary(operand(0), operand(1), |left, right| left << right),
            ECodeOpcode::And => binary(operand(0), operand(1), |left, right| left & right),
            ECodeOpcode::Or => binary(operand(0), operand(1), |left, right| left | right),
            ECodeOpcode::LogicalRightShift => {
                binary(operand(0), operand(1), |left, right| left >> right)
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
        IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlGraph, IlIndexRange, IlMetadata,
    };
    use crate::il::ecode::test::emit_value;
    use crate::il::ecode::{ECodeBuilder, ECodeOpSpec, ECodeOpcode};
    use crate::ir::FunctionId;

    fn builder() -> ECodeBuilder {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        ECodeBuilder::new(metadata, IlGraph::default())
    }

    #[test]
    fn masking_bounds_an_unknown_index() {
        let mut builder = builder();
        let unknown = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Undefined, 32),
            [],
        )
        .unwrap();
        let mask = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(0xff),
            [],
        )
        .unwrap();
        let index = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::And, 32),
            [unknown, mask],
        )
        .unwrap();

        let ir = builder.build(&CancellationToken::default()).unwrap();
        let intervals = ir.analyse::<ECodeStridedIntervals>();

        assert_eq!(
            intervals.interval_for(index),
            Some(&StridedInterval::masked(&BitVec::from_u64(0xff, 32)))
        );
    }

    #[test]
    fn arithmetic_propagates_through_operations() {
        let mut builder = builder();
        let left = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(10),
            [],
        )
        .unwrap();
        let right = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(5),
            [],
        )
        .unwrap();
        let sum = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Add, 32),
            [left, right],
        )
        .unwrap();

        let ir = builder.build(&CancellationToken::default()).unwrap();
        let intervals = ir.analyse::<ECodeStridedIntervals>();

        assert_eq!(
            intervals.interval_for(sum),
            Some(&StridedInterval::single(BitVec::from_u64(15, 32)))
        );
    }

    #[test]
    fn loop_carried_value_widens_to_termination() {
        let block1 = IlBlockId::try_from_index(1).unwrap();
        let block2 = IlBlockId::try_from_index(2).unwrap();
        let mut builder = builder();

        builder.set_graph(IlGraph::new(
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
            vec![IlEdgeKinds::UNCONDITIONAL; 3],
        ));

        let initial = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(0),
            [],
        )
        .unwrap();

        let counter = builder.emitter().emit_block_arg(block1, 32).unwrap();

        let one = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(1),
            [],
        )
        .unwrap();
        let next = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Add, 32),
            [counter, one],
        )
        .unwrap();

        builder.emitter().emit_edge_args([initial]).unwrap();
        builder.emitter().emit_edge_args([next]).unwrap();
        builder.emitter().emit_edge_args([]).unwrap();

        let ir = builder.build(&CancellationToken::default()).unwrap();
        let intervals = ir.analyse::<ECodeStridedIntervals>();

        assert_eq!(
            intervals.interval_for(counter),
            Some(&StridedInterval::full(32))
        );
    }
}
