use crate::il::common::{IlBlockId, IlValueId};
use crate::il::ecode::ssa::ECodeSsaIr;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ECodeSsaLiveness {
    live_in_offsets: Vec<u32>,
    live_in_values: Vec<IlValueId>,
    live_out_offsets: Vec<u32>,
    live_out_values: Vec<IlValueId>,
}

impl ECodeSsaLiveness {
    pub fn build(body: &ECodeSsaIr) -> Self {
        let block_count = body.graph().blocks().len();
        let value_count = body.values().len();

        if block_count == 0 {
            return Self::default();
        }

        let mut block_use = vec![vec![false; value_count]; block_count];
        let mut block_def = vec![vec![false; value_count]; block_count];

        Self::collect_block_arguments(body, &mut block_def);
        Self::collect_operation_uses(body, &mut block_use, &mut block_def);

        let mut live_in = vec![vec![false; value_count]; block_count];
        let mut live_out = vec![vec![false; value_count]; block_count];
        let mut changed = true;

        while changed {
            changed = false;

            for (block_index, block) in body.graph().blocks().iter().enumerate().rev() {
                let mut next_live_out = vec![false; value_count];

                for successor in block.successors().slice(body.graph().successors()) {
                    for (value_index, live) in live_in[successor.index()].iter().enumerate() {
                        next_live_out[value_index] |= *live;
                    }
                }

                let mut next_live_in = block_use[block_index].clone();

                for value_index in 0..value_count {
                    next_live_in[value_index] |=
                        next_live_out[value_index] && !block_def[block_index][value_index];
                }

                if live_out[block_index] != next_live_out {
                    live_out[block_index] = next_live_out;
                    changed = true;
                }

                if live_in[block_index] != next_live_in {
                    live_in[block_index] = next_live_in;
                    changed = true;
                }
            }
        }

        let (live_in_offsets, live_in_values) = Self::pack_sets(&live_in);
        let (live_out_offsets, live_out_values) = Self::pack_sets(&live_out);

        Self {
            live_in_offsets,
            live_in_values,
            live_out_offsets,
            live_out_values,
        }
    }

    pub fn live_in(&self, block: IlBlockId) -> &[IlValueId] {
        Self::values_for(block, &self.live_in_offsets, &self.live_in_values)
    }

    pub fn live_out(&self, block: IlBlockId) -> &[IlValueId] {
        Self::values_for(block, &self.live_out_offsets, &self.live_out_values)
    }

    fn collect_block_arguments(body: &ECodeSsaIr, block_def: &mut [Vec<bool>]) {
        for argument in body.block_arguments() {
            block_def[argument.block().index()][argument.value().index()] = true;
        }
    }

    fn collect_operation_uses(
        body: &ECodeSsaIr,
        block_use: &mut [Vec<bool>],
        block_def: &mut [Vec<bool>],
    ) {
        for (block_index, block) in body.graph().blocks().iter().enumerate() {
            for operation in block.operations().slice(body.operations()) {
                for operand in operation.operands().slice(body.value_operands()) {
                    let value_index = operand.index();

                    if !block_def[block_index][value_index] {
                        block_use[block_index][value_index] = true;
                    }
                }

                for defined in &mut block_def[block_index]
                    [operation.results().start()..operation.results().end()]
                {
                    *defined = true;
                }
            }
        }
    }

    fn pack_sets(sets: &[Vec<bool>]) -> (Vec<u32>, Vec<IlValueId>) {
        let mut offsets = Vec::with_capacity(sets.len() + 1);
        let mut values = Vec::new();

        offsets.push(0);

        for set in sets {
            for (value_index, live) in set.iter().enumerate() {
                if *live {
                    values.push(
                        IlValueId::try_from_index(value_index)
                            .expect("value count fits the value id space"),
                    );
                }
            }

            offsets.push(values.len() as u32);
        }

        (offsets, values)
    }

    fn values_for<'a>(
        block: IlBlockId,
        offsets: &[u32],
        values: &'a [IlValueId],
    ) -> &'a [IlValueId] {
        let index = block.index();
        let Some(start) = offsets.get(index).copied() else {
            return &[];
        };
        let end = offsets.get(index + 1).copied().unwrap_or(start);

        &values[start as usize..end as usize]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::analysis::control::CancellationToken;
    use crate::il::common::{IlBlock, IlBlockProperties, IlGraph, IlHeader, IlIndexRange};
    use crate::il::ecode::ssa::{
        ECODE_SSA_SCHEMA_VERSION, ECodeSsaBuilder, ECodeSsaOp, ECodeSsaOpcode,
    };
    use crate::ir::FunctionId;

    #[test]
    fn liveness_tracks_value_across_linear_edge() {
        let block0 = IlBlockId::try_from_index(0).unwrap();
        let block1 = IlBlockId::try_from_index(1).unwrap();
        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::new(0, 1).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::new(1, 2).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            vec![block1],
        );
        let mut builder = ECodeSsaBuilder::new(header, graph);
        let (value, results) = builder.push_result_value(64).unwrap();

        builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                results,
                IlIndexRange::EMPTY,
                64,
            ))
            .unwrap();

        let operands = builder.push_value_operands([value]).unwrap();

        builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::Return,
                IlIndexRange::EMPTY,
                operands,
                0,
            ))
            .unwrap();

        let body = builder.build(&CancellationToken::default()).unwrap();
        let liveness = ECodeSsaLiveness::build(&body);

        assert_eq!(liveness.live_in(block0), &[]);
        assert_eq!(liveness.live_out(block0), &[value]);
        assert_eq!(liveness.live_in(block1), &[value]);
        assert_eq!(liveness.live_out(block1), &[]);
    }

    #[test]
    fn liveness_ignores_value_defined_before_same_block_use() {
        let block = IlBlockId::try_from_index(0).unwrap();
        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let graph = IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::new(0, 2).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::ENTRY | IlBlockProperties::EXIT,
            )],
            Vec::new(),
        );
        let mut builder = ECodeSsaBuilder::new(header, graph);
        let (value, results) = builder.push_result_value(32).unwrap();

        builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                results,
                IlIndexRange::EMPTY,
                32,
            ))
            .unwrap();

        let operands = builder.push_value_operands([value]).unwrap();

        builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::Return,
                IlIndexRange::EMPTY,
                operands,
                0,
            ))
            .unwrap();

        let body = builder.build(&CancellationToken::default()).unwrap();
        let liveness = ECodeSsaLiveness::build(&body);

        assert_eq!(liveness.live_in(block), &[]);
        assert_eq!(liveness.live_out(block), &[]);
    }

    #[test]
    fn liveness_treats_block_argument_as_entry_definition() {
        let block = IlBlockId::try_from_index(0).unwrap();
        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let graph = IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::ENTRY | IlBlockProperties::EXIT,
            )],
            Vec::new(),
        );
        let mut builder = ECodeSsaBuilder::new(header, graph);
        let argument = builder.push_block_argument_value(block, 32).unwrap();
        let operands = builder.push_value_operands([argument]).unwrap();

        builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::Return,
                IlIndexRange::EMPTY,
                operands,
                0,
            ))
            .unwrap();

        let body = builder.build(&CancellationToken::default()).unwrap();
        let liveness = ECodeSsaLiveness::build(&body);

        assert_eq!(liveness.live_in(block), &[]);
        assert_eq!(liveness.live_out(block), &[]);
    }
}
