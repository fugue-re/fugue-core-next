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

        let words = value_count.div_ceil(64).max(1);

        let mut block_use = vec![0u64; block_count * words];
        let mut block_def = vec![0u64; block_count * words];

        Self::collect_block_arguments(body, &mut block_def, words);
        Self::collect_operation_uses(body, &mut block_use, &mut block_def, words);
        let edge_uses = Self::collect_edge_uses(body, block_count, words);

        let mut live_in = vec![0u64; block_count * words];
        let mut live_out = vec![0u64; block_count * words];
        let mut next_live_out = vec![0u64; words];
        let mut next_live_in = vec![0u64; words];
        let mut changed = true;

        while changed {
            changed = false;

            for (block_index, block) in body.graph().blocks().iter().enumerate().rev() {
                let base = block_index * words;
                next_live_out.copy_from_slice(&edge_uses[base..base + words]);

                for successor in block.successors().slice(body.graph().successors()) {
                    let successor_base = successor.index() * words;
                    for word in 0..words {
                        next_live_out[word] |= live_in[successor_base + word];
                    }
                }

                for word in 0..words {
                    next_live_in[word] =
                        block_use[base + word] | (next_live_out[word] & !block_def[base + word]);
                }

                if live_out[base..base + words] != next_live_out[..] {
                    live_out[base..base + words].copy_from_slice(&next_live_out);
                    changed = true;
                }

                if live_in[base..base + words] != next_live_in[..] {
                    live_in[base..base + words].copy_from_slice(&next_live_in);
                    changed = true;
                }
            }
        }

        let (live_in_offsets, live_in_values) = Self::pack_sets(&live_in, block_count, words);
        let (live_out_offsets, live_out_values) = Self::pack_sets(&live_out, block_count, words);

        Self {
            live_in_offsets,
            live_in_values,
            live_out_offsets,
            live_out_values,
        }
    }

    fn set_bit(rows: &mut [u64], base: usize, value: usize) {
        rows[base + value / 64] |= 1u64 << (value % 64);
    }

    fn test_bit(rows: &[u64], base: usize, value: usize) -> bool {
        (rows[base + value / 64] >> (value % 64)) & 1 == 1
    }

    pub fn live_in(&self, block: IlBlockId) -> &[IlValueId] {
        Self::values_for(block, &self.live_in_offsets, &self.live_in_values)
    }

    pub fn live_out(&self, block: IlBlockId) -> &[IlValueId] {
        Self::values_for(block, &self.live_out_offsets, &self.live_out_values)
    }

    fn collect_block_arguments(body: &ECodeSsaIr, block_def: &mut [u64], words: usize) {
        for argument in body.block_arguments() {
            Self::set_bit(
                block_def,
                argument.block().index() * words,
                argument.value().index(),
            );
        }
    }

    fn collect_edge_uses(body: &ECodeSsaIr, block_count: usize, words: usize) -> Vec<u64> {
        let mut edge_uses = vec![0u64; block_count * words];

        for (block_index, block) in body.graph().blocks().iter().enumerate() {
            let base = block_index * words;
            let successors = block.successors();
            for offset in 0..successors.len() {
                for argument in body.arguments_for_edge(successors.start() + offset) {
                    Self::set_bit(&mut edge_uses, base, argument.index());
                }
            }
        }

        edge_uses
    }

    fn collect_operation_uses(
        body: &ECodeSsaIr,
        block_use: &mut [u64],
        block_def: &mut [u64],
        words: usize,
    ) {
        for (block_index, block) in body.graph().blocks().iter().enumerate() {
            let base = block_index * words;
            for operation in block.operations().slice(body.operations()) {
                for operand in operation.operands().slice(body.value_operands()) {
                    let value_index = operand.index();

                    if !Self::test_bit(block_def, base, value_index) {
                        Self::set_bit(block_use, base, value_index);
                    }
                }

                for defined in operation.results().start()..operation.results().end() {
                    Self::set_bit(block_def, base, defined);
                }
            }
        }
    }

    fn pack_sets(rows: &[u64], block_count: usize, words: usize) -> (Vec<u32>, Vec<IlValueId>) {
        let mut offsets = Vec::with_capacity(block_count + 1);
        let mut values = Vec::new();

        offsets.push(0);

        for block_index in 0..block_count {
            let base = block_index * words;
            for word in 0..words {
                let mut bits = rows[base + word];
                while bits != 0 {
                    let value_index = word * 64 + bits.trailing_zeros() as usize;
                    values.push(
                        IlValueId::try_from_index(value_index)
                            .expect("value count fits the value id space"),
                    );
                    bits &= bits - 1;
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

    #[test]
    fn liveness_tracks_value_used_only_as_edge_argument() {
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

        let argument = builder.push_block_argument_value(block1, 64).unwrap();
        let operands = builder.push_value_operands([argument]).unwrap();
        builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::Return,
                IlIndexRange::EMPTY,
                operands,
                0,
            ))
            .unwrap();

        builder.push_edge_arguments([value]).unwrap();

        let body = builder.build(&CancellationToken::default()).unwrap();
        let liveness = ECodeSsaLiveness::build(&body);

        assert_eq!(liveness.live_out(block0), &[value]);
        assert_eq!(liveness.live_in(block0), &[]);
        assert_eq!(liveness.live_in(block1), &[]);
    }
}
