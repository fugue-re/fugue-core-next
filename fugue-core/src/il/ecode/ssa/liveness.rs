use crate::il::common::{IlAnalysis, IlBlockId, IlValueId};
use crate::il::ecode::ssa::ECodeSsaIr;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ECodeSsaLiveness {
    live_in: PackedLivenessSets,
    live_out: PackedLivenessSets,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PackedLivenessSets {
    offsets: Vec<u32>,
    values: Vec<IlValueId>,
}

impl PackedLivenessSets {
    fn from_matrix(matrix: &LivenessMatrix) -> Self {
        let mut offsets = Vec::with_capacity(matrix.row_count() + 1);
        let mut values = Vec::new();
        offsets.push(0);

        for row in 0..matrix.row_count() {
            for (word, &bits) in matrix.row(row).iter().enumerate() {
                let mut bits = bits;
                while bits != 0 {
                    let value = word * 64 + bits.trailing_zeros() as usize;
                    values.push(
                        IlValueId::try_from_index(value)
                            .expect("value count fits the value id space"),
                    );
                    bits &= bits - 1;
                }
            }
            offsets.push(values.len() as u32);
        }

        Self { offsets, values }
    }

    fn get(&self, block: IlBlockId) -> &[IlValueId] {
        let index = block.index();
        let Some(start) = self.offsets.get(index).copied() else {
            return &[];
        };
        let end = self.offsets.get(index + 1).copied().unwrap_or(start);
        &self.values[start as usize..end as usize]
    }
}

struct LivenessMatrix {
    rows: Vec<u64>,
    row_count: usize,
    words: usize,
}

impl LivenessMatrix {
    fn new(row_count: usize, value_count: usize) -> Self {
        let words = value_count.div_ceil(64).max(1);
        Self {
            rows: vec![0; row_count * words],
            row_count,
            words,
        }
    }

    fn contains(&self, row: usize, value: usize) -> bool {
        (self.rows[row * self.words + value / 64] >> (value % 64)) & 1 == 1
    }

    fn insert(&mut self, row: usize, value: usize) {
        self.rows[row * self.words + value / 64] |= 1u64 << (value % 64);
    }

    fn row(&self, row: usize) -> &[u64] {
        let start = row * self.words;
        &self.rows[start..start + self.words]
    }

    fn row_count(&self) -> usize {
        self.row_count
    }

    fn row_mut(&mut self, row: usize) -> &mut [u64] {
        let start = row * self.words;
        &mut self.rows[start..start + self.words]
    }
}

struct ECodeSsaLivenessBuilder<'a> {
    block_definitions: LivenessMatrix,
    block_uses: LivenessMatrix,
    body: &'a ECodeSsaIr,
    edge_uses: LivenessMatrix,
}

impl<'a> ECodeSsaLivenessBuilder<'a> {
    fn new(body: &'a ECodeSsaIr) -> Self {
        let block_count = body.graph().blocks().len();
        let value_count = body.values().len();
        Self {
            block_definitions: LivenessMatrix::new(block_count, value_count),
            block_uses: LivenessMatrix::new(block_count, value_count),
            body,
            edge_uses: LivenessMatrix::new(block_count, value_count),
        }
    }

    fn build(mut self) -> ECodeSsaLiveness {
        if self.body.graph().blocks().is_empty() {
            return ECodeSsaLiveness::default();
        }

        self.collect_block_arguments();
        self.collect_operation_uses();
        self.collect_edge_uses();

        let block_count = self.body.graph().blocks().len();
        let value_count = self.body.values().len();
        let mut live_in = LivenessMatrix::new(block_count, value_count);
        let mut live_out = LivenessMatrix::new(block_count, value_count);
        let mut next_live_out = vec![0u64; live_in.words];
        let mut next_live_in = vec![0u64; live_in.words];
        let mut changed = true;

        while changed {
            changed = false;

            for (block_index, block) in self.body.graph().blocks().iter().enumerate().rev() {
                next_live_out.copy_from_slice(self.edge_uses.row(block_index));

                for successor in block.successors().slice(self.body.graph().successors()) {
                    for (next, successor) in
                        next_live_out.iter_mut().zip(live_in.row(successor.index()))
                    {
                        *next |= successor;
                    }
                }

                for (word, next) in next_live_in.iter_mut().enumerate() {
                    *next = self.block_uses.row(block_index)[word]
                        | (next_live_out[word] & !self.block_definitions.row(block_index)[word]);
                }

                if live_out.row(block_index) != next_live_out {
                    live_out
                        .row_mut(block_index)
                        .copy_from_slice(&next_live_out);
                    changed = true;
                }

                if live_in.row(block_index) != next_live_in {
                    live_in.row_mut(block_index).copy_from_slice(&next_live_in);
                    changed = true;
                }
            }
        }

        ECodeSsaLiveness {
            live_in: PackedLivenessSets::from_matrix(&live_in),
            live_out: PackedLivenessSets::from_matrix(&live_out),
        }
    }

    fn collect_block_arguments(&mut self) {
        for argument in self.body.block_arguments() {
            self.block_definitions
                .insert(argument.block().index(), argument.value().index());
        }
    }

    fn collect_edge_uses(&mut self) {
        for (block_index, block) in self.body.graph().blocks().iter().enumerate() {
            let successors = block.successors();
            for offset in 0..successors.len() {
                for argument in self.body.arguments_for_edge(successors.start() + offset) {
                    self.edge_uses.insert(block_index, argument.index());
                }
            }
        }
    }

    fn collect_operation_uses(&mut self) {
        for (block_index, block) in self.body.graph().blocks().iter().enumerate() {
            for operation in block.operations().slice(self.body.operations()) {
                for operand in operation.operands().slice(self.body.value_operands()) {
                    if !self
                        .block_definitions
                        .contains(block_index, operand.index())
                    {
                        self.block_uses.insert(block_index, operand.index());
                    }
                }

                for defined in operation.results().start()..operation.results().end() {
                    self.block_definitions.insert(block_index, defined);
                }
            }
        }
    }
}

impl IlAnalysis<ECodeSsaIr> for ECodeSsaLiveness {
    fn analyse(body: &ECodeSsaIr) -> Self {
        ECodeSsaLivenessBuilder::new(body).build()
    }
}

impl ECodeSsaLiveness {
    pub fn live_in(&self, block: IlBlockId) -> &[IlValueId] {
        self.live_in.get(block)
    }

    pub fn live_out(&self, block: IlBlockId) -> &[IlValueId] {
        self.live_out.get(block)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::analysis::control::CancellationToken;
    use crate::il::common::{
        IlArtefact, IlBlock, IlBlockProperties, IlGraph, IlHeader, IlIndexRange,
    };
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
        let liveness = body.analyse::<ECodeSsaLiveness>();

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
        let liveness = body.analyse::<ECodeSsaLiveness>();

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
        let liveness = body.analyse::<ECodeSsaLiveness>();

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
        let liveness = body.analyse::<ECodeSsaLiveness>();

        assert_eq!(liveness.live_out(block0), &[value]);
        assert_eq!(liveness.live_in(block0), &[]);
        assert_eq!(liveness.live_in(block1), &[]);
    }
}
