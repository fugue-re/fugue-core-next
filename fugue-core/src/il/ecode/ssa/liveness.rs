use fixedbitset::FixedBitSet;

use crate::il::common::{IlAnalysis, IlBlockId, IlCsr, IlValueId};
use crate::il::ecode::ssa::ECodeSsaIr;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ECodeSsaLiveness {
    live_in: IlCsr<IlValueId>,
    live_out: IlCsr<IlValueId>,
}

struct LivenessMatrix {
    rows: Vec<FixedBitSet>,
}

impl LivenessMatrix {
    fn new(row_count: usize, value_count: usize) -> Self {
        Self {
            rows: std::iter::repeat_with(|| FixedBitSet::with_capacity(value_count))
                .take(row_count)
                .collect(),
        }
    }

    fn contains(&self, row: usize, value: usize) -> bool {
        self.rows[row].contains(value)
    }

    fn insert(&mut self, row: usize, value: usize) {
        self.rows[row].insert(value);
    }

    fn into_sparse(self) -> IlCsr<IlValueId> {
        IlCsr::from_rows(self.rows.iter().map(|row| {
            row.ones().map(|value| {
                IlValueId::try_from_index(value).expect("value count fits the value id space")
            })
        }))
    }

    fn row(&self, row: usize) -> &FixedBitSet {
        &self.rows[row]
    }

    fn row_mut(&mut self, row: usize) -> &mut FixedBitSet {
        &mut self.rows[row]
    }
}

struct ECodeSsaLivenessBuilder<'a> {
    block_definitions: LivenessMatrix,
    block_uses: LivenessMatrix,
    ir: &'a ECodeSsaIr,
    edge_uses: LivenessMatrix,
}

impl<'a> ECodeSsaLivenessBuilder<'a> {
    fn new(ir: &'a ECodeSsaIr) -> Self {
        let block_count = ir.graph().blocks().len();
        let value_count = ir.values().len();
        Self {
            block_definitions: LivenessMatrix::new(block_count, value_count),
            block_uses: LivenessMatrix::new(block_count, value_count),
            ir,
            edge_uses: LivenessMatrix::new(block_count, value_count),
        }
    }

    fn build(mut self) -> ECodeSsaLiveness {
        if self.ir.graph().blocks().is_empty() {
            return ECodeSsaLiveness::default();
        }

        self.collect_block_arguments();
        self.collect_operation_uses();
        self.collect_edge_uses();

        let block_count = self.ir.graph().blocks().len();
        let value_count = self.ir.values().len();
        let mut live_in = LivenessMatrix::new(block_count, value_count);
        let mut live_out = LivenessMatrix::new(block_count, value_count);
        let mut next_live_out = FixedBitSet::with_capacity(value_count);
        let mut next_live_in = FixedBitSet::with_capacity(value_count);
        let mut changed = true;

        while changed {
            changed = false;

            for (block_index, block) in self.ir.graph().blocks().iter().enumerate().rev() {
                next_live_out.clear();
                next_live_out.union_with(self.edge_uses.row(block_index));

                for successor in block.successors().slice(self.ir.graph().successors()) {
                    next_live_out.union_with(live_in.row(successor.index()));
                }

                next_live_in.clear();
                next_live_in.union_with(&next_live_out);
                next_live_in.difference_with(self.block_definitions.row(block_index));
                next_live_in.union_with(self.block_uses.row(block_index));

                if live_out.row(block_index) != &next_live_out {
                    live_out.row_mut(block_index).clone_from(&next_live_out);
                    changed = true;
                }

                if live_in.row(block_index) != &next_live_in {
                    live_in.row_mut(block_index).clone_from(&next_live_in);
                    changed = true;
                }
            }
        }

        ECodeSsaLiveness {
            live_in: live_in.into_sparse(),
            live_out: live_out.into_sparse(),
        }
    }

    fn collect_block_arguments(&mut self) {
        for argument in self.ir.block_arguments() {
            self.block_definitions
                .insert(argument.block().index(), argument.value().index());
        }
    }

    fn collect_edge_uses(&mut self) {
        for (block_index, block) in self.ir.graph().blocks().iter().enumerate() {
            let successors = block.successors();
            for offset in 0..successors.len() {
                for argument in self.ir.arguments_for_edge(successors.start() + offset) {
                    self.edge_uses.insert(block_index, argument.index());
                }
            }
        }
    }

    fn collect_operation_uses(&mut self) {
        for (block_index, block) in self.ir.graph().blocks().iter().enumerate() {
            for operation in block.operations().slice(self.ir.operations()) {
                for operand in self.ir.operation_operands_for(operation) {
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
    fn analyse(ir: &ECodeSsaIr) -> Self {
        ECodeSsaLivenessBuilder::new(ir).build()
    }
}

impl ECodeSsaLiveness {
    pub fn live_in(&self, block: IlBlockId) -> &[IlValueId] {
        self.live_in.row(block.index())
    }

    pub fn live_out(&self, block: IlBlockId) -> &[IlValueId] {
        self.live_out.row(block.index())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::analysis::control::CancellationToken;
    use crate::il::common::{
        IlArtefact, IlBlock, IlBlockProperties, IlEdgeKinds, IlGraph, IlIndexRange, IlMetadata,
    };
    use crate::il::ecode::ssa::{
        ECODE_SSA_SCHEMA_VERSION, ECodeSsaBuilder, ECodeSsaOp, ECodeSsaOpcode,
    };
    use crate::ir::FunctionId;

    #[test]
    fn liveness_tracks_value_across_linear_edge() {
        let block0 = IlBlockId::try_from_index(0).unwrap();
        let block1 = IlBlockId::try_from_index(1).unwrap();
        let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
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
            vec![IlEdgeKinds::UNCONDITIONAL; 1],
        );
        let mut builder = ECodeSsaBuilder::new(metadata, graph);
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

        let ir = builder.build(&CancellationToken::default()).unwrap();
        let liveness = ir.analyse::<ECodeSsaLiveness>();

        assert_eq!(liveness.live_in(block0), &[]);
        assert_eq!(liveness.live_out(block0), &[value]);
        assert_eq!(liveness.live_in(block1), &[value]);
        assert_eq!(liveness.live_out(block1), &[]);
    }

    #[test]
    fn liveness_ignores_value_defined_before_same_block_use() {
        let block = IlBlockId::try_from_index(0).unwrap();
        let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let graph = IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::new(0, 2).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::ENTRY | IlBlockProperties::EXIT,
            )],
            Vec::new(),
            Vec::new(),
        );
        let mut builder = ECodeSsaBuilder::new(metadata, graph);
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

        let ir = builder.build(&CancellationToken::default()).unwrap();
        let liveness = ir.analyse::<ECodeSsaLiveness>();

        assert_eq!(liveness.live_in(block), &[]);
        assert_eq!(liveness.live_out(block), &[]);
    }

    #[test]
    fn liveness_treats_block_argument_as_entry_definition() {
        let block = IlBlockId::try_from_index(0).unwrap();
        let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let graph = IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::ENTRY | IlBlockProperties::EXIT,
            )],
            Vec::new(),
            Vec::new(),
        );
        let mut builder = ECodeSsaBuilder::new(metadata, graph);
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

        let ir = builder.build(&CancellationToken::default()).unwrap();
        let liveness = ir.analyse::<ECodeSsaLiveness>();

        assert_eq!(liveness.live_in(block), &[]);
        assert_eq!(liveness.live_out(block), &[]);
    }

    #[test]
    fn liveness_tracks_value_used_only_as_edge_argument() {
        let block0 = IlBlockId::try_from_index(0).unwrap();
        let block1 = IlBlockId::try_from_index(1).unwrap();
        let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
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
            vec![IlEdgeKinds::UNCONDITIONAL; 1],
        );
        let mut builder = ECodeSsaBuilder::new(metadata, graph);

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

        let ir = builder.build(&CancellationToken::default()).unwrap();
        let liveness = ir.analyse::<ECodeSsaLiveness>();

        assert_eq!(liveness.live_out(block0), &[value]);
        assert_eq!(liveness.live_in(block0), &[]);
        assert_eq!(liveness.live_in(block1), &[]);
    }
}
