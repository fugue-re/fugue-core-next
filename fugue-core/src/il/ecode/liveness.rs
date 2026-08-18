use std::iter;

use fixedbitset::FixedBitSet;

use crate::il::common::{IlAnalysis, IlBlockId, IlCsr, IlValueId};
use crate::il::ecode::ECodeIr;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ECodeLiveness {
    live_in: IlCsr<IlValueId>,
    live_out: IlCsr<IlValueId>,
}

struct LivenessMatrix {
    rows: Vec<FixedBitSet>,
}

impl LivenessMatrix {
    fn new(row_count: usize, value_count: usize) -> Self {
        Self {
            rows: iter::repeat_with(|| FixedBitSet::with_capacity(value_count))
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

struct ECodeLivenessSolver<'a> {
    block_definitions: LivenessMatrix,
    block_uses: LivenessMatrix,
    ir: &'a ECodeIr,
    edge_uses: LivenessMatrix,
}

impl<'a> ECodeLivenessSolver<'a> {
    fn new(ir: &'a ECodeIr) -> Self {
        let block_count = ir.graph().blocks().len();
        let value_count = ir.values().len();
        Self {
            block_definitions: LivenessMatrix::new(block_count, value_count),
            block_uses: LivenessMatrix::new(block_count, value_count),
            ir,
            edge_uses: LivenessMatrix::new(block_count, value_count),
        }
    }

    fn solve(mut self) -> ECodeLiveness {
        if self.ir.graph().blocks().is_empty() {
            return ECodeLiveness::default();
        }

        self.collect_block_args();
        self.collect_op_uses();
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

        ECodeLiveness {
            live_in: live_in.into_sparse(),
            live_out: live_out.into_sparse(),
        }
    }

    fn collect_block_args(&mut self) {
        for arg in self.ir.block_args() {
            self.block_definitions
                .insert(arg.block().index(), arg.value().index());
        }
    }

    fn collect_edge_uses(&mut self) {
        for (block_index, block) in self.ir.graph().blocks().iter().enumerate() {
            let successors = block.successors();
            for offset in 0..successors.len() {
                for arg in self.ir.args_for_edge(successors.start() + offset) {
                    self.edge_uses.insert(block_index, arg.index());
                }
            }
        }
    }

    fn collect_op_uses(&mut self) {
        for (block_index, block) in self.ir.graph().blocks().iter().enumerate() {
            for operation in block.ops().slice(self.ir.ops()) {
                for operand in self.ir.op_operands_for(operation) {
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

impl IlAnalysis<ECodeIr> for ECodeLiveness {
    fn analyse(ir: &ECodeIr) -> Self {
        ECodeLivenessSolver::new(ir).solve()
    }
}

impl ECodeLiveness {
    pub fn live_in(&self, block: IlBlockId) -> &[IlValueId] {
        self.live_in.checked_row(block.index()).unwrap_or_default()
    }

    pub fn live_out(&self, block: IlBlockId) -> &[IlValueId] {
        self.live_out.checked_row(block.index()).unwrap_or_default()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::analysis::control::CancellationToken;
    use crate::il::common::{
        IlArtefact, IlBlock, IlBlockProperties, IlEdgeKinds, IlGraph, IlIndexRange, IlMetadata,
    };
    use crate::il::ecode::test::emit_value;
    use crate::il::ecode::{ECodeBuilder, ECodeOpSpec, ECodeOpcode};
    use crate::ir::FunctionId;

    #[test]
    fn liveness_tracks_value_across_linear_edge() {
        let block0 = IlBlockId::try_from_index(0).unwrap();
        let block1 = IlBlockId::try_from_index(1).unwrap();
        let metadata = IlMetadata::new(FunctionId::default(), 0);
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
        let mut builder = ECodeBuilder::new(metadata, graph);
        let value = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64),
            [],
        )
        .unwrap();
        builder
            .emitter()
            .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [value], 0)
            .unwrap();

        let ir = builder.build(&CancellationToken::default()).unwrap();
        let liveness = ir.analyse::<ECodeLiveness>();

        assert_eq!(liveness.live_in(block0), &[]);
        assert_eq!(liveness.live_out(block0), &[value]);
        assert_eq!(liveness.live_in(block1), &[value]);
        assert_eq!(liveness.live_out(block1), &[]);
    }

    #[test]
    fn liveness_ignores_value_defined_before_same_block_use() {
        let block = IlBlockId::try_from_index(0).unwrap();
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let graph = IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::new(0, 2).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::ENTRY | IlBlockProperties::EXIT,
            )],
            Vec::new(),
            Vec::new(),
        );
        let mut builder = ECodeBuilder::new(metadata, graph);
        let value = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 32),
            [],
        )
        .unwrap();
        builder
            .emitter()
            .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [value], 0)
            .unwrap();

        let ir = builder.build(&CancellationToken::default()).unwrap();
        let liveness = ir.analyse::<ECodeLiveness>();

        assert_eq!(liveness.live_in(block), &[]);
        assert_eq!(liveness.live_out(block), &[]);
    }

    #[test]
    fn liveness_treats_block_arg_as_entry_definition() {
        let block = IlBlockId::try_from_index(0).unwrap();
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let graph = IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::ENTRY | IlBlockProperties::EXIT,
            )],
            Vec::new(),
            Vec::new(),
        );
        let mut builder = ECodeBuilder::new(metadata, graph);
        let arg = builder.emitter().emit_block_arg(block, 32).unwrap();
        builder
            .emitter()
            .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [arg], 0)
            .unwrap();

        let ir = builder.build(&CancellationToken::default()).unwrap();
        let liveness = ir.analyse::<ECodeLiveness>();

        assert_eq!(liveness.live_in(block), &[]);
        assert_eq!(liveness.live_out(block), &[]);
    }

    #[test]
    fn liveness_tracks_value_used_only_as_edge_arg() {
        let block0 = IlBlockId::try_from_index(0).unwrap();
        let block1 = IlBlockId::try_from_index(1).unwrap();
        let metadata = IlMetadata::new(FunctionId::default(), 0);
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
        let mut builder = ECodeBuilder::new(metadata, graph);

        let value = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64),
            [],
        )
        .unwrap();

        let arg = builder.emitter().emit_block_arg(block1, 64).unwrap();
        builder
            .emitter()
            .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [arg], 0)
            .unwrap();

        builder.emitter().emit_edge_args([value]).unwrap();

        let ir = builder.build(&CancellationToken::default()).unwrap();
        let liveness = ir.analyse::<ECodeLiveness>();

        assert_eq!(liveness.live_out(block0), &[value]);
        assert_eq!(liveness.live_in(block0), &[]);
        assert_eq!(liveness.live_in(block1), &[]);
    }
}
