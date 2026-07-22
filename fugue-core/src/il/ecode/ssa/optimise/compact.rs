use rustc_hash::FxHashMap;

use crate::il::common::{IlBlock, IlGraph, IlIndexRange, IlParentSpan, IlSourceSpan, IlValueId};
use crate::il::ecode::ssa::{
    ECodeSsaBlockArg, ECodeSsaIr, ECodeSsaOpcode, ECodeSsaValue, ECodeSsaValueKind,
};

impl ECodeSsaIr {
    pub(crate) fn compact(&mut self) {
        let reachable = self.compute_reachability();

        let mut operation_index = vec![0u32; self.operations.len() + 1];
        for index in 0..self.operations.len() {
            operation_index[index + 1] =
                operation_index[index] + u32::from(reachable.operations[index]);
        }

        let mut block_argument_index = vec![0u32; self.block_arguments.len() + 1];
        for index in 0..self.block_arguments.len() {
            block_argument_index[index + 1] =
                block_argument_index[index] + u32::from(reachable.block_arguments[index]);
        }

        let mut value_kept = vec![false; self.values.len()];
        for (index, value) in self.values.iter().enumerate() {
            value_kept[index] = match value.definition_kind() {
                ECodeSsaValueKind::BlockArgument => {
                    reachable.block_arguments[value.definition_index() as usize]
                }
                ECodeSsaValueKind::Operation => {
                    reachable.operations[value.definition_index() as usize]
                }
            };
        }
        let mut value_index = vec![0u32; self.values.len() + 1];
        for index in 0..self.values.len() {
            value_index[index + 1] = value_index[index] + u32::from(value_kept[index]);
        }

        let remap_value = |value: IlValueId| {
            IlValueId::try_from_index(value_index[value.index()] as usize)
                .expect("remapped value id is representable")
        };
        let remap_range = |range: IlIndexRange, map: &[u32]| {
            IlIndexRange::new(map[range.start()] as usize, map[range.end()] as usize)
                .expect("remapped range stays ordered")
        };

        let values = self
            .values
            .iter()
            .enumerate()
            .filter(|(index, _)| value_kept[*index])
            .map(|(_, value)| {
                let definition = match value.definition_kind() {
                    ECodeSsaValueKind::Operation => {
                        operation_index[value.definition_index() as usize]
                    }
                    ECodeSsaValueKind::BlockArgument => {
                        block_argument_index[value.definition_index() as usize]
                    }
                };
                ECodeSsaValue::new(value.width(), value.definition_kind(), definition)
            })
            .collect::<Vec<_>>();

        let mut operations = Vec::new();
        let mut value_operands = Vec::new();
        for (index, operation) in self.operations.iter().enumerate() {
            if !reachable.operations[index] {
                continue;
            }
            let operand_start = value_operands.len();
            for &operand in operation.operands().slice(&self.value_operands) {
                value_operands.push(remap_value(operand));
            }
            let operands = IlIndexRange::new(operand_start, value_operands.len())
                .expect("operand range stays ordered");
            let mut compacted = *operation;
            compacted.set_results(remap_range(operation.results(), &value_index));
            compacted.set_operands(operands);
            operations.push(compacted);
        }

        let mut constants = Vec::new();
        let mut interned = FxHashMap::<Box<[u8]>, u64>::default();
        for operation in &mut operations {
            if !matches!(operation.opcode(), ECodeSsaOpcode::Constant) || operation.width() <= 64 {
                continue;
            }
            if let Some(value) = operation.constant(&self.constants) {
                let immediate = Self::intern_constant_into(&value, &mut constants, &mut interned);
                operation.replace_with_constant(immediate);
            }
        }

        let block_arguments = self
            .block_arguments
            .iter()
            .enumerate()
            .filter(|(index, _)| reachable.block_arguments[*index])
            .map(|(_, argument)| {
                ECodeSsaBlockArg::new(
                    argument.block(),
                    remap_value(argument.value()),
                    argument.width(),
                )
            })
            .collect::<Vec<_>>();

        let mut block_argument_kept = vec![Vec::new(); self.graph.blocks().len()];
        for (index, argument) in self.block_arguments.iter().enumerate() {
            block_argument_kept[argument.block().index()].push(reachable.block_arguments[index]);
        }

        let mut edge_arguments = Vec::with_capacity(self.edge_arguments.len());
        let mut edge_argument_values = Vec::new();
        for (edge, target) in self.graph.successors().iter().enumerate() {
            let kept = &block_argument_kept[target.index()];
            let start = edge_argument_values.len();
            for (position, &value) in self.arguments_for_edge(edge).iter().enumerate() {
                if kept.get(position).copied().unwrap_or(false) {
                    edge_argument_values.push(remap_value(value));
                }
            }
            edge_arguments.push(
                IlIndexRange::new(start, edge_argument_values.len())
                    .expect("edge argument range stays ordered"),
            );
        }

        let source_spans = self
            .source_spans
            .iter()
            .filter(|span| {
                operation_index[span.destination().start()]
                    != operation_index[span.destination().end()]
            })
            .map(|span| {
                IlSourceSpan::new(
                    remap_range(span.destination(), &operation_index),
                    span.address(),
                    span.first_pcode_index(),
                    span.pcode_count(),
                )
            })
            .collect::<Vec<_>>();

        let parent_spans = self
            .parent_spans
            .iter()
            .filter(|span| {
                operation_index[span.destination().start()]
                    != operation_index[span.destination().end()]
            })
            .map(|span| {
                IlParentSpan::new(
                    remap_range(span.destination(), &operation_index),
                    span.source(),
                )
            })
            .collect::<Vec<_>>();

        let blocks = self
            .graph
            .blocks()
            .iter()
            .map(|block| {
                IlBlock::new(
                    remap_range(block.operations(), &operation_index),
                    block.successors(),
                    block.properties(),
                )
            })
            .collect::<Vec<_>>();
        let graph = IlGraph::new(blocks, self.graph.successors().to_vec());

        self.graph = graph;
        self.source_spans = source_spans;
        self.parent_spans = parent_spans;
        self.values = values;
        self.block_arguments = block_arguments;
        self.operations = operations;
        self.value_operands = value_operands;
        self.edge_arguments = edge_arguments;
        self.edge_argument_values = edge_argument_values;
        self.constants = constants;
    }
}
