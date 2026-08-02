use super::required::ECodeSsaRequiredDefinitions;
use crate::il::common::{
    IlArtefact, IlBlock, IlCsr, IlGraph, IlIndexRange, IlParentSpan, IlRewrite, IlSourceSpan,
    IlValueId,
};
use crate::il::ecode::ssa::{
    ECodeSsaBlockArg, ECodeSsaConstantInterner, ECodeSsaIr, ECodeSsaIrParts, ECodeSsaOpcode,
    ECodeSsaValue, ECodeSsaValueKind,
};

pub(crate) struct ECodeSsaCompaction;

impl IlRewrite<ECodeSsaIr> for ECodeSsaCompaction {
    fn rewrite(&mut self, ir: &mut ECodeSsaIr) {
        let required = ir.analyse::<ECodeSsaRequiredDefinitions>();

        let mut operation_index = vec![0u32; ir.operations().len() + 1];
        for index in 0..ir.operations().len() {
            operation_index[index + 1] =
                operation_index[index] + u32::from(required.operation_is_required(index));
        }

        let mut block_argument_index = vec![0u32; ir.block_arguments().len() + 1];
        for index in 0..ir.block_arguments().len() {
            block_argument_index[index + 1] =
                block_argument_index[index] + u32::from(required.block_argument_is_required(index));
        }

        let mut value_kept = vec![false; ir.values().len()];
        for (index, value) in ir.values().iter().enumerate() {
            value_kept[index] = match value.definition_kind() {
                ECodeSsaValueKind::BlockArgument => {
                    required.block_argument_is_required(value.definition_index() as usize)
                }
                ECodeSsaValueKind::Operation => {
                    required.operation_is_required(value.definition_index() as usize)
                }
            };
        }
        let mut value_index = vec![0u32; ir.values().len() + 1];
        for index in 0..ir.values().len() {
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

        let values = ir
            .values()
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
        for (index, operation) in ir.operations().iter().enumerate() {
            if !required.operation_is_required(index) {
                continue;
            }
            let operand_start = value_operands.len();
            for &operand in ir.operation_operands_for(operation) {
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
        let mut interner = ECodeSsaConstantInterner::new(&mut constants);
        for operation in &mut operations {
            if !matches!(operation.opcode(), ECodeSsaOpcode::Constant) || operation.width() <= 64 {
                continue;
            }
            if let Some(value) = operation.constant(ir.constant_storage()) {
                let immediate = interner.intern(&value);
                operation.replace_with_constant(immediate);
            }
        }

        let block_arguments = ir
            .block_arguments()
            .iter()
            .enumerate()
            .filter(|(index, _)| required.block_argument_is_required(*index))
            .map(|(_, argument)| {
                ECodeSsaBlockArg::new(
                    argument.block(),
                    remap_value(argument.value()),
                    argument.width(),
                )
            })
            .collect::<Vec<_>>();

        let block_argument_kept = IlCsr::from_entries(
            ir.graph().blocks().len(),
            ir.block_arguments()
                .iter()
                .enumerate()
                .map(|(index, argument)| {
                    (
                        argument.block().index(),
                        required.block_argument_is_required(index),
                    )
                }),
        );

        let mut edge_arguments = Vec::with_capacity(ir.edge_arguments().len());
        let mut edge_argument_values = Vec::new();
        for (edge, target) in ir.graph().successors().iter().enumerate() {
            let kept = block_argument_kept.row(target.index());
            let start = edge_argument_values.len();
            for (position, &value) in ir.arguments_for_edge(edge).iter().enumerate() {
                if kept.get(position).copied().unwrap_or(false) {
                    edge_argument_values.push(remap_value(value));
                }
            }
            edge_arguments.push(
                IlIndexRange::new(start, edge_argument_values.len())
                    .expect("edge argument range stays ordered"),
            );
        }

        let source_spans = ir
            .source_spans()
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

        let parent_spans = ir
            .parent_spans()
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

        let blocks = ir
            .graph()
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
        let graph = IlGraph::new(
            blocks,
            ir.graph().successors().to_vec(),
            ir.graph().successor_kinds().to_vec(),
        );
        let graph = if ir.graph().block_sources().is_empty() {
            graph
        } else {
            graph.with_block_sources(ir.graph().block_sources().to_vec())
        };

        let metadata = *ir.metadata();
        let memory_domains = ir.memory_domains().to_vec();
        *ir = ECodeSsaIr::new(ECodeSsaIrParts {
            metadata,
            graph,
            source_spans,
            parent_spans,
            values,
            block_arguments,
            edge_arguments,
            edge_argument_values,
            operations,
            value_operands,
            memory_domains,
            constant_storage: constants,
        });
    }
}
