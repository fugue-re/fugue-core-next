use super::required::ECodeSsaRequiredDefs;
use crate::il::common::{
    IlArtefact, IlBlock, IlBlockArgId, IlConstantInterner, IlCsr, IlGraph, IlIndexMapper,
    IlIndexRange, IlOpId, IlParentSpan, IlRewrite, IlSourceSpan, IlSsaDef, IlValueId,
};
use crate::il::ecode::ssa::{
    ECodeSsaBlockArg, ECodeSsaBuilderContext, ECodeSsaIr, ECodeSsaOpcode, ECodeSsaValue,
};

pub(crate) struct ECodeSsaCompaction;

impl IlRewrite<ECodeSsaIr> for ECodeSsaCompaction {
    fn rewrite(&mut self, ir: &mut ECodeSsaIr) {
        let required = ir.analyse::<ECodeSsaRequiredDefs>();

        let operation_map = IlIndexMapper::from_kept(ir.operations().len(), |index| {
            required.operation_is_required(index)
        });
        let block_argument_map = IlIndexMapper::from_kept(ir.block_arguments().len(), |index| {
            required.block_argument_is_required(index)
        });

        let mut value_kept = vec![false; ir.values().len()];
        for (index, value) in ir.values().iter().enumerate() {
            value_kept[index] = match value.definition() {
                IlSsaDef::BlockArgument(argument) => {
                    required.block_argument_is_required(argument.index())
                }
                IlSsaDef::Operation(operation) => required.operation_is_required(operation.index()),
            };
        }
        let value_map = IlIndexMapper::from_kept(ir.values().len(), |index| value_kept[index]);

        let remap_value = |value: IlValueId| {
            IlValueId::try_from_index(value_map.map_index(value.index()))
                .expect("remapped value id is representable")
        };

        let values = ir
            .values()
            .iter()
            .enumerate()
            .filter(|(index, _)| value_kept[*index])
            .map(|(_, value)| {
                let definition = match value.definition() {
                    IlSsaDef::Operation(operation) => {
                        let operation = operation_map.map_index(operation.index());
                        IlSsaDef::Operation(
                            IlOpId::try_from_index(operation)
                                .expect("remapped operation id is representable"),
                        )
                    }
                    IlSsaDef::BlockArgument(argument) => {
                        let argument = block_argument_map.map_index(argument.index());
                        IlSsaDef::BlockArgument(
                            IlBlockArgId::try_from_index(argument)
                                .expect("remapped block argument id is representable"),
                        )
                    }
                };
                ECodeSsaValue::new(value.width(), definition)
            })
            .collect::<Vec<_>>();

        let value_domains = (0..ir.values().len())
            .filter(|index| value_kept[*index])
            .map(|index| {
                ir.value_domain(
                    IlValueId::try_from_index(index).expect("value id is representable"),
                )
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
            compacted.set_results(value_map.map_range(operation.results()));
            compacted.set_operands(operands);
            operations.push(compacted);
        }

        let mut constants = Vec::new();
        let mut interner = IlConstantInterner::new();
        for operation in &mut operations {
            if !matches!(operation.opcode(), ECodeSsaOpcode::Constant) || operation.width() <= 64 {
                continue;
            }
            if let Some(value) = operation.constant(ir.constant_storage()) {
                let immediate = interner.intern(&mut constants, &value);
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
            .filter_map(|span| {
                let destination = operation_map.map_range(span.destination());
                (!destination.is_empty()).then(|| {
                    IlSourceSpan::new(
                        destination,
                        span.address(),
                        span.first_pcode_index(),
                        span.pcode_count(),
                    )
                })
            })
            .collect::<Vec<_>>();

        let parent_spans = ir
            .parent_spans()
            .iter()
            .filter_map(|span| {
                let destination = operation_map.map_range(span.destination());
                (!destination.is_empty()).then(|| IlParentSpan::new(destination, span.source()))
            })
            .collect::<Vec<_>>();

        let blocks = ir
            .graph()
            .blocks()
            .iter()
            .map(|block| {
                IlBlock::new(
                    operation_map.map_range(block.operations()),
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
        *ir = ECodeSsaIr::new(ECodeSsaBuilderContext {
            metadata,
            graph,
            source_spans,
            parent_spans,
            values,
            value_domains,
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
