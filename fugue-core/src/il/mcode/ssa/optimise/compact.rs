use std::collections::BTreeMap;

use super::required::MCodeSsaRequiredDefs;
use crate::il::common::{
    IlBlock, IlBlockArgId, IlConstantInterner, IlCsr, IlGraph, IlIndexMapper, IlIndexRange, IlOpId,
    IlParentSpan, IlRewrite, IlSourceSpan, IlSsaDef, IlValueId,
};
use crate::il::mcode::MCodeVarId;
use crate::il::mcode::ssa::{
    MCodeSsaBlockArg, MCodeSsaBuilderContext, MCodeSsaIr, MCodeSsaOpcode, MCodeSsaValue,
    MCodeSsaVersion,
};

pub(crate) struct MCodeSsaCompaction<'a> {
    required_values: &'a [IlValueId],
}

impl IlRewrite<MCodeSsaIr> for MCodeSsaCompaction<'_> {
    fn rewrite(&mut self, ir: &mut MCodeSsaIr) {
        let required = MCodeSsaRequiredDefs::new(ir, self.required_values);
        let operation_map = IlIndexMapper::from_kept(ir.operations().len(), |index| {
            required.operation_is_required(index)
        });
        let block_argument_map = IlIndexMapper::from_kept(ir.block_arguments().len(), |index| {
            required.block_argument_is_required(index)
        });

        let value_kept = ir
            .values()
            .iter()
            .map(|value| match value.definition() {
                IlSsaDef::BlockArgument(argument) => {
                    required.block_argument_is_required(argument.index())
                }
                IlSsaDef::Operation(operation) => required.operation_is_required(operation.index()),
            })
            .collect::<Vec<_>>();
        let value_map = IlIndexMapper::from_kept(ir.values().len(), |index| value_kept[index]);

        let mut variable_kept = vec![false; ir.variables().len()];
        for (index, value) in ir.values().iter().enumerate() {
            if value_kept[index]
                && let Some(variable) = value.variable()
            {
                variable_kept[variable.index()] = true;
            }
        }
        for (index, operation) in ir.operations().iter().enumerate() {
            if required.operation_is_required(index)
                && let Some(variable) = operation.variable()
            {
                variable_kept[variable.index()] = true;
            }
        }
        let variable_map =
            IlIndexMapper::from_kept(ir.variables().len(), |index| variable_kept[index]);

        let remap_value = |value: IlValueId| {
            IlValueId::try_from_index(value_map.map_index(value.index()))
                .expect("remapped value id is representable")
        };
        let remap_variable = |variable: MCodeVarId| {
            MCodeVarId::try_from_index(variable_map.map_index(variable.index()))
                .expect("remapped variable id is representable")
        };

        let mut new_versions = vec![MCodeSsaVersion::new(0); ir.values().len()];
        let mut versions = BTreeMap::<MCodeVarId, Vec<(MCodeSsaVersion, usize)>>::new();
        for (index, value) in ir.values().iter().enumerate() {
            if value_kept[index]
                && let Some(variable) = value.variable()
            {
                versions
                    .entry(variable)
                    .or_default()
                    .push((value.version(), index));
            }
        }
        for entries in versions.values_mut() {
            entries.sort_unstable_by_key(|(version, _)| *version);
            for (index, &(_, value)) in entries.iter().enumerate() {
                new_versions[value] = MCodeSsaVersion::new(
                    u32::try_from(index + 1).expect("compacted variable version is representable"),
                );
            }
        }

        let values = ir
            .values()
            .iter()
            .enumerate()
            .filter(|(index, _)| value_kept[*index])
            .map(|(index, value)| {
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
                let mut compacted = MCodeSsaValue::new(value.width(), definition);
                if let Some(variable) = value.variable() {
                    compacted.set_binding(remap_variable(variable), new_versions[index]);
                }
                compacted
            })
            .collect::<Vec<_>>();

        let mut operations = Vec::new();
        let mut value_operands = Vec::new();
        for (index, operation) in ir.operations().iter().enumerate() {
            if !required.operation_is_required(index) {
                continue;
            }
            let start = value_operands.len();
            value_operands.extend(
                ir.operation_operands_for(operation)
                    .iter()
                    .copied()
                    .map(remap_value),
            );
            let operands = IlIndexRange::new(start, value_operands.len())
                .expect("compacted operand range stays ordered");
            let mut compacted = *operation;
            compacted.set_results(value_map.map_range(operation.results()));
            compacted.set_operands(operands);
            if let Some(variable) = operation.variable() {
                compacted = compacted.with_variable(remap_variable(variable));
            }
            operations.push(compacted);
        }

        let mut constant_storage = Vec::new();
        let mut constants = IlConstantInterner::new();
        for operation in &mut operations {
            if operation.opcode() != MCodeSsaOpcode::Constant || operation.width() <= 64 {
                continue;
            }
            if let Some(value) = operation.constant(ir.constant_storage()) {
                let immediate = constants.intern(&mut constant_storage, &value);
                operation.replace_with_constant(immediate);
            }
        }

        let block_arguments = ir
            .block_arguments()
            .iter()
            .enumerate()
            .filter(|(index, _)| required.block_argument_is_required(*index))
            .map(|(_, argument)| {
                MCodeSsaBlockArg::new(
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
                    .expect("compacted edge argument range stays ordered"),
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

        let variables = ir
            .variables()
            .iter()
            .enumerate()
            .filter_map(|(index, variable)| variable_kept[index].then_some(*variable))
            .collect();
        let aliased_variables = ir
            .aliased_variables()
            .iter()
            .filter(|variable| variable_kept[variable.index()])
            .copied()
            .map(remap_variable)
            .collect();
        let metadata = *ir.metadata();
        let memory_domains = ir.memory_domains().to_vec();
        *ir = MCodeSsaIr::new(MCodeSsaBuilderContext {
            metadata,
            graph,
            source_spans,
            parent_spans,
            variables,
            aliased_variables,
            values,
            block_arguments,
            edge_arguments,
            edge_argument_values,
            operations,
            value_operands,
            memory_domains,
            constant_storage,
        });
    }
}

impl<'a> MCodeSsaCompaction<'a> {
    pub(crate) const fn new(required_values: &'a [IlValueId]) -> Self {
        Self { required_values }
    }
}
