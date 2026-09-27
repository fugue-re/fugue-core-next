use std::ops::Range;

use super::required::MCodeRequiredDefs;
use crate::il::common::{IlBlockId, IlCsr, IlIndexMapper, IlRewrite, IlSsaDef, IlValueId};
use crate::il::mcode::{
    MCodeBuilder, MCodeIr, MCodeOpSpec, MCodeOpcode, MCodeResultSpec, MCodeVarId,
};

pub(crate) struct MCodeCompaction<'a> {
    required_values: &'a [IlValueId],
}

impl IlRewrite<MCodeIr> for MCodeCompaction<'_> {
    fn rewrite(&mut self, ir: &mut MCodeIr) {
        let required = MCodeRequiredDefs::new(ir, self.required_values);
        let operation_map =
            IlIndexMapper::from_kept(ir.ops().len(), |index| required.op_is_required(index));
        let value_kept = ir
            .values()
            .iter()
            .map(|value| match value.definition() {
                IlSsaDef::BlockArg(arg) => required.block_arg_is_required(arg.index()),
                IlSsaDef::Op(operation) => required.op_is_required(operation.index()),
            })
            .collect::<Vec<_>>();
        let mut variable_kept = vec![false; ir.variables().len()];
        for (index, value) in ir.values().iter().enumerate() {
            if value_kept[index]
                && let Some(variable) = value.variable()
            {
                variable_kept[variable.index()] = true;
            }
        }
        for (index, operation) in ir.ops().iter().enumerate() {
            if required.op_is_required(index)
                && let Some(variable) = operation.variable()
            {
                variable_kept[variable.index()] = true;
            }
        }
        let variable_map =
            IlIndexMapper::from_kept(ir.variables().len(), |index| variable_kept[index]);

        let remap_variable = |variable: MCodeVarId| {
            MCodeVarId::try_from_index(variable_map.map_index(variable.index()))
                .expect("remapped variable id is representable")
        };

        let block_arg_kept = IlCsr::from_entries(
            ir.graph().blocks().len(),
            ir.block_args()
                .iter()
                .enumerate()
                .map(|(index, arg)| (arg.block().index(), required.block_arg_is_required(index))),
        );
        let block_arg_indices = IlCsr::from_entries(
            ir.graph().blocks().len(),
            ir.block_args()
                .iter()
                .enumerate()
                .filter(|(index, _)| required.block_arg_is_required(*index))
                .map(|(index, arg)| (arg.block().index(), index)),
        );
        let block_ranges = ir
            .graph()
            .blocks()
            .iter()
            .map(|block| block.ops())
            .collect::<Vec<_>>();
        let block_edge_ranges = ir
            .graph()
            .blocks()
            .iter()
            .map(|block| block.successors())
            .collect::<Vec<_>>();
        let mut block_order = (0..block_ranges.len())
            .map(|index| IlBlockId::try_from_index(index).expect("MCode block id is representable"))
            .collect::<Vec<_>>();
        block_order.sort_unstable_by_key(|block| block_ranges[block.index()].start());
        let edge_targets = ir.graph().successors().to_vec();
        let edge_kinds = ir.graph().successor_kinds().to_vec();

        let source_spans = operation_map
            .remap_source_spans(ir.primary_source_spans())
            .expect("source spans use the compaction source domain");
        let supplemental_source_spans = operation_map
            .remap_source_spans(ir.supplemental_source_spans())
            .expect("supplemental source spans use the compaction source domain");
        let parent_spans = operation_map
            .remap_parent_spans(ir.primary_parent_spans())
            .expect("parent spans use the compaction source domain");
        let supplemental_parent_spans = operation_map
            .remap_parent_spans(ir.supplemental_parent_spans())
            .expect("supplemental parent spans use the compaction source domain");

        let graph = ir.take_graph();

        let metadata = *ir.metadata();
        let mut builder = MCodeBuilder::new_with(metadata, graph)
            .with_source_spans(source_spans)
            .with_parent_spans(parent_spans);
        builder.extend_source_spans(supplemental_source_spans);
        builder.extend_parent_spans(supplemental_parent_spans);

        for (index, variable) in ir.variables().iter().enumerate() {
            if variable_kept[index] {
                let mapped = builder
                    .add_variable(*variable)
                    .expect("compacted variable id is representable");
                let source = MCodeVarId::try_from_index(index)
                    .expect("retained variable id is representable");
                debug_assert_eq!(mapped, remap_variable(source));
            }
        }
        for &variable in ir.aliased_variables() {
            if variable_kept[variable.index()] {
                builder
                    .add_aliased_variable(remap_variable(variable))
                    .expect("compacted aliased variable is representable");
            }
        }
        for domain in ir.memory_domains() {
            builder.add_memory_domain(domain.space());
        }

        let mut value_map = vec![None; ir.values().len()];
        let mut result_specs = Vec::new();
        let mut emit_operations = |builder: &mut MCodeBuilder,
                                   value_map: &mut [Option<IlValueId>],
                                   range: Range<usize>| {
            for index in range.filter(|index| required.op_is_required(*index)) {
                let source_operation = &ir.ops()[index];
                let mut spec =
                    MCodeOpSpec::new(source_operation.opcode(), source_operation.width())
                        .with_immediate(source_operation.immediate());
                if let Some(variable) = source_operation.variable() {
                    spec.set_variable(remap_variable(variable));
                }
                if source_operation.opcode() == MCodeOpcode::Constant
                    && source_operation.width() > 64
                    && let Some(value) = source_operation.constant(ir.constant_storage())
                {
                    spec.set_immediate(builder.intern_constant(&value));
                }
                if let Some(address) = source_operation.address() {
                    spec.set_address(address);
                }
                if let Some(address_space) = source_operation.address_space() {
                    spec.set_address_space(address_space);
                }
                result_specs.clear();
                result_specs.extend(source_operation.results().slice(ir.values()).iter().map(
                    |value| {
                        let mut result = MCodeResultSpec::new(value.width());
                        if let Some(variable) = value.variable() {
                            result.set_variable(remap_variable(variable));
                        }
                        result
                    },
                ));
                let operation = builder
                    .emit(
                        spec,
                        ir.op_operands_for(source_operation).iter().map(|value| {
                            value_map[value.index()]
                                .expect("a compacted operand is defined before its use")
                        }),
                        &result_specs,
                    )
                    .expect("compacted operation is representable");
                for (source, target) in (source_operation.results().start()
                    ..source_operation.results().end())
                    .zip(operation.results().start()..operation.results().end())
                {
                    value_map[source] = Some(
                        IlValueId::try_from_index(target)
                            .expect("compacted value id is representable"),
                    );
                }
            }
        };

        if block_order.is_empty() {
            emit_operations(&mut builder, &mut value_map, 0..ir.ops().len());
        } else {
            for index in 0..block_ranges.len() {
                let block =
                    IlBlockId::try_from_index(index).expect("MCode block id is representable");
                for &index in block_arg_indices.row(block.index()) {
                    let arg = &ir.block_args()[index];
                    let original = &ir.values()[arg.value().index()];
                    let mut result = MCodeResultSpec::new(arg.width());
                    if let Some(variable) = original.variable() {
                        result.set_variable(remap_variable(variable));
                    }
                    let value = builder
                        .add_block_arg(block, result)
                        .expect("compacted block argument is representable");
                    value_map[arg.value().index()] = Some(value);
                }
            }

            for block in block_order {
                builder
                    .switch_to_block(block)
                    .expect("compacted MCode block is representable");
                builder
                    .begin_block()
                    .expect("compacted MCode block can be started");
                let range = block_ranges[block.index()];
                emit_operations(&mut builder, &mut value_map, range.start()..range.end());
                let edges = block_edge_ranges[block.index()];
                for edge in edges.start()..edges.end() {
                    let target = edge_targets[edge];
                    let kept = block_arg_kept.row(target.index());
                    builder
                        .add_successor(
                            target,
                            edge_kinds[edge],
                            ir.args_for_edge(edge)
                                .iter()
                                .enumerate()
                                .filter(|(position, _)| {
                                    kept.get(*position).copied().unwrap_or(false)
                                })
                                .map(|(_, value)| {
                                    value_map[value.index()]
                                        .expect("a compacted edge argument remains defined")
                                }),
                        )
                        .expect("compacted MCode edge is representable");
                }
                builder
                    .end_block()
                    .expect("compacted MCode block can be ended");
            }
        }

        *ir = builder.build_unchecked();
    }
}

impl<'a> MCodeCompaction<'a> {
    pub(crate) const fn new(required_values: &'a [IlValueId]) -> Self {
        Self { required_values }
    }
}
