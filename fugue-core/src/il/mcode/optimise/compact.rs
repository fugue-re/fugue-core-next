use std::collections::BTreeMap;

use super::required::MCodeRequiredDefs;
use crate::il::common::{IlCsr, IlIndexMapper, IlRewrite, IlSsaDef, IlValueId};
use crate::il::mcode::{MCodeBuilder, MCodeIr, MCodeOpSpec, MCodeOpcode, MCodeVarId, MCodeVersion};

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
        let value_map = IlIndexMapper::from_kept(ir.values().len(), |index| value_kept[index]);

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

        let remap_value = |value: IlValueId| {
            IlValueId::try_from_index(value_map.map_index(value.index()))
                .expect("remapped value id is representable")
        };
        let remap_variable = |variable: MCodeVarId| {
            MCodeVarId::try_from_index(variable_map.map_index(variable.index()))
                .expect("remapped variable id is representable")
        };

        let mut new_versions = vec![MCodeVersion::new(0); ir.values().len()];
        let mut versions = BTreeMap::<MCodeVarId, Vec<(MCodeVersion, usize)>>::new();
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
                new_versions[value] = MCodeVersion::new(
                    u32::try_from(index + 1).expect("compacted variable version is representable"),
                );
            }
        }

        let block_arg_kept = IlCsr::from_entries(
            ir.graph().blocks().len(),
            ir.block_args()
                .iter()
                .enumerate()
                .map(|(index, arg)| (arg.block().index(), required.block_arg_is_required(index))),
        );
        let edge_targets = ir.graph().successors().to_vec();

        let source_spans = operation_map
            .remap_source_spans(ir.source_spans())
            .expect("source spans use the compaction source domain");
        let parent_spans = operation_map
            .remap_parent_spans(ir.parent_spans())
            .expect("parent spans use the compaction source domain");

        let mut graph = ir.take_graph();
        graph
            .remap_op_ranges(&operation_map)
            .expect("graph operation ranges use the compaction source domain");

        let aliased_variables = ir
            .aliased_variables()
            .iter()
            .filter(|variable| variable_kept[variable.index()])
            .copied()
            .map(remap_variable)
            .collect();
        let metadata = *ir.metadata();
        let mut builder = MCodeBuilder::new(metadata, graph)
            .with_source_spans(source_spans)
            .with_parent_spans(parent_spans)
            .with_aliased_variables(aliased_variables);

        {
            let mut emitter = builder.emitter();
            for (index, variable) in ir.variables().iter().enumerate() {
                if variable_kept[index] {
                    emitter
                        .intern_variable(*variable)
                        .expect("compacted variable id is representable");
                }
            }
            for domain in ir.memory_domains() {
                emitter.intern_memory_domain(domain.space());
            }

            let mut operations = ir
                .ops()
                .iter()
                .enumerate()
                .filter(|(index, _)| required.op_is_required(*index))
                .peekable();
            let mut block_args = ir
                .block_args()
                .iter()
                .enumerate()
                .filter(|(index, _)| required.block_arg_is_required(*index))
                .peekable();

            while operations.peek().is_some() || block_args.peek().is_some() {
                let emit_block_arg = match (operations.peek(), block_args.peek()) {
                    (Some((_, operation)), Some((_, arg))) => {
                        arg.value().index() < operation.results().start()
                    }
                    (None, Some(_)) => true,
                    _ => false,
                };

                if emit_block_arg {
                    let (_, arg) = block_args.next().expect("block argument remains");
                    let value = emitter
                        .emit_block_arg(arg.block(), arg.width())
                        .expect("compacted block argument is representable");
                    let original = &ir.values()[arg.value().index()];
                    if let Some(variable) = original.variable() {
                        emitter
                            .bind_value(
                                value,
                                remap_variable(variable),
                                new_versions[arg.value().index()],
                            )
                            .expect("compacted block argument binding is valid");
                    }
                    continue;
                }

                let (_, operation) = operations.next().expect("operation remains");
                let mut spec = MCodeOpSpec::new(operation.opcode(), operation.width())
                    .with_immediate(operation.immediate());
                if let Some(variable) = operation.variable() {
                    spec.set_variable(remap_variable(variable));
                }
                if operation.opcode() == MCodeOpcode::Constant
                    && operation.width() > 64
                    && let Some(value) = operation.constant(ir.constant_storage())
                {
                    spec.set_immediate(emitter.intern_constant(&value));
                }
                if let Some(address) = operation.address() {
                    spec.set_address(address);
                }
                if let Some(address_space) = operation.address_space() {
                    spec.set_address_space(address_space);
                }
                let (_, results) = emitter
                    .emit(
                        spec,
                        ir.op_operands_for(operation)
                            .iter()
                            .copied()
                            .map(remap_value),
                        operation
                            .results()
                            .slice(ir.values())
                            .iter()
                            .map(|value| value.width()),
                    )
                    .expect("compacted operation is representable");
                for (old, new) in (operation.results().start()..operation.results().end())
                    .zip(results.start()..results.end())
                {
                    let original = &ir.values()[old];
                    if let Some(variable) = original.variable() {
                        let value = IlValueId::try_from_index(new)
                            .expect("compacted value id is representable");
                        emitter
                            .bind_value(value, remap_variable(variable), new_versions[old])
                            .expect("compacted result binding is valid");
                    }
                }
            }

            for (edge, target) in edge_targets.iter().enumerate() {
                let kept = block_arg_kept.row(target.index());
                emitter
                    .emit_edge_args(
                        ir.args_for_edge(edge)
                            .iter()
                            .enumerate()
                            .filter(|(position, _)| kept.get(*position).copied().unwrap_or(false))
                            .map(|(_, &value)| remap_value(value)),
                    )
                    .expect("compacted edge arguments are representable");
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
