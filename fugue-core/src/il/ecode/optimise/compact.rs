use super::required::ECodeRequiredDefs;
use crate::il::common::{IlArtefact, IlCsr, IlIndexMapper, IlRewrite, IlSsaDef, IlValueId};
use crate::il::ecode::{ECodeBuilder, ECodeIr, ECodeOpSpec, ECodeOpcode};

pub(crate) struct ECodeCompaction;

impl IlRewrite<ECodeIr> for ECodeCompaction {
    fn rewrite(&mut self, ir: &mut ECodeIr) {
        let required = ir.analyse::<ECodeRequiredDefs>();

        let operation_map =
            IlIndexMapper::from_kept(ir.ops().len(), |index| required.op_is_required(index));
        let mut value_kept = vec![false; ir.values().len()];
        for (index, value) in ir.values().iter().enumerate() {
            value_kept[index] = match value.definition() {
                IlSsaDef::BlockArg(arg) => required.block_arg_is_required(arg.index()),
                IlSsaDef::Op(operation) => required.op_is_required(operation.index()),
            };
        }
        let value_map = IlIndexMapper::from_kept(ir.values().len(), |index| value_kept[index]);

        let remap_value = |value: IlValueId| {
            IlValueId::try_from_index(value_map.map_index(value.index()))
                .expect("remapped value id is representable")
        };

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

        let metadata = *ir.metadata();
        let mut builder = ECodeBuilder::new(metadata, graph)
            .with_source_spans(source_spans)
            .with_parent_spans(parent_spans);

        {
            let mut emitter = builder.emitter();
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
                    if let Some(domain) = ir.value_domain(arg.value()) {
                        emitter
                            .set_value_domain(value, domain)
                            .expect("compacted block argument domain is valid");
                    }
                    continue;
                }

                let (_, operation) = operations.next().expect("operation remains");
                let mut spec = ECodeOpSpec::new(operation.opcode(), operation.width())
                    .with_immediate(operation.immediate());
                if operation.opcode() == ECodeOpcode::Constant
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
                        operation.results().len(),
                    )
                    .expect("compacted operation is representable");
                for (old, new) in (operation.results().start()..operation.results().end())
                    .zip(results.start()..results.end())
                {
                    let old = IlValueId::try_from_index(old).expect("value id is representable");
                    let new = IlValueId::try_from_index(new)
                        .expect("compacted value id is representable");
                    if let Some(domain) = ir.value_domain(old) {
                        emitter
                            .set_value_domain(new, domain)
                            .expect("compacted result domain is valid");
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
