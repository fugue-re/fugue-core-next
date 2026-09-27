use std::ops::Range;

use crate::il::common::{
    IlArtefact, IlBlockId, IlCsr, IlIndexMapper, IlRewrite, IlSsaDef, IlValueId,
};
use crate::il::ecode::{ECodeBuilder, ECodeIr, ECodeOpSpec, ECodeOpcode};

use super::required::ECodeRequiredDefs;

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
        let mut value_map = vec![None; ir.values().len()];

        let block_arg_kept = IlCsr::from_entries(
            ir.graph().blocks().len(),
            ir.block_args()
                .iter()
                .enumerate()
                .map(|(index, arg)| (arg.block().index(), required.block_arg_is_required(index))),
        );

        let edge_targets = ir.graph().successors().to_vec();
        let edge_kinds = ir.graph().successor_kinds().to_vec();
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
            .map(|index| IlBlockId::try_from_index(index).expect("ECode block id is representable"))
            .collect::<Vec<_>>();
        block_order.sort_unstable_by_key(|block| block_ranges[block.index()].start());

        let source_spans = operation_map
            .remap_source_spans(ir.source_spans())
            .expect("source spans use the compaction source domain");
        let parent_spans = operation_map
            .remap_parent_spans(ir.parent_spans())
            .expect("parent spans use the compaction source domain");

        let graph = ir.take_graph();

        let metadata = *ir.metadata();
        let mut builder = ECodeBuilder::new_with(metadata, graph)
            .with_source_spans(source_spans)
            .with_parent_spans(parent_spans);

        for domain in ir.memory_domains() {
            builder.intern_memory_domain(domain.space());
        }

        for (index, arg) in ir.block_args().iter().enumerate() {
            if !required.block_arg_is_required(index) {
                continue;
            }
            let value = builder
                .add_block_arg(arg.block(), arg.width())
                .expect("compacted block argument is representable");
            if let Some(domain) = ir.value_domain(arg.value()) {
                builder
                    .set_value_domain(value, domain)
                    .expect("compacted block argument domain is valid");
            }
            value_map[arg.value().index()] = Some(value);
        }

        let emit_operations = |builder: &mut ECodeBuilder,
                               value_map: &mut [Option<IlValueId>],
                               range: Range<usize>| {
            for index in range.filter(|index| required.op_is_required(*index)) {
                let operation = &ir.ops()[index];
                let mut spec = ECodeOpSpec::new(operation.opcode(), operation.width())
                    .with_immediate(operation.immediate());
                if operation.opcode() == ECodeOpcode::Constant
                    && operation.width() > 64
                    && let Some(value) = operation.constant(ir.constant_storage())
                {
                    spec.set_immediate(builder.intern_constant(&value));
                }
                if let Some(address) = operation.address() {
                    spec.set_address(address);
                }
                if let Some(address_space) = operation.address_space() {
                    spec.set_address_space(address_space);
                }
                let emitted = builder
                    .emit(
                        spec,
                        ir.op_operands_for(operation).iter().map(|value| {
                            value_map[value.index()]
                                .expect("a compacted operand is defined before its use")
                        }),
                        operation.results().len(),
                    )
                    .expect("compacted operation is representable");
                for (old, new) in (operation.results().start()..operation.results().end())
                    .zip(emitted.results().start()..emitted.results().end())
                {
                    let old = IlValueId::try_from_index(old).expect("value id is representable");
                    let new = IlValueId::try_from_index(new)
                        .expect("compacted value id is representable");
                    if let Some(domain) = ir.value_domain(old) {
                        builder
                            .set_value_domain(new, domain)
                            .expect("compacted result domain is valid");
                    }
                    value_map[old.index()] = Some(new);
                }
            }
        };

        if block_order.is_empty() {
            emit_operations(&mut builder, &mut value_map, 0..ir.ops().len());
        } else {
            for block in block_order {
                builder
                    .switch_to_block(block)
                    .expect("compacted ECode block is representable");
                builder
                    .begin_block()
                    .expect("compacted ECode block can be started");
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
                        .expect("compacted ECode edge is representable");
                }
                builder
                    .end_block()
                    .expect("compacted ECode block can be ended");
            }
        }

        *ir = builder.build_unchecked();
    }
}
