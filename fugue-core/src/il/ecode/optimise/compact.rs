use super::required::ECodeRequiredDefs;
use crate::il::common::{
    IlArtefact, IlBlockArgId, IlConstantInterner, IlCsr, IlIndexMapper, IlIndexRange, IlOpId,
    IlRewrite, IlSsaDef, IlValueId,
};
use crate::il::ecode::ir::ECodeIrStorage;
use crate::il::ecode::{ECodeBlockArg, ECodeIr, ECodeOpcode, ECodeValue};

pub(crate) struct ECodeCompaction;

impl IlRewrite<ECodeIr> for ECodeCompaction {
    fn rewrite(&mut self, ir: &mut ECodeIr) {
        let required = ir.analyse::<ECodeRequiredDefs>();

        let operation_map = IlIndexMapper::from_kept(ir.ops().len(), |index| {
            required.op_is_required(index)
        });
        let block_arg_map = IlIndexMapper::from_kept(ir.block_args().len(), |index| {
            required.block_arg_is_required(index)
        });

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

        let values = ir
            .values()
            .iter()
            .enumerate()
            .filter(|(index, _)| value_kept[*index])
            .map(|(_, value)| {
                let definition = match value.definition() {
                    IlSsaDef::Op(operation) => {
                        let operation = operation_map.map_index(operation.index());
                        IlSsaDef::Op(
                            IlOpId::try_from_index(operation)
                                .expect("remapped operation id is representable"),
                        )
                    }
                    IlSsaDef::BlockArg(arg) => {
                        let arg = block_arg_map.map_index(arg.index());
                        IlSsaDef::BlockArg(
                            IlBlockArgId::try_from_index(arg)
                                .expect("remapped block argument id is representable"),
                        )
                    }
                };
                ECodeValue::new(value.width(), definition)
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
        for (index, operation) in ir.ops().iter().enumerate() {
            if !required.op_is_required(index) {
                continue;
            }
            let operand_start = value_operands.len();
            for &operand in ir.op_operands_for(operation) {
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
            if !matches!(operation.opcode(), ECodeOpcode::Constant) || operation.width() <= 64 {
                continue;
            }
            if let Some(value) = operation.constant(ir.constant_storage()) {
                let immediate = interner.intern(&mut constants, &value);
                operation.replace_with_constant(immediate);
            }
        }

        let block_args = ir
            .block_args()
            .iter()
            .enumerate()
            .filter(|(index, _)| required.block_arg_is_required(*index))
            .map(|(_, arg)| ECodeBlockArg::new(arg.block(), remap_value(arg.value()), arg.width()))
            .collect::<Vec<_>>();

        let block_arg_kept = IlCsr::from_entries(
            ir.graph().blocks().len(),
            ir.block_args()
                .iter()
                .enumerate()
                .map(|(index, arg)| (arg.block().index(), required.block_arg_is_required(index))),
        );

        let mut edge_args = Vec::with_capacity(ir.edge_args().len());
        let mut edge_arg_values = Vec::new();
        for (edge, target) in ir.graph().successors().iter().enumerate() {
            let kept = block_arg_kept.row(target.index());
            let start = edge_arg_values.len();
            for (position, &value) in ir.args_for_edge(edge).iter().enumerate() {
                if kept.get(position).copied().unwrap_or(false) {
                    edge_arg_values.push(remap_value(value));
                }
            }
            edge_args.push(
                IlIndexRange::new(start, edge_arg_values.len())
                    .expect("edge argument range stays ordered"),
            );
        }

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
        let memory_domains = ir.take_memory_domains();
        *ir = ECodeIr::new(ECodeIrStorage {
            metadata,
            graph,
            source_spans,
            parent_spans,
            values,
            value_domains,
            block_args,
            edge_args,
            edge_arg_values,
            operations,
            value_operands,
            memory_domains,
            constant_storage: constants,
        });
    }
}
