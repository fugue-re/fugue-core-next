use rustc_hash::FxHashMap;

use crate::il::common::{IlBlockArgId, IlBlockId, IlCsr, IlGraph, IlOpId, IlValueId};

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(u8)]
pub enum IlSsaDef {
    BlockArgument(IlBlockArgId),
    Operation(IlOpId),
}

pub(crate) fn build_ssa_uses<'a, T>(
    value_count: usize,
    operation_operands: impl Clone + Iterator<Item = &'a [IlValueId]>,
    make_use: impl Copy + Fn(IlOpId, u32) -> T,
) -> IlCsr<T>
where
    T: Copy,
{
    let entries = operation_operands
        .enumerate()
        .flat_map(|(operation, operands)| {
            let user = IlOpId::try_from_index(operation)
                .expect("operation count fits the operation id space");
            operands
                .iter()
                .enumerate()
                .map(move |(operand, value)| (value.index(), make_use(user, operand as u32)))
        });

    IlCsr::from_entries(value_count, entries)
}

pub(crate) fn build_ssa_block_argument_inputs<'a>(
    graph: &IlGraph,
    arguments: impl Clone + Iterator<Item = (IlBlockId, IlValueId)>,
    arguments_for_edge: impl Fn(usize) -> &'a [IlValueId],
) -> FxHashMap<IlValueId, Vec<IlValueId>> {
    let block_count = graph.blocks().len();
    let arguments = IlCsr::from_entries(
        block_count,
        arguments.map(|(block, value)| (block.index(), value)),
    );
    let incoming = IlCsr::from_entries(
        block_count,
        graph
            .successors()
            .iter()
            .enumerate()
            .map(|(edge, target)| (target.index(), edge)),
    );

    let mut inputs = FxHashMap::default();
    for block in 0..block_count {
        for (position, &argument) in arguments.row(block).iter().enumerate() {
            let argument_inputs = incoming
                .row(block)
                .iter()
                .filter_map(|&edge| arguments_for_edge(edge).get(position).copied())
                .collect();
            inputs.insert(argument, argument_inputs);
        }
    }

    inputs
}
