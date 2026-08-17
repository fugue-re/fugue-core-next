use fixedbitset::FixedBitSet;

use crate::il::common::{
    ControlFlowIl, IlBlockArgId, IlBlockId, IlCsr, IlGraph, IlIndexRange, IlOpId, IlValueId,
};
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(u8)]
pub enum IlSsaDef {
    BlockArg(IlBlockArgId),
    Op(IlOpId),
}

pub trait SsaIl: ControlFlowIl {
    fn value_count(&self) -> usize;

    fn value_definition(&self, value: IlValueId) -> Option<IlSsaDef>;

    fn value_width(&self, value: IlValueId) -> Option<u32>;

    fn block_arg_count(&self) -> usize;

    fn block_arg_block(&self, arg: IlBlockArgId) -> Option<IlBlockId>;

    fn block_arg_value(&self, arg: IlBlockArgId) -> Option<IlValueId>;

    fn block_arg_width(&self, arg: IlBlockArgId) -> Option<u32>;

    fn operation_count(&self) -> usize;

    fn operation_operands(&self, operation: IlOpId) -> Option<&[IlValueId]>;

    fn edge_args(&self) -> &[IlIndexRange];

    fn edge_arg_values(&self) -> &[IlValueId];

    fn memory_domain_count(&self) -> usize;

    fn memory_domain_space(&self, index: usize) -> Option<AddressSpaceId>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IlRequiredDefs {
    block_args: FixedBitSet,
    operations: FixedBitSet,
}

impl IlRequiredDefs {
    pub fn new(block_arg_count: usize, operation_count: usize) -> Self {
        Self {
            block_args: FixedBitSet::with_capacity(block_arg_count),
            operations: FixedBitSet::with_capacity(operation_count),
        }
    }

    pub fn mark(&mut self, definition: IlSsaDef) -> bool {
        match definition {
            IlSsaDef::BlockArg(arg) => !self.block_args.put(arg.index()),
            IlSsaDef::Op(operation) => !self.operations.put(operation.index()),
        }
    }

    pub fn block_arg_is_required(&self, index: usize) -> bool {
        self.block_args.contains(index)
    }

    pub fn operation_is_required(&self, index: usize) -> bool {
        self.operations.contains(index)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct IlSsaBlockArgInputs {
    args: FixedBitSet,
    inputs: IlCsr<IlValueId>,
}

impl IlSsaBlockArgInputs {
    pub(crate) fn inputs_for(&self, arg: IlValueId) -> Option<&[IlValueId]> {
        self.args
            .contains(arg.index())
            .then(|| self.inputs.row(arg.index()))
    }

    pub(crate) fn iter(&self) -> impl Clone + Iterator<Item = (IlValueId, &[IlValueId])> {
        (0..self.inputs.len())
            .filter(|index| self.args.contains(*index))
            .map(|index| {
                (
                    IlValueId::try_from_index(index)
                        .expect("value count fits the value identifier space"),
                    self.inputs.row(index),
                )
            })
    }

    pub(crate) fn new<'a>(
        value_count: usize,
        graph: &IlGraph,
        args: impl Clone + Iterator<Item = (IlBlockId, IlValueId)>,
        args_for_edge: impl Fn(usize) -> &'a [IlValueId],
    ) -> Self {
        let block_count = graph.blocks().len();
        let mut present = FixedBitSet::with_capacity(value_count);
        for (_, arg) in args.clone() {
            present.insert(arg.index());
        }
        let args = IlCsr::from_entries(
            block_count,
            args.map(|(block, value)| (block.index(), value)),
        );
        let incoming = IlCsr::from_entries(
            block_count,
            graph
                .successors()
                .iter()
                .enumerate()
                .map(|(edge, target)| (target.index(), edge)),
        );

        let mut entries = Vec::new();
        for block in 0..block_count {
            for (position, &arg) in args.row(block).iter().enumerate() {
                entries.extend(incoming.row(block).iter().filter_map(|&edge| {
                    args_for_edge(edge)
                        .get(position)
                        .copied()
                        .map(|input| (arg.index(), input))
                }));
            }
        }

        IlSsaBlockArgInputs {
            args: present,
            inputs: IlCsr::from_entries(value_count, entries.into_iter()),
        }
    }
}

pub(crate) fn collect_ssa_uses<'a, T>(
    value_count: usize,
    operation_operands: impl Clone + Iterator<Item = &'a [IlValueId]>,
    make_use: impl Copy + Fn(IlOpId, usize) -> T,
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
                .map(move |(operand, value)| (value.index(), make_use(user, operand)))
        });

    IlCsr::from_entries(value_count, entries)
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::{IlBlockProperties, IlEdgeKinds, IlGraphBuilder, IlIndexRange};

    #[test]
    fn required_defs_mark_each_definition_once() {
        let arg = IlBlockArgId::try_from_index(2).unwrap();
        let operation = IlOpId::try_from_index(4).unwrap();
        let mut required = IlRequiredDefs::new(3, 5);

        assert!(required.mark(IlSsaDef::BlockArg(arg)));
        assert!(!required.mark(IlSsaDef::BlockArg(arg)));
        assert!(required.mark(IlSsaDef::Op(operation)));
        assert!(!required.mark(IlSsaDef::Op(operation)));
        assert!(required.block_arg_is_required(arg.index()));
        assert!(required.operation_is_required(operation.index()));
    }

    #[test]
    fn block_arg_inputs_preserve_many_dense_rows() {
        const ARG_COUNT: usize = 64;
        const PREDECESSOR_COUNT: usize = 32;

        let mut graph = IlGraphBuilder::new();
        let mut predecessors = Vec::with_capacity(PREDECESSOR_COUNT);
        for index in 0..PREDECESSOR_COUNT {
            let properties = if index == 0 {
                IlBlockProperties::ENTRY
            } else {
                IlBlockProperties::empty()
            };
            predecessors.push(
                graph
                    .push_block(IlIndexRange::EMPTY, properties)
                    .expect("the predecessor block is allocated"),
            );
        }
        let join = graph
            .push_block(IlIndexRange::EMPTY, IlBlockProperties::EXIT)
            .expect("the join block is allocated");
        for predecessor in &predecessors {
            graph
                .add_successor(*predecessor, join, IlEdgeKinds::UNCONDITIONAL)
                .expect("the join edge is valid");
        }
        let graph = graph.build(0).expect("the graph is valid");

        let args = (0..ARG_COUNT)
            .map(|index| {
                (
                    join,
                    IlValueId::try_from_index(index).expect("the argument identifier is valid"),
                )
            })
            .collect::<Vec<_>>();
        let edge_args = (0..PREDECESSOR_COUNT)
            .map(|predecessor| {
                (0..ARG_COUNT)
                    .map(|arg| {
                        IlValueId::try_from_index(ARG_COUNT + predecessor * ARG_COUNT + arg)
                            .expect("the incoming value identifier is valid")
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let value_count = ARG_COUNT + PREDECESSOR_COUNT * ARG_COUNT;

        let inputs =
            IlSsaBlockArgInputs::new(value_count, &graph, args.iter().copied(), |edge| {
                &edge_args[edge]
            });

        for (position, (_, arg)) in args.iter().enumerate() {
            let expected = edge_args
                .iter()
                .map(|values| values[position])
                .collect::<Vec<_>>();
            assert_eq!(inputs.inputs_for(*arg), Some(expected.as_slice()));
        }
        assert_eq!(inputs.inputs.len(), value_count);
        assert_eq!(inputs.inputs_for(edge_args[0][0]), None);
    }
}
