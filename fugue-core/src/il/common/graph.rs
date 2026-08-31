use std::mem::size_of;

use crate::il::common::verify::StructureError;
use crate::il::common::{IlBlockId, IlCsr, IlError, IlIndexMapper, IlIndexRange, IlOpId, IlPool};
use crate::ir::{Address, FlowKind};
use crate::storage::schema::bitflags::archived_bitflags;
use crate::types::EstimateSize;

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
    pub struct IlBlockProperties: u16 {
        const ENTRY = 0x0001;
        const EXIT  = 0x0002;
    }
}

archived_bitflags!(IlBlockProperties, ArchivedIlBlockProperties, u16);

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
    pub struct IlEdgeKinds: u8 {
        const COMPUTED      = 0x01;
        const FALL_THROUGH  = 0x02;
        const TAKEN         = 0x04;
        const UNCONDITIONAL = 0x08;
    }
}

archived_bitflags!(IlEdgeKinds, ArchivedIlEdgeKinds, u8);

impl IlEdgeKinds {
    pub const SINGULAR: Self = Self::FALL_THROUGH
        .union(Self::TAKEN)
        .union(Self::UNCONDITIONAL);

    pub const fn from_flow(kind: FlowKind) -> Option<Self> {
        match kind {
            FlowKind::Branch | FlowKind::TailCallBranch => Some(Self::UNCONDITIONAL),
            FlowKind::CBranch => Some(Self::TAKEN),
            FlowKind::Fall => Some(Self::FALL_THROUGH),
            FlowKind::IBranch | FlowKind::SwitchBranch => Some(Self::COMPUTED),
            FlowKind::Call
            | FlowKind::ICall
            | FlowKind::Return
            | FlowKind::ServiceCall
            | FlowKind::SwitchCall => None,
        }
    }

    pub const fn is_computed(self) -> bool {
        self.contains(Self::COMPUTED)
    }

    pub const fn is_fall_through(self) -> bool {
        self.contains(Self::FALL_THROUGH)
    }

    pub const fn is_taken(self) -> bool {
        self.contains(Self::TAKEN)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct IlBlock {
    operations: IlIndexRange,
    successors: IlIndexRange,
    properties: IlBlockProperties,
}

impl IlBlock {
    pub(crate) const fn new(
        operations: IlIndexRange,
        successors: IlIndexRange,
        properties: IlBlockProperties,
    ) -> Self {
        Self {
            operations,
            successors,
            properties,
        }
    }

    pub const fn ops(&self) -> IlIndexRange {
        self.operations
    }

    pub const fn successors(&self) -> IlIndexRange {
        self.successors
    }

    pub const fn properties(&self) -> IlBlockProperties {
        self.properties
    }

    pub const fn is_entry(&self) -> bool {
        self.properties.contains(IlBlockProperties::ENTRY)
    }

    pub const fn is_exit(&self) -> bool {
        self.properties.contains(IlBlockProperties::EXIT)
    }
}

#[derive(
    Debug, Clone, Default, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct IlGraph {
    blocks: Vec<IlBlock>,
    successors: Vec<IlBlockId>,
    successor_kinds: Vec<IlEdgeKinds>,
    block_sources: Vec<Address>,
}

impl EstimateSize for IlGraph {
    fn estimate_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(self.blocks.capacity().saturating_mul(size_of::<IlBlock>()))
            .saturating_add(
                self.successors
                    .capacity()
                    .saturating_mul(size_of::<IlBlockId>()),
            )
            .saturating_add(
                self.successor_kinds
                    .capacity()
                    .saturating_mul(size_of::<IlEdgeKinds>()),
            )
            .saturating_add(
                self.block_sources
                    .capacity()
                    .saturating_mul(size_of::<Address>()),
            )
    }
}

impl IlGraph {
    pub(crate) fn new(
        blocks: Vec<IlBlock>,
        successors: Vec<IlBlockId>,
        successor_kinds: Vec<IlEdgeKinds>,
    ) -> Self {
        for block in &blocks {
            debug_assert!(
                block.successors().end() <= successors.len(),
                "block successor range is within the successor pool"
            );
        }

        for successor in &successors {
            debug_assert!(
                successor.index() < blocks.len(),
                "successor id is within the block count"
            );
        }

        debug_assert_eq!(
            successors.len(),
            successor_kinds.len(),
            "each successor edge carries its own kind set"
        );

        Self {
            blocks,
            successors,
            successor_kinds,
            block_sources: Vec::new(),
        }
    }

    pub(crate) fn set_block_sources(&mut self, block_sources: Vec<Address>) {
        debug_assert_eq!(
            block_sources.len(),
            self.blocks.len(),
            "block source count matches the block count",
        );
        self.block_sources = block_sources;
    }

    pub(crate) fn with_block_sources(mut self, block_sources: Vec<Address>) -> Self {
        self.set_block_sources(block_sources);
        self
    }

    pub fn blocks(&self) -> &[IlBlock] {
        &self.blocks
    }

    pub fn successors(&self) -> &[IlBlockId] {
        &self.successors
    }

    pub fn successor_kinds(&self) -> &[IlEdgeKinds] {
        &self.successor_kinds
    }

    pub fn block_sources(&self) -> &[Address] {
        &self.block_sources
    }

    pub fn blocks_with_sources(&self) -> impl Iterator<Item = (IlBlockId, Address)> + '_ {
        self.block_sources
            .iter()
            .enumerate()
            .map(|(index, &source)| {
                (
                    IlBlockId::try_from_index(index).expect("block count fits the block id space"),
                    source,
                )
            })
    }

    pub fn block_source(&self, block: IlBlockId) -> Option<Address> {
        self.block_sources.get(block.index()).copied()
    }

    pub fn block_for_op(&self, operation: IlOpId) -> Option<IlBlockId> {
        self.blocks
            .iter()
            .position(|block| block.ops().contains_index(operation.index()))
            .and_then(|index| IlBlockId::try_from_index(index).ok())
    }

    pub fn ops_for_block<'a, T>(
        &'a self,
        block: IlBlockId,
        operations: &'a [T],
    ) -> impl DoubleEndedIterator<Item = (IlOpId, &'a T)> + 'a {
        self.blocks
            .get(block.index())
            .into_iter()
            .flat_map(|block| {
                let start = block.ops().start();
                block
                    .ops()
                    .slice(operations)
                    .iter()
                    .enumerate()
                    .map(move |(index, operation)| {
                        (
                            IlOpId::try_from_index(start + index)
                                .expect("operation count fits the operation id space"),
                            operation,
                        )
                    })
            })
    }

    pub fn successors_for(&self, block: IlBlockId) -> &[IlBlockId] {
        let Some(block) = self.blocks.get(block.index()) else {
            return &[];
        };
        block.successors().slice(&self.successors)
    }

    pub fn successor_kinds_for(&self, block: IlBlockId) -> &[IlEdgeKinds] {
        let Some(block) = self.blocks.get(block.index()) else {
            return &[];
        };
        block.successors().slice(&self.successor_kinds)
    }

    pub fn set_op_ranges(
        &mut self,
        operation_ranges: impl ExactSizeIterator<Item = IlIndexRange>,
    ) -> Result<(), IlError> {
        if operation_ranges.len() != self.blocks.len() {
            return Err(IlError::graph_block_count_mismatch(
                self.blocks.len(),
                operation_ranges.len(),
            ));
        }

        for (block, operations) in self.blocks.iter_mut().zip(operation_ranges) {
            block.operations = operations;
        }

        Ok(())
    }

    pub fn with_op_ranges(
        mut self,
        operation_ranges: impl ExactSizeIterator<Item = IlIndexRange>,
    ) -> Result<Self, IlError> {
        self.set_op_ranges(operation_ranges)?;
        Ok(self)
    }

    pub fn op_blocks(&self, operation_count: usize) -> Vec<Option<IlBlockId>> {
        let mut operation_blocks = vec![None; operation_count];
        for (index, block) in self.blocks.iter().enumerate() {
            let block_id =
                IlBlockId::try_from_index(index).expect("block count fits the block id space");
            for operation in block.ops().start()..block.ops().end() {
                if let Some(entry) = operation_blocks.get_mut(operation) {
                    *entry = Some(block_id);
                }
            }
        }
        operation_blocks
    }

    pub fn remap_op_ranges(&mut self, operation_map: &IlIndexMapper) -> Result<(), IlError> {
        for block in &self.blocks {
            operation_map.checked_map_range(block.operations)?;
        }
        for block in &mut self.blocks {
            block.operations = operation_map.map_range(block.operations);
        }

        Ok(())
    }

    pub fn entry_block(&self) -> Option<IlBlockId> {
        if self.blocks.is_empty() {
            return None;
        }

        let index = self.blocks.iter().position(IlBlock::is_entry).unwrap_or(0);

        Some(IlBlockId::try_from_index(index).expect("block count fits the block id space"))
    }

    pub fn shrink_to_fit(&mut self) {
        self.blocks.shrink_to_fit();
        self.successors.shrink_to_fit();
        self.successor_kinds.shrink_to_fit();
        self.block_sources.shrink_to_fit();
    }

    pub(crate) fn verify(&self) -> Result<(), StructureError> {
        let mut operation_ranges = Vec::new();

        for (index, block) in self.blocks.iter().enumerate() {
            let block_id = IlBlockId::try_from_index(index)?;
            block.ops().verify_bounds(usize::MAX)?;
            self.verify_successors(block, block_id)?;

            if !block.ops().is_empty() {
                operation_ranges.push((block.ops(), block_id));
            }

            for successor in block.successors().checked_slice(&self.successors)? {
                if successor.index() >= self.blocks.len() {
                    return Err(
                        IlError::range_out_of_bounds(successor.index(), self.blocks.len()).into(),
                    );
                }
            }
        }

        operation_ranges.sort_unstable_by_key(|(range, _)| range.start());
        let mut previous_operation_end = 0usize;
        for (operations, block_id) in operation_ranges {
            if operations.start() < previous_operation_end {
                return Err(StructureError::OverlappingBlockOps {
                    block: block_id.value(),
                    operation: operations.start(),
                });
            }
            previous_operation_end = operations.end();
        }

        if self.successor_kinds.len() != self.successors.len() {
            return Err(StructureError::EdgeKindCount {
                expected: self.successors.len(),
                found: self.successor_kinds.len(),
            });
        }

        if !self.block_sources.is_empty() && self.block_sources.len() != self.blocks.len() {
            return Err(StructureError::BlockSourceCount {
                expected: self.blocks.len(),
                found: self.block_sources.len(),
            });
        }

        Ok(())
    }

    pub(crate) fn verify_node_bounds(&self, node_count: usize) -> Result<(), StructureError> {
        for block in &self.blocks {
            block.ops().verify_bounds(node_count)?;
        }

        Ok(())
    }

    fn verify_successors(
        &self,
        block: &IlBlock,
        block_id: IlBlockId,
    ) -> Result<(), StructureError> {
        let successors = block.successors().checked_slice(&self.successors)?;

        for (index, successor) in successors.iter().enumerate() {
            if successors[..index].contains(successor) {
                return Err(StructureError::DuplicateSuccessor {
                    block: block_id.value(),
                    successor: successor.value(),
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct IlGraphBuilder {
    blocks: Vec<IlGraphBuilderBlock>,
    block_sources: Option<Vec<Address>>,
}

impl IlGraphBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_block(
        &mut self,
        operations: IlIndexRange,
        properties: IlBlockProperties,
    ) -> Result<IlBlockId, IlError> {
        if self.block_sources.is_some() {
            return Err(IlError::inconsistent_block_sources());
        }

        self.push_block_record(operations, properties)
    }

    pub fn push_block_with_source(
        &mut self,
        operations: IlIndexRange,
        properties: IlBlockProperties,
        source: Address,
    ) -> Result<IlBlockId, IlError> {
        if self.block_sources.is_none() {
            if !self.blocks.is_empty() {
                return Err(IlError::inconsistent_block_sources());
            }
            self.block_sources = Some(Vec::new());
        }

        let block = self.push_block_record(operations, properties)?;
        self.block_sources
            .as_mut()
            .expect("source mode was selected above")
            .push(source);

        Ok(block)
    }

    pub fn add_successor(
        &mut self,
        block: IlBlockId,
        successor: IlBlockId,
        kinds: IlEdgeKinds,
    ) -> Result<(), IlError> {
        if successor.index() >= self.blocks.len() {
            return Err(IlError::range_out_of_bounds(
                successor.index(),
                self.blocks.len(),
            ));
        }

        let block_count = self.blocks.len();
        let block = self
            .blocks
            .get_mut(block.index())
            .ok_or_else(|| IlError::range_out_of_bounds(block.index(), block_count))?;

        if let Some((_, existing)) = block
            .successors
            .iter_mut()
            .find(|(target, _)| *target == successor)
        {
            *existing |= kinds;
        } else {
            block.successors.push((successor, kinds));
        }

        Ok(())
    }

    pub fn build(self, operation_count: usize) -> Result<IlGraph, IlError> {
        self.verify_op_ranges(operation_count)?;

        let mut successors = IlPool::new();
        let mut successor_kinds = Vec::new();
        let mut blocks = Vec::with_capacity(self.blocks.len());

        for block in self.blocks {
            let successor_range =
                successors.append(block.successors.iter().map(|(successor, _)| *successor))?;
            successor_kinds.extend(block.successors.iter().map(|(_, kinds)| *kinds));
            blocks.push(IlBlock::new(
                block.operations,
                successor_range,
                block.properties,
            ));
        }

        let graph = IlGraph::new(blocks, successors.into_values(), successor_kinds);

        Ok(match self.block_sources {
            Some(block_sources) => graph.with_block_sources(block_sources),
            None => graph,
        })
    }

    fn push_block_record(
        &mut self,
        operations: IlIndexRange,
        properties: IlBlockProperties,
    ) -> Result<IlBlockId, IlError> {
        let id = IlBlockId::try_from_index(self.blocks.len())?;
        self.blocks.push(IlGraphBuilderBlock {
            operations,
            properties,
            successors: Vec::new(),
        });

        Ok(id)
    }

    fn verify_op_ranges(&self, operation_count: usize) -> Result<(), IlError> {
        let mut ranges = self
            .blocks
            .iter()
            .map(|block| block.operations)
            .filter(|range| !range.is_empty())
            .collect::<Vec<_>>();
        ranges.sort_unstable_by_key(IlIndexRange::start);

        let mut previous_end = 0usize;
        for range in ranges {
            range.verify_bounds(operation_count)?;
            if range.start() < previous_end {
                return Err(IlError::overlapping_ranges(range.start(), previous_end));
            }
            previous_end = range.end();
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct IlGraphBuilderBlock {
    operations: IlIndexRange,
    properties: IlBlockProperties,
    successors: Vec<(IlBlockId, IlEdgeKinds)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IlBlockPredecessors {
    predecessors: IlCsr<IlBlockId>,
}

impl IlBlockPredecessors {
    pub fn new(blocks: &[IlBlock], successors: &[IlBlockId]) -> Self {
        let entries = blocks.iter().enumerate().flat_map(|(block_index, block)| {
            let block_id = IlBlockId::try_from_index(block_index)
                .expect("block count fits the block id space");

            block
                .successors()
                .slice(successors)
                .iter()
                .map(move |successor| (successor.index(), block_id))
        });

        Self {
            predecessors: IlCsr::from_entries(blocks.len(), entries),
        }
    }

    pub fn predecessors_for(&self, block: IlBlockId) -> &[IlBlockId] {
        self.predecessors.checked_row(block.index()).unwrap_or(&[])
    }
}

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn block_stays_compact() {
        assert!(size_of::<IlBlock>() <= 32);
    }

    #[test]
    fn empty_graph_has_no_entry_block() {
        assert_eq!(IlGraph::default().entry_block(), None);
    }

    #[test]
    fn entry_block_prefers_flagged_block() {
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::empty(),
                ),
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::ENTRY,
                ),
            ],
            Vec::new(),
            Vec::new(),
        );

        assert_eq!(graph.entry_block(), IlBlockId::try_from_index(1).ok());
    }

    #[test]
    fn predecessor_index_builds_from_successor_ranges() {
        let block0 = IlBlockId::try_from_index(0).unwrap();
        let block1 = IlBlockId::try_from_index(1).unwrap();
        let block2 = IlBlockId::try_from_index(2).unwrap();
        let blocks = vec![
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::new(0, 2).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::new(2, 3).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::EMPTY,
                IlBlockProperties::empty(),
            ),
        ];
        let successors = vec![block1, block2, block2];
        let index = IlBlockPredecessors::new(&blocks, &successors);

        assert_eq!(index.predecessors_for(block0), &[]);
        assert_eq!(index.predecessors_for(block1), &[block0]);
        assert_eq!(index.predecessors_for(block2), &[block0, block1]);
    }

    #[test]
    fn invalid_block_queries_are_empty() {
        let graph = IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::EMPTY,
                IlBlockProperties::empty(),
            )],
            Vec::new(),
            Vec::new(),
        );
        let predecessors = IlBlockPredecessors::new(graph.blocks(), graph.successors());
        let invalid = IlBlockId::try_from_index(graph.blocks().len()).unwrap();

        assert!(graph.successors_for(invalid).is_empty());
        assert!(graph.successor_kinds_for(invalid).is_empty());
        assert!(predecessors.predecessors_for(invalid).is_empty());
    }

    #[test]
    fn interprocedural_flow_has_no_edge_kind() {
        assert_eq!(IlEdgeKinds::from_flow(FlowKind::Call), None);
        assert_eq!(IlEdgeKinds::from_flow(FlowKind::Return), None);
        assert_eq!(
            IlEdgeKinds::from_flow(FlowKind::CBranch),
            Some(IlEdgeKinds::TAKEN)
        );
        assert_eq!(
            IlEdgeKinds::from_flow(FlowKind::Fall),
            Some(IlEdgeKinds::FALL_THROUGH)
        );
    }

    #[test]
    fn edge_kinds_combine_for_a_collapsed_conditional_edge() {
        let collapsed = IlEdgeKinds::TAKEN | IlEdgeKinds::FALL_THROUGH;

        assert!(collapsed.is_taken());
        assert!(collapsed.is_fall_through());
        assert!(!collapsed.is_computed());
    }

    #[test]
    fn graph_builder_allocates_blocks_and_combines_edges() {
        let mut builder = IlGraphBuilder::new();
        let entry = builder
            .push_block(IlIndexRange::new(0, 1).unwrap(), IlBlockProperties::ENTRY)
            .unwrap();
        let exit = builder
            .push_block(IlIndexRange::new(1, 2).unwrap(), IlBlockProperties::EXIT)
            .unwrap();
        builder
            .add_successor(entry, exit, IlEdgeKinds::TAKEN)
            .unwrap();
        builder
            .add_successor(entry, exit, IlEdgeKinds::FALL_THROUGH)
            .unwrap();

        let graph = builder.build(2).unwrap();

        assert_eq!(graph.successors_for(entry), &[exit]);
        assert_eq!(
            graph.successor_kinds_for(entry),
            &[IlEdgeKinds::TAKEN | IlEdgeKinds::FALL_THROUGH]
        );
    }

    #[test]
    fn operation_remapping_retains_graph_topology_storage() {
        let entry = IlBlockId::try_from_index(0).unwrap();
        let exit = IlBlockId::try_from_index(1).unwrap();
        let mut graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::new(0, 2).unwrap(),
                    IlIndexRange::new(0, 1).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::new(2, 4).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            vec![exit],
            vec![IlEdgeKinds::FALL_THROUGH],
        )
        .with_block_sources(vec![Address::from(0x1000u64), Address::from(0x1004u64)]);
        let block_storage = graph.blocks.as_ptr();
        let successor_storage = graph.successors.as_ptr();
        let kind_storage = graph.successor_kinds.as_ptr();
        let source_storage = graph.block_sources.as_ptr();
        let mapper = IlIndexMapper::from_kept(4, |index| index != 1);

        graph.remap_op_ranges(&mapper).unwrap();

        assert_eq!(graph.blocks.as_ptr(), block_storage);
        assert_eq!(graph.successors.as_ptr(), successor_storage);
        assert_eq!(graph.successor_kinds.as_ptr(), kind_storage);
        assert_eq!(graph.block_sources.as_ptr(), source_storage);
        assert_eq!(
            graph.blocks[entry.index()].ops(),
            IlIndexRange::new(0, 1).unwrap()
        );
        assert_eq!(
            graph.blocks[exit.index()].ops(),
            IlIndexRange::new(1, 3).unwrap()
        );
    }

    #[test]
    fn operation_remapping_does_not_mutate_before_validation_completes() {
        let mut graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::new(1, 3).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            Vec::new(),
            Vec::new(),
        );
        let original = graph.clone();
        let mapper = IlIndexMapper::new(vec![0, 2, 3]).unwrap();

        assert!(matches!(
            graph.remap_op_ranges(&mapper),
            Err(IlError::RangeOutOfBounds { .. })
        ));
        assert_eq!(graph, original);
    }

    #[test]
    fn structural_verifier_rejects_edge_kind_count_mismatch() {
        let block = IlBlockId::try_from_index(0).unwrap();
        let graph = IlGraph {
            blocks: vec![IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::new(0, 1).unwrap(),
                IlBlockProperties::empty(),
            )],
            successors: vec![block],
            successor_kinds: Vec::new(),
            block_sources: Vec::new(),
        };

        assert!(matches!(
            graph.verify(),
            Err(StructureError::EdgeKindCount { .. })
        ));
    }

    #[test]
    fn structural_verifier_rejects_duplicate_successor() {
        let block = IlBlockId::try_from_index(0).unwrap();
        let graph = IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::new(0, 2).unwrap(),
                IlBlockProperties::empty(),
            )],
            vec![block, block],
            vec![IlEdgeKinds::UNCONDITIONAL; 2],
        );

        assert!(matches!(
            graph.verify(),
            Err(StructureError::DuplicateSuccessor { .. })
        ));
    }

    #[test]
    fn structural_verifier_rejects_out_of_range_block_operations() {
        let graph = IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::new(0, 2).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::empty(),
            )],
            Vec::new(),
            Vec::new(),
        );

        assert!(matches!(
            graph.verify_node_bounds(1),
            Err(StructureError::Il(IlError::RangeOutOfBounds { .. }))
        ));
    }

    #[test]
    fn structural_verifier_rejects_out_of_range_successor() {
        let graph = IlGraph {
            blocks: vec![IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::new(0, 1).unwrap(),
                IlBlockProperties::empty(),
            )],
            successors: vec![IlBlockId::try_from_index(1).unwrap()],
            successor_kinds: vec![IlEdgeKinds::UNCONDITIONAL],
            block_sources: Vec::new(),
        };

        assert!(matches!(
            graph.verify(),
            Err(StructureError::Il(IlError::RangeOutOfBounds { .. }))
        ));
    }

    #[test]
    fn structural_verifier_rejects_overlapping_block_operations() {
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::new(0, 2).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::empty(),
                ),
                IlBlock::new(
                    IlIndexRange::new(1, 3).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::empty(),
                ),
            ],
            Vec::new(),
            Vec::new(),
        );

        assert!(matches!(
            graph.verify(),
            Err(StructureError::OverlappingBlockOps { .. })
        ));
    }
}
