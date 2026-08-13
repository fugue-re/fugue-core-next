use std::mem::size_of;

use crate::il::common::verify::StructureError;
use crate::il::common::{IlBlockId, IlCsr, IlError, IlIndexRange};
use crate::ir::{Address, FlowKind};
use crate::types::EstimateSize;
use crate::types::common::archived_bitflags;

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

    pub const fn operations(&self) -> IlIndexRange {
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

    pub(crate) fn with_block_sources(mut self, block_sources: Vec<Address>) -> Self {
        debug_assert_eq!(
            block_sources.len(),
            self.blocks.len(),
            "block source count matches the block count",
        );
        self.block_sources = block_sources;
        self
    }

    pub fn blocks(&self) -> &[IlBlock] {
        &self.blocks
    }

    pub fn successors(&self) -> &[IlBlockId] {
        &self.successors
    }

    pub fn successors_for(&self, block: IlBlockId) -> &[IlBlockId] {
        let Some(block) = self.blocks.get(block.index()) else {
            return &[];
        };
        block.successors().slice(&self.successors)
    }

    pub fn successor_kinds(&self) -> &[IlEdgeKinds] {
        &self.successor_kinds
    }

    pub fn successor_kinds_for(&self, block: IlBlockId) -> &[IlEdgeKinds] {
        let Some(block) = self.blocks.get(block.index()) else {
            return &[];
        };
        block.successors().slice(&self.successor_kinds)
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

    pub fn entry_block(&self) -> Option<IlBlockId> {
        if self.blocks.is_empty() {
            return None;
        }

        let index = self.blocks.iter().position(IlBlock::is_entry).unwrap_or(0);

        Some(IlBlockId::try_from_index(index).expect("block count fits the block id space"))
    }

    pub fn predecessors(&self) -> IlBlockPredecessors {
        IlBlockPredecessors::build(&self.blocks, &self.successors)
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
            block.operations().verify_bounds(usize::MAX)?;
            self.verify_successors(block, block_id)?;

            if !block.operations().is_empty() {
                operation_ranges.push((block.operations(), block_id));
            }

            for successor in block.successors().checked_slice(&self.successors)? {
                if successor.index() >= self.blocks.len() {
                    return Err(
                        IlError::range_out_of_bounds(successor.value(), self.blocks.len()).into(),
                    );
                }
            }
        }

        operation_ranges.sort_unstable_by_key(|(range, _)| range.start());
        let mut previous_operation_end = 0usize;
        for (operations, block_id) in operation_ranges {
            if operations.start() < previous_operation_end {
                return Err(StructureError::OverlappingBlockOperations {
                    block: block_id.value(),
                    operation: operations.start() as u32,
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
            block.operations().verify_bounds(node_count)?;
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IlBlockPredecessors {
    predecessors: IlCsr<IlBlockId>,
}

impl IlBlockPredecessors {
    pub(crate) fn build(blocks: &[IlBlock], successors: &[IlBlockId]) -> Self {
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
        self.predecessors.row(block.index())
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
        let index = IlBlockPredecessors::build(&blocks, &successors);

        assert_eq!(index.predecessors_for(block0), &[]);
        assert_eq!(index.predecessors_for(block1), &[block0]);
        assert_eq!(index.predecessors_for(block2), &[block0, block1]);
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
            Err(StructureError::OverlappingBlockOperations { .. })
        ));
    }
}
