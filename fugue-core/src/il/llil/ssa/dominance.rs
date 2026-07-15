use crate::il::common::{Block, BlockId, IlError, PredecessorIndex};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dominance {
    entry: Option<BlockId>,
    immediate_dominators: Vec<Option<BlockId>>,
    children_offsets: Vec<u32>,
    children: Vec<BlockId>,
    preorder: Vec<u32>,
    postorder: Vec<u32>,
    reachable: Vec<bool>,
}

impl Dominance {
    pub fn new(
        immediate_dominators: Vec<Option<BlockId>>,
        children_offsets: Vec<u32>,
        children: Vec<BlockId>,
        preorder: Vec<u32>,
        postorder: Vec<u32>,
    ) -> Self {
        let reachable = preorder
            .iter()
            .zip(&postorder)
            .map(|(preorder, postorder)| *preorder != u32::MAX && *postorder != u32::MAX)
            .collect();

        Self {
            entry: None,
            immediate_dominators,
            children_offsets,
            children,
            preorder,
            postorder,
            reachable,
        }
    }

    pub fn from_blocks(
        blocks: &[Block],
        successors: &[BlockId],
        entry: BlockId,
    ) -> Result<Self, IlError> {
        let builder = DominanceBuilder::new(blocks, successors, entry)?;

        builder.build()
    }

    pub fn immediate_dominator(&self, block: BlockId) -> Option<BlockId> {
        self.immediate_dominators
            .get(block.index())
            .copied()
            .flatten()
    }

    pub fn children(&self, block: BlockId) -> &[BlockId] {
        let Some(start) = self.children_offsets.get(block.index()).copied() else {
            return &[];
        };
        let end = self
            .children_offsets
            .get(block.index() + 1)
            .copied()
            .unwrap_or(start);

        &self.children[start as usize..end as usize]
    }

    pub fn is_reachable(&self, block: BlockId) -> bool {
        self.reachable.get(block.index()).copied().unwrap_or(false)
    }

    pub fn frontiers(
        &self,
        blocks: &[Block],
        successors: &[BlockId],
    ) -> Result<DominanceFrontier, IlError> {
        if blocks.len() != self.reachable.len() {
            return Err(IlError::range_out_of_bounds(
                u32::try_from(blocks.len()).unwrap_or(u32::MAX),
                self.reachable.len(),
            ));
        }

        for block in blocks {
            block.successors().verify_bounds(successors.len())?;

            for successor in block.successors().checked_slice(successors)? {
                if successor.index() >= blocks.len() {
                    return Err(IlError::range_out_of_bounds(
                        successor.value(),
                        blocks.len(),
                    ));
                }
            }
        }

        let mut frontiers = vec![Vec::new(); blocks.len()];

        for block in self.tree_postorder() {
            self.add_successor_frontiers(blocks, successors, block, &mut frontiers)?;
            self.add_child_frontiers(block, &mut frontiers);
        }

        DominanceFrontier::from_frontiers(frontiers)
    }

    pub fn dominates(&self, dominator: BlockId, block: BlockId) -> bool {
        if !self.is_reachable(dominator) || !self.is_reachable(block) {
            return false;
        }

        let Some(dominator_preorder) = self.preorder.get(dominator.index()).copied() else {
            return false;
        };
        let Some(dominator_postorder) = self.postorder.get(dominator.index()).copied() else {
            return false;
        };
        let Some(block_preorder) = self.preorder.get(block.index()).copied() else {
            return false;
        };
        let Some(block_postorder) = self.postorder.get(block.index()).copied() else {
            return false;
        };

        dominator_preorder <= block_preorder && block_postorder <= dominator_postorder
    }

    fn add_successor_frontiers(
        &self,
        blocks: &[Block],
        successors: &[BlockId],
        block: BlockId,
        frontiers: &mut [Vec<BlockId>],
    ) -> Result<(), IlError> {
        for successor in blocks[block.index()]
            .successors()
            .checked_slice(successors)?
        {
            if self.is_reachable(*successor) && self.immediate_dominator(*successor) != Some(block)
            {
                Self::push_frontier(frontiers, block, *successor);
            }
        }

        Ok(())
    }

    fn add_child_frontiers(&self, block: BlockId, frontiers: &mut [Vec<BlockId>]) {
        for child in self.children(block) {
            let child_frontiers = frontiers[child.index()].clone();

            for frontier in child_frontiers {
                if self.immediate_dominator(frontier) != Some(block) {
                    Self::push_frontier(frontiers, block, frontier);
                }
            }
        }
    }

    fn push_frontier(frontiers: &mut [Vec<BlockId>], block: BlockId, frontier: BlockId) {
        let block_frontiers = &mut frontiers[block.index()];

        if !block_frontiers.contains(&frontier) {
            block_frontiers.push(frontier);
        }
    }

    fn tree_postorder(&self) -> Vec<BlockId> {
        let mut order = Vec::new();

        let Some(entry) = self.entry else {
            return order;
        };
        let mut stack = vec![(entry, false)];

        while let Some((block, expanded)) = stack.pop() {
            if !self.is_reachable(block) {
                continue;
            }

            if expanded {
                order.push(block);
                continue;
            }

            stack.push((block, true));

            for child in self.children(block).iter().rev() {
                stack.push((*child, false));
            }
        }

        order
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DominanceFrontier {
    offsets: Vec<u32>,
    frontiers: Vec<BlockId>,
}

impl DominanceFrontier {
    pub fn new(offsets: Vec<u32>, frontiers: Vec<BlockId>) -> Self {
        Self { offsets, frontiers }
    }

    pub fn frontier(&self, block: BlockId) -> &[BlockId] {
        let Some(start) = self.offsets.get(block.index()).copied() else {
            return &[];
        };
        let end = self
            .offsets
            .get(block.index() + 1)
            .copied()
            .unwrap_or(start);

        &self.frontiers[start as usize..end as usize]
    }

    pub fn place_phis(
        &self,
        block_count: usize,
        definitions: impl IntoIterator<Item = BlockId>,
    ) -> Result<PhiPlacement, IlError> {
        if self.offsets.len() != block_count + 1 {
            return Err(IlError::range_out_of_bounds(
                u32::try_from(self.offsets.len()).unwrap_or(u32::MAX),
                block_count + 1,
            ));
        }

        let mut placed = vec![false; block_count];
        let mut queued = vec![false; block_count];
        let mut queue = Vec::new();
        let mut phis = Vec::new();

        for definition in definitions {
            if definition.index() >= block_count {
                return Err(IlError::range_out_of_bounds(
                    definition.value(),
                    block_count,
                ));
            }

            if !queued[definition.index()] {
                queued[definition.index()] = true;
                queue.push(definition);
            }
        }

        while let Some(block) = queue.pop() {
            for frontier in self.frontier(block) {
                if frontier.index() >= block_count {
                    return Err(IlError::range_out_of_bounds(frontier.value(), block_count));
                }

                if placed[frontier.index()] {
                    continue;
                }

                placed[frontier.index()] = true;
                phis.push(*frontier);

                if !queued[frontier.index()] {
                    queued[frontier.index()] = true;
                    queue.push(*frontier);
                }
            }
        }

        phis.sort();

        Ok(PhiPlacement::new(phis))
    }

    fn from_frontiers(frontiers: Vec<Vec<BlockId>>) -> Result<Self, IlError> {
        let mut offsets = Vec::with_capacity(frontiers.len() + 1);
        let mut values = Vec::new();
        let mut offset = 0u32;

        offsets.push(offset);

        for mut frontier in frontiers {
            frontier.sort();

            for block in frontier {
                values.push(block);
                offset = offset
                    .checked_add(1)
                    .ok_or(IlError::integer_overflow("dominance frontier offset"))?;
            }

            offsets.push(offset);
        }

        Ok(Self {
            offsets,
            frontiers: values,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhiPlacement {
    blocks: Vec<BlockId>,
}

impl PhiPlacement {
    pub fn new(blocks: Vec<BlockId>) -> Self {
        Self { blocks }
    }

    pub fn blocks(&self) -> &[BlockId] {
        &self.blocks
    }

    pub fn contains(&self, block: BlockId) -> bool {
        self.blocks.contains(&block)
    }
}

struct DominanceBuilder<'a> {
    blocks: &'a [Block],
    successors: &'a [BlockId],
    entry: BlockId,
    predecessors: PredecessorIndex,
    reachable: Vec<bool>,
    reverse_postorder: Vec<BlockId>,
    positions: Vec<u32>,
    immediate_dominators: Vec<Option<BlockId>>,
}

impl<'a> DominanceBuilder<'a> {
    fn new(
        blocks: &'a [Block],
        successors: &'a [BlockId],
        entry: BlockId,
    ) -> Result<Self, IlError> {
        if entry.index() >= blocks.len() {
            return Err(IlError::range_out_of_bounds(entry.value(), blocks.len()));
        }

        for block in blocks {
            block.successors().verify_bounds(successors.len())?;

            for successor in block.successors().checked_slice(successors)? {
                if successor.index() >= blocks.len() {
                    return Err(IlError::range_out_of_bounds(
                        successor.value(),
                        blocks.len(),
                    ));
                }
            }
        }

        let mut builder = Self {
            blocks,
            successors,
            entry,
            predecessors: PredecessorIndex::build(blocks, successors)?,
            reachable: vec![false; blocks.len()],
            reverse_postorder: Vec::new(),
            positions: vec![u32::MAX; blocks.len()],
            immediate_dominators: vec![None; blocks.len()],
        };

        builder.build_reverse_postorder()?;

        Ok(builder)
    }

    fn build(mut self) -> Result<Dominance, IlError> {
        self.solve_immediate_dominators();
        self.immediate_dominators[self.entry.index()] = None;

        let (children_offsets, children) = self.build_children()?;
        let (preorder, postorder) = self.build_intervals(&children_offsets, &children)?;

        Ok(Dominance {
            entry: Some(self.entry),
            immediate_dominators: self.immediate_dominators,
            children_offsets,
            children,
            preorder,
            postorder,
            reachable: self.reachable,
        })
    }

    fn build_reverse_postorder(&mut self) -> Result<(), IlError> {
        let mut visited = vec![false; self.blocks.len()];
        let mut stack = vec![(self.entry, false)];
        let mut postorder = Vec::new();

        while let Some((block, expanded)) = stack.pop() {
            if expanded {
                postorder.push(block);
                continue;
            }

            if visited[block.index()] {
                continue;
            }

            visited[block.index()] = true;
            self.reachable[block.index()] = true;
            stack.push((block, true));

            let successors = self.blocks[block.index()]
                .successors()
                .checked_slice(self.successors)?;

            for successor in successors.iter().rev() {
                if !visited[successor.index()] {
                    stack.push((*successor, false));
                }
            }
        }

        postorder.reverse();
        self.reverse_postorder = postorder;

        for (position, block) in self.reverse_postorder.iter().enumerate() {
            self.positions[block.index()] = u32::try_from(position)
                .map_err(|_| IlError::integer_overflow("dominance position"))?;
        }

        Ok(())
    }

    fn solve_immediate_dominators(&mut self) {
        self.immediate_dominators[self.entry.index()] = Some(self.entry);

        let mut changed = true;

        while changed {
            changed = false;

            for block in self.reverse_postorder.iter().copied().skip(1) {
                let mut predecessors = self.processed_predecessors(block);
                let Some(mut new_immediate_dominator) = predecessors.next() else {
                    continue;
                };

                for predecessor in predecessors {
                    new_immediate_dominator = self.intersect(predecessor, new_immediate_dominator);
                }

                if self.immediate_dominators[block.index()] != Some(new_immediate_dominator) {
                    self.immediate_dominators[block.index()] = Some(new_immediate_dominator);
                    changed = true;
                }
            }
        }
    }

    fn processed_predecessors(&self, block: BlockId) -> impl Iterator<Item = BlockId> + '_ {
        self.predecessors
            .predecessors(block)
            .iter()
            .copied()
            .filter(|predecessor| {
                self.reachable[predecessor.index()]
                    && self.immediate_dominators[predecessor.index()].is_some()
            })
    }

    fn intersect(&self, first: BlockId, second: BlockId) -> BlockId {
        let mut first = first;
        let mut second = second;

        while first != second {
            while self.positions[first.index()] > self.positions[second.index()] {
                first = self.immediate_dominators[first.index()].unwrap_or(self.entry);
            }

            while self.positions[second.index()] > self.positions[first.index()] {
                second = self.immediate_dominators[second.index()].unwrap_or(self.entry);
            }
        }

        first
    }

    fn build_children(&self) -> Result<(Vec<u32>, Vec<BlockId>), IlError> {
        let mut offsets = vec![0u32; self.blocks.len() + 1];

        for dominator in self.immediate_dominators.iter().flatten() {
            let index = dominator.index() + 1;
            offsets[index] = offsets[index]
                .checked_add(1)
                .ok_or(IlError::integer_overflow("dominator tree child count"))?;
        }

        for index in 1..offsets.len() {
            offsets[index] = offsets[index]
                .checked_add(offsets[index - 1])
                .ok_or(IlError::integer_overflow("dominator tree child offset"))?;
        }

        let mut cursor = offsets.clone();
        let mut children =
            vec![BlockId::try_from_index(0)?; *offsets.last().unwrap_or(&0) as usize];

        for (block_index, dominator) in self.immediate_dominators.iter().enumerate() {
            let Some(dominator) = dominator else {
                continue;
            };
            let block = BlockId::try_from_index(block_index)?;
            let cursor_index = dominator.index();
            let index = cursor[cursor_index] as usize;

            children[index] = block;
            cursor[cursor_index] += 1;
        }

        Ok((offsets, children))
    }

    fn build_intervals(
        &self,
        children_offsets: &[u32],
        children: &[BlockId],
    ) -> Result<(Vec<u32>, Vec<u32>), IlError> {
        let mut preorder = vec![u32::MAX; self.blocks.len()];
        let mut postorder = vec![u32::MAX; self.blocks.len()];
        let mut next = 0u32;
        let mut stack = vec![(self.entry, false)];

        while let Some((block, expanded)) = stack.pop() {
            if !self.reachable[block.index()] {
                continue;
            }

            if expanded {
                postorder[block.index()] = next;
                next = next
                    .checked_add(1)
                    .ok_or(IlError::integer_overflow("dominance postorder"))?;
                continue;
            }

            preorder[block.index()] = next;
            next = next
                .checked_add(1)
                .ok_or(IlError::integer_overflow("dominance preorder"))?;
            stack.push((block, true));

            let start = children_offsets[block.index()] as usize;
            let end = children_offsets[block.index() + 1] as usize;

            for child in children[start..end].iter().rev() {
                stack.push((*child, false));
            }
        }

        Ok((preorder, postorder))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::common::PackedRange;

    #[test]
    fn dominance_builds_linear_tree() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[1], &[2], &[]])?;
        let dominance = Dominance::from_blocks(&blocks, &successors, block_id(0)?)?;

        assert_eq!(
            dominance.immediate_dominator(block_id(1)?),
            Some(block_id(0)?)
        );
        assert_eq!(
            dominance.immediate_dominator(block_id(2)?),
            Some(block_id(1)?)
        );
        assert!(dominance.dominates(block_id(0)?, block_id(2)?));
        assert!(dominance.dominates(block_id(1)?, block_id(2)?));
        assert!(!dominance.dominates(block_id(2)?, block_id(1)?));
        assert_eq!(dominance.children(block_id(0)?), &[block_id(1)?]);

        Ok(())
    }

    #[test]
    fn dominance_builds_diamond_tree() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[1, 2], &[3], &[3], &[]])?;
        let dominance = Dominance::from_blocks(&blocks, &successors, block_id(0)?)?;

        assert_eq!(
            dominance.immediate_dominator(block_id(1)?),
            Some(block_id(0)?)
        );
        assert_eq!(
            dominance.immediate_dominator(block_id(2)?),
            Some(block_id(0)?)
        );
        assert_eq!(
            dominance.immediate_dominator(block_id(3)?),
            Some(block_id(0)?)
        );
        assert!(dominance.dominates(block_id(0)?, block_id(3)?));
        assert!(!dominance.dominates(block_id(1)?, block_id(3)?));
        assert!(!dominance.dominates(block_id(2)?, block_id(3)?));

        Ok(())
    }

    #[test]
    fn dominance_frontier_marks_diamond_join() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[1, 2], &[3], &[3], &[]])?;
        let dominance = Dominance::from_blocks(&blocks, &successors, block_id(0)?)?;
        let frontiers = dominance.frontiers(&blocks, &successors)?;

        assert_eq!(frontiers.frontier(block_id(0)?), &[]);
        assert_eq!(frontiers.frontier(block_id(1)?), &[block_id(3)?]);
        assert_eq!(frontiers.frontier(block_id(2)?), &[block_id(3)?]);
        assert_eq!(frontiers.frontier(block_id(3)?), &[]);

        Ok(())
    }

    #[test]
    fn phi_placement_places_diamond_join() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[1, 2], &[3], &[3], &[]])?;
        let dominance = Dominance::from_blocks(&blocks, &successors, block_id(0)?)?;
        let frontiers = dominance.frontiers(&blocks, &successors)?;
        let placement = frontiers.place_phis(blocks.len(), [block_id(1)?, block_id(2)?])?;

        assert_eq!(placement.blocks(), &[block_id(3)?]);
        assert!(placement.contains(block_id(3)?));

        Ok(())
    }

    #[test]
    fn dominance_handles_loop_back_edge() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[1], &[2], &[1, 3], &[]])?;
        let dominance = Dominance::from_blocks(&blocks, &successors, block_id(0)?)?;

        assert_eq!(
            dominance.immediate_dominator(block_id(1)?),
            Some(block_id(0)?)
        );
        assert_eq!(
            dominance.immediate_dominator(block_id(2)?),
            Some(block_id(1)?)
        );
        assert_eq!(
            dominance.immediate_dominator(block_id(3)?),
            Some(block_id(2)?)
        );
        assert!(dominance.dominates(block_id(1)?, block_id(3)?));
        assert!(!dominance.dominates(block_id(2)?, block_id(1)?));

        Ok(())
    }

    #[test]
    fn phi_placement_iterates_from_new_phi_blocks() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[1, 2], &[3], &[3], &[4, 5], &[6], &[6], &[]])?;
        let dominance = Dominance::from_blocks(&blocks, &successors, block_id(0)?)?;
        let frontiers = dominance.frontiers(&blocks, &successors)?;
        let placement =
            frontiers.place_phis(blocks.len(), [block_id(1)?, block_id(2)?, block_id(4)?])?;

        assert_eq!(placement.blocks(), &[block_id(3)?, block_id(6)?]);

        Ok(())
    }

    #[test]
    fn dominance_frontier_marks_loop_header() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[1], &[2], &[1, 3], &[]])?;
        let dominance = Dominance::from_blocks(&blocks, &successors, block_id(0)?)?;
        let frontiers = dominance.frontiers(&blocks, &successors)?;

        assert_eq!(frontiers.frontier(block_id(0)?), &[]);
        assert_eq!(frontiers.frontier(block_id(1)?), &[block_id(1)?]);
        assert_eq!(frontiers.frontier(block_id(2)?), &[block_id(1)?]);
        assert_eq!(frontiers.frontier(block_id(3)?), &[]);

        Ok(())
    }

    #[test]
    fn phi_placement_rejects_out_of_range_definition() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[1], &[]])?;
        let dominance = Dominance::from_blocks(&blocks, &successors, block_id(0)?)?;
        let frontiers = dominance.frontiers(&blocks, &successors)?;

        assert!(matches!(
            frontiers.place_phis(blocks.len(), [block_id(2)?]),
            Err(IlError::RangeOutOfBounds { .. })
        ));

        Ok(())
    }

    #[test]
    fn dominance_ignores_unreachable_blocks() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[1], &[], &[3], &[]])?;
        let dominance = Dominance::from_blocks(&blocks, &successors, block_id(0)?)?;

        assert!(dominance.is_reachable(block_id(1)?));
        assert!(!dominance.is_reachable(block_id(2)?));
        assert!(!dominance.is_reachable(block_id(3)?));
        assert_eq!(dominance.immediate_dominator(block_id(2)?), None);
        assert!(!dominance.dominates(block_id(2)?, block_id(3)?));

        Ok(())
    }

    #[test]
    fn dominance_frontier_uses_non_zero_entry() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[], &[2], &[]])?;
        let dominance = Dominance::from_blocks(&blocks, &successors, block_id(1)?)?;
        let frontiers = dominance.frontiers(&blocks, &successors)?;

        assert!(!dominance.is_reachable(block_id(0)?));
        assert!(dominance.is_reachable(block_id(2)?));
        assert_eq!(frontiers.frontier(block_id(1)?), &[]);
        assert_eq!(frontiers.frontier(block_id(2)?), &[]);

        Ok(())
    }

    #[test]
    fn dominance_rejects_out_of_range_successor() -> Result<(), IlError> {
        let blocks = vec![Block::new(PackedRange::EMPTY, PackedRange::new(0, 1)?, 0)];
        let successors = vec![block_id(1)?];

        assert!(matches!(
            Dominance::from_blocks(&blocks, &successors, block_id(0)?),
            Err(IlError::RangeOutOfBounds { .. })
        ));

        Ok(())
    }

    #[test]
    fn dominance_matches_slow_oracle_for_generated_graphs() -> Result<(), IlError> {
        let mut generator = GraphGenerator::new(0x5eed);

        for node_count in 1..9 {
            for _ in 0..64 {
                let edges = generator.edges(node_count);
                let (blocks, successors) = graph_from_edges(&edges)?;
                let dominance = Dominance::from_blocks(&blocks, &successors, block_id(0)?)?;
                let oracle = SlowDominance::new(&blocks, &successors, block_id(0)?)?;

                for dominator in 0..node_count {
                    for block in 0..node_count {
                        assert_eq!(
                            dominance.dominates(block_id(dominator)?, block_id(block)?),
                            oracle.dominates(dominator, block)
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn graph(edges: &[&[usize]]) -> Result<(Vec<Block>, Vec<BlockId>), IlError> {
        let edges = edges.iter().map(|edge| edge.to_vec()).collect::<Vec<_>>();

        graph_from_edges(&edges)
    }

    fn graph_from_edges(edges: &[Vec<usize>]) -> Result<(Vec<Block>, Vec<BlockId>), IlError> {
        let mut blocks = Vec::new();
        let mut successors = Vec::new();

        for edge in edges {
            let start = successors.len();

            for successor in edge {
                successors.push(block_id(*successor)?);
            }

            blocks.push(Block::new(
                PackedRange::EMPTY,
                PackedRange::new(start, successors.len())?,
                0,
            ));
        }

        Ok((blocks, successors))
    }

    fn block_id(index: usize) -> Result<BlockId, IlError> {
        BlockId::try_from_index(index)
    }

    struct GraphGenerator {
        state: u64,
    }

    impl GraphGenerator {
        const fn new(seed: u64) -> Self {
            Self { state: seed }
        }

        fn edges(&mut self, node_count: usize) -> Vec<Vec<usize>> {
            let mut edges = vec![Vec::new(); node_count];

            for (block, block_edges) in edges.iter_mut().enumerate().take(node_count) {
                if block + 1 < node_count && !self.next().is_multiple_of(4) {
                    block_edges.push(block + 1);
                }

                for successor in 0..node_count {
                    if block == successor {
                        if self.next().is_multiple_of(16) {
                            block_edges.push(successor);
                        }
                    } else if self.next().is_multiple_of(9) {
                        block_edges.push(successor);
                    }
                }

                block_edges.sort_unstable();
                block_edges.dedup();
            }

            edges
        }

        fn next(&mut self) -> u64 {
            self.state = self
                .state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);

            self.state
        }
    }

    struct SlowDominance {
        reachable: Vec<bool>,
        sets: Vec<Vec<bool>>,
    }

    impl SlowDominance {
        fn new(blocks: &[Block], successors: &[BlockId], entry: BlockId) -> Result<Self, IlError> {
            let reachable = Self::reachable(blocks, successors, entry)?;
            let predecessors = Self::predecessors(blocks, successors)?;
            let mut sets = vec![vec![false; blocks.len()]; blocks.len()];

            for block in 0..blocks.len() {
                if !reachable[block] {
                    continue;
                }

                if block == entry.index() {
                    sets[block][block] = true;
                } else {
                    sets[block][..blocks.len()].copy_from_slice(&reachable[..blocks.len()]);
                }
            }

            let mut changed = true;

            while changed {
                changed = false;

                for block in 0..blocks.len() {
                    if !reachable[block] || block == entry.index() {
                        continue;
                    }

                    let mut next = vec![true; blocks.len()];
                    let mut saw_predecessor = false;

                    for predecessor in &predecessors[block] {
                        if !reachable[*predecessor] {
                            continue;
                        }

                        saw_predecessor = true;

                        for (dominator, value) in next.iter_mut().enumerate() {
                            *value &= sets[*predecessor][dominator];
                        }
                    }

                    if !saw_predecessor {
                        next.fill(false);
                    }

                    next[block] = true;

                    if sets[block] != next {
                        sets[block] = next;
                        changed = true;
                    }
                }
            }

            Ok(Self { reachable, sets })
        }

        fn dominates(&self, dominator: usize, block: usize) -> bool {
            self.reachable.get(block).copied().unwrap_or(false)
                && self
                    .sets
                    .get(block)
                    .and_then(|set| set.get(dominator))
                    .copied()
                    .unwrap_or(false)
        }

        fn reachable(
            blocks: &[Block],
            successors: &[BlockId],
            entry: BlockId,
        ) -> Result<Vec<bool>, IlError> {
            let mut reachable = vec![false; blocks.len()];
            let mut stack = vec![entry];

            while let Some(block) = stack.pop() {
                if reachable[block.index()] {
                    continue;
                }

                reachable[block.index()] = true;

                for successor in blocks[block.index()]
                    .successors()
                    .checked_slice(successors)?
                {
                    if !reachable[successor.index()] {
                        stack.push(*successor);
                    }
                }
            }

            Ok(reachable)
        }

        fn predecessors(
            blocks: &[Block],
            successors: &[BlockId],
        ) -> Result<Vec<Vec<usize>>, IlError> {
            let mut predecessors = vec![Vec::new(); blocks.len()];

            for (block_index, block) in blocks.iter().enumerate() {
                for successor in block.successors().checked_slice(successors)? {
                    predecessors[successor.index()].push(block_index);
                }
            }

            Ok(predecessors)
        }
    }
}
