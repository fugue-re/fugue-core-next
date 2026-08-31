use std::iter::Copied;
use std::slice::Iter;
use std::vec::IntoIter;

use crate::il::common::{
    ControlFlowIl, IlAnalysis, IlBlock, IlBlockId, IlBlockPredecessors, IlCsr, IlError,
};

fn push_frontier(frontiers: &mut [Vec<IlBlockId>], block: IlBlockId, frontier: IlBlockId) {
    let block_frontiers = &mut frontiers[block.index()];

    if !block_frontiers.contains(&frontier) {
        block_frontiers.push(frontier);
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IlDominance {
    entry: Option<IlBlockId>,
    immediate_dominators: Vec<Option<IlBlockId>>,
    children: IlCsr<IlBlockId>,
    preorder: Vec<u32>,
    postorder: Vec<u32>,
    reachable: Vec<bool>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IlDominanceEvent {
    Enter(IlBlockId),
    Exit(IlBlockId),
}

pub struct IlDominanceEvents<'a> {
    dominance: &'a IlDominance,
    pending: Vec<IlDominanceEvent>,
}

impl Iterator for IlDominanceEvents<'_> {
    type Item = IlDominanceEvent;

    fn next(&mut self) -> Option<Self::Item> {
        let event = self.pending.pop()?;
        if let IlDominanceEvent::Enter(block) = event {
            self.pending.push(IlDominanceEvent::Exit(block));
            self.pending.extend(
                self.dominance
                    .children_for(block)
                    .iter()
                    .rev()
                    .copied()
                    .map(IlDominanceEvent::Enter),
            );
        }
        Some(event)
    }
}

impl IlDominance {
    pub fn from_blocks(blocks: &[IlBlock], successors: &[IlBlockId], entry: IlBlockId) -> Self {
        DominanceSolver::new(blocks, successors, entry).solve()
    }

    pub fn immediate_dominator(&self, block: IlBlockId) -> Option<IlBlockId> {
        self.immediate_dominators
            .get(block.index())
            .copied()
            .flatten()
    }

    pub fn children_for(&self, block: IlBlockId) -> &[IlBlockId] {
        self.children.checked_row(block.index()).unwrap_or_default()
    }

    pub fn is_reachable(&self, block: IlBlockId) -> bool {
        self.reachable.get(block.index()).copied().unwrap_or(false)
    }

    pub fn events_from(&self, root: IlBlockId) -> IlDominanceEvents<'_> {
        let pending = if self.is_reachable(root) {
            vec![IlDominanceEvent::Enter(root)]
        } else {
            Vec::new()
        };
        IlDominanceEvents {
            dominance: self,
            pending,
        }
    }

    pub fn frontiers(&self, blocks: &[IlBlock], successors: &[IlBlockId]) -> IlDominanceFrontier {
        let mut frontiers = vec![Vec::new(); blocks.len()];

        for block in self.tree_postorder() {
            self.add_successor_frontiers(blocks, successors, block, &mut frontiers);
            self.add_child_frontiers(block, &mut frontiers);
        }

        IlDominanceFrontier::from_frontiers(frontiers)
    }

    pub fn dominates(&self, dominator: IlBlockId, block: IlBlockId) -> bool {
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
        blocks: &[IlBlock],
        successors: &[IlBlockId],
        block: IlBlockId,
        frontiers: &mut [Vec<IlBlockId>],
    ) {
        for successor in blocks[block.index()].successors().slice(successors) {
            if self.is_reachable(*successor) && self.immediate_dominator(*successor) != Some(block)
            {
                push_frontier(frontiers, block, *successor);
            }
        }
    }

    fn add_child_frontiers(&self, block: IlBlockId, frontiers: &mut [Vec<IlBlockId>]) {
        for child in self.children_for(block) {
            for index in 0..frontiers[child.index()].len() {
                let frontier = frontiers[child.index()][index];
                if self.immediate_dominator(frontier) != Some(block) {
                    push_frontier(frontiers, block, frontier);
                }
            }
        }
    }

    fn tree_postorder(&self) -> Vec<IlBlockId> {
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

            for child in self.children_for(block).iter().rev() {
                stack.push((*child, false));
            }
        }

        order
    }
}

impl<I: ControlFlowIl> IlAnalysis<I> for IlDominance {
    fn analyse(ir: &I) -> Self {
        let Some(entry) = ir.graph().entry_block() else {
            return Self::default();
        };

        Self::from_blocks(ir.graph().blocks(), ir.graph().successors(), entry)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IlDominanceFrontier {
    frontiers: IlCsr<IlBlockId>,
}

impl IlDominanceFrontier {
    fn from_frontiers(mut frontiers: Vec<Vec<IlBlockId>>) -> Self {
        for frontier in &mut frontiers {
            frontier.sort();
        }

        Self {
            frontiers: IlCsr::from_rows(frontiers),
        }
    }

    pub fn frontier_for(&self, block: IlBlockId) -> &[IlBlockId] {
        self.frontiers
            .checked_row(block.index())
            .unwrap_or_default()
    }

    pub fn place_phis(
        &self,
        block_count: usize,
        definitions: impl IntoIterator<Item = IlBlockId>,
    ) -> Result<IlPhiPlacement, IlError> {
        let mut placed = vec![false; block_count];
        let mut queued = vec![false; block_count];
        let mut queue = Vec::new();
        let mut phis = Vec::new();

        for definition in definitions {
            if definition.index() >= block_count {
                return Err(IlError::range_out_of_bounds(
                    definition.index(),
                    block_count,
                ));
            }
            if !queued[definition.index()] {
                queued[definition.index()] = true;
                queue.push(definition);
            }
        }

        while let Some(block) = queue.pop() {
            for frontier in self.frontier_for(block) {
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

        Ok(IlPhiPlacement::new(phis))
    }
}

impl<I: ControlFlowIl> IlAnalysis<I> for IlDominanceFrontier {
    fn analyse(ir: &I) -> Self {
        ir.analyse::<IlDominance>()
            .frontiers(ir.graph().blocks(), ir.graph().successors())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IlPhiPlacement {
    blocks: Vec<IlBlockId>,
}

impl IlPhiPlacement {
    fn new(blocks: Vec<IlBlockId>) -> Self {
        Self { blocks }
    }

    pub fn blocks(&self) -> &[IlBlockId] {
        &self.blocks
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = IlBlockId> + '_ {
        self.blocks.iter().copied()
    }
}

impl IntoIterator for IlPhiPlacement {
    type Item = IlBlockId;
    type IntoIter = IntoIter<IlBlockId>;

    fn into_iter(self) -> Self::IntoIter {
        self.blocks.into_iter()
    }
}

impl<'a> IntoIterator for &'a IlPhiPlacement {
    type Item = IlBlockId;
    type IntoIter = Copied<Iter<'a, IlBlockId>>;

    fn into_iter(self) -> Self::IntoIter {
        self.blocks.iter().copied()
    }
}

struct DominanceSolver<'a> {
    blocks: &'a [IlBlock],
    successors: &'a [IlBlockId],
    entry: IlBlockId,
    predecessors: IlBlockPredecessors,
    reachable: Vec<bool>,
    reverse_postorder: Vec<IlBlockId>,
    positions: Vec<u32>,
    immediate_dominators: Vec<Option<IlBlockId>>,
}

impl<'a> DominanceSolver<'a> {
    fn new(blocks: &'a [IlBlock], successors: &'a [IlBlockId], entry: IlBlockId) -> Self {
        let mut builder = Self {
            blocks,
            successors,
            entry,
            predecessors: IlBlockPredecessors::new(blocks, successors),
            reachable: vec![false; blocks.len()],
            reverse_postorder: Vec::new(),
            positions: vec![u32::MAX; blocks.len()],
            immediate_dominators: vec![None; blocks.len()],
        };

        builder.compute_reverse_postorder();

        builder
    }

    fn processed_predecessors(&self, block: IlBlockId) -> impl Iterator<Item = IlBlockId> + '_ {
        self.predecessors
            .predecessors_for(block)
            .iter()
            .copied()
            .filter(|predecessor| {
                self.reachable[predecessor.index()]
                    && self.immediate_dominators[predecessor.index()].is_some()
            })
    }

    fn solve(mut self) -> IlDominance {
        self.solve_immediate_dominators();
        self.immediate_dominators[self.entry.index()] = None;

        let children = self.compute_children();
        let (preorder, postorder) = self.compute_intervals(&children);

        IlDominance {
            entry: Some(self.entry),
            immediate_dominators: self.immediate_dominators,
            children,
            preorder,
            postorder,
            reachable: self.reachable,
        }
    }

    fn compute_reverse_postorder(&mut self) {
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
                .slice(self.successors);

            for successor in successors.iter().rev() {
                if !visited[successor.index()] {
                    stack.push((*successor, false));
                }
            }
        }

        postorder.reverse();
        self.reverse_postorder = postorder;

        for (position, block) in self.reverse_postorder.iter().enumerate() {
            self.positions[block.index()] = position as u32;
        }
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

    fn intersect(&self, first: IlBlockId, second: IlBlockId) -> IlBlockId {
        let mut first = first;
        let mut second = second;

        while first != second {
            while self.positions[first.index()] > self.positions[second.index()] {
                first = self.immediate_dominators[first.index()]
                    .expect("processed block has an immediate dominator");
            }

            while self.positions[second.index()] > self.positions[first.index()] {
                second = self.immediate_dominators[second.index()]
                    .expect("processed block has an immediate dominator");
            }
        }

        first
    }

    fn compute_children(&self) -> IlCsr<IlBlockId> {
        let entries =
            self.immediate_dominators
                .iter()
                .enumerate()
                .filter_map(|(block_index, dominator)| {
                    let dominator = dominator.as_ref()?;
                    let block = IlBlockId::try_from_index(block_index)
                        .expect("block count fits the block id space");
                    Some((dominator.index(), block))
                });

        IlCsr::from_entries(self.blocks.len(), entries)
    }

    fn compute_intervals(&self, children: &IlCsr<IlBlockId>) -> (Vec<u32>, Vec<u32>) {
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
                next += 1;
                continue;
            }

            preorder[block.index()] = next;
            next += 1;
            stack.push((block, true));

            for child in children.row(block.index()).iter().rev() {
                stack.push((*child, false));
            }
        }

        (preorder, postorder)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::{IlBlockProperties, IlError, IlIndexRange};

    #[test]
    fn dominance_builds_linear_tree() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[1], &[2], &[]])?;
        let dominance = IlDominance::from_blocks(&blocks, &successors, block_id(0)?);

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
        assert_eq!(dominance.children_for(block_id(0)?), &[block_id(1)?]);

        Ok(())
    }

    #[test]
    fn dominance_builds_diamond_tree() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[1, 2], &[3], &[3], &[]])?;
        let dominance = IlDominance::from_blocks(&blocks, &successors, block_id(0)?);

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
    fn dominance_events_enter_and_exit_each_subtree() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[1, 2], &[3], &[3], &[]])?;
        let dominance = IlDominance::from_blocks(&blocks, &successors, block_id(0)?);

        assert_eq!(
            dominance.events_from(block_id(0)?).collect::<Vec<_>>(),
            vec![
                IlDominanceEvent::Enter(block_id(0)?),
                IlDominanceEvent::Enter(block_id(1)?),
                IlDominanceEvent::Exit(block_id(1)?),
                IlDominanceEvent::Enter(block_id(2)?),
                IlDominanceEvent::Exit(block_id(2)?),
                IlDominanceEvent::Enter(block_id(3)?),
                IlDominanceEvent::Exit(block_id(3)?),
                IlDominanceEvent::Exit(block_id(0)?),
            ]
        );

        Ok(())
    }

    #[test]
    fn dominance_frontier_marks_diamond_join() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[1, 2], &[3], &[3], &[]])?;
        let dominance = IlDominance::from_blocks(&blocks, &successors, block_id(0)?);
        let frontiers = dominance.frontiers(&blocks, &successors);

        assert_eq!(frontiers.frontier_for(block_id(0)?), &[]);
        assert_eq!(frontiers.frontier_for(block_id(1)?), &[block_id(3)?]);
        assert_eq!(frontiers.frontier_for(block_id(2)?), &[block_id(3)?]);
        assert_eq!(frontiers.frontier_for(block_id(3)?), &[]);

        Ok(())
    }

    #[test]
    fn phi_placement_places_diamond_join() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[1, 2], &[3], &[3], &[]])?;
        let dominance = IlDominance::from_blocks(&blocks, &successors, block_id(0)?);
        let frontiers = dominance.frontiers(&blocks, &successors);
        let placement = frontiers.place_phis(blocks.len(), [block_id(1)?, block_id(2)?])?;

        assert_eq!(placement.blocks(), &[block_id(3)?]);
        assert!(placement.blocks().contains(&block_id(3)?));

        Ok(())
    }

    #[test]
    fn dominance_handles_loop_back_edge() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[1], &[2], &[1, 3], &[]])?;
        let dominance = IlDominance::from_blocks(&blocks, &successors, block_id(0)?);

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
        let dominance = IlDominance::from_blocks(&blocks, &successors, block_id(0)?);
        let frontiers = dominance.frontiers(&blocks, &successors);
        let placement =
            frontiers.place_phis(blocks.len(), [block_id(1)?, block_id(2)?, block_id(4)?])?;

        assert_eq!(placement.blocks(), &[block_id(3)?, block_id(6)?]);

        Ok(())
    }

    #[test]
    fn dominance_frontier_marks_loop_header() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[1], &[2], &[1, 3], &[]])?;
        let dominance = IlDominance::from_blocks(&blocks, &successors, block_id(0)?);
        let frontiers = dominance.frontiers(&blocks, &successors);

        assert_eq!(frontiers.frontier_for(block_id(0)?), &[]);
        assert_eq!(frontiers.frontier_for(block_id(1)?), &[block_id(1)?]);
        assert_eq!(frontiers.frontier_for(block_id(2)?), &[block_id(1)?]);
        assert_eq!(frontiers.frontier_for(block_id(3)?), &[]);

        Ok(())
    }

    #[test]
    fn dominance_ignores_unreachable_blocks() -> Result<(), IlError> {
        let (blocks, successors) = graph(&[&[1], &[], &[3], &[]])?;
        let dominance = IlDominance::from_blocks(&blocks, &successors, block_id(0)?);

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
        let dominance = IlDominance::from_blocks(&blocks, &successors, block_id(1)?);
        let frontiers = dominance.frontiers(&blocks, &successors);

        assert!(!dominance.is_reachable(block_id(0)?));
        assert!(dominance.is_reachable(block_id(2)?));
        assert_eq!(frontiers.frontier_for(block_id(1)?), &[]);
        assert_eq!(frontiers.frontier_for(block_id(2)?), &[]);

        Ok(())
    }

    #[test]
    fn dominance_matches_slow_oracle_for_generated_graphs() -> Result<(), IlError> {
        let mut generator = GraphGenerator::new(0x5eed);

        for node_count in 1..9 {
            for _ in 0..64 {
                let edges = generator.edges(node_count);
                let (blocks, successors) = graph_from_edges(&edges)?;
                let dominance = IlDominance::from_blocks(&blocks, &successors, block_id(0)?);
                let oracle = SlowDominance::new(&blocks, &successors, block_id(0)?);

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

    fn graph(edges: &[&[usize]]) -> Result<(Vec<IlBlock>, Vec<IlBlockId>), IlError> {
        let edges = edges.iter().map(|edge| edge.to_vec()).collect::<Vec<_>>();

        graph_from_edges(&edges)
    }

    fn graph_from_edges(edges: &[Vec<usize>]) -> Result<(Vec<IlBlock>, Vec<IlBlockId>), IlError> {
        let mut blocks = Vec::new();
        let mut successors = Vec::new();

        for edge in edges {
            let start = successors.len();

            for successor in edge {
                successors.push(block_id(*successor)?);
            }

            blocks.push(IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::new(start, successors.len())?,
                IlBlockProperties::empty(),
            ));
        }

        Ok((blocks, successors))
    }

    fn block_id(index: usize) -> Result<IlBlockId, IlError> {
        IlBlockId::try_from_index(index)
    }

    struct GraphGenerator {
        state: u64,
    }

    impl GraphGenerator {
        const fn new(state: u64) -> Self {
            Self { state }
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
        fn new(blocks: &[IlBlock], successors: &[IlBlockId], entry: IlBlockId) -> Self {
            let reachable = Self::reachable(blocks, successors, entry);
            let predecessors = Self::predecessors(blocks, successors);
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

            Self { reachable, sets }
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

        fn reachable(blocks: &[IlBlock], successors: &[IlBlockId], entry: IlBlockId) -> Vec<bool> {
            let mut reachable = vec![false; blocks.len()];
            let mut stack = vec![entry];

            while let Some(block) = stack.pop() {
                if reachable[block.index()] {
                    continue;
                }

                reachable[block.index()] = true;

                for successor in blocks[block.index()].successors().slice(successors) {
                    if !reachable[successor.index()] {
                        stack.push(*successor);
                    }
                }
            }

            reachable
        }

        fn predecessors(blocks: &[IlBlock], successors: &[IlBlockId]) -> Vec<Vec<usize>> {
            let mut predecessors = vec![Vec::new(); blocks.len()];

            for (block_index, block) in blocks.iter().enumerate() {
                for successor in block.successors().slice(successors) {
                    predecessors[successor.index()].push(block_index);
                }
            }

            predecessors
        }
    }
}
