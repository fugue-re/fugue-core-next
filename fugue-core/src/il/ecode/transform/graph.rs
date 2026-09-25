use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::il::common::{
    IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlError, IlGraph, IlIndexMapper,
    IlIndexRange, IlSourceSpan,
};
use crate::il::pcode::{PCodeIr, PCodeOp, PCodeOpcode};
use crate::ir::Address;

#[derive(Debug, Default)]
struct BlockSuccessors {
    targets: SmallVec<[IlBlockId; 2]>,
    kinds: SmallVec<[IlEdgeKinds; 2]>,
}

impl BlockSuccessors {
    fn from_partition(
        mapper: &PCodeToECodeGraphMapper,
        source: &PCodeIr,
        source_block: &IlBlock,
        ranges: &[IlIndexRange],
        range_index: usize,
        first_block: IlBlockId,
        first_blocks: &[IlBlockId],
    ) -> Self {
        let range = ranges[range_index];
        let next = (range_index + 1 < ranges.len()).then(|| {
            IlBlockId::try_from_index(first_block.index() + range_index + 1)
                .expect("refined block id was validated while partitioning")
        });
        let original_successors = source_block.successors().slice(source.graph().successors());
        let original_kinds = source_block
            .successors()
            .slice(source.graph().successor_kinds());
        let terminal = range
            .end()
            .checked_sub(1)
            .filter(|index| *index >= range.start())
            .and_then(|index| source.ops().get(index).map(|operation| (index, operation)));

        let mut successors = Self::default();
        match terminal {
            Some((operation_index, operation))
                if matches!(
                    operation.opcode(),
                    PCodeOpcode::Branch | PCodeOpcode::CBranch
                ) =>
            {
                let conditional = operation.opcode() == PCodeOpcode::CBranch;
                let permitted = match (conditional, next) {
                    (false, _) => IlEdgeKinds::UNCONDITIONAL,
                    (true, Some(_)) => IlEdgeKinds::TAKEN,
                    (true, None) => IlEdgeKinds::TAKEN | IlEdgeKinds::FALL_THROUGH,
                };
                let taken_arm = mapper
                    .internal_target(source, source_block.ops(), operation_index, operation)
                    .and_then(|target| refined_target(first_block, ranges, target))
                    .or_else(|| {
                        external_target(source, operation, original_successors, first_blocks)
                    });

                match taken_arm {
                    Some(target) => {
                        let kind = if conditional {
                            IlEdgeKinds::TAKEN
                        } else {
                            IlEdgeKinds::UNCONDITIONAL
                        };
                        successors.push(target, kind);
                    }
                    None => successors.extend_mapped_within(
                        original_successors,
                        original_kinds,
                        first_blocks,
                        permitted,
                    ),
                }
                if conditional {
                    match next {
                        Some(next) => successors.push(next, IlEdgeKinds::FALL_THROUGH),
                        None => successors.extend_mapped_within(
                            original_successors,
                            original_kinds,
                            first_blocks,
                            permitted,
                        ),
                    }
                }
            }
            Some((_, operation)) if operation.opcode() == PCodeOpcode::IBranch => {
                successors.extend_mapped_within(
                    original_successors,
                    original_kinds,
                    first_blocks,
                    IlEdgeKinds::COMPUTED,
                );
            }
            Some((_, operation)) if operation.opcode() == PCodeOpcode::Return => {}
            _ => match next {
                Some(next) => successors.push(next, IlEdgeKinds::FALL_THROUGH),
                None => successors.extend_mapped_within(
                    original_successors,
                    original_kinds,
                    first_blocks,
                    IlEdgeKinds::FALL_THROUGH | IlEdgeKinds::UNCONDITIONAL,
                ),
            },
        }

        successors
    }

    fn extend_mapped_within(
        &mut self,
        additions: &[IlBlockId],
        addition_kinds: &[IlEdgeKinds],
        first_blocks: &[IlBlockId],
        permitted: IlEdgeKinds,
    ) {
        for (successor, kind) in additions.iter().zip(addition_kinds) {
            let narrowed = *kind & permitted;
            let kind = if narrowed.is_empty() {
                permitted
            } else {
                narrowed
            };
            self.push(first_blocks[successor.index()], kind);
        }
    }

    fn push(&mut self, target: IlBlockId, kind: IlEdgeKinds) {
        match self.targets.iter().position(|entry| *entry == target) {
            Some(index) => self.kinds[index] |= kind,
            None => {
                self.targets.push(target);
                self.kinds.push(kind);
            }
        }
    }
}

fn external_target(
    source: &PCodeIr,
    operation: &PCodeOp,
    successors: &[IlBlockId],
    first_blocks: &[IlBlockId],
) -> Option<IlBlockId> {
    let address = source.target(operation.target()?)?.address();
    let sources = source.graph().block_sources();
    let mut resolved = successors
        .iter()
        .filter(|successor| sources.get(successor.index()).copied() == Some(address));
    let target = resolved.next()?;
    resolved
        .next()
        .is_none()
        .then(|| first_blocks[target.index()])
}

fn refined_target(
    first: IlBlockId,
    ranges: &[IlIndexRange],
    operation: usize,
) -> Option<IlBlockId> {
    let offset = ranges
        .binary_search_by_key(&operation, IlIndexRange::start)
        .ok()?;
    IlBlockId::try_from_index(first.index() + offset).ok()
}

#[derive(Debug, Default)]
pub(crate) struct PCodeToECodeGraphMapper {
    source_spans_by_address: FxHashMap<Address, SmallVec<[IlSourceSpan; 1]>>,
}

struct PCodeBlockPartitions {
    ranges: Vec<IlIndexRange>,
    ranges_for_block: Vec<IlIndexRange>,
    first_blocks: Vec<IlBlockId>,
}

impl PCodeToECodeGraphMapper {
    pub(crate) fn remap(
        &mut self,
        source: &PCodeIr,
        operation_map: &IlIndexMapper,
    ) -> Result<IlGraph, IlError> {
        let mut partitions = Vec::new();
        let mut partition_ranges = Vec::with_capacity(source.graph().blocks().len());
        let mut first_blocks = Vec::with_capacity(source.graph().blocks().len());
        let mut refined_block_count = 0usize;
        let mut boundaries = Vec::new();
        self.source_spans_by_address.clear();
        for &span in source.source_spans() {
            self.source_spans_by_address
                .entry(span.address())
                .or_default()
                .push(span);
        }

        for block in source.graph().blocks() {
            let operations = block.ops();
            boundaries.clear();
            boundaries.push(operations.start());
            boundaries.push(operations.end());

            for operation_index in operations.start()..operations.end() {
                let operation = &source.ops()[operation_index];
                if matches!(
                    operation.opcode(),
                    PCodeOpcode::Branch
                        | PCodeOpcode::CBranch
                        | PCodeOpcode::IBranch
                        | PCodeOpcode::Return
                ) {
                    boundaries.push(operation_index + 1);
                }
                if let Some(target) =
                    self.internal_target(source, operations, operation_index, operation)
                {
                    boundaries.push(target);
                }
            }

            boundaries.sort_unstable();
            boundaries.dedup();
            let partition_start = partitions.len();
            for pair in boundaries.windows(2) {
                partitions.push(IlIndexRange::new(pair[0], pair[1])?);
            }
            if partition_start == partitions.len() {
                partitions.push(operations);
            }

            first_blocks.push(IlBlockId::try_from_index(refined_block_count)?);
            refined_block_count += partitions.len() - partition_start;
            partition_ranges.push(IlIndexRange::new(partition_start, partitions.len())?);
        }

        let partitions = PCodeBlockPartitions {
            ranges: partitions,
            ranges_for_block: partition_ranges,
            first_blocks,
        };
        self.remap_edges(source, operation_map, &partitions)
    }

    fn remap_edges(
        &self,
        source: &PCodeIr,
        operation_map: &IlIndexMapper,
        partitions: &PCodeBlockPartitions,
    ) -> Result<IlGraph, IlError> {
        let mut blocks = Vec::with_capacity(partitions.ranges.len());
        let mut successors = Vec::new();
        let mut successor_kinds = Vec::new();
        let mut block_sources = (!source.graph().block_sources().is_empty())
            .then(|| Vec::with_capacity(partitions.ranges.len()));

        for (block_index, (source_block, ranges)) in source
            .graph()
            .blocks()
            .iter()
            .zip(&partitions.ranges_for_block)
            .enumerate()
        {
            let ranges = ranges.slice(&partitions.ranges);
            for (range_index, range) in ranges.iter().copied().enumerate() {
                let block_successors = BlockSuccessors::from_partition(
                    self,
                    source,
                    source_block,
                    ranges,
                    range_index,
                    partitions.first_blocks[block_index],
                    &partitions.first_blocks,
                );

                let successor_start = successors.len();
                successors.extend(block_successors.targets);
                successor_kinds.extend(block_successors.kinds);
                let mut properties = IlBlockProperties::empty();
                if source_block.is_entry() && range_index == 0 {
                    properties |= IlBlockProperties::ENTRY;
                }
                if successor_start == successors.len() {
                    properties |= IlBlockProperties::EXIT;
                }
                blocks.push(IlBlock::new(
                    operation_map.map_range(range),
                    IlIndexRange::new(successor_start, successors.len())?,
                    properties,
                ));
                if let Some(block_sources) = block_sources.as_mut() {
                    let source_address = if range_index == 0 {
                        source.graph().block_sources()[block_index]
                    } else {
                        source
                            .source_span_for(range.start())
                            .map(|span| span.address())
                            .unwrap_or(source.graph().block_sources()[block_index])
                    };
                    block_sources.push(source_address);
                }
            }
        }

        let graph = IlGraph::new(blocks, successors, successor_kinds);
        Ok(match block_sources {
            Some(block_sources) => graph.with_block_sources(block_sources),
            None => graph,
        })
    }

    fn internal_target(
        &self,
        source: &PCodeIr,
        block: IlIndexRange,
        operation_index: usize,
        operation: &PCodeOp,
    ) -> Option<usize> {
        if !matches!(
            operation.opcode(),
            PCodeOpcode::Branch | PCodeOpcode::CBranch
        ) {
            return None;
        }
        let target = source.target(operation.target()?)?;
        let source_span = source.source_span_for(operation_index)?;

        if target.address() != source_span.address() {
            return self
                .source_spans_by_address
                .get(&target.address())?
                .iter()
                .find(|span| {
                    block.start() <= span.destination().start()
                        && span.destination().start() < block.end()
                })
                .map(|span| span.destination().start());
        }

        let relative =
            u32::from(target.position()).checked_sub(source_span.first_source_index())?;
        let relative = usize::try_from(relative).ok()?;
        let target_operation = source_span.destination().start().checked_add(relative)?;
        (block.start() <= target_operation && target_operation <= block.end())
            .then_some(target_operation)
    }
}

pub(crate) fn remap_source_spans(
    source: &PCodeIr,
    operation_map: &IlIndexMapper,
) -> Result<Vec<IlSourceSpan>, IlError> {
    source
        .source_spans()
        .iter()
        .map(|span| {
            let destination = span.destination();
            Ok(IlSourceSpan::new(
                operation_map.map_range(destination),
                span.address(),
                span.first_source_index(),
                span.source_count(),
            ))
        })
        .collect()
}
