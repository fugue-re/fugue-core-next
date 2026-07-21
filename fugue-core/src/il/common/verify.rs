use thiserror::Error;

use crate::il::common::{
    IlBlock, IlBlockId, IlError, IlGraph, IlIndexRange, IlLevel, IlParentSpan, IlSourceSpan,
};

pub(crate) fn verify_bounds(range: IlIndexRange, len: usize) -> Result<(), VerifyError> {
    if range.start() > range.end() {
        return Err(IlError::reversed_range(range.start() as u32, range.end() as u32).into());
    }

    if range.end() > len {
        return Err(IlError::range_out_of_bounds(range.end() as u32, len).into());
    }

    Ok(())
}

pub(crate) fn checked_slice<T>(range: IlIndexRange, values: &[T]) -> Result<&[T], VerifyError> {
    verify_bounds(range, values.len())?;

    Ok(range.slice(values))
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum VerifyError {
    #[error("block {block} argument count mismatch: expected {expected}, found {found}")]
    BlockArgumentCount {
        block: u32,
        expected: usize,
        found: usize,
    },
    #[error("{level} operation has a duplicate memory domain")]
    DuplicateMemoryDomain { level: IlLevel },
    #[error("block {block} has duplicate successor {successor}")]
    DuplicateSuccessor { block: usize, successor: usize },
    #[error("{level} operation has a forbidden output")]
    ForbiddenOutput { level: IlLevel },
    #[error(transparent)]
    Il(#[from] IlError),
    #[error("{level} operation {operation} has invalid block placement")]
    InvalidOperationPlacement { level: IlLevel, operation: u32 },
    #[error("{level} operation has an invalid operand count: expected {expected}, found {found}")]
    InvalidOperandCount {
        level: IlLevel,
        expected: usize,
        found: usize,
    },
    #[error("{level} value has an invalid definition")]
    InvalidValueDefinition { level: IlLevel },
    #[error(
        "{level} value {value} does not dominate edge from block {predecessor} to block {successor}"
    )]
    NonDominatingEdgeArgument {
        level: IlLevel,
        value: u32,
        predecessor: u32,
        successor: u32,
    },
    #[error("{level} value {value} does not dominate use by operation {user}")]
    NonDominatingUse {
        level: IlLevel,
        value: u32,
        user: u32,
    },
    #[error("block {block} operation range overlaps at operation {operation}")]
    OverlappingBlockOperations { block: u32, operation: u32 },
    #[error("parent spans overlap at destination node {node}")]
    OverlappingParentSpan { node: u32 },
    #[error("source spans overlap at destination node {node}")]
    OverlappingSourceSpan { node: u32 },
}

pub(crate) fn verify_graph(graph: &IlGraph) -> Result<(), VerifyError> {
    verify_blocks(graph.blocks(), graph.successors())
}

pub(crate) fn verify_graph_bounds(graph: &IlGraph, node_count: usize) -> Result<(), VerifyError> {
    for block in graph.blocks() {
        verify_bounds(block.operations(), node_count)?;
    }

    Ok(())
}

pub(crate) fn verify_source_spans(
    spans: &[IlSourceSpan],
    node_count: usize,
) -> Result<(), VerifyError> {
    let mut previous_end = 0usize;

    for span in spans {
        verify_bounds(span.destination(), node_count)?;

        if span.destination().start() < previous_end {
            return Err(VerifyError::OverlappingSourceSpan {
                node: span.destination().start() as u32,
            });
        }

        previous_end = span.destination().end();
    }

    Ok(())
}

pub(crate) fn verify_parent_spans(
    spans: &[IlParentSpan],
    node_count: usize,
) -> Result<(), VerifyError> {
    let mut previous_end = 0usize;

    for span in spans {
        verify_bounds(span.destination(), node_count)?;
        verify_bounds(span.source(), usize::MAX)?;

        if span.destination().start() < previous_end {
            return Err(VerifyError::OverlappingParentSpan {
                node: span.destination().start() as u32,
            });
        }

        previous_end = span.destination().end();
    }

    Ok(())
}

pub(crate) fn verify_blocks(
    blocks: &[IlBlock],
    successors: &[IlBlockId],
) -> Result<(), VerifyError> {
    let mut operation_ranges = Vec::new();

    for (index, block) in blocks.iter().enumerate() {
        let block_id = IlBlockId::try_from_index(index)?;
        verify_bounds(block.operations(), usize::MAX)?;
        verify_block_successors(block, block_id, successors)?;

        if !block.operations().is_empty() {
            operation_ranges.push((block.operations(), block_id));
        }

        for successor in checked_slice(block.successors(), successors)? {
            if successor.index() >= blocks.len() {
                return Err(IlError::range_out_of_bounds(successor.value(), blocks.len()).into());
            }
        }
    }

    operation_ranges.sort_unstable_by_key(|(range, _)| range.start());
    let mut previous_operation_end = 0usize;
    for (operations, block_id) in operation_ranges {
        if operations.start() < previous_operation_end {
            return Err(VerifyError::OverlappingBlockOperations {
                block: block_id.value(),
                operation: operations.start() as u32,
            });
        }
        previous_operation_end = operations.end();
    }

    Ok(())
}

pub(crate) fn verify_block_successors(
    block: &IlBlock,
    block_id: IlBlockId,
    successors: &[IlBlockId],
) -> Result<(), VerifyError> {
    let successors = checked_slice(block.successors(), successors)?;

    for (index, successor) in successors.iter().enumerate() {
        if successors[..index].contains(successor) {
            return Err(VerifyError::DuplicateSuccessor {
                block: block_id.index(),
                successor: successor.index(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::{IlBlockProperties, IlIndexRange};
    use crate::ir::Address;
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn structural_verifier_rejects_out_of_range_successor() {
        let blocks = vec![IlBlock::new(
            IlIndexRange::EMPTY,
            IlIndexRange::new(0, 1).unwrap(),
            IlBlockProperties::empty(),
        )];
        let successors = vec![IlBlockId::try_from_index(1).unwrap()];

        assert!(matches!(
            verify_blocks(&blocks, &successors),
            Err(VerifyError::Il(IlError::RangeOutOfBounds { .. }))
        ));
    }

    #[test]
    fn structural_verifier_rejects_overlapping_block_operations() {
        let blocks = vec![
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
        ];

        assert!(matches!(
            verify_blocks(&blocks, &[]),
            Err(VerifyError::OverlappingBlockOperations { .. })
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
        );

        assert!(matches!(
            verify_graph_bounds(&graph, 1),
            Err(VerifyError::Il(IlError::RangeOutOfBounds { .. }))
        ));
    }

    #[test]
    fn structural_verifier_rejects_duplicate_successor() {
        let block = IlBlock::new(
            IlIndexRange::EMPTY,
            IlIndexRange::new(0, 2).unwrap(),
            IlBlockProperties::empty(),
        );
        let successors = vec![
            IlBlockId::try_from_index(0).unwrap(),
            IlBlockId::try_from_index(0).unwrap(),
        ];

        assert!(matches!(
            verify_block_successors(&block, IlBlockId::try_from_index(0).unwrap(), &successors),
            Err(VerifyError::DuplicateSuccessor { .. })
        ));
    }

    #[test]
    fn structural_verifier_rejects_out_of_range_source_span() {
        let span = IlSourceSpan::new(
            IlIndexRange::new(0, 2).unwrap(),
            Address::new(AddressSpaceId::new(1), 0),
            0,
            1,
        );

        assert!(matches!(
            verify_source_spans(&[span], 1),
            Err(VerifyError::Il(IlError::RangeOutOfBounds { .. }))
        ));
    }

    #[test]
    fn structural_verifier_rejects_overlapping_source_spans() {
        let first = IlSourceSpan::new(
            IlIndexRange::new(0, 2).unwrap(),
            Address::new(AddressSpaceId::new(1), 0),
            0,
            1,
        );
        let second = IlSourceSpan::new(
            IlIndexRange::new(1, 3).unwrap(),
            Address::new(AddressSpaceId::new(1), 4),
            0,
            1,
        );

        assert!(matches!(
            verify_source_spans(&[first, second], 8),
            Err(VerifyError::OverlappingSourceSpan { .. })
        ));
    }

    #[test]
    fn structural_verifier_rejects_out_of_range_parent_span() {
        let span = IlParentSpan::new(
            IlIndexRange::new(0, 2).unwrap(),
            IlIndexRange::new(0, 1).unwrap(),
        );

        assert!(matches!(
            verify_parent_spans(&[span], 1),
            Err(VerifyError::Il(IlError::RangeOutOfBounds { .. }))
        ));
    }
}
