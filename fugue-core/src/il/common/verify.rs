use thiserror::Error;

use crate::il::common::{IlError, IlParentSpan, IlSourceSpan};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StructureError {
    #[error("block source count mismatch: expected {expected}, found {found}")]
    BlockSourceCount { expected: usize, found: usize },
    #[error("block {block} has duplicate successor {successor}")]
    DuplicateSuccessor { block: u32, successor: u32 },
    #[error(transparent)]
    Il(#[from] IlError),
    #[error("block {block} operation range overlaps at operation {operation}")]
    OverlappingBlockOperations { block: u32, operation: u32 },
    #[error("parent spans overlap at destination node {node}")]
    OverlappingParentSpan { node: u32 },
    #[error("source spans overlap at destination node {node}")]
    OverlappingSourceSpan { node: u32 },
}

pub trait StructureVerifierError: From<IlError> {
    fn structure(error: StructureError) -> Self;

    fn from_structure(error: StructureError) -> Self {
        match error {
            StructureError::Il(error) => error.into(),
            error => Self::structure(error),
        }
    }
}

pub(crate) fn verify_source_spans(
    spans: &[IlSourceSpan],
    node_count: usize,
) -> Result<(), StructureError> {
    let mut previous_end = 0usize;

    for span in spans {
        span.destination().verify_bounds(node_count)?;

        if span.destination().start() < previous_end {
            return Err(StructureError::OverlappingSourceSpan {
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
) -> Result<(), StructureError> {
    let mut previous_end = 0usize;

    for span in spans {
        span.destination().verify_bounds(node_count)?;
        span.source().verify_bounds(usize::MAX)?;

        if span.destination().start() < previous_end {
            return Err(StructureError::OverlappingParentSpan {
                node: span.destination().start() as u32,
            });
        }

        previous_end = span.destination().end();
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::IlIndexRange;
    use crate::ir::Address;
    use crate::storage::segments::space::AddressSpaceId;

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
            Err(StructureError::Il(IlError::RangeOutOfBounds { .. }))
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
            Err(StructureError::OverlappingSourceSpan { .. })
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
            Err(StructureError::Il(IlError::RangeOutOfBounds { .. }))
        ));
    }
}
