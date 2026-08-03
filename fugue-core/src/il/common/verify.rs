use thiserror::Error;

use crate::il::common::{IlEdgeKinds, IlError};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StructureError {
    #[error("block source count mismatch: expected {expected}, found {found}")]
    BlockSourceCount { expected: usize, found: usize },
    #[error("block {block} has duplicate successor {successor}")]
    DuplicateSuccessor { block: u32, successor: u32 },
    #[error("edge kind count mismatch: expected {expected}, found {found}")]
    EdgeKindCount { expected: usize, found: usize },
    #[error("block {block} edge {edge} has kinds {kinds:?} its terminator cannot produce")]
    EdgeKindMismatch {
        block: u32,
        edge: u32,
        kinds: IlEdgeKinds,
    },
    #[error("block {block} carries kinds {covered:?} but its terminator requires {required:?}")]
    EdgeKindMissing {
        block: u32,
        covered: IlEdgeKinds,
        required: IlEdgeKinds,
    },
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::{IlIndexRange, IlParentSpan, IlSourceSpan};
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
            IlSourceSpan::verify(&[span], 1),
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
            IlSourceSpan::verify(&[first, second], 8),
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
            IlParentSpan::verify(&[span], 1),
            Err(StructureError::Il(IlError::RangeOutOfBounds { .. }))
        ));
    }
}
