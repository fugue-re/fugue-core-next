use crate::il::common::{Block, BlockId, IlError, MappingRun, SourceRun};

pub trait Verify {
    fn verify(&self) -> Result<(), IlError>;
}

pub struct StructuralVerifier;

impl StructuralVerifier {
    pub fn verify_blocks(blocks: &[Block], successors: &[BlockId]) -> Result<(), IlError> {
        let mut previous_operation_end = 0usize;

        for (index, block) in blocks.iter().enumerate() {
            let block_id = BlockId::try_from_index(index)?;
            block.operations().verify_bounds(usize::MAX)?;
            block.verify_successors(block_id, successors)?;

            if !block.operations().is_empty() {
                if block.operations().start() < previous_operation_end {
                    return Err(IlError::overlapping_block_operations(
                        block_id.value(),
                        block.operations().start() as u32,
                    ));
                }

                previous_operation_end = block.operations().end();
            }

            for successor in block.successors().checked_slice(successors)? {
                if successor.index() >= blocks.len() {
                    return Err(IlError::range_out_of_bounds(
                        successor.value(),
                        blocks.len(),
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn verify_block_operation_bounds(
        blocks: &[Block],
        node_count: usize,
    ) -> Result<(), IlError> {
        for block in blocks {
            block.operations().verify_bounds(node_count)?;
        }

        Ok(())
    }

    pub fn verify_source_runs(runs: &[SourceRun]) -> Result<(), IlError> {
        let mut previous_end = 0usize;

        for run in runs {
            run.destination().verify_bounds(usize::MAX)?;

            if run.destination().start() < previous_end {
                return Err(IlError::overlapping_source_run(
                    run.destination().start() as u32
                ));
            }

            previous_end = run.destination().end();
        }

        Ok(())
    }

    pub fn verify_source_run_bounds(runs: &[SourceRun], node_count: usize) -> Result<(), IlError> {
        for run in runs {
            run.destination().verify_bounds(node_count)?;
        }

        Ok(())
    }

    pub fn verify_mapping_runs(runs: &[MappingRun]) -> Result<(), IlError> {
        let mut previous_end = 0usize;

        for run in runs {
            run.destination().verify_bounds(usize::MAX)?;
            run.source().verify_bounds(usize::MAX)?;

            if run.destination().start() < previous_end {
                return Err(IlError::overlapping_mapping_run(
                    run.destination().start() as u32
                ));
            }

            previous_end = run.destination().end();
        }

        Ok(())
    }

    pub fn verify_mapping_destination_bounds(
        runs: &[MappingRun],
        node_count: usize,
    ) -> Result<(), IlError> {
        for run in runs {
            run.destination().verify_bounds(node_count)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::common::PackedRange;
    use crate::ir::Address;
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn structural_verifier_rejects_out_of_range_successor() {
        let blocks = vec![Block::new(
            PackedRange::EMPTY,
            PackedRange::new(0, 1).unwrap(),
            0,
        )];
        let successors = vec![BlockId::try_from_index(1).unwrap()];

        assert!(matches!(
            StructuralVerifier::verify_blocks(&blocks, &successors),
            Err(IlError::RangeOutOfBounds { .. })
        ));
    }

    #[test]
    fn structural_verifier_rejects_overlapping_block_operations() {
        let blocks = vec![
            Block::new(PackedRange::new(0, 2).unwrap(), PackedRange::EMPTY, 0),
            Block::new(PackedRange::new(1, 3).unwrap(), PackedRange::EMPTY, 0),
        ];

        assert!(matches!(
            StructuralVerifier::verify_blocks(&blocks, &[]),
            Err(IlError::OverlappingBlockOperations { .. })
        ));
    }

    #[test]
    fn structural_verifier_rejects_out_of_range_block_operations() {
        let blocks = vec![Block::new(
            PackedRange::new(0, 2).unwrap(),
            PackedRange::EMPTY,
            0,
        )];

        assert!(matches!(
            StructuralVerifier::verify_block_operation_bounds(&blocks, 1),
            Err(IlError::RangeOutOfBounds { .. })
        ));
    }

    #[test]
    fn structural_verifier_rejects_out_of_range_source_run() {
        let run = SourceRun::new(
            PackedRange::new(0, 2).unwrap(),
            Address::new(AddressSpaceId::new(1), 0),
            0,
            1,
        );

        assert!(matches!(
            StructuralVerifier::verify_source_run_bounds(&[run], 1),
            Err(IlError::RangeOutOfBounds { .. })
        ));
    }

    #[test]
    fn structural_verifier_rejects_out_of_range_mapping_destination() {
        let run = MappingRun::new(
            PackedRange::new(0, 2).unwrap(),
            PackedRange::new(0, 1).unwrap(),
        );

        assert!(matches!(
            StructuralVerifier::verify_mapping_destination_bounds(&[run], 1),
            Err(IlError::RangeOutOfBounds { .. })
        ));
    }
}
