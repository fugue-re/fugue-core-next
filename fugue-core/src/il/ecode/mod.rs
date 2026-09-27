pub mod analysis;
mod domain;
mod format;
mod ir;
mod memory;
mod opcode;
mod operation;
mod optimise;
mod transform;
mod value;

pub use domain::ECodeDomain;
pub use format::{ECodeIrDisplay, ECodeSourceDisplay};
pub use ir::{ECodeBuilder, ECodeIr};
pub use memory::ECodeMemoryDomain;
pub use opcode::ECodeOpcode;
pub use operation::{ECodeOp, ECodeOpSpec};
pub(crate) use optimise::ECodeOptimiser;
pub use transform::PCodeToECode;
pub use value::{ECodeBlockArg, ECodeValue};

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::{ECodeBlockArg, ECodeBuilder, ECodeOp, ECodeOpSpec, ECodeOpcode, ECodeValue};
    use crate::il::common::{IlBlockProperties, IlEdgeKinds, IlError, IlMetadata, IlValueId};
    use crate::ir::FunctionId;

    fn emit_value(
        builder: &mut ECodeBuilder,
        spec: ECodeOpSpec,
        operands: impl IntoIterator<Item = IlValueId>,
    ) -> Result<IlValueId, IlError> {
        builder.emit_value(spec, operands)
    }

    #[test]
    fn ecode_records_stay_compact() {
        assert!(size_of::<ECodeValue>() <= 12);
        assert!(size_of::<ECodeBlockArg>() <= 12);
        assert!(size_of::<ECodeOp>() <= 64);
    }

    #[test]
    fn terminator_emission_does_not_end_a_block() {
        let mut builder = ECodeBuilder::new(IlMetadata::new(FunctionId::default(), 0));
        let block = builder
            .add_block(IlBlockProperties::ENTRY | IlBlockProperties::EXIT)
            .unwrap();
        builder.switch_to_block(block).unwrap();
        builder.begin_block().unwrap();
        builder
            .emit_effect(ECodeOpSpec::new(ECodeOpcode::Trap, 0), [])
            .unwrap();
        builder.end_block().unwrap();

        assert!(builder.build().is_ok());
    }

    #[test]
    fn switching_blocks_only_changes_the_selected_block() {
        let mut builder = ECodeBuilder::new(IlMetadata::new(FunctionId::default(), 0));
        let entry = builder.add_block(IlBlockProperties::ENTRY).unwrap();
        let exit = builder.add_block(IlBlockProperties::EXIT).unwrap();

        builder.switch_to_block(entry).unwrap();
        builder.switch_to_block(exit).unwrap();

        assert_eq!(builder.op_count(), 0);
        builder.switch_to_block(entry).unwrap();
        builder.begin_block().unwrap();
        builder.end_block().unwrap();
        builder.switch_to_block(exit).unwrap();
        builder.begin_block().unwrap();
        builder.end_block().unwrap();
        let ir = builder.build_unchecked();
        assert!(ir.ops().is_empty());
        assert!(
            ir.graph()
                .blocks()
                .iter()
                .all(|block| block.ops().is_empty())
        );
    }

    #[test]
    fn builder_rejects_switching_away_from_a_started_block() {
        let mut builder = ECodeBuilder::new(IlMetadata::new(FunctionId::default(), 0));
        let entry = builder.add_block(IlBlockProperties::ENTRY).unwrap();
        let exit = builder.add_block(IlBlockProperties::EXIT).unwrap();
        builder.switch_to_block(entry).unwrap();
        builder.begin_block().unwrap();

        assert!(matches!(
            builder.switch_to_block(exit),
            Err(IlError::InvalidArtefact { .. })
        ));
    }

    #[test]
    fn builder_rejects_a_block_argument_after_the_block_starts() {
        let mut builder = ECodeBuilder::new(IlMetadata::new(FunctionId::default(), 0));
        let block = builder
            .add_block(IlBlockProperties::ENTRY | IlBlockProperties::EXIT)
            .unwrap();
        builder.switch_to_block(block).unwrap();
        builder.begin_block().unwrap();

        assert!(matches!(
            builder.add_block_arg(block, 64),
            Err(IlError::InvalidArtefact { .. })
        ));
    }

    #[test]
    fn builder_requires_a_started_block_for_emission() {
        let mut builder = ECodeBuilder::new(IlMetadata::new(FunctionId::default(), 0));
        let block = builder
            .add_block(IlBlockProperties::ENTRY | IlBlockProperties::EXIT)
            .unwrap();
        builder.switch_to_block(block).unwrap();

        assert!(matches!(
            builder.emit_value(ECodeOpSpec::new(ECodeOpcode::Undefined, 64), []),
            Err(IlError::InvalidArtefact { .. })
        ));
    }

    #[test]
    fn builder_rejects_emission_after_a_block_ends() {
        let mut builder = ECodeBuilder::new(IlMetadata::new(FunctionId::default(), 0));
        let block = builder
            .add_block(IlBlockProperties::ENTRY | IlBlockProperties::EXIT)
            .unwrap();
        builder.switch_to_block(block).unwrap();
        builder.begin_block().unwrap();
        builder.end_block().unwrap();

        assert!(matches!(
            builder.emit_value(ECodeOpSpec::new(ECodeOpcode::Undefined, 64), []),
            Err(IlError::InvalidArtefact { .. })
        ));
    }

    #[test]
    fn builder_rejects_invalid_block_transitions() {
        let mut builder = ECodeBuilder::new(IlMetadata::new(FunctionId::default(), 0));

        assert!(matches!(
            builder.begin_block(),
            Err(IlError::InvalidArtefact { .. })
        ));

        let block = builder
            .add_block(IlBlockProperties::ENTRY | IlBlockProperties::EXIT)
            .unwrap();
        builder.switch_to_block(block).unwrap();
        assert!(matches!(
            builder.end_block(),
            Err(IlError::InvalidArtefact { .. })
        ));

        builder.begin_block().unwrap();
        assert!(matches!(
            builder.begin_block(),
            Err(IlError::InvalidArtefact { .. })
        ));
        builder.end_block().unwrap();
        assert!(matches!(
            builder.end_block(),
            Err(IlError::InvalidArtefact { .. })
        ));
        assert!(matches!(
            builder.switch_to_block(block),
            Err(IlError::InvalidArtefact { .. })
        ));
    }

    #[test]
    fn builder_requires_declared_blocks_to_end_before_building() {
        let mut pending = ECodeBuilder::new(IlMetadata::new(FunctionId::default(), 0));
        pending
            .add_block(IlBlockProperties::ENTRY | IlBlockProperties::EXIT)
            .unwrap();
        assert!(matches!(
            pending.build(),
            Err(IlError::InvalidArtefact { .. })
        ));

        let mut started = ECodeBuilder::new(IlMetadata::new(FunctionId::default(), 0));
        let block = started
            .add_block(IlBlockProperties::ENTRY | IlBlockProperties::EXIT)
            .unwrap();
        started.switch_to_block(block).unwrap();
        started.begin_block().unwrap();
        assert!(matches!(
            started.build(),
            Err(IlError::InvalidArtefact { .. })
        ));
    }

    #[test]
    fn successor_construction_requires_a_started_block_and_does_not_end_it() {
        let mut builder = ECodeBuilder::new(IlMetadata::new(FunctionId::default(), 0));
        let entry = builder.add_block(IlBlockProperties::ENTRY).unwrap();
        let successor = builder.add_block(IlBlockProperties::EXIT).unwrap();
        builder.switch_to_block(entry).unwrap();

        assert!(matches!(
            builder.add_successor(successor, IlEdgeKinds::FALL_THROUGH, []),
            Err(IlError::InvalidArtefact { .. })
        ));

        builder.begin_block().unwrap();
        builder
            .add_successor(successor, IlEdgeKinds::FALL_THROUGH, [])
            .unwrap();
        builder.end_block().unwrap();

        assert!(matches!(
            builder.add_successor(successor, IlEdgeKinds::UNCONDITIONAL, []),
            Err(IlError::InvalidArtefact { .. })
        ));
    }

    #[test]
    fn exact_insert_extract_pair_recovers_only_the_inserted_value() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeBuilder::new(metadata);

        let base = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Undefined, 64),
            [],
        )
        .unwrap();
        let inserted = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Undefined, 32),
            [],
        )
        .unwrap();
        let combined = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Insert, 64).with_immediate(8),
            [base, inserted],
        )
        .unwrap();
        let exact = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Extract, 32).with_immediate(8),
            [combined],
        )
        .unwrap();
        let narrow = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Extract, 8).with_immediate(8),
            [combined],
        )
        .unwrap();
        let shifted = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Extract, 32),
            [combined],
        )
        .unwrap();

        let ir = builder.build().unwrap();

        assert_eq!(ir.extract_source(exact), Some(inserted));
        assert_eq!(ir.extract_source(narrow), None);
        assert_eq!(ir.extract_source(shifted), Some(combined));
        assert_eq!(ir.underlying_value(exact), exact);
    }
}
