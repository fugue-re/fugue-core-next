pub mod analysis;
mod format;
mod ir;
mod memory;
mod opcode;
mod operation;
mod optimise;
mod transform;
mod value;
mod variable;

pub use format::{MCodeIrDisplay, MCodeSourceDisplay};
pub use ir::{MCodeAliasedWriteResults, MCodeBuilder, MCodeCallResults, MCodeIr};
pub use memory::MCodeMemoryDomain;
pub use opcode::MCodeOpcode;
pub use operation::{MCodeOp, MCodeOpSpec, MCodeResultSpec};
pub(crate) use optimise::MCodeOptimiser;
pub use transform::{ECodeToMCode, MCodeCallFacts, MCodeFunctionFacts, MCodeStorageFact};
pub use value::{MCodeBinding, MCodeBlockArg, MCodeValue, MCodeVersion};
pub use variable::{MCodeVar, MCodeVarId, MCodeVarKind};

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::ir::verify::VerifyError;
    use super::*;
    use crate::il::common::{
        IlBlockProperties, IlEdgeKinds, IlError, IlIndexRange, IlMetadata, IlOpId, IlParentSpan,
        IlSourceSpan, IlValueId, RegisterId,
    };
    use crate::il::mcode::{MCodeVar, MCodeVarId};
    use crate::ir::{Address, FunctionId};

    fn metadata() -> IlMetadata {
        IlMetadata::new(FunctionId::default(), 0)
    }

    fn emit_value(
        builder: &mut MCodeBuilder,
        spec: MCodeOpSpec,
        operands: impl IntoIterator<Item = IlValueId>,
        width: u32,
    ) -> Result<IlValueId, IlError> {
        emit_result(builder, spec, operands, MCodeResultSpec::new(width))
    }

    fn emit_result(
        builder: &mut MCodeBuilder,
        spec: MCodeOpSpec,
        operands: impl IntoIterator<Item = IlValueId>,
        result: MCodeResultSpec,
    ) -> Result<IlValueId, IlError> {
        builder.emit_value(spec, operands, result)
    }

    fn provenance_builder(operation_count: usize) -> MCodeBuilder {
        let mut builder = MCodeBuilder::new(metadata());
        for _ in 0..operation_count {
            builder.emit_undefined(0, 64).unwrap();
        }
        builder
    }

    #[test]
    fn mcode_value_stays_compact() {
        assert_eq!(size_of::<MCodeValue>(), 20);
    }

    #[test]
    fn supplemental_provenance_queries_include_primary_relations_first() {
        let first = Address::from(0x1000u64);
        let second = Address::from(0x2000u64);
        let primary_source =
            IlSourceSpan::try_new(IlIndexRange::new(0, 2).unwrap(), first, 0, 2).unwrap();
        let supplemental_sources = vec![
            IlSourceSpan::try_new(IlIndexRange::new(0, 1).unwrap(), first, 7, 1).unwrap(),
            IlSourceSpan::try_new(IlIndexRange::new(0, 1).unwrap(), second, 3, 1).unwrap(),
        ];
        let primary_parent = IlParentSpan::new(
            IlIndexRange::new(0, 2).unwrap(),
            IlIndexRange::new(10, 12).unwrap(),
        );
        let supplemental_parents = vec![
            IlParentSpan::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::new(20, 21).unwrap(),
            ),
            IlParentSpan::new(
                IlIndexRange::new(2, 3).unwrap(),
                IlIndexRange::new(10, 11).unwrap(),
            ),
        ];
        let mut builder = provenance_builder(3);
        builder.set_source_spans(vec![primary_source]);
        builder.extend_source_spans(supplemental_sources.clone());
        builder.set_parent_spans(vec![primary_parent]);
        builder.extend_parent_spans(supplemental_parents.clone());
        let ir = builder.build().unwrap();
        let first_op = IlOpId::try_from_index(0).unwrap();

        assert_eq!(ir.source_span_for(first_op.index()), Some(primary_source));
        assert_eq!(ir.parent_span_for(first_op.index()), Some(primary_parent));
        assert_eq!(
            ir.source_spans().collect::<Vec<_>>(),
            [vec![primary_source], supplemental_sources.clone()].concat()
        );
        assert_eq!(
            ir.parent_spans().collect::<Vec<_>>(),
            [vec![primary_parent], supplemental_parents.clone()].concat()
        );
        assert_eq!(
            ir.source_spans_for_op(first_op).collect::<Vec<_>>(),
            [vec![primary_source], supplemental_sources].concat()
        );
        assert_eq!(
            ir.parent_spans_for_op(first_op).collect::<Vec<_>>(),
            vec![primary_parent, supplemental_parents[0]]
        );
        assert_eq!(
            ir.ops_for_source(first)
                .map(|(operation, _)| operation.index())
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(
            ir.ops_for_source(second)
                .map(|(operation, _)| operation.index())
                .collect::<Vec<_>>(),
            vec![0]
        );
        assert_eq!(
            ir.ops_for_parent(IlOpId::try_from_index(10).unwrap())
                .map(|(operation, _)| operation.index())
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn verifier_rejects_malformed_supplemental_provenance() {
        let address = Address::from(0x1000u64);

        let mut builder = provenance_builder(2);
        builder.add_source_span(
            IlSourceSpan::try_new(IlIndexRange::new(0, 2).unwrap(), address, 0, 1).unwrap(),
        );
        assert!(matches!(
            builder.build_unchecked().verify(),
            Err(VerifyError::InvalidSourceSpan { .. })
        ));

        let primary =
            IlSourceSpan::try_new(IlIndexRange::new(0, 1).unwrap(), address, 0, 1).unwrap();
        let mut builder = provenance_builder(2);
        builder.set_source_spans(vec![primary]);
        builder.add_source_span(primary);
        assert!(matches!(
            builder.build_unchecked().verify(),
            Err(VerifyError::InvalidSourceSpan { .. })
        ));

        let mut builder = provenance_builder(2);
        builder.extend_source_spans([
            IlSourceSpan::try_new(IlIndexRange::new(1, 2).unwrap(), address, 0, 1).unwrap(),
            IlSourceSpan::try_new(IlIndexRange::new(0, 1).unwrap(), address, 1, 1).unwrap(),
        ]);
        assert!(matches!(
            builder.build_unchecked().verify(),
            Err(VerifyError::InvalidSourceSpan { .. })
        ));

        let supplemental_parent = IlParentSpan::new(
            IlIndexRange::new(0, 1).unwrap(),
            IlIndexRange::new(4, 5).unwrap(),
        );
        let mut builder = provenance_builder(2);
        builder.extend_parent_spans([supplemental_parent, supplemental_parent]);
        assert!(matches!(
            builder.build_unchecked().verify(),
            Err(VerifyError::InvalidParentSpan { .. })
        ));

        let mut builder = provenance_builder(2);
        builder.add_parent_span(IlParentSpan::new(
            IlIndexRange::new(2, 3).unwrap(),
            IlIndexRange::new(4, 5).unwrap(),
        ));
        assert!(matches!(
            builder.build_unchecked().verify(),
            Err(VerifyError::Il(IlError::RangeOutOfBounds { .. }))
        ));
    }

    #[test]
    fn rewriter_preserves_result_identity_across_algebraic_replacements() {
        let mut builder = MCodeBuilder::new(metadata());
        let left = builder.emit_undefined(0, 64).unwrap();
        let right = builder.emit_undefined(0, 64).unwrap();
        let operation = IlOpId::try_from_index(builder.op_count()).unwrap();
        let result = builder
            .emit_value(
                MCodeOpSpec::new(MCodeOpcode::Not, 64),
                [left],
                MCodeResultSpec::new(64),
            )
            .unwrap();
        let results =
            IlIndexRange::new(result.index(), result.index().checked_add(1).unwrap()).unwrap();
        builder
            .emit_effect(MCodeOpSpec::new(MCodeOpcode::Return, 0), [result])
            .unwrap();
        let mut ir = builder.build_unchecked();

        ir.rewriter()
            .replace_scalar(operation, MCodeOpcode::And, &[left, right])
            .unwrap();

        let rewritten = &ir.ops()[operation.index()];
        assert_eq!(rewritten.opcode(), MCodeOpcode::And);
        assert_eq!(rewritten.results(), results);
        assert_eq!(ir.op_operands_for(rewritten), &[left, right]);
        assert!(ir.verify().is_ok());

        ir.rewriter()
            .replace_scalar(operation, MCodeOpcode::Copy, &[right])
            .unwrap();

        let rewritten = &ir.ops()[operation.index()];
        assert_eq!(rewritten.opcode(), MCodeOpcode::Copy);
        assert_eq!(rewritten.results(), results);
        assert_eq!(ir.op_operands_for(rewritten), &[right]);
        assert!(ir.verify().is_ok());
    }

    #[test]
    fn ssa_body_display_is_deterministic() {
        let mut builder = MCodeBuilder::new(metadata());
        let value = emit_value(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::Constant, 64).with_immediate(0x2a),
            [],
            64,
        )
        .unwrap();

        builder
            .emit_effect(MCodeOpSpec::new(MCodeOpcode::Return, 0), [value])
            .unwrap();
        let destination = IlIndexRange::new(0, 1).unwrap();
        builder.add_source_span(
            IlSourceSpan::try_new(destination, Address::from(0x1000u64), 3, 1).unwrap(),
        );
        builder.add_parent_span(IlParentSpan::new(
            destination,
            IlIndexRange::new(4, 5).unwrap(),
        ));

        let ir = builder.build_unchecked();

        assert_eq!(
            ir.display().to_string(),
            "%v0:bits<64> = operation<0>\n\
             @o0 %v0:bits<64> = mcode.const 0x2a\n\
             @o1 mcode.ret %v0"
        );
    }

    #[test]
    fn bound_value_renders_variable_name() {
        let mut builder = MCodeBuilder::new(metadata());
        let variable = builder
            .add_variable(MCodeVar::register(RegisterId::new(16), 0))
            .unwrap();

        let source = emit_value(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::Constant, 64).with_immediate(1),
            [],
            64,
        )
        .unwrap();

        let bound = emit_result(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::SetVar, 64).with_variable(variable),
            [source],
            MCodeResultSpec::new(64).with_variable(variable),
        )
        .unwrap();

        let ir = builder.build_unchecked();

        assert!(
            ir.display()
                .to_string()
                .contains("reg[16]#1:bits<64> = %v0")
        );
        let binding = ir.binding(bound).expect("bound value");
        assert_eq!(binding.variable(), variable);
        assert_eq!(binding.version(), MCodeVersion::new(1));
        assert!(ir.verify().is_ok());
    }

    #[test]
    fn field_offset_renders_in_bits_including_zero() {
        let mut builder = MCodeBuilder::new(metadata());
        let variable = builder
            .add_variable(MCodeVar::register(RegisterId::new(16), 0))
            .unwrap();

        let previous = builder.emit_variable_undefined(variable, 64).unwrap();

        let source = emit_value(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::Constant, 8),
            [],
            8,
        )
        .unwrap();

        let _ = emit_result(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::SetVarField, 8).with_variable(variable),
            [previous, source],
            MCodeResultSpec::new(64).with_variable(variable),
        )
        .unwrap();

        let ir = builder.build_unchecked();

        assert!(
            ir.display()
                .to_string()
                .contains("mcode.set_var_field @0 reg[16]#1, %v1")
        );
        assert!(ir.verify().is_ok());
    }

    #[test]
    fn ssa_round_trips_through_rkyv_and_reverifies() {
        let mut builder = MCodeBuilder::new(metadata());
        let value = emit_value(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::Constant, 64).with_immediate(0x2a),
            [],
            64,
        )
        .unwrap();
        builder
            .emit_effect(MCodeOpSpec::new(MCodeOpcode::Return, 0), [value])
            .unwrap();

        let ir = builder.build_unchecked();
        assert!(ir.verify().is_ok());

        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&ir).unwrap();
        let restored = rkyv::from_bytes::<MCodeIr, rkyv::rancor::Error>(&bytes).unwrap();

        assert_eq!(restored, ir);
        assert!(restored.verify().is_ok());
    }

    #[test]
    fn verifier_indexes_block_args_in_a_large_chain() {
        const BLOCK_COUNT: usize = 512;

        let mut builder = MCodeBuilder::new(metadata());
        let mut blocks = Vec::with_capacity(BLOCK_COUNT);
        blocks.push(builder.add_block(IlBlockProperties::ENTRY).unwrap());
        for _ in 1..BLOCK_COUNT {
            blocks.push(builder.add_block(IlBlockProperties::empty()).unwrap());
        }
        let mut block_args = Vec::with_capacity(BLOCK_COUNT - 1);
        for &block in &blocks[1..] {
            block_args.push(builder.add_block_arg(block, 64).unwrap());
        }

        builder.switch_to_block(blocks[0]).unwrap();
        builder.begin_block().unwrap();
        let mut incoming = builder
            .emit_value(
                MCodeOpSpec::new(MCodeOpcode::Constant, 64),
                [],
                MCodeResultSpec::new(64),
            )
            .unwrap();
        for (&block, &arg) in blocks[1..].iter().zip(&block_args) {
            builder
                .add_successor(block, IlEdgeKinds::FALL_THROUGH, [incoming])
                .unwrap();
            builder.end_block().unwrap();
            builder.switch_to_block(block).unwrap();
            builder.begin_block().unwrap();
            incoming = arg;
        }
        builder.end_block().unwrap();

        let ir = builder.build_unchecked();

        assert_eq!(ir.verify(), Ok(()));
    }

    #[test]
    fn verifier_rejects_missing_required_variable() {
        let mut builder = MCodeBuilder::new(metadata());
        let source = emit_value(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::Constant, 64),
            [],
            64,
        )
        .unwrap();
        builder
            .emit_value(
                MCodeOpSpec::new(MCodeOpcode::SetVar, 64),
                [source],
                MCodeResultSpec::new(64),
            )
            .unwrap();

        let ir = builder.build_unchecked();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::MissingVariable { .. })
        ));
    }

    #[test]
    fn verifier_rejects_unknown_variable() {
        let mut builder = MCodeBuilder::new(metadata());
        let unknown = MCodeVarId::try_from_index(3).unwrap();
        builder
            .emit_value(
                MCodeOpSpec::new(MCodeOpcode::AddressOf, 64).with_variable(unknown),
                [],
                MCodeResultSpec::new(64),
            )
            .unwrap();

        let ir = builder.build_unchecked();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::UnknownVariable { .. })
        ));
    }

    #[test]
    fn verifier_rejects_aliased_ordinary_variable() {
        let mut builder = MCodeBuilder::new(metadata());
        let variable = builder.add_variable(MCodeVar::stack(-16)).unwrap();

        let _ = emit_value(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::AddressOf, 64).with_variable(variable),
            [],
            64,
        )
        .unwrap();

        let ir = builder.build_unchecked();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::AliasedVariableMismatch { .. })
        ));
    }

    #[test]
    fn builder_rejects_an_unknown_bound_variable() {
        let mut builder = MCodeBuilder::new(metadata());
        assert!(matches!(
            emit_result(
                &mut builder,
                MCodeOpSpec::new(MCodeOpcode::Constant, 64).with_immediate(1),
                [],
                MCodeResultSpec::new(64).with_variable(MCodeVarId::try_from_index(9).unwrap()),
            ),
            Err(IlError::RangeOutOfBounds { .. })
        ));
    }

    #[test]
    fn verifier_rejects_a_field_beyond_its_variable() {
        let mut builder = MCodeBuilder::new(metadata());
        let variable = builder
            .add_variable(MCodeVar::register(RegisterId::new(16), 0))
            .unwrap();

        let previous = builder.emit_variable_undefined(variable, 64).unwrap();

        let source = builder.emit_undefined(0, 64).unwrap();

        let _ = emit_result(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::SetVarField, 64)
                .with_variable(variable)
                .with_immediate(32),
            [previous, source],
            MCodeResultSpec::new(64).with_variable(variable),
        )
        .unwrap();

        let ir = builder.build_unchecked();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::FieldOutOfBounds { .. })
        ));
    }

    #[test]
    fn verifier_accepts_a_partial_field_update() {
        let mut builder = MCodeBuilder::new(metadata());
        let variable = builder
            .add_variable(MCodeVar::register(RegisterId::new(16), 0))
            .unwrap();

        let previous = builder.emit_variable_undefined(variable, 64).unwrap();

        let source = emit_value(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::Constant, 8),
            [],
            8,
        )
        .unwrap();

        let _ = emit_result(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::SetVarField, 8)
                .with_variable(variable)
                .with_immediate(8),
            [previous, source],
            MCodeResultSpec::new(64).with_variable(variable),
        )
        .unwrap();

        let ir = builder.build_unchecked();

        assert!(ir.verify().is_ok());
    }

    #[test]
    fn verifier_accepts_a_field_predecessor_with_an_earlier_version() {
        let mut builder = MCodeBuilder::new(metadata());
        let variable = builder
            .add_variable(MCodeVar::register(RegisterId::new(16), 0))
            .unwrap();

        let first = builder.emit_variable_undefined(variable, 64).unwrap();

        let second_source = builder.emit_undefined(0, 64).unwrap();
        let _ = emit_result(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::SetVar, 64).with_variable(variable),
            [second_source],
            MCodeResultSpec::new(64).with_variable(variable),
        )
        .unwrap();

        let field = builder.emit_undefined(0, 8).unwrap();
        let _ = emit_result(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::SetVarField, 8).with_variable(variable),
            [first, field],
            MCodeResultSpec::new(64).with_variable(variable),
        )
        .unwrap();

        let ir = builder.build_unchecked();

        assert!(ir.verify().is_ok());
    }

    #[test]
    fn verifier_rejects_a_binding_from_an_invalid_opcode() {
        let mut builder = MCodeBuilder::new(metadata());
        let variable = builder
            .add_variable(MCodeVar::register(RegisterId::new(16), 0))
            .unwrap();
        let _ = emit_result(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::Address, 64),
            [],
            MCodeResultSpec::new(64).with_variable(variable),
        )
        .unwrap();

        let ir = builder.build_unchecked();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::InconsistentBinding { .. })
        ));
    }

    #[test]
    fn verifier_rejects_a_malformed_fixed_arity_operation() {
        let mut builder = MCodeBuilder::new(metadata());
        let _ = emit_value(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::Copy, 64),
            [],
            64,
        )
        .unwrap();

        let ir = builder.build_unchecked();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::InvalidOperandCount { .. })
        ));
    }

    #[test]
    fn verifier_rejects_an_empty_field_result() {
        let mut builder = MCodeBuilder::new(metadata());
        let variable = builder
            .add_variable(MCodeVar::register(RegisterId::new(16), 0))
            .unwrap();
        let mut operands = Vec::new();
        for _ in 0..2 {
            let value = emit_value(
                &mut builder,
                MCodeOpSpec::new(MCodeOpcode::Constant, 64),
                [],
                64,
            )
            .unwrap();
            operands.push(value);
        }
        builder
            .emit_effect(
                MCodeOpSpec::new(MCodeOpcode::SetVarField, 64).with_variable(variable),
                operands,
            )
            .unwrap();

        let ir = builder.build_unchecked();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::InvalidResultCount { .. })
        ));
    }

    #[test]
    fn terminator_emission_does_not_end_a_block() {
        let mut builder = MCodeBuilder::new(metadata());
        let block = builder
            .add_block(IlBlockProperties::ENTRY | IlBlockProperties::EXIT)
            .unwrap();
        builder.switch_to_block(block).unwrap();
        builder.begin_block().unwrap();
        builder
            .emit_effect(MCodeOpSpec::new(MCodeOpcode::Trap, 0), [])
            .unwrap();
        builder.end_block().unwrap();

        assert!(builder.build().is_ok());
    }

    #[test]
    fn verifier_rejects_a_terminator_before_the_end_of_a_linear_body() {
        let mut builder = MCodeBuilder::new(metadata());
        builder
            .emit_effect(MCodeOpSpec::new(MCodeOpcode::Trap, 0), [])
            .unwrap();
        let _ = emit_value(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::Constant, 64),
            [],
            64,
        )
        .unwrap();

        let ir = builder.build_unchecked();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::InvalidOpPlacement { .. })
        ));
    }

    #[test]
    fn switching_blocks_only_changes_the_selected_block() {
        let mut builder = MCodeBuilder::new(metadata());
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
        let mut builder = MCodeBuilder::new(metadata());
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
        let mut builder = MCodeBuilder::new(metadata());
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
        let mut builder = MCodeBuilder::new(metadata());
        let block = builder
            .add_block(IlBlockProperties::ENTRY | IlBlockProperties::EXIT)
            .unwrap();
        builder.switch_to_block(block).unwrap();

        assert!(matches!(
            builder.emit_undefined(0, 64),
            Err(IlError::InvalidArtefact { .. })
        ));
    }

    #[test]
    fn builder_rejects_emission_after_a_block_ends() {
        let mut builder = MCodeBuilder::new(metadata());
        let block = builder
            .add_block(IlBlockProperties::ENTRY | IlBlockProperties::EXIT)
            .unwrap();
        builder.switch_to_block(block).unwrap();
        builder.begin_block().unwrap();
        builder.end_block().unwrap();

        assert!(matches!(
            builder.emit_undefined(0, 64),
            Err(IlError::InvalidArtefact { .. })
        ));
    }

    #[test]
    fn builder_rejects_invalid_block_transitions() {
        let mut builder = MCodeBuilder::new(metadata());

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
        let mut pending = MCodeBuilder::new(metadata());
        pending
            .add_block(IlBlockProperties::ENTRY | IlBlockProperties::EXIT)
            .unwrap();
        assert!(matches!(
            pending.build(),
            Err(IlError::InvalidArtefact { .. })
        ));

        let mut started = MCodeBuilder::new(metadata());
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
        let mut builder = MCodeBuilder::new(metadata());
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
    fn builder_rejects_wrong_edge_arg_count() {
        let mut builder = MCodeBuilder::new(metadata());
        let entry = builder.add_block(IlBlockProperties::ENTRY).unwrap();
        let successor = builder.add_block(IlBlockProperties::EXIT).unwrap();
        builder.switch_to_block(entry).unwrap();
        builder.add_block_arg(successor, 64).unwrap();
        builder.begin_block().unwrap();
        assert!(matches!(
            builder.add_successor(successor, IlEdgeKinds::UNCONDITIONAL, []),
            Err(IlError::InvalidArtefact { .. })
        ));
    }

    #[test]
    fn verifier_rejects_an_edge_kind_incompatible_with_the_terminator() {
        let mut builder = MCodeBuilder::new(metadata());
        let entry = builder.add_block(IlBlockProperties::ENTRY).unwrap();
        let successor = builder.add_block(IlBlockProperties::EXIT).unwrap();
        builder.switch_to_block(entry).unwrap();
        builder.begin_block().unwrap();
        builder
            .emit_effect(
                MCodeOpSpec::new(MCodeOpcode::Branch, 0).with_address(Address::from(0x1000u64)),
                [],
            )
            .unwrap();
        builder
            .add_successor(successor, IlEdgeKinds::FALL_THROUGH, [])
            .unwrap();
        builder.end_block().unwrap();
        builder.switch_to_block(successor).unwrap();
        builder.begin_block().unwrap();
        builder.end_block().unwrap();

        let error = builder.build_unchecked().verify().unwrap_err();
        assert!(matches!(error, VerifyError::Structure(_)), "{error:?}");
    }

    #[test]
    fn builder_rejects_a_repeated_singular_edge_kind() {
        let mut builder = MCodeBuilder::new(metadata());
        let entry = builder.add_block(IlBlockProperties::ENTRY).unwrap();
        let left = builder.add_block(IlBlockProperties::EXIT).unwrap();
        let right = builder.add_block(IlBlockProperties::EXIT).unwrap();
        builder.switch_to_block(entry).unwrap();
        builder.begin_block().unwrap();
        builder
            .add_successor(left, IlEdgeKinds::FALL_THROUGH, [])
            .unwrap();

        assert!(matches!(
            builder.add_successor(right, IlEdgeKinds::FALL_THROUGH, []),
            Err(IlError::InvalidArtefact { .. })
        ));
    }

    #[test]
    fn builder_rejects_different_args_for_a_collapsed_edge() {
        let mut builder = MCodeBuilder::new(metadata());
        let entry = builder.add_block(IlBlockProperties::ENTRY).unwrap();
        let successor = builder.add_block(IlBlockProperties::EXIT).unwrap();
        builder.add_block_arg(successor, 64).unwrap();
        builder.switch_to_block(entry).unwrap();
        builder.begin_block().unwrap();
        let left = builder.emit_undefined(0, 64).unwrap();
        let right = builder.emit_undefined(0, 64).unwrap();
        builder
            .add_successor(successor, IlEdgeKinds::FALL_THROUGH, [left])
            .unwrap();

        assert!(matches!(
            builder.add_successor(successor, IlEdgeKinds::UNCONDITIONAL, [right]),
            Err(IlError::InvalidArtefact { .. })
        ));
    }

    #[test]
    fn builder_rejects_an_edge_arg_for_a_different_variable() {
        let mut builder = MCodeBuilder::new(metadata());
        let entry = builder.add_block(IlBlockProperties::ENTRY).unwrap();
        let successor = builder.add_block(IlBlockProperties::EXIT).unwrap();
        let left = builder
            .add_variable(MCodeVar::register(RegisterId::new(16), 0))
            .unwrap();
        let right = builder
            .add_variable(MCodeVar::register(RegisterId::new(24), 0))
            .unwrap();
        builder
            .add_variable_block_arg(successor, right, 64)
            .unwrap();
        builder.switch_to_block(entry).unwrap();
        builder.begin_block().unwrap();
        let left_value = builder.emit_variable_undefined(left, 64).unwrap();
        assert!(matches!(
            builder.add_successor(successor, IlEdgeKinds::UNCONDITIONAL, [left_value],),
            Err(IlError::InvalidArtefact { .. })
        ));
    }

    #[test]
    fn builder_checks_edge_arg_width_from_an_unreachable_block() {
        let mut builder = MCodeBuilder::new(metadata());
        let entry = builder.add_block(IlBlockProperties::ENTRY).unwrap();
        let unreachable = builder.add_block(IlBlockProperties::empty()).unwrap();
        let successor = builder.add_block(IlBlockProperties::EXIT).unwrap();
        builder.add_block_arg(successor, 64).unwrap();
        builder.switch_to_block(entry).unwrap();
        builder.switch_to_block(unreachable).unwrap();
        builder.begin_block().unwrap();
        let incoming = builder
            .emit_value(
                MCodeOpSpec::new(MCodeOpcode::Constant, 32),
                [],
                MCodeResultSpec::new(32),
            )
            .unwrap();
        assert!(matches!(
            builder.add_successor(successor, IlEdgeKinds::UNCONDITIONAL, [incoming]),
            Err(IlError::InvalidArtefact { .. })
        ));
    }
}
