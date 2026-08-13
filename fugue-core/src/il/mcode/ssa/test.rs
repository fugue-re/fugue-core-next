use super::verify::VerifyError;
use super::*;
use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlError, IlGraph, IlIndexRange, IlMetadata,
    IlValueId, RegisterId,
};
use crate::il::mcode::{MCodeVar, MCodeVarId};
use crate::ir::FunctionId;

fn metadata() -> IlMetadata {
    IlMetadata::new(FunctionId::default(), 0)
}

impl MCodeSsaBuilder {
    pub(super) fn push_result_value(
        &mut self,
        width: u32,
    ) -> Result<(IlValueId, IlIndexRange), IlError> {
        let results = self.push_result_values([width])?;
        let value = IlValueId::try_from_index(results.start())?;
        Ok((value, results))
    }
}

#[test]
fn ssa_body_display_is_deterministic() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    let (value, results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            MCodeSsaOp::new(MCodeSsaOpcode::Constant, results, IlIndexRange::EMPTY, 64)
                .with_immediate(0x2a),
        )
        .unwrap();

    let operands = builder.push_value_operands([value]).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            operands,
            0,
        ))
        .unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert_eq!(
        ir.display().to_string(),
        "%v0:bits<64> = operation<0>\n\
         @o0 %v0:bits<64> = mcode.ssa.const 0x2a\n\
         @o1 mcode.ssa.ret %v0"
    );
}

#[test]
fn bound_value_renders_variable_name() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();

    let (source, source_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            MCodeSsaOp::new(
                MCodeSsaOpcode::Constant,
                source_results,
                IlIndexRange::EMPTY,
                64,
            )
            .with_immediate(1),
        )
        .unwrap();

    let operands = builder.push_value_operands([source]).unwrap();
    let (bound, bound_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            MCodeSsaOp::new(MCodeSsaOpcode::SetVar, bound_results, operands, 64)
                .with_variable(variable),
        )
        .unwrap();
    builder.bind_value(bound, variable, MCodeSsaVersion::new(1));

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(
        ir.display()
            .to_string()
            .contains("reg[16]#1:bits<64> = mcode.ssa.set_var")
    );
    let binding = ir.binding(bound).expect("bound value");
    assert_eq!(binding.variable(), variable);
    assert_eq!(binding.version(), MCodeSsaVersion::new(1));
    assert!(ir.verify().is_ok());
}

#[test]
fn field_offset_renders_in_bits_including_zero() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();

    let (previous, previous_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Undefined,
            previous_results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();
    builder.bind_value(previous, variable, MCodeSsaVersion::new(1));

    let (source, source_results) = builder.push_result_value(8).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Constant,
            source_results,
            IlIndexRange::EMPTY,
            8,
        ))
        .unwrap();

    let operands = builder.push_value_operands([previous, source]).unwrap();
    let (result, results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            MCodeSsaOp::new(MCodeSsaOpcode::SetVarField, results, operands, 8)
                .with_variable(variable),
        )
        .unwrap();
    builder.bind_value(result, variable, MCodeSsaVersion::new(2));

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(
        ir.display()
            .to_string()
            .contains("mcode.ssa.set_var_field @0 reg[16]#1, %v1")
    );
    assert!(ir.verify().is_ok());
}

#[test]
fn ssa_round_trips_through_rkyv_and_reverifies() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    let (value, results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            MCodeSsaOp::new(MCodeSsaOpcode::Constant, results, IlIndexRange::EMPTY, 64)
                .with_immediate(0x2a),
        )
        .unwrap();
    let operands = builder.push_value_operands([value]).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            operands,
            0,
        ))
        .unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();
    assert!(ir.verify().is_ok());

    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&ir).unwrap();
    let restored = rkyv::from_bytes::<MCodeSsaIr, rkyv::rancor::Error>(&bytes).unwrap();

    assert_eq!(restored, ir);
    assert!(restored.verify().is_ok());
}

#[test]
fn verifier_rejects_missing_required_variable() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    let (source, source_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Constant,
            source_results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();
    let operands = builder.push_value_operands([source]).unwrap();
    let (_, results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::SetVar,
            results,
            operands,
            64,
        ))
        .unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::MissingVariable { .. })
    ));
}

#[test]
fn verifier_rejects_unknown_variable() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    let (_, results) = builder.push_result_value(64).unwrap();
    let unknown = MCodeVarId::try_from_index(3).unwrap();
    builder
        .push_operation(
            MCodeSsaOp::new(MCodeSsaOpcode::AddressOf, results, IlIndexRange::EMPTY, 64)
                .with_variable(unknown),
        )
        .unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::UnknownVariable { .. })
    ));
}

#[test]
fn verifier_rejects_aliased_ordinary_variable() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    let variable = builder.intern_variable(MCodeVar::stack(-16)).unwrap();

    let (_, results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            MCodeSsaOp::new(MCodeSsaOpcode::AddressOf, results, IlIndexRange::EMPTY, 64)
                .with_variable(variable),
        )
        .unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::AliasedVariableMismatch { .. })
    ));
}

#[test]
fn verifier_rejects_an_unknown_bound_variable() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    let (value, results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            MCodeSsaOp::new(MCodeSsaOpcode::Constant, results, IlIndexRange::EMPTY, 64)
                .with_immediate(1),
        )
        .unwrap();
    builder.bind_value(
        value,
        MCodeVarId::try_from_index(9).unwrap(),
        MCodeSsaVersion::new(1),
    );

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::UnknownVariable { .. })
    ));
}

#[test]
fn verifier_rejects_a_duplicate_version() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();

    for _ in 0..2 {
        let (source, source_results) = builder.push_result_value(64).unwrap();
        builder
            .push_operation(
                MCodeSsaOp::new(
                    MCodeSsaOpcode::Constant,
                    source_results,
                    IlIndexRange::EMPTY,
                    64,
                )
                .with_immediate(1),
            )
            .unwrap();
        let operands = builder.push_value_operands([source]).unwrap();
        let (bound, bound_results) = builder.push_result_value(64).unwrap();
        builder
            .push_operation(
                MCodeSsaOp::new(MCodeSsaOpcode::SetVar, bound_results, operands, 64)
                    .with_variable(variable),
            )
            .unwrap();
        builder.bind_value(bound, variable, MCodeSsaVersion::new(1));
    }

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::DuplicateVersion { .. })
    ));
}

#[test]
fn verifier_rejects_a_field_beyond_its_variable() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();

    let (previous, previous_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Undefined,
            previous_results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();
    builder.bind_value(previous, variable, MCodeSsaVersion::new(1));

    let (source, source_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Undefined,
            source_results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();

    let operands = builder.push_value_operands([previous, source]).unwrap();
    let (bound, bound_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            MCodeSsaOp::new(MCodeSsaOpcode::SetVarField, bound_results, operands, 64)
                .with_variable(variable)
                .with_immediate(32),
        )
        .unwrap();
    builder.bind_value(bound, variable, MCodeSsaVersion::new(2));

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::FieldOutOfBounds { .. })
    ));
}

#[test]
fn verifier_accepts_a_partial_field_update() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();

    let (previous, previous_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Undefined,
            previous_results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();
    builder.bind_value(previous, variable, MCodeSsaVersion::new(1));

    let (source, source_results) = builder.push_result_value(8).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Constant,
            source_results,
            IlIndexRange::EMPTY,
            8,
        ))
        .unwrap();

    let operands = builder.push_value_operands([previous, source]).unwrap();
    let (bound, bound_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            MCodeSsaOp::new(MCodeSsaOpcode::SetVarField, bound_results, operands, 8)
                .with_variable(variable)
                .with_immediate(8),
        )
        .unwrap();
    builder.bind_value(bound, variable, MCodeSsaVersion::new(2));

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(ir.verify().is_ok());
}

#[test]
fn verifier_rejects_a_field_update_that_skips_a_version() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();

    let (first, first_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Undefined,
            first_results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();
    builder.bind_value(first, variable, MCodeSsaVersion::new(1));

    let (second_source, second_source_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Undefined,
            second_source_results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();
    let second_operands = builder.push_value_operands([second_source]).unwrap();
    let (second, second_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            MCodeSsaOp::new(MCodeSsaOpcode::SetVar, second_results, second_operands, 64)
                .with_variable(variable),
        )
        .unwrap();
    builder.bind_value(second, variable, MCodeSsaVersion::new(2));

    let (field, field_results) = builder.push_result_value(8).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Undefined,
            field_results,
            IlIndexRange::EMPTY,
            8,
        ))
        .unwrap();
    let third_operands = builder.push_value_operands([first, field]).unwrap();
    let (third, third_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            MCodeSsaOp::new(
                MCodeSsaOpcode::SetVarField,
                third_results,
                third_operands,
                8,
            )
            .with_variable(variable),
        )
        .unwrap();
    builder.bind_value(third, variable, MCodeSsaVersion::new(3));

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InconsistentBinding { .. })
    ));
}

#[test]
fn verifier_rejects_field_predecessor_from_a_later_version() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();

    let (previous, previous_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Undefined,
            previous_results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();
    builder.bind_value(previous, variable, MCodeSsaVersion::new(2));

    let (source, source_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Constant,
            source_results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();

    let operands = builder.push_value_operands([previous, source]).unwrap();
    let (bound, bound_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            MCodeSsaOp::new(MCodeSsaOpcode::SetVarField, bound_results, operands, 64)
                .with_variable(variable),
        )
        .unwrap();
    builder.bind_value(bound, variable, MCodeSsaVersion::new(1));

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InconsistentBinding { .. })
    ));
}

#[test]
fn verifier_rejects_a_non_dense_version() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();
    let (value, results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Undefined,
            results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();
    builder.bind_value(value, variable, MCodeSsaVersion::new(2));

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InvalidVersion { .. })
    ));
}

#[test]
fn verifier_rejects_a_binding_from_an_invalid_opcode() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();
    let (value, results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Address,
            results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();
    builder.bind_value(value, variable, MCodeSsaVersion::new(1));

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InconsistentBinding { .. })
    ));
}

#[test]
fn verifier_rejects_a_malformed_fixed_arity_operation() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    let (_, results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Copy,
            results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InvalidOperandCount { .. })
    ));
}

#[test]
fn verifier_rejects_an_empty_field_result() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();
    let mut operands = Vec::new();
    for _ in 0..2 {
        let (value, results) = builder.push_result_value(64).unwrap();
        builder
            .push_operation(MCodeSsaOp::new(
                MCodeSsaOpcode::Constant,
                results,
                IlIndexRange::EMPTY,
                64,
            ))
            .unwrap();
        operands.push(value);
    }
    let operands = builder.push_value_operands(operands).unwrap();
    builder
        .push_operation(
            MCodeSsaOp::new(
                MCodeSsaOpcode::SetVarField,
                IlIndexRange::EMPTY,
                operands,
                64,
            )
            .with_variable(variable),
        )
        .unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InvalidResultCount { .. })
    ));
}

#[test]
fn verifier_rejects_a_terminator_before_the_end_of_a_block() {
    let block = IlBlock::new(
        IlIndexRange::new(0, 2).unwrap(),
        IlIndexRange::EMPTY,
        IlBlockProperties::ENTRY | IlBlockProperties::EXIT,
    );
    let mut builder = MCodeSsaBuilder::new(
        metadata(),
        IlGraph::new(vec![block], Vec::new(), Vec::new()),
    );
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Trap,
            IlIndexRange::EMPTY,
            IlIndexRange::EMPTY,
            0,
        ))
        .unwrap();
    let (_, results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Constant,
            results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InvalidOperationPlacement { .. })
    ));
}

#[test]
fn verifier_rejects_a_terminator_before_the_end_of_a_linear_body() {
    let mut builder = MCodeSsaBuilder::new(metadata(), IlGraph::default());
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Trap,
            IlIndexRange::EMPTY,
            IlIndexRange::EMPTY,
            0,
        ))
        .unwrap();
    let (_, results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Constant,
            results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InvalidOperationPlacement { .. })
    ));
}

#[test]
fn verifier_rejects_an_edge_argument_for_a_different_variable() {
    let successor = IlBlockId::try_from_index(1).unwrap();
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::new(0, 2).unwrap(),
                IlIndexRange::new(0, 1).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        vec![successor],
        vec![IlEdgeKinds::UNCONDITIONAL],
    );
    let mut builder = MCodeSsaBuilder::new(metadata(), graph);
    let left = builder
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();
    let right = builder
        .intern_variable(MCodeVar::register(RegisterId::new(24), 0))
        .unwrap();

    let (left_value, left_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Undefined,
            left_results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();
    builder.bind_value(left_value, left, MCodeSsaVersion::new(1));
    let (right_value, right_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Undefined,
            right_results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();
    builder.bind_value(right_value, right, MCodeSsaVersion::new(1));

    let argument = builder.push_block_argument_value(successor, 64).unwrap();
    builder.bind_value(argument, right, MCodeSsaVersion::new(2));
    builder.push_edge_arguments([left_value]).unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InconsistentBinding { .. })
    ));
}

#[test]
fn verifier_checks_edge_argument_width_from_an_unreachable_block() {
    let successor = IlBlockId::try_from_index(2).unwrap();
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::EMPTY,
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::new(0, 1).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        vec![successor],
        vec![IlEdgeKinds::UNCONDITIONAL],
    );
    let mut builder = MCodeSsaBuilder::new(metadata(), graph);
    let (incoming, results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Constant,
            results,
            IlIndexRange::EMPTY,
            32,
        ))
        .unwrap();
    builder.push_block_argument_value(successor, 64).unwrap();
    builder.push_edge_arguments([incoming]).unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::Il(IlError::WidthMismatch { .. }))
    ));
}
