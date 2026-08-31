use super::verify::VerifyError;
use super::*;
use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlError, IlGraph, IlGraphBuilder,
    IlIndexRange, IlMetadata, IlValueId, RegisterId,
};
use crate::il::mcode::{MCodeVar, MCodeVarId};
use crate::ir::FunctionId;

fn metadata() -> IlMetadata {
    IlMetadata::new(FunctionId::default(), 0)
}

pub(crate) fn emit_value(
    builder: &mut MCodeBuilder,
    spec: MCodeOpSpec,
    operands: impl IntoIterator<Item = IlValueId>,
    width: u32,
) -> Result<IlValueId, IlError> {
    let (_, results) = builder.emitter().emit(spec, operands, [width])?;
    IlValueId::try_from_index(results.start())
}

#[test]
fn rewriter_preserves_result_identity_across_algebraic_replacements() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let left = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Undefined, 64),
        [],
        64,
    )
    .unwrap();
    let right = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Undefined, 64),
        [],
        64,
    )
    .unwrap();
    let (operation, results) = builder
        .emitter()
        .emit(MCodeOpSpec::new(MCodeOpcode::Not, 64), [left], [64])
        .unwrap();
    let result = IlValueId::try_from_index(results.start()).unwrap();
    builder
        .emitter()
        .emit(MCodeOpSpec::new(MCodeOpcode::Return, 0), [result], [])
        .unwrap();
    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

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
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let value = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Constant, 64).with_immediate(0x2a),
        [],
        64,
    )
    .unwrap();

    builder
        .emitter()
        .emit(MCodeOpSpec::new(MCodeOpcode::Return, 0), [value], [])
        .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert_eq!(
        ir.display().to_string(),
        "%v0:bits<64> = operation<0>\n\
         @o0 %v0:bits<64> = mcode.const 0x2a\n\
         @o1 mcode.ret %v0"
    );
}

#[test]
fn bound_value_renders_variable_name() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .emitter()
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();

    let source = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Constant, 64).with_immediate(1),
        [],
        64,
    )
    .unwrap();

    let bound = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::SetVar, 64).with_variable(variable),
        [source],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(bound, variable, MCodeVersion::new(1))
        .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(
        ir.display()
            .to_string()
            .contains("reg[16]#1:bits<64> = mcode.set_var")
    );
    let binding = ir.binding(bound).expect("bound value");
    assert_eq!(binding.variable(), variable);
    assert_eq!(binding.version(), MCodeVersion::new(1));
    assert!(ir.verify().is_ok());
}

#[test]
fn field_offset_renders_in_bits_including_zero() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .emitter()
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();

    let previous = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Undefined, 64),
        [],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(previous, variable, MCodeVersion::new(1))
        .unwrap();

    let source = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Constant, 8),
        [],
        8,
    )
    .unwrap();

    let result = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::SetVarField, 8).with_variable(variable),
        [previous, source],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(result, variable, MCodeVersion::new(2))
        .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(
        ir.display()
            .to_string()
            .contains("mcode.set_var_field @0 reg[16]#1, %v1")
    );
    assert!(ir.verify().is_ok());
}

#[test]
fn ssa_round_trips_through_rkyv_and_reverifies() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let value = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Constant, 64).with_immediate(0x2a),
        [],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .emit(MCodeOpSpec::new(MCodeOpcode::Return, 0), [value], [])
        .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    assert!(ir.verify().is_ok());

    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&ir).unwrap();
    let restored = rkyv::from_bytes::<MCodeIr, rkyv::rancor::Error>(&bytes).unwrap();

    assert_eq!(restored, ir);
    assert!(restored.verify().is_ok());
}

#[test]
fn verifier_indexes_block_args_in_a_large_chain() {
    const BLOCK_COUNT: usize = 512;

    let mut graph = IlGraphBuilder::new();
    let mut blocks = Vec::with_capacity(BLOCK_COUNT);
    blocks.push(
        graph
            .push_block(IlIndexRange::new(0, 1).unwrap(), IlBlockProperties::ENTRY)
            .unwrap(),
    );
    for _ in 1..BLOCK_COUNT {
        blocks.push(
            graph
                .push_block(IlIndexRange::new(1, 1).unwrap(), IlBlockProperties::empty())
                .unwrap(),
        );
    }
    for pair in blocks.windows(2) {
        graph
            .add_successor(pair[0], pair[1], IlEdgeKinds::FALL_THROUGH)
            .unwrap();
    }

    let mut builder = MCodeBuilder::new(metadata(), graph.build(1).unwrap());
    let mut incoming = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Constant, 64),
        [],
        64,
    )
    .unwrap();
    for &block in &blocks[1..] {
        let arg = builder.emitter().emit_block_arg(block, 64).unwrap();
        builder.emitter().emit_edge_args([incoming]).unwrap();
        incoming = arg;
    }

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert_eq!(ir.verify(), Ok(()));
}

#[test]
fn verifier_rejects_missing_required_variable() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let source = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Constant, 64),
        [],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .emit(MCodeOpSpec::new(MCodeOpcode::SetVar, 64), [source], [64])
        .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::MissingVariable { .. })
    ));
}

#[test]
fn verifier_rejects_unknown_variable() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let unknown = MCodeVarId::try_from_index(3).unwrap();
    builder
        .emitter()
        .emit(
            MCodeOpSpec::new(MCodeOpcode::AddressOf, 64).with_variable(unknown),
            [],
            [64],
        )
        .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::UnknownVariable { .. })
    ));
}

#[test]
fn verifier_rejects_aliased_ordinary_variable() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .emitter()
        .intern_variable(MCodeVar::stack(-16))
        .unwrap();

    let _ = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::AddressOf, 64).with_variable(variable),
        [],
        64,
    )
    .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::AliasedVariableMismatch { .. })
    ));
}

#[test]
fn verifier_rejects_an_unknown_bound_variable() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let value = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Constant, 64).with_immediate(1),
        [],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(
            value,
            MCodeVarId::try_from_index(9).unwrap(),
            MCodeVersion::new(1),
        )
        .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::UnknownVariable { .. })
    ));
}

#[test]
fn verifier_rejects_a_duplicate_version() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .emitter()
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();

    for _ in 0..2 {
        let source = emit_value(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::Constant, 64).with_immediate(1),
            [],
            64,
        )
        .unwrap();
        let bound = emit_value(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::SetVar, 64).with_variable(variable),
            [source],
            64,
        )
        .unwrap();
        builder
            .emitter()
            .bind_value(bound, variable, MCodeVersion::new(1))
            .unwrap();
    }

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::DuplicateVersion { .. })
    ));
}

#[test]
fn verifier_rejects_a_field_beyond_its_variable() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .emitter()
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();

    let previous = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Undefined, 64),
        [],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(previous, variable, MCodeVersion::new(1))
        .unwrap();

    let source = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Undefined, 64),
        [],
        64,
    )
    .unwrap();

    let bound = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::SetVarField, 64)
            .with_variable(variable)
            .with_immediate(32),
        [previous, source],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(bound, variable, MCodeVersion::new(2))
        .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::FieldOutOfBounds { .. })
    ));
}

#[test]
fn verifier_accepts_a_partial_field_update() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .emitter()
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();

    let previous = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Undefined, 64),
        [],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(previous, variable, MCodeVersion::new(1))
        .unwrap();

    let source = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Constant, 8),
        [],
        8,
    )
    .unwrap();

    let bound = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::SetVarField, 8)
            .with_variable(variable)
            .with_immediate(8),
        [previous, source],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(bound, variable, MCodeVersion::new(2))
        .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(ir.verify().is_ok());
}

#[test]
fn verifier_rejects_a_field_update_that_skips_a_version() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .emitter()
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();

    let first = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Undefined, 64),
        [],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(first, variable, MCodeVersion::new(1))
        .unwrap();

    let second_source = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Undefined, 64),
        [],
        64,
    )
    .unwrap();
    let second = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::SetVar, 64).with_variable(variable),
        [second_source],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(second, variable, MCodeVersion::new(2))
        .unwrap();

    let field = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Undefined, 8),
        [],
        8,
    )
    .unwrap();
    let third = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::SetVarField, 8).with_variable(variable),
        [first, field],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(third, variable, MCodeVersion::new(3))
        .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InconsistentBinding { .. })
    ));
}

#[test]
fn verifier_rejects_field_predecessor_from_a_later_version() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .emitter()
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();

    let previous = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Undefined, 64),
        [],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(previous, variable, MCodeVersion::new(2))
        .unwrap();

    let source = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Constant, 64),
        [],
        64,
    )
    .unwrap();

    let bound = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::SetVarField, 64).with_variable(variable),
        [previous, source],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(bound, variable, MCodeVersion::new(1))
        .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InconsistentBinding { .. })
    ));
}

#[test]
fn verifier_rejects_a_non_dense_version() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .emitter()
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();
    let value = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Undefined, 64),
        [],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(value, variable, MCodeVersion::new(2))
        .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InvalidVersion { .. })
    ));
}

#[test]
fn verifier_rejects_a_binding_from_an_invalid_opcode() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .emitter()
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();
    let value = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Address, 64),
        [],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(value, variable, MCodeVersion::new(1))
        .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InconsistentBinding { .. })
    ));
}

#[test]
fn verifier_rejects_a_malformed_fixed_arity_operation() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let _ = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Copy, 64),
        [],
        64,
    )
    .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InvalidOperandCount { .. })
    ));
}

#[test]
fn verifier_rejects_an_empty_field_result() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    let variable = builder
        .emitter()
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
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
        .emitter()
        .emit(
            MCodeOpSpec::new(MCodeOpcode::SetVarField, 64).with_variable(variable),
            operands,
            [],
        )
        .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

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
    let mut builder = MCodeBuilder::new(
        metadata(),
        IlGraph::new(vec![block], Vec::new(), Vec::new()),
    );
    builder
        .emitter()
        .emit(MCodeOpSpec::new(MCodeOpcode::Trap, 0), [], [])
        .unwrap();
    let _ = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Constant, 64),
        [],
        64,
    )
    .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InvalidOpPlacement { .. })
    ));
}

#[test]
fn verifier_rejects_a_terminator_before_the_end_of_a_linear_body() {
    let mut builder = MCodeBuilder::new(metadata(), IlGraph::default());
    builder
        .emitter()
        .emit(MCodeOpSpec::new(MCodeOpcode::Trap, 0), [], [])
        .unwrap();
    let _ = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Constant, 64),
        [],
        64,
    )
    .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InvalidOpPlacement { .. })
    ));
}

#[test]
fn verifier_rejects_wrong_edge_arg_table_count() {
    let successor = IlBlockId::try_from_index(1).unwrap();
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::EMPTY,
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
    let mut builder = MCodeBuilder::new(metadata(), graph);
    builder.emitter().emit_edge_args([]).unwrap();
    builder.emitter().emit_edge_args([]).unwrap();
    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert_eq!(
        ir.verify(),
        Err(VerifyError::EdgeArgTableCount {
            expected: 1,
            found: 2,
        })
    );
}

#[test]
fn verifier_rejects_wrong_edge_arg_count() {
    let successor = IlBlockId::try_from_index(1).unwrap();
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::EMPTY,
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
    let mut builder = MCodeBuilder::new(metadata(), graph);
    builder.emitter().emit_block_arg(successor, 64).unwrap();
    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::BlockArgCount { .. })
    ));
}

#[test]
fn verifier_rejects_an_edge_arg_for_a_different_variable() {
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
    let mut builder = MCodeBuilder::new(metadata(), graph);
    let left = builder
        .emitter()
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();
    let right = builder
        .emitter()
        .intern_variable(MCodeVar::register(RegisterId::new(24), 0))
        .unwrap();

    let left_value = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Undefined, 64),
        [],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(left_value, left, MCodeVersion::new(1))
        .unwrap();
    let right_value = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Undefined, 64),
        [],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(right_value, right, MCodeVersion::new(1))
        .unwrap();

    let arg = builder.emitter().emit_block_arg(successor, 64).unwrap();
    builder
        .emitter()
        .bind_value(arg, right, MCodeVersion::new(2))
        .unwrap();
    builder.emitter().emit_edge_args([left_value]).unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InconsistentBinding { .. })
    ));
}

#[test]
fn verifier_checks_edge_arg_width_from_an_unreachable_block() {
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
    let mut builder = MCodeBuilder::new(metadata(), graph);
    let incoming = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Constant, 32),
        [],
        32,
    )
    .unwrap();
    builder.emitter().emit_block_arg(successor, 64).unwrap();
    builder.emitter().emit_edge_args([incoming]).unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::Il(IlError::WidthMismatch { .. }))
    ));
}
