use fugue_bv::BitVec;

use super::{MCodeCompaction, MCodeOptimiser};
use crate::analysis::control::CancellationToken;
use crate::il::common::{IlArtefact, IlGraph, IlMetadata, IlValueId, RegisterId};
use crate::il::mcode::test::emit_value;
use crate::il::mcode::{MCodeBuilder, MCodeOpSpec, MCodeOpcode, MCodeVar, MCodeVersion};
use crate::ir::FunctionId;
use crate::storage::segments::space::AddressSpaceId;

#[test]
fn compaction_preserves_interned_constants_across_inline_capacity() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = MCodeBuilder::new(metadata, IlGraph::default());
    let mut constants = Vec::new();
    for width in [65, 128, 192] {
        let (operation, results) = builder
            .emitter()
            .emit(MCodeOpSpec::new(MCodeOpcode::Constant, width), [], [width])
            .unwrap();
        let value = IlValueId::try_from_index(results.start()).unwrap();
        constants.push((value, operation));
    }
    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    let values = [
        BitVec::from_le_bytes(&[1; 9]).unsigned_cast(65),
        BitVec::from_le_bytes(&[2; 16]),
        BitVec::from_le_bytes(&[3; 24]),
    ];
    for ((_, operation), value) in constants.iter().zip(&values) {
        ir.rewriter().replace_with_constant(*operation, value);
    }

    let required = constants
        .iter()
        .map(|(value, _)| *value)
        .collect::<Vec<_>>();
    ir.rewrite(MCodeCompaction::new(&required));

    for ((value, _), expected) in constants.iter().zip(values) {
        assert_eq!(ir.constant_value(*value), Some(expected));
    }
    assert_eq!(ir.constant_storage().len(), 49);
}

#[test]
fn compaction_preserves_empty_and_multi_space_memory_domains() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut empty = MCodeBuilder::new(metadata, IlGraph::default())
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    empty.rewrite(MCodeCompaction::new(&[]));

    assert!(empty.memory_domains().is_empty());

    let spaces = [AddressSpaceId::new(3), AddressSpaceId::new(7)];
    let mut builder = MCodeBuilder::new(metadata, IlGraph::default());
    for space in spaces {
        builder.emitter().intern_memory_domain(space);
    }
    let mut multi_space = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    multi_space.rewrite(MCodeCompaction::new(&[]));

    assert_eq!(
        multi_space
            .memory_domains()
            .iter()
            .map(|domain| domain.space())
            .collect::<Vec<_>>(),
        spaces
    );
}

#[test]
fn compaction_removes_a_dead_pure_definition() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = MCodeBuilder::new(metadata, IlGraph::default());
    emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Constant, 64).with_immediate(7),
        [],
        64,
    )
    .unwrap();
    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    ir.rewrite(MCodeCompaction::new(&[]));

    assert!(ir.ops().is_empty());
    assert!(ir.values().is_empty());
}

#[test]
fn compaction_preserves_an_explicitly_required_value() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = MCodeBuilder::new(metadata, IlGraph::default());
    let variable = builder
        .emitter()
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();
    let source = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Constant, 64).with_immediate(7),
        [],
        64,
    )
    .unwrap();
    let required = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::SetVar, 64).with_variable(variable),
        [source],
        64,
    )
    .unwrap();
    builder
        .emitter()
        .bind_value(required, variable, MCodeVersion::new(1))
        .unwrap();
    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    ir.rewrite(MCodeCompaction::new(&[required]));

    assert_eq!(ir.ops().len(), 2);
    assert_eq!(ir.ops()[1].opcode(), MCodeOpcode::SetVar);
    assert!(ir.values()[1].variable().is_some());
}

#[test]
fn compaction_preserves_variable_definitions_for_required_addresses() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = MCodeBuilder::new(metadata, IlGraph::default());
    let mut required = Vec::new();
    let mut aliased_variables = Vec::new();
    for index in 0..256 {
        let variable = builder
            .emitter()
            .intern_variable(MCodeVar::stack(index))
            .unwrap();
        aliased_variables.push(variable);
        let source = emit_value(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::Undefined, 64),
            [],
            64,
        )
        .unwrap();
        builder
            .emitter()
            .bind_value(source, variable, MCodeVersion::new(1))
            .unwrap();
        let address = emit_value(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::AddressOf, 64).with_variable(variable),
            [],
            64,
        )
        .unwrap();
        required.push(address);
    }
    builder.set_aliased_variables(aliased_variables);
    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    ir.rewrite(MCodeCompaction::new(&required));

    assert_eq!(ir.ops().len(), 512);
    assert_eq!(ir.variables().len(), 256);
}

#[test]
fn folding_preserves_a_bound_value() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = MCodeBuilder::new(metadata, IlGraph::default());
    let variable = builder
        .emitter()
        .intern_variable(MCodeVar::register(RegisterId::new(16), 0))
        .unwrap();
    let source = emit_value(
        &mut builder,
        MCodeOpSpec::new(MCodeOpcode::Constant, 64).with_immediate(7),
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
    builder
        .emitter()
        .emit(MCodeOpSpec::new(MCodeOpcode::Return, 0), [bound], [])
        .unwrap();
    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    ir.rewrite(MCodeOptimiser::new(&[]));

    assert_eq!(ir.ops()[0].opcode(), MCodeOpcode::Constant);
    assert_eq!(ir.values()[0].binding().unwrap().variable(), variable);
    assert!(ir.verify().is_ok());
}
