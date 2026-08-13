use fugue_bv::BitVec;

use super::{MCodeSsaCompaction, MCodeSsaOptimiser};
use crate::analysis::control::CancellationToken;
use crate::il::common::{IlArtefact, IlGraph, IlIndexRange, IlMetadata, IlValueId, RegisterId};
use crate::il::mcode::MCodeVar;
use crate::il::mcode::ssa::{MCodeSsaBuilder, MCodeSsaOp, MCodeSsaOpcode, MCodeSsaVersion};
use crate::ir::FunctionId;

#[test]
fn compaction_preserves_interned_constants_across_inline_capacity() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = MCodeSsaBuilder::new(metadata, IlGraph::default());
    let mut constants = Vec::new();
    for width in [65, 128, 192] {
        let results = builder.push_result_values([width]).unwrap();
        let value = IlValueId::try_from_index(results.start()).unwrap();
        let operation = builder
            .push_operation(MCodeSsaOp::new(
                MCodeSsaOpcode::Constant,
                results,
                IlIndexRange::EMPTY,
                width,
            ))
            .unwrap();
        constants.push((value, operation));
    }
    let mut ir = builder.build(&CancellationToken::default()).unwrap();
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
    ir.rewrite(MCodeSsaCompaction::new(&required));

    for ((value, _), expected) in constants.iter().zip(values) {
        assert_eq!(ir.constant_value(*value), Some(expected));
    }
    assert_eq!(ir.constant_storage().len(), 49);
}

#[test]
fn compaction_removes_a_dead_pure_definition() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = MCodeSsaBuilder::new(metadata, IlGraph::default());
    let (_, results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            MCodeSsaOp::new(MCodeSsaOpcode::Constant, results, IlIndexRange::EMPTY, 64)
                .with_immediate(7),
        )
        .unwrap();
    let mut ir = builder.build(&CancellationToken::default()).unwrap();

    ir.rewrite(MCodeSsaCompaction::new(&[]));

    assert!(ir.operations().is_empty());
    assert!(ir.values().is_empty());
}

#[test]
fn compaction_preserves_an_explicitly_required_value() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = MCodeSsaBuilder::new(metadata, IlGraph::default());
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
            .with_immediate(7),
        )
        .unwrap();
    let operands = builder.push_value_operands([source]).unwrap();
    let (required, required_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            MCodeSsaOp::new(MCodeSsaOpcode::SetVar, required_results, operands, 64)
                .with_variable(variable),
        )
        .unwrap();
    builder.bind_value(required, variable, MCodeSsaVersion::new(1));
    let mut ir = builder.build(&CancellationToken::default()).unwrap();

    ir.rewrite(MCodeSsaCompaction::new(&[required]));

    assert_eq!(ir.operations().len(), 2);
    assert_eq!(ir.operations()[1].opcode(), MCodeSsaOpcode::SetVar);
    assert!(ir.values()[1].variable().is_some());
}

#[test]
fn folding_preserves_a_bound_value() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = MCodeSsaBuilder::new(metadata, IlGraph::default());
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
            .with_immediate(7),
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
    let return_operands = builder.push_value_operands([bound]).unwrap();
    builder
        .push_operation(MCodeSsaOp::new(
            MCodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            return_operands,
            0,
        ))
        .unwrap();
    let mut ir = builder.build(&CancellationToken::default()).unwrap();

    ir.rewrite(MCodeSsaOptimiser::new(&[]));

    assert_eq!(ir.operations()[0].opcode(), MCodeSsaOpcode::Constant);
    assert_eq!(ir.values()[0].binding().unwrap().variable(), variable);
    assert!(ir.verify().is_ok());
}
