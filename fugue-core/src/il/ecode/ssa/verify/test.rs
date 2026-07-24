use fugue_bv::BitVec;

use super::VerifyError;
use crate::analysis::control::CancellationToken;
use crate::il::common::verify::StructureError;
use crate::il::common::{
    IlArtefact, IlBlock, IlBlockId, IlBlockProperties, IlError, IlGraph, IlIndexRange, IlMetadata,
    IlOpId, IlValueId,
};
use crate::il::ecode::ssa::optimise::ECodeSsaConstantFolding;
use crate::il::ecode::ssa::{
    ECODE_SSA_SCHEMA_VERSION, ECodeSsaBlockArg, ECodeSsaBuilder, ECodeSsaIr, ECodeSsaMemoryDomain,
    ECodeSsaOp, ECodeSsaOpcode, ECodeSsaValue, ECodeSsaValueKind,
};
use crate::ir::FunctionId;
use crate::storage::segments::space::AddressSpaceId;

#[test]
fn ssa_verifier_rejects_invalid_value_definition() {
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let body = ECodeSsaIr::new(metadata, IlGraph::default()).with_values(
        vec![ECodeSsaValue::new(64, ECodeSsaValueKind::Operation, 3)],
        Vec::new(),
    );

    assert!(matches!(
        body.verify(),
        Err(VerifyError::InvalidValueDefinition)
    ));
}

#[test]
fn ssa_verifier_rejects_duplicate_memory_domains() {
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let space = AddressSpaceId::new(7);
    let body = ECodeSsaIr::new(metadata, IlGraph::default()).with_memory_domains(vec![
        ECodeSsaMemoryDomain::new(space),
        ECodeSsaMemoryDomain::new(space),
    ]);

    assert!(matches!(
        body.verify(),
        Err(VerifyError::DuplicateMemoryDomain)
    ));
}

#[test]
fn ssa_verifier_rejects_load_without_memory_domain() {
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let space = AddressSpaceId::new(7);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());
    let (_value, results) = builder.push_result_value(8).unwrap();

    builder
        .push_operation(
            ECodeSsaOp::new(ECodeSsaOpcode::Load, results, IlIndexRange::EMPTY, 8)
                .with_address_space(space),
        )
        .unwrap();

    let body = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        body.verify(),
        Err(VerifyError::Il(IlError::MissingComponent { .. }))
    ));
}

#[test]
fn ssa_verifier_reports_invalid_store_result_count() {
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let space = AddressSpaceId::new(7);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());
    builder.ensure_memory_domain(space);

    let (pointer, pointer_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Constant,
            pointer_results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();

    let (value, value_results) = builder.push_result_value(8).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Constant,
            value_results,
            IlIndexRange::EMPTY,
            8,
        ))
        .unwrap();

    let (memory, memory_results) = builder.push_result_value(0).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Undefined,
            memory_results,
            IlIndexRange::EMPTY,
            0,
        ))
        .unwrap();

    let operands = builder
        .push_value_operands([pointer, value, memory])
        .unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(ECodeSsaOpcode::Store, IlIndexRange::EMPTY, operands, 0)
                .with_address_space(space),
        )
        .unwrap();

    let body = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        body.verify(),
        Err(VerifyError::InvalidResultCount {
            operation: 4,
            expected: 1,
            found: 0,
        })
    ));
}

#[test]
fn ssa_verifier_rejects_wide_constant_beyond_pool() {
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());
    let (_value, results) = builder.push_result_value(128).unwrap();

    builder
        .push_operation(
            ECodeSsaOp::new(ECodeSsaOpcode::Constant, results, IlIndexRange::EMPTY, 128)
                .with_immediate(100),
        )
        .unwrap();

    let body = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        body.verify(),
        Err(VerifyError::Il(IlError::RangeOutOfBounds { .. }))
    ));
}

#[test]
fn ssa_verifier_rejects_operand_width_mismatch() {
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());

    let (wide, wide_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Constant,
            wide_results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();

    let operands = builder.push_value_operands([wide, wide]).unwrap();
    let (_sum, sum_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Add,
            sum_results,
            operands,
            32,
        ))
        .unwrap();

    let body = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        body.verify(),
        Err(VerifyError::Il(IlError::WidthMismatch { .. }))
    ));
}

#[test]
fn ssa_verifier_accepts_wide_constant_within_pool() {
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());

    let (source, source_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                source_results,
                IlIndexRange::EMPTY,
                64,
            )
            .with_immediate(0xabc),
        )
        .unwrap();

    let widen_operands = builder.push_value_operands([source]).unwrap();
    let (widened, widened_results) = builder.push_result_value(128).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::ZeroExtend,
            widened_results,
            widen_operands,
            128,
        ))
        .unwrap();

    let return_operands = builder.push_value_operands([widened]).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            return_operands,
            0,
        ))
        .unwrap();

    let mut body = builder.build(&CancellationToken::default()).unwrap();
    body.verify().unwrap();

    body.rewrite(ECodeSsaConstantFolding);

    body.verify().unwrap();
    assert_eq!(
        body.constant_value(widened),
        Some(BitVec::from_u64(0xabc, 64).unsigned_cast(128))
    );
}

#[test]
fn ssa_verifier_bounds_wide_constant_at_pool_edge() {
    let wide_constant = |pool_len: usize| {
        let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        ECodeSsaIr::new(metadata, IlGraph::default())
            .with_values(
                vec![ECodeSsaValue::operation_result(
                    128,
                    IlOpId::try_from_index(0).unwrap(),
                )],
                Vec::new(),
            )
            .with_operations(
                vec![
                    ECodeSsaOp::new(
                        ECodeSsaOpcode::Constant,
                        IlIndexRange::new(0, 1).unwrap(),
                        IlIndexRange::EMPTY,
                        128,
                    )
                    .with_immediate(0),
                ],
                Vec::new(),
            )
            .with_constant_storage(vec![0u8; pool_len])
    };

    wide_constant(16).verify().unwrap();

    assert!(matches!(
        wide_constant(15).verify(),
        Err(VerifyError::Il(IlError::RangeOutOfBounds { .. }))
    ));
}

#[test]
fn ssa_verifier_rejects_non_dominating_linear_use() {
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let value = IlValueId::try_from_index(0).unwrap();
    let result = IlIndexRange::new(0, 1).unwrap();
    let operands = IlIndexRange::new(0, 1).unwrap();
    let body = ECodeSsaIr::new(metadata, IlGraph::default())
        .with_values(
            vec![ECodeSsaValue::operation_result(
                32,
                IlOpId::try_from_index(1).unwrap(),
            )],
            Vec::new(),
        )
        .with_operations(
            vec![
                ECodeSsaOp::new(ECodeSsaOpcode::Return, IlIndexRange::EMPTY, operands, 0),
                ECodeSsaOp::new(ECodeSsaOpcode::Constant, result, IlIndexRange::EMPTY, 32),
            ],
            vec![value],
        );

    assert!(matches!(
        body.verify(),
        Err(VerifyError::NonDominatingUse { .. })
    ));
}

#[test]
fn ssa_verifier_rejects_non_dominating_block_use() {
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let left = IlBlockId::try_from_index(1).unwrap();
    let right = IlBlockId::try_from_index(2).unwrap();
    let value = IlValueId::try_from_index(0).unwrap();
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::new(0, 2).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::new(1, 2).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::empty(),
            ),
        ],
        vec![left, right],
    );
    let body = ECodeSsaIr::new(metadata, graph)
        .with_values(
            vec![ECodeSsaValue::operation_result(
                32,
                IlOpId::try_from_index(0).unwrap(),
            )],
            Vec::new(),
        )
        .with_operations(
            vec![
                ECodeSsaOp::new(
                    ECodeSsaOpcode::Constant,
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::EMPTY,
                    32,
                ),
                ECodeSsaOp::new(
                    ECodeSsaOpcode::Return,
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(0, 1).unwrap(),
                    0,
                ),
            ],
            vec![value],
        );

    assert!(matches!(
        body.verify(),
        Err(VerifyError::NonDominatingUse { .. })
    ));
}

#[test]
fn ssa_verifier_rejects_wrong_edge_argument_count() {
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let successor = IlBlockId::try_from_index(1).unwrap();
    let argument_value = IlValueId::try_from_index(0).unwrap();
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
    );
    let body = ECodeSsaIr::new(metadata, graph)
        .with_values(
            vec![ECodeSsaValue::block_argument(32, 0)],
            vec![ECodeSsaBlockArg::new(successor, argument_value, 32)],
        )
        .with_edge_argument_storage(vec![IlIndexRange::EMPTY], Vec::new());

    assert!(matches!(
        body.verify(),
        Err(VerifyError::BlockArgumentCount { .. })
    ));
}

#[test]
fn ssa_verifier_rejects_non_dominating_edge_argument() {
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let left = IlBlockId::try_from_index(1).unwrap();
    let right = IlBlockId::try_from_index(2).unwrap();
    let value = IlValueId::try_from_index(0).unwrap();
    let argument_value = IlValueId::try_from_index(1).unwrap();
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::new(0, 2).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        vec![left, right],
    );
    let body = ECodeSsaIr::new(metadata, graph)
        .with_values(
            vec![
                ECodeSsaValue::operation_result(32, IlOpId::try_from_index(0).unwrap()),
                ECodeSsaValue::block_argument(32, 0),
            ],
            vec![ECodeSsaBlockArg::new(right, argument_value, 32)],
        )
        .with_operations(
            vec![ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::EMPTY,
                32,
            )],
            Vec::new(),
        )
        .with_edge_argument_storage(
            vec![IlIndexRange::EMPTY, IlIndexRange::new(0, 1).unwrap()],
            vec![value],
        );

    assert!(matches!(
        body.verify(),
        Err(VerifyError::NonDominatingEdgeArgument { .. })
    ));
}

#[test]
fn ssa_verifier_rejects_duplicate_operation_placement() {
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::empty(),
            ),
        ],
        Vec::new(),
    );
    let body = ECodeSsaIr::new(metadata, graph)
        .with_values(
            vec![ECodeSsaValue::operation_result(
                32,
                IlOpId::try_from_index(0).unwrap(),
            )],
            Vec::new(),
        )
        .with_operations(
            vec![ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::EMPTY,
                32,
            )],
            Vec::new(),
        );

    assert!(matches!(
        body.verify(),
        Err(VerifyError::Structure(
            StructureError::OverlappingBlockOperations { .. }
        ))
    ));
}
