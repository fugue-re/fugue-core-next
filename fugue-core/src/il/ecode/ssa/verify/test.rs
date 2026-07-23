use fugue_bv::BitVec;

use crate::analysis::control::CancellationToken;
use crate::il::common::verify::VerifyError;
use crate::il::common::{
    IlArtefact, IlBlock, IlBlockId, IlBlockProperties, IlError, IlGraph, IlHeader, IlIndexRange,
    IlOpId, IlValueId,
};
use crate::il::ecode::ssa::optimise::ECodeSsaConstantFolding;
use crate::il::ecode::ssa::{
    ECODE_SSA_SCHEMA_VERSION, ECodeSsaBlockArg, ECodeSsaBuilder, ECodeSsaIr, ECodeSsaMemoryDomain,
    ECodeSsaOp, ECodeSsaOpcode, ECodeSsaValue, ECodeSsaValueKind, verify,
};
use crate::ir::FunctionId;
use crate::storage::segments::space::AddressSpaceId;

#[test]
fn ssa_verifier_rejects_invalid_value_definition() {
    let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let body = ECodeSsaIr::new(
        header,
        IlGraph::default(),
        Vec::new(),
        Vec::new(),
        vec![ECodeSsaValue::new(64, ECodeSsaValueKind::Operation, 3)],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );

    assert!(matches!(
        verify(&body),
        Err(VerifyError::InvalidValueDefinition { .. })
    ));
}

#[test]
fn ssa_verifier_rejects_duplicate_memory_domains() {
    let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let space = AddressSpaceId::new(7);
    let body = ECodeSsaIr::new(
        header,
        IlGraph::default(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![
            ECodeSsaMemoryDomain::new(space),
            ECodeSsaMemoryDomain::new(space),
        ],
    );

    assert!(matches!(
        verify(&body),
        Err(VerifyError::DuplicateMemoryDomain { .. })
    ));
}

#[test]
fn ssa_verifier_rejects_load_without_memory_domain() {
    let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let space = AddressSpaceId::new(7);
    let mut builder = ECodeSsaBuilder::new(header, IlGraph::default());
    let (_value, results) = builder.push_result_value(8).unwrap();

    builder
        .push_operation(
            ECodeSsaOp::new(ECodeSsaOpcode::Load, results, IlIndexRange::EMPTY, 8)
                .with_address_space(space),
        )
        .unwrap();

    let body = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        verify(&body),
        Err(VerifyError::Il(IlError::MissingComponent { .. }))
    ));
}

#[test]
fn ssa_verifier_rejects_wide_constant_beyond_pool() {
    let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let mut builder = ECodeSsaBuilder::new(header, IlGraph::default());
    let (_value, results) = builder.push_result_value(128).unwrap();

    builder
        .push_operation(
            ECodeSsaOp::new(ECodeSsaOpcode::Constant, results, IlIndexRange::EMPTY, 128)
                .with_immediate(100),
        )
        .unwrap();

    let body = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        verify(&body),
        Err(VerifyError::Il(IlError::RangeOutOfBounds { .. }))
    ));
}

#[test]
fn ssa_verifier_rejects_operand_width_mismatch() {
    let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let mut builder = ECodeSsaBuilder::new(header, IlGraph::default());

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
        verify(&body),
        Err(VerifyError::Il(IlError::WidthMismatch { .. }))
    ));
}

#[test]
fn ssa_verifier_accepts_wide_constant_within_pool() {
    let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let mut builder = ECodeSsaBuilder::new(header, IlGraph::default());

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
    verify(&body).unwrap();

    body.rewrite(ECodeSsaConstantFolding);

    verify(&body).unwrap();
    assert_eq!(
        body.constant_value(widened),
        Some(BitVec::from_u64(0xabc, 64).unsigned_cast(128))
    );
}

#[test]
fn ssa_verifier_bounds_wide_constant_at_pool_edge() {
    let wide_constant = |pool_len: usize| {
        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        ECodeSsaIr::new(
            header,
            IlGraph::default(),
            Vec::new(),
            Vec::new(),
            vec![ECodeSsaValue::operation_result(
                128,
                IlOpId::try_from_index(0).unwrap(),
            )],
            Vec::new(),
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
            Vec::new(),
        )
        .with_constants(vec![0u8; pool_len])
    };

    verify(&wide_constant(16)).unwrap();

    assert!(matches!(
        verify(&wide_constant(15)),
        Err(VerifyError::Il(IlError::RangeOutOfBounds { .. }))
    ));
}

#[test]
fn ssa_verifier_rejects_non_dominating_linear_use() {
    let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let value = IlValueId::try_from_index(0).unwrap();
    let result = IlIndexRange::new(0, 1).unwrap();
    let operands = IlIndexRange::new(0, 1).unwrap();
    let body = ECodeSsaIr::new(
        header,
        IlGraph::default(),
        Vec::new(),
        Vec::new(),
        vec![ECodeSsaValue::operation_result(
            32,
            IlOpId::try_from_index(1).unwrap(),
        )],
        Vec::new(),
        vec![
            ECodeSsaOp::new(ECodeSsaOpcode::Return, IlIndexRange::EMPTY, operands, 0),
            ECodeSsaOp::new(ECodeSsaOpcode::Constant, result, IlIndexRange::EMPTY, 32),
        ],
        vec![value],
        Vec::new(),
    );

    assert!(matches!(
        verify(&body),
        Err(VerifyError::NonDominatingUse { .. })
    ));
}

#[test]
fn ssa_verifier_rejects_non_dominating_block_use() {
    let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
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
    let body = ECodeSsaIr::new(
        header,
        graph,
        Vec::new(),
        Vec::new(),
        vec![ECodeSsaValue::operation_result(
            32,
            IlOpId::try_from_index(0).unwrap(),
        )],
        Vec::new(),
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
        Vec::new(),
    );

    assert!(matches!(
        verify(&body),
        Err(VerifyError::NonDominatingUse { .. })
    ));
}

#[test]
fn ssa_verifier_rejects_wrong_edge_argument_count() {
    let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
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
    let body = ECodeSsaIr::new(
        header,
        graph,
        Vec::new(),
        Vec::new(),
        vec![ECodeSsaValue::block_argument(32, 0)],
        vec![ECodeSsaBlockArg::new(successor, argument_value, 32)],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .with_edge_argument_storage(vec![IlIndexRange::EMPTY], Vec::new());

    assert!(matches!(
        verify(&body),
        Err(VerifyError::BlockArgumentCount { .. })
    ));
}

#[test]
fn ssa_verifier_rejects_non_dominating_edge_argument() {
    let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
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
    let body = ECodeSsaIr::new(
        header,
        graph,
        Vec::new(),
        Vec::new(),
        vec![
            ECodeSsaValue::operation_result(32, IlOpId::try_from_index(0).unwrap()),
            ECodeSsaValue::block_argument(32, 0),
        ],
        vec![ECodeSsaBlockArg::new(right, argument_value, 32)],
        vec![ECodeSsaOp::new(
            ECodeSsaOpcode::Constant,
            IlIndexRange::new(0, 1).unwrap(),
            IlIndexRange::EMPTY,
            32,
        )],
        Vec::new(),
        Vec::new(),
    )
    .with_edge_argument_storage(
        vec![IlIndexRange::EMPTY, IlIndexRange::new(0, 1).unwrap()],
        vec![value],
    );

    assert!(matches!(
        verify(&body),
        Err(VerifyError::NonDominatingEdgeArgument { .. })
    ));
}

#[test]
fn ssa_verifier_rejects_duplicate_operation_placement() {
    let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
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
    let body = ECodeSsaIr::new(
        header,
        graph,
        Vec::new(),
        Vec::new(),
        vec![ECodeSsaValue::operation_result(
            32,
            IlOpId::try_from_index(0).unwrap(),
        )],
        Vec::new(),
        vec![ECodeSsaOp::new(
            ECodeSsaOpcode::Constant,
            IlIndexRange::new(0, 1).unwrap(),
            IlIndexRange::EMPTY,
            32,
        )],
        Vec::new(),
        Vec::new(),
    );

    assert!(matches!(
        verify(&body),
        Err(VerifyError::OverlappingBlockOperations { .. })
    ));
}
