use fugue_bv::BitVec;

use super::VerifyError;
use crate::analysis::control::CancellationToken;
use crate::il::common::verify::StructureError;
use crate::il::common::{
    FlagId, IlArtefact, IlBlock, IlBlockArgId, IlBlockId, IlBlockProperties, IlEdgeKinds, IlError,
    IlGraph, IlIndexRange, IlMetadata, IlOpId, IlSsaDef, IlValueId, RegisterId,
};
use crate::il::ecode::ssa::optimise::ECodeSsaConstantFolding;
use crate::il::ecode::ssa::{
    ECodeSsaBlockArg, ECodeSsaBuilder, ECodeSsaBuilderContext, ECodeSsaDomain, ECodeSsaIr,
    ECodeSsaMemoryDomain, ECodeSsaOp, ECodeSsaOpcode, ECodeSsaValue,
};
use crate::ir::FunctionId;
use crate::storage::segments::space::AddressSpaceId;

#[derive(Default)]
struct SsaFixture {
    values: Vec<ECodeSsaValue>,
    block_arguments: Vec<ECodeSsaBlockArg>,
    edge_arguments: Vec<IlIndexRange>,
    edge_argument_values: Vec<IlValueId>,
    operations: Vec<ECodeSsaOp>,
    value_operands: Vec<IlValueId>,
    memory_domains: Vec<ECodeSsaMemoryDomain>,
    constant_storage: Vec<u8>,
}

impl SsaFixture {
    fn with_values(
        mut self,
        values: Vec<ECodeSsaValue>,
        block_arguments: Vec<ECodeSsaBlockArg>,
    ) -> Self {
        self.values = values;
        self.block_arguments = block_arguments;
        self
    }

    fn with_operations(
        mut self,
        operations: Vec<ECodeSsaOp>,
        value_operands: Vec<IlValueId>,
    ) -> Self {
        self.operations = operations;
        self.value_operands = value_operands;
        self
    }

    fn with_edge_argument_storage(
        mut self,
        edge_arguments: Vec<IlIndexRange>,
        edge_argument_values: Vec<IlValueId>,
    ) -> Self {
        self.edge_arguments = edge_arguments;
        self.edge_argument_values = edge_argument_values;
        self
    }

    fn with_memory_domains(mut self, memory_domains: Vec<ECodeSsaMemoryDomain>) -> Self {
        self.memory_domains = memory_domains;
        self
    }

    fn with_constant_storage(mut self, constant_storage: Vec<u8>) -> Self {
        self.constant_storage = constant_storage;
        self
    }

    fn build(self, metadata: IlMetadata, graph: IlGraph) -> ECodeSsaIr {
        let value_domains = vec![None; self.values.len()];
        ECodeSsaIr::new(ECodeSsaBuilderContext {
            metadata,
            graph,
            source_spans: Vec::new(),
            parent_spans: Vec::new(),
            values: self.values,
            value_domains,
            block_arguments: self.block_arguments,
            edge_arguments: self.edge_arguments,
            edge_argument_values: self.edge_argument_values,
            operations: self.operations,
            value_operands: self.value_operands,
            memory_domains: self.memory_domains,
            constant_storage: self.constant_storage,
        })
    }
}

#[test]
fn ssa_verifier_rejects_invalid_value_definition() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let ir = SsaFixture::default()
        .with_values(
            vec![ECodeSsaValue::new(
                64,
                IlSsaDef::Operation(IlOpId::try_from_index(3).unwrap()),
            )],
            Vec::new(),
        )
        .build(metadata, IlGraph::default());

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InvalidValueDefinition)
    ));
}

#[test]
fn ssa_verifier_rejects_register_write_with_wrong_domain() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());
    let (source, source_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Constant,
            source_results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();

    let operands = builder.push_value_operands([source]).unwrap();
    let (written, written_results) = builder.push_result_value(64).unwrap();
    builder.set_value_domain(written, ECodeSsaDomain::Flag(FlagId::new(7)));
    builder
        .push_operation(
            ECodeSsaOp::new(ECodeSsaOpcode::WriteRegister, written_results, operands, 64)
                .with_immediate(7),
        )
        .unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert_eq!(
        ir.verify(),
        Err(VerifyError::InconsistentValueDomain {
            value: written.value(),
        })
    );
}

#[test]
fn ssa_verifier_rejects_duplicate_memory_domains() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let space = AddressSpaceId::new(7);
    let ir = SsaFixture::default()
        .with_memory_domains(vec![
            ECodeSsaMemoryDomain::new(space),
            ECodeSsaMemoryDomain::new(space),
        ])
        .build(metadata, IlGraph::default());

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::DuplicateMemoryDomain)
    ));
}

#[test]
fn ssa_verifier_rejects_load_without_memory_domain() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let space = AddressSpaceId::new(7);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());
    let (_value, results) = builder.push_result_value(8).unwrap();

    builder
        .push_operation(
            ECodeSsaOp::new(ECodeSsaOpcode::Load, results, IlIndexRange::EMPTY, 8)
                .with_address_space(space),
        )
        .unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::Il(IlError::MissingComponent { .. }))
    ));
}

#[test]
fn ssa_verifier_reports_invalid_store_result_count() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
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

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InvalidResultCount {
            operation: 4,
            expected: 1,
            found: 0,
        })
    ));
}

#[test]
fn ssa_verifier_rejects_wide_constant_beyond_pool() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());
    let (_value, results) = builder.push_result_value(128).unwrap();

    builder
        .push_operation(
            ECodeSsaOp::new(ECodeSsaOpcode::Constant, results, IlIndexRange::EMPTY, 128)
                .with_immediate(100),
        )
        .unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::Il(IlError::RangeOutOfBounds { .. }))
    ));
}

#[test]
fn ssa_verifier_rejects_operand_width_mismatch() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
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

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::Il(IlError::WidthMismatch { .. }))
    ));
}

#[test]
fn ssa_verifier_accepts_wide_constant_within_pool() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
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

    let mut ir = builder.build(&CancellationToken::default()).unwrap();
    ir.verify().unwrap();

    ir.rewrite(ECodeSsaConstantFolding);

    ir.verify().unwrap();
    assert_eq!(
        ir.constant_value(widened),
        Some(BitVec::from_u64(0xabc, 64).unsigned_cast(128))
    );
}

#[test]
fn ssa_verifier_bounds_wide_constant_at_pool_edge() {
    let wide_constant = |pool_len: usize| {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        SsaFixture::default()
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
            .build(metadata, IlGraph::default())
    };

    wide_constant(16).verify().unwrap();

    assert!(matches!(
        wide_constant(15).verify(),
        Err(VerifyError::Il(IlError::RangeOutOfBounds { .. }))
    ));
}

#[test]
fn ssa_verifier_rejects_non_dominating_linear_use() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let value = IlValueId::try_from_index(0).unwrap();
    let result = IlIndexRange::new(0, 1).unwrap();
    let operands = IlIndexRange::new(0, 1).unwrap();
    let ir = SsaFixture::default()
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
        )
        .build(metadata, IlGraph::default());

    let result = ir.verify();
    assert!(
        matches!(result, Err(VerifyError::NonDominatingUse { .. })),
        "{result:?}"
    );
}

#[test]
fn ssa_verifier_rejects_non_dominating_block_use() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
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
        vec![IlEdgeKinds::UNCONDITIONAL; 2],
    );
    let ir = SsaFixture::default()
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
        )
        .with_edge_argument_storage(vec![IlIndexRange::EMPTY; 2], Vec::new())
        .build(metadata, graph);

    let result = ir.verify();
    assert!(
        matches!(result, Err(VerifyError::NonDominatingUse { .. })),
        "{result:?}"
    );
}

#[test]
fn ssa_verifier_rejects_wrong_edge_argument_count() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
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
        vec![IlEdgeKinds::UNCONDITIONAL; 1],
    );
    let ir = SsaFixture::default()
        .with_values(
            vec![ECodeSsaValue::block_argument(
                32,
                IlBlockArgId::try_from_index(0).unwrap(),
            )],
            vec![ECodeSsaBlockArg::new(successor, argument_value, 32)],
        )
        .with_edge_argument_storage(vec![IlIndexRange::EMPTY], Vec::new())
        .build(metadata, graph);

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::BlockArgumentCount { .. })
    ));
}

#[test]
fn ssa_verifier_rejects_non_dominating_edge_argument() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
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
        vec![IlEdgeKinds::UNCONDITIONAL; 2],
    );
    let ir = SsaFixture::default()
        .with_values(
            vec![
                ECodeSsaValue::operation_result(32, IlOpId::try_from_index(0).unwrap()),
                ECodeSsaValue::block_argument(32, IlBlockArgId::try_from_index(0).unwrap()),
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
        )
        .build(metadata, graph);

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::NonDominatingEdgeArgument { .. })
    ));
}

#[test]
fn ssa_verifier_rejects_duplicate_operation_placement() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
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
        Vec::new(),
    );
    let ir = SsaFixture::default()
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
        )
        .build(metadata, graph);

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::Structure(
            StructureError::OverlappingBlockOperations { .. }
        ))
    ));
}

#[test]
fn ssa_verifier_rejects_an_edge_argument_from_a_different_domain() {
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
    let mut builder = ECodeSsaBuilder::new(IlMetadata::new(FunctionId::default(), 0), graph);

    let (left, left_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Undefined,
                left_results,
                IlIndexRange::EMPTY,
                64,
            )
            .with_immediate(16),
        )
        .unwrap();
    builder.set_value_domain(left, ECodeSsaDomain::Register(RegisterId::new(16)));
    let (right, right_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Undefined,
                right_results,
                IlIndexRange::EMPTY,
                64,
            )
            .with_immediate(24),
        )
        .unwrap();
    builder.set_value_domain(right, ECodeSsaDomain::Register(RegisterId::new(24)));

    let argument = builder.push_block_argument_value(successor, 64).unwrap();
    builder.set_value_domain(argument, ECodeSsaDomain::Register(RegisterId::new(24)));
    builder.push_edge_arguments([left]).unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InconsistentValueDomain { .. })
    ));
}

#[test]
fn ssa_verifier_checks_edge_argument_width_from_an_unreachable_block() {
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
    let mut builder = ECodeSsaBuilder::new(IlMetadata::new(FunctionId::default(), 0), graph);
    let (incoming, results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Constant,
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
