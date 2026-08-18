use fugue_bv::BitVec;

use super::VerifyError;
use crate::analysis::control::CancellationToken;
use crate::il::common::verify::StructureError;
use crate::il::common::{
    FlagId, IlArtefact, IlBlock, IlBlockArgId, IlBlockId, IlBlockProperties, IlEdgeKinds, IlError,
    IlGraph, IlGraphBuilder, IlIndexRange, IlMetadata, IlOpId, IlSsaDef, IlValueId, RegisterId,
};
use crate::il::ecode::ir::ECodeIrStorage;
use crate::il::ecode::optimise::ECodeConstantFolding;
use crate::il::ecode::test::emit_value;
use crate::il::ecode::{
    ECodeBlockArg, ECodeBuilder, ECodeDomain, ECodeIr, ECodeMemoryDomain, ECodeOp, ECodeOpSpec,
    ECodeOpcode, ECodeValue,
};
use crate::ir::FunctionId;
use crate::storage::segments::space::AddressSpaceId;

#[derive(Default)]
struct ECodeFixture {
    values: Vec<ECodeValue>,
    block_args: Vec<ECodeBlockArg>,
    edge_args: Vec<IlIndexRange>,
    edge_arg_values: Vec<IlValueId>,
    operations: Vec<ECodeOp>,
    value_operands: Vec<IlValueId>,
    memory_domains: Vec<ECodeMemoryDomain>,
    constant_storage: Vec<u8>,
}

impl ECodeFixture {
    fn with_values(mut self, values: Vec<ECodeValue>, block_args: Vec<ECodeBlockArg>) -> Self {
        self.values = values;
        self.block_args = block_args;
        self
    }

    fn with_operations(mut self, operations: Vec<ECodeOp>, value_operands: Vec<IlValueId>) -> Self {
        self.operations = operations;
        self.value_operands = value_operands;
        self
    }

    fn with_edge_arg_storage(
        mut self,
        edge_args: Vec<IlIndexRange>,
        edge_arg_values: Vec<IlValueId>,
    ) -> Self {
        self.edge_args = edge_args;
        self.edge_arg_values = edge_arg_values;
        self
    }

    fn with_memory_domains(mut self, memory_domains: Vec<ECodeMemoryDomain>) -> Self {
        self.memory_domains = memory_domains;
        self
    }

    fn with_constant_storage(mut self, constant_storage: Vec<u8>) -> Self {
        self.constant_storage = constant_storage;
        self
    }

    fn build(self, metadata: IlMetadata, graph: IlGraph) -> ECodeIr {
        let value_domains = vec![None; self.values.len()];
        ECodeIr::new(ECodeIrStorage {
            metadata,
            graph,
            source_spans: Vec::new(),
            parent_spans: Vec::new(),
            values: self.values,
            value_domains,
            block_args: self.block_args,
            edge_args: self.edge_args,
            edge_arg_values: self.edge_arg_values,
            operations: self.operations,
            value_operands: self.value_operands,
            memory_domains: self.memory_domains,
            constant_storage: self.constant_storage,
        })
    }
}

#[test]
fn ecode_verifier_rejects_invalid_value_definition() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let ir = ECodeFixture::default()
        .with_values(
            vec![ECodeValue::new(
                64,
                IlSsaDef::Op(IlOpId::try_from_index(3).unwrap()),
            )],
            Vec::new(),
        )
        .build(metadata, IlGraph::default());

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InvalidValueDef)
    ));
}

#[test]
fn ecode_verifier_rejects_register_write_with_wrong_domain() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let source = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 64),
        [],
    )
    .unwrap();

    let (_, written_results) = builder
        .emitter()
        .emit(
            ECodeOpSpec::new(ECodeOpcode::WriteRegister, 64).with_immediate(7),
            [source],
            1,
        )
        .unwrap();
    let written = IlValueId::try_from_index(written_results.start()).unwrap();
    builder
        .emitter()
        .set_value_domain(written, ECodeDomain::Flag(FlagId::new(7)))
        .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert_eq!(
        ir.verify(),
        Err(VerifyError::InconsistentValueDomain {
            value: written.value(),
        })
    );
}

#[test]
fn ecode_verifier_rejects_duplicate_memory_domains() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let space = AddressSpaceId::new(7);
    let ir = ECodeFixture::default()
        .with_memory_domains(vec![
            ECodeMemoryDomain::new(space),
            ECodeMemoryDomain::new(space),
        ])
        .build(metadata, IlGraph::default());

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::DuplicateMemoryDomain)
    ));
}

#[test]
fn ecode_verifier_rejects_load_without_memory_domain() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let space = AddressSpaceId::new(7);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    builder
        .emitter()
        .emit(
            ECodeOpSpec::new(ECodeOpcode::Load, 8).with_address_space(space),
            [],
            1,
        )
        .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::Il(IlError::MissingComponent { .. }))
    ));
}

#[test]
fn ecode_verifier_indexes_block_args_in_a_large_chain() {
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

    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, graph.build(1).unwrap());
    let mut incoming = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 64),
        [],
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
fn ecode_verifier_reports_invalid_store_result_count() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let space = AddressSpaceId::new(7);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    builder.emitter().intern_memory_domain(space);

    let pointer = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 64),
        [],
    )
    .unwrap();

    let value = emit_value(&mut builder, ECodeOpSpec::new(ECodeOpcode::Constant, 8), []).unwrap();

    let memory = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Undefined, 0),
        [],
    )
    .unwrap();

    builder
        .emitter()
        .emit(
            ECodeOpSpec::new(ECodeOpcode::Store, 0).with_address_space(space),
            [pointer, value, memory],
            0,
        )
        .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

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
fn ecode_verifier_rejects_wide_constant_beyond_pool() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let _value = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 128).with_immediate(100),
        [],
    )
    .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::Il(IlError::RangeOutOfBounds { .. }))
    ));
}

#[test]
fn ecode_verifier_rejects_operand_width_mismatch() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());

    let wide = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 64),
        [],
    )
    .unwrap();

    emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Add, 32),
        [wide, wide],
    )
    .unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::Il(IlError::WidthMismatch { .. }))
    ));
}

#[test]
fn ecode_verifier_accepts_wide_constant_within_pool() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());

    let source = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(0xabc),
        [],
    )
    .unwrap();

    let widened = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::ZeroExtend, 128),
        [source],
    )
    .unwrap();

    builder
        .emitter()
        .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [widened], 0)
        .unwrap();

    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    ir.verify().unwrap();

    ir.rewrite(ECodeConstantFolding);

    ir.verify().unwrap();
    assert_eq!(
        ir.constant_value(widened),
        Some(BitVec::from_u64(0xabc, 64).unsigned_cast(128))
    );
}

#[test]
fn ecode_verifier_bounds_wide_constant_at_pool_edge() {
    let wide_constant = |pool_len: usize| {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        ECodeFixture::default()
            .with_values(
                vec![ECodeValue::op_result(
                    128,
                    IlOpId::try_from_index(0).unwrap(),
                )],
                Vec::new(),
            )
            .with_operations(
                vec![
                    ECodeOp::new(
                        ECodeOpcode::Constant,
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
fn ecode_verifier_rejects_non_dominating_linear_use() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let value = IlValueId::try_from_index(0).unwrap();
    let result = IlIndexRange::new(0, 1).unwrap();
    let operands = IlIndexRange::new(0, 1).unwrap();
    let ir = ECodeFixture::default()
        .with_values(
            vec![ECodeValue::op_result(
                32,
                IlOpId::try_from_index(1).unwrap(),
            )],
            Vec::new(),
        )
        .with_operations(
            vec![
                ECodeOp::new(ECodeOpcode::Return, IlIndexRange::EMPTY, operands, 0),
                ECodeOp::new(ECodeOpcode::Constant, result, IlIndexRange::EMPTY, 32),
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
fn ecode_verifier_rejects_non_dominating_block_use() {
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
    let ir = ECodeFixture::default()
        .with_values(
            vec![ECodeValue::op_result(
                32,
                IlOpId::try_from_index(0).unwrap(),
            )],
            Vec::new(),
        )
        .with_operations(
            vec![
                ECodeOp::new(
                    ECodeOpcode::Constant,
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::EMPTY,
                    32,
                ),
                ECodeOp::new(
                    ECodeOpcode::Return,
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(0, 1).unwrap(),
                    0,
                ),
            ],
            vec![value],
        )
        .with_edge_arg_storage(vec![IlIndexRange::EMPTY; 2], Vec::new())
        .build(metadata, graph);

    let result = ir.verify();
    assert!(
        matches!(result, Err(VerifyError::NonDominatingUse { .. })),
        "{result:?}"
    );
}

#[test]
fn ecode_verifier_rejects_wrong_edge_arg_table_count() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
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
    let ir = ECodeFixture::default().build(metadata, graph);

    assert_eq!(
        ir.verify(),
        Err(VerifyError::EdgeArgTableCount {
            expected: 1,
            found: 0,
        })
    );
}

#[test]
fn ecode_verifier_rejects_wrong_edge_arg_count() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let successor = IlBlockId::try_from_index(1).unwrap();
    let arg_value = IlValueId::try_from_index(0).unwrap();
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
    let ir = ECodeFixture::default()
        .with_values(
            vec![ECodeValue::block_arg(
                32,
                IlBlockArgId::try_from_index(0).unwrap(),
            )],
            vec![ECodeBlockArg::new(successor, arg_value, 32)],
        )
        .with_edge_arg_storage(vec![IlIndexRange::EMPTY], Vec::new())
        .build(metadata, graph);

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::BlockArgCount { .. })
    ));
}

#[test]
fn ecode_verifier_rejects_non_dominating_edge_arg() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let left = IlBlockId::try_from_index(1).unwrap();
    let right = IlBlockId::try_from_index(2).unwrap();
    let value = IlValueId::try_from_index(0).unwrap();
    let arg_value = IlValueId::try_from_index(1).unwrap();
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
    let ir = ECodeFixture::default()
        .with_values(
            vec![
                ECodeValue::op_result(32, IlOpId::try_from_index(0).unwrap()),
                ECodeValue::block_arg(32, IlBlockArgId::try_from_index(0).unwrap()),
            ],
            vec![ECodeBlockArg::new(right, arg_value, 32)],
        )
        .with_operations(
            vec![ECodeOp::new(
                ECodeOpcode::Constant,
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::EMPTY,
                32,
            )],
            Vec::new(),
        )
        .with_edge_arg_storage(
            vec![IlIndexRange::EMPTY, IlIndexRange::new(0, 1).unwrap()],
            vec![value],
        )
        .build(metadata, graph);

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::NonDominatingEdgeArg { .. })
    ));
}

#[test]
fn ecode_verifier_rejects_duplicate_operation_placement() {
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
    let ir = ECodeFixture::default()
        .with_values(
            vec![ECodeValue::op_result(
                32,
                IlOpId::try_from_index(0).unwrap(),
            )],
            Vec::new(),
        )
        .with_operations(
            vec![ECodeOp::new(
                ECodeOpcode::Constant,
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
            StructureError::OverlappingBlockOps { .. }
        ))
    ));
}

#[test]
fn ecode_verifier_rejects_an_edge_arg_from_a_different_domain() {
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
    let mut builder = ECodeBuilder::new(IlMetadata::new(FunctionId::default(), 0), graph);

    let left = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Undefined, 64).with_immediate(16),
        [],
    )
    .unwrap();
    builder
        .emitter()
        .set_value_domain(left, ECodeDomain::Register(RegisterId::new(16)))
        .unwrap();
    let right = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Undefined, 64).with_immediate(24),
        [],
    )
    .unwrap();
    builder
        .emitter()
        .set_value_domain(right, ECodeDomain::Register(RegisterId::new(24)))
        .unwrap();

    let arg = builder.emitter().emit_block_arg(successor, 64).unwrap();
    builder
        .emitter()
        .set_value_domain(arg, ECodeDomain::Register(RegisterId::new(24)))
        .unwrap();
    builder.emitter().emit_edge_args([left]).unwrap();

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    assert!(matches!(
        ir.verify(),
        Err(VerifyError::InconsistentValueDomain { .. })
    ));
}

#[test]
fn ecode_verifier_checks_edge_arg_width_from_an_unreachable_block() {
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
    let mut builder = ECodeBuilder::new(IlMetadata::new(FunctionId::default(), 0), graph);
    let incoming = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 32),
        [],
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
