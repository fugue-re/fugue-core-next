use super::*;
use crate::il::common::{
    FlagId, IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlGraph, IlMetadata, IlOpId,
    IlParentSpan, IlSourceSpan, RegisterId,
};
use crate::il::ecode::transform::buffer::{
    PCodeToECodeBuffer, PCodeToECodeEffect, PCodeToECodeExpr, PCodeToECodeExprKind,
};
use crate::il::ecode::{ECodeOpcode, ECodeOptimiser};
use crate::ir::{Address, FunctionId};
use crate::storage::segments::space::AddressSpaceId;

struct PCodeToECodeBufferFixture {
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    buffer: PCodeToECodeBuffer,
}

struct PCodeToECodeBufferFixtureBuilder {
    fixture: PCodeToECodeBufferFixture,
}

impl PCodeToECodeBufferFixtureBuilder {
    fn new(metadata: IlMetadata, graph: IlGraph) -> Self {
        Self {
            fixture: PCodeToECodeBufferFixture {
                metadata,
                graph,
                source_spans: Vec::new(),
                parent_spans: Vec::new(),
                buffer: PCodeToECodeBuffer::default(),
            },
        }
    }

    fn push_expression(&mut self, expression: PCodeToECodeExpr) -> Result<IlExprId, IlError> {
        self.fixture.buffer.push_expression(expression)
    }

    fn push_expression_operands(
        &mut self,
        operands: impl IntoIterator<Item = IlExprId>,
    ) -> Result<IlIndexRange, IlError> {
        self.fixture.buffer.push_expression_operands(operands)
    }

    fn push_statement(&mut self, operation: PCodeToECodeEffect) -> Result<IlOpId, IlError> {
        self.fixture.buffer.push_op(operation)
    }

    fn push_effect_operands(
        &mut self,
        operands: impl IntoIterator<Item = IlExprId>,
    ) -> Result<IlIndexRange, IlError> {
        self.fixture.buffer.push_op_operands(operands)
    }

    fn set_call_preserved_registers(&mut self, registers: Vec<RegisterId>) {
        self.fixture.buffer.set_call_preserved_registers(registers);
    }

    fn set_parent_spans(&mut self, spans: Vec<IlParentSpan>) {
        self.fixture.parent_spans = spans;
    }

    fn set_source_spans(&mut self, spans: Vec<IlSourceSpan>) {
        self.fixture.source_spans = spans;
    }

    fn build(self, cancellation: &CancellationToken) -> Result<PCodeToECodeBufferFixture, IlError> {
        cancellation.check()?;
        Ok(self.fixture)
    }
}

#[derive(Default)]
struct ECodeFixtureBuilder {
    scratch: PCodeToECodeSsaScratch,
}

impl ECodeFixtureBuilder {
    fn build(
        &mut self,
        fixture: PCodeToECodeBufferFixture,
        cancellation: &CancellationToken,
    ) -> Result<ECodeIr, IlError> {
        let builder = ECodeBuilder::new(fixture.metadata, IlGraph::default());
        PCodeToECodeSsaLifter::new(
            fixture.buffer,
            fixture.graph,
            fixture.source_spans,
            fixture.parent_spans,
            builder,
            &mut self.scratch,
        )
        .lift(cancellation)
    }

    fn build_optimised(
        &mut self,
        fixture: PCodeToECodeBufferFixture,
        cancellation: &CancellationToken,
    ) -> Result<ECodeIr, IlError> {
        let mut ir = self.build(fixture, cancellation)?;
        ir.rewrite(ECodeOptimiser);
        Ok(ir)
    }
}

#[test]
fn empty_ecode_constructs_empty_body() {
    let source_metadata = IlMetadata::new(FunctionId::default(), 11);
    let source = PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default())
        .build(&CancellationToken::default())
        .unwrap();
    let cancellation = CancellationToken::default();
    let mut transform = ECodeFixtureBuilder::default();

    let ir = transform.build(source, &cancellation).unwrap();

    assert_eq!(ir.metadata().input_revision().value(), 11);
    assert!(ir.ops().is_empty());
}

#[test]
fn register_read_after_write_uses_current_value() {
    let source_metadata = IlMetadata::new(FunctionId::default(), 11);
    let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());
    let value = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            64,
            IlIndexRange::EMPTY,
            0x2a,
            None,
        ))
        .unwrap();

    builder
        .push_statement(
            PCodeToECodeEffect::new(
                ECodeOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(value),
                None,
                None,
            )
            .with_immediate(7),
        )
        .unwrap();

    let read = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::ReadRegister,
            64,
            IlIndexRange::EMPTY,
            7,
            None,
        ))
        .unwrap();
    let operands = builder.push_effect_operands([read]).unwrap();

    builder
        .push_statement(PCodeToECodeEffect::new(
            ECodeOpcode::Return,
            operands,
            None,
            None,
            None,
        ))
        .unwrap();
    builder.set_parent_spans(vec![IlParentSpan::new(
        IlIndexRange::new(0, 2).unwrap(),
        IlIndexRange::new(4, 6).unwrap(),
    )]);

    let source = builder.build(&CancellationToken::default()).unwrap();
    let cancellation = CancellationToken::default();
    let mut transform = ECodeFixtureBuilder::default();
    let ir = transform.build(source, &cancellation).unwrap();

    assert_eq!(ir.ops()[0].opcode(), ECodeOpcode::Constant);
    assert_eq!(ir.ops()[1].opcode(), ECodeOpcode::WriteRegister);
    assert_eq!(ir.ops()[2].opcode(), ECodeOpcode::Return);
    assert_eq!(ir.op_operands().len(), 2);
    assert_eq!(
        ir.op_operands_for(&ir.ops()[2]),
        &[IlValueId::try_from_index(ir.ops()[1].results().start()).unwrap()]
    );
    assert_eq!(
        ir.parent_spans(),
        &[IlParentSpan::new(
            IlIndexRange::new(0, 3).unwrap(),
            IlIndexRange::new(4, 6).unwrap(),
        )]
    );
}

#[test]
fn call_preserves_only_declared_register_state() {
    let source_metadata = IlMetadata::new(FunctionId::default(), 11);
    let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());
    builder.set_call_preserved_registers(vec![RegisterId::new(7)]);
    let preserved = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            64,
            IlIndexRange::EMPTY,
            0x2a,
            None,
        ))
        .unwrap();
    builder
        .push_statement(
            PCodeToECodeEffect::new(
                ECodeOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(preserved),
                None,
                None,
            )
            .with_immediate(7),
        )
        .unwrap();
    let clobbered = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            64,
            IlIndexRange::EMPTY,
            0x2b,
            None,
        ))
        .unwrap();
    builder
        .push_statement(
            PCodeToECodeEffect::new(
                ECodeOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(clobbered),
                None,
                None,
            )
            .with_immediate(8),
        )
        .unwrap();
    builder
        .push_statement(PCodeToECodeEffect::new(
            ECodeOpcode::Call,
            IlIndexRange::EMPTY,
            None,
            Some(Address::from(0x2000u64)),
            None,
        ))
        .unwrap();
    let read_preserved = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::ReadRegister,
            64,
            IlIndexRange::EMPTY,
            7,
            None,
        ))
        .unwrap();
    let read_clobbered = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::ReadRegister,
            64,
            IlIndexRange::EMPTY,
            8,
            None,
        ))
        .unwrap();
    let operands = builder
        .push_effect_operands([read_preserved, read_clobbered])
        .unwrap();
    builder
        .push_statement(PCodeToECodeEffect::new(
            ECodeOpcode::Return,
            operands,
            None,
            None,
            None,
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let ir = ECodeFixtureBuilder::default()
        .build(source, &CancellationToken::default())
        .unwrap();

    assert_eq!(ir.ops()[0].opcode(), ECodeOpcode::Constant);
    assert_eq!(ir.ops()[1].opcode(), ECodeOpcode::WriteRegister);
    assert_eq!(ir.ops()[2].opcode(), ECodeOpcode::Constant);
    assert_eq!(ir.ops()[3].opcode(), ECodeOpcode::WriteRegister);
    assert_eq!(ir.ops()[4].opcode(), ECodeOpcode::Call);
    assert_eq!(ir.ops()[5].opcode(), ECodeOpcode::Undefined);
    assert_eq!(ir.ops()[6].opcode(), ECodeOpcode::Return);
    assert_eq!(
        ir.op_operands_for(&ir.ops()[6]),
        &[
            IlValueId::try_from_index(ir.ops()[1].results().start()).unwrap(),
            IlValueId::try_from_index(ir.ops()[5].results().start()).unwrap(),
        ]
    );
}

#[test]
fn insn_wide_expression_is_not_rebuilt_after_register_write() {
    let source_metadata = IlMetadata::new(FunctionId::default(), 11);
    let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());
    let register = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::ReadRegister,
            64,
            IlIndexRange::EMPTY,
            7,
            None,
        ))
        .unwrap();
    let decrement = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            64,
            IlIndexRange::EMPTY,
            8,
            None,
        ))
        .unwrap();
    let subtract_operands = builder
        .push_expression_operands([register, decrement])
        .unwrap();
    let address = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Sub),
            64,
            subtract_operands,
            0,
            None,
        ))
        .unwrap();
    builder
        .push_statement(
            PCodeToECodeEffect::new(
                ECodeOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(address),
                None,
                None,
            )
            .with_immediate(7),
        )
        .unwrap();

    let value = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            64,
            IlIndexRange::EMPTY,
            0x2a,
            None,
        ))
        .unwrap();
    let store_operands = builder.push_effect_operands([address, value]).unwrap();
    builder
        .push_statement(PCodeToECodeEffect::new(
            ECodeOpcode::Store,
            store_operands,
            None,
            None,
            Some(AddressSpaceId::new(1)),
        ))
        .unwrap();
    builder.set_source_spans(vec![IlSourceSpan::new(
        IlIndexRange::new(0, 2).unwrap(),
        Address::from(0x1000u64),
        0,
        1,
    )]);

    let source = builder.build(&CancellationToken::default()).unwrap();
    let ir = ECodeFixtureBuilder::default()
        .build(source, &CancellationToken::default())
        .unwrap();
    let subtracts = ir
        .ops()
        .iter()
        .enumerate()
        .filter(|(_, operation)| operation.opcode() == ECodeOpcode::Sub)
        .collect::<Vec<_>>();
    assert_eq!(subtracts.len(), 1);
    let address_value =
        IlValueId::try_from_index(subtracts[0].1.results().start()).expect("result must exist");
    let store = ir
        .ops()
        .iter()
        .find(|operation| operation.opcode() == ECodeOpcode::Store)
        .expect("store must exist");
    assert_eq!(ir.op_operands_for(store)[0], address_value);
}

#[test]
fn register_read_without_write_becomes_undefined() {
    let source_metadata = IlMetadata::new(FunctionId::default(), 11);
    let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());
    let read = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::ReadRegister,
            32,
            IlIndexRange::EMPTY,
            9,
            None,
        ))
        .unwrap();
    let operands = builder.push_effect_operands([read]).unwrap();

    builder
        .push_statement(PCodeToECodeEffect::new(
            ECodeOpcode::Return,
            operands,
            None,
            None,
            None,
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let cancellation = CancellationToken::default();
    let mut transform = ECodeFixtureBuilder::default();
    let ir = transform.build(source, &cancellation).unwrap();

    assert_eq!(ir.ops()[0].opcode(), ECodeOpcode::Undefined);
    assert_eq!(ir.ops()[0].width(), 32);
    assert_eq!(ir.ops()[0].immediate(), 9);
    assert_eq!(ir.ops()[1].opcode(), ECodeOpcode::Return);
}

#[test]
fn load_preserves_fugue_address_space() {
    let source_metadata = IlMetadata::new(FunctionId::default(), 11);
    let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());
    let offset = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            64,
            IlIndexRange::EMPTY,
            0x1000,
            None,
        ))
        .unwrap();
    let load_operands = builder.push_expression_operands([offset]).unwrap();
    let space = AddressSpaceId::new(3);
    let load = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Load),
            8,
            load_operands,
            0,
            Some(space),
        ))
        .unwrap();
    let return_operands = builder.push_effect_operands([load]).unwrap();

    builder
        .push_statement(PCodeToECodeEffect::new(
            ECodeOpcode::Return,
            return_operands,
            None,
            None,
            None,
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let cancellation = CancellationToken::default();
    let mut transform = ECodeFixtureBuilder::default();
    let ir = transform.build(source, &cancellation).unwrap();

    let load_index = ir
        .ops()
        .iter()
        .position(|operation| operation.opcode() == ECodeOpcode::Load)
        .unwrap();

    assert_eq!(ir.ops()[load_index].address_space(), Some(space));
    assert_eq!(ir.memory_domains().len(), 1);
    assert_eq!(ir.memory_domains()[0].space(), space);

    let memory = ir.values()[ir
        .memory_operand(&ir.ops()[load_index])
        .unwrap()
        .index()];

    assert_eq!(memory.width(), 0);
}

#[test]
fn load_after_store_uses_store_memory_result() {
    let source_metadata = IlMetadata::new(FunctionId::default(), 11);
    let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());
    let space = AddressSpaceId::new(3);
    let store_address = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            64,
            IlIndexRange::EMPTY,
            0x1000,
            None,
        ))
        .unwrap();
    let store_value = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            32,
            IlIndexRange::EMPTY,
            0x2a,
            None,
        ))
        .unwrap();
    let store_operands = builder
        .push_effect_operands([store_address, store_value])
        .unwrap();

    builder
        .push_statement(PCodeToECodeEffect::new(
            ECodeOpcode::Store,
            store_operands,
            None,
            None,
            Some(space),
        ))
        .unwrap();

    let load_address = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            64,
            IlIndexRange::EMPTY,
            0x1000,
            None,
        ))
        .unwrap();
    let load_operands = builder.push_expression_operands([load_address]).unwrap();
    let load = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Load),
            32,
            load_operands,
            0,
            Some(space),
        ))
        .unwrap();
    let return_operands = builder.push_effect_operands([load]).unwrap();

    builder
        .push_statement(PCodeToECodeEffect::new(
            ECodeOpcode::Return,
            return_operands,
            None,
            None,
            None,
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let cancellation = CancellationToken::default();
    let mut transform = ECodeFixtureBuilder::default();
    let ir = transform.build(source, &cancellation).unwrap();
    let store_index = ir
        .ops()
        .iter()
        .position(|operation| operation.opcode() == ECodeOpcode::Store)
        .unwrap();
    let load_index = ir
        .ops()
        .iter()
        .position(|operation| operation.opcode() == ECodeOpcode::Load)
        .unwrap();
    let store_memory =
        IlValueId::try_from_index(ir.ops()[store_index].results().start()).unwrap();
    let load_operands = ir.op_operands_for(&ir.ops()[load_index]);

    assert_eq!(ir.memory_domains().len(), 1);
    assert_eq!(ir.memory_domains()[0].space(), space);
    assert_eq!(ir.values()[store_memory.index()].width(), 0);
    assert_eq!(*load_operands.last().unwrap(), store_memory);
}

#[test]
fn store_without_load_registers_memory_domain() {
    let source_metadata = IlMetadata::new(FunctionId::default(), 11);
    let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());
    let space = AddressSpaceId::new(3);
    let address = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            64,
            IlIndexRange::EMPTY,
            0x1000,
            None,
        ))
        .unwrap();
    let value = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            32,
            IlIndexRange::EMPTY,
            0x2a,
            None,
        ))
        .unwrap();
    let operands = builder.push_effect_operands([address, value]).unwrap();

    builder
        .push_statement(PCodeToECodeEffect::new(
            ECodeOpcode::Store,
            operands,
            None,
            None,
            Some(space),
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let mut transform = ECodeFixtureBuilder::default();
    let ir = transform
        .build_optimised(source, &CancellationToken::default())
        .unwrap();

    ir.verify().unwrap();

    assert_eq!(ir.memory_domains().len(), 1);
    assert_eq!(ir.memory_domains()[0].space(), space);
}

#[test]
fn direct_branch_preserves_fugue_address() {
    let source_metadata = IlMetadata::new(FunctionId::default(), 11);
    let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());
    let condition = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            1,
            IlIndexRange::EMPTY,
            1,
            None,
        ))
        .unwrap();
    let target_expression = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            64,
            IlIndexRange::EMPTY,
            0x2000,
            None,
        ))
        .unwrap();
    let operands = builder
        .push_effect_operands([condition, target_expression])
        .unwrap();
    let target = Address::new(AddressSpaceId::new(4), 0x2000u64);

    builder
        .push_statement(PCodeToECodeEffect::new(
            ECodeOpcode::ConditionalBranch,
            operands,
            None,
            Some(target),
            None,
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let cancellation = CancellationToken::default();
    let mut transform = ECodeFixtureBuilder::default();
    let ir = transform.build(source, &cancellation).unwrap();

    assert_eq!(ir.ops()[2].opcode(), ECodeOpcode::ConditionalBranch);
    assert_eq!(ir.ops()[2].address(), Some(target));
}

#[test]
fn deep_dominance_chain_constructs_iteratively() {
    let source_metadata = IlMetadata::new(FunctionId::default(), 11);
    let block_count = 128usize;
    let mut successors = Vec::new();
    let mut blocks = Vec::new();

    for index in 0..block_count {
        let mut flags = IlBlockProperties::empty();
        if index == 0 {
            flags |= IlBlockProperties::ENTRY;
        }
        if index + 1 == block_count {
            flags |= IlBlockProperties::EXIT;
        }

        let successor_range = if index + 1 == block_count {
            IlIndexRange::EMPTY
        } else {
            successors.push(IlBlockId::try_from_index(index + 1).unwrap());
            IlIndexRange::new(successors.len() - 1, successors.len()).unwrap()
        };

        blocks.push(IlBlock::new(
            IlIndexRange::new(index, index + 1).unwrap(),
            successor_range,
            flags,
        ));
    }

    let successor_kinds = vec![IlEdgeKinds::UNCONDITIONAL; successors.len()];
    let graph = IlGraph::new(blocks, successors, successor_kinds);
    let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, graph);

    for index in 0..block_count {
        let value = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                index as u64,
                None,
            ))
            .unwrap();

        builder
            .push_statement(
                PCodeToECodeEffect::new(
                    ECodeOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(value),
                    None,
                    None,
                )
                .with_immediate(7),
            )
            .unwrap();
    }

    let source = builder.build(&CancellationToken::default()).unwrap();
    let cancellation = CancellationToken::default();
    let mut transform = ECodeFixtureBuilder::default();
    let ir = transform.build(source, &cancellation).unwrap();

    assert_eq!(ir.graph().blocks().len(), block_count);
    assert_eq!(ir.graph().successors().len(), block_count - 1);
    assert_eq!(ir.ops().len(), block_count * 2);
    assert!(ir.block_args().is_empty());
}

#[test]
fn branch_heavy_ssa_restores_live_domains_between_siblings() {
    const DOMAIN_COUNT: usize = 64;

    let left = IlBlockId::try_from_index(1).unwrap();
    let right = IlBlockId::try_from_index(2).unwrap();
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::new(0, DOMAIN_COUNT).unwrap(),
                IlIndexRange::new(0, 2).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(DOMAIN_COUNT, DOMAIN_COUNT * 2).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
            IlBlock::new(
                IlIndexRange::new(DOMAIN_COUNT * 2, DOMAIN_COUNT * 2 + 1).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        vec![left, right],
        vec![IlEdgeKinds::FALL_THROUGH, IlEdgeKinds::TAKEN],
    );
    let metadata = IlMetadata::new(FunctionId::default(), 11);
    let mut builder = PCodeToECodeBufferFixtureBuilder::new(metadata, graph);

    for register in 0..DOMAIN_COUNT {
        let value = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                register as u64,
                None,
            ))
            .unwrap();
        builder
            .push_statement(
                PCodeToECodeEffect::new(
                    ECodeOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(value),
                    None,
                    None,
                )
                .with_immediate(register as u64),
            )
            .unwrap();
    }
    for register in 0..DOMAIN_COUNT {
        let value = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                0x1000 + register as u64,
                None,
            ))
            .unwrap();
        builder
            .push_statement(
                PCodeToECodeEffect::new(
                    ECodeOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(value),
                    None,
                    None,
                )
                .with_immediate(register as u64),
            )
            .unwrap();
    }
    let reads = (0..DOMAIN_COUNT)
        .map(|register| {
            builder.push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::ReadRegister,
                64,
                IlIndexRange::EMPTY,
                register as u64,
                None,
            ))
        })
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let operands = builder.push_effect_operands(reads).unwrap();
    builder
        .push_statement(PCodeToECodeEffect::new(
            ECodeOpcode::Return,
            operands,
            None,
            None,
            None,
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let ir = ECodeFixtureBuilder::default()
        .build(source, &CancellationToken::default())
        .unwrap();
    let returned = ir
        .ops()
        .iter()
        .find(|operation| operation.opcode() == ECodeOpcode::Return)
        .map(|operation| ir.op_operands_for(operation))
        .expect("the right sibling retains its return");

    assert_eq!(returned.len(), DOMAIN_COUNT);
    for (register, value) in returned.iter().copied().enumerate() {
        let write = ir
            .defining_op(value)
            .expect("each returned register has a reaching definition");
        let source = ir.op_operands_for(write)[0];
        let constant = ir
            .defining_op(source)
            .expect("each reaching definition has a constant source");
        assert_eq!(constant.immediate(), register as u64);
    }
}

#[test]
fn merge_block_register_read_becomes_block_arg() {
    let source_metadata = IlMetadata::new(FunctionId::default(), 11);
    let successors = vec![
        IlBlockId::try_from_index(1).unwrap(),
        IlBlockId::try_from_index(2).unwrap(),
        IlBlockId::try_from_index(3).unwrap(),
        IlBlockId::try_from_index(3).unwrap(),
    ];
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::new(0, 2).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::new(2, 3).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::new(1, 2).unwrap(),
                IlIndexRange::new(3, 4).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::new(2, 3).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        successors.clone(),
        vec![IlEdgeKinds::UNCONDITIONAL; successors.len()],
    );
    let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, graph);
    let left = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            64,
            IlIndexRange::EMPTY,
            1,
            None,
        ))
        .unwrap();
    let right = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            64,
            IlIndexRange::EMPTY,
            2,
            None,
        ))
        .unwrap();
    let read = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::ReadRegister,
            64,
            IlIndexRange::EMPTY,
            7,
            None,
        ))
        .unwrap();

    builder
        .push_statement(
            PCodeToECodeEffect::new(
                ECodeOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(left),
                None,
                None,
            )
            .with_immediate(7),
        )
        .unwrap();
    builder
        .push_statement(
            PCodeToECodeEffect::new(
                ECodeOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(right),
                None,
                None,
            )
            .with_immediate(7),
        )
        .unwrap();
    let operands = builder.push_effect_operands([read]).unwrap();
    builder
        .push_statement(PCodeToECodeEffect::new(
            ECodeOpcode::Return,
            operands,
            None,
            None,
            None,
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let cancellation = CancellationToken::default();
    let mut transform = ECodeFixtureBuilder::default();
    let ir = transform.build(source, &cancellation).unwrap();

    assert_eq!(ir.block_args().len(), 1);
    assert_eq!(
        ir.block_args()[0].block(),
        IlBlockId::try_from_index(3).unwrap()
    );
    let return_operation = ir
        .ops()
        .iter()
        .find(|operation| operation.opcode() == ECodeOpcode::Return)
        .unwrap();
    assert_eq!(
        ir.op_operands_for(return_operation),
        &[ir.block_args()[0].value()]
    );
    assert_eq!(ir.edge_args().len(), 4);
    assert_eq!(ir.edge_arg_values().len(), 2);
    assert!(ir.edge_args()[0].is_empty());
    assert!(ir.edge_args()[1].is_empty());
    assert_eq!(ir.args_for_edge(2).len(), 1);
    assert_eq!(ir.args_for_edge(3).len(), 1);
}

#[test]
fn merge_block_load_uses_memory_block_arg() {
    let source_metadata = IlMetadata::new(FunctionId::default(), 11);
    let join = IlBlockId::try_from_index(3).unwrap();
    let successors = vec![
        IlBlockId::try_from_index(1).unwrap(),
        IlBlockId::try_from_index(2).unwrap(),
        join,
        join,
    ];
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::new(0, 2).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::new(2, 3).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::new(3, 4).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::new(1, 2).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        successors.clone(),
        vec![IlEdgeKinds::UNCONDITIONAL; successors.len()],
    );
    let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, graph);
    let space = AddressSpaceId::new(3);
    let store_address = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            64,
            IlIndexRange::EMPTY,
            0x1000,
            None,
        ))
        .unwrap();
    let store_value = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            32,
            IlIndexRange::EMPTY,
            0x2a,
            None,
        ))
        .unwrap();
    let load_address = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            64,
            IlIndexRange::EMPTY,
            0x1000,
            None,
        ))
        .unwrap();
    let load_operands = builder.push_expression_operands([load_address]).unwrap();
    let load = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Load),
            32,
            load_operands,
            0,
            Some(space),
        ))
        .unwrap();
    let store_operands = builder
        .push_effect_operands([store_address, store_value])
        .unwrap();

    builder
        .push_statement(PCodeToECodeEffect::new(
            ECodeOpcode::Store,
            store_operands,
            None,
            None,
            Some(space),
        ))
        .unwrap();

    let return_operands = builder.push_effect_operands([load]).unwrap();

    builder
        .push_statement(PCodeToECodeEffect::new(
            ECodeOpcode::Return,
            return_operands,
            None,
            None,
            None,
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let cancellation = CancellationToken::default();
    let mut transform = ECodeFixtureBuilder::default();
    let ir = transform.build(source, &cancellation).unwrap();
    let load_index = ir
        .ops()
        .iter()
        .position(|operation| operation.opcode() == ECodeOpcode::Load)
        .unwrap();
    let load_operands = ir.op_operands_for(&ir.ops()[load_index]);

    assert_eq!(ir.memory_domains().len(), 1);
    assert_eq!(ir.memory_domains()[0].space(), space);
    assert_eq!(ir.block_args().len(), 1);
    assert_eq!(ir.block_args()[0].block(), join);
    assert_eq!(ir.values()[ir.block_args()[0].value().index()].width(), 0);
    assert_eq!(*load_operands.last().unwrap(), ir.block_args()[0].value());
    assert!(ir.args_for_edge(0).is_empty());
    assert!(ir.args_for_edge(1).is_empty());
    assert_eq!(ir.args_for_edge(2).len(), 1);
    assert_eq!(ir.args_for_edge(3).len(), 1);
}

#[test]
fn loop_carried_register_uses_header_block_arg() {
    let source_metadata = IlMetadata::new(FunctionId::default(), 11);
    let loop_header = IlBlockId::try_from_index(1).unwrap();
    let loop_body = IlBlockId::try_from_index(2).unwrap();
    let exit = IlBlockId::try_from_index(3).unwrap();
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::new(0, 1).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::new(1, 2).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::new(1, 2).unwrap(),
                IlIndexRange::new(2, 4).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        vec![loop_header, loop_body, loop_header, exit],
        vec![IlEdgeKinds::UNCONDITIONAL; 4],
    );
    let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, graph);
    let read = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::ReadRegister,
            32,
            IlIndexRange::EMPTY,
            9,
            None,
        ))
        .unwrap();
    let constant = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            32,
            IlIndexRange::EMPTY,
            1,
            None,
        ))
        .unwrap();
    let return_operands = builder.push_effect_operands([read]).unwrap();

    builder
        .push_statement(PCodeToECodeEffect::new(
            ECodeOpcode::Return,
            return_operands,
            None,
            None,
            None,
        ))
        .unwrap();
    builder
        .push_statement(
            PCodeToECodeEffect::new(
                ECodeOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(constant),
                None,
                None,
            )
            .with_immediate(9),
        )
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let cancellation = CancellationToken::default();
    let mut transform = ECodeFixtureBuilder::default();
    let ir = transform.build(source, &cancellation).unwrap();

    assert_eq!(ir.block_args().len(), 1);
    assert_eq!(ir.block_args()[0].block(), loop_header);
    assert_eq!(ir.op_operands()[0], ir.block_args()[0].value());
    assert_eq!(ir.args_for_edge(0).len(), 1);
    assert_eq!(ir.args_for_edge(2).len(), 1);

    let entry_value = ir.args_for_edge(0)[0];
    let back_edge_value = ir.args_for_edge(2)[0];

    assert_eq!(
        ir.defining_op(entry_value).unwrap().opcode(),
        ECodeOpcode::Undefined
    );
    assert_eq!(
        ir.defining_op(back_edge_value).unwrap().opcode(),
        ECodeOpcode::WriteRegister
    );
}

#[test]
fn value_domains_create_distinct_register_and_flag_definitions() {
    let source_metadata = IlMetadata::new(FunctionId::default(), 11);
    let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());

    let source_value = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            8,
            IlIndexRange::EMPTY,
            0x2a,
            None,
        ))
        .unwrap();
    builder
        .push_statement(
            PCodeToECodeEffect::new(
                ECodeOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(source_value),
                None,
                None,
            )
            .with_immediate(7),
        )
        .unwrap();

    builder
        .push_statement(
            PCodeToECodeEffect::new(
                ECodeOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(source_value),
                None,
                None,
            )
            .with_immediate(8),
        )
        .unwrap();
    builder
        .push_statement(
            PCodeToECodeEffect::new(
                ECodeOpcode::WriteFlag,
                IlIndexRange::EMPTY,
                Some(source_value),
                None,
                None,
            )
            .with_immediate(3),
        )
        .unwrap();

    let register_seven = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::ReadRegister,
            8,
            IlIndexRange::EMPTY,
            7,
            None,
        ))
        .unwrap();
    let register_eight = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::ReadRegister,
            8,
            IlIndexRange::EMPTY,
            8,
            None,
        ))
        .unwrap();
    let flag = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::ReadFlag,
            8,
            IlIndexRange::EMPTY,
            3,
            None,
        ))
        .unwrap();
    let operands = builder
        .push_effect_operands([register_seven, register_eight, flag])
        .unwrap();
    builder
        .push_statement(PCodeToECodeEffect::new(
            ECodeOpcode::Return,
            operands,
            None,
            None,
            None,
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let mut transform = ECodeFixtureBuilder::default();
    let ir = transform
        .build_optimised(source, &CancellationToken::default())
        .unwrap();

    assert_eq!(ir.ops()[0].opcode(), ECodeOpcode::Constant);
    assert_eq!(ir.ops()[1].opcode(), ECodeOpcode::WriteRegister);
    assert_eq!(ir.ops()[2].opcode(), ECodeOpcode::WriteRegister);
    assert_eq!(ir.ops()[3].opcode(), ECodeOpcode::WriteFlag);
    assert_eq!(ir.ops()[4].opcode(), ECodeOpcode::Return);

    let register_seven = IlValueId::try_from_index(ir.ops()[1].results().start()).unwrap();
    let register_eight = IlValueId::try_from_index(ir.ops()[2].results().start()).unwrap();
    let flag = IlValueId::try_from_index(ir.ops()[3].results().start()).unwrap();

    assert_eq!(
        ir.value_domain(register_seven),
        Some(ECodeDomain::Register(RegisterId::new(7)))
    );
    assert_eq!(
        ir.value_domain(register_eight),
        Some(ECodeDomain::Register(RegisterId::new(8)))
    );
    assert_eq!(
        ir.value_domain(flag),
        Some(ECodeDomain::Flag(FlagId::new(3)))
    );
    assert_eq!(
        ir.constant_value(register_seven)
            .and_then(|value| value.to_u64()),
        Some(0x2a)
    );
    assert_eq!(
        ir.op_operands_for(&ir.ops()[4]),
        &[register_seven, register_eight, flag]
    );

    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&ir).unwrap();
    let restored = rkyv::from_bytes::<ECodeIr, rkyv::rancor::Error>(&bytes).unwrap();

    assert_eq!(restored, ir);
}

#[test]
fn value_domains_survive_compaction_and_rkyv() {
    let source_metadata = IlMetadata::new(FunctionId::default(), 11);
    let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());

    let written = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            64,
            IlIndexRange::EMPTY,
            0x2a,
            None,
        ))
        .unwrap();
    builder
        .push_statement(
            PCodeToECodeEffect::new(
                ECodeOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(written),
                None,
                None,
            )
            .with_immediate(7),
        )
        .unwrap();

    let read = builder
        .push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::ReadRegister,
            64,
            IlIndexRange::EMPTY,
            7,
            None,
        ))
        .unwrap();
    let operands = builder.push_effect_operands([read]).unwrap();
    builder
        .push_statement(PCodeToECodeEffect::new(
            ECodeOpcode::Return,
            operands,
            None,
            None,
            None,
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let mut transform = ECodeFixtureBuilder::default();
    let ir = transform
        .build_optimised(source, &CancellationToken::default())
        .unwrap();

    let carries_register = |ir: &ECodeIr| {
        (0..ir.values().len()).any(|index| {
            ir.value_domain(IlValueId::try_from_index(index).unwrap())
                == Some(ECodeDomain::Register(RegisterId::new(7)))
        })
    };

    assert!(carries_register(&ir));

    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&ir).unwrap();
    let restored = rkyv::from_bytes::<ECodeIr, rkyv::rancor::Error>(&bytes).unwrap();

    assert!(carries_register(&restored));
}
