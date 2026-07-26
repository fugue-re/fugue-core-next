use super::*;
use crate::il::common::{
    IlBlock, IlBlockId, IlBlockProperties, IlGraph, IlParentSpan, IlSourceSpan,
};
use crate::il::ecode::ssa::ECodeSsaOpcode;
use crate::il::ecode::{
    ECODE_SCHEMA_VERSION, ECodeBuilder, ECodeExpr, ECodeExprOpcode, ECodeStmt, ECodeStmtOpcode,
};
use crate::il::pcode::RegisterId;
use crate::ir::{Address, FunctionId};
use crate::storage::segments::space::AddressSpaceId;

#[test]
fn empty_ecode_constructs_empty_ssa() {
    let source_header = IlMetadata::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
    let source = ECodeBuilder::new(source_header, IlGraph::default())
        .build(&CancellationToken::default())
        .unwrap();
    let cancellation = CancellationToken::default();
    let mut transform = ECodeToSsa::default();

    let ssa = transform.transform(&source, &cancellation).unwrap();

    assert_eq!(ssa.metadata().input_revision().value(), 11);
    assert!(ssa.operations().is_empty());
}

#[test]
fn register_read_after_write_uses_current_value() {
    let source_header = IlMetadata::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
    let mut builder = ECodeBuilder::new(source_header, IlGraph::default());
    let value = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            64,
            IlIndexRange::EMPTY,
            0x2a,
            None,
        ))
        .unwrap();

    builder
        .push_statement(
            ECodeStmt::new(
                ECodeStmtOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(value),
                None,
                None,
            )
            .with_immediate(7),
        )
        .unwrap();

    let read = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::ReadRegister,
            64,
            IlIndexRange::EMPTY,
            7,
            None,
        ))
        .unwrap();
    let operands = builder.push_statement_operands([read]).unwrap();

    builder
        .push_statement(ECodeStmt::new(
            ECodeStmtOpcode::Return,
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
    let mut transform = ECodeToSsa::default();
    let ssa = transform.transform(&source, &cancellation).unwrap();

    assert_eq!(ssa.operations()[0].opcode(), ECodeSsaOpcode::Constant);
    assert_eq!(ssa.operations()[1].opcode(), ECodeSsaOpcode::Return);
    assert_eq!(ssa.value_operands().len(), 1);
    assert_eq!(
        ssa.value_operands()[0],
        IlValueId::try_from_index(ssa.operations()[0].results().start()).unwrap()
    );
    assert_eq!(
        ssa.parent_spans(),
        &[IlParentSpan::new(
            IlIndexRange::new(0, 2).unwrap(),
            IlIndexRange::new(4, 6).unwrap(),
        )]
    );
}

#[test]
fn call_preserves_only_declared_register_state() {
    let source_header = IlMetadata::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
    let mut builder = ECodeBuilder::new(source_header, IlGraph::default());
    builder.set_call_preserved_registers(vec![RegisterId::new(7)]);
    let preserved = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            64,
            IlIndexRange::EMPTY,
            0x2a,
            None,
        ))
        .unwrap();
    builder
        .push_statement(
            ECodeStmt::new(
                ECodeStmtOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(preserved),
                None,
                None,
            )
            .with_immediate(7),
        )
        .unwrap();
    let clobbered = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            64,
            IlIndexRange::EMPTY,
            0x2b,
            None,
        ))
        .unwrap();
    builder
        .push_statement(
            ECodeStmt::new(
                ECodeStmtOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(clobbered),
                None,
                None,
            )
            .with_immediate(8),
        )
        .unwrap();
    builder
        .push_statement(ECodeStmt::new(
            ECodeStmtOpcode::Call,
            IlIndexRange::EMPTY,
            None,
            Some(Address::from(0x2000u64)),
            None,
        ))
        .unwrap();
    let read_preserved = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::ReadRegister,
            64,
            IlIndexRange::EMPTY,
            7,
            None,
        ))
        .unwrap();
    let read_clobbered = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::ReadRegister,
            64,
            IlIndexRange::EMPTY,
            8,
            None,
        ))
        .unwrap();
    let operands = builder
        .push_statement_operands([read_preserved, read_clobbered])
        .unwrap();
    builder
        .push_statement(ECodeStmt::new(
            ECodeStmtOpcode::Return,
            operands,
            None,
            None,
            None,
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let ssa = ECodeToSsa::default()
        .transform(&source, &CancellationToken::default())
        .unwrap();

    assert_eq!(ssa.operations()[0].opcode(), ECodeSsaOpcode::Constant);
    assert_eq!(ssa.operations()[1].opcode(), ECodeSsaOpcode::Constant);
    assert_eq!(ssa.operations()[2].opcode(), ECodeSsaOpcode::Call);
    assert_eq!(ssa.operations()[3].opcode(), ECodeSsaOpcode::Undefined);
    assert_eq!(ssa.operations()[4].opcode(), ECodeSsaOpcode::Return);
    assert_eq!(
        ssa.operation_operands(&ssa.operations()[4]),
        &[
            IlValueId::try_from_index(ssa.operations()[0].results().start()).unwrap(),
            IlValueId::try_from_index(ssa.operations()[3].results().start()).unwrap(),
        ]
    );
}

#[test]
fn instruction_wide_expression_is_not_rebuilt_after_register_write() {
    let source_header = IlMetadata::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
    let mut builder = ECodeBuilder::new(source_header, IlGraph::default());
    let register = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::ReadRegister,
            64,
            IlIndexRange::EMPTY,
            7,
            None,
        ))
        .unwrap();
    let decrement = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
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
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Sub,
            64,
            subtract_operands,
            0,
            None,
        ))
        .unwrap();
    builder
        .push_statement(
            ECodeStmt::new(
                ECodeStmtOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(address),
                None,
                None,
            )
            .with_immediate(7),
        )
        .unwrap();

    let value = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            64,
            IlIndexRange::EMPTY,
            0x2a,
            None,
        ))
        .unwrap();
    let store_operands = builder.push_statement_operands([address, value]).unwrap();
    builder
        .push_statement(ECodeStmt::new(
            ECodeStmtOpcode::Store,
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
    let ssa = ECodeToSsa::default()
        .transform(&source, &CancellationToken::default())
        .unwrap();
    let subtracts = ssa
        .operations()
        .iter()
        .enumerate()
        .filter(|(_, operation)| operation.opcode() == ECodeSsaOpcode::Sub)
        .collect::<Vec<_>>();
    assert_eq!(subtracts.len(), 1);
    let address_value =
        IlValueId::try_from_index(subtracts[0].1.results().start()).expect("result must exist");
    let store = ssa
        .operations()
        .iter()
        .find(|operation| operation.opcode() == ECodeSsaOpcode::Store)
        .expect("store must exist");
    assert_eq!(ssa.operation_operands(store)[0], address_value);
}

#[test]
fn register_read_without_write_becomes_undefined() {
    let source_header = IlMetadata::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
    let mut builder = ECodeBuilder::new(source_header, IlGraph::default());
    let read = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::ReadRegister,
            32,
            IlIndexRange::EMPTY,
            9,
            None,
        ))
        .unwrap();
    let operands = builder.push_statement_operands([read]).unwrap();

    builder
        .push_statement(ECodeStmt::new(
            ECodeStmtOpcode::Return,
            operands,
            None,
            None,
            None,
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let cancellation = CancellationToken::default();
    let mut transform = ECodeToSsa::default();
    let ssa = transform.transform(&source, &cancellation).unwrap();

    assert_eq!(ssa.operations()[0].opcode(), ECodeSsaOpcode::Undefined);
    assert_eq!(ssa.operations()[0].width(), 32);
    assert_eq!(ssa.operations()[0].immediate(), 9);
    assert_eq!(ssa.operations()[1].opcode(), ECodeSsaOpcode::Return);
}

#[test]
fn load_preserves_fugue_address_space() {
    let source_header = IlMetadata::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
    let mut builder = ECodeBuilder::new(source_header, IlGraph::default());
    let offset = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            64,
            IlIndexRange::EMPTY,
            0x1000,
            None,
        ))
        .unwrap();
    let load_operands = builder.push_expression_operands([offset]).unwrap();
    let space = AddressSpaceId::new(3);
    let load = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Load,
            8,
            load_operands,
            0,
            Some(space),
        ))
        .unwrap();
    let return_operands = builder.push_statement_operands([load]).unwrap();

    builder
        .push_statement(ECodeStmt::new(
            ECodeStmtOpcode::Return,
            return_operands,
            None,
            None,
            None,
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let cancellation = CancellationToken::default();
    let mut transform = ECodeToSsa::default();
    let ssa = transform.transform(&source, &cancellation).unwrap();

    let load_index = ssa
        .operations()
        .iter()
        .position(|operation| operation.opcode() == ECodeSsaOpcode::Load)
        .unwrap();

    assert_eq!(ssa.operations()[load_index].address_space(), Some(space));
    assert_eq!(ssa.memory_domains().len(), 1);
    assert_eq!(ssa.memory_domains()[0].space(), space);

    let memory = ssa.values()[ssa
        .memory_operand(&ssa.operations()[load_index])
        .unwrap()
        .index()];

    assert_eq!(memory.width(), 0);
}

#[test]
fn load_after_store_uses_store_memory_result() {
    let source_header = IlMetadata::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
    let mut builder = ECodeBuilder::new(source_header, IlGraph::default());
    let space = AddressSpaceId::new(3);
    let store_address = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            64,
            IlIndexRange::EMPTY,
            0x1000,
            None,
        ))
        .unwrap();
    let store_value = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            32,
            IlIndexRange::EMPTY,
            0x2a,
            None,
        ))
        .unwrap();
    let store_operands = builder
        .push_statement_operands([store_address, store_value])
        .unwrap();

    builder
        .push_statement(ECodeStmt::new(
            ECodeStmtOpcode::Store,
            store_operands,
            None,
            None,
            Some(space),
        ))
        .unwrap();

    let load_address = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            64,
            IlIndexRange::EMPTY,
            0x1000,
            None,
        ))
        .unwrap();
    let load_operands = builder.push_expression_operands([load_address]).unwrap();
    let load = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Load,
            32,
            load_operands,
            0,
            Some(space),
        ))
        .unwrap();
    let return_operands = builder.push_statement_operands([load]).unwrap();

    builder
        .push_statement(ECodeStmt::new(
            ECodeStmtOpcode::Return,
            return_operands,
            None,
            None,
            None,
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let cancellation = CancellationToken::default();
    let mut transform = ECodeToSsa::default();
    let ssa = transform.transform(&source, &cancellation).unwrap();
    let store_index = ssa
        .operations()
        .iter()
        .position(|operation| operation.opcode() == ECodeSsaOpcode::Store)
        .unwrap();
    let load_index = ssa
        .operations()
        .iter()
        .position(|operation| operation.opcode() == ECodeSsaOpcode::Load)
        .unwrap();
    let store_memory =
        IlValueId::try_from_index(ssa.operations()[store_index].results().start()).unwrap();
    let load_operands = ssa.operation_operands(&ssa.operations()[load_index]);

    assert_eq!(ssa.memory_domains().len(), 1);
    assert_eq!(ssa.memory_domains()[0].space(), space);
    assert_eq!(ssa.values()[store_memory.index()].width(), 0);
    assert_eq!(*load_operands.last().unwrap(), store_memory);
}

#[test]
fn store_without_load_registers_memory_domain() {
    let source_header = IlMetadata::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
    let mut builder = ECodeBuilder::new(source_header, IlGraph::default());
    let space = AddressSpaceId::new(3);
    let address = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            64,
            IlIndexRange::EMPTY,
            0x1000,
            None,
        ))
        .unwrap();
    let value = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            32,
            IlIndexRange::EMPTY,
            0x2a,
            None,
        ))
        .unwrap();
    let operands = builder.push_statement_operands([address, value]).unwrap();

    builder
        .push_statement(ECodeStmt::new(
            ECodeStmtOpcode::Store,
            operands,
            None,
            None,
            Some(space),
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let mut transform = ECodeToSsa::default();
    let ssa = transform
        .transform(&source, &CancellationToken::default())
        .unwrap();

    assert_eq!(ssa.memory_domains().len(), 1);
    assert_eq!(ssa.memory_domains()[0].space(), space);
    ssa.verify().unwrap();
}

#[test]
fn direct_branch_preserves_fugue_address() {
    let source_header = IlMetadata::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
    let mut builder = ECodeBuilder::new(source_header, IlGraph::default());
    let condition = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            1,
            IlIndexRange::EMPTY,
            1,
            None,
        ))
        .unwrap();
    let target_expression = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            64,
            IlIndexRange::EMPTY,
            0x2000,
            None,
        ))
        .unwrap();
    let operands = builder
        .push_statement_operands([condition, target_expression])
        .unwrap();
    let target = Address::new(AddressSpaceId::new(4), 0x2000u64);

    builder
        .push_statement(ECodeStmt::new(
            ECodeStmtOpcode::ConditionalBranch,
            operands,
            None,
            Some(target),
            None,
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let cancellation = CancellationToken::default();
    let mut transform = ECodeToSsa::default();
    let ssa = transform.transform(&source, &cancellation).unwrap();

    assert_eq!(
        ssa.operations()[2].opcode(),
        ECodeSsaOpcode::ConditionalBranch
    );
    assert_eq!(ssa.operations()[2].address(), Some(target));
}

#[test]
fn deep_dominance_chain_constructs_iteratively() {
    let source_header = IlMetadata::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
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

    let graph = IlGraph::new(blocks, successors);
    let mut builder = ECodeBuilder::new(source_header, graph);

    for index in 0..block_count {
        let value = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                64,
                IlIndexRange::EMPTY,
                index as u64,
                None,
            ))
            .unwrap();

        builder
            .push_statement(
                ECodeStmt::new(
                    ECodeStmtOpcode::WriteRegister,
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
    let mut transform = ECodeToSsa::default();
    let ssa = transform.transform(&source, &cancellation).unwrap();

    assert_eq!(ssa.graph().blocks().len(), block_count);
    assert_eq!(ssa.graph().successors().len(), block_count - 1);
    assert_eq!(ssa.operations().len(), block_count);
    assert!(ssa.block_arguments().is_empty());
}

#[test]
fn merge_block_register_read_becomes_block_argument() {
    let source_header = IlMetadata::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
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
        successors,
    );
    let mut builder = ECodeBuilder::new(source_header, graph);
    let left = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            64,
            IlIndexRange::EMPTY,
            1,
            None,
        ))
        .unwrap();
    let right = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            64,
            IlIndexRange::EMPTY,
            2,
            None,
        ))
        .unwrap();
    let read = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::ReadRegister,
            64,
            IlIndexRange::EMPTY,
            7,
            None,
        ))
        .unwrap();

    builder
        .push_statement(
            ECodeStmt::new(
                ECodeStmtOpcode::WriteRegister,
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
            ECodeStmt::new(
                ECodeStmtOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(right),
                None,
                None,
            )
            .with_immediate(7),
        )
        .unwrap();
    let operands = builder.push_statement_operands([read]).unwrap();
    builder
        .push_statement(ECodeStmt::new(
            ECodeStmtOpcode::Return,
            operands,
            None,
            None,
            None,
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let cancellation = CancellationToken::default();
    let mut transform = ECodeToSsa::default();
    let ssa = transform.transform(&source, &cancellation).unwrap();

    assert_eq!(ssa.block_arguments().len(), 1);
    assert_eq!(
        ssa.block_arguments()[0].block(),
        IlBlockId::try_from_index(3).unwrap()
    );
    assert_eq!(ssa.operations()[2].opcode(), ECodeSsaOpcode::Return);
    assert_eq!(ssa.value_operands()[0], ssa.block_arguments()[0].value());
    assert_eq!(ssa.edge_arguments().len(), 4);
    assert_eq!(ssa.edge_argument_values().len(), 2);
    assert!(ssa.edge_arguments()[0].is_empty());
    assert!(ssa.edge_arguments()[1].is_empty());
    assert_eq!(ssa.arguments_for_edge(2).len(), 1);
    assert_eq!(ssa.arguments_for_edge(3).len(), 1);
}

#[test]
fn merge_block_load_uses_memory_block_argument() {
    let source_header = IlMetadata::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
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
        successors,
    );
    let mut builder = ECodeBuilder::new(source_header, graph);
    let space = AddressSpaceId::new(3);
    let store_address = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            64,
            IlIndexRange::EMPTY,
            0x1000,
            None,
        ))
        .unwrap();
    let store_value = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            32,
            IlIndexRange::EMPTY,
            0x2a,
            None,
        ))
        .unwrap();
    let load_address = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            64,
            IlIndexRange::EMPTY,
            0x1000,
            None,
        ))
        .unwrap();
    let load_operands = builder.push_expression_operands([load_address]).unwrap();
    let load = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Load,
            32,
            load_operands,
            0,
            Some(space),
        ))
        .unwrap();
    let store_operands = builder
        .push_statement_operands([store_address, store_value])
        .unwrap();

    builder
        .push_statement(ECodeStmt::new(
            ECodeStmtOpcode::Store,
            store_operands,
            None,
            None,
            Some(space),
        ))
        .unwrap();

    let return_operands = builder.push_statement_operands([load]).unwrap();

    builder
        .push_statement(ECodeStmt::new(
            ECodeStmtOpcode::Return,
            return_operands,
            None,
            None,
            None,
        ))
        .unwrap();

    let source = builder.build(&CancellationToken::default()).unwrap();
    let cancellation = CancellationToken::default();
    let mut transform = ECodeToSsa::default();
    let ssa = transform.transform(&source, &cancellation).unwrap();
    let load_index = ssa
        .operations()
        .iter()
        .position(|operation| operation.opcode() == ECodeSsaOpcode::Load)
        .unwrap();
    let load_operands = ssa.operation_operands(&ssa.operations()[load_index]);

    assert_eq!(ssa.memory_domains().len(), 1);
    assert_eq!(ssa.memory_domains()[0].space(), space);
    assert_eq!(ssa.block_arguments().len(), 1);
    assert_eq!(ssa.block_arguments()[0].block(), join);
    assert_eq!(
        ssa.values()[ssa.block_arguments()[0].value().index()].width(),
        0
    );
    assert_eq!(
        *load_operands.last().unwrap(),
        ssa.block_arguments()[0].value()
    );
    assert!(ssa.arguments_for_edge(0).is_empty());
    assert!(ssa.arguments_for_edge(1).is_empty());
    assert_eq!(ssa.arguments_for_edge(2).len(), 1);
    assert_eq!(ssa.arguments_for_edge(3).len(), 1);
}

#[test]
fn loop_carried_register_uses_header_block_argument() {
    let source_header = IlMetadata::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
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
    );
    let mut builder = ECodeBuilder::new(source_header, graph);
    let read = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::ReadRegister,
            32,
            IlIndexRange::EMPTY,
            9,
            None,
        ))
        .unwrap();
    let constant = builder
        .push_expression(ECodeExpr::new(
            ECodeExprOpcode::Constant,
            32,
            IlIndexRange::EMPTY,
            1,
            None,
        ))
        .unwrap();
    let return_operands = builder.push_statement_operands([read]).unwrap();

    builder
        .push_statement(ECodeStmt::new(
            ECodeStmtOpcode::Return,
            return_operands,
            None,
            None,
            None,
        ))
        .unwrap();
    builder
        .push_statement(
            ECodeStmt::new(
                ECodeStmtOpcode::WriteRegister,
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
    let mut transform = ECodeToSsa::default();
    let ssa = transform.transform(&source, &cancellation).unwrap();

    assert_eq!(ssa.block_arguments().len(), 1);
    assert_eq!(ssa.block_arguments()[0].block(), loop_header);
    assert_eq!(ssa.value_operands()[0], ssa.block_arguments()[0].value());
    assert_eq!(ssa.arguments_for_edge(0).len(), 1);
    assert_eq!(ssa.arguments_for_edge(2).len(), 1);

    let entry_value = ssa.arguments_for_edge(0)[0];
    let back_edge_value = ssa.arguments_for_edge(2)[0];

    assert_eq!(
        ssa.operations()[ssa.values()[entry_value.index()].definition_index() as usize].opcode(),
        ECodeSsaOpcode::Undefined
    );
    assert_eq!(
        ssa.operations()[ssa.values()[back_edge_value.index()].definition_index() as usize]
            .opcode(),
        ECodeSsaOpcode::Constant
    );
}
