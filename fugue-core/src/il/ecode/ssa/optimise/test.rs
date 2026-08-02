use fugue_bv::BitVec;

use super::{ECodeSsaCompaction, ECodeSsaConstantFolding};
use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlBlock, IlBlockId, IlBlockProperties, IlGraph, IlIndexRange, IlMetadata,
};
use crate::il::ecode::ssa::{
    ECODE_SSA_SCHEMA_VERSION, ECodeSsaBuilder, ECodeSsaOp, ECodeSsaOpcode, ECodeSsaValueKind,
};
use crate::ir::{Address, FunctionId};
use crate::storage::segments::space::AddressSpaceId;

#[test]
fn fold_constants_materialises_wide_result_in_pool() {
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
            .with_immediate(0xdead_beef),
        )
        .unwrap();

    let operands = builder.push_value_operands([source]).unwrap();
    let (widened, widened_results) = builder.push_result_value(128).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::ZeroExtend,
            widened_results,
            operands,
            128,
        ))
        .unwrap();

    let mut ssa = builder.build(&CancellationToken::default()).unwrap();

    ssa.rewrite(ECodeSsaConstantFolding);

    let folded = ssa.defining_operation(widened).unwrap();
    assert_eq!(folded.opcode(), ECodeSsaOpcode::Constant);
    assert_eq!(folded.operands().len(), 0);
    assert_eq!(
        ssa.constant_value(widened),
        Some(BitVec::from_u64(0xdead_beef, 64).unsigned_cast(128))
    );
}

#[test]
fn fold_constants_propagates_through_block_argument() {
    let block1 = IlBlockId::try_from_index(1).unwrap();
    let block2 = IlBlockId::try_from_index(2).unwrap();
    let block3 = IlBlockId::try_from_index(3).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::new(0, 2).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(1, 2).unwrap(),
                IlIndexRange::new(2, 3).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::new(2, 3).unwrap(),
                IlIndexRange::new(3, 4).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::new(3, 5).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        vec![block1, block2, block3, block3],
    );
    let mut builder = ECodeSsaBuilder::new(metadata, graph);

    let (_, entry_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                entry_results,
                IlIndexRange::EMPTY,
                32,
            )
            .with_immediate(0),
        )
        .unwrap();

    let (left, left_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                left_results,
                IlIndexRange::EMPTY,
                32,
            )
            .with_immediate(7),
        )
        .unwrap();

    let (right, right_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                right_results,
                IlIndexRange::EMPTY,
                32,
            )
            .with_immediate(7),
        )
        .unwrap();

    let phi = builder.push_block_argument_value(block3, 32).unwrap();
    let sum_operands = builder.push_value_operands([phi, phi]).unwrap();
    let (sum, sum_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Add,
            sum_results,
            sum_operands,
            32,
        ))
        .unwrap();

    let return_operands = builder.push_value_operands([sum]).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            return_operands,
            0,
        ))
        .unwrap();

    builder.push_edge_arguments([]).unwrap();
    builder.push_edge_arguments([]).unwrap();
    builder.push_edge_arguments([left]).unwrap();
    builder.push_edge_arguments([right]).unwrap();

    let mut ssa = builder.build(&CancellationToken::default()).unwrap();
    ssa.verify().unwrap();

    ssa.rewrite(ECodeSsaConstantFolding);

    let folded = ssa.defining_operation(sum).unwrap();
    assert_eq!(folded.opcode(), ECodeSsaOpcode::Constant);
    assert_eq!(ssa.constant_value(sum), Some(BitVec::from_u64(14, 32)));
}

#[test]
fn fold_constants_leaves_disagreeing_block_argument_unfolded() {
    let block1 = IlBlockId::try_from_index(1).unwrap();
    let block2 = IlBlockId::try_from_index(2).unwrap();
    let block3 = IlBlockId::try_from_index(3).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::new(0, 2).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(1, 2).unwrap(),
                IlIndexRange::new(2, 3).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::new(2, 3).unwrap(),
                IlIndexRange::new(3, 4).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::new(3, 5).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        vec![block1, block2, block3, block3],
    );
    let mut builder = ECodeSsaBuilder::new(metadata, graph);

    let (_, entry_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                entry_results,
                IlIndexRange::EMPTY,
                32,
            )
            .with_immediate(0),
        )
        .unwrap();

    let (left, left_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                left_results,
                IlIndexRange::EMPTY,
                32,
            )
            .with_immediate(7),
        )
        .unwrap();

    let (right, right_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                right_results,
                IlIndexRange::EMPTY,
                32,
            )
            .with_immediate(9),
        )
        .unwrap();

    let phi = builder.push_block_argument_value(block3, 32).unwrap();
    let sum_operands = builder.push_value_operands([phi, phi]).unwrap();
    let (sum, sum_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Add,
            sum_results,
            sum_operands,
            32,
        ))
        .unwrap();

    let return_operands = builder.push_value_operands([sum]).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            return_operands,
            0,
        ))
        .unwrap();

    builder.push_edge_arguments([]).unwrap();
    builder.push_edge_arguments([]).unwrap();
    builder.push_edge_arguments([left]).unwrap();
    builder.push_edge_arguments([right]).unwrap();

    let mut ssa = builder.build(&CancellationToken::default()).unwrap();
    ssa.rewrite(ECodeSsaConstantFolding);

    assert_eq!(
        ssa.defining_operation(sum).unwrap().opcode(),
        ECodeSsaOpcode::Add
    );
    assert_eq!(ssa.constant_value(sum), None);
}

#[test]
fn fold_constants_leaves_sourceless_block_argument_unfolded() {
    let block0 = IlBlockId::try_from_index(0).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let graph = IlGraph::new(
        vec![IlBlock::new(
            IlIndexRange::new(0, 2).unwrap(),
            IlIndexRange::EMPTY,
            IlBlockProperties::ENTRY | IlBlockProperties::EXIT,
        )],
        Vec::new(),
    );
    let mut builder = ECodeSsaBuilder::new(metadata, graph);

    let phi = builder.push_block_argument_value(block0, 32).unwrap();
    let copy_operands = builder.push_value_operands([phi]).unwrap();
    let (copied, copy_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Copy,
            copy_results,
            copy_operands,
            32,
        ))
        .unwrap();

    let return_operands = builder.push_value_operands([copied]).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            return_operands,
            0,
        ))
        .unwrap();

    let mut ssa = builder.build(&CancellationToken::default()).unwrap();
    ssa.verify().unwrap();

    ssa.rewrite(ECodeSsaConstantFolding);

    assert_eq!(
        ssa.defining_operation(copied).unwrap().opcode(),
        ECodeSsaOpcode::Copy
    );
    assert_eq!(ssa.constant_value(copied), None);
}

#[test]
fn fold_constants_leaves_self_referential_loop_argument_unfolded() {
    let block1 = IlBlockId::try_from_index(1).unwrap();
    let block2 = IlBlockId::try_from_index(2).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::new(0, 1).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(1, 2).unwrap(),
                IlIndexRange::new(1, 3).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::new(2, 3).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        vec![block1, block1, block2],
    );
    let mut builder = ECodeSsaBuilder::new(metadata, graph);

    let (seed, seed_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                seed_results,
                IlIndexRange::EMPTY,
                32,
            )
            .with_immediate(7),
        )
        .unwrap();

    let phi = builder.push_block_argument_value(block1, 32).unwrap();
    let sum_operands = builder.push_value_operands([phi, phi]).unwrap();
    let (sum, sum_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Add,
            sum_results,
            sum_operands,
            32,
        ))
        .unwrap();

    let return_operands = builder.push_value_operands([sum]).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            return_operands,
            0,
        ))
        .unwrap();

    builder.push_edge_arguments([seed]).unwrap();
    builder.push_edge_arguments([phi]).unwrap();
    builder.push_edge_arguments([]).unwrap();

    let mut ssa = builder.build(&CancellationToken::default()).unwrap();
    ssa.rewrite(ECodeSsaConstantFolding);

    assert_eq!(
        ssa.defining_operation(sum).unwrap().opcode(),
        ECodeSsaOpcode::Add
    );
    assert_eq!(ssa.constant_value(sum), None);
}

#[test]
fn compact_removes_dead_operations_and_remaps_indices() {
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());

    let (first, first_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                first_results,
                IlIndexRange::EMPTY,
                64,
            )
            .with_immediate(5),
        )
        .unwrap();
    let (second, second_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                second_results,
                IlIndexRange::EMPTY,
                64,
            )
            .with_immediate(7),
        )
        .unwrap();

    let dead_operands = builder.push_value_operands([first]).unwrap();
    let (_dead, dead_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Copy,
            dead_results,
            dead_operands,
            64,
        ))
        .unwrap();

    let sum_operands = builder.push_value_operands([first, second]).unwrap();
    let (sum, sum_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Add,
            sum_results,
            sum_operands,
            64,
        ))
        .unwrap();
    let return_operands = builder.push_value_operands([sum]).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            return_operands,
            0,
        ))
        .unwrap();

    let mut ssa = builder.build(&CancellationToken::default()).unwrap();
    assert_eq!(ssa.operations().len(), 5);
    assert_eq!(ssa.values().len(), 4);

    ssa.rewrite(ECodeSsaCompaction);

    assert_eq!(ssa.operations().len(), 4);
    assert_eq!(ssa.values().len(), 3);
    assert!(
        ssa.operations()
            .iter()
            .all(|operation| operation.opcode() != ECodeSsaOpcode::Copy)
    );
    ssa.verify().unwrap();

    let add = ssa
        .operations()
        .iter()
        .find(|operation| operation.opcode() == ECodeSsaOpcode::Add)
        .unwrap();
    let operands = ssa.operation_operands_for(add);
    assert_eq!(
        ssa.constant_value(operands[0]),
        Some(BitVec::from_u64(5, 64))
    );
    assert_eq!(
        ssa.constant_value(operands[1]),
        Some(BitVec::from_u64(7, 64))
    );
}

#[test]
fn compact_preserves_sources_for_operation_empty_blocks() {
    let entry = IlBlockId::try_from_index(0).unwrap();
    let exit = IlBlockId::try_from_index(1).unwrap();
    let space = AddressSpaceId::new(1);
    let entry_source = Address::new(space, 0x1000u64);
    let exit_source = Address::new(space, 0x2000u64);
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::new(0, 1).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(1, 2).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        vec![exit],
    )
    .with_block_sources(vec![entry_source, exit_source]);
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let mut builder = ECodeSsaBuilder::new(metadata, graph);

    let (_, dead_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                dead_results,
                IlIndexRange::EMPTY,
                32,
            )
            .with_immediate(1),
        )
        .unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            IlIndexRange::EMPTY,
            0,
        ))
        .unwrap();

    let mut ssa = builder.build(&CancellationToken::default()).unwrap();
    ssa.rewrite(ECodeSsaCompaction);

    assert!(ssa.graph().blocks()[entry.index()].operations().is_empty());
    assert_eq!(ssa.graph().block_source(entry), Some(entry_source));
    assert_eq!(ssa.graph().block_source(exit), Some(exit_source));
    ssa.verify().unwrap();
}

#[test]
fn compact_drops_dead_loop_phi_and_sources() {
    let block1 = IlBlockId::try_from_index(1).unwrap();
    let block2 = IlBlockId::try_from_index(2).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::new(0, 2).unwrap(),
                IlIndexRange::new(0, 1).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(2, 3).unwrap(),
                IlIndexRange::new(1, 3).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::new(3, 4).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        vec![block1, block1, block2],
    );
    let mut builder = ECodeSsaBuilder::new(metadata, graph);

    let (seed, seed_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                seed_results,
                IlIndexRange::EMPTY,
                32,
            )
            .with_immediate(0),
        )
        .unwrap();

    let (one, one_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                one_results,
                IlIndexRange::EMPTY,
                32,
            )
            .with_immediate(1),
        )
        .unwrap();

    let counter = builder.push_block_argument_value(block1, 32).unwrap();
    let step_operands = builder.push_value_operands([counter, one]).unwrap();
    let (next, next_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Add,
            next_results,
            step_operands,
            32,
        ))
        .unwrap();

    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            IlIndexRange::EMPTY,
            0,
        ))
        .unwrap();

    builder.push_edge_arguments([seed]).unwrap();
    builder.push_edge_arguments([next]).unwrap();
    builder.push_edge_arguments([]).unwrap();

    let mut ssa = builder.build(&CancellationToken::default()).unwrap();
    ssa.verify().unwrap();

    ssa.rewrite(ECodeSsaCompaction);
    ssa.verify().unwrap();

    assert_eq!(ssa.operations().len(), 1);
    assert_eq!(ssa.operations()[0].opcode(), ECodeSsaOpcode::Return);
    assert_eq!(ssa.block_arguments().len(), 0);
    assert_eq!(ssa.values().len(), 0);
    assert!(ssa.arguments_for_edge(0).is_empty());
    assert!(ssa.arguments_for_edge(1).is_empty());
}

#[test]
fn compact_preserves_live_phi_and_remaps_edge_arguments() {
    let block1 = IlBlockId::try_from_index(1).unwrap();
    let block2 = IlBlockId::try_from_index(2).unwrap();
    let block3 = IlBlockId::try_from_index(3).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::new(0, 2).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(1, 2).unwrap(),
                IlIndexRange::new(2, 3).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::new(2, 3).unwrap(),
                IlIndexRange::new(3, 4).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::new(3, 4).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        vec![block1, block2, block3, block3],
    );
    let mut builder = ECodeSsaBuilder::new(metadata, graph);

    let (_, dead_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                dead_results,
                IlIndexRange::EMPTY,
                32,
            )
            .with_immediate(99),
        )
        .unwrap();

    let (left, left_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                left_results,
                IlIndexRange::EMPTY,
                32,
            )
            .with_immediate(5),
        )
        .unwrap();

    let (right, right_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                right_results,
                IlIndexRange::EMPTY,
                32,
            )
            .with_immediate(9),
        )
        .unwrap();

    let phi = builder.push_block_argument_value(block3, 32).unwrap();
    let return_operands = builder.push_value_operands([phi]).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            return_operands,
            0,
        ))
        .unwrap();

    builder.push_edge_arguments([]).unwrap();
    builder.push_edge_arguments([]).unwrap();
    builder.push_edge_arguments([left]).unwrap();
    builder.push_edge_arguments([right]).unwrap();

    let mut ssa = builder.build(&CancellationToken::default()).unwrap();
    ssa.verify().unwrap();

    ssa.rewrite(ECodeSsaCompaction);
    ssa.verify().unwrap();

    assert_eq!(ssa.operations().len(), 3);
    assert_eq!(ssa.block_arguments().len(), 1);
    assert_eq!(ssa.values().len(), 3);
    assert_eq!(ssa.arguments_for_edge(2).len(), 1);
    assert_eq!(ssa.arguments_for_edge(3).len(), 1);

    let return_op = ssa
        .operations()
        .iter()
        .find(|operation| operation.opcode() == ECodeSsaOpcode::Return)
        .unwrap();
    let consumed = ssa.operation_operands_for(return_op)[0];
    assert_eq!(
        ssa.values()[consumed.index()].definition_kind(),
        ECodeSsaValueKind::BlockArgument
    );
}

#[test]
fn compact_drops_one_of_two_phis_by_position() {
    let block1 = IlBlockId::try_from_index(1).unwrap();
    let block2 = IlBlockId::try_from_index(2).unwrap();
    let block3 = IlBlockId::try_from_index(3).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let graph = IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::new(0, 2).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(0, 2).unwrap(),
                IlIndexRange::new(2, 3).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::new(2, 4).unwrap(),
                IlIndexRange::new(3, 4).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::new(4, 5).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        vec![block1, block2, block3, block3],
    );
    let mut builder = ECodeSsaBuilder::new(metadata, graph);

    let (narrow_left, narrow_left_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                narrow_left_results,
                IlIndexRange::EMPTY,
                32,
            )
            .with_immediate(5),
        )
        .unwrap();
    let (wide_left, wide_left_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                wide_left_results,
                IlIndexRange::EMPTY,
                64,
            )
            .with_immediate(50),
        )
        .unwrap();

    let (narrow_right, narrow_right_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                narrow_right_results,
                IlIndexRange::EMPTY,
                32,
            )
            .with_immediate(9),
        )
        .unwrap();
    let (wide_right, wide_right_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                wide_right_results,
                IlIndexRange::EMPTY,
                64,
            )
            .with_immediate(90),
        )
        .unwrap();

    let _dead_phi = builder.push_block_argument_value(block3, 32).unwrap();
    let live_phi = builder.push_block_argument_value(block3, 64).unwrap();
    let return_operands = builder.push_value_operands([live_phi]).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            return_operands,
            0,
        ))
        .unwrap();

    builder.push_edge_arguments([]).unwrap();
    builder.push_edge_arguments([]).unwrap();
    builder
        .push_edge_arguments([narrow_left, wide_left])
        .unwrap();
    builder
        .push_edge_arguments([narrow_right, wide_right])
        .unwrap();

    let mut ssa = builder.build(&CancellationToken::default()).unwrap();
    ssa.verify().unwrap();

    ssa.rewrite(ECodeSsaCompaction);
    ssa.verify().unwrap();

    assert_eq!(ssa.block_arguments().len(), 1);
    assert_eq!(ssa.block_arguments()[0].width(), 64);
    assert_eq!(ssa.arguments_for_edge(2).len(), 1);
    assert_eq!(ssa.arguments_for_edge(3).len(), 1);
    assert_eq!(ssa.value_width(ssa.arguments_for_edge(2)[0]), Some(64));
}

#[test]
fn fold_then_compact_collapses_constant_expression() {
    let metadata = IlMetadata::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());

    let (first, first_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                first_results,
                IlIndexRange::EMPTY,
                64,
            )
            .with_immediate(5),
        )
        .unwrap();
    let (second, second_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                second_results,
                IlIndexRange::EMPTY,
                64,
            )
            .with_immediate(7),
        )
        .unwrap();

    let sum_operands = builder.push_value_operands([first, second]).unwrap();
    let (sum, sum_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Add,
            sum_results,
            sum_operands,
            64,
        ))
        .unwrap();
    let return_operands = builder.push_value_operands([sum]).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            return_operands,
            0,
        ))
        .unwrap();

    let mut ssa = builder.build(&CancellationToken::default()).unwrap();

    ssa.rewrite(ECodeSsaConstantFolding);
    ssa.rewrite(ECodeSsaCompaction);

    assert_eq!(ssa.operations().len(), 2);
    ssa.verify().unwrap();

    let returned = ssa
        .operations()
        .iter()
        .find(|operation| operation.opcode() == ECodeSsaOpcode::Return)
        .unwrap();
    let sum_value = ssa.operation_operands_for(returned)[0];
    assert_eq!(
        ssa.constant_value(sum_value),
        Some(BitVec::from_u64(12, 64))
    );
}
