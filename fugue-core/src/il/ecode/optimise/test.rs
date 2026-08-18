use fugue_bv::BitVec;

use super::{ECodeCompaction, ECodeConstantFolding};
use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlGraph, IlIndexRange,
    IlMetadata, IlSsaDef, IlValueId,
};
use crate::il::ecode::test::emit_value;
use crate::il::ecode::{ECodeBuilder, ECodeOpSpec, ECodeOpcode};
use crate::ir::{Address, FunctionId};
use crate::storage::segments::space::AddressSpaceId;

#[test]
fn compaction_preserves_interned_constants_across_inline_capacity() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let mut constants = Vec::new();
    for width in [65, 128, 192] {
        let (operation, results) = builder
            .emitter()
            .emit(ECodeOpSpec::new(ECodeOpcode::Constant, width), [], 1)
            .unwrap();
        let value = IlValueId::try_from_index(results.start()).unwrap();
        constants.push((value, operation));
    }
    builder
        .emitter()
        .emit(
            ECodeOpSpec::new(ECodeOpcode::Return, 0),
            constants.iter().map(|(value, _)| *value),
            0,
        )
        .unwrap();
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

    ir.rewrite(ECodeCompaction);

    for ((value, _), expected) in constants.iter().zip(values) {
        assert_eq!(ir.constant_value(*value), Some(expected));
    }
    assert_eq!(ir.constant_storage().len(), 49);
}

#[test]
fn compaction_preserves_empty_and_multi_space_memory_domains() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut empty = ECodeBuilder::new(metadata, IlGraph::default())
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    empty.rewrite(ECodeCompaction);

    assert!(empty.memory_domains().is_empty());

    let spaces = [AddressSpaceId::new(3), AddressSpaceId::new(7)];
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    for space in spaces {
        builder.emitter().intern_memory_domain(space);
    }
    let mut multi_space = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    multi_space.rewrite(ECodeCompaction);

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
fn fold_constants_materialises_wide_result_in_pool() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());

    let source = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(0xdead_beef),
        [],
    )
    .unwrap();

    let widened = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::ZeroExtend, 128),
        [source],
    )
    .unwrap();

    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    ir.rewrite(ECodeConstantFolding);

    let folded = ir.defining_op(widened).unwrap();
    assert_eq!(folded.opcode(), ECodeOpcode::Constant);
    assert_eq!(folded.operands().len(), 0);
    assert_eq!(
        ir.constant_value(widened),
        Some(BitVec::from_u64(0xdead_beef, 64).unsigned_cast(128))
    );
}

#[test]
fn fold_constants_propagates_through_block_arg() {
    let block1 = IlBlockId::try_from_index(1).unwrap();
    let block2 = IlBlockId::try_from_index(2).unwrap();
    let block3 = IlBlockId::try_from_index(3).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
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
        vec![IlEdgeKinds::UNCONDITIONAL; 4],
    );
    let mut builder = ECodeBuilder::new(metadata, graph);

    let _ = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(0),
        [],
    )
    .unwrap();

    let left = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(7),
        [],
    )
    .unwrap();

    let right = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(7),
        [],
    )
    .unwrap();

    let phi = builder.emitter().emit_block_arg(block3, 32).unwrap();
    let sum = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Add, 32),
        [phi, phi],
    )
    .unwrap();

    builder
        .emitter()
        .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [sum], 0)
        .unwrap();

    builder.emitter().emit_edge_args([]).unwrap();
    builder.emitter().emit_edge_args([]).unwrap();
    builder.emitter().emit_edge_args([left]).unwrap();
    builder.emitter().emit_edge_args([right]).unwrap();

    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    ir.verify().unwrap();

    ir.rewrite(ECodeConstantFolding);

    let folded = ir.defining_op(sum).unwrap();
    assert_eq!(folded.opcode(), ECodeOpcode::Constant);
    assert_eq!(ir.constant_value(sum), Some(BitVec::from_u64(14, 32)));
}

#[test]
fn fold_constants_leaves_disagreeing_block_arg_unfolded() {
    let block1 = IlBlockId::try_from_index(1).unwrap();
    let block2 = IlBlockId::try_from_index(2).unwrap();
    let block3 = IlBlockId::try_from_index(3).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
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
        vec![IlEdgeKinds::UNCONDITIONAL; 4],
    );
    let mut builder = ECodeBuilder::new(metadata, graph);

    let _ = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(0),
        [],
    )
    .unwrap();

    let left = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(7),
        [],
    )
    .unwrap();

    let right = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(9),
        [],
    )
    .unwrap();

    let phi = builder.emitter().emit_block_arg(block3, 32).unwrap();
    let sum = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Add, 32),
        [phi, phi],
    )
    .unwrap();

    builder
        .emitter()
        .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [sum], 0)
        .unwrap();

    builder.emitter().emit_edge_args([]).unwrap();
    builder.emitter().emit_edge_args([]).unwrap();
    builder.emitter().emit_edge_args([left]).unwrap();
    builder.emitter().emit_edge_args([right]).unwrap();

    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    ir.rewrite(ECodeConstantFolding);

    assert_eq!(
        ir.defining_op(sum).unwrap().opcode(),
        ECodeOpcode::Add
    );
    assert_eq!(ir.constant_value(sum), None);
}

#[test]
fn fold_constants_leaves_sourceless_block_arg_unfolded() {
    let block0 = IlBlockId::try_from_index(0).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let graph = IlGraph::new(
        vec![IlBlock::new(
            IlIndexRange::new(0, 2).unwrap(),
            IlIndexRange::EMPTY,
            IlBlockProperties::ENTRY | IlBlockProperties::EXIT,
        )],
        Vec::new(),
        Vec::new(),
    );
    let mut builder = ECodeBuilder::new(metadata, graph);

    let phi = builder.emitter().emit_block_arg(block0, 32).unwrap();
    let copied = emit_value(&mut builder, ECodeOpSpec::new(ECodeOpcode::Copy, 32), [phi]).unwrap();

    builder
        .emitter()
        .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [copied], 0)
        .unwrap();

    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    ir.verify().unwrap();

    ir.rewrite(ECodeConstantFolding);

    assert_eq!(
        ir.defining_op(copied).unwrap().opcode(),
        ECodeOpcode::Copy
    );
    assert_eq!(ir.constant_value(copied), None);
}

#[test]
fn fold_constants_leaves_self_referential_loop_arg_unfolded() {
    let block1 = IlBlockId::try_from_index(1).unwrap();
    let block2 = IlBlockId::try_from_index(2).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
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
        vec![IlEdgeKinds::UNCONDITIONAL; 3],
    );
    let mut builder = ECodeBuilder::new(metadata, graph);

    let initial = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(7),
        [],
    )
    .unwrap();

    let phi = builder.emitter().emit_block_arg(block1, 32).unwrap();
    let sum = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Add, 32),
        [phi, phi],
    )
    .unwrap();

    builder
        .emitter()
        .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [sum], 0)
        .unwrap();

    builder.emitter().emit_edge_args([initial]).unwrap();
    builder.emitter().emit_edge_args([phi]).unwrap();
    builder.emitter().emit_edge_args([]).unwrap();

    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    ir.rewrite(ECodeConstantFolding);

    assert_eq!(
        ir.defining_op(sum).unwrap().opcode(),
        ECodeOpcode::Add
    );
    assert_eq!(ir.constant_value(sum), None);
}

#[test]
fn compact_removes_dead_operations_and_remaps_indices() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());

    let first = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(5),
        [],
    )
    .unwrap();
    let second = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(7),
        [],
    )
    .unwrap();

    let _dead = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Copy, 64),
        [first],
    )
    .unwrap();

    let sum = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Add, 64),
        [first, second],
    )
    .unwrap();
    builder
        .emitter()
        .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [sum], 0)
        .unwrap();

    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    assert_eq!(ir.ops().len(), 5);
    assert_eq!(ir.values().len(), 4);

    ir.rewrite(ECodeCompaction);

    assert_eq!(ir.ops().len(), 4);
    assert_eq!(ir.values().len(), 3);
    assert!(
        ir.ops()
            .iter()
            .all(|operation| operation.opcode() != ECodeOpcode::Copy)
    );
    ir.verify().unwrap();

    let add = ir
        .ops()
        .iter()
        .find(|operation| operation.opcode() == ECodeOpcode::Add)
        .unwrap();
    let operands = ir.op_operands_for(add);
    assert_eq!(
        ir.constant_value(operands[0]),
        Some(BitVec::from_u64(5, 64))
    );
    assert_eq!(
        ir.constant_value(operands[1]),
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
        vec![IlEdgeKinds::UNCONDITIONAL; 1],
    )
    .with_block_sources(vec![entry_source, exit_source]);
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, graph);

    let _ = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(1),
        [],
    )
    .unwrap();
    builder
        .emitter()
        .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [], 0)
        .unwrap();

    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    ir.rewrite(ECodeCompaction);

    assert!(ir.graph().blocks()[entry.index()].ops().is_empty());
    assert_eq!(ir.graph().block_source(entry), Some(entry_source));
    assert_eq!(ir.graph().block_source(exit), Some(exit_source));
    ir.verify().unwrap();
}

#[test]
fn compact_drops_dead_loop_phi_and_sources() {
    let block1 = IlBlockId::try_from_index(1).unwrap();
    let block2 = IlBlockId::try_from_index(2).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
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
        vec![IlEdgeKinds::UNCONDITIONAL; 3],
    );
    let mut builder = ECodeBuilder::new(metadata, graph);

    let initial = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(0),
        [],
    )
    .unwrap();

    let one = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(1),
        [],
    )
    .unwrap();

    let counter = builder.emitter().emit_block_arg(block1, 32).unwrap();
    let next = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Add, 32),
        [counter, one],
    )
    .unwrap();

    builder
        .emitter()
        .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [], 0)
        .unwrap();

    builder.emitter().emit_edge_args([initial]).unwrap();
    builder.emitter().emit_edge_args([next]).unwrap();
    builder.emitter().emit_edge_args([]).unwrap();

    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    ir.verify().unwrap();

    ir.rewrite(ECodeCompaction);
    ir.verify().unwrap();

    assert_eq!(ir.ops().len(), 1);
    assert_eq!(ir.ops()[0].opcode(), ECodeOpcode::Return);
    assert_eq!(ir.block_args().len(), 0);
    assert_eq!(ir.values().len(), 0);
    assert!(ir.args_for_edge(0).is_empty());
    assert!(ir.args_for_edge(1).is_empty());
}

#[test]
fn compact_preserves_live_phi_and_remaps_edge_args() {
    let block1 = IlBlockId::try_from_index(1).unwrap();
    let block2 = IlBlockId::try_from_index(2).unwrap();
    let block3 = IlBlockId::try_from_index(3).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
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
        vec![IlEdgeKinds::UNCONDITIONAL; 4],
    );
    let mut builder = ECodeBuilder::new(metadata, graph);

    let _ = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(99),
        [],
    )
    .unwrap();

    let left = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(5),
        [],
    )
    .unwrap();

    let right = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(9),
        [],
    )
    .unwrap();

    let phi = builder.emitter().emit_block_arg(block3, 32).unwrap();
    builder
        .emitter()
        .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [phi], 0)
        .unwrap();

    builder.emitter().emit_edge_args([]).unwrap();
    builder.emitter().emit_edge_args([]).unwrap();
    builder.emitter().emit_edge_args([left]).unwrap();
    builder.emitter().emit_edge_args([right]).unwrap();

    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    ir.verify().unwrap();

    ir.rewrite(ECodeCompaction);
    ir.verify().unwrap();

    assert_eq!(ir.ops().len(), 3);
    assert_eq!(ir.block_args().len(), 1);
    assert_eq!(ir.values().len(), 3);
    assert_eq!(ir.args_for_edge(2).len(), 1);
    assert_eq!(ir.args_for_edge(3).len(), 1);

    let return_op = ir
        .ops()
        .iter()
        .find(|operation| operation.opcode() == ECodeOpcode::Return)
        .unwrap();
    let consumed = ir.op_operands_for(return_op)[0];
    assert!(matches!(
        ir.values()[consumed.index()].definition(),
        IlSsaDef::BlockArg(_)
    ));
}

#[test]
fn compact_drops_one_of_two_phis_by_position() {
    let block1 = IlBlockId::try_from_index(1).unwrap();
    let block2 = IlBlockId::try_from_index(2).unwrap();
    let block3 = IlBlockId::try_from_index(3).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
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
        vec![IlEdgeKinds::UNCONDITIONAL; 4],
    );
    let mut builder = ECodeBuilder::new(metadata, graph);

    let narrow_left = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(5),
        [],
    )
    .unwrap();
    let wide_left = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(50),
        [],
    )
    .unwrap();

    let narrow_right = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 32).with_immediate(9),
        [],
    )
    .unwrap();
    let wide_right = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(90),
        [],
    )
    .unwrap();

    let _dead_phi = builder.emitter().emit_block_arg(block3, 32).unwrap();
    let live_phi = builder.emitter().emit_block_arg(block3, 64).unwrap();
    builder
        .emitter()
        .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [live_phi], 0)
        .unwrap();

    builder.emitter().emit_edge_args([]).unwrap();
    builder.emitter().emit_edge_args([]).unwrap();
    builder
        .emitter()
        .emit_edge_args([narrow_left, wide_left])
        .unwrap();
    builder
        .emitter()
        .emit_edge_args([narrow_right, wide_right])
        .unwrap();

    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    ir.verify().unwrap();

    ir.rewrite(ECodeCompaction);
    ir.verify().unwrap();

    assert_eq!(ir.block_args().len(), 1);
    assert_eq!(ir.block_args()[0].width(), 64);
    assert_eq!(ir.args_for_edge(2).len(), 1);
    assert_eq!(ir.args_for_edge(3).len(), 1);
    assert_eq!(ir.value_width(ir.args_for_edge(2)[0]), Some(64));
}

#[test]
fn fold_then_compact_collapses_constant_expression() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());

    let first = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(5),
        [],
    )
    .unwrap();
    let second = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(7),
        [],
    )
    .unwrap();

    let sum = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Add, 64),
        [first, second],
    )
    .unwrap();
    builder
        .emitter()
        .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [sum], 0)
        .unwrap();

    let mut ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    ir.rewrite(ECodeConstantFolding);
    ir.rewrite(ECodeCompaction);

    assert_eq!(ir.ops().len(), 2);
    ir.verify().unwrap();

    let returned = ir
        .ops()
        .iter()
        .find(|operation| operation.opcode() == ECodeOpcode::Return)
        .unwrap();
    let sum_value = ir.op_operands_for(returned)[0];
    assert_eq!(ir.constant_value(sum_value), Some(BitVec::from_u64(12, 64)));
}
