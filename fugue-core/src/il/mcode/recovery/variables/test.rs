use super::*;
use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlGraph, IlIndexRange, IlMetadata,
    RegisterId,
};
use crate::il::ecode::ssa::{ECodeSsaBuilder, ECodeSsaOp, ECodeSsaOpcode};
use crate::il::mcode::recovery::MCodeStackModel;
use crate::ir::FunctionId;
use crate::storage::segments::space::AddressSpaceId;

const REGISTER: u64 = 0x10;

fn builder() -> ECodeSsaBuilder {
    ECodeSsaBuilder::new(
        IlMetadata::new(FunctionId::default(), 0),
        IlGraph::default(),
    )
}

fn register_definition(builder: &mut ECodeSsaBuilder) -> IlValueId {
    let (id, results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Undefined,
            results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();
    builder.set_value_domain(id, ECodeSsaDomain::Register(RegisterId::new(REGISTER)));
    id
}

fn table(ir: &ECodeSsaIr) -> MCodeVariableModel {
    let stack = MCodeStackModel::new(ir, RegisterId::new(0xffff), []);
    MCodeVariableModel::new(ir, &stack)
}

struct Function {
    builder: ECodeSsaBuilder,
    operations: usize,
}

impl Function {
    fn new() -> Self {
        Self {
            builder: ECodeSsaBuilder::new(
                IlMetadata::new(FunctionId::default(), 0),
                IlGraph::default(),
            ),
            operations: 0,
        }
    }

    fn constant(&mut self, value: u64) -> IlValueId {
        let (id, results) = self.builder.push_result_value(64).unwrap();
        self.builder
            .push_operation(
                ECodeSsaOp::new(ECodeSsaOpcode::Constant, results, IlIndexRange::EMPTY, 64)
                    .with_immediate(value),
            )
            .unwrap();
        self.operations += 1;
        id
    }

    fn unary(&mut self, opcode: ECodeSsaOpcode, source: IlValueId, register: bool) -> IlValueId {
        let operands = self.builder.push_value_operands([source]).unwrap();
        let (id, results) = self.builder.push_result_value(64).unwrap();
        self.builder
            .push_operation(ECodeSsaOp::new(opcode, results, operands, 64).with_immediate(REGISTER))
            .unwrap();
        if register {
            self.builder
                .set_value_domain(id, ECodeSsaDomain::Register(RegisterId::new(REGISTER)));
        }
        self.operations += 1;
        id
    }

    fn binary(&mut self, opcode: ECodeSsaOpcode, left: IlValueId, right: IlValueId) -> IlValueId {
        let operands = self.builder.push_value_operands([left, right]).unwrap();
        let (id, results) = self.builder.push_result_value(64).unwrap();
        self.builder
            .push_operation(ECodeSsaOp::new(opcode, results, operands, 64))
            .unwrap();
        self.operations += 1;
        id
    }

    fn finish(mut self) -> ECodeSsaIr {
        self.builder.set_graph(IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::new(0, self.operations).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::ENTRY,
            )],
            Vec::new(),
            Vec::new(),
        ));
        self.builder.build(&CancellationToken::default()).unwrap()
    }

    fn finish_linear(self) -> ECodeSsaIr {
        self.builder.build(&CancellationToken::default()).unwrap()
    }
}

fn branching_ir(reverse: bool) -> ECodeSsaIr {
    let left = IlBlockId::try_from_index(1).unwrap();
    let right = IlBlockId::try_from_index(2).unwrap();
    let mut builder = builder();
    register_definition(&mut builder);
    register_definition(&mut builder);
    let (successors, kinds) = if reverse {
        (
            vec![right, left],
            vec![IlEdgeKinds::TAKEN, IlEdgeKinds::FALL_THROUGH],
        )
    } else {
        (
            vec![left, right],
            vec![IlEdgeKinds::FALL_THROUGH, IlEdgeKinds::TAKEN],
        )
    };
    builder.set_graph(IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::new(0, 2).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
            IlBlock::new(
                IlIndexRange::new(1, 2).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        successors,
        kinds,
    ));
    builder.build(&CancellationToken::default()).unwrap()
}

#[test]
fn disjoint_register_definitions_split_by_lifetime() {
    let mut builder = builder();
    let first = register_definition(&mut builder);
    let second = register_definition(&mut builder);

    let ir = builder.build(&CancellationToken::default()).unwrap();
    let table = table(&ir);

    let first_variable = table.variable_for_value(first).unwrap();
    let second_variable = table.variable_for_value(second).unwrap();
    assert_ne!(first_variable, second_variable);

    let first = table.variables()[first_variable.index()];
    let second = table.variables()[second_variable.index()];
    assert_eq!(first.kind(), MCodeVarKind::Register);
    assert_eq!(first.register_id(), Some(RegisterId::new(REGISTER)));
    assert_eq!(second.register_id(), Some(RegisterId::new(REGISTER)));
    assert_ne!(first.index(), second.index());
}

#[test]
fn a_phi_connected_web_is_one_variable() {
    let entry = IlBlockId::try_from_index(0).unwrap();
    let merge = IlBlockId::try_from_index(1).unwrap();
    let mut builder = builder();

    builder.set_graph(IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::new(0, 1).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        vec![merge],
        vec![IlEdgeKinds::UNCONDITIONAL],
    ));

    let _ = entry;
    let definition = register_definition(&mut builder);
    let argument = builder.push_block_argument_value(merge, 64).unwrap();
    builder.set_value_domain(
        argument,
        ECodeSsaDomain::Register(RegisterId::new(REGISTER)),
    );
    builder.push_edge_arguments([definition]).unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();
    let table = table(&ir);

    assert_eq!(
        table.variable_for_value(definition),
        table.variable_for_value(argument)
    );
}

#[test]
fn stack_objects_become_stack_variables() {
    let mut builder = builder();
    let sp = {
        let (id, results) = builder.push_result_value(64).unwrap();
        builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::Undefined,
                results,
                IlIndexRange::EMPTY,
                64,
            ))
            .unwrap();
        builder.set_value_domain(id, ECodeSsaDomain::Register(RegisterId::new(0x20)));
        id
    };
    let size = {
        let (id, results) = builder.push_result_value(64).unwrap();
        builder
            .push_operation(
                ECodeSsaOp::new(ECodeSsaOpcode::Constant, results, IlIndexRange::EMPTY, 64)
                    .with_immediate(0x10),
            )
            .unwrap();
        id
    };
    let operands = builder.push_value_operands([sp, size]).unwrap();
    let (frame, frame_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Sub,
            frame_results,
            operands,
            64,
        ))
        .unwrap();
    let value = {
        let (id, results) = builder.push_result_value(64).unwrap();
        builder
            .push_operation(
                ECodeSsaOp::new(ECodeSsaOpcode::Constant, results, IlIndexRange::EMPTY, 64)
                    .with_immediate(1),
            )
            .unwrap();
        id
    };
    let (memory, _) = builder.push_result_value(0).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Undefined,
            IlIndexRange::EMPTY,
            IlIndexRange::EMPTY,
            0,
        ))
        .unwrap();
    let space = AddressSpaceId::new(0);
    builder.set_value_domain(memory, ECodeSsaDomain::Memory(space));
    builder.ensure_memory_domain(space);
    let store_operands = builder.push_value_operands([frame, value, memory]).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Store,
                IlIndexRange::EMPTY,
                store_operands,
                0,
            )
            .with_address_space(space),
        )
        .unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();
    let stack = MCodeStackModel::new(&ir, RegisterId::new(0x20), []);
    let table = MCodeVariableModel::new(&ir, &stack);

    let variable = table
        .stack_variable(MCodeStackObjectId::from_index(0))
        .expect("one stack object");
    assert_eq!(
        table.variables()[variable.index()].kind(),
        MCodeVarKind::Stack
    );
    assert_eq!(
        table.variables()[variable.index()].stack_offset(),
        Some(-0x10)
    );
}

#[test]
fn an_overlapping_redefinition_is_one_variable() {
    let mut function = Function::new();
    let first_value = function.constant(1);
    let first = function.unary(ECodeSsaOpcode::WriteRegister, first_value, true);
    let second_value = function.constant(2);
    let second = function.unary(ECodeSsaOpcode::WriteRegister, second_value, true);
    function.binary(ECodeSsaOpcode::Add, first, second);
    let ir = function.finish();

    let table = table(&ir);

    assert_eq!(
        table.variable_for_value(first),
        table.variable_for_value(second)
    );
    let variable = table.variable_for_value(first).unwrap();
    assert_eq!(table.variables()[variable.index()].index(), 0);
}

#[test]
fn an_overlapping_linear_redefinition_is_one_variable() {
    let mut function = Function::new();
    let first_value = function.constant(1);
    let first = function.unary(ECodeSsaOpcode::WriteRegister, first_value, true);
    let second_value = function.constant(2);
    let second = function.unary(ECodeSsaOpcode::WriteRegister, second_value, true);
    function.binary(ECodeSsaOpcode::Add, first, second);
    let ir = function.finish_linear();

    let table = table(&ir);

    assert_eq!(
        table.variable_for_value(first),
        table.variable_for_value(second)
    );
}

#[test]
fn a_partial_update_stays_one_variable() {
    let mut function = Function::new();
    let initial = function.constant(0x1122_3344);
    let whole = function.unary(ECodeSsaOpcode::WriteRegister, initial, true);
    let byte = function.constant(0xff);
    let inserted = function.binary(ECodeSsaOpcode::Insert, whole, byte);
    let updated = function.unary(ECodeSsaOpcode::WriteRegister, inserted, true);
    let ir = function.finish();

    let table = table(&ir);

    assert_eq!(
        table.variable_for_value(whole),
        table.variable_for_value(updated)
    );
    let variable = table.variable_for_value(whole).unwrap();
    assert_eq!(table.variables()[variable.index()].index(), 0);
}

#[test]
fn proven_disjoint_redefinitions_split_into_distinct_variables() {
    let mut function = Function::new();
    let first_value = function.constant(1);
    let first = function.unary(ECodeSsaOpcode::WriteRegister, first_value, true);
    function.unary(ECodeSsaOpcode::Copy, first, false);
    let second_value = function.constant(2);
    let second = function.unary(ECodeSsaOpcode::WriteRegister, second_value, true);
    function.unary(ECodeSsaOpcode::Copy, second, false);
    let ir = function.finish();

    let table = table(&ir);

    let first_variable = table.variable_for_value(first).unwrap();
    let second_variable = table.variable_for_value(second).unwrap();
    assert_ne!(first_variable, second_variable);
    assert_eq!(
        table.variables()[first_variable.index()].register_id(),
        Some(RegisterId::new(REGISTER))
    );
    assert_ne!(
        table.variables()[first_variable.index()].index(),
        table.variables()[second_variable.index()].index()
    );
}

#[test]
fn shared_expression_ancestry_is_coalesced_once() {
    let mut function = Function::new();
    let initial = function.constant(1);
    let initial = function.unary(ECodeSsaOpcode::WriteRegister, initial, true);
    let mut shared = initial;
    for _ in 0..2048 {
        shared = function.unary(ECodeSsaOpcode::Copy, shared, false);
    }
    let mut definitions = Vec::new();
    for _ in 0..2048 {
        definitions.push(function.unary(ECodeSsaOpcode::WriteRegister, shared, true));
    }
    let ir = function.finish();

    let table = table(&ir);
    let expected = table.variable_for_value(initial);

    assert!(
        definitions
            .iter()
            .all(|&definition| table.variable_for_value(definition) == expected)
    );
}

#[test]
fn successor_order_does_not_rename_variables() {
    let forward = table(&branching_ir(false));
    let reverse = table(&branching_ir(true));

    assert_eq!(forward.variables(), reverse.variables());
}
