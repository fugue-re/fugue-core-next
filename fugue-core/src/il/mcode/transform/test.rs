use fugue_bv::BitVec;
use fugue_lifter::runtime::convention::{Convention, Prototype, PrototypeEntry, PrototypeOperand};

use super::*;
use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlGraph, IlIndexRange, IlMetadata,
    IlValueId, RegisterId,
};
use crate::il::ecode::ssa::{ECodeSsaBuilder, ECodeSsaDomain, ECodeSsaOp, ECodeSsaOpcode};
use crate::il::mcode::MCodeVarKind;
use crate::il::mcode::recovery::{MCodeCallFacts, MCodeStorageFact};
use crate::il::mcode::ssa::{MCodeSsaIr, MCodeSsaOpcode};
use crate::il::pcode::RegisterBank;
use crate::ir::{Address, FunctionId};
use crate::lifter::{Varnode, resolve_language};
use crate::storage::segments::space::AddressSpaceId;

const RAX: u64 = 0x00;
const RSP: u64 = 0x20;
const PAIR_HIGH: Varnode = Varnode::new(0, 0x08, 4);
const PAIR_LOW: Varnode = Varnode::new(0, 0x10, 4);
const PAIR_OUTPUT: Varnode = Varnode::new(0, RAX, 8);
const PAIR_INPUTS: [PrototypeEntry; 1] = [PrototypeEntry::new(
    8,
    8,
    1,
    PrototypeOperand::RegisterJoin(PAIR_HIGH, PAIR_LOW),
)];
const PAIR_OUTPUTS: [PrototypeEntry; 1] = [PrototypeEntry::new(
    8,
    8,
    1,
    PrototypeOperand::Register(PAIR_OUTPUT),
)];
const PAIR_PROTOTYPE: Prototype = Prototype::new("pair", 0, 0)
    .with_inputs(&PAIR_INPUTS)
    .with_outputs(&PAIR_OUTPUTS);
const PAIR_PROTOTYPES: [Prototype; 1] = [PAIR_PROTOTYPE];

fn config() -> MCodeRecoveryConfig<'static> {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let convention = Convention::new("test", Varnode::new(0, RSP, 8));
    MCodeRecoveryConfig::from_convention(&registers, &convention, Vec::new(), 64).unwrap()
}

fn convert(builder: ECodeSsaBuilder, config: &MCodeRecoveryConfig<'_>) -> MCodeSsaIr {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let source = builder.build(&CancellationToken::default()).unwrap();
    source.verify().unwrap();
    let recovery = MCodeRecovery::new(&source, config, &registers).unwrap();
    let mcode = ECodeSsaToMCode::default()
        .build(&source, &recovery, &CancellationToken::default())
        .unwrap();
    mcode.verify().unwrap();
    mcode
}

fn push_constant(builder: &mut ECodeSsaBuilder, width: u32, immediate: u64) -> IlValueId {
    let (value, results) = builder.push_result_value(width).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                results,
                IlIndexRange::EMPTY,
                width,
            )
            .with_immediate(immediate),
        )
        .unwrap();
    value
}

fn push_undefined(
    builder: &mut ECodeSsaBuilder,
    width: u32,
    domain: Option<ECodeSsaDomain>,
) -> IlValueId {
    let (value, results) = builder.push_result_value(width).unwrap();
    let immediate = match domain {
        Some(ECodeSsaDomain::Flag(flag)) => flag.value(),
        Some(ECodeSsaDomain::Memory(space)) => space.index() as u64,
        Some(ECodeSsaDomain::Register(register)) => register.value(),
        None => 0,
    };
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Undefined,
                results,
                IlIndexRange::EMPTY,
                width,
            )
            .with_immediate(immediate),
        )
        .unwrap();
    if let Some(domain) = domain {
        builder.set_value_domain(value, domain);
    }
    value
}

fn push_binary(
    builder: &mut ECodeSsaBuilder,
    opcode: ECodeSsaOpcode,
    left: IlValueId,
    right: IlValueId,
) -> IlValueId {
    let operands = builder.push_value_operands([left, right]).unwrap();
    let (value, results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(opcode, results, operands, 64))
        .unwrap();
    value
}

fn push_store(
    builder: &mut ECodeSsaBuilder,
    space: AddressSpaceId,
    pointer: IlValueId,
    value: IlValueId,
    memory: IlValueId,
) -> IlValueId {
    let operands = builder
        .push_value_operands([pointer, value, memory])
        .unwrap();
    let (result, results) = builder.push_result_value(0).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(ECodeSsaOpcode::Store, results, operands, 0).with_address_space(space),
        )
        .unwrap();
    builder.set_value_domain(result, ECodeSsaDomain::Memory(space));
    result
}

fn push_load(
    builder: &mut ECodeSsaBuilder,
    space: AddressSpaceId,
    pointer: IlValueId,
    memory: IlValueId,
    width: u32,
) -> IlValueId {
    let operands = builder.push_value_operands([pointer, memory]).unwrap();
    let (result, results) = builder.push_result_value(width).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(ECodeSsaOpcode::Load, results, operands, width)
                .with_address_space(space),
        )
        .unwrap();
    result
}

fn push_partial_write(
    builder: &mut ECodeSsaBuilder,
    previous: IlValueId,
    immediate: u64,
) -> IlValueId {
    let byte = push_constant(builder, 8, immediate);
    let insert_operands = builder.push_value_operands([previous, byte]).unwrap();
    let (inserted, insert_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(ECodeSsaOpcode::Insert, insert_results, insert_operands, 64)
                .with_immediate(16),
        )
        .unwrap();
    let write_operands = builder.push_value_operands([inserted]).unwrap();
    let (written, write_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::WriteRegister,
                write_results,
                write_operands,
                64,
            )
            .with_immediate(RAX),
        )
        .unwrap();
    builder.set_value_domain(written, ECodeSsaDomain::Register(RegisterId::new(RAX)));
    written
}

fn push_return(builder: &mut ECodeSsaBuilder, values: impl IntoIterator<Item = IlValueId>) {
    let operands = builder.push_value_operands(values).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            operands,
            0,
        ))
        .unwrap();
}

#[test]
fn a_register_write_becomes_a_bound_variable_definition() {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let convention = language.convention("gcc").unwrap();
    let config = MCodeRecoveryConfig::from_convention(
        &registers,
        convention,
        Vec::new(),
        language.address_bits(),
    )
    .unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());
    let (constant, constant_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                constant_results,
                IlIndexRange::EMPTY,
                64,
            )
            .with_immediate(7),
        )
        .unwrap();
    let operands = builder.push_value_operands([constant]).unwrap();
    let (written, written_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::WriteRegister,
            written_results,
            operands,
            64,
        ))
        .unwrap();
    builder.set_value_domain(written, ECodeSsaDomain::Register(RegisterId::new(0x38)));
    let return_operands = builder.push_value_operands([written]).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            return_operands,
            0,
        ))
        .unwrap();
    let source = builder.build(&CancellationToken::default()).unwrap();
    let recovery = MCodeRecovery::new(&source, &config, &registers).unwrap();

    let mcode = ECodeSsaToMCode::default()
        .build(&source, &recovery, &CancellationToken::default())
        .unwrap();

    mcode.verify().unwrap();
    assert!(
        mcode
            .operations()
            .iter()
            .any(|operation| operation.opcode() == MCodeSsaOpcode::Constant)
    );
    assert!(
        mcode
            .values()
            .iter()
            .any(|value| value.variable().is_some())
    );
}

#[test]
fn a_partial_register_write_uses_the_immediate_predecessor() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());
    let previous = push_undefined(
        &mut builder,
        64,
        Some(ECodeSsaDomain::Register(RegisterId::new(RAX))),
    );
    let written = push_partial_write(&mut builder, previous, 0x7f);
    push_return(&mut builder, [written]);

    let mcode = convert(builder, &config());
    let field = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeSsaOpcode::SetVarField)
        .expect("the partial write is retained");
    let operands = mcode.operation_operands_for(field);
    let previous = mcode.binding(operands[0]).unwrap();
    let result = mcode
        .binding(IlValueId::try_from_index(field.results().start()).unwrap())
        .unwrap();

    assert_eq!(field.immediate(), 16);
    assert_eq!(previous.variable(), result.variable());
    assert_eq!(previous.version().checked_next(), Some(result.version()));
}

#[test]
fn sibling_partial_writes_materialise_a_non_adjacent_predecessor() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());
    let previous = push_undefined(
        &mut builder,
        64,
        Some(ECodeSsaDomain::Register(RegisterId::new(RAX))),
    );
    let branch_operands = builder.push_value_operands([previous]).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::ConditionalBranch,
                IlIndexRange::EMPTY,
                branch_operands,
                0,
            )
            .with_address(Address::from(0x1000u64)),
        )
        .unwrap();
    let left = push_partial_write(&mut builder, previous, 0x11);
    push_return(&mut builder, [left]);
    let right = push_partial_write(&mut builder, previous, 0x22);
    push_return(&mut builder, [right]);
    builder.set_graph(IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::new(0, 2).unwrap(),
                IlIndexRange::new(0, 2).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(2, 6).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
            IlBlock::new(
                IlIndexRange::new(6, 10).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        vec![
            IlBlockId::try_from_index(1).unwrap(),
            IlBlockId::try_from_index(2).unwrap(),
        ],
        vec![IlEdgeKinds::FALL_THROUGH, IlEdgeKinds::TAKEN],
    ));

    let mcode = convert(builder, &config());
    let field_count = mcode
        .operations()
        .iter()
        .filter(|operation| operation.opcode() == MCodeSsaOpcode::SetVarField)
        .count();
    let full = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeSsaOpcode::SetVar)
        .expect("one sibling materialises a full assignment");
    let materialised = mcode.operation_operands_for(full)[0];

    assert_eq!(field_count, 1);
    assert_eq!(
        mcode
            .defining_operation(materialised)
            .map(|operation| operation.opcode()),
        Some(MCodeSsaOpcode::Insert)
    );
}

#[test]
fn a_fixed_stack_slot_promotes_store_and_load() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());
    let space = AddressSpaceId::new(0);
    builder.ensure_memory_domain(space);
    let stack_pointer = push_undefined(
        &mut builder,
        64,
        Some(ECodeSsaDomain::Register(RegisterId::new(RSP))),
    );
    let frame_size = push_constant(&mut builder, 64, 0x20);
    let address = push_binary(&mut builder, ECodeSsaOpcode::Sub, stack_pointer, frame_size);
    let stored = push_undefined(&mut builder, 64, None);
    let memory = push_undefined(&mut builder, 0, Some(ECodeSsaDomain::Memory(space)));
    let memory = push_store(&mut builder, space, address, stored, memory);
    let loaded = push_load(&mut builder, space, address, memory, 64);
    push_return(&mut builder, [loaded]);

    let mcode = convert(builder, &config());
    let assignment = mcode
        .operations()
        .iter()
        .find(|operation| {
            operation.opcode() == MCodeSsaOpcode::SetVar
                && operation
                    .variable()
                    .and_then(|variable| mcode.variable(variable))
                    .is_some_and(|variable| variable.kind() == MCodeVarKind::Stack)
        })
        .expect("the stack store is promoted");
    let assigned = IlValueId::try_from_index(assignment.results().start()).unwrap();
    let returned = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeSsaOpcode::Return)
        .and_then(|operation| mcode.operation_operands_for(operation).first())
        .copied();

    assert_eq!(returned, Some(assigned));
    assert!(!mcode.operations().iter().any(|operation| matches!(
        operation.opcode(),
        MCodeSsaOpcode::Load | MCodeSsaOpcode::Store
    )));
    assert!(mcode.aliased_variables().is_empty());
}

#[test]
fn an_address_taken_stack_slot_uses_aliased_operations() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());
    let space = AddressSpaceId::new(0);
    builder.ensure_memory_domain(space);
    let stack_pointer = push_undefined(
        &mut builder,
        64,
        Some(ECodeSsaDomain::Register(RegisterId::new(RSP))),
    );
    let frame_size = push_constant(&mut builder, 64, 0x20);
    let address = push_binary(&mut builder, ECodeSsaOpcode::Sub, stack_pointer, frame_size);
    let stored = push_constant(&mut builder, 64, 0x2a);
    let memory = push_undefined(&mut builder, 0, Some(ECodeSsaDomain::Memory(space)));
    let memory = push_store(&mut builder, space, address, stored, memory);
    let loaded = push_load(&mut builder, space, address, memory, 64);
    let returned = push_binary(&mut builder, ECodeSsaOpcode::Add, address, loaded);
    push_return(&mut builder, [returned]);

    let mcode = convert(builder, &config());

    assert!(mcode.operations().iter().any(|operation| {
        operation.opcode() == MCodeSsaOpcode::SetVarAliased
            && operation
                .variable()
                .is_some_and(|variable| mcode.is_aliased(variable))
    }));
    assert!(
        mcode
            .operations()
            .iter()
            .any(|operation| operation.opcode() == MCodeSsaOpcode::AddressOf)
    );
    assert!(
        mcode
            .operations()
            .iter()
            .any(|operation| operation.opcode() == MCodeSsaOpcode::VarAliased)
    );
}

#[test]
fn call_outputs_bind_the_post_call_register_definition() {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let convention =
        Convention::new("pair", Varnode::new(0, RSP, 8)).with_prototypes(&PAIR_PROTOTYPES);
    let config =
        MCodeRecoveryConfig::from_convention(&registers, &convention, Vec::new(), 64).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());
    let space = AddressSpaceId::new(0);
    builder.ensure_memory_domain(space);

    push_undefined(
        &mut builder,
        32,
        Some(ECodeSsaDomain::Register(RegisterId::new(
            PAIR_HIGH.offset(),
        ))),
    );
    push_undefined(
        &mut builder,
        32,
        Some(ECodeSsaDomain::Register(RegisterId::new(PAIR_LOW.offset()))),
    );
    let pointer = push_constant(&mut builder, 64, 0x2000);
    let stored = push_undefined(&mut builder, 64, None);

    let (initial_memory, initial_memory_results) = builder.push_result_value(0).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Undefined,
                initial_memory_results,
                IlIndexRange::EMPTY,
                0,
            )
            .with_immediate(0),
        )
        .unwrap();
    builder.set_value_domain(initial_memory, ECodeSsaDomain::Memory(space));
    push_store(&mut builder, space, pointer, stored, initial_memory);
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Call,
                IlIndexRange::EMPTY,
                IlIndexRange::EMPTY,
                0,
            )
            .with_address(Address::from(0x1000u64)),
        )
        .unwrap();

    let (post_memory, post_memory_results) = builder.push_result_value(0).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Undefined,
                post_memory_results,
                IlIndexRange::EMPTY,
                0,
            )
            .with_immediate(0),
        )
        .unwrap();
    builder.set_value_domain(post_memory, ECodeSsaDomain::Memory(space));

    let (output, output_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Undefined,
            output_results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();
    builder.set_value_domain(output, ECodeSsaDomain::Register(RegisterId::new(RAX)));
    let loaded = push_load(&mut builder, space, pointer, post_memory, 64);
    push_return(&mut builder, [loaded]);
    let source = builder.build(&CancellationToken::default()).unwrap();
    let recovery = MCodeRecovery::new(&source, &config, &registers).unwrap();

    let mcode = ECodeSsaToMCode::default()
        .build(&source, &recovery, &CancellationToken::default())
        .unwrap();
    let call = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeSsaOpcode::Call)
        .expect("the call survives optimisation");
    let output = IlValueId::try_from_index(call.results().start() + 1).unwrap();
    let binding = mcode.binding(output).expect("the call output is bound");
    let returned = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeSsaOpcode::Return)
        .and_then(|operation| mcode.operation_operands_for(operation).first())
        .copied();
    let split = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeSsaOpcode::VarSplit)
        .expect("the register-pair argument is reconstructed");
    let stored_memory = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeSsaOpcode::Store)
        .and_then(|operation| IlValueId::try_from_index(operation.results().start()).ok())
        .expect("the general store is retained");
    let load = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeSsaOpcode::Load)
        .expect("the general load is retained");
    let loaded_memory = mcode.memory_operand(load).unwrap();
    let call_operands = mcode.operation_operands_for(call);

    mcode.verify().unwrap();
    assert_eq!(call.results().len(), 2);
    assert_eq!(mcode.values()[call.results().start()].width(), 0);
    assert!(
        mcode
            .operation_operands_for(split)
            .iter()
            .all(|&value| mcode.value_width(value) == Some(32))
    );
    assert_eq!(call_operands[0].index(), split.results().start());
    assert_eq!(call_operands.last(), Some(&stored_memory));
    assert_eq!(loaded_memory.index(), call.results().start());
    assert_eq!(
        mcode.variable(binding.variable()).unwrap().register_id(),
        Some(RegisterId::new(RAX))
    );
    assert_eq!(
        returned.map(|value| value.index()),
        Some(load.results().start())
    );
}

#[test]
fn exact_stack_call_facts_materialise_stack_inputs_and_outputs() {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());
    let space = AddressSpaceId::new(0);
    builder.ensure_memory_domain(space);
    let (memory, memory_results) = builder.push_result_value(0).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Undefined,
                memory_results,
                IlIndexRange::EMPTY,
                0,
            )
            .with_immediate(0),
        )
        .unwrap();
    builder.set_value_domain(memory, ECodeSsaDomain::Memory(space));
    let call = builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Call,
                IlIndexRange::EMPTY,
                IlIndexRange::EMPTY,
                0,
            )
            .with_address(Address::from(0x1000u64)),
        )
        .unwrap();
    push_return(&mut builder, [memory]);
    let source = builder.build(&CancellationToken::default()).unwrap();
    let mut facts = MCodeCallFacts::new();
    facts.add_input(
        call,
        MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -16 }, 128),
    );
    facts.add_output(
        call,
        MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: 8 }, 192),
    );
    let config = config().with_call_facts(&facts);
    let recovery = MCodeRecovery::new(&source, &config, &registers).unwrap();

    let mcode = ECodeSsaToMCode::default()
        .build(&source, &recovery, &CancellationToken::default())
        .unwrap();
    let call = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeSsaOpcode::Call)
        .expect("the stack call survives optimisation");
    let output = IlValueId::try_from_index(call.results().start() + 1).unwrap();
    let variable = mcode
        .binding(output)
        .expect("the stack output is bound")
        .variable();

    mcode.verify().unwrap();
    assert_eq!(call.operands().len(), 2);
    assert_eq!(call.results().len(), 2);
    assert_eq!(mcode.values()[output.index()].width(), 192);
    assert_eq!(
        mcode.variable(variable).unwrap().kind(),
        MCodeVarKind::Stack
    );
    assert!(mcode.is_aliased(variable));
}

#[test]
fn a_resolved_indirect_branch_becomes_a_switch() {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let config = config();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());
    let (selector, selector_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Undefined,
            selector_results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();
    let branch_operands = builder.push_value_operands([selector]).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::BranchIndirect,
                IlIndexRange::EMPTY,
                branch_operands,
                0,
            )
            .with_address_space(AddressSpaceId::new(0)),
        )
        .unwrap();
    let return_operands = builder.push_value_operands([selector]).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            return_operands,
            0,
        ))
        .unwrap();
    builder.set_graph(IlGraph::new(
        vec![
            IlBlock::new(
                IlIndexRange::new(0, 2).unwrap(),
                IlIndexRange::new(0, 1).unwrap(),
                IlBlockProperties::ENTRY,
            ),
            IlBlock::new(
                IlIndexRange::new(2, 3).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            ),
        ],
        vec![IlBlockId::try_from_index(1).unwrap()],
        vec![IlEdgeKinds::COMPUTED],
    ));
    let source = builder.build(&CancellationToken::default()).unwrap();
    let recovery = MCodeRecovery::new(&source, &config, &registers).unwrap();

    let mcode = ECodeSsaToMCode::default()
        .build(&source, &recovery, &CancellationToken::default())
        .unwrap();

    mcode.verify().unwrap();
    assert!(
        mcode
            .operations()
            .iter()
            .any(|operation| operation.opcode() == MCodeSsaOpcode::Switch)
    );
}

#[test]
fn conversion_copies_only_emitted_wide_constants() {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let config = config();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());
    let (constant, results) = builder.push_result_value(128).unwrap();
    let operation = builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Constant,
            results,
            IlIndexRange::EMPTY,
            128,
        ))
        .unwrap();
    let return_operands = builder.push_value_operands([constant]).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Return,
            IlIndexRange::EMPTY,
            return_operands,
            0,
        ))
        .unwrap();
    let mut source = builder.build(&CancellationToken::default()).unwrap();
    let constant_value = BitVec::from_le_bytes(&[
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23,
        0x01,
    ]);
    source
        .rewriter()
        .replace_with_constant(operation, &constant_value);
    source.verify().unwrap();
    let recovery = MCodeRecovery::new(&source, &config, &registers).unwrap();

    let mcode = ECodeSsaToMCode::default()
        .build(&source, &recovery, &CancellationToken::default())
        .unwrap();
    let returned = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeSsaOpcode::Return)
        .and_then(|operation| mcode.operation_operands_for(operation).first())
        .copied()
        .expect("the wide constant is returned");

    mcode.verify().unwrap();
    assert_eq!(mcode.constant_value(returned), Some(constant_value));
    assert_eq!(mcode.constant_storage().len(), 16);
}
