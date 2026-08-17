use fugue_bv::BitVec;
use fugue_lifter::runtime::convention::{Convention, Prototype, PrototypeEntry, PrototypeOperand};

use super::variables::{MCodeCallOutputSite, MCodeCallOutputVariables};
use super::*;
use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlGraph, IlIndexRange,
    IlMetadata, IlOpId, IlSsaDef, IlValueId, RegisterBank, RegisterId,
};
use crate::il::ecode::test::emit_value;
use crate::il::ecode::{ECodeBuilder, ECodeDomain, ECodeIr, ECodeOpSpec, ECodeOpcode};
use crate::il::mcode::recovery::{MCodeAliasOverride, MCodeAliasOverrides};
use crate::il::mcode::{
    MCodeBuilder, MCodeCallFacts, MCodeFunctionFacts, MCodeIr, MCodeOpcode, MCodeOptimiser,
    MCodeStorageFact, MCodeStorageLocation, MCodeVar, MCodeVarKind,
};
use crate::ir::{Address, FunctionId};
use crate::lifter::{Varnode, resolve_language};
use crate::storage::segments::space::AddressSpaceId;

const RAX: u64 = 0x00;
const RDX: u64 = 0x28;
const RSI: u64 = 0x30;
const RDI: u64 = 0x38;
const RSP: u64 = 0x20;
const PAIR_HIGH: Varnode = Varnode::new(0, 0x08, 8);
const PAIR_LOW: Varnode = Varnode::new(0, 0x10, 8);
const PAIR_OUTPUT: Varnode = Varnode::new(0, RAX, 8);
const PAIR_INPUTS: [PrototypeEntry; 1] = [PrototypeEntry::new(
    16,
    16,
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
    MCodeRecoveryConfig::from_convention(&registers, &convention, Vec::new()).unwrap()
}

fn call_source(function: FunctionId) -> (ECodeIr, IlOpId) {
    let metadata = IlMetadata::new(function, 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let input = push_undefined(
        &mut builder,
        64,
        Some(ECodeDomain::Register(RegisterId::new(RDI))),
    );
    let site = builder
        .emitter()
        .emit(
            ECodeOpSpec::new(ECodeOpcode::Call, 0).with_address(Address::from(0x1000u64)),
            [],
            0,
        )
        .map(|(operation, _)| operation)
        .unwrap();
    push_return(&mut builder, [input]);
    (builder.build(&CancellationToken::default()).unwrap(), site)
}

fn lift_stack_call_case(
    inputs: &[MCodeStorageFact],
    output: MCodeStorageFact,
    alias: MCodeAliasOverride,
) -> MCodeIr {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let site = builder
        .emitter()
        .emit(
            ECodeOpSpec::new(ECodeOpcode::Call, 0).with_address(Address::from(0x1000u64)),
            [],
            0,
        )
        .map(|(operation, _)| operation)
        .unwrap();
    let source = builder.build(&CancellationToken::default()).unwrap();
    let mut call = MCodeCallFacts::new(site);
    call.set_inputs(inputs.iter().copied());
    call.set_outputs([output]);
    let mut facts = MCodeFunctionFacts::new(source.metadata().function());
    facts.insert_call(call);
    let object_start = inputs
        .iter()
        .chain([&output])
        .filter_map(|fact| match fact.location() {
            MCodeStorageLocation::Stack { offset } => Some(offset),
            _ => None,
        })
        .min()
        .expect("the case contains stack storage");
    let mut overrides = MCodeAliasOverrides::default();
    overrides.insert(MCodeVar::stack(object_start), alias);
    let config = config()
        .with_call_facts(&facts)
        .with_alias_overrides(&overrides);
    let recovery = MCodeRecovery::new(&source, &config, &registers).unwrap();

    lift_recovered(&source, &recovery)
}

fn lift_stack_return_case(output: MCodeStorageFact, alias: MCodeAliasOverride) -> MCodeIr {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let space = AddressSpaceId::new(0);
    builder.emitter().intern_memory_domain(space);
    let stack_pointer = push_undefined(
        &mut builder,
        64,
        Some(ECodeDomain::Register(RegisterId::new(RSP))),
    );
    let frame_size = push_constant(&mut builder, 64, 16);
    let address = push_binary(&mut builder, ECodeOpcode::Sub, stack_pointer, frame_size);
    let value = push_constant(&mut builder, 64, 0x2a);
    let memory = push_undefined(&mut builder, 0, Some(ECodeDomain::Memory(space)));
    push_store(&mut builder, space, address, value, memory);
    push_return(&mut builder, [value]);
    let source = builder.build(&CancellationToken::default()).unwrap();
    let mut facts = MCodeFunctionFacts::new(source.metadata().function());
    facts.set_return_live_outputs([output]);
    let mut overrides = MCodeAliasOverrides::default();
    overrides.insert(MCodeVar::stack(-16), alias);
    let config = config()
        .with_call_facts(&facts)
        .with_alias_overrides(&overrides);
    let recovery = MCodeRecovery::new(&source, &config, &registers).unwrap();

    lift_recovered(&source, &recovery)
}

fn transform_with_config(builder: ECodeBuilder, config: &MCodeRecoveryConfig<'_>) -> MCodeIr {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let source = builder.build(&CancellationToken::default()).unwrap();
    source.verify().unwrap();
    let recovery = MCodeRecovery::new(&source, config, &registers).unwrap();
    lift_recovered(&source, &recovery)
}

fn lift_recovered(source: &ECodeIr, recovery: &MCodeRecovery) -> MCodeIr {
    let metadata = IlMetadata::new(
        source.metadata().function(),
        source.metadata().input_revision(),
    );
    let builder = MCodeBuilder::new(metadata, IlGraph::default());
    let mut scratch = ECodeToMCodeScratch::default();
    let mut mcode = ECodeToMCodeLifter::new(source, recovery, builder, &mut scratch)
        .unwrap()
        .lift(&CancellationToken::default())
        .unwrap();
    mcode.rewrite(MCodeOptimiser::new(&scratch.required_values));
    mcode.verify().unwrap();
    mcode
}

fn push_constant(builder: &mut ECodeBuilder, width: u32, immediate: u64) -> IlValueId {
    emit_value(
        builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, width).with_immediate(immediate),
        [],
    )
    .unwrap()
}

fn push_undefined(
    builder: &mut ECodeBuilder,
    width: u32,
    domain: Option<ECodeDomain>,
) -> IlValueId {
    let immediate = match domain {
        Some(ECodeDomain::Flag(flag)) => flag.value(),
        Some(ECodeDomain::Memory(space)) => u64::from(space.value()),
        Some(ECodeDomain::Register(register)) => register.value(),
        None => 0,
    };
    let value = emit_value(
        builder,
        ECodeOpSpec::new(ECodeOpcode::Undefined, width).with_immediate(immediate),
        [],
    )
    .unwrap();
    if let Some(domain) = domain {
        builder.emitter().set_value_domain(value, domain).unwrap();
    }
    value
}

fn push_binary(
    builder: &mut ECodeBuilder,
    opcode: ECodeOpcode,
    left: IlValueId,
    right: IlValueId,
) -> IlValueId {
    emit_value(builder, ECodeOpSpec::new(opcode, 64), [left, right]).unwrap()
}

fn push_store(
    builder: &mut ECodeBuilder,
    space: AddressSpaceId,
    pointer: IlValueId,
    value: IlValueId,
    memory: IlValueId,
) -> IlValueId {
    let result = emit_value(
        builder,
        ECodeOpSpec::new(ECodeOpcode::Store, 0).with_address_space(space),
        [pointer, value, memory],
    )
    .unwrap();
    builder
        .emitter()
        .set_value_domain(result, ECodeDomain::Memory(space))
        .unwrap();
    result
}

fn push_load(
    builder: &mut ECodeBuilder,
    space: AddressSpaceId,
    pointer: IlValueId,
    memory: IlValueId,
    width: u32,
) -> IlValueId {
    emit_value(
        builder,
        ECodeOpSpec::new(ECodeOpcode::Load, width).with_address_space(space),
        [pointer, memory],
    )
    .unwrap()
}

fn push_partial_write(
    builder: &mut ECodeBuilder,
    previous: IlValueId,
    immediate: u64,
) -> IlValueId {
    let byte = push_constant(builder, 8, immediate);
    let inserted = emit_value(
        builder,
        ECodeOpSpec::new(ECodeOpcode::Insert, 64).with_immediate(16),
        [previous, byte],
    )
    .unwrap();
    let written = emit_value(
        builder,
        ECodeOpSpec::new(ECodeOpcode::WriteRegister, 64).with_immediate(RAX),
        [inserted],
    )
    .unwrap();
    builder
        .emitter()
        .set_value_domain(written, ECodeDomain::Register(RegisterId::new(RAX)))
        .unwrap();
    written
}

fn push_return(builder: &mut ECodeBuilder, values: impl IntoIterator<Item = IlValueId>) {
    builder
        .emitter()
        .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), values, 0)
        .unwrap();
}

#[test]
fn memory_domain_identifiers_round_trip_through_ecode_and_mcode() {
    let space = AddressSpaceId::from(u16::MAX);
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let pointer = push_constant(&mut builder, 64, 0x1000);
    let stored = push_constant(&mut builder, 64, 0x2a);
    let memory = push_undefined(&mut builder, 0, Some(ECodeDomain::Memory(space)));
    push_store(&mut builder, space, pointer, stored, memory);
    push_return(&mut builder, [stored]);
    let source = builder.build(&CancellationToken::default()).unwrap();
    let IlSsaDef::Op(memory_definition) = source.values()[memory.index()].definition()
    else {
        panic!("the ECode memory value is operation-defined");
    };
    let encoded = source.operations()[memory_definition.index()].immediate();
    assert_eq!(encoded, u64::from(space.value()));
    assert_eq!(
        AddressSpaceId::try_new(usize::try_from(encoded).unwrap()).unwrap(),
        space
    );

    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let recovery = MCodeRecovery::new(&source, &config(), &registers).unwrap();
    let mcode = lift_recovered(&source, &recovery);
    let encoded = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeOpcode::Undefined && operation.width() == 0)
        .expect("the MCode memory input is retained")
        .immediate();
    assert_eq!(encoded, u64::from(space.value()));
    assert_eq!(
        AddressSpaceId::try_new(usize::try_from(encoded).unwrap()).unwrap(),
        space
    );
}

#[test]
fn a_register_write_becomes_a_bound_variable_definition() {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let convention = language.convention("gcc").unwrap();
    let config = MCodeRecoveryConfig::from_convention(&registers, convention, Vec::new()).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let constant = push_constant(&mut builder, 64, 7);
    let written = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::WriteRegister, 64).with_immediate(0x38),
        [constant],
    )
    .unwrap();
    builder
        .emitter()
        .set_value_domain(written, ECodeDomain::Register(RegisterId::new(0x38)))
        .unwrap();
    push_return(&mut builder, [written]);

    let mcode = transform_with_config(builder, &config);

    mcode.verify().unwrap();
    assert!(
        mcode
            .operations()
            .iter()
            .any(|operation| operation.opcode() == MCodeOpcode::Constant)
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
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let previous = push_undefined(
        &mut builder,
        64,
        Some(ECodeDomain::Register(RegisterId::new(RAX))),
    );
    let written = push_partial_write(&mut builder, previous, 0x7f);
    push_return(&mut builder, [written]);

    let mcode = transform_with_config(builder, &config());
    let field = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeOpcode::SetVarField)
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
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let previous = push_undefined(
        &mut builder,
        64,
        Some(ECodeDomain::Register(RegisterId::new(RAX))),
    );
    builder
        .emitter()
        .emit(
            ECodeOpSpec::new(ECodeOpcode::ConditionalBranch, 0)
                .with_address(Address::from(0x1000u64)),
            [previous],
            0,
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

    let mcode = transform_with_config(builder, &config());
    let field_count = mcode
        .operations()
        .iter()
        .filter(|operation| operation.opcode() == MCodeOpcode::SetVarField)
        .count();
    let full = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeOpcode::SetVar)
        .expect("one sibling materialises a full assignment");
    let materialised = mcode.operation_operands_for(full)[0];

    assert_eq!(field_count, 1);
    assert_eq!(
        mcode
            .defining_operation(materialised)
            .map(|operation| operation.opcode()),
        Some(MCodeOpcode::Insert)
    );
}

#[test]
fn a_fixed_stack_slot_promotes_store_and_load() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let space = AddressSpaceId::new(0);
    builder.emitter().intern_memory_domain(space);
    let stack_pointer = push_undefined(
        &mut builder,
        64,
        Some(ECodeDomain::Register(RegisterId::new(RSP))),
    );
    let frame_size = push_constant(&mut builder, 64, 0x20);
    let address = push_binary(&mut builder, ECodeOpcode::Sub, stack_pointer, frame_size);
    let stored = push_undefined(&mut builder, 64, None);
    let memory = push_undefined(&mut builder, 0, Some(ECodeDomain::Memory(space)));
    let memory = push_store(&mut builder, space, address, stored, memory);
    let loaded = push_load(&mut builder, space, address, memory, 64);
    push_return(&mut builder, [loaded]);

    let mcode = transform_with_config(builder, &config());
    let assignment = mcode
        .operations()
        .iter()
        .find(|operation| {
            operation.opcode() == MCodeOpcode::SetVar
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
        .find(|operation| operation.opcode() == MCodeOpcode::Return)
        .and_then(|operation| mcode.operation_operands_for(operation).first())
        .copied();

    assert_eq!(returned, Some(assigned));
    assert!(
        !mcode
            .operations()
            .iter()
            .any(|operation| matches!(operation.opcode(), MCodeOpcode::Load | MCodeOpcode::Store))
    );
    assert!(mcode.aliased_variables().is_empty());
}

#[test]
fn whole_and_partial_unaliased_stack_outputs_survive_return_compaction() {
    let outputs = [
        MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -16 }, 64),
        MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -12 }, 32),
    ];

    for output in outputs {
        let mcode = lift_stack_return_case(output, MCodeAliasOverride::Unaliased);
        let (value, variable) = mcode
            .values()
            .iter()
            .enumerate()
            .find_map(|(index, value)| {
                let variable = value.variable()?;
                (mcode.variable(variable)?.stack_offset() == Some(-16))
                    .then(|| (IlValueId::try_from_index(index).unwrap(), variable))
            })
            .expect("the live stack output retains its bound value");

        assert_eq!(mcode.variable(variable).unwrap().stack_offset(), Some(-16));
        assert!(!mcode.is_aliased(variable));
        assert!(mcode.defining_operation(value).is_some());
        assert!(
            mcode
                .operations()
                .iter()
                .any(|operation| operation.opcode() == MCodeOpcode::Return)
        );
    }
}

#[test]
fn an_aliased_stack_output_survives_return_compaction() {
    let output = MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -12 }, 32);
    let mcode = lift_stack_return_case(output, MCodeAliasOverride::Aliased);
    let assignment = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeOpcode::SetVarAliased)
        .expect("the live aliased stack output retains its assignment");
    let value = IlValueId::try_from_index(assignment.results().start() + 1).unwrap();
    let variable = mcode
        .binding(value)
        .expect("the output is bound")
        .variable();

    assert_eq!(mcode.variable(variable).unwrap().stack_offset(), Some(-16));
    assert!(mcode.is_aliased(variable));
    assert!(
        mcode
            .operations()
            .iter()
            .any(|operation| operation.opcode() == MCodeOpcode::Return)
    );
}

#[test]
fn an_address_taken_stack_slot_uses_aliased_operations() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let space = AddressSpaceId::new(0);
    builder.emitter().intern_memory_domain(space);
    let stack_pointer = push_undefined(
        &mut builder,
        64,
        Some(ECodeDomain::Register(RegisterId::new(RSP))),
    );
    let frame_size = push_constant(&mut builder, 64, 0x20);
    let address = push_binary(&mut builder, ECodeOpcode::Sub, stack_pointer, frame_size);
    let stored = push_constant(&mut builder, 64, 0x2a);
    let memory = push_undefined(&mut builder, 0, Some(ECodeDomain::Memory(space)));
    let memory = push_store(&mut builder, space, address, stored, memory);
    let loaded = push_load(&mut builder, space, address, memory, 64);
    let returned = push_binary(&mut builder, ECodeOpcode::Add, address, loaded);
    push_return(&mut builder, [returned]);

    let mcode = transform_with_config(builder, &config());

    assert!(mcode.operations().iter().any(|operation| {
        operation.opcode() == MCodeOpcode::SetVarAliased
            && operation
                .variable()
                .is_some_and(|variable| mcode.is_aliased(variable))
    }));
    assert!(
        mcode
            .operations()
            .iter()
            .any(|operation| operation.opcode() == MCodeOpcode::AddressOf)
    );
    assert!(
        mcode
            .operations()
            .iter()
            .any(|operation| operation.opcode() == MCodeOpcode::VarAliased)
    );
}

#[test]
fn call_outputs_bind_the_post_call_register_definition() {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let convention =
        Convention::new("pair", Varnode::new(0, RSP, 8)).with_prototypes(&PAIR_PROTOTYPES);
    let config = MCodeRecoveryConfig::from_convention(&registers, &convention, Vec::new()).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let space = AddressSpaceId::new(0);
    builder.emitter().intern_memory_domain(space);

    push_undefined(
        &mut builder,
        64,
        Some(ECodeDomain::Register(RegisterId::new(PAIR_HIGH.offset()))),
    );
    push_undefined(
        &mut builder,
        64,
        Some(ECodeDomain::Register(RegisterId::new(PAIR_LOW.offset()))),
    );
    let pointer = push_constant(&mut builder, 64, 0x2000);
    let stored = push_undefined(&mut builder, 64, None);

    let initial_memory = push_undefined(&mut builder, 0, Some(ECodeDomain::Memory(space)));
    push_store(&mut builder, space, pointer, stored, initial_memory);
    builder
        .emitter()
        .emit(
            ECodeOpSpec::new(ECodeOpcode::Call, 0).with_address(Address::from(0x1000u64)),
            [],
            0,
        )
        .unwrap();

    let post_memory = push_undefined(&mut builder, 0, Some(ECodeDomain::Memory(space)));
    push_undefined(
        &mut builder,
        64,
        Some(ECodeDomain::Register(RegisterId::new(RAX))),
    );
    let loaded = push_load(&mut builder, space, pointer, post_memory, 64);
    push_return(&mut builder, [loaded]);
    let mcode = transform_with_config(builder, &config);
    let call = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeOpcode::Call)
        .expect("the call survives optimisation");
    let output = IlValueId::try_from_index(call.results().start() + 1).unwrap();
    let binding = mcode.binding(output).expect("the call output is bound");
    let returned = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeOpcode::Return)
        .and_then(|operation| mcode.operation_operands_for(operation).first())
        .copied();
    let split = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeOpcode::VarSplit)
        .expect("the register-pair argument is reconstructed");
    let stored_memory = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeOpcode::Store)
        .and_then(|operation| IlValueId::try_from_index(operation.results().start()).ok())
        .expect("the general store is retained");
    let load = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeOpcode::Load)
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
            .all(|&value| mcode.value_width(value) == Some(64))
    );
    assert_eq!(mcode.values()[split.results().start()].width(), 128);
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
fn branch_heavy_call_outputs_do_not_leak_candidates_between_siblings() {
    const BRANCH_COUNT: usize = 32;

    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let convention =
        Convention::new("pair", Varnode::new(0, RSP, 8)).with_prototypes(&PAIR_PROTOTYPES);
    let config = MCodeRecoveryConfig::from_convention(&registers, &convention, Vec::new()).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    push_constant(&mut builder, 1, 1);

    let mut calls = Vec::new();
    for index in 1..BRANCH_COUNT {
        let call = builder
            .emitter()
            .emit(
                ECodeOpSpec::new(ECodeOpcode::Call, 0)
                    .with_address(Address::from(0x1000u64 + index as u64)),
                [],
                0,
            )
            .map(|(operation, _)| operation)
            .unwrap();
        calls.push(call);
    }
    push_undefined(
        &mut builder,
        64,
        Some(ECodeDomain::Register(RegisterId::new(RAX))),
    );

    let successors = (1..=BRANCH_COUNT)
        .map(|index| IlBlockId::try_from_index(index).unwrap())
        .collect::<Vec<_>>();
    let mut blocks = vec![IlBlock::new(
        IlIndexRange::new(0, 1).unwrap(),
        IlIndexRange::new(0, BRANCH_COUNT).unwrap(),
        IlBlockProperties::ENTRY,
    )];
    blocks.extend((1..=BRANCH_COUNT).map(|index| {
        IlBlock::new(
            IlIndexRange::new(index, index + 1).unwrap(),
            IlIndexRange::EMPTY,
            IlBlockProperties::EXIT,
        )
    }));
    builder.set_graph(IlGraph::new(
        blocks,
        successors,
        vec![IlEdgeKinds::UNCONDITIONAL; BRANCH_COUNT],
    ));
    let source = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    let recovery = MCodeRecovery::new(&source, &config, &registers).unwrap();
    let outputs = MCodeCallOutputVariables::new(&source, &recovery).unwrap();
    let location = MCodeStorageLocation::Register(RegisterId::new(RAX));

    for call in calls {
        assert!(
            outputs
                .representative_for_output(MCodeCallOutputSite::new(
                    call,
                    location,
                    RegisterId::new(RAX),
                ))
                .is_none()
        );
    }
}

#[test]
fn exact_stack_call_facts_materialise_stack_inputs_and_outputs() {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let space = AddressSpaceId::new(0);
    builder.emitter().intern_memory_domain(space);
    let memory = push_undefined(&mut builder, 0, Some(ECodeDomain::Memory(space)));
    let call = builder
        .emitter()
        .emit(
            ECodeOpSpec::new(ECodeOpcode::Call, 0).with_address(Address::from(0x1000u64)),
            [],
            0,
        )
        .map(|(operation, _)| operation)
        .unwrap();
    push_return(&mut builder, [memory]);
    let source = builder.build(&CancellationToken::default()).unwrap();
    let mut call_facts = MCodeCallFacts::new(call);
    call_facts.insert_input(MCodeStorageFact::new(
        MCodeStorageLocation::Stack { offset: -16 },
        128,
    ));
    call_facts.insert_output(MCodeStorageFact::new(
        MCodeStorageLocation::Stack { offset: 8 },
        192,
    ));
    let mut facts = MCodeFunctionFacts::new(source.metadata().function());
    facts.insert_call(call_facts);
    let config = config().with_call_facts(&facts);
    let recovery = MCodeRecovery::new(&source, &config, &registers).unwrap();
    let mcode = lift_recovered(&source, &recovery);
    let call = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeOpcode::Call)
        .expect("the stack call survives optimisation");
    let output = IlValueId::try_from_index(call.results().start() + 1).unwrap();
    let materialisation = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeOpcode::SetVarAliased)
        .expect("the complete aliased output is materialised");
    let variable_output = IlValueId::try_from_index(materialisation.results().start() + 1).unwrap();
    let variable = mcode
        .binding(variable_output)
        .expect("the materialised stack output is bound")
        .variable();

    mcode.verify().unwrap();
    assert_eq!(call.operands().len(), 2);
    assert_eq!(call.results().len(), 2);
    assert_eq!(mcode.values()[output.index()].width(), 192);
    assert_eq!(mcode.binding(output), None);
    assert_eq!(mcode.values()[variable_output.index()].width(), 192);
    assert_eq!(
        mcode.operation_operands_for(materialisation)[1].index(),
        call.results().start()
    );
    assert_eq!(
        mcode.variable(variable).unwrap().kind(),
        MCodeVarKind::Stack
    );
    assert!(mcode.is_aliased(variable));
}

#[test]
fn exact_call_inputs_keep_descending_register_order_in_mcode() {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    push_undefined(
        &mut builder,
        64,
        Some(ECodeDomain::Register(RegisterId::new(RDI))),
    );
    let rax = push_undefined(
        &mut builder,
        64,
        Some(ECodeDomain::Register(RegisterId::new(RAX))),
    );
    let site = builder
        .emitter()
        .emit(
            ECodeOpSpec::new(ECodeOpcode::Call, 0).with_address(Address::from(0x1000u64)),
            [],
            0,
        )
        .map(|(operation, _)| operation)
        .unwrap();
    push_return(&mut builder, [rax]);
    let source = builder.build(&CancellationToken::default()).unwrap();
    let mut call = MCodeCallFacts::new(site);
    call.set_inputs([
        MCodeStorageFact::new(MCodeStorageLocation::Register(RegisterId::new(RDI)), 64),
        MCodeStorageFact::new(MCodeStorageLocation::Register(RegisterId::new(RAX)), 64),
    ]);
    call.set_outputs([]);
    let mut facts = MCodeFunctionFacts::new(source.metadata().function());
    facts.insert_call(call);
    let config = config().with_call_facts(&facts);
    let recovery = MCodeRecovery::new(&source, &config, &registers).unwrap();
    let mcode = lift_recovered(&source, &recovery);
    let call = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeOpcode::Call)
        .expect("the call survives optimisation");
    let variables = mcode
        .operation_operands_for(call)
        .iter()
        .take(2)
        .map(|&value| {
            mcode
                .binding(value)
                .and_then(|binding| mcode.variable(binding.variable()))
                .and_then(|variable| variable.register_id())
        })
        .collect::<Vec<_>>();

    assert_eq!(
        variables,
        &[Some(RegisterId::new(RDI)), Some(RegisterId::new(RAX))]
    );
}

#[test]
fn exact_call_outputs_keep_register_pair_and_stack_order_in_mcode() {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let site = builder
        .emitter()
        .emit(
            ECodeOpSpec::new(ECodeOpcode::Call, 0).with_address(Address::from(0x1000u64)),
            [],
            0,
        )
        .map(|(operation, _)| operation)
        .unwrap();
    push_undefined(
        &mut builder,
        64,
        Some(ECodeDomain::Register(RegisterId::new(RSI))),
    );
    push_undefined(
        &mut builder,
        64,
        Some(ECodeDomain::Register(RegisterId::new(RDX))),
    );
    let rax = push_undefined(
        &mut builder,
        64,
        Some(ECodeDomain::Register(RegisterId::new(RAX))),
    );
    push_return(&mut builder, [rax]);
    let source = builder.build(&CancellationToken::default()).unwrap();
    let mut call = MCodeCallFacts::new(site);
    call.set_inputs([]);
    call.set_outputs([
        MCodeStorageFact::new(MCodeStorageLocation::Register(RegisterId::new(RSI)), 64),
        MCodeStorageFact::new(
            MCodeStorageLocation::RegisterPair {
                high: RegisterId::new(RDX),
                low: RegisterId::new(RAX),
            },
            128,
        ),
        MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: 8 }, 192),
    ]);
    let mut facts = MCodeFunctionFacts::new(source.metadata().function());
    facts.insert_call(call);
    let config = config().with_call_facts(&facts);
    let recovery = MCodeRecovery::new(&source, &config, &registers).unwrap();
    let mcode = lift_recovered(&source, &recovery);
    let call = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeOpcode::Call)
        .expect("the call survives optimisation");
    let variables = call
        .results()
        .slice(mcode.values())
        .iter()
        .skip(1)
        .map(|value| {
            value.binding().and_then(|binding| {
                mcode
                    .variable(binding.variable())
                    .map(|variable| (variable.kind(), variable.register_id()))
            })
        })
        .collect::<Vec<_>>();

    assert_eq!(
        variables,
        &[
            Some((MCodeVarKind::Register, Some(RegisterId::new(RSI)))),
            Some((MCodeVarKind::Register, Some(RegisterId::new(RDX)))),
            Some((MCodeVarKind::Register, Some(RegisterId::new(RAX)))),
            None,
        ]
    );
    let stack_output = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeOpcode::SetVarAliased)
        .and_then(|operation| {
            IlValueId::try_from_index(operation.results().start() + 1)
                .ok()
                .and_then(|value| mcode.binding(value))
        })
        .and_then(|binding| mcode.variable(binding.variable()));
    assert!(stack_output.is_some_and(|variable| variable.kind() == MCodeVarKind::Stack));
}

#[test]
fn a_reused_transformer_does_not_retain_function_facts() {
    let language = resolve_language("x86:LE:64").unwrap();
    let arch = crate::arch::Arch::new(language);
    let mut platform = crate::platform::Platform::for_arch(&arch);
    platform.set_compiler_spec_id("gcc");
    let (first, first_site) = call_source(FunctionId::from_index(0));
    let (second, _) = call_source(FunctionId::from_index(1));
    let mut call = MCodeCallFacts::new(first_site);
    call.set_inputs([]);
    call.set_outputs([]);
    let mut facts = MCodeFunctionFacts::new(first.metadata().function());
    facts.insert_call(call);
    let mut transformer = ECodeToMCode::default();

    let first = transformer
        .transform(
            &first,
            &arch,
            &platform,
            Some(&facts),
            &CancellationToken::default(),
        )
        .unwrap();
    let second = transformer
        .transform(
            &second,
            &arch,
            &platform,
            None,
            &CancellationToken::default(),
        )
        .unwrap();
    let operand_count = |ir: &MCodeIr| {
        let call = ir
            .operations()
            .iter()
            .find(|operation| operation.opcode() == MCodeOpcode::Call)
            .expect("the call survives optimisation");
        ir.operation_operands_for(call).len()
    };

    assert_eq!(operand_count(&first), 1);
    assert_eq!(operand_count(&second), 2);
}

#[test]
fn transform_rejects_mismatched_and_out_of_range_function_facts() {
    let language = resolve_language("x86:LE:64").unwrap();
    let arch = crate::arch::Arch::new(language);
    let mut platform = crate::platform::Platform::for_arch(&arch);
    platform.set_compiler_spec_id("gcc");
    let (source, _) = call_source(FunctionId::from_index(0));
    let mismatched = MCodeFunctionFacts::new(FunctionId::from_index(1));
    let mut out_of_range = MCodeFunctionFacts::new(source.metadata().function());
    out_of_range.insert_call(MCodeCallFacts::new(
        IlOpId::try_from_index(source.operations().len()).unwrap(),
    ));
    let non_call_site = IlOpId::try_from_index(0).unwrap();
    let mut non_call = MCodeCallFacts::new(non_call_site);
    non_call.insert_input(MCodeStorageFact::new(
        MCodeStorageLocation::Stack { offset: -8 },
        64,
    ));
    let mut invalid_site = MCodeFunctionFacts::new(source.metadata().function());
    invalid_site.insert_call(non_call);
    let mut transformer = ECodeToMCode::default();

    let mismatch = transformer.transform(
        &source,
        &arch,
        &platform,
        Some(&mismatched),
        &CancellationToken::default(),
    );
    let range = transformer.transform(
        &source,
        &arch,
        &platform,
        Some(&out_of_range),
        &CancellationToken::default(),
    );
    let site = transformer.transform(
        &source,
        &arch,
        &platform,
        Some(&invalid_site),
        &CancellationToken::default(),
    );

    assert!(matches!(mismatch, Err(IlError::FunctionMismatch { .. })));
    assert!(matches!(range, Err(IlError::RangeOutOfBounds { .. })));
    assert_eq!(site, Err(IlError::invalid_fact_site(non_call_site.value())));
}

#[test]
fn a_partial_unaliased_call_output_materialises_a_full_merged_object() {
    let inputs = [
        MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -16 }, 64),
        MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -12 }, 64),
    ];
    let output = MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -12 }, 32);
    let mcode = lift_stack_call_case(&inputs, output, MCodeAliasOverride::Unaliased);
    let call_index = mcode
        .operations()
        .iter()
        .position(|operation| operation.opcode() == MCodeOpcode::Call)
        .expect("the call survives optimisation");
    let call = mcode.operations()[call_index];
    let field = mcode.operations()[call_index + 1];
    let call_output = IlValueId::try_from_index(call.results().start() + 1).unwrap();
    let full_output = IlValueId::try_from_index(field.results().start()).unwrap();
    let variable = mcode
        .binding(full_output)
        .and_then(|binding| mcode.variable(binding.variable()))
        .expect("the full object result is bound");

    assert_eq!(field.opcode(), MCodeOpcode::SetVarField);
    assert_eq!(field.immediate(), 32);
    assert_eq!(mcode.binding(call_output), None);
    assert_eq!(mcode.values()[call_output.index()].width(), 32);
    assert_eq!(mcode.values()[full_output.index()].width(), 96);
    assert_eq!(variable.stack_offset(), Some(-16));
    assert!(!mcode.is_aliased(mcode.binding(full_output).unwrap().variable()));
    mcode.verify().unwrap();
    assert!(!mcode.display().to_string().is_empty());

    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&mcode).unwrap();
    let restored = rkyv::from_bytes::<MCodeIr, rkyv::rancor::Error>(&bytes).unwrap();
    restored.verify().unwrap();
    assert_eq!(restored, mcode);
}

#[test]
fn a_partial_aliased_call_output_advances_memory_and_the_full_object() {
    let inputs = [
        MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -16 }, 64),
        MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -12 }, 64),
    ];
    let output = MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -12 }, 32);
    let mcode = lift_stack_call_case(&inputs, output, MCodeAliasOverride::Aliased);
    let call_index = mcode
        .operations()
        .iter()
        .position(|operation| operation.opcode() == MCodeOpcode::Call)
        .expect("the call survives optimisation");
    let call = mcode.operations()[call_index];
    let field = mcode.operations()[call_index + 1];
    let call_output = IlValueId::try_from_index(call.results().start() + 1).unwrap();
    let memory_output = IlValueId::try_from_index(field.results().start()).unwrap();
    let full_output = IlValueId::try_from_index(field.results().start() + 1).unwrap();
    let variable = mcode
        .binding(full_output)
        .and_then(|binding| mcode.variable(binding.variable()))
        .expect("the full object result is bound");

    assert_eq!(field.opcode(), MCodeOpcode::SetVarAliasedField);
    assert_eq!(field.immediate(), 32);
    assert_eq!(mcode.binding(call_output), None);
    assert_eq!(mcode.values()[call_output.index()].width(), 32);
    assert_eq!(mcode.values()[memory_output.index()].width(), 0);
    assert_eq!(mcode.values()[full_output.index()].width(), 96);
    assert_eq!(variable.stack_offset(), Some(-16));
    assert_eq!(
        mcode.operation_operands_for(&field),
        &[
            call_output,
            IlValueId::try_from_index(call.results().start()).unwrap(),
        ]
    );
    assert!(mcode.is_aliased(mcode.binding(full_output).unwrap().variable()));
    mcode.verify().unwrap();
}

#[test]
fn zero_offset_narrow_and_complete_stack_outputs_use_distinct_forms() {
    let complete = MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -16 }, 128);
    let narrow = MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -16 }, 32);
    let partial = lift_stack_call_case(&[complete], narrow, MCodeAliasOverride::Unaliased);
    let partial_call = partial
        .operations()
        .iter()
        .position(|operation| operation.opcode() == MCodeOpcode::Call)
        .expect("the partial call survives optimisation");
    let field = partial.operations()[partial_call + 1];

    assert_eq!(field.opcode(), MCodeOpcode::SetVarField);
    assert_eq!(field.immediate(), 0);
    assert_eq!(field.width(), 32);
    assert_eq!(partial.values()[field.results().start()].width(), 128);
    partial.verify().unwrap();

    let complete = lift_stack_call_case(&[], complete, MCodeAliasOverride::Unaliased);
    let call = complete
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeOpcode::Call)
        .expect("the complete call survives optimisation");
    let output = IlValueId::try_from_index(call.results().start() + 1).unwrap();
    let binding = complete
        .binding(output)
        .expect("a complete unaliased object binds the call result");

    assert_eq!(complete.values()[output.index()].width(), 128);
    assert_eq!(
        complete
            .variable(binding.variable())
            .unwrap()
            .stack_offset(),
        Some(-16)
    );
    complete.verify().unwrap();
}

#[test]
fn exact_register_pair_and_stack_facts_survive_tail_call_lifting() {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    for register in [RDI, RDX, RAX] {
        push_undefined(
            &mut builder,
            64,
            Some(ECodeDomain::Register(RegisterId::new(register))),
        );
    }
    let site = builder
        .emitter()
        .emit(
            ECodeOpSpec::new(ECodeOpcode::Branch, 0).with_address(Address::from(0x2000u64)),
            [],
            0,
        )
        .map(|(operation, _)| operation)
        .unwrap();
    builder.set_graph(IlGraph::new(
        vec![IlBlock::new(
            IlIndexRange::new(0, 4).unwrap(),
            IlIndexRange::EMPTY,
            IlBlockProperties::ENTRY | IlBlockProperties::EXIT,
        )],
        Vec::new(),
        Vec::new(),
    ));
    let source = builder.build(&CancellationToken::default()).unwrap();
    let locations = [
        MCodeStorageLocation::Register(RegisterId::new(RDI)),
        MCodeStorageLocation::RegisterPair {
            high: RegisterId::new(RDX),
            low: RegisterId::new(RAX),
        },
        MCodeStorageLocation::Stack { offset: -16 },
    ];
    let mut call = MCodeCallFacts::new(site);
    call.set_inputs([
        MCodeStorageFact::new(locations[0], 64),
        MCodeStorageFact::new(locations[1], 128),
        MCodeStorageFact::new(locations[2], 64),
    ]);
    call.set_outputs([
        MCodeStorageFact::new(locations[0], 64),
        MCodeStorageFact::new(locations[1], 128),
        MCodeStorageFact::new(locations[2], 64),
    ]);
    let mut facts = MCodeFunctionFacts::new(source.metadata().function());
    facts.set_tail_call_live_outputs([
        MCodeStorageFact::new(locations[0], 64),
        MCodeStorageFact::new(locations[1], 128),
        MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -32 }, 64),
    ]);
    facts.insert_call(call);
    let config = config().with_call_facts(&facts);
    let recovery = MCodeRecovery::new(&source, &config, &registers).unwrap();
    let mcode = lift_recovered(&source, &recovery);
    let tail_call = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeOpcode::TailCall)
        .expect("the tail call survives optimisation");
    let operands = mcode.operation_operands_for(tail_call);
    let stack_output = mcode
        .values()
        .iter()
        .enumerate()
        .find_map(|(index, value)| {
            let variable = value.variable()?;
            (mcode.variable(variable)?.stack_offset() == Some(-32))
                .then(|| IlValueId::try_from_index(index).unwrap())
        })
        .expect("the stack live output survives optimisation");
    let IlSsaDef::Op(stack_definition) = mcode.values()[stack_output.index()].definition()
    else {
        panic!("the stack live output has an operation definition");
    };
    let tail_call_index = mcode
        .operations()
        .iter()
        .position(|operation| operation == tail_call)
        .unwrap();

    assert_eq!(operands.len(), 4);
    assert_eq!(mcode.values()[operands[3].index()].width(), 0);
    assert!(stack_definition.index() < tail_call_index);
    assert!(
        mcode
            .operations()
            .iter()
            .any(|operation| operation.opcode() == MCodeOpcode::VarSplit)
    );
    assert!(tail_call.results().is_empty());
    mcode.verify().unwrap();
}

#[test]
fn a_resolved_indirect_branch_becomes_a_switch() {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let config = config();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let selector = push_undefined(&mut builder, 64, None);
    builder
        .emitter()
        .emit(
            ECodeOpSpec::new(ECodeOpcode::BranchIndirect, 0)
                .with_address_space(AddressSpaceId::new(0)),
            [selector],
            0,
        )
        .unwrap();
    push_return(&mut builder, [selector]);
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
    let mcode = lift_recovered(&source, &recovery);

    mcode.verify().unwrap();
    assert!(
        mcode
            .operations()
            .iter()
            .any(|operation| operation.opcode() == MCodeOpcode::Switch)
    );
}

#[test]
fn transform_copies_only_emitted_wide_constants() {
    let language = resolve_language("x86:LE:64").unwrap();
    let registers = RegisterBank::new(language).unwrap();
    let config = config();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let (operation, results) = builder
        .emitter()
        .emit(ECodeOpSpec::new(ECodeOpcode::Constant, 128), [], 1)
        .unwrap();
    let constant = IlValueId::try_from_index(results.start()).unwrap();
    push_return(&mut builder, [constant]);
    let mut source = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    let constant_value = BitVec::from_le_bytes(&[
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23,
        0x01,
    ]);
    source
        .rewriter()
        .replace_with_constant(operation, &constant_value);
    source.verify().unwrap();
    let recovery = MCodeRecovery::new(&source, &config, &registers).unwrap();
    let mcode = lift_recovered(&source, &recovery);
    let returned = mcode
        .operations()
        .iter()
        .find(|operation| operation.opcode() == MCodeOpcode::Return)
        .and_then(|operation| mcode.operation_operands_for(operation).first())
        .copied()
        .expect("the wide constant is returned");

    mcode.verify().unwrap();
    assert_eq!(mcode.constant_value(returned), Some(constant_value));
    assert_eq!(mcode.constant_storage().len(), 16);
}
