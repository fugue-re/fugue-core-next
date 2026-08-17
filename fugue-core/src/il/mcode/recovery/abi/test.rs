use super::*;
use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlError, IlGraph,
    IlGraphBuilder, IlIndexRange, IlMetadata, RegisterBank,
};
use crate::il::ecode::test::emit_value;
use crate::il::ecode::{ECodeBuilder, ECodeDomain, ECodeIr, ECodeOpSpec, ECodeOpcode};
use crate::ir::{Address, FunctionId};
use crate::lifter::resolve_language;
use crate::storage::segments::space::AddressSpaceId;

const RDI: u64 = 0x38;
const RSI: u64 = 0x30;
const RDX: u64 = 0x28;
const RAX: u64 = 0x00;
const RSP: u64 = 0x20;

fn recover(ir: &ECodeIr, convention: &MCodeCallingConvention) -> MCodeAbiModel {
    let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
    let stack = MCodeStackModel::new(ir, RegisterId::new(RSP), []);
    MCodeAbiModel::new(ir, convention, &[], &[], None, &registers, &stack).unwrap()
}

fn recover_with_facts(
    ir: &ECodeIr,
    convention: &MCodeCallingConvention,
    facts: &MCodeFunctionFacts,
) -> MCodeAbiModel {
    let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
    facts.validate(ir, &registers).unwrap();
    let stack = MCodeStackModel::new(ir, RegisterId::new(RSP), facts.stack_storage());
    facts.validate_stack(&stack).unwrap();
    MCodeAbiModel::new(ir, convention, &[], &[], Some(facts), &registers, &stack).unwrap()
}

fn entry(location: MCodeStorageLocation) -> MCodeCallingConventionEntry {
    MCodeCallingConventionEntry::new(location, 1, 8)
}

fn register(root: u64) -> MCodeCallingConventionEntry {
    entry(MCodeStorageLocation::Register(RegisterId::new(root)))
}

#[test]
fn stack_offsets_are_normalised_to_the_target_address_width() {
    assert_eq!(normalise_stack_offset(0x10, 32), Ok(16));
    assert_eq!(normalise_stack_offset(0xffff_fff0, 32), Ok(-16));
    assert_eq!(normalise_stack_offset(0x10, 64), Ok(16));
    assert_eq!(normalise_stack_offset(0xffff_ffff_ffff_fff0, 64), Ok(-16));
}

#[test]
fn exact_stack_facts_produce_stack_inputs_and_outputs() {
    let mut function = Function::new();
    let site = function.call();
    let ir = function.finish();
    let mut call = MCodeCallFacts::new(site);
    call.insert_input(MCodeStorageFact::new(
        MCodeStorageLocation::Stack { offset: -16 },
        128,
    ));
    call.insert_output(MCodeStorageFact::new(
        MCodeStorageLocation::Stack { offset: 8 },
        192,
    ));
    let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
    facts.insert_call(call);

    let model = recover_with_facts(&ir, &MCodeCallingConvention::default(), &facts);
    let call = model.call(site).expect("a recovered call");
    let output = call.outputs().first().expect("a recovered stack output");
    let component = output.components().first().expect("one stack component");

    assert_eq!(
        call.args(),
        &[MCodeCallArg::Stack {
            offset: -16,
            width: 128,
        }]
    );
    assert_eq!(output.location(), MCodeStorageLocation::Stack { offset: 8 });
    assert!(matches!(
        component,
        MCodeCallOutputComponent::Stack {
            object_width: 192,
            width: 192,
            ..
        }
    ));
    assert_eq!(component.width(), 192);
}

#[test]
fn exact_call_facts_preserve_input_and_output_order() {
    let mut function = Function::new();
    let rdi = function.define(RDI);
    let rax = function.define(RAX);
    let site = function.call();
    let ir = function.finish();
    let mut call = MCodeCallFacts::new(site);
    call.set_inputs([
        MCodeStorageFact::new(MCodeStorageLocation::Register(RegisterId::new(RDI)), 64),
        MCodeStorageFact::new(MCodeStorageLocation::Register(RegisterId::new(RAX)), 64),
    ]);
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
    let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
    facts.insert_call(call);

    let model = recover_with_facts(&ir, &MCodeCallingConvention::default(), &facts);
    let call = model.call(site).expect("a recovered call");

    assert_eq!(
        call.args(),
        &[MCodeCallArg::Value(rdi), MCodeCallArg::Value(rax)]
    );
    assert_eq!(
        call.outputs()
            .iter()
            .map(MCodeCallOutput::location)
            .collect::<Vec<_>>(),
        &[
            MCodeStorageLocation::Register(RegisterId::new(RSI)),
            MCodeStorageLocation::RegisterPair {
                high: RegisterId::new(RDX),
                low: RegisterId::new(RAX),
            },
            MCodeStorageLocation::Stack { offset: 8 },
        ]
    );
}

#[test]
fn known_empty_call_facts_do_not_use_the_convention() {
    let mut function = Function::new();
    function.define(RDI);
    let site = function.call();
    let ir = function.finish();
    let mut call = MCodeCallFacts::new(site);
    call.set_inputs([]);
    call.set_outputs([]);
    let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
    facts.insert_call(call);
    let convention = MCodeCallingConvention::new(vec![register(RDI)], vec![register(RAX)]);

    let model = recover_with_facts(&ir, &convention, &facts);
    let call = model.call(site).expect("a recovered call");

    assert!(call.args().is_empty());
    assert!(call.outputs().is_empty());
}

#[test]
fn known_empty_function_outputs_do_not_use_the_fallback() {
    let mut function = Function::new();
    let rax = function.define(RAX);
    let site = function.return_();
    let ir = function.finish();
    let output = MCodeStorageFact::new(MCodeStorageLocation::Register(RegisterId::new(RAX)), 64);
    let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
    let stack = MCodeStackModel::new(&ir, RegisterId::new(RSP), []);
    let unknown = MCodeFunctionFacts::new(ir.metadata().function());
    let mut known_empty = MCodeFunctionFacts::new(ir.metadata().function());
    known_empty.set_return_live_outputs([]);

    let fallback = MCodeAbiModel::new(
        &ir,
        &MCodeCallingConvention::default(),
        &[output],
        &[],
        Some(&unknown),
        &registers,
        &stack,
    )
    .unwrap();
    let exact = MCodeAbiModel::new(
        &ir,
        &MCodeCallingConvention::default(),
        &[output],
        &[],
        Some(&known_empty),
        &registers,
        &stack,
    )
    .unwrap();

    assert_eq!(
        fallback.exit_requirements(site),
        &[MCodeExitRequirement::Register(rax)]
    );
    assert!(exact.exit_requirements(site).is_empty());
}

#[test]
fn function_exit_requirements_retain_register_pairs_and_stack_storage() {
    let mut function = Function::new();
    let high = function.define(RDX);
    let low = function.define(RAX);
    let site = function.return_();
    let ir = function.finish();
    let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
    facts.set_return_live_outputs([
        MCodeStorageFact::new(
            MCodeStorageLocation::RegisterPair {
                high: RegisterId::new(RDX),
                low: RegisterId::new(RAX),
            },
            128,
        ),
        MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -8 }, 64),
    ]);

    let model = recover_with_facts(&ir, &MCodeCallingConvention::default(), &facts);
    let requirements = model.exit_requirements(site);

    assert_eq!(
        &requirements[..2],
        &[
            MCodeExitRequirement::Register(high),
            MCodeExitRequirement::Register(low),
        ]
    );
    assert!(matches!(requirements[2], MCodeExitRequirement::Stack(_)));
}

#[test]
fn function_live_outputs_are_sorted_and_deduplicated() {
    let register = MCodeStorageFact::new(MCodeStorageLocation::Register(RegisterId::new(RAX)), 64);
    let stack = MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -8 }, 64);
    let mut facts = MCodeFunctionFacts::new(FunctionId::default());

    facts.insert_return_live_output(stack);
    facts.insert_return_live_output(register);
    facts.insert_return_live_output(stack);
    facts.set_tail_call_live_outputs([stack, register, stack]);

    assert_eq!(facts.return_live_outputs(), Some(&[register, stack][..]));
    assert_eq!(facts.tail_call_live_outputs(), Some(&[register, stack][..]));
}

#[test]
fn storage_fact_validation_rejects_inconsistent_widths_and_roots() {
    let mut function = Function::new();
    let site = function.call();
    let ir = function.finish();
    let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
    let validate = |fact| {
        let mut call = MCodeCallFacts::new(site);
        call.insert_input(fact);
        let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
        facts.insert_call(call);
        facts.validate(&ir, &registers)
    };

    assert_eq!(
        validate(MCodeStorageFact::new(
            MCodeStorageLocation::Register(RegisterId::new(RDI)),
            32,
        )),
        Err(IlError::width_mismatch(ECodeIr::FORM))
    );
    assert_eq!(
        validate(MCodeStorageFact::new(
            MCodeStorageLocation::RegisterPair {
                high: RegisterId::new(RDX),
                low: RegisterId::new(RAX),
            },
            63,
        )),
        Err(IlError::width_mismatch(ECodeIr::FORM))
    );
    assert!(matches!(
        validate(MCodeStorageFact::new(
            MCodeStorageLocation::Register(RegisterId::new(u64::MAX)),
            64,
        )),
        Err(IlError::MissingComponent { .. })
    ));
    assert_eq!(
        validate(MCodeStorageFact::new(
            MCodeStorageLocation::Stack { offset: -8 },
            0,
        )),
        Err(IlError::width_mismatch(ECodeIr::FORM))
    );
    assert_eq!(
        validate(MCodeStorageFact::new(
            MCodeStorageLocation::Stack { offset: i64::MAX },
            16,
        )),
        Err(IlError::integer_overflow("stack storage range"))
    );
}

#[test]
fn conflicting_function_exit_widths_are_rejected() {
    let function = Function::new();
    let ir = function.finish();
    let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
    let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
    facts.set_return_live_outputs([
        MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -8 }, 32),
        MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -8 }, 64),
    ]);

    assert_eq!(
        facts.validate(&ir, &registers),
        Err(IlError::width_mismatch(ECodeIr::FORM))
    );
}

#[test]
fn call_facts_reject_arithmetic_and_internal_branch_sites() {
    let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let left = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 64),
        [],
    )
    .unwrap();
    let right = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 64),
        [],
    )
    .unwrap();
    let arithmetic = builder
        .emitter()
        .emit(ECodeOpSpec::new(ECodeOpcode::Add, 64), [left, right], 1)
        .map(|(operation, _)| operation)
        .unwrap();
    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
    facts.insert_call(MCodeCallFacts::new(arithmetic));

    assert_eq!(
        facts.validate(&ir, &registers),
        Err(IlError::invalid_fact_site(arithmetic.value()))
    );

    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let branch = builder
        .emitter()
        .emit(
            ECodeOpSpec::new(ECodeOpcode::Branch, 0).with_address(Address::from(0x1000u64)),
            [],
            0,
        )
        .map(|(operation, _)| operation)
        .unwrap();
    builder
        .emitter()
        .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [], 0)
        .unwrap();
    builder.set_graph(IlGraph::new(
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
        vec![IlBlockId::try_from_index(1).unwrap()],
        vec![IlEdgeKinds::UNCONDITIONAL],
    ));
    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
    facts.insert_call(MCodeCallFacts::new(branch));

    assert_eq!(
        facts.validate(&ir, &registers),
        Err(IlError::invalid_fact_site(branch.value()))
    );
}

#[test]
fn call_fact_site_validation_accepts_direct_indirect_and_tail_calls() {
    let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
    let validate = |ir: &ECodeIr, site| {
        let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
        facts.insert_call(MCodeCallFacts::new(site));
        facts.validate(ir, &registers)
    };

    let mut direct = Function::new();
    let direct_site = direct.call();
    let direct = direct.finish();
    assert_eq!(validate(&direct, direct_site), Ok(()));

    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let destination = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Undefined, 64),
        [],
    )
    .unwrap();
    let indirect_site = builder
        .emitter()
        .emit(
            ECodeOpSpec::new(ECodeOpcode::CallIndirect, 0)
                .with_address_space(AddressSpaceId::new(0)),
            [destination],
            0,
        )
        .map(|(operation, _)| operation)
        .unwrap();
    let indirect = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    assert_eq!(validate(&indirect, indirect_site), Ok(()));

    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let tail_site = builder
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
            IlIndexRange::new(0, 1).unwrap(),
            IlIndexRange::EMPTY,
            IlBlockProperties::ENTRY | IlBlockProperties::EXIT,
        )],
        Vec::new(),
        Vec::new(),
    ));
    let tail = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    assert_eq!(validate(&tail, tail_site), Ok(()));
}

struct Function {
    builder: ECodeBuilder,
    operations: usize,
}

impl Function {
    fn new() -> Self {
        Self {
            builder: ECodeBuilder::new(
                IlMetadata::new(FunctionId::default(), 0),
                IlGraph::default(),
            ),
            operations: 0,
        }
    }

    fn define(&mut self, root: u64) -> IlValueId {
        self.define_width(root, 64)
    }

    fn define_width(&mut self, root: u64, width: u32) -> IlValueId {
        let id = emit_value(
            &mut self.builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, width),
            [],
        )
        .unwrap();
        self.builder
            .emitter()
            .set_value_domain(id, ECodeDomain::Register(RegisterId::new(root)))
            .unwrap();
        self.operations += 1;
        id
    }

    fn live_in(&mut self, root: u64) -> IlValueId {
        let id = emit_value(
            &mut self.builder,
            ECodeOpSpec::new(ECodeOpcode::Undefined, 64),
            [],
        )
        .unwrap();
        self.builder
            .emitter()
            .set_value_domain(id, ECodeDomain::Register(RegisterId::new(root)))
            .unwrap();
        self.operations += 1;
        id
    }

    fn call(&mut self) -> IlOpId {
        let site = self
            .builder
            .emitter()
            .emit(
                ECodeOpSpec::new(ECodeOpcode::Call, 0).with_address(Address::from(0x1000u64)),
                [],
                0,
            )
            .map(|(operation, _)| operation)
            .unwrap();
        self.operations += 1;
        site
    }

    fn return_(&mut self) -> IlOpId {
        let site = self
            .builder
            .emitter()
            .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [], 0)
            .map(|(operation, _)| operation)
            .unwrap();
        self.operations += 1;
        site
    }

    fn finish(mut self) -> ECodeIr {
        self.builder.set_graph(IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::new(0, self.operations).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::ENTRY,
            )],
            Vec::new(),
            Vec::new(),
        ));
        self.builder
            .build_unchecked(&CancellationToken::default())
            .unwrap()
    }

    fn finish_linear(self) -> ECodeIr {
        self.builder
            .build_unchecked(&CancellationToken::default())
            .unwrap()
    }
}

#[test]
fn a_reaching_register_value_must_match_the_root_width() {
    let mut function = Function::new();
    function.define_width(RDI, 32);
    let site = function.call();
    let ir = function.finish();
    let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
    let mut call = MCodeCallFacts::new(site);
    call.insert_input(MCodeStorageFact::new(
        MCodeStorageLocation::Register(RegisterId::new(RDI)),
        64,
    ));
    let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
    facts.insert_call(call);
    facts.validate(&ir, &registers).unwrap();
    let stack = MCodeStackModel::new(&ir, RegisterId::new(RSP), facts.stack_storage());

    let result = MCodeAbiModel::new(
        &ir,
        &MCodeCallingConvention::default(),
        &[],
        &[],
        Some(&facts),
        &registers,
        &stack,
    );

    assert_eq!(
        result.expect_err("the reaching value width must match its register root"),
        IlError::width_mismatch(ECodeIr::FORM)
    );
}

#[test]
fn recovers_register_args_in_convention_order() {
    let mut function = Function::new();
    let rdi = function.define(RDI);
    let rsi = function.define(RSI);
    let site = function.call();
    let ir = function.finish();

    let convention = MCodeCallingConvention::new(
        vec![register(RDI), register(RSI), register(RDX)],
        vec![register(RAX)],
    );
    let model = recover(&ir, &convention);
    let call = model.call(site).expect("a recovered call");

    assert_eq!(
        call.args(),
        &[MCodeCallArg::Value(rdi), MCodeCallArg::Value(rsi),]
    );
    assert_eq!(
        call.outputs()[0].location(),
        MCodeStorageLocation::Register(RegisterId::new(RAX))
    );
}

#[test]
fn recovers_register_args_in_a_linear_body() {
    let mut function = Function::new();
    let rdi = function.define(RDI);
    let site = function.call();
    let ir = function.finish_linear();

    let convention = MCodeCallingConvention::new(vec![register(RDI)], Vec::new());
    let model = recover(&ir, &convention);
    let call = model.call(site).expect("a recovered call");

    assert_eq!(call.args(), &[MCodeCallArg::Value(rdi)]);
}

#[test]
fn branch_heavy_abi_recovery_restores_reaching_registers_between_siblings() {
    const BRANCH_COUNT: usize = 32;

    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
    let reaching = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(1),
        [],
    )
    .unwrap();
    builder
        .emitter()
        .set_value_domain(reaching, ECodeDomain::Register(RegisterId::new(RDI)))
        .unwrap();

    for immediate in 1..BRANCH_COUNT {
        let sibling = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(immediate as u64 + 1),
            [],
        )
        .unwrap();
        builder
            .emitter()
            .set_value_domain(sibling, ECodeDomain::Register(RegisterId::new(RDI)))
            .unwrap();
    }
    let site = builder
        .emitter()
        .emit(
            ECodeOpSpec::new(ECodeOpcode::Call, 0).with_address(Address::from(0x1000u64)),
            [],
            0,
        )
        .map(|(operation, _)| operation)
        .unwrap();

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
    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    let convention = MCodeCallingConvention::new(vec![register(RDI)], Vec::new());
    let model = recover(&ir, &convention);

    assert_eq!(
        model.call(site).expect("the final sibling call").args(),
        &[MCodeCallArg::Value(reaching)]
    );
}

#[test]
fn recovers_a_register_arg_from_a_block_arg() {
    let mut graph = IlGraphBuilder::new();
    let entry = graph
        .push_block(IlIndexRange::new(0, 1).unwrap(), IlBlockProperties::ENTRY)
        .unwrap();
    let successor = graph
        .push_block(IlIndexRange::new(1, 2).unwrap(), IlBlockProperties::EXIT)
        .unwrap();
    graph
        .add_successor(entry, successor, IlEdgeKinds::FALL_THROUGH)
        .unwrap();

    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, graph.build(2).unwrap());
    let initial = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Constant, 64),
        [],
    )
    .unwrap();
    builder
        .emitter()
        .set_value_domain(initial, ECodeDomain::Register(RegisterId::new(RDI)))
        .unwrap();
    let arg = builder.emitter().emit_block_arg(successor, 64).unwrap();
    builder
        .emitter()
        .set_value_domain(arg, ECodeDomain::Register(RegisterId::new(RDI)))
        .unwrap();
    builder.emitter().emit_edge_args([initial]).unwrap();
    let site = builder
        .emitter()
        .emit(
            ECodeOpSpec::new(ECodeOpcode::Call, 0).with_address(Address::from(0x1000u64)),
            [],
            0,
        )
        .map(|(operation, _)| operation)
        .unwrap();
    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();

    let convention = MCodeCallingConvention::new(vec![register(RDI)], Vec::new());
    let model = recover(&ir, &convention);

    assert_eq!(
        model.call(site).expect("a recovered call").args(),
        &[MCodeCallArg::Value(arg)]
    );
}

#[test]
fn arity_stops_at_the_first_unset_arg_register() {
    let mut function = Function::new();
    let rdi = function.define(RDI);
    let site = function.call();
    let ir = function.finish();

    let convention = MCodeCallingConvention::new(vec![register(RDI), register(RSI)], Vec::new());
    let model = recover(&ir, &convention);
    let call = model.call(site).expect("a recovered call");

    assert_eq!(call.args(), &[MCodeCallArg::Value(rdi)]);
}

#[test]
fn a_register_outside_the_convention_width_range_is_an_error() {
    let mut function = Function::new();
    function.define(RDI);
    function.call();
    let ir = function.finish();
    let convention = MCodeCallingConvention::new(
        vec![MCodeCallingConventionEntry::new(
            MCodeStorageLocation::Register(RegisterId::new(RDI)),
            1,
            4,
        )],
        Vec::new(),
    );
    let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
    let stack = MCodeStackModel::new(&ir, RegisterId::new(RSP), []);

    let result = MCodeAbiModel::new(&ir, &convention, &[], &[], None, &registers, &stack);

    assert_eq!(
        result.expect_err("an incompatible convention input must fail recovery"),
        IlError::width_mismatch(ECodeIr::FORM)
    );
}

#[test]
fn a_forwarded_parameter_counts_but_a_post_clobber_value_does_not() {
    let mut function = Function::new();
    let forwarded = function.live_in(RDI);
    let forwarding_call = function.call();
    function.live_in(RDI);
    let clobbered_call = function.call();
    let ir = function.finish();

    let convention = MCodeCallingConvention::new(vec![register(RDI)], Vec::new());
    let model = recover(&ir, &convention);

    assert_eq!(
        model
            .call(forwarding_call)
            .expect("a recovered forwarding call")
            .args(),
        &[MCodeCallArg::Value(forwarded)]
    );
    assert!(
        model
            .call(clobbered_call)
            .expect("a recovered clobbered call")
            .args()
            .is_empty()
    );
}

#[test]
fn a_register_join_output_lowers_to_both_roots() {
    const HIGH: Varnode = Varnode::new(4, RDX, 8);
    const LOW: Varnode = Varnode::new(4, RAX, 8);
    static OUTPUTS: [PrototypeEntry; 1] = [PrototypeEntry::new(
        1,
        16,
        1,
        PrototypeOperand::RegisterJoin(HIGH, LOW),
    )];

    let prototype = Prototype::new("joined", 0, 0).with_outputs(&OUTPUTS);
    let convention = MCodeCallingConvention::from_prototype(&prototype, 64, |varnode| {
        Ok(RegisterId::new(varnode.offset()))
    })
    .unwrap();

    assert_eq!(
        convention.outputs(),
        &[MCodeCallingConventionEntry::new(
            MCodeStorageLocation::RegisterPair {
                high: RegisterId::new(RDX),
                low: RegisterId::new(RAX),
            },
            1,
            16,
        )]
    );
}

#[test]
fn an_unresolvable_register_join_is_an_error() {
    const HIGH: Varnode = Varnode::new(4, RDX, 8);
    const LOW: Varnode = Varnode::new(4, RAX, 8);
    static INPUTS: [PrototypeEntry; 1] = [PrototypeEntry::new(
        1,
        16,
        1,
        PrototypeOperand::RegisterJoin(HIGH, LOW),
    )];
    static OUTPUTS: [PrototypeEntry; 1] = [PrototypeEntry::new(
        1,
        16,
        1,
        PrototypeOperand::RegisterJoin(HIGH, LOW),
    )];

    let input_prototype = Prototype::new("joined", 0, 0).with_inputs(&INPUTS);
    let output_prototype = Prototype::new("joined", 0, 0).with_outputs(&OUTPUTS);
    let missing_root =
        || IlError::missing_component(ECodeIr::FORM, "call-convention register root");

    let input_error = MCodeCallingConvention::from_prototype(&input_prototype, 64, |varnode| {
        (varnode.offset() == HIGH.offset())
            .then_some(RegisterId::new(varnode.offset()))
            .ok_or_else(missing_root)
    });
    assert!(matches!(input_error, Err(IlError::MissingComponent { .. })));

    let output_error = MCodeCallingConvention::from_prototype(&output_prototype, 64, |varnode| {
        (varnode.offset() == HIGH.offset())
            .then_some(RegisterId::new(varnode.offset()))
            .ok_or_else(missing_root)
    });
    assert!(matches!(
        output_error,
        Err(IlError::MissingComponent { .. })
    ));
}

#[test]
fn recovers_a_register_join_as_a_pair() {
    let mut function = Function::new();
    let high = function.define(RDX);
    let low = function.define(RAX);
    let site = function.call();
    let ir = function.finish();

    let convention = MCodeCallingConvention::new(
        vec![MCodeCallingConventionEntry::new(
            MCodeStorageLocation::RegisterPair {
                high: RegisterId::new(RDX),
                low: RegisterId::new(RAX),
            },
            1,
            16,
        )],
        Vec::new(),
    );
    let model = recover(&ir, &convention);
    let call = model.call(site).expect("a recovered call");

    assert_eq!(call.args(), &[MCodeCallArg::Pair { high, low }]);
}
