use super::*;
use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlBlock, IlBlockProperties, IlError, IlGraph, IlIndexRange, IlMetadata,
};
use crate::il::ecode::ssa::{
    ECodeSsaBuilder, ECodeSsaDomain, ECodeSsaIr, ECodeSsaOp, ECodeSsaOpcode,
};
use crate::il::pcode::RegisterBank;
use crate::ir::{Address, FunctionId};
use crate::lifter::resolve_language;

const RDI: u64 = 0x38;
const RSI: u64 = 0x30;
const RDX: u64 = 0x28;
const RAX: u64 = 0x00;

fn recover(ir: &ECodeSsaIr, convention: &MCodeCallingConvention) -> MCodeAbiModel {
    let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
    MCodeAbiModel::new(
        ir,
        convention,
        &MCodeFunctionFacts::default(),
        &MCodeCallFacts::default(),
        &registers,
    )
    .unwrap()
}

fn recover_with_facts(
    ir: &ECodeSsaIr,
    convention: &MCodeCallingConvention,
    facts: &MCodeCallFacts,
) -> MCodeAbiModel {
    let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
    MCodeAbiModel::new(
        ir,
        convention,
        &MCodeFunctionFacts::default(),
        facts,
        &registers,
    )
    .unwrap()
}

fn entry(location: MCodeStorageLocation) -> MCodeCallingConventionEntry {
    MCodeCallingConventionEntry::new(location, 1, 8)
}

fn register(root: u64) -> MCodeCallingConventionEntry {
    entry(MCodeStorageLocation::Register(RegisterId::new(root)))
}

#[test]
fn stack_offsets_are_normalised_to_the_target_address_width() {
    assert_eq!(
        MCodeStorageLocation::normalise_stack_offset(0x10, 32),
        Ok(16)
    );
    assert_eq!(
        MCodeStorageLocation::normalise_stack_offset(0xffff_fff0, 32),
        Ok(-16)
    );
    assert_eq!(
        MCodeStorageLocation::normalise_stack_offset(0x10, 64),
        Ok(16)
    );
    assert_eq!(
        MCodeStorageLocation::normalise_stack_offset(0xffff_ffff_ffff_fff0, 64),
        Ok(-16)
    );
}

#[test]
fn exact_stack_facts_produce_stack_inputs_and_outputs() {
    let mut function = Function::new();
    let site = function.call();
    let ir = function.finish();
    let mut facts = MCodeCallFacts::new();
    facts.add_input(
        site,
        MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -16 }, 128),
    );
    facts.add_output(
        site,
        MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: 8 }, 192),
    );

    let model = recover_with_facts(&ir, &MCodeCallingConvention::default(), &facts);
    let call = model.call(site).expect("a recovered call");
    let output = call.outputs().first().expect("a recovered stack output");
    let component = output.components().first().expect("one stack component");

    assert_eq!(
        call.arguments(),
        &[MCodeCallArgument::Stack {
            offset: -16,
            width: 128,
        }]
    );
    assert_eq!(output.location(), MCodeStorageLocation::Stack { offset: 8 });
    assert_eq!(component.stack_offset(), Some(8));
    assert_eq!(component.width(), 192);
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

    fn define(&mut self, root: u64) -> IlValueId {
        let (id, results) = self.builder.push_result_value(64).unwrap();
        self.builder
            .push_operation(
                ECodeSsaOp::new(ECodeSsaOpcode::Constant, results, IlIndexRange::EMPTY, 64)
                    .with_immediate(0),
            )
            .unwrap();
        self.builder
            .set_value_domain(id, ECodeSsaDomain::Register(RegisterId::new(root)));
        self.operations += 1;
        id
    }

    fn live_in(&mut self, root: u64) -> IlValueId {
        let (id, results) = self.builder.push_result_value(64).unwrap();
        self.builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::Undefined,
                results,
                IlIndexRange::EMPTY,
                64,
            ))
            .unwrap();
        self.builder
            .set_value_domain(id, ECodeSsaDomain::Register(RegisterId::new(root)));
        self.operations += 1;
        id
    }

    fn call(&mut self) -> IlOpId {
        let site = IlOpId::try_from_index(self.operations).unwrap();
        self.builder
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
        self.operations += 1;
        site
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

#[test]
fn recovers_register_arguments_in_convention_order() {
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
        call.arguments(),
        &[MCodeCallArgument::Value(rdi), MCodeCallArgument::Value(rsi),]
    );
    assert_eq!(
        call.outputs()[0].location(),
        MCodeStorageLocation::Register(RegisterId::new(RAX))
    );
}

#[test]
fn recovers_register_arguments_in_a_linear_body() {
    let mut function = Function::new();
    let rdi = function.define(RDI);
    let site = function.call();
    let ir = function.finish_linear();

    let convention = MCodeCallingConvention::new(vec![register(RDI)], Vec::new());
    let model = recover(&ir, &convention);
    let call = model.call(site).expect("a recovered call");

    assert_eq!(call.arguments(), &[MCodeCallArgument::Value(rdi)]);
}

#[test]
fn arity_stops_at_the_first_unset_argument_register() {
    let mut function = Function::new();
    let rdi = function.define(RDI);
    let site = function.call();
    let ir = function.finish();

    let convention = MCodeCallingConvention::new(vec![register(RDI), register(RSI)], Vec::new());
    let model = recover(&ir, &convention);
    let call = model.call(site).expect("a recovered call");

    assert_eq!(call.arguments(), &[MCodeCallArgument::Value(rdi)]);
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
            .arguments(),
        &[MCodeCallArgument::Value(forwarded)]
    );
    assert!(
        model
            .call(clobbered_call)
            .expect("a recovered clobbered call")
            .arguments()
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
        || IlError::missing_component(ECodeSsaIr::FORM, "call-convention register root");

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
        vec![entry(MCodeStorageLocation::RegisterPair {
            high: RegisterId::new(RDX),
            low: RegisterId::new(RAX),
        })],
        Vec::new(),
    );
    let model = recover(&ir, &convention);
    let call = model.call(site).expect("a recovered call");

    assert_eq!(call.arguments(), &[MCodeCallArgument::Pair { high, low }]);
}
