use fugue_lifter::runtime::convention::Convention;

use crate::il::common::{IlArtefact, IlError, RegisterId};
use crate::il::ecode::ssa::ECodeSsaIr;
use crate::il::pcode::RegisterBank;
use crate::lifter::Varnode;

mod abi;
mod aliases;
mod stack;
mod variables;

pub use abi::MCodeStorageLocation;
pub(crate) use abi::{
    MCodeAbiModel, MCodeCallArgument, MCodeCallFacts, MCodeCallingConvention, MCodeFunctionFacts,
    MCodeStorageFact,
};
pub(crate) use aliases::{MCodeAliasOverride, MCodeAliasOverrides, MCodeAliasSet};
pub(crate) use stack::{MCodeStackModel, MCodeStackObjectId};
pub(crate) use variables::MCodeVariableModel;

#[derive(Debug, Clone)]
pub(crate) struct MCodeRecoveryConfig<'a> {
    stack_pointer: RegisterId,
    calling_convention: MCodeCallingConvention,
    function: MCodeFunctionFacts,
    calls: Option<&'a MCodeCallFacts>,
    alias_overrides: Option<&'a MCodeAliasOverrides>,
}

impl<'a> MCodeRecoveryConfig<'a> {
    pub(crate) fn from_convention(
        bank: &RegisterBank,
        convention: &Convention,
        preserved: Vec<RegisterId>,
        address_bits: u32,
    ) -> Result<Self, IlError> {
        let pointer = convention.stack_pointer();
        let stack_pointer = bank
            .root_id(pointer.offset(), pointer.size())
            .ok_or_else(|| {
                IlError::missing_component(ECodeSsaIr::FORM, "stack pointer register root")
            })?;
        let calling_convention = match convention.default_prototype() {
            Some(prototype) => MCodeCallingConvention::from_prototype(
                prototype,
                address_bits,
                |varnode: &Varnode| {
                    bank.root_id(varnode.offset(), varnode.size())
                        .ok_or_else(|| {
                            IlError::missing_component(
                                ECodeSsaIr::FORM,
                                "calling-convention register root",
                            )
                        })
                },
            )?,
            None => MCodeCallingConvention::default(),
        };
        let mut function = MCodeFunctionFacts::new();
        for register in preserved {
            let location = MCodeStorageLocation::Register(register);
            function.add_return_live_output(location);
            function.add_tail_call_live_output(location);
        }
        let stack_pointer_location = MCodeStorageLocation::Register(stack_pointer);
        function.add_return_live_output(stack_pointer_location);
        function.add_tail_call_live_output(stack_pointer_location);
        for output in calling_convention.outputs() {
            function.add_return_live_output(output.location());
        }

        Ok(Self {
            stack_pointer,
            calling_convention,
            function,
            calls: None,
            alias_overrides: None,
        })
    }

    pub(crate) fn with_alias_overrides<'b>(
        self,
        alias_overrides: &'b MCodeAliasOverrides,
    ) -> MCodeRecoveryConfig<'b>
    where
        'a: 'b,
    {
        MCodeRecoveryConfig {
            stack_pointer: self.stack_pointer,
            calling_convention: self.calling_convention,
            function: self.function,
            calls: self.calls,
            alias_overrides: Some(alias_overrides),
        }
    }

    pub(crate) fn with_call_facts<'b>(self, calls: &'b MCodeCallFacts) -> MCodeRecoveryConfig<'b>
    where
        'a: 'b,
    {
        MCodeRecoveryConfig {
            stack_pointer: self.stack_pointer,
            calling_convention: self.calling_convention,
            function: self.function,
            calls: Some(calls),
            alias_overrides: self.alias_overrides,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MCodeRecovery {
    stack: MCodeStackModel,
    variables: MCodeVariableModel,
    aliases: MCodeAliasSet,
    abi: MCodeAbiModel,
}

impl MCodeRecovery {
    pub(crate) fn new(
        ir: &ECodeSsaIr,
        config: &MCodeRecoveryConfig<'_>,
        registers: &RegisterBank,
    ) -> Result<Self, IlError> {
        let empty_calls = MCodeCallFacts::new();
        let calls = config.calls.unwrap_or(&empty_calls);
        let stack = MCodeStackModel::new(ir, config.stack_pointer, calls.stack_storage());
        let variables = MCodeVariableModel::new(ir, &stack);
        let aliases = MCodeAliasSet::new(&stack, &variables, config.alias_overrides);
        let abi = MCodeAbiModel::new(
            ir,
            &config.calling_convention,
            &config.function,
            calls,
            registers,
        )?;

        Ok(Self {
            stack,
            variables,
            aliases,
            abi,
        })
    }

    pub(crate) fn stack(&self) -> &MCodeStackModel {
        &self.stack
    }

    pub(crate) fn variables(&self) -> &MCodeVariableModel {
        &self.variables
    }

    pub(crate) fn aliases(&self) -> &MCodeAliasSet {
        &self.aliases
    }

    pub(crate) fn abi(&self) -> &MCodeAbiModel {
        &self.abi
    }
}

#[cfg(test)]
mod test {
    use fugue_lifter::runtime::convention::Convention;

    use super::abi::MCodeCallingConventionEntry;
    use super::*;
    use crate::analysis::control::CancellationToken;
    use crate::il::common::{
        IlBlock, IlBlockProperties, IlGraph, IlIndexRange, IlMetadata, IlOpId,
    };
    use crate::il::ecode::ssa::{ECodeSsaBuilder, ECodeSsaDomain, ECodeSsaOp, ECodeSsaOpcode};
    use crate::ir::{Address, FunctionId};
    use crate::lifter::resolve_language;

    const RAX: u64 = 0x00;
    const RDI: u64 = 0x38;
    const RSI: u64 = 0x30;
    const RSP: u64 = 0x20;

    fn x86_64_config() -> MCodeRecoveryConfig<'static> {
        let language = resolve_language("x86:LE:64").unwrap();
        let bank = RegisterBank::new(language).unwrap();
        let convention = language.convention("gcc").expect("gcc convention");
        MCodeRecoveryConfig::from_convention(&bank, convention, Vec::new(), language.address_bits())
            .expect("resolvable convention")
    }

    #[test]
    fn a_config_without_a_convention_has_no_call_recovery() {
        let language = resolve_language("x86:LE:64").unwrap();
        let bank = RegisterBank::new(language).unwrap();
        let convention = Convention::new("test", Varnode::new(0, RSP, 8));
        let config =
            MCodeRecoveryConfig::from_convention(&bank, &convention, Vec::new(), 64).unwrap();

        assert_eq!(config.stack_pointer, RegisterId::new(RSP));
        assert!(config.calling_convention.inputs().is_empty());
        assert!(config.calling_convention.outputs().is_empty());
    }

    #[test]
    fn config_resolves_the_gcc_convention() {
        let config = x86_64_config();

        assert_eq!(config.stack_pointer, RegisterId::new(RSP));
        assert_eq!(
            config
                .calling_convention
                .inputs()
                .iter()
                .map(MCodeCallingConventionEntry::location)
                .collect::<Vec<_>>(),
            &[
                MCodeStorageLocation::Register(RegisterId::new(RDI)),
                MCodeStorageLocation::Register(RegisterId::new(RSI)),
                MCodeStorageLocation::Register(RegisterId::new(0x10)),
                MCodeStorageLocation::Register(RegisterId::new(0x08)),
                MCodeStorageLocation::Register(RegisterId::new(0x80)),
                MCodeStorageLocation::Register(RegisterId::new(0x88)),
                MCodeStorageLocation::Stack { offset: 8 },
            ]
        );
        assert_eq!(
            config
                .calling_convention
                .outputs()
                .iter()
                .map(MCodeCallingConventionEntry::location)
                .collect::<Vec<_>>(),
            &[
                MCodeStorageLocation::Register(RegisterId::new(RAX)),
                MCodeStorageLocation::Register(RegisterId::new(0x10)),
            ]
        );
    }

    #[test]
    fn recovery_bundles_all_models() {
        let mut builder = ECodeSsaBuilder::new(
            IlMetadata::new(FunctionId::default(), 0),
            IlGraph::default(),
        );
        let mut operations = 0;
        let mut define = |builder: &mut ECodeSsaBuilder, root: u64| {
            let (id, results) = builder.push_result_value(64).unwrap();
            builder
                .push_operation(
                    ECodeSsaOp::new(ECodeSsaOpcode::Constant, results, IlIndexRange::EMPTY, 64)
                        .with_immediate(0),
                )
                .unwrap();
            builder.set_value_domain(id, ECodeSsaDomain::Register(RegisterId::new(root)));
            operations += 1;
            id
        };

        let rdi = define(&mut builder, RDI);
        let rsi = define(&mut builder, RSI);
        let site = IlOpId::try_from_index(operations).unwrap();
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
        operations += 1;

        builder.set_graph(IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::new(0, operations).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::ENTRY,
            )],
            Vec::new(),
            Vec::new(),
        ));
        let ir = builder.build(&CancellationToken::default()).unwrap();

        let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
        let recovery = MCodeRecovery::new(&ir, &x86_64_config(), &registers).unwrap();

        assert!(recovery.stack().objects().is_empty());
        assert!(recovery.aliases().iter().next().is_none());
        assert!(recovery.variables().variable_for_value(rdi).is_some());
        let call = recovery.abi().call(site).expect("a recovered call");
        assert_eq!(
            call.arguments(),
            &[MCodeCallArgument::Value(rdi), MCodeCallArgument::Value(rsi)]
        );
        assert_eq!(
            call.outputs()
                .iter()
                .flat_map(|output| output.components())
                .filter_map(|component| component.register_id())
                .collect::<Vec<_>>(),
            &[RegisterId::new(RAX), RegisterId::new(0x10)]
        );
        assert_eq!(recovery.stack().offset_of(rdi), None);
    }
}
