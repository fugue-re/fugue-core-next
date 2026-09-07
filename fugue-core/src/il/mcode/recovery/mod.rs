use fugue_lifter::runtime::convention::Convention;

use crate::il::common::{IlArtefact, IlError, RegisterBank, RegisterId};
use crate::il::ecode::ECodeIr;
use crate::il::mcode::MCodeStorageLocation;
use crate::lifter::Varnode;

mod abi;
mod aliases;
mod stack;
mod variables;

pub(crate) use abi::{
    MCodeAbiModel, MCodeCallArg, MCodeCallOutputComponent, MCodeCallingConvention,
    MCodeExitRequirement,
};
pub use abi::{MCodeCallFacts, MCodeFunctionFacts, MCodeStorageFact};
pub(crate) use aliases::{MCodeAliasOverride, MCodeAliasOverrides, MCodeAliasSet};
pub(crate) use stack::{MCodeStackModel, MCodeStackObjectId};
pub(crate) use variables::MCodeVariableModel;

#[derive(Debug)]
pub(crate) struct MCodeRecoveryConfig<'a> {
    stack_pointer: RegisterId,
    calling_convention: MCodeCallingConvention,
    return_live_outputs: Vec<MCodeStorageFact>,
    tail_call_live_outputs: Vec<MCodeStorageFact>,
    facts: Option<&'a MCodeFunctionFacts>,
    alias_overrides: Option<&'a MCodeAliasOverrides>,
}

impl<'a> MCodeRecoveryConfig<'a> {
    pub(crate) fn from_convention(
        registers: &RegisterBank,
        convention: &Convention,
        preserved: Vec<RegisterId>,
    ) -> Result<Self, IlError> {
        let pointer = convention.stack_pointer();
        let stack_pointer = registers
            .root_id(pointer.offset(), pointer.size())
            .ok_or_else(|| {
                IlError::missing_component(ECodeIr::FORM, "stack pointer register root")
            })?;
        let calling_convention = match convention.default_prototype() {
            Some(prototype) => MCodeCallingConvention::from_prototype(
                prototype,
                registers.language().address_bits(),
                |varnode: &Varnode| {
                    registers
                        .root_id(varnode.offset(), varnode.size())
                        .ok_or_else(|| {
                            IlError::missing_component(
                                ECodeIr::FORM,
                                "calling-convention register root",
                            )
                        })
                },
            )?,
            None => MCodeCallingConvention::default(),
        };
        let mut return_live_outputs = Vec::new();
        let mut tail_call_live_outputs = Vec::new();
        for register in preserved.into_iter().chain([stack_pointer]) {
            let width = registers.root_bits(register).ok_or_else(|| {
                IlError::missing_component(ECodeIr::FORM, "live-output register width")
            })?;
            let fact = MCodeStorageFact::new(MCodeStorageLocation::Register(register), width);
            return_live_outputs.push(fact);
            tail_call_live_outputs.push(fact);
        }
        for output in calling_convention.outputs() {
            if let Some(fact) = output.resolve_fact(registers)? {
                return_live_outputs.push(fact);
            }
        }
        return_live_outputs.sort_unstable();
        return_live_outputs.dedup();
        tail_call_live_outputs.sort_unstable();
        tail_call_live_outputs.dedup();

        Ok(Self {
            stack_pointer,
            calling_convention,
            return_live_outputs,
            tail_call_live_outputs,
            facts: None,
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
            return_live_outputs: self.return_live_outputs,
            tail_call_live_outputs: self.tail_call_live_outputs,
            facts: self.facts,
            alias_overrides: Some(alias_overrides),
        }
    }

    pub(crate) fn with_call_facts<'b>(
        self,
        facts: &'b MCodeFunctionFacts,
    ) -> MCodeRecoveryConfig<'b>
    where
        'a: 'b,
    {
        MCodeRecoveryConfig {
            stack_pointer: self.stack_pointer,
            calling_convention: self.calling_convention,
            return_live_outputs: self.return_live_outputs,
            tail_call_live_outputs: self.tail_call_live_outputs,
            facts: Some(facts),
            alias_overrides: self.alias_overrides,
        }
    }
}

#[derive(Debug)]
pub(crate) struct MCodeRecovery {
    stack: MCodeStackModel,
    variables: MCodeVariableModel,
    aliases: MCodeAliasSet,
    abi: MCodeAbiModel,
}

impl MCodeRecovery {
    pub(crate) fn new(
        ir: &ECodeIr,
        config: &MCodeRecoveryConfig<'_>,
        registers: &RegisterBank,
    ) -> Result<Self, IlError> {
        if let Some(facts) = config.facts {
            facts.validate(ir, registers)?;
        }
        let stack = MCodeStackModel::new(
            ir,
            config.stack_pointer,
            config
                .facts
                .into_iter()
                .flat_map(MCodeFunctionFacts::stack_storage),
        );
        if let Some(facts) = config.facts {
            facts.validate_stack(&stack)?;
        }
        let variables = MCodeVariableModel::new(ir, &stack);
        let aliases = MCodeAliasSet::new(&stack, &variables, config.alias_overrides);
        let abi = MCodeAbiModel::new(
            ir,
            &config.calling_convention,
            &config.return_live_outputs,
            &config.tail_call_live_outputs,
            config.facts,
            registers,
            &stack,
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
    use crate::il::common::{
        IlBlock, IlBlockProperties, IlError, IlGraph, IlIndexRange, IlMetadata, IlValueId,
    };
    use crate::il::ecode::{ECodeBuilder, ECodeDomain, ECodeOpSpec, ECodeOpcode};
    use crate::ir::{Address, FunctionId};
    use crate::lifter::resolve_language;

    const RAX: u64 = 0x00;
    const RDI: u64 = 0x38;
    const RSI: u64 = 0x30;
    const RSP: u64 = 0x20;

    fn emit_value(
        builder: &mut ECodeBuilder,
        spec: ECodeOpSpec,
        operands: impl IntoIterator<Item = IlValueId>,
    ) -> Result<IlValueId, IlError> {
        let (_, results) = builder.emitter().emit(spec, operands, 1)?;
        IlValueId::try_from_index(results.start())
    }

    fn x86_64_config() -> MCodeRecoveryConfig<'static> {
        let language = resolve_language("x86:LE:64").unwrap();
        let bank = RegisterBank::new(language).unwrap();
        let convention = language.convention("gcc").expect("gcc convention");
        MCodeRecoveryConfig::from_convention(&bank, convention, Vec::new())
            .expect("resolvable convention")
    }

    #[test]
    fn a_config_without_a_convention_has_no_call_recovery() {
        let language = resolve_language("x86:LE:64").unwrap();
        let bank = RegisterBank::new(language).unwrap();
        let convention = Convention::new("test", Varnode::new(0, RSP, 8));
        let config = MCodeRecoveryConfig::from_convention(&bank, &convention, Vec::new()).unwrap();

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
        let mut builder = ECodeBuilder::new(
            IlMetadata::new(FunctionId::default(), 0),
            IlGraph::default(),
        );
        let mut operations = 0;
        let mut define = |builder: &mut ECodeBuilder, root: u64| {
            let id = emit_value(builder, ECodeOpSpec::new(ECodeOpcode::Constant, 64), []).unwrap();
            builder
                .emitter()
                .set_value_domain(id, ECodeDomain::Register(RegisterId::new(root)))
                .unwrap();
            operations += 1;
            id
        };

        let rdi = define(&mut builder, RDI);
        let rsi = define(&mut builder, RSI);
        let site = builder
            .emitter()
            .emit(
                ECodeOpSpec::new(ECodeOpcode::Call, 0).with_address(Address::from(0x1000u64)),
                [],
                0,
            )
            .map(|(operation, _)| operation)
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
        let ir = builder.build_unchecked();

        let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
        let recovery = MCodeRecovery::new(&ir, &x86_64_config(), &registers).unwrap();

        assert!(recovery.stack().objects().is_empty());
        assert!(recovery.aliases().iter().next().is_none());
        assert!(recovery.variables().variable_for_value(rdi).is_some());
        let call = recovery.abi().call(site).expect("a recovered call");
        assert_eq!(
            call.args(),
            &[MCodeCallArg::Value(rdi), MCodeCallArg::Value(rsi)]
        );
        assert_eq!(
            call.outputs()
                .iter()
                .flat_map(|output| output.components())
                .filter_map(|component| match component {
                    MCodeCallOutputComponent::Register { register, .. } => Some(*register),
                    MCodeCallOutputComponent::Stack { .. } => None,
                })
                .collect::<Vec<_>>(),
            &[RegisterId::new(RAX), RegisterId::new(0x10)]
        );
        assert_eq!(recovery.stack().offset_of(rdi), None);
    }
}
