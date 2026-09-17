use crate::il::common::{IlError, RegisterBank};
use crate::il::ecode::ECodeIr;
use crate::il::mcode::transform::ECodeToMCodeConfig;
use crate::il::mcode::transform::abi::MCodeAbiModel;
use crate::il::mcode::transform::aliases::MCodeAliasSet;
use crate::il::mcode::transform::facts::MCodeFunctionFacts;
use crate::il::mcode::transform::stack::MCodeStackModel;
use crate::il::mcode::transform::variables::MCodeVariableModel;

#[derive(Debug)]
pub(crate) struct ECodeToMCodeAnalysis {
    stack: MCodeStackModel,
    variables: MCodeVariableModel,
    aliases: MCodeAliasSet,
    abi: MCodeAbiModel,
}

impl ECodeToMCodeAnalysis {
    pub(crate) fn new(
        ir: &ECodeIr,
        config: &ECodeToMCodeConfig<'_>,
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

    use super::*;
    use crate::il::common::{
        IlBlock, IlBlockProperties, IlError, IlGraph, IlIndexRange, IlMetadata, IlValueId,
        RegisterId,
    };
    use crate::il::ecode::{ECodeBuilder, ECodeDomain, ECodeOpSpec, ECodeOpcode};
    use crate::il::mcode::MCodeStorageLocation;
    use crate::il::mcode::transform::abi::{
        MCodeCallArg, MCodeCallOutputComponent, MCodeCallingConventionEntry,
    };
    use crate::ir::{Address, FunctionId};
    use crate::lifter::{Varnode, resolve_language};

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

    fn x86_64_config() -> ECodeToMCodeConfig<'static> {
        let language = resolve_language("x86:LE:64").unwrap();
        let bank = RegisterBank::new(language).unwrap();
        let convention = language.convention("gcc").expect("gcc convention");
        ECodeToMCodeConfig::from_convention(&bank, convention, Vec::new())
            .expect("resolvable convention")
    }

    #[test]
    fn a_config_without_a_convention_has_no_call_analysis() {
        let language = resolve_language("x86:LE:64").unwrap();
        let bank = RegisterBank::new(language).unwrap();
        let convention = Convention::new("test", Varnode::new(0, RSP, 8));
        let config = ECodeToMCodeConfig::from_convention(&bank, &convention, Vec::new()).unwrap();

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
        let analysis = ECodeToMCodeAnalysis::new(&ir, &x86_64_config(), &registers).unwrap();

        assert!(analysis.stack().objects().is_empty());
        assert!(analysis.aliases().iter().next().is_none());
        assert!(analysis.variables().variable_for_value(rdi).is_some());
        let call = analysis.abi().call(site).expect("a analysed call");
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
        assert_eq!(analysis.stack().offset_of(rdi), None);
    }
}
