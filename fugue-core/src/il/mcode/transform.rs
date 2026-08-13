use rustc_hash::{FxHashMap, FxHashSet};

use self::variables::{MCodeCallOutputSite, MCodeCallOutputVariables, MCodeVariableWidths};
use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlBlock, IlBlockId, IlConverter, IlError, IlGenerationContext, IlGenerationError,
    IlIndexRange, IlMetadata, IlOpId, IlValueId, RegisterId,
};
use crate::il::ecode::ssa::{ECodeSsaDomain, ECodeSsaIr};
use crate::il::mcode::recovery::{
    MCodeAliasOverride, MCodeAliasOverrides, MCodeCallFacts, MCodeRecovery, MCodeRecoveryConfig,
    MCodeStorageFact,
};
use crate::il::mcode::ssa::{MCodeSsaBuilder, MCodeSsaIr, MCodeSsaOptimiser};
use crate::il::mcode::{MCodeStorageLocation, MCodeVar, MCodeVarId};
use crate::il::pcode::RegisterBank;
use crate::storage::segments::space::AddressSpaceId;

mod blocks;
mod build;
mod spans;
mod variables;

#[derive(Debug, Default)]
pub struct ECodeSsaToMCode {
    scratch: MCodeSsaScratch,
    overrides: MCodeAliasOverrides,
    call_facts: MCodeCallFacts,
}

impl IlConverter for ECodeSsaToMCode {
    type Input = ECodeSsaIr;
    type Output = MCodeSsaIr;

    fn convert(
        &mut self,
        source: &Self::Input,
        context: &IlGenerationContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<Self::Output, IlGenerationError> {
        let registers = RegisterBank::new(context.language())?;
        let convention = context
            .language()
            .convention(context.platform().compiler_spec_id())
            .or_else(|| context.language().convention("default"))
            .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "calling convention"))?;
        let preserved = registers.call_preserved_registers(
            context.language(),
            context.arch().endian(),
            context.platform().compiler_spec_id(),
        )?;
        let config = MCodeRecoveryConfig::from_convention(
            &registers,
            convention,
            preserved,
            context.language().address_bits(),
        )?
        .with_call_facts(&self.call_facts)
        .with_alias_overrides(&self.overrides);
        let recovery = MCodeRecovery::new(source, &config, &registers)?;
        let mcode = self.build(source, &recovery, cancellation)?;

        if cfg!(debug_assertions) && !context.is_speculative() {
            mcode
                .verify()
                .expect("transformed MCode SSA fails verification");
        }

        Ok(mcode)
    }
}

impl ECodeSsaToMCode {
    pub fn add_call_input(&mut self, site: IlOpId, location: MCodeStorageLocation, width: u32) {
        self.call_facts
            .add_input(site, MCodeStorageFact::new(location, width));
    }

    pub fn add_call_output(&mut self, site: IlOpId, location: MCodeStorageLocation, width: u32) {
        self.call_facts
            .add_output(site, MCodeStorageFact::new(location, width));
    }

    pub fn force_aliased(&mut self, variable: MCodeVar) {
        self.overrides.insert(variable, MCodeAliasOverride::Aliased);
    }

    pub fn force_unaliased(&mut self, variable: MCodeVar) {
        self.overrides
            .insert(variable, MCodeAliasOverride::Unaliased);
    }

    pub fn clear_alias_override(&mut self, variable: MCodeVar) {
        self.overrides.remove(variable);
    }

    fn build(
        &mut self,
        source: &ECodeSsaIr,
        recovery: &MCodeRecovery,
        cancellation: &CancellationToken,
    ) -> Result<MCodeSsaIr, IlError> {
        cancellation.check()?;
        self.scratch.required_values.clear();

        let metadata = IlMetadata::new(
            source.metadata().function(),
            source.metadata().input_revision(),
        );
        let graph = source.graph().clone();
        let mut builder = MCodeSsaBuilder::new(metadata, graph);
        let mut construction =
            MCodeSsaConstruction::new(source, recovery, &mut builder, &mut self.scratch)?;

        construction.build(cancellation)?;
        drop(construction);

        let mut mcode = builder.build(cancellation)?;
        if cfg!(debug_assertions) {
            mcode
                .verify()
                .expect("unoptimised MCode SSA fails verification");
        }
        mcode.rewrite(MCodeSsaOptimiser::new(&self.scratch.required_values));

        Ok(mcode)
    }
}

#[derive(Debug, Clone, Default)]
struct MCodeSsaRenameState {
    stack: FxHashMap<MCodeVarId, IlValueId>,
    memory: FxHashMap<AddressSpaceId, IlValueId>,
    pending_memory: FxHashSet<AddressSpaceId>,
    pending_outputs: FxHashMap<RegisterId, IlValueId>,
}

#[derive(Debug, Default)]
struct MCodeSsaScratch {
    operands: Vec<IlValueId>,
    required_values: Vec<IlValueId>,
}

#[derive(Debug, Copy, Clone)]
enum MCodeSsaBlockArgOrigin {
    Source { value: IlValueId, position: usize },
    Stack(MCodeVarId),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum MCodeSsaBlockArgDomain {
    Memory(AddressSpaceId),
    Variable(MCodeVarId),
}

#[derive(Debug, Copy, Clone)]
struct MCodeSsaBlockArgBinding {
    domain: MCodeSsaBlockArgDomain,
    origin: MCodeSsaBlockArgOrigin,
    value: IlValueId,
}

impl MCodeSsaBlockArgBinding {
    const fn new(
        domain: MCodeSsaBlockArgDomain,
        origin: MCodeSsaBlockArgOrigin,
        value: IlValueId,
    ) -> Self {
        Self {
            domain,
            origin,
            value,
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct MCodeSsaPendingBlockArg {
    domain: MCodeSsaBlockArgDomain,
    origin: MCodeSsaBlockArgOrigin,
    width: u32,
}

impl MCodeSsaPendingBlockArg {
    const fn source(
        domain: MCodeSsaBlockArgDomain,
        value: IlValueId,
        position: usize,
        width: u32,
    ) -> Self {
        Self {
            domain,
            origin: MCodeSsaBlockArgOrigin::Source { value, position },
            width,
        }
    }

    const fn stack(variable: MCodeVarId, width: u32) -> Self {
        Self {
            domain: MCodeSsaBlockArgDomain::Variable(variable),
            origin: MCodeSsaBlockArgOrigin::Stack(variable),
            width,
        }
    }
}

#[derive(Default)]
struct MCodeSsaBindings {
    ordered: Vec<(IlValueId, MCodeVarId)>,
    variables: FxHashMap<IlValueId, MCodeVarId>,
    latest: FxHashMap<MCodeVarId, IlValueId>,
}

impl MCodeSsaBindings {
    fn insert(&mut self, value: IlValueId, variable: MCodeVarId) -> Result<(), IlError> {
        match self.variables.insert(value, variable) {
            Some(existing) if existing != variable => Err(IlError::missing_component(
                MCodeSsaIr::FORM,
                "consistent binding",
            )),
            Some(_) => Ok(()),
            None => {
                self.ordered.push((value, variable));
                self.latest.insert(variable, value);
                Ok(())
            }
        }
    }

    fn iter(&self) -> impl Iterator<Item = (IlValueId, MCodeVarId)> + '_ {
        self.ordered.iter().copied()
    }

    fn latest(&self, variable: MCodeVarId) -> Option<IlValueId> {
        self.latest.get(&variable).copied()
    }

    fn variable_for(&self, value: IlValueId) -> Option<MCodeVarId> {
        self.variables.get(&value).copied()
    }
}

struct MCodeSsaConstruction<'a, 'b> {
    source: &'a ECodeSsaIr,
    recovery: &'a MCodeRecovery,
    builder: &'b mut MCodeSsaBuilder,
    scratch: &'b mut MCodeSsaScratch,
    values: Vec<Option<IlValueId>>,
    variables: Vec<MCodeVarId>,
    variable_widths: MCodeVariableWidths,
    bindings: MCodeSsaBindings,
    call_output_variables: MCodeCallOutputVariables,
    block_arguments: Vec<Vec<MCodeSsaBlockArgBinding>>,
    blocks: Vec<Option<IlBlock>>,
    edge_arguments: Vec<Vec<IlValueId>>,
    operation_blocks: Vec<Option<IlBlockId>>,
    operation_ranges: Vec<IlIndexRange>,
}

impl<'a, 'b> MCodeSsaConstruction<'a, 'b> {
    fn new(
        source: &'a ECodeSsaIr,
        recovery: &'a MCodeRecovery,
        builder: &'b mut MCodeSsaBuilder,
        scratch: &'b mut MCodeSsaScratch,
    ) -> Result<Self, IlError> {
        let mut call_outputs = MCodeCallOutputVariables::new(source, recovery)?;
        let mut variables = Vec::with_capacity(recovery.variables().variables().len());
        for &component in call_outputs.components() {
            let variable = recovery.variables().variables()[component.index()];
            variables.push(builder.intern_variable(variable)?);
        }
        let variable_widths = MCodeVariableWidths::new(source, recovery, &variables)?;
        call_outputs.remap(&variables);

        Ok(Self {
            source,
            recovery,
            builder,
            scratch,
            values: vec![None; source.values().len()],
            variables,
            variable_widths,
            bindings: MCodeSsaBindings::default(),
            call_output_variables: call_outputs,
            block_arguments: vec![Vec::new(); source.graph().blocks().len()],
            blocks: vec![None; source.graph().blocks().len()],
            edge_arguments: vec![Vec::new(); source.graph().successors().len()],
            operation_blocks: source.operation_blocks(),
            operation_ranges: vec![IlIndexRange::EMPTY; source.operations().len()],
        })
    }

    fn variable(&self, recovered: MCodeVarId) -> MCodeVarId {
        self.variables[recovered.index()]
    }

    fn recovered_variable(&self, value: IlValueId) -> Result<MCodeVarId, IlError> {
        self.recovery
            .variables()
            .variable_for_value(value)
            .map(|variable| self.variable(variable))
            .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "variable binding"))
    }

    fn insert_binding(&mut self, value: IlValueId, variable: MCodeVarId) -> Result<(), IlError> {
        self.bindings.insert(value, variable)
    }

    fn source_value(&self, value: IlValueId) -> Result<IlValueId, IlError> {
        self.values
            .get(value.index())
            .copied()
            .flatten()
            .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "operand"))
    }

    fn source_domain(&self, value: IlValueId) -> Option<ECodeSsaDomain> {
        self.source.value_domain(value)
    }
}

#[cfg(test)]
mod test;
