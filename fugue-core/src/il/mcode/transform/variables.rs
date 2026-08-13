use std::collections::{BTreeMap, BTreeSet};

use rustc_hash::FxHashMap;

use super::{
    MCodeSsaBlockArgBinding, MCodeSsaBlockArgDomain, MCodeSsaBlockArgOrigin, MCodeSsaConstruction,
    MCodeSsaPendingBlockArg,
};
use crate::il::common::{
    IlArtefact, IlBlockId, IlDominance, IlError, IlOpId, IlValueId, RegisterId,
};
use crate::il::ecode::ssa::{ECodeSsaDomain, ECodeSsaIr, ECodeSsaOpcode};
use crate::il::mcode::MCodeVarId;
use crate::il::mcode::disjoint_set::DisjointSet;
use crate::il::mcode::recovery::{MCodeRecovery, MCodeStackObjectId, MCodeStorageLocation};
use crate::il::mcode::ssa::MCodeSsaIr;

pub(super) struct MCodeVariableWidths(FxHashMap<MCodeVarId, u32>);

impl MCodeVariableWidths {
    pub(super) fn new(
        source: &ECodeSsaIr,
        recovery: &MCodeRecovery,
        variables: &[MCodeVarId],
    ) -> Result<Self, IlError> {
        let mut widths = Self(FxHashMap::default());
        for (index, value) in source.values().iter().enumerate() {
            let source_value = IlValueId::try_from_index(index)?;
            let Some(recovered) = recovery.variables().variable_for_value(source_value) else {
                continue;
            };
            widths.insert(variables[recovered.index()], value.width())?;
        }
        for (object_index, object) in recovery.stack().objects().iter().enumerate() {
            let object_id = MCodeStackObjectId::from_index(object_index);
            let recovered = recovery
                .variables()
                .stack_variable(object_id)
                .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "stack variable"))?;
            let width = object
                .end()
                .checked_sub(object.start())
                .and_then(|bytes| bytes.checked_mul(8))
                .and_then(|bits| u32::try_from(bits).ok())
                .ok_or_else(|| IlError::integer_overflow("stack variable width"))?;
            widths.insert(variables[recovered.index()], width)?;
        }
        Ok(widths)
    }

    pub(super) fn get(&self, variable: MCodeVarId) -> Option<u32> {
        self.0.get(&variable).copied()
    }

    fn insert(&mut self, variable: MCodeVarId, width: u32) -> Result<(), IlError> {
        match self.0.insert(variable, width) {
            Some(existing) if existing != width => Err(IlError::width_mismatch(MCodeSsaIr::FORM)),
            _ => Ok(()),
        }
    }
}

struct MCodeStackDefs(BTreeMap<MCodeVarId, Vec<IlBlockId>>);

impl MCodeStackDefs {
    fn new(
        source: &ECodeSsaIr,
        recovery: &MCodeRecovery,
        variables: &[MCodeVarId],
        operation_blocks: &[Option<IlBlockId>],
    ) -> Result<Self, IlError> {
        let mut definitions = BTreeMap::<MCodeVarId, Vec<IlBlockId>>::new();
        for (index, operation) in source.operations().iter().enumerate() {
            if operation.opcode() != ECodeSsaOpcode::Store {
                continue;
            }
            let site = IlOpId::try_from_index(index)?;
            let Some(access) = recovery.stack().access_for(site) else {
                continue;
            };
            let recovered = recovery
                .variables()
                .stack_variable(access.object())
                .ok_or_else(|| IlError::missing_component(ECodeSsaIr::FORM, "stack variable"))?;
            if recovery.aliases().contains(recovered) {
                continue;
            }
            let variable = variables
                .get(recovered.index())
                .copied()
                .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "stack variable"))?;
            let Some(block) = operation_blocks[index] else {
                continue;
            };
            let blocks = definitions.entry(variable).or_default();
            if blocks.last() != Some(&block) {
                blocks.push(block);
            }
        }
        Ok(Self(definitions))
    }

    fn into_entries(self) -> impl Iterator<Item = (MCodeVarId, Vec<IlBlockId>)> {
        self.0.into_iter()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(super) struct MCodeCallOutputSite {
    operation: IlOpId,
    location: MCodeStorageLocation,
    register: RegisterId,
}

impl MCodeCallOutputSite {
    pub(super) const fn new(
        operation: IlOpId,
        location: MCodeStorageLocation,
        register: RegisterId,
    ) -> Self {
        Self {
            operation,
            location,
            register,
        }
    }
}

pub(super) struct MCodeCallOutputVariables {
    components: Vec<MCodeVarId>,
    outputs: FxHashMap<MCodeCallOutputSite, MCodeVarId>,
}

#[derive(Clone, Default)]
struct MCodePendingCallOutputs(FxHashMap<RegisterId, (IlOpId, MCodeStorageLocation)>);

struct MCodeCallOutputAnalysis<'a> {
    source: &'a ECodeSsaIr,
    recovery: &'a MCodeRecovery,
    components: DisjointSet,
    outputs: FxHashMap<MCodeCallOutputSite, MCodeVarId>,
}

impl MCodePendingCallOutputs {
    fn begin_call(
        &mut self,
        site: IlOpId,
        outputs: impl IntoIterator<Item = (RegisterId, MCodeStorageLocation)>,
    ) {
        self.0.clear();
        self.0.extend(
            outputs
                .into_iter()
                .map(|(register, location)| (register, (site, location))),
        );
    }

    fn resolve(&mut self, register: RegisterId) -> Option<(IlOpId, MCodeStorageLocation)> {
        self.0.remove(&register)
    }

    fn kill(&mut self, register: RegisterId) {
        self.0.remove(&register);
    }
}

impl MCodeCallOutputVariables {
    pub(super) fn new(source: &ECodeSsaIr, recovery: &MCodeRecovery) -> Result<Self, IlError> {
        MCodeCallOutputAnalysis::new(source, recovery).build()
    }

    pub(super) fn components(&self) -> &[MCodeVarId] {
        &self.components
    }

    pub(super) fn remap(&mut self, variables: &[MCodeVarId]) {
        for component in &mut self.components {
            *component = variables[component.index()];
        }
        for component in self.outputs.values_mut() {
            *component = variables[component.index()];
        }
    }

    pub(super) fn get(&self, site: MCodeCallOutputSite) -> Option<MCodeVarId> {
        self.outputs.get(&site).copied()
    }
}

impl MCodeSsaConstruction<'_, '_> {
    pub(super) fn place_block_arguments(&mut self, dominance: &IlDominance) -> Result<(), IlError> {
        let graph = self.source.graph();
        let frontiers = dominance.frontiers(graph.blocks(), graph.successors());
        let mut stack_phis = BTreeSet::new();

        let stack_definitions = MCodeStackDefs::new(
            self.source,
            self.recovery,
            &self.variables,
            &self.operation_blocks,
        )?;
        for (variable, definitions) in stack_definitions.into_entries() {
            let placement = frontiers.place_phis(graph.blocks().len(), definitions);
            for &block in placement.blocks() {
                stack_phis.insert((block, variable));
            }
        }

        let mut source_positions = vec![0usize; graph.blocks().len()];
        let mut arguments = BTreeMap::<IlBlockId, Vec<MCodeSsaPendingBlockArg>>::new();
        for argument in self.source.block_arguments() {
            let position = source_positions[argument.block().index()];
            source_positions[argument.block().index()] += 1;
            let domain = match self.source_domain(argument.value()) {
                Some(ECodeSsaDomain::Memory(space)) => MCodeSsaBlockArgDomain::Memory(space),
                Some(domain) if domain.is_register_or_flag() => {
                    MCodeSsaBlockArgDomain::Variable(self.recovered_variable(argument.value())?)
                }
                Some(_) | None => {
                    return Err(IlError::missing_component(
                        MCodeSsaIr::FORM,
                        "block argument domain",
                    ));
                }
            };
            arguments
                .entry(argument.block())
                .or_default()
                .push(MCodeSsaPendingBlockArg::source(
                    domain,
                    argument.value(),
                    position,
                    argument.width(),
                ));
        }

        for (block, variable) in stack_phis {
            arguments
                .entry(block)
                .or_default()
                .push(MCodeSsaPendingBlockArg::stack(
                    variable,
                    self.variable_width(variable)?,
                ));
        }

        for (block, definitions) in arguments {
            let block_arguments = &mut self.block_arguments[block.index()];
            let mut definitions = definitions;
            definitions.sort_unstable_by_key(|definition| definition.domain);
            for definition in definitions {
                let value = self
                    .builder
                    .push_block_argument_value(block, definition.width)?;
                if let MCodeSsaBlockArgOrigin::Source { value: source, .. } = definition.origin {
                    self.values[source.index()] = Some(value);
                }
                block_arguments.push(MCodeSsaBlockArgBinding::new(
                    definition.domain,
                    definition.origin,
                    value,
                ));
            }
        }

        Ok(())
    }

    pub(super) fn variable_width(&self, variable: MCodeVarId) -> Result<u32, IlError> {
        self.variable_widths
            .get(variable)
            .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "variable width"))
    }
}

impl<'a> MCodeCallOutputAnalysis<'a> {
    fn new(source: &'a ECodeSsaIr, recovery: &'a MCodeRecovery) -> Self {
        Self {
            source,
            recovery,
            components: DisjointSet::new(recovery.variables().variables().len()),
            outputs: FxHashMap::default(),
        }
    }

    fn build(mut self) -> Result<MCodeCallOutputVariables, IlError> {
        let Some(entry) = self.source.graph().entry_block() else {
            self.collect_linear_call_outputs()?;
            return self.finish();
        };
        let dominance = IlDominance::from_blocks(
            self.source.graph().blocks(),
            self.source.graph().successors(),
            entry,
        );
        let mut built = vec![false; self.source.graph().blocks().len()];
        let mut stack = vec![(entry, MCodePendingCallOutputs::default())];
        while let Some((block, mut pending)) = stack.pop() {
            built[block.index()] = true;
            for argument in self
                .source
                .block_arguments()
                .iter()
                .filter(|argument| argument.block() == block)
            {
                if let Some(ECodeSsaDomain::Register(root)) =
                    self.source.value_domain(argument.value())
                {
                    pending.kill(root);
                }
            }
            self.collect_block_call_outputs(block, &mut pending)?;
            let children = dominance.children_for(block);
            let mut pending = Some(pending);
            for index in (0..children.len()).rev() {
                let child_pending = if index == 0 {
                    pending
                        .take()
                        .expect("call-output state is moved into exactly one child")
                } else {
                    pending
                        .as_ref()
                        .expect("call-output state exists until the final child")
                        .clone()
                };
                stack.push((children[index], child_pending));
            }
        }
        for (index, was_built) in built.into_iter().enumerate() {
            if !was_built {
                self.collect_block_call_outputs(
                    IlBlockId::try_from_index(index)?,
                    &mut MCodePendingCallOutputs::default(),
                )?;
            }
        }
        self.finish()
    }

    fn collect_linear_call_outputs(&mut self) -> Result<(), IlError> {
        let mut pending = MCodePendingCallOutputs::default();
        for index in 0..self.source.operations().len() {
            self.collect_call_output_at(IlOpId::try_from_index(index)?, &mut pending)?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<MCodeCallOutputVariables, IlError> {
        let components = (0..self.components.len())
            .map(|index| MCodeVarId::try_from_index(self.components.find(index)))
            .collect::<Result<Vec<_>, _>>()?;
        let outputs = self
            .outputs
            .into_iter()
            .map(|(output, variable)| (output, components[variable.index()]))
            .collect();
        Ok(MCodeCallOutputVariables {
            components,
            outputs,
        })
    }

    fn collect_block_call_outputs(
        &mut self,
        block: IlBlockId,
        pending: &mut MCodePendingCallOutputs,
    ) -> Result<(), IlError> {
        for (site, _) in self.source.operations_for_block(block) {
            self.collect_call_output_at(site, pending)?;
        }
        Ok(())
    }

    fn collect_call_output_at(
        &mut self,
        site: IlOpId,
        pending: &mut MCodePendingCallOutputs,
    ) -> Result<(), IlError> {
        let operation = &self.source.operations()[site.index()];
        if matches!(
            operation.opcode(),
            ECodeSsaOpcode::Call | ECodeSsaOpcode::CallIndirect
        ) {
            let outputs = self.recovery.abi().call(site).into_iter().flat_map(|call| {
                call.outputs().iter().flat_map(|output| {
                    output.components().iter().filter_map(move |component| {
                        component
                            .register_id()
                            .map(|register| (register, output.location()))
                    })
                })
            });
            pending.begin_call(site, outputs);
            return Ok(());
        }
        if operation.results().is_empty() {
            return Ok(());
        }
        let value = IlValueId::try_from_index(operation.results().start())?;
        let Some(ECodeSsaDomain::Register(root)) = self.source.value_domain(value) else {
            return Ok(());
        };
        if operation.opcode() == ECodeSsaOpcode::Undefined
            && let Some((call, location)) = pending.resolve(root)
            && let Some(variable) = self.recovery.variables().variable_for_value(value)
        {
            let output = *self
                .outputs
                .entry(MCodeCallOutputSite::new(call, location, root))
                .or_insert(variable);
            self.components.union(output.index(), variable.index());
        } else if operation.opcode() == ECodeSsaOpcode::WriteRegister {
            pending.kill(root);
        }

        Ok(())
    }
}
