use std::collections::BTreeMap;

use rustc_hash::FxHashMap;

use crate::il::common::{
    IlArtefact, IlBlockId, IlCsr, IlDominance, IlDominanceEvent, IlError, IlOpId, IlValueId,
    RegisterId,
};
use crate::il::ecode::{ECodeDomain, ECodeIr, ECodeOpcode};
use crate::il::mcode::disjoint_set::DisjointSet;
use crate::il::mcode::recovery::{MCodeCallOutputComponent, MCodeRecovery, MCodeStackObjectId};
use crate::il::mcode::{MCodeIr, MCodeStorageLocation, MCodeVarId};

pub(crate) struct MCodeVariableWidths(FxHashMap<MCodeVarId, u32>);

impl MCodeVariableWidths {
    pub(crate) fn new(
        ir: &ECodeIr,
        recovery: &MCodeRecovery,
        variables: &[MCodeVarId],
    ) -> Result<Self, IlError> {
        let mut widths = Self(FxHashMap::default());
        for (index, value) in ir.values().iter().enumerate() {
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
                .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "stack variable"))?;
            let width = object
                .width()
                .ok_or_else(|| IlError::integer_overflow("stack variable width"))?;
            widths.insert(variables[recovered.index()], width)?;
        }
        Ok(widths)
    }

    pub(crate) fn width(&self, variable: MCodeVarId) -> Result<u32, IlError> {
        self.0
            .get(&variable)
            .copied()
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "variable width"))
    }

    fn insert(&mut self, variable: MCodeVarId, width: u32) -> Result<(), IlError> {
        match self.0.insert(variable, width) {
            Some(existing) if existing != width => Err(IlError::width_mismatch(MCodeIr::FORM)),
            _ => Ok(()),
        }
    }
}

pub(crate) struct MCodeStackDefs(BTreeMap<MCodeVarId, Vec<IlBlockId>>);

impl MCodeStackDefs {
    pub(crate) fn new(
        ir: &ECodeIr,
        recovery: &MCodeRecovery,
        variables: &[MCodeVarId],
        operation_blocks: &[Option<IlBlockId>],
    ) -> Result<Self, IlError> {
        let mut definitions = BTreeMap::<MCodeVarId, Vec<IlBlockId>>::new();
        for (index, operation) in ir.operations().iter().enumerate() {
            if operation.opcode() != ECodeOpcode::Store {
                continue;
            }
            let site = IlOpId::try_from_index(index)?;
            let Some(access) = recovery.stack().access_for(site) else {
                continue;
            };
            let recovered = recovery
                .variables()
                .stack_variable(access.object())
                .ok_or_else(|| IlError::missing_component(ECodeIr::FORM, "stack variable"))?;
            if recovery.aliases().contains(recovered) {
                continue;
            }
            let variable = variables
                .get(recovered.index())
                .copied()
                .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "stack variable"))?;
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

    pub(crate) fn into_entries(self) -> impl Iterator<Item = (MCodeVarId, Vec<IlBlockId>)> {
        self.0.into_iter()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) struct MCodeCallOutputSite {
    operation: IlOpId,
    location: MCodeStorageLocation,
    register: RegisterId,
}

impl MCodeCallOutputSite {
    pub(crate) const fn new(
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

pub(crate) struct MCodeCallOutputVariables {
    representatives: Vec<MCodeVarId>,
    outputs: FxHashMap<MCodeCallOutputSite, MCodeVarId>,
}

#[derive(Debug, Copy, Clone)]
struct MCodeCallOutputCandidate {
    site: IlOpId,
    location: MCodeStorageLocation,
}

#[derive(Default)]
struct MCodeCallOutputCandidates {
    values: FxHashMap<RegisterId, MCodeCallOutputCandidate>,
    undo: Vec<(RegisterId, Option<MCodeCallOutputCandidate>)>,
    tracking: bool,
}

struct MCodeCallOutputSolver<'a> {
    source: &'a ECodeIr,
    recovery: &'a MCodeRecovery,
    representatives: DisjointSet,
    outputs: FxHashMap<MCodeCallOutputSite, MCodeVarId>,
}

impl MCodeCallOutputCandidates {
    fn checkpoint(&mut self) -> usize {
        self.tracking = true;
        self.undo.len()
    }

    fn rollback(&mut self, checkpoint: usize) {
        while self.undo.len() > checkpoint {
            let (register, previous) = self
                .undo
                .pop()
                .expect("a call-output checkpoint is within the undo log");
            match previous {
                Some(candidate) => {
                    self.values.insert(register, candidate);
                }
                None => {
                    self.values.remove(&register);
                }
            }
        }
    }

    fn begin_call(
        &mut self,
        site: IlOpId,
        outputs: impl IntoIterator<Item = (RegisterId, MCodeStorageLocation)>,
    ) {
        if self.tracking {
            self.undo.extend(
                self.values
                    .drain()
                    .map(|(register, candidate)| (register, Some(candidate))),
            );
        } else {
            self.values.clear();
        }
        for (register, location) in outputs {
            let previous = self
                .values
                .insert(register, MCodeCallOutputCandidate { site, location });
            if self.tracking {
                self.undo.push((register, previous));
            }
        }
    }

    fn resolve(&mut self, register: RegisterId) -> Option<MCodeCallOutputCandidate> {
        let candidate = self.values.remove(&register);
        if let Some(candidate) = candidate.filter(|_| self.tracking) {
            self.undo.push((register, Some(candidate)));
        }
        candidate
    }
}

impl MCodeCallOutputVariables {
    pub(crate) fn new(ir: &ECodeIr, recovery: &MCodeRecovery) -> Result<Self, IlError> {
        MCodeCallOutputSolver::new(ir, recovery).solve()
    }

    pub(crate) fn representative_for(&self, variable: MCodeVarId) -> MCodeVarId {
        self.representatives[variable.index()]
    }

    pub(crate) fn representative_for_output(
        &self,
        site: MCodeCallOutputSite,
    ) -> Option<MCodeVarId> {
        self.outputs.get(&site).copied()
    }
}

impl<'a> MCodeCallOutputSolver<'a> {
    fn new(ir: &'a ECodeIr, recovery: &'a MCodeRecovery) -> Self {
        Self {
            source: ir,
            recovery,
            representatives: DisjointSet::new(recovery.variables().variables().len()),
            outputs: FxHashMap::default(),
        }
    }

    fn solve(mut self) -> Result<MCodeCallOutputVariables, IlError> {
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
        let block_args = IlCsr::from_entries(
            self.source.graph().blocks().len(),
            self.source
                .block_args()
                .iter()
                .map(|arg| (arg.block().index(), arg.value())),
        );
        let mut candidates = MCodeCallOutputCandidates::default();
        let mut checkpoints = Vec::new();
        for event in dominance.events_from(entry) {
            match event {
                IlDominanceEvent::Enter(block) => {
                    built[block.index()] = true;
                    checkpoints.push(candidates.checkpoint());
                    for &arg in block_args.row(block.index()) {
                        if let Some(ECodeDomain::Register(root)) = self.source.value_domain(arg) {
                            let _ = candidates.resolve(root);
                        }
                    }
                    self.collect_block_call_outputs(block, &mut candidates)?;
                }
                IlDominanceEvent::Exit(_) => {
                    candidates.rollback(
                        checkpoints
                            .pop()
                            .expect("each dominance exit follows a matching entry"),
                    );
                }
            }
        }
        for (index, was_built) in built.into_iter().enumerate() {
            if !was_built {
                let mut candidates = MCodeCallOutputCandidates::default();
                self.collect_block_call_outputs(
                    IlBlockId::try_from_index(index)?,
                    &mut candidates,
                )?;
            }
        }
        self.finish()
    }

    fn collect_linear_call_outputs(&mut self) -> Result<(), IlError> {
        let mut candidates = MCodeCallOutputCandidates::default();
        for index in 0..self.source.operations().len() {
            self.collect_call_output_at(IlOpId::try_from_index(index)?, &mut candidates)?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<MCodeCallOutputVariables, IlError> {
        let representatives = (0..self.representatives.len())
            .map(|index| MCodeVarId::try_from_index(self.representatives.find(index)))
            .collect::<Result<Vec<_>, _>>()?;
        let outputs = self
            .outputs
            .into_iter()
            .map(|(output, variable)| (output, representatives[variable.index()]))
            .collect();
        Ok(MCodeCallOutputVariables {
            representatives,
            outputs,
        })
    }

    fn collect_block_call_outputs(
        &mut self,
        block: IlBlockId,
        candidates: &mut MCodeCallOutputCandidates,
    ) -> Result<(), IlError> {
        for (site, _) in self
            .source
            .graph()
            .operations_for_block(block, self.source.operations())
        {
            self.collect_call_output_at(site, candidates)?;
        }
        Ok(())
    }

    fn collect_call_output_at(
        &mut self,
        site: IlOpId,
        candidates: &mut MCodeCallOutputCandidates,
    ) -> Result<(), IlError> {
        let operation = &self.source.operations()[site.index()];
        if matches!(
            operation.opcode(),
            ECodeOpcode::Call | ECodeOpcode::CallIndirect
        ) {
            let outputs = self.recovery.abi().call(site).into_iter().flat_map(|call| {
                call.outputs().iter().flat_map(|output| {
                    output
                        .components()
                        .iter()
                        .filter_map(move |component| match component {
                            MCodeCallOutputComponent::Register { register, .. } => {
                                Some((*register, output.location()))
                            }
                            MCodeCallOutputComponent::Stack { .. } => None,
                        })
                })
            });
            candidates.begin_call(site, outputs);
            return Ok(());
        }
        if operation.results().is_empty() {
            return Ok(());
        }
        let value = IlValueId::try_from_index(operation.results().start())?;
        let Some(ECodeDomain::Register(root)) = self.source.value_domain(value) else {
            return Ok(());
        };
        if operation.opcode() == ECodeOpcode::Undefined
            && let Some(candidate) = candidates.resolve(root)
            && let Some(variable) = self.recovery.variables().variable_for_value(value)
        {
            let output = *self
                .outputs
                .entry(MCodeCallOutputSite::new(
                    candidate.site,
                    candidate.location,
                    root,
                ))
                .or_insert(variable);
            self.representatives.union(output.index(), variable.index());
        } else if operation.opcode() == ECodeOpcode::WriteRegister {
            let _ = candidates.resolve(root);
        }

        Ok(())
    }
}
