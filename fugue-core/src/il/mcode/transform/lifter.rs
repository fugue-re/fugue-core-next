use std::collections::{BTreeMap, BTreeSet};
use std::{iter, mem};

use rustc_hash::{FxHashMap, FxHashSet};

use super::ECodeToMCodeScratch;
use super::variables::{
    MCodeCallOutputSite, MCodeCallOutputVariables, MCodeStackDefs, MCodeVariableWidths,
};
use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlBlock, IlBlockId, IlDominance, IlDominanceEvent, IlError, IlIndexRange,
    IlIndexRangeMap, IlOpId, IlValueId, RegisterId,
};
use crate::il::ecode::{ECodeDomain, ECodeIr, ECodeOp, ECodeOpcode};
use crate::il::mcode::recovery::{
    MCodeCallArg, MCodeCallOutputComponent, MCodeExitRequirement, MCodeRecovery,
};
use crate::il::mcode::{
    MCodeBuilder, MCodeIr, MCodeOpSpec, MCodeOpcode, MCodeStorageLocation, MCodeVar, MCodeVarId,
    MCodeVersion,
};
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Default)]
struct ECodeToMCodeRenameState {
    stack: FxHashMap<MCodeVarId, IlValueId>,
    memory: FxHashMap<AddressSpaceId, IlValueId>,
    unmatched_call_memory: FxHashSet<AddressSpaceId>,
    unmatched_call_outputs: FxHashMap<RegisterId, IlValueId>,
    undo: Vec<ECodeToMCodeRenameChange>,
    tracking: bool,
}

#[derive(Debug, Copy, Clone)]
enum ECodeToMCodeRenameChange {
    Stack(MCodeVarId, Option<IlValueId>),
    Memory(AddressSpaceId, Option<IlValueId>),
    UnmatchedCallMemory(AddressSpaceId, bool),
    UnmatchedCallOutput(RegisterId, Option<IlValueId>),
}

#[derive(Debug, Copy, Clone)]
enum MCodeBlockArgOrigin {
    Source { value: IlValueId, position: usize },
    Stack(MCodeVarId),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum MCodeBlockArgDomain {
    Memory(AddressSpaceId),
    Variable(MCodeVarId),
}

#[derive(Debug, Copy, Clone)]
struct MCodeBlockArgBinding {
    domain: MCodeBlockArgDomain,
    origin: MCodeBlockArgOrigin,
    value: IlValueId,
}

impl MCodeBlockArgBinding {
    const fn new(
        domain: MCodeBlockArgDomain,
        origin: MCodeBlockArgOrigin,
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
struct MCodeBlockArgSpec {
    domain: MCodeBlockArgDomain,
    origin: MCodeBlockArgOrigin,
    width: u32,
}

impl MCodeBlockArgSpec {
    const fn source(
        domain: MCodeBlockArgDomain,
        value: IlValueId,
        position: usize,
        width: u32,
    ) -> Self {
        Self {
            domain,
            origin: MCodeBlockArgOrigin::Source { value, position },
            width,
        }
    }

    const fn stack(variable: MCodeVarId, width: u32) -> Self {
        Self {
            domain: MCodeBlockArgDomain::Variable(variable),
            origin: MCodeBlockArgOrigin::Stack(variable),
            width,
        }
    }
}

#[derive(Default)]
struct MCodeBindings {
    ordered: Vec<(IlValueId, MCodeVarId)>,
    variables: FxHashMap<IlValueId, MCodeVarId>,
    latest: FxHashMap<MCodeVarId, IlValueId>,
}

impl MCodeBindings {
    fn iter(&self) -> impl Iterator<Item = (IlValueId, MCodeVarId)> + '_ {
        self.ordered.iter().copied()
    }

    fn latest(&self, variable: MCodeVarId) -> Option<IlValueId> {
        self.latest.get(&variable).copied()
    }

    fn variable_for(&self, value: IlValueId) -> Option<MCodeVarId> {
        self.variables.get(&value).copied()
    }

    fn insert(&mut self, value: IlValueId, variable: MCodeVarId) -> Result<(), IlError> {
        match self.variables.insert(value, variable) {
            Some(existing) if existing != variable => Err(IlError::missing_component(
                MCodeIr::FORM,
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
}

impl ECodeToMCodeRenameState {
    fn stack_value(&self, variable: MCodeVarId) -> Option<IlValueId> {
        self.stack.get(&variable).copied()
    }

    fn contains_stack(&self, variable: MCodeVarId) -> bool {
        self.stack.contains_key(&variable)
    }

    fn memory_value(&self, space: AddressSpaceId) -> Option<IlValueId> {
        self.memory.get(&space).copied()
    }

    fn contains_unmatched_call_output(&self, root: RegisterId) -> bool {
        self.unmatched_call_outputs.contains_key(&root)
    }

    fn insert_stack(&mut self, variable: MCodeVarId, value: IlValueId) {
        let previous = self.stack.insert(variable, value);
        if self.tracking {
            self.undo
                .push(ECodeToMCodeRenameChange::Stack(variable, previous));
        }
    }

    fn insert_memory(&mut self, space: AddressSpaceId, value: IlValueId) {
        let previous = self.memory.insert(space, value);
        if self.tracking {
            self.undo
                .push(ECodeToMCodeRenameChange::Memory(space, previous));
        }
    }

    fn clear_memory(&mut self) {
        if self.tracking {
            self.undo.extend(
                self.memory
                    .drain()
                    .map(|(space, value)| ECodeToMCodeRenameChange::Memory(space, Some(value))),
            );
        } else {
            self.memory.clear();
        }
    }

    fn remove_unmatched_call_memory(&mut self, space: AddressSpaceId) -> bool {
        let removed = self.unmatched_call_memory.remove(&space);
        if removed && self.tracking {
            self.undo
                .push(ECodeToMCodeRenameChange::UnmatchedCallMemory(space, true));
        }
        removed
    }

    fn insert_unmatched_call_memory(&mut self, space: AddressSpaceId) {
        if self.unmatched_call_memory.insert(space) && self.tracking {
            self.undo
                .push(ECodeToMCodeRenameChange::UnmatchedCallMemory(space, false));
        }
    }

    fn clear_unmatched_call_memory(&mut self) {
        if self.tracking {
            self.undo.extend(
                self.unmatched_call_memory
                    .drain()
                    .map(|space| ECodeToMCodeRenameChange::UnmatchedCallMemory(space, true)),
            );
        } else {
            self.unmatched_call_memory.clear();
        }
    }

    fn remove_unmatched_call_output(&mut self, root: RegisterId) -> Option<IlValueId> {
        let previous = self.unmatched_call_outputs.remove(&root);
        if let Some(value) = previous.filter(|_| self.tracking) {
            self.undo
                .push(ECodeToMCodeRenameChange::UnmatchedCallOutput(
                    root,
                    Some(value),
                ));
        }
        previous
    }

    fn insert_unmatched_call_output(&mut self, root: RegisterId, value: IlValueId) {
        let previous = self.unmatched_call_outputs.insert(root, value);
        if self.tracking {
            self.undo
                .push(ECodeToMCodeRenameChange::UnmatchedCallOutput(
                    root, previous,
                ));
        }
    }

    fn clear_unmatched_call_outputs(&mut self) {
        if self.tracking {
            self.undo
                .extend(self.unmatched_call_outputs.drain().map(|(root, value)| {
                    ECodeToMCodeRenameChange::UnmatchedCallOutput(root, Some(value))
                }));
        } else {
            self.unmatched_call_outputs.clear();
        }
    }

    fn clear_unmatched_call_output(&mut self, domain: Option<ECodeDomain>) {
        if let Some(ECodeDomain::Register(root)) = domain {
            self.remove_unmatched_call_output(root);
        }
    }

    fn checkpoint(&mut self) -> usize {
        self.tracking = true;
        self.undo.len()
    }

    fn rollback(&mut self, checkpoint: usize) {
        while self.undo.len() > checkpoint {
            match self
                .undo
                .pop()
                .expect("a rename checkpoint is within the undo log")
            {
                ECodeToMCodeRenameChange::Stack(variable, previous) => match previous {
                    Some(value) => {
                        self.stack.insert(variable, value);
                    }
                    None => {
                        self.stack.remove(&variable);
                    }
                },
                ECodeToMCodeRenameChange::Memory(space, previous) => match previous {
                    Some(value) => {
                        self.memory.insert(space, value);
                    }
                    None => {
                        self.memory.remove(&space);
                    }
                },
                ECodeToMCodeRenameChange::UnmatchedCallMemory(space, previous) => {
                    if previous {
                        self.unmatched_call_memory.insert(space);
                    } else {
                        self.unmatched_call_memory.remove(&space);
                    }
                }
                ECodeToMCodeRenameChange::UnmatchedCallOutput(root, previous) => match previous {
                    Some(value) => {
                        self.unmatched_call_outputs.insert(root, value);
                    }
                    None => {
                        self.unmatched_call_outputs.remove(&root);
                    }
                },
            }
        }
    }
}

pub(crate) struct ECodeToMCodeLifter<'a, 'b> {
    source: &'a ECodeIr,
    recovery: &'a MCodeRecovery,
    builder: MCodeBuilder,
    scratch: &'b mut ECodeToMCodeScratch,
    target_values: Vec<Option<IlValueId>>,
    target_variables: Vec<MCodeVarId>,
    variable_widths: MCodeVariableWidths,
    bindings: MCodeBindings,
    call_output_variables: MCodeCallOutputVariables,
    block_args: Vec<Vec<MCodeBlockArgBinding>>,
    blocks: Vec<Option<IlBlock>>,
    edge_args: Vec<Vec<IlValueId>>,
    operation_blocks: Vec<Option<IlBlockId>>,
    operation_ranges: IlIndexRangeMap,
}

impl<'a, 'b> ECodeToMCodeLifter<'a, 'b> {
    pub(crate) fn new(
        ir: &'a ECodeIr,
        recovery: &'a MCodeRecovery,
        mut builder: MCodeBuilder,
        scratch: &'b mut ECodeToMCodeScratch,
    ) -> Result<Self, IlError> {
        let call_outputs = MCodeCallOutputVariables::new(ir, recovery)?;
        let mut target_variables = Vec::with_capacity(recovery.variables().variables().len());
        for index in 0..recovery.variables().variables().len() {
            let recovered = MCodeVarId::try_from_index(index)?;
            let representative = call_outputs.representative_for(recovered);
            let variable = recovery.variables().variables()[representative.index()];
            target_variables.push(builder.emitter().intern_variable(variable)?);
        }
        let variable_widths = MCodeVariableWidths::new(ir, recovery, &target_variables)?;

        Ok(Self {
            source: ir,
            recovery,
            builder,
            scratch,
            target_values: vec![None; ir.values().len()],
            target_variables,
            variable_widths,
            bindings: MCodeBindings::default(),
            call_output_variables: call_outputs,
            block_args: vec![Vec::new(); ir.graph().blocks().len()],
            blocks: vec![None; ir.graph().blocks().len()],
            edge_args: vec![Vec::new(); ir.graph().successors().len()],
            operation_blocks: ir.op_blocks(),
            operation_ranges: IlIndexRangeMap::unmapped(ir.ops().len()),
        })
    }

    fn is_switch(&self, site: IlOpId) -> bool {
        self.operation_blocks
            .get(site.index())
            .copied()
            .flatten()
            .and_then(|block| self.source.graph().blocks().get(block.index()))
            .is_some_and(|block| {
                block
                    .successors()
                    .slice(self.source.graph().successor_kinds())
                    .iter()
                    .any(|kinds| kinds.is_computed())
            })
    }

    fn target_variable(&self, variable: MCodeVarId) -> MCodeVarId {
        self.target_variables[variable.index()]
    }

    fn target_value(&self, value: IlValueId) -> Result<IlValueId, IlError> {
        self.target_values
            .get(value.index())
            .copied()
            .flatten()
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "operand"))
    }

    fn target_variable_for_value(&self, value: IlValueId) -> Result<MCodeVarId, IlError> {
        self.recovery
            .variables()
            .variable_for_value(value)
            .map(|variable| self.target_variable(variable))
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "variable binding"))
    }

    pub(crate) fn lift(mut self, cancellation: &CancellationToken) -> Result<MCodeIr, IlError> {
        for domain in self.source.memory_domains() {
            self.builder.emitter().intern_memory_domain(domain.space());
        }
        self.builder.set_aliased_variables(
            self.recovery
                .aliases()
                .iter()
                .map(|variable| self.target_variable(variable))
                .collect(),
        );

        match self.source.graph().entry_block() {
            Some(entry) => self.lift_blocks(entry, cancellation)?,
            None => self.lift_linear(cancellation)?,
        }

        let mut versions = FxHashMap::default();
        for (value, variable) in self.bindings.iter() {
            let version = versions.entry(variable).or_insert(MCodeVersion::new(0));
            *version = version
                .checked_next()
                .ok_or_else(|| IlError::id_exhausted("MCode version"))?;
            self.builder
                .emitter()
                .bind_value(value, variable, *version)?;
        }

        self.builder.build(cancellation)
    }

    fn lift_linear(&mut self, cancellation: &CancellationToken) -> Result<(), IlError> {
        let mut current = ECodeToMCodeRenameState::default();
        for index in 0..self.source.ops().len() {
            cancellation.check()?;
            self.lift_op_at(index, &mut current)?;
        }

        self.finish_graph(self.source.graph().blocks().iter().map(|block| block.ops()))
    }

    fn lift_blocks(
        &mut self,
        entry: IlBlockId,
        cancellation: &CancellationToken,
    ) -> Result<(), IlError> {
        let graph = self.source.graph();
        let dominance = IlDominance::from_blocks(graph.blocks(), graph.successors(), entry);
        self.place_block_args(&dominance)?;
        self.lift_block_tree(
            entry,
            &dominance,
            ECodeToMCodeRenameState::default(),
            cancellation,
        )?;

        for index in 0..graph.blocks().len() {
            if self.blocks[index].is_some() {
                continue;
            }
            let block = IlBlockId::try_from_index(index)?;
            self.lift_block(block, &mut ECodeToMCodeRenameState::default(), cancellation)?;
        }

        for args in mem::take(&mut self.edge_args) {
            self.builder.emitter().emit_edge_args(args)?;
        }
        let blocks = mem::take(&mut self.blocks)
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .expect("every MCode block is constructed before graph replacement");
        self.finish_graph(blocks.into_iter().map(|block| block.ops()))
    }

    fn lift_block_tree(
        &mut self,
        entry: IlBlockId,
        dominance: &IlDominance,
        mut current: ECodeToMCodeRenameState,
        cancellation: &CancellationToken,
    ) -> Result<(), IlError> {
        let mut checkpoints = Vec::new();
        for event in dominance.events_from(entry) {
            match event {
                IlDominanceEvent::Enter(block) => {
                    checkpoints.push(current.checkpoint());
                    self.lift_block(block, &mut current, cancellation)?;
                }
                IlDominanceEvent::Exit(_) => {
                    current.rollback(
                        checkpoints
                            .pop()
                            .expect("each dominance exit follows a matching entry"),
                    );
                }
            }
        }

        Ok(())
    }

    fn lift_block(
        &mut self,
        block: IlBlockId,
        current: &mut ECodeToMCodeRenameState,
        cancellation: &CancellationToken,
    ) -> Result<(), IlError> {
        cancellation.check()?;

        for index in 0..self.block_args[block.index()].len() {
            let arg = self.block_args[block.index()][index];
            match arg.domain {
                MCodeBlockArgDomain::Memory(space) => {
                    current.insert_memory(space, arg.value);
                    current.remove_unmatched_call_memory(space);
                }
                MCodeBlockArgDomain::Variable(variable) => {
                    self.bindings.insert(arg.value, variable)?;
                    if let MCodeBlockArgOrigin::Stack(_) = arg.origin {
                        current.insert_stack(variable, arg.value);
                    }
                }
            }
            if let MCodeBlockArgOrigin::Source { value, .. } = arg.origin
                && let Some(ECodeDomain::Register(root)) = self.source.value_domain(value)
            {
                current.remove_unmatched_call_output(root);
            }
        }

        let source_block = *self.source.graph().blocks().get(block.index()).ok_or(
            IlError::range_out_of_bounds(block.index(), self.source.graph().blocks().len()),
        )?;
        let start = self.builder.emitter().op_count();
        self.allocate_missing_stack_arg_values(source_block, current)?;

        let terminator = (source_block.ops().start()..source_block.ops().end())
            .rev()
            .find(|index| {
                matches!(
                    self.source.ops()[*index].opcode(),
                    ECodeOpcode::Branch
                        | ECodeOpcode::BranchIndirect
                        | ECodeOpcode::ConditionalBranch
                        | ECodeOpcode::Return
                        | ECodeOpcode::Trap
                )
            });
        for index in source_block.ops().start()..source_block.ops().end() {
            if Some(index) == terminator {
                continue;
            }
            cancellation.check()?;
            self.lift_op_at(index, current)?;
        }
        if let Some(index) = terminator {
            cancellation.check()?;
            self.lift_op_at(index, current)?;
        }

        self.lift_edge_args(source_block, current)?;
        let end = self.builder.emitter().op_count();
        self.blocks[block.index()] = Some(IlBlock::new(
            IlIndexRange::new(start, end)?,
            source_block.successors(),
            source_block.properties(),
        ));

        Ok(())
    }

    fn allocate_missing_stack_arg_values(
        &mut self,
        source_block: IlBlock,
        current: &mut ECodeToMCodeRenameState,
    ) -> Result<(), IlError> {
        for successor in source_block
            .successors()
            .slice(self.source.graph().successors())
        {
            for index in 0..self.block_args[successor.index()].len() {
                let arg = self.block_args[successor.index()][index];
                let MCodeBlockArgOrigin::Stack(variable) = arg.origin else {
                    continue;
                };
                if current.contains_stack(variable) {
                    continue;
                }
                let value =
                    self.push_variable_undefined(variable, self.variable_widths.width(variable)?)?;
                current.insert_stack(variable, value);
            }
        }

        Ok(())
    }

    fn lift_edge_args(
        &mut self,
        source_block: IlBlock,
        current: &mut ECodeToMCodeRenameState,
    ) -> Result<(), IlError> {
        for (offset, successor) in source_block
            .successors()
            .slice(self.source.graph().successors())
            .iter()
            .enumerate()
        {
            let edge = source_block.successors().start() + offset;
            let source_args = self.source.args_for_edge(edge);
            let mut args = Vec::with_capacity(self.block_args[successor.index()].len());
            for index in 0..self.block_args[successor.index()].len() {
                let arg = self.block_args[successor.index()][index];
                let value = match arg.origin {
                    MCodeBlockArgOrigin::Source { position, .. } => {
                        let source = source_args.get(position).copied().ok_or_else(|| {
                            IlError::missing_component(MCodeIr::FORM, "edge argument")
                        })?;
                        self.target_value(source)?
                    }
                    MCodeBlockArgOrigin::Stack(variable) => match current.stack_value(variable) {
                        Some(value) => value,
                        None => {
                            let value = self.push_variable_undefined(
                                variable,
                                self.variable_widths.width(variable)?,
                            )?;
                            current.insert_stack(variable, value);
                            value
                        }
                    },
                };
                args.push(value);
            }
            self.edge_args[edge] = args;
        }

        Ok(())
    }

    fn finish_graph(
        &mut self,
        operation_ranges: impl ExactSizeIterator<Item = IlIndexRange>,
    ) -> Result<(), IlError> {
        let source = self.source.graph();
        let graph = source.clone().with_op_ranges(operation_ranges)?;
        let source_spans = self
            .operation_ranges
            .remap_source_spans(self.source.source_spans())?;
        let parent_spans = self.operation_ranges.parent_spans()?;
        self.builder.set_graph(graph);
        self.builder.set_source_spans(source_spans);
        self.builder.set_parent_spans(parent_spans);

        Ok(())
    }

    fn lift_op_at(
        &mut self,
        index: usize,
        current: &mut ECodeToMCodeRenameState,
    ) -> Result<(), IlError> {
        let start = self.builder.emitter().op_count();
        let site = IlOpId::try_from_index(index)?;
        let operation = self.source.ops()[index];

        for &requirement in self.recovery.abi().exit_requirements(site) {
            let value = match requirement {
                MCodeExitRequirement::Register(source) => self.target_value(source)?,
                MCodeExitRequirement::Stack(access) => {
                    let recovered = self
                        .recovery
                        .variables()
                        .stack_variable(access.object())
                        .ok_or_else(|| {
                            IlError::missing_component(MCodeIr::FORM, "stack variable")
                        })?;
                    let variable = self.target_variable(recovered);
                    match current.stack_value(variable) {
                        Some(value) => value,
                        None => {
                            let width = self.variable_widths.width(variable)?;
                            let value = self.push_variable_undefined(variable, width)?;
                            current.insert_stack(variable, value);
                            value
                        }
                    }
                }
            };
            self.scratch.required_values.push(value);
        }

        match operation.opcode() {
            ECodeOpcode::Call | ECodeOpcode::CallIndirect => {
                self.lift_call(site, operation, current)?;
            }
            ECodeOpcode::Branch | ECodeOpcode::BranchIndirect
                if self
                    .recovery
                    .abi()
                    .call(site)
                    .is_some_and(|call| call.is_tail_call()) =>
            {
                self.lift_tail_call(site, operation, current)?;
            }
            ECodeOpcode::Load if self.recovery.stack().access_for(site).is_some() => {
                self.lift_stack_load(site, operation, current)?;
            }
            ECodeOpcode::Store if self.recovery.stack().access_for(site).is_some() => {
                self.lift_stack_store(site, operation, current)?;
            }
            ECodeOpcode::Return => {
                self.lift_carried(site, operation, current)?;
            }
            ECodeOpcode::Undefined => self.lift_undefined(site, operation, current)?,
            ECodeOpcode::WriteFlag | ECodeOpcode::WriteRegister => {
                self.lift_variable_write(operation, current)?;
            }
            _ => self.lift_carried(site, operation, current)?,
        }

        let end = self.builder.emitter().op_count();
        self.operation_ranges
            .set_range(index, IlIndexRange::new(start, end)?)?;

        Ok(())
    }

    fn push_variable_undefined(
        &mut self,
        variable: MCodeVarId,
        width: u32,
    ) -> Result<IlValueId, IlError> {
        let (_, results) = self.builder.emitter().emit(
            MCodeOpSpec::new(MCodeOpcode::Undefined, width),
            [],
            [width],
        )?;
        let value = IlValueId::try_from_index(results.start())?;
        self.bindings.insert(value, variable)?;

        Ok(value)
    }

    fn push_memory_undefined(&mut self, space: AddressSpaceId) -> Result<IlValueId, IlError> {
        self.builder.emitter().intern_memory_domain(space);
        let immediate = u64::from(space.value());
        let (_, results) = self.builder.emitter().emit(
            MCodeOpSpec::new(MCodeOpcode::Undefined, 0).with_immediate(immediate),
            [],
            [0],
        )?;

        IlValueId::try_from_index(results.start())
    }

    fn lift_undefined(
        &mut self,
        site: IlOpId,
        operation: ECodeOp,
        current: &mut ECodeToMCodeRenameState,
    ) -> Result<(), IlError> {
        let source = operation
            .single_result()
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "single operation result"))?;
        let domain = self.source.value_domain(source);
        match domain {
            Some(ECodeDomain::Memory(space)) if current.remove_unmatched_call_memory(space) => {
                let value = current
                    .memory_value(space)
                    .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "post-call memory"))?;
                self.target_values[source.index()] = Some(value);
            }
            Some(ECodeDomain::Register(root)) if current.contains_unmatched_call_output(root) => {
                let value = current
                    .remove_unmatched_call_output(root)
                    .expect("the unmatched call output was checked before removal");
                let variable = self.target_variable_for_value(source)?;
                self.bindings.insert(value, variable)?;
                self.target_values[source.index()] = Some(value);
            }
            domain => {
                self.lift_carried(site, operation, current)?;
                let value = self.target_value(source)?;
                match domain {
                    Some(ECodeDomain::Memory(space)) => {
                        current.insert_memory(space, value);
                        current.remove_unmatched_call_memory(space);
                    }
                    Some(domain) if domain.is_register_or_flag() => {
                        let variable = self.target_variable_for_value(source)?;
                        self.bindings.insert(value, variable)?;
                        current.clear_unmatched_call_output(Some(domain));
                    }
                    Some(_) | None => {}
                }
            }
        }
        Ok(())
    }

    fn lift_variable_write(
        &mut self,
        operation: ECodeOp,
        current: &mut ECodeToMCodeRenameState,
    ) -> Result<(), IlError> {
        let result = operation
            .single_result()
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "single operation result"))?;
        let variable = self.target_variable_for_value(result)?;
        let source_operand = self
            .source
            .op_operands_for(&operation)
            .first()
            .copied()
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "variable value"))?;

        let (_, results) = match self
            .source
            .defining_op(source_operand)
            .filter(|insert| insert.opcode() == ECodeOpcode::Insert)
        {
            Some(insert) => {
                let insert_operands = self.source.op_operands_for(insert);
                let previous_source = insert_operands
                    .first()
                    .copied()
                    .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "partial variable"))?;
                let inserted_source = insert_operands.get(1).copied().ok_or_else(|| {
                    IlError::missing_component(MCodeIr::FORM, "partial variable value")
                })?;
                let previous = self.target_value(previous_source)?;
                if self.bindings.variable_for(previous) != Some(variable)
                    || self.bindings.latest(variable) != Some(previous)
                {
                    let value = self.target_value(source_operand)?;
                    self.builder.emitter().emit(
                        MCodeOpSpec::new(MCodeOpcode::SetVar, operation.width())
                            .with_variable(variable),
                        [value],
                        [operation.width()],
                    )?
                } else {
                    let inserted = self.target_value(inserted_source)?;
                    let width = self.source.value_width(inserted_source).ok_or_else(|| {
                        IlError::missing_component(MCodeIr::FORM, "partial variable width")
                    })?;
                    self.builder.emitter().emit(
                        MCodeOpSpec::new(MCodeOpcode::SetVarField, width)
                            .with_variable(variable)
                            .with_immediate(insert.immediate()),
                        [previous, inserted],
                        [operation.width()],
                    )?
                }
            }
            None => {
                let value = self.target_value(source_operand)?;
                self.builder.emitter().emit(
                    MCodeOpSpec::new(MCodeOpcode::SetVar, operation.width())
                        .with_variable(variable),
                    [value],
                    [operation.width()],
                )?
            }
        };
        let value = IlValueId::try_from_index(results.start())?;
        self.bindings.insert(value, variable)?;
        self.target_values[result.index()] = Some(value);
        let domain = self.source.value_domain(result);
        current.clear_unmatched_call_output(domain);

        Ok(())
    }

    fn lift_stack_load(
        &mut self,
        site: IlOpId,
        operation: ECodeOp,
        current: &mut ECodeToMCodeRenameState,
    ) -> Result<(), IlError> {
        let access = self
            .recovery
            .stack()
            .access_for(site)
            .expect("fixed stack access was checked before translation");
        let recovered = self
            .recovery
            .variables()
            .stack_variable(access.object())
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "stack variable"))?;
        let variable = self.target_variable(recovered);
        let result = operation
            .single_result()
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "single operation result"))?;
        let full_width = self.variable_widths.width(variable)?;

        if self.recovery.aliases().contains(recovered) {
            if !current.contains_stack(variable) {
                let value = self.push_variable_undefined(variable, full_width)?;
                current.insert_stack(variable, value);
            }
            let memory = self.mapped_memory_operand(operation)?;
            let field = access.field_offset() != 0 || operation.width() != full_width;
            let opcode = if field {
                MCodeOpcode::VarAliasedField
            } else {
                MCodeOpcode::VarAliased
            };
            let space = operation
                .address_space()
                .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "address space"))?;
            let spec = MCodeOpSpec::new(opcode, operation.width())
                .with_variable(variable)
                .with_immediate(access.field_offset())
                .with_address_space(space);
            let (_, results) = self
                .builder
                .emitter()
                .emit(spec, [memory], [operation.width()])?;
            self.target_values[result.index()] = Some(IlValueId::try_from_index(results.start())?);
            return Ok(());
        }

        let previous = match current.stack_value(variable) {
            Some(value) => value,
            None => {
                let value = self.push_variable_undefined(variable, full_width)?;
                current.insert_stack(variable, value);
                value
            }
        };
        if access.field_offset() == 0 && operation.width() == full_width {
            self.target_values[result.index()] = Some(previous);
            return Ok(());
        }

        let (_, results) = self.builder.emitter().emit(
            MCodeOpSpec::new(MCodeOpcode::Extract, operation.width())
                .with_immediate(access.field_offset()),
            [previous],
            [operation.width()],
        )?;
        self.target_values[result.index()] = Some(IlValueId::try_from_index(results.start())?);

        Ok(())
    }

    fn lift_stack_store(
        &mut self,
        site: IlOpId,
        operation: ECodeOp,
        current: &mut ECodeToMCodeRenameState,
    ) -> Result<(), IlError> {
        let access = self
            .recovery
            .stack()
            .access_for(site)
            .expect("fixed stack access was checked before translation");
        let recovered = self
            .recovery
            .variables()
            .stack_variable(access.object())
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "stack variable"))?;
        let variable = self.target_variable(recovered);
        let full_width = self.variable_widths.width(variable)?;
        let source_operands = self.source.op_operands_for(&operation);
        let source_value = source_operands
            .get(1)
            .copied()
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "stored stack value"))?;
        let value = self.target_value(source_value)?;
        let width = self
            .source
            .value_width(source_value)
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "stored stack width"))?;
        let memory = self.mapped_memory_operand(operation)?;
        let source_result = operation
            .single_result()
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "single operation result"))?;
        let space = operation
            .address_space()
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "address space"))?;
        let field = access.field_offset() != 0 || width != full_width;

        if self.recovery.aliases().contains(recovered) {
            let opcode = if field {
                MCodeOpcode::SetVarAliasedField
            } else {
                MCodeOpcode::SetVarAliased
            };
            let spec = MCodeOpSpec::new(opcode, width)
                .with_variable(variable)
                .with_immediate(access.field_offset())
                .with_address_space(space);
            let (_, results) =
                self.builder
                    .emitter()
                    .emit(spec, [value, memory], [0, full_width])?;
            let memory_result = IlValueId::try_from_index(results.start())?;
            let variable_result = IlValueId::try_from_index(results.start() + 1)?;
            self.target_values[source_result.index()] = Some(memory_result);
            self.bindings.insert(variable_result, variable)?;
            current.insert_memory(space, memory_result);
            current.remove_unmatched_call_memory(space);
            current.insert_stack(variable, variable_result);
            return Ok(());
        }

        let (_, results) = if field {
            let previous = match current.stack_value(variable) {
                Some(value) => value,
                None => {
                    let value = self.push_variable_undefined(variable, full_width)?;
                    current.insert_stack(variable, value);
                    value
                }
            };
            if self.bindings.latest(variable) == Some(previous) {
                self.builder.emitter().emit(
                    MCodeOpSpec::new(MCodeOpcode::SetVarField, width)
                        .with_variable(variable)
                        .with_immediate(access.field_offset()),
                    [previous, value],
                    [full_width],
                )?
            } else {
                let (_, results) = self.builder.emitter().emit(
                    MCodeOpSpec::new(MCodeOpcode::Insert, full_width)
                        .with_immediate(access.field_offset()),
                    [previous, value],
                    [full_width],
                )?;
                let inserted = IlValueId::try_from_index(results.start())?;
                self.builder.emitter().emit(
                    MCodeOpSpec::new(MCodeOpcode::SetVar, full_width).with_variable(variable),
                    [inserted],
                    [full_width],
                )?
            }
        } else {
            self.builder.emitter().emit(
                MCodeOpSpec::new(MCodeOpcode::SetVar, full_width).with_variable(variable),
                [value],
                [full_width],
            )?
        };
        let variable_result = IlValueId::try_from_index(results.start())?;
        self.bindings.insert(variable_result, variable)?;
        self.target_values[source_result.index()] = Some(memory);
        current.insert_memory(space, memory);
        current.remove_unmatched_call_memory(space);
        current.insert_stack(variable, variable_result);

        Ok(())
    }

    fn materialise_call_output_component(
        &mut self,
        site: IlOpId,
        location: MCodeStorageLocation,
        component: MCodeCallOutputComponent,
        value: IlValueId,
        space: AddressSpaceId,
        current: &mut ECodeToMCodeRenameState,
    ) -> Result<(), IlError> {
        if let MCodeCallOutputComponent::Register { register, .. } = component {
            let variable = self.intern_call_output_variable(site, location, register)?;
            current.insert_unmatched_call_output(register, value);
            self.bindings.insert(value, variable)?;
            return Ok(());
        }

        let MCodeCallOutputComponent::Stack {
            access,
            object_width,
            width,
        } = component
        else {
            unreachable!();
        };
        let recovered = self
            .recovery
            .variables()
            .stack_variable(access.object())
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "stack variable"))?;
        let variable = self.target_variable(recovered);
        if self.variable_widths.width(variable)? != object_width {
            return Err(IlError::width_mismatch(MCodeIr::FORM));
        }

        let field = access.field_offset() != 0 || width != object_width;
        if self.recovery.aliases().contains(recovered) {
            let opcode = if field {
                MCodeOpcode::SetVarAliasedField
            } else {
                MCodeOpcode::SetVarAliased
            };
            let memory = current
                .memory_value(space)
                .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "post-call memory"))?;
            let spec = MCodeOpSpec::new(opcode, width)
                .with_variable(variable)
                .with_immediate(access.field_offset())
                .with_address_space(space);
            let (_, materialised) =
                self.builder
                    .emitter()
                    .emit(spec, [value, memory], [0, object_width])?;
            let memory = IlValueId::try_from_index(materialised.start())?;
            let full_value = IlValueId::try_from_index(materialised.start() + 1)?;
            self.bindings.insert(full_value, variable)?;
            self.scratch.required_values.push(full_value);
            current.insert_memory(space, memory);
            current.insert_stack(variable, full_value);
            return Ok(());
        }

        if !field {
            self.bindings.insert(value, variable)?;
            current.insert_stack(variable, value);
            return Ok(());
        }

        let previous = match current.stack_value(variable) {
            Some(value) => value,
            None => {
                let value = self.push_variable_undefined(variable, object_width)?;
                current.insert_stack(variable, value);
                value
            }
        };
        let (_, materialised) = if self.bindings.latest(variable) == Some(previous) {
            self.builder.emitter().emit(
                MCodeOpSpec::new(MCodeOpcode::SetVarField, width)
                    .with_variable(variable)
                    .with_immediate(access.field_offset()),
                [previous, value],
                [object_width],
            )?
        } else {
            let (_, inserted) = self.builder.emitter().emit(
                MCodeOpSpec::new(MCodeOpcode::Insert, object_width)
                    .with_immediate(access.field_offset()),
                [previous, value],
                [object_width],
            )?;
            let inserted = IlValueId::try_from_index(inserted.start())?;
            self.builder.emitter().emit(
                MCodeOpSpec::new(MCodeOpcode::SetVar, object_width).with_variable(variable),
                [inserted],
                [object_width],
            )?
        };
        let full_value = IlValueId::try_from_index(materialised.start())?;
        self.bindings.insert(full_value, variable)?;
        self.scratch.required_values.push(full_value);
        current.insert_stack(variable, full_value);

        Ok(())
    }

    fn lift_call(
        &mut self,
        site: IlOpId,
        operation: ECodeOp,
        current: &mut ECodeToMCodeRenameState,
    ) -> Result<(), IlError> {
        let space = match operation.opcode() {
            ECodeOpcode::Call => operation
                .address()
                .map(|address| address.space())
                .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "call target"))?,
            ECodeOpcode::CallIndirect => operation
                .address_space()
                .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "address space"))?,
            _ => unreachable!(),
        };
        self.builder.emitter().intern_memory_domain(space);
        let memory = match current.memory_value(space) {
            Some(value) => value,
            None => {
                let value = self.push_memory_undefined(space)?;
                current.insert_memory(space, value);
                value
            }
        };
        let mut operands = mem::take(&mut self.scratch.operands);
        operands.clear();
        if operation.opcode() == ECodeOpcode::CallIndirect {
            let destination = self
                .source
                .op_operands_for(&operation)
                .first()
                .copied()
                .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "call target"))?;
            operands.push(self.target_value(destination)?);
        }
        let arg_count = self
            .recovery
            .abi()
            .call(site)
            .map_or(0, |call| call.args().len());
        for index in 0..arg_count {
            let arg = self
                .recovery
                .abi()
                .call(site)
                .and_then(|call| call.args().get(index))
                .copied()
                .expect("the recovered call argument count is stable");
            operands.push(match arg {
                MCodeCallArg::Value(value) => self.target_value(value)?,
                MCodeCallArg::Pair { high, low } => self.push_split(high, low)?,
                MCodeCallArg::Stack { offset, width } => {
                    self.stack_arg_value(offset, width, space, memory, current)?
                }
            });
        }
        operands.push(memory);

        let widths = iter::once(0).chain(
            self.recovery
                .abi()
                .call(site)
                .into_iter()
                .flat_map(|call| call.outputs())
                .flat_map(|output| output.components())
                .map(MCodeCallOutputComponent::width),
        );
        let opcode = match operation.opcode() {
            ECodeOpcode::Call => MCodeOpcode::Call,
            ECodeOpcode::CallIndirect => MCodeOpcode::CallIndirect,
            _ => unreachable!(),
        };
        let mut spec = MCodeOpSpec::new(opcode, 0).with_address_space(space);
        if let Some(address) = operation.address() {
            spec = spec.with_address(address);
        }
        let results = self
            .builder
            .emitter()
            .emit(spec, operands.iter().copied(), widths);
        operands.clear();
        self.scratch.operands = operands;
        let (_, results) = results?;
        let memory_result = IlValueId::try_from_index(results.start())?;
        current.clear_memory();
        current.clear_unmatched_call_memory();
        current.insert_memory(space, memory_result);
        current.insert_unmatched_call_memory(space);
        current.clear_unmatched_call_outputs();

        let mut result_index = results.start() + 1;
        let output_count = self
            .recovery
            .abi()
            .call(site)
            .map_or(0, |call| call.outputs().len());
        for output_index in 0..output_count {
            let (location, component_count) = self
                .recovery
                .abi()
                .call(site)
                .and_then(|call| call.outputs().get(output_index))
                .map(|output| (output.location(), output.components().len()))
                .expect("the recovered call output count is stable");
            for component_index in 0..component_count {
                let component = self
                    .recovery
                    .abi()
                    .call(site)
                    .and_then(|call| call.outputs().get(output_index))
                    .and_then(|output| output.components().get(component_index))
                    .copied()
                    .expect("the recovered call output component count is stable");
                let value = IlValueId::try_from_index(result_index)?;
                self.materialise_call_output_component(
                    site, location, component, value, space, current,
                )?;
                result_index += 1;
            }
        }

        Ok(())
    }

    fn lift_tail_call(
        &mut self,
        site: IlOpId,
        operation: ECodeOp,
        current: &mut ECodeToMCodeRenameState,
    ) -> Result<(), IlError> {
        let space = match operation.opcode() {
            ECodeOpcode::Branch => operation
                .address()
                .map(|address| address.space())
                .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "tail-call target"))?,
            ECodeOpcode::BranchIndirect => operation
                .address_space()
                .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "address space"))?,
            _ => unreachable!(),
        };
        self.builder.emitter().intern_memory_domain(space);
        let memory = match current.memory_value(space) {
            Some(value) => value,
            None => {
                let value = self.push_memory_undefined(space)?;
                current.insert_memory(space, value);
                value
            }
        };
        let mut operands = mem::take(&mut self.scratch.operands);
        operands.clear();
        if operation.opcode() == ECodeOpcode::BranchIndirect {
            let destination = self
                .source
                .op_operands_for(&operation)
                .first()
                .copied()
                .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "tail-call target"))?;
            operands.push(self.target_value(destination)?);
        }
        let arg_count = self
            .recovery
            .abi()
            .call(site)
            .map_or(0, |call| call.args().len());
        for index in 0..arg_count {
            let arg = self
                .recovery
                .abi()
                .call(site)
                .and_then(|call| call.args().get(index))
                .copied()
                .expect("the recovered tail-call argument count is stable");
            operands.push(match arg {
                MCodeCallArg::Value(value) => self.target_value(value)?,
                MCodeCallArg::Pair { high, low } => self.push_split(high, low)?,
                MCodeCallArg::Stack { offset, width } => {
                    self.stack_arg_value(offset, width, space, memory, current)?
                }
            });
        }
        operands.push(memory);

        let opcode = match operation.opcode() {
            ECodeOpcode::Branch => MCodeOpcode::TailCall,
            ECodeOpcode::BranchIndirect => MCodeOpcode::TailCallIndirect,
            _ => unreachable!(),
        };
        let mut spec = MCodeOpSpec::new(opcode, 0).with_address_space(space);
        if let Some(address) = operation.address() {
            spec = spec.with_address(address);
        }
        let results = self
            .builder
            .emitter()
            .emit(spec, operands.iter().copied(), []);
        operands.clear();
        self.scratch.operands = operands;
        results?;

        Ok(())
    }

    fn push_split(&mut self, high: IlValueId, low: IlValueId) -> Result<IlValueId, IlError> {
        let high_value = self.target_value(high)?;
        let low_value = self.target_value(low)?;
        let width = self
            .source
            .value_width(high)
            .and_then(|high| {
                self.source
                    .value_width(low)
                    .and_then(|low| high.checked_add(low))
            })
            .ok_or_else(|| IlError::integer_overflow("split variable width"))?;
        let (_, results) = self.builder.emitter().emit(
            MCodeOpSpec::new(MCodeOpcode::VarSplit, width),
            [high_value, low_value],
            [width],
        )?;

        IlValueId::try_from_index(results.start())
    }

    fn stack_arg_value(
        &mut self,
        offset: i64,
        width: u32,
        space: AddressSpaceId,
        memory: IlValueId,
        current: &mut ECodeToMCodeRenameState,
    ) -> Result<IlValueId, IlError> {
        let access = self
            .recovery
            .stack()
            .storage_access(offset, width)
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "stack call input"))?;
        let recovered = self
            .recovery
            .variables()
            .stack_variable(access.object())
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "stack variable"))?;
        let variable = self.target_variable(recovered);
        let full_width = self.variable_widths.width(variable)?;

        if self.recovery.aliases().contains(recovered) {
            if !current.contains_stack(variable) {
                let value = self.push_variable_undefined(variable, full_width)?;
                current.insert_stack(variable, value);
            }
            let opcode = if access.field_offset() != 0 || width != full_width {
                MCodeOpcode::VarAliasedField
            } else {
                MCodeOpcode::VarAliased
            };
            let (_, results) = self.builder.emitter().emit(
                MCodeOpSpec::new(opcode, width)
                    .with_variable(variable)
                    .with_immediate(access.field_offset())
                    .with_address_space(space),
                [memory],
                [width],
            )?;
            return IlValueId::try_from_index(results.start());
        }

        let value = match current.stack_value(variable) {
            Some(value) => value,
            None => {
                let value = self.push_variable_undefined(variable, full_width)?;
                current.insert_stack(variable, value);
                value
            }
        };
        if access.field_offset() == 0 && width == full_width {
            return Ok(value);
        }
        let (_, results) = self.builder.emitter().emit(
            MCodeOpSpec::new(MCodeOpcode::Extract, width).with_immediate(access.field_offset()),
            [value],
            [width],
        )?;
        IlValueId::try_from_index(results.start())
    }

    fn intern_call_output_variable(
        &mut self,
        site: IlOpId,
        location: MCodeStorageLocation,
        root: RegisterId,
    ) -> Result<MCodeVarId, IlError> {
        if let Some(variable) = self
            .call_output_variables
            .representative_for_output(MCodeCallOutputSite::new(site, location, root))
        {
            return Ok(self.target_variable(variable));
        }

        let next = self
            .recovery
            .variables()
            .variables()
            .iter()
            .filter(|variable| variable.register_id() == Some(root))
            .map(MCodeVar::index)
            .max()
            .map_or(0, |index| index.saturating_add(1));
        self.builder
            .emitter()
            .intern_variable(MCodeVar::register(root, next))
    }

    fn lift_carried(
        &mut self,
        site: IlOpId,
        operation: ECodeOp,
        current: &mut ECodeToMCodeRenameState,
    ) -> Result<(), IlError> {
        if operation.results().len() == 1 {
            let source = operation.single_result().ok_or_else(|| {
                IlError::missing_component(MCodeIr::FORM, "single operation result")
            })?;
            if self.source.value_domain(source).is_none()
                && let Some(access) = self.recovery.stack().address_for(source)
            {
                self.recovery.stack().offset_of(source).ok_or_else(|| {
                    IlError::missing_component(MCodeIr::FORM, "stack-derived address")
                })?;
                let recovered = self
                    .recovery
                    .variables()
                    .stack_variable(access.object())
                    .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "stack variable"))?;
                if self.recovery.aliases().contains(recovered) {
                    let variable = self.target_variable(recovered);
                    if !current.contains_stack(variable) {
                        let value = self.push_variable_undefined(
                            variable,
                            self.variable_widths.width(variable)?,
                        )?;
                        current.insert_stack(variable, value);
                    }
                    let field = access.field_offset() != 0;
                    let opcode = if field {
                        MCodeOpcode::AddressOfField
                    } else {
                        MCodeOpcode::AddressOf
                    };
                    let spec = MCodeOpSpec::new(opcode, operation.width())
                        .with_variable(variable)
                        .with_immediate(access.field_offset());
                    let (_, results) =
                        self.builder.emitter().emit(spec, [], [operation.width()])?;
                    self.target_values[source.index()] =
                        Some(IlValueId::try_from_index(results.start())?);
                    return Ok(());
                }
            }
        }

        self.scratch.operands.clear();
        for operand in self.source.op_operands_for(&operation) {
            self.scratch.operands.push(self.target_value(*operand)?);
        }
        let opcode = self.lift_opcode(site, operation.opcode())?;
        let immediate = if operation.opcode() == ECodeOpcode::Constant && operation.width() > 64 {
            let value = operation
                .constant(self.source.constant_storage())
                .ok_or_else(|| IlError::missing_component(ECodeIr::FORM, "constant"))?;
            self.builder.emitter().intern_constant(&value)
        } else {
            operation.immediate()
        };
        let mut spec = MCodeOpSpec::new(opcode, operation.width()).with_immediate(immediate);
        if let Some(address) = operation.address() {
            spec = spec.with_address(address);
        }
        if let Some(space) = operation.address_space() {
            spec = spec.with_address_space(space);
            if opcode.requires_memory_domain() {
                self.builder.emitter().intern_memory_domain(space);
            }
        }
        let mut operands = mem::take(&mut self.scratch.operands);
        let result_widths = operation
            .results()
            .slice(self.source.values())
            .iter()
            .map(|value| value.width());
        let results = self
            .builder
            .emitter()
            .emit(spec, operands.iter().copied(), result_widths);
        operands.clear();
        self.scratch.operands = operands;
        let (_, results) = results?;
        for (offset, source_index) in
            (operation.results().start()..operation.results().end()).enumerate()
        {
            let source = IlValueId::try_from_index(source_index)?;
            let value = IlValueId::try_from_index(results.start() + offset)?;
            self.target_values[source.index()] = Some(value);
            if let Some(ECodeDomain::Memory(space)) = self.source.value_domain(source) {
                current.insert_memory(space, value);
                current.remove_unmatched_call_memory(space);
            }
        }

        Ok(())
    }

    fn lift_opcode(&self, site: IlOpId, opcode: ECodeOpcode) -> Result<MCodeOpcode, IlError> {
        let opcode = match opcode {
            ECodeOpcode::Constant => MCodeOpcode::Constant,
            ECodeOpcode::Address => MCodeOpcode::Address,
            ECodeOpcode::Undefined => MCodeOpcode::Undefined,
            ECodeOpcode::Load => MCodeOpcode::Load,
            ECodeOpcode::Copy => MCodeOpcode::Copy,
            ECodeOpcode::Add => MCodeOpcode::Add,
            ECodeOpcode::Sub => MCodeOpcode::Sub,
            ECodeOpcode::Mul => MCodeOpcode::Mul,
            ECodeOpcode::UnsignedDiv => MCodeOpcode::UnsignedDiv,
            ECodeOpcode::SignedDiv => MCodeOpcode::SignedDiv,
            ECodeOpcode::UnsignedRem => MCodeOpcode::UnsignedRem,
            ECodeOpcode::SignedRem => MCodeOpcode::SignedRem,
            ECodeOpcode::Negate => MCodeOpcode::Negate,
            ECodeOpcode::LeftShift => MCodeOpcode::LeftShift,
            ECodeOpcode::LogicalRightShift => MCodeOpcode::LogicalRightShift,
            ECodeOpcode::ArithmeticRightShift => MCodeOpcode::ArithmeticRightShift,
            ECodeOpcode::And => MCodeOpcode::And,
            ECodeOpcode::Or => MCodeOpcode::Or,
            ECodeOpcode::Xor => MCodeOpcode::Xor,
            ECodeOpcode::Not => MCodeOpcode::Not,
            ECodeOpcode::BoolAnd => MCodeOpcode::BoolAnd,
            ECodeOpcode::BoolOr => MCodeOpcode::BoolOr,
            ECodeOpcode::BoolXor => MCodeOpcode::BoolXor,
            ECodeOpcode::BoolNot => MCodeOpcode::BoolNot,
            ECodeOpcode::IntEqual => MCodeOpcode::IntEqual,
            ECodeOpcode::IntNotEqual => MCodeOpcode::IntNotEqual,
            ECodeOpcode::IntLess => MCodeOpcode::IntLess,
            ECodeOpcode::IntSignedLess => MCodeOpcode::IntSignedLess,
            ECodeOpcode::IntLessEqual => MCodeOpcode::IntLessEqual,
            ECodeOpcode::IntSignedLessEqual => MCodeOpcode::IntSignedLessEqual,
            ECodeOpcode::Carry => MCodeOpcode::Carry,
            ECodeOpcode::SignedCarry => MCodeOpcode::SignedCarry,
            ECodeOpcode::SignedBorrow => MCodeOpcode::SignedBorrow,
            ECodeOpcode::CountOnes => MCodeOpcode::CountOnes,
            ECodeOpcode::CountLeadingZeros => MCodeOpcode::CountLeadingZeros,
            ECodeOpcode::ZeroExtend => MCodeOpcode::ZeroExtend,
            ECodeOpcode::SignExtend => MCodeOpcode::SignExtend,
            ECodeOpcode::Truncate => MCodeOpcode::Truncate,
            ECodeOpcode::Extract => MCodeOpcode::Extract,
            ECodeOpcode::Insert => MCodeOpcode::Insert,
            ECodeOpcode::FloatAdd => MCodeOpcode::FloatAdd,
            ECodeOpcode::FloatSub => MCodeOpcode::FloatSub,
            ECodeOpcode::FloatMul => MCodeOpcode::FloatMul,
            ECodeOpcode::FloatDiv => MCodeOpcode::FloatDiv,
            ECodeOpcode::FloatNegate => MCodeOpcode::FloatNegate,
            ECodeOpcode::FloatAbs => MCodeOpcode::FloatAbs,
            ECodeOpcode::FloatSqrt => MCodeOpcode::FloatSqrt,
            ECodeOpcode::FloatCeiling => MCodeOpcode::FloatCeiling,
            ECodeOpcode::FloatFloor => MCodeOpcode::FloatFloor,
            ECodeOpcode::FloatRound => MCodeOpcode::FloatRound,
            ECodeOpcode::FloatIsNan => MCodeOpcode::FloatIsNan,
            ECodeOpcode::FloatEqual => MCodeOpcode::FloatEqual,
            ECodeOpcode::FloatNotEqual => MCodeOpcode::FloatNotEqual,
            ECodeOpcode::FloatLess => MCodeOpcode::FloatLess,
            ECodeOpcode::FloatLessEqual => MCodeOpcode::FloatLessEqual,
            ECodeOpcode::FloatToInt => MCodeOpcode::FloatToInt,
            ECodeOpcode::FloatToFloat => MCodeOpcode::FloatToFloat,
            ECodeOpcode::IntToFloat => MCodeOpcode::IntToFloat,
            ECodeOpcode::IntrinsicResult => MCodeOpcode::IntrinsicResult,
            ECodeOpcode::Intrinsic => MCodeOpcode::Intrinsic,
            ECodeOpcode::Store => MCodeOpcode::Store,
            ECodeOpcode::Branch => MCodeOpcode::Branch,
            ECodeOpcode::ConditionalBranch => MCodeOpcode::ConditionalBranch,
            ECodeOpcode::BranchIndirect if self.is_switch(site) => MCodeOpcode::Switch,
            ECodeOpcode::BranchIndirect => MCodeOpcode::BranchIndirect,
            ECodeOpcode::Return => MCodeOpcode::Return,
            ECodeOpcode::Trap => MCodeOpcode::Trap,
            ECodeOpcode::Call
            | ECodeOpcode::CallIndirect
            | ECodeOpcode::WriteRegister
            | ECodeOpcode::WriteFlag => {
                return Err(IlError::unsupported_opcode(MCodeIr::FORM));
            }
        };
        Ok(opcode)
    }

    fn mapped_memory_operand(&self, operation: ECodeOp) -> Result<IlValueId, IlError> {
        self.source
            .memory_operand(&operation)
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "memory operand"))
            .and_then(|value| self.target_value(value))
    }

    fn place_block_args(&mut self, dominance: &IlDominance) -> Result<(), IlError> {
        let graph = self.source.graph();
        let frontiers = dominance.frontiers(graph.blocks(), graph.successors());
        let mut stack_phis = BTreeSet::new();

        let stack_definitions = MCodeStackDefs::new(
            self.source,
            self.recovery,
            &self.target_variables,
            &self.operation_blocks,
        )?;
        for (variable, definitions) in stack_definitions.into_entries() {
            let placement = frontiers.place_phis(graph.blocks().len(), definitions)?;
            for &block in placement.blocks() {
                stack_phis.insert((block, variable));
            }
        }

        let mut source_positions = vec![0usize; graph.blocks().len()];
        let mut args = BTreeMap::<IlBlockId, Vec<MCodeBlockArgSpec>>::new();
        for arg in self.source.block_args() {
            let position = source_positions[arg.block().index()];
            source_positions[arg.block().index()] += 1;
            let domain = match self.source.value_domain(arg.value()) {
                Some(ECodeDomain::Memory(space)) => MCodeBlockArgDomain::Memory(space),
                Some(domain) if domain.is_register_or_flag() => {
                    MCodeBlockArgDomain::Variable(self.target_variable_for_value(arg.value())?)
                }
                Some(_) | None => {
                    return Err(IlError::missing_component(
                        MCodeIr::FORM,
                        "block argument domain",
                    ));
                }
            };
            args.entry(arg.block())
                .or_default()
                .push(MCodeBlockArgSpec::source(
                    domain,
                    arg.value(),
                    position,
                    arg.width(),
                ));
        }

        for (block, variable) in stack_phis {
            args.entry(block)
                .or_default()
                .push(MCodeBlockArgSpec::stack(
                    variable,
                    self.variable_widths.width(variable)?,
                ));
        }

        for (block, definitions) in args {
            let block_args = &mut self.block_args[block.index()];
            let mut definitions = definitions;
            definitions.sort_unstable_by_key(|definition| definition.domain);
            for definition in definitions {
                let value = self
                    .builder
                    .emitter()
                    .emit_block_arg(block, definition.width)?;
                if let MCodeBlockArgOrigin::Source { value: source, .. } = definition.origin {
                    self.target_values[source.index()] = Some(value);
                }
                block_args.push(MCodeBlockArgBinding::new(
                    definition.domain,
                    definition.origin,
                    value,
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test;
