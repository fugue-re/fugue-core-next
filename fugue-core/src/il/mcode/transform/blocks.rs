use std::mem;

use rustc_hash::FxHashMap;

use super::{
    MCodeSsaBlockArgDomain, MCodeSsaBlockArgOrigin, MCodeSsaConstruction, MCodeSsaRenameState,
};
use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlBlock, IlBlockId, IlDominance, IlError, IlGraph, IlIndexRange,
};
use crate::il::ecode::ssa::{ECodeSsaDomain, ECodeSsaOpcode};
use crate::il::mcode::ssa::{MCodeSsaIr, MCodeSsaVersion};

impl MCodeSsaConstruction<'_, '_> {
    pub(super) fn build(&mut self, cancellation: &CancellationToken) -> Result<(), IlError> {
        for domain in self.source.memory_domains() {
            self.builder.ensure_memory_domain(domain.space());
        }
        self.builder.set_aliased_variables(
            self.recovery
                .aliases()
                .iter()
                .map(|variable| self.variable(variable))
                .collect(),
        );

        match self.source.graph().entry_block() {
            Some(entry) => self.build_blocks(entry, cancellation)?,
            None => self.build_linear(cancellation)?,
        }

        let mut versions = FxHashMap::default();
        for (value, variable) in self.bindings.iter() {
            let version = versions.entry(variable).or_insert(MCodeSsaVersion::new(0));
            *version = version
                .checked_next()
                .ok_or_else(|| IlError::id_exhausted("MCode SSA version"))?;
            self.builder.bind_value(value, variable, *version);
        }

        Ok(())
    }

    fn build_linear(&mut self, cancellation: &CancellationToken) -> Result<(), IlError> {
        let mut current = MCodeSsaRenameState::default();
        for index in 0..self.source.operations().len() {
            cancellation.check()?;
            self.build_operation_at(index, &mut current)?;
        }

        self.finish_graph(self.source.graph().blocks().to_vec())
    }

    fn build_blocks(
        &mut self,
        entry: IlBlockId,
        cancellation: &CancellationToken,
    ) -> Result<(), IlError> {
        let graph = self.source.graph();
        let dominance = IlDominance::from_blocks(graph.blocks(), graph.successors(), entry);
        self.place_block_arguments(&dominance)?;
        self.build_block_tree(
            entry,
            &dominance,
            MCodeSsaRenameState::default(),
            cancellation,
        )?;

        for index in 0..graph.blocks().len() {
            if self.blocks[index].is_some() {
                continue;
            }
            let block = IlBlockId::try_from_index(index)?;
            self.build_block(block, MCodeSsaRenameState::default(), cancellation)?;
        }

        self.builder.clear_edge_arguments();
        for arguments in mem::take(&mut self.edge_arguments) {
            self.builder.push_edge_arguments(arguments)?;
        }
        let blocks = mem::take(&mut self.blocks)
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .expect("every MCode block is constructed before graph replacement");
        self.finish_graph(blocks)
    }

    fn build_block_tree(
        &mut self,
        entry: IlBlockId,
        dominance: &IlDominance,
        current: MCodeSsaRenameState,
        cancellation: &CancellationToken,
    ) -> Result<(), IlError> {
        let mut stack = vec![(entry, current)];
        while let Some((block, current)) = stack.pop() {
            let current = self.build_block(block, current, cancellation)?;
            let children = dominance.children_for(block);
            let mut current = Some(current);
            for index in (0..children.len()).rev() {
                let child_current = if index == 0 {
                    current
                        .take()
                        .expect("renaming state is moved into exactly one child")
                } else {
                    current
                        .as_ref()
                        .expect("renaming state exists until the final child")
                        .clone()
                };
                stack.push((children[index], child_current));
            }
        }

        Ok(())
    }

    fn build_block(
        &mut self,
        block: IlBlockId,
        mut current: MCodeSsaRenameState,
        cancellation: &CancellationToken,
    ) -> Result<MCodeSsaRenameState, IlError> {
        cancellation.check()?;

        for index in 0..self.block_arguments[block.index()].len() {
            let argument = self.block_arguments[block.index()][index];
            match argument.domain {
                MCodeSsaBlockArgDomain::Memory(space) => {
                    current.memory.insert(space, argument.value);
                    current.pending_memory.remove(&space);
                }
                MCodeSsaBlockArgDomain::Variable(variable) => {
                    self.insert_binding(argument.value, variable)?;
                    if let MCodeSsaBlockArgOrigin::Stack(_) = argument.origin {
                        current.stack.insert(variable, argument.value);
                    }
                }
            }
            if let MCodeSsaBlockArgOrigin::Source { value, .. } = argument.origin
                && let Some(ECodeSsaDomain::Register(root)) = self.source_domain(value)
            {
                current.pending_outputs.remove(&root);
            }
        }

        let source_block = *self.source.graph().blocks().get(block.index()).ok_or(
            IlError::range_out_of_bounds(block.value(), self.source.graph().blocks().len()),
        )?;
        let start = self.builder.operation_count();
        self.allocate_missing_stack_argument_values(source_block, &mut current)?;

        let terminator = (source_block.operations().start()..source_block.operations().end())
            .rev()
            .find(|index| {
                matches!(
                    self.source.operations()[*index].opcode(),
                    ECodeSsaOpcode::Branch
                        | ECodeSsaOpcode::BranchIndirect
                        | ECodeSsaOpcode::ConditionalBranch
                        | ECodeSsaOpcode::Return
                        | ECodeSsaOpcode::Trap
                )
            });
        for index in source_block.operations().start()..source_block.operations().end() {
            if Some(index) == terminator {
                continue;
            }
            cancellation.check()?;
            self.build_operation_at(index, &mut current)?;
        }
        if let Some(index) = terminator {
            cancellation.check()?;
            self.build_operation_at(index, &mut current)?;
        }

        self.build_edge_arguments(source_block, &mut current)?;
        let end = self.builder.operation_count();
        self.blocks[block.index()] = Some(IlBlock::new(
            IlIndexRange::new(start, end)?,
            source_block.successors(),
            source_block.properties(),
        ));

        Ok(current)
    }

    fn allocate_missing_stack_argument_values(
        &mut self,
        source_block: IlBlock,
        current: &mut MCodeSsaRenameState,
    ) -> Result<(), IlError> {
        for successor in source_block
            .successors()
            .slice(self.source.graph().successors())
        {
            for index in 0..self.block_arguments[successor.index()].len() {
                let argument = self.block_arguments[successor.index()][index];
                let MCodeSsaBlockArgOrigin::Stack(variable) = argument.origin else {
                    continue;
                };
                if current.stack.contains_key(&variable) {
                    continue;
                }
                let value =
                    self.push_variable_undefined(variable, self.variable_width(variable)?)?;
                current.stack.insert(variable, value);
            }
        }

        Ok(())
    }

    fn build_edge_arguments(
        &mut self,
        source_block: IlBlock,
        current: &mut MCodeSsaRenameState,
    ) -> Result<(), IlError> {
        for (offset, successor) in source_block
            .successors()
            .slice(self.source.graph().successors())
            .iter()
            .enumerate()
        {
            let edge = source_block.successors().start() + offset;
            let source_arguments = self.source.arguments_for_edge(edge);
            let mut arguments = Vec::with_capacity(self.block_arguments[successor.index()].len());
            for index in 0..self.block_arguments[successor.index()].len() {
                let argument = self.block_arguments[successor.index()][index];
                let value = match argument.origin {
                    MCodeSsaBlockArgOrigin::Source { position, .. } => {
                        let source = source_arguments.get(position).copied().ok_or_else(|| {
                            IlError::missing_component(MCodeSsaIr::FORM, "edge argument")
                        })?;
                        self.source_value(source)?
                    }
                    MCodeSsaBlockArgOrigin::Stack(variable) => {
                        match current.stack.get(&variable).copied() {
                            Some(value) => value,
                            None => {
                                let value = self.push_variable_undefined(
                                    variable,
                                    self.variable_width(variable)?,
                                )?;
                                current.stack.insert(variable, value);
                                value
                            }
                        }
                    }
                };
                arguments.push(value);
            }
            self.edge_arguments[edge] = arguments;
        }

        Ok(())
    }

    fn finish_graph(&mut self, blocks: Vec<IlBlock>) -> Result<(), IlError> {
        let source = self.source.graph();
        let graph = IlGraph::new(
            blocks,
            source.successors().to_vec(),
            source.successor_kinds().to_vec(),
        );
        let graph = if source.block_sources().is_empty() {
            graph
        } else {
            graph.with_block_sources(source.block_sources().to_vec())
        };
        self.builder.set_graph(graph);
        self.builder.set_source_spans(self.remap_source_spans()?);
        self.builder.set_parent_spans(self.remap_parent_spans()?);

        Ok(())
    }

    pub(super) fn clear_pending_output(
        current: &mut MCodeSsaRenameState,
        domain: Option<ECodeSsaDomain>,
    ) {
        if let Some(ECodeSsaDomain::Register(root)) = domain {
            current.pending_outputs.remove(&root);
        }
    }
}
