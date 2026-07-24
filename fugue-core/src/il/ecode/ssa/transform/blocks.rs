use std::collections::BTreeMap;
use std::mem;

use super::{SsaConstruction, SsaDomain};
use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlBlock, IlBlockId, IlDominance, IlError, IlGraph, IlIndexRange, IlValueId,
};

impl SsaConstruction<'_, '_> {
    pub(crate) fn build(&mut self, cancellation: &CancellationToken) -> Result<(), IlError> {
        match self.source.graph().entry_block() {
            Some(entry) => self.build_blocks(entry, cancellation),
            None => self.build_linear(cancellation),
        }
    }

    fn build_linear(&mut self, cancellation: &CancellationToken) -> Result<(), IlError> {
        let mut current = BTreeMap::new();

        for index in 0..self.source.statements().len() {
            cancellation.check()?;
            self.build_statement_at(index, &mut current)?;
        }

        let graph = IlGraph::new(
            self.source.graph().blocks().to_vec(),
            self.source.graph().successors().to_vec(),
        );
        let graph = if self.source.graph().block_sources().is_empty() {
            graph
        } else {
            graph.with_block_sources(self.source.graph().block_sources().to_vec())
        };
        self.builder.replace_graph(graph);
        self.builder
            .replace_source_spans(self.remap_source_spans()?);
        self.builder
            .replace_parent_spans(self.remap_parent_spans()?);

        Ok(())
    }

    fn build_blocks(
        &mut self,
        entry: IlBlockId,
        cancellation: &CancellationToken,
    ) -> Result<(), IlError> {
        let source_graph = self.source.graph();
        let dominance =
            IlDominance::from_blocks(source_graph.blocks(), source_graph.successors(), entry);
        let domains = self.discover_domains()?;

        self.place_block_arguments(&domains, &dominance)?;
        self.entry_block = Some(entry);
        self.input_domains = domains
            .reads
            .iter()
            .filter(|domain| !domains.definitions.contains_key(domain))
            .map(|domain| (*domain, domains.widths[domain]))
            .collect();
        self.domain_widths = domains.widths;
        self.blocks = vec![None; source_graph.blocks().len()];
        self.edge_arguments = vec![Vec::new(); source_graph.successors().len()];
        self.build_block_tree(entry, &dominance, BTreeMap::new(), cancellation)?;

        for block_index in 0..source_graph.blocks().len() {
            let block_id = IlBlockId::try_from_index(block_index)?;

            if self.blocks[block_index].is_none() {
                self.build_block(block_id, BTreeMap::new(), cancellation)?;
            }
        }

        self.builder.clear_edge_arguments();
        for arguments in mem::take(&mut self.edge_arguments) {
            self.builder.push_edge_arguments(arguments)?;
        }
        let graph = IlGraph::new(
            mem::take(&mut self.blocks)
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .expect("every block is constructed before the graph is replaced"),
            source_graph.successors().to_vec(),
        );
        let graph = if source_graph.block_sources().is_empty() {
            graph
        } else {
            graph.with_block_sources(source_graph.block_sources().to_vec())
        };
        self.builder.replace_graph(graph);
        self.builder
            .replace_source_spans(self.remap_source_spans()?);
        self.builder
            .replace_parent_spans(self.remap_parent_spans()?);

        Ok(())
    }

    fn build_block_tree(
        &mut self,
        block: IlBlockId,
        dominance: &IlDominance,
        current: BTreeMap<SsaDomain, IlValueId>,
        cancellation: &CancellationToken,
    ) -> Result<(), IlError> {
        let mut stack = Vec::new();
        stack.push((block, current));

        while let Some((block, current)) = stack.pop() {
            let current = self.build_block(block, current, cancellation)?;
            let children = dominance.children(block);
            let mut current = Some(current);

            for child_index in (0..children.len()).rev() {
                let child_current = if child_index == 0 {
                    current
                        .take()
                        .expect("renaming state is moved into exactly one child")
                } else {
                    current
                        .as_ref()
                        .expect("renaming state exists until the final child")
                        .clone()
                };
                stack.push((children[child_index], child_current));
            }
        }

        Ok(())
    }

    fn build_block(
        &mut self,
        block: IlBlockId,
        mut current: BTreeMap<SsaDomain, IlValueId>,
        cancellation: &CancellationToken,
    ) -> Result<BTreeMap<SsaDomain, IlValueId>, IlError> {
        cancellation.check()?;

        for (domain, value) in &self.block_arguments[block.index()] {
            current.insert(*domain, *value);
        }

        let source_block = *self.source.graph().blocks().get(block.index()).ok_or(
            IlError::range_out_of_bounds(block.value(), self.source.graph().blocks().len()),
        )?;
        let start = self.builder.operation_count();

        if self.entry_block == Some(block) {
            self.seed_input_domains(&mut current)?;
        }

        for statement_index in source_block.operations().start()..source_block.operations().end() {
            cancellation.check()?;
            self.build_statement_at(statement_index, &mut current)?;
        }

        self.fill_successor_edges(block, &mut current, source_block)?;

        let end = self.builder.operation_count();
        self.blocks[block.index()] = Some(IlBlock::new(
            IlIndexRange::new(start, end)?,
            source_block.successors(),
            source_block.properties(),
        ));

        Ok(current)
    }

    fn fill_successor_edges(
        &mut self,
        block: IlBlockId,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
        source_block: IlBlock,
    ) -> Result<(), IlError> {
        for (successor_offset, successor) in source_block
            .successors()
            .slice(self.source.graph().successors())
            .iter()
            .enumerate()
        {
            let edge = source_block.successors().start() + successor_offset;
            let mut arguments = Vec::new();
            let argument_count = self.block_arguments[successor.index()].len();

            for argument_index in 0..argument_count {
                let domain = self.block_arguments[successor.index()][argument_index].0;
                let value = match current.get(&domain).copied() {
                    Some(value) => value,
                    None => {
                        let width = self.domain_widths[&domain];
                        let value = self.push_undefined(domain, width)?;

                        current.insert(domain, value);

                        value
                    }
                };

                arguments.push(value);
            }

            self.edge_arguments[edge] = arguments;
        }

        if block.index() >= self.source.graph().blocks().len() {
            return Err(IlError::range_out_of_bounds(
                block.value(),
                self.source.graph().blocks().len(),
            ));
        }

        Ok(())
    }

    fn seed_input_domains(
        &mut self,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<(), IlError> {
        for index in 0..self.input_domains.len() {
            let (domain, width) = self.input_domains[index];

            if current.contains_key(&domain) {
                continue;
            }

            let value = self.push_undefined(domain, width)?;
            current.insert(domain, value);
        }

        Ok(())
    }
}
