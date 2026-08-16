use std::collections::{BTreeMap, BTreeSet};
use std::mem;

use rustc_hash::FxHashMap;

use super::buffer::{PCodeToECodeBuffer, PCodeToECodeEffect, PCodeToECodeExprKind};
use crate::analysis::control::CancellationToken;
use crate::il::common::{
    FlagId, IlArtefact, IlBlock, IlBlockId, IlDominance, IlDominanceEvent, IlError, IlExprId,
    IlGraph, IlIndexRange, IlIndexRangeMap, IlParentSpan, IlSourceSpan, IlValueId, RegisterId,
};
use crate::il::ecode::{ECodeBuilder, ECodeDomain, ECodeIr, ECodeOpSpec, ECodeOpcode};

#[derive(Debug, Default)]
pub(crate) struct PCodeToECodeSsaScratch {
    expression_operands: Vec<IlValueId>,
    expr_visits: Vec<ExprVisit>,
    effect_operands: Vec<IlValueId>,
}

#[derive(Debug, Default)]
struct ECodeRenameState {
    values: FxHashMap<ECodeDomain, IlValueId>,
    undo: Vec<(ECodeDomain, Option<IlValueId>)>,
    tracking: bool,
}

impl ECodeRenameState {
    fn checkpoint(&mut self) -> usize {
        self.tracking = true;
        self.undo.len()
    }

    fn rollback(&mut self, checkpoint: usize) {
        while self.undo.len() > checkpoint {
            let (domain, previous) = self
                .undo
                .pop()
                .expect("a rename checkpoint is within the undo log");
            match previous {
                Some(value) => {
                    self.values.insert(domain, value);
                }
                None => {
                    self.values.remove(&domain);
                }
            }
        }
    }

    fn value(&self, domain: ECodeDomain) -> Option<IlValueId> {
        self.values.get(&domain).copied()
    }

    fn contains(&self, domain: ECodeDomain) -> bool {
        self.values.contains_key(&domain)
    }

    fn define(&mut self, domain: ECodeDomain, value: IlValueId) {
        let previous = self.values.insert(domain, value);
        if self.tracking {
            self.undo.push((domain, previous));
        }
    }

    fn retain(&mut self, mut keep: impl FnMut(ECodeDomain, IlValueId) -> bool) {
        let tracking = self.tracking;
        let undo = &mut self.undo;
        self.values.retain(|domain, value| {
            let retained = keep(*domain, *value);
            if !retained && tracking {
                undo.push((*domain, Some(*value)));
            }
            retained
        });
    }
}

#[derive(Debug)]
enum ExprVisit {
    Enter(IlExprId),
    Exit(IlExprId),
}

pub(crate) struct PCodeToECodeSsaLifter<'a> {
    source: PCodeToECodeBuffer,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    builder: ECodeBuilder,
    values: Vec<Option<IlValueId>>,
    built_expressions: Vec<IlExprId>,
    scratch: &'a mut PCodeToECodeSsaScratch,
    block_args: Vec<Vec<(ECodeDomain, IlValueId)>>,
    domain_widths: BTreeMap<ECodeDomain, u32>,
    entry_block: Option<IlBlockId>,
    input_domains: Vec<(ECodeDomain, u32)>,
    blocks: Vec<Option<IlBlock>>,
    edge_args: Vec<Vec<IlValueId>>,
    statement_ranges: IlIndexRangeMap,
}

#[derive(Debug, Default)]
struct ECodeDomains {
    widths: BTreeMap<ECodeDomain, u32>,
    definitions: BTreeMap<ECodeDomain, Vec<IlBlockId>>,
    reads: BTreeSet<ECodeDomain>,
}

impl ECodeDomains {
    fn new(source: &PCodeToECodeBuffer, graph: &IlGraph) -> Result<Self, IlError> {
        let mut domains = Self::default();

        for (block_index, block) in graph.blocks().iter().enumerate() {
            let block_id = IlBlockId::try_from_index(block_index)?;

            for operation_index in block.operations().start()..block.operations().end() {
                let operation = &source.operations()[operation_index];

                match operation.opcode() {
                    ECodeOpcode::WriteRegister | ECodeOpcode::WriteFlag => {
                        let value = operation
                            .value()
                            .ok_or_else(|| IlError::missing_component(ECodeIr::FORM, "value"))?;
                        let width = source.expressions()[value.index()].width();
                        let domain = match operation.opcode() {
                            ECodeOpcode::WriteFlag => {
                                ECodeDomain::Flag(FlagId::new(operation.immediate()))
                            }
                            ECodeOpcode::WriteRegister => {
                                ECodeDomain::Register(RegisterId::new(operation.immediate()))
                            }
                            _ => unreachable!(),
                        };
                        domains.record_width(domain, width)?;
                        domains
                            .definitions
                            .entry(domain)
                            .or_default()
                            .push(block_id);
                    }
                    ECodeOpcode::Store => {
                        let space = operation.address_space().ok_or_else(|| {
                            IlError::missing_component(ECodeIr::FORM, "address space")
                        })?;
                        let domain = ECodeDomain::Memory(space);
                        domains.record_width(domain, 0)?;
                        domains
                            .definitions
                            .entry(domain)
                            .or_default()
                            .push(block_id);
                    }
                    _ => {}
                }
            }
        }

        for expression in source.expressions() {
            match expression.kind() {
                PCodeToECodeExprKind::ReadFlag | PCodeToECodeExprKind::ReadRegister => {
                    let domain = match expression.kind() {
                        PCodeToECodeExprKind::ReadFlag => {
                            ECodeDomain::Flag(FlagId::new(expression.immediate()))
                        }
                        PCodeToECodeExprKind::ReadRegister => {
                            ECodeDomain::Register(RegisterId::new(expression.immediate()))
                        }
                        PCodeToECodeExprKind::Operation(_) => unreachable!(),
                    };
                    domains.record_width(domain, expression.width())?;
                    domains.reads.insert(domain);
                }
                PCodeToECodeExprKind::Operation(ECodeOpcode::Load) => {
                    let space = expression.address_space().ok_or_else(|| {
                        IlError::missing_component(ECodeIr::FORM, "address space")
                    })?;
                    domains.record_width(ECodeDomain::Memory(space), 0)?;
                }
                PCodeToECodeExprKind::Operation(_) => {}
            }
        }

        for definitions in domains.definitions.values_mut() {
            definitions.sort();
            definitions.dedup();
        }

        Ok(domains)
    }

    fn record_width(&mut self, domain: ECodeDomain, width: u32) -> Result<(), IlError> {
        match self.widths.get(&domain) {
            Some(existing) if *existing != width => Err(IlError::width_mismatch(ECodeIr::FORM)),
            Some(_) => Ok(()),
            None => {
                self.widths.insert(domain, width);
                Ok(())
            }
        }
    }
}

impl<'a> PCodeToECodeSsaLifter<'a> {
    pub(crate) fn new(
        source: PCodeToECodeBuffer,
        graph: IlGraph,
        source_spans: Vec<IlSourceSpan>,
        parent_spans: Vec<IlParentSpan>,
        builder: ECodeBuilder,
        scratch: &'a mut PCodeToECodeSsaScratch,
    ) -> Self {
        let expression_count = source.expressions().len();
        let operation_count = source.operations().len();
        let block_count = graph.blocks().len();
        let edge_count = graph.successors().len();

        Self {
            source,
            graph,
            source_spans,
            parent_spans,
            builder,
            values: vec![None; expression_count],
            built_expressions: Vec::new(),
            scratch,
            block_args: vec![Vec::new(); block_count],
            domain_widths: BTreeMap::new(),
            entry_block: None,
            input_domains: Vec::new(),
            blocks: vec![None; block_count],
            edge_args: vec![Vec::new(); edge_count],
            statement_ranges: IlIndexRangeMap::unmapped(operation_count),
        }
    }

    pub(crate) fn lift(mut self, cancellation: &CancellationToken) -> Result<ECodeIr, IlError> {
        cancellation.check()?;

        match self.graph.entry_block() {
            Some(entry) => self.lift_blocks(entry, cancellation)?,
            None => self.lift_linear(cancellation)?,
        }

        self.builder.build(cancellation)
    }

    fn lift_linear(&mut self, cancellation: &CancellationToken) -> Result<(), IlError> {
        let mut current = ECodeRenameState::default();

        for index in 0..self.source.operations().len() {
            cancellation.check()?;
            self.lift_statement_at(index, &mut current)?;
        }

        self.builder.set_graph(mem::take(&mut self.graph));
        self.builder.set_source_spans(
            self.statement_ranges
                .remap_source_spans(&self.source_spans)?,
        );
        self.builder.set_parent_spans(
            self.statement_ranges
                .remap_parent_spans(&self.parent_spans)?,
        );

        Ok(())
    }

    fn lift_blocks(
        &mut self,
        entry: IlBlockId,
        cancellation: &CancellationToken,
    ) -> Result<(), IlError> {
        let dominance =
            IlDominance::from_blocks(self.graph.blocks(), self.graph.successors(), entry);
        let domains = ECodeDomains::new(&self.source, &self.graph)?;

        self.place_block_args(&domains, &dominance)?;
        self.entry_block = Some(entry);
        self.input_domains = domains
            .reads
            .iter()
            .filter(|domain| !domains.definitions.contains_key(domain))
            .map(|domain| (*domain, domains.widths[domain]))
            .collect();
        self.domain_widths = domains.widths;
        self.lift_block_tree(entry, &dominance, ECodeRenameState::default(), cancellation)?;

        for block_index in 0..self.graph.blocks().len() {
            let block_id = IlBlockId::try_from_index(block_index)?;

            if self.blocks[block_index].is_none() {
                self.lift_block(block_id, &mut ECodeRenameState::default(), cancellation)?;
            }
        }

        for args in mem::take(&mut self.edge_args) {
            self.builder.emitter().emit_edge_args(args)?;
        }
        let blocks = mem::take(&mut self.blocks)
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .expect("every block is constructed before the graph is replaced");
        let graph = mem::take(&mut self.graph)
            .with_operation_ranges(blocks.into_iter().map(|block| block.operations()))?;
        self.builder.set_graph(graph);
        self.builder.set_source_spans(
            self.statement_ranges
                .remap_source_spans(&self.source_spans)?,
        );
        self.builder.set_parent_spans(
            self.statement_ranges
                .remap_parent_spans(&self.parent_spans)?,
        );

        Ok(())
    }

    fn lift_block_tree(
        &mut self,
        root: IlBlockId,
        dominance: &IlDominance,
        mut current: ECodeRenameState,
        cancellation: &CancellationToken,
    ) -> Result<(), IlError> {
        let mut checkpoints = Vec::new();
        for event in dominance.events_from(root) {
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
        current: &mut ECodeRenameState,
        cancellation: &CancellationToken,
    ) -> Result<(), IlError> {
        cancellation.check()?;

        for (domain, value) in &self.block_args[block.index()] {
            current.define(*domain, *value);
        }

        let source_block =
            *self
                .graph
                .blocks()
                .get(block.index())
                .ok_or(IlError::range_out_of_bounds(
                    block.index(),
                    self.graph.blocks().len(),
                ))?;
        let start = self.builder.emitter().operation_count();

        if self.entry_block == Some(block) {
            self.allocate_input_values(current)?;
        }

        self.reset_expression_cache();

        for statement_index in source_block.operations().start()..source_block.operations().end() {
            cancellation.check()?;
            self.lift_statement_at(statement_index, current)?;
        }

        self.lift_edge_args(source_block, current)?;

        let end = self.builder.emitter().operation_count();
        self.blocks[block.index()] = Some(IlBlock::new(
            IlIndexRange::new(start, end)?,
            source_block.successors(),
            source_block.properties(),
        ));

        Ok(())
    }

    fn lift_edge_args(
        &mut self,
        source_block: IlBlock,
        current: &mut ECodeRenameState,
    ) -> Result<(), IlError> {
        for successor_offset in 0..source_block.successors().len() {
            let edge = source_block.successors().start() + successor_offset;
            let successor = self.graph.successors()[edge];
            let mut args = Vec::new();
            let arg_count = self.block_args[successor.index()].len();

            for arg_index in 0..arg_count {
                let domain = self.block_args[successor.index()][arg_index].0;
                let value = match current.value(domain) {
                    Some(value) => value,
                    None => {
                        let width = self.domain_widths[&domain];
                        let value = self.push_undefined(domain, width)?;

                        current.define(domain, value);

                        value
                    }
                };

                args.push(value);
            }

            self.edge_args[edge] = args;
        }

        Ok(())
    }

    fn allocate_input_values(&mut self, current: &mut ECodeRenameState) -> Result<(), IlError> {
        for index in 0..self.input_domains.len() {
            let (domain, width) = self.input_domains[index];

            if current.contains(domain) {
                continue;
            }

            let value = self.push_undefined(domain, width)?;
            current.define(domain, value);
        }

        Ok(())
    }

    fn lift_statement_at(
        &mut self,
        index: usize,
        current: &mut ECodeRenameState,
    ) -> Result<(), IlError> {
        let spans = &self.source_spans;
        let span = spans.partition_point(|span| span.destination().start() < index);
        if spans
            .get(span)
            .is_some_and(|span| span.destination().start() == index)
        {
            self.reset_expression_cache();
        }
        let start = self.builder.emitter().operation_count();
        let statement = self.source.operations()[index];

        self.lift_statement(&statement, current)?;

        let end = self.builder.emitter().operation_count();
        self.statement_ranges
            .set_range(index, IlIndexRange::new(start, end)?)?;

        Ok(())
    }

    fn reset_expression_cache(&mut self) {
        for expression in self.built_expressions.drain(..) {
            self.values[expression.index()] = None;
        }
    }

    fn lift_statement(
        &mut self,
        statement: &PCodeToECodeEffect,
        current: &mut ECodeRenameState,
    ) -> Result<(), IlError> {
        match statement.opcode() {
            ECodeOpcode::WriteRegister | ECodeOpcode::WriteFlag => {
                let source_expression = statement
                    .value()
                    .ok_or_else(|| IlError::missing_component(ECodeIr::FORM, "value"))?;
                let width = self.source.expressions()[source_expression.index()].width();
                let source = self.lift_expression(source_expression, current)?;
                let (opcode, domain) = match statement.opcode() {
                    ECodeOpcode::WriteRegister => (
                        ECodeOpcode::WriteRegister,
                        ECodeDomain::Register(RegisterId::new(statement.immediate())),
                    ),
                    ECodeOpcode::WriteFlag => (
                        ECodeOpcode::WriteFlag,
                        ECodeDomain::Flag(FlagId::new(statement.immediate())),
                    ),
                    _ => unreachable!(),
                };
                let spec = ECodeOpSpec::new(opcode, width).with_immediate(statement.immediate());
                let (_, results) = self.builder.emitter().emit(spec, [source], 1)?;
                let value = IlValueId::try_from_index(results.start())?;
                self.builder.emitter().set_value_domain(value, domain)?;
                current.define(domain, value);
            }
            ECodeOpcode::Store => {
                let address_space = statement
                    .address_space()
                    .ok_or_else(|| IlError::missing_component(ECodeIr::FORM, "address space"))?;
                self.lift_effect_operands(statement, current)?;
                let memory = self.current_value(ECodeDomain::Memory(address_space), 0, current)?;

                self.scratch.effect_operands.push(memory);

                let domain = ECodeDomain::Memory(address_space);
                let spec = ECodeOpSpec::new(ECodeOpcode::Store, 0)
                    .with_address_space(address_space)
                    .with_immediate(statement.immediate());
                let (_, results) = self.builder.emitter().emit(
                    spec,
                    self.scratch.effect_operands.iter().copied(),
                    1,
                )?;
                let memory = IlValueId::try_from_index(results.start())?;
                self.builder.emitter().set_value_domain(memory, domain)?;
                current.define(domain, memory);
            }
            opcode => {
                self.lift_effect_operands(statement, current)?;
                let mut spec = ECodeOpSpec::new(opcode, 0).with_immediate(statement.immediate());

                if let Some(address) = statement.address() {
                    spec = spec.with_address(address);
                }

                if let Some(address_space) = statement.address_space() {
                    spec = spec.with_address_space(address_space);
                }

                self.builder.emitter().emit(
                    spec,
                    self.scratch.effect_operands.iter().copied(),
                    0,
                )?;
                if matches!(opcode, ECodeOpcode::Call | ECodeOpcode::CallIndirect) {
                    let preserved = self.source.call_preserved_registers();
                    current.retain(|domain, _| match domain {
                        ECodeDomain::Register(register) => {
                            preserved.binary_search(&register).is_ok()
                        }
                        ECodeDomain::Flag(_) | ECodeDomain::Memory(_) => false,
                    });
                }
            }
        }

        Ok(())
    }

    fn lift_effect_operands(
        &mut self,
        statement: &PCodeToECodeEffect,
        current: &mut ECodeRenameState,
    ) -> Result<(), IlError> {
        self.scratch.effect_operands.clear();

        if let Some(value) = statement.value() {
            let value = self.lift_expression(value, current)?;
            self.scratch.effect_operands.push(value);
        }

        let operand_count = self.source.operation_operands_for(statement).len();
        for index in 0..operand_count {
            let operand = self.source.operation_operands_for(statement)[index];
            let operand = self.lift_expression(operand, current)?;
            self.scratch.effect_operands.push(operand);
        }

        Ok(())
    }

    fn lift_expression(
        &mut self,
        id: IlExprId,
        current: &mut ECodeRenameState,
    ) -> Result<IlValueId, IlError> {
        self.scratch.expr_visits.clear();
        self.scratch.expr_visits.push(ExprVisit::Enter(id));

        while let Some(step) = self.scratch.expr_visits.pop() {
            let expression_id = match step {
                ExprVisit::Enter(expression_id) => {
                    if self.values[expression_id.index()].is_some() {
                        continue;
                    }

                    let expression = self.source.expressions()[expression_id.index()];
                    match expression.kind() {
                        PCodeToECodeExprKind::ReadFlag | PCodeToECodeExprKind::ReadRegister => {
                            let domain = match expression.kind() {
                                PCodeToECodeExprKind::ReadFlag => {
                                    ECodeDomain::Flag(FlagId::new(expression.immediate()))
                                }
                                PCodeToECodeExprKind::ReadRegister => {
                                    ECodeDomain::Register(RegisterId::new(expression.immediate()))
                                }
                                PCodeToECodeExprKind::Operation(_) => unreachable!(),
                            };
                            let value = self.current_value(domain, expression.width(), current)?;
                            self.values[expression_id.index()] = Some(value);
                            self.built_expressions.push(expression_id);
                            continue;
                        }
                        PCodeToECodeExprKind::Operation(_) => {}
                    }

                    self.scratch
                        .expr_visits
                        .push(ExprVisit::Exit(expression_id));
                    for operand in self
                        .source
                        .expression_operands_for(&expression)
                        .iter()
                        .rev()
                    {
                        self.scratch.expr_visits.push(ExprVisit::Enter(*operand));
                    }
                    continue;
                }
                ExprVisit::Exit(expression_id) => expression_id,
            };

            if self.values[expression_id.index()].is_some() {
                continue;
            }

            let expression = self.source.expressions()[expression_id.index()];
            self.scratch.expression_operands.clear();
            for operand in self.source.expression_operands_for(&expression) {
                let operand = self.values[operand.index()]
                    .ok_or_else(|| IlError::missing_component(ECodeIr::FORM, "operand"))?;
                self.scratch.expression_operands.push(operand);
            }
            if expression.kind() == PCodeToECodeExprKind::Operation(ECodeOpcode::Load) {
                let address_space = expression
                    .address_space()
                    .ok_or_else(|| IlError::missing_component(ECodeIr::FORM, "address space"))?;
                let memory = self.current_value(ECodeDomain::Memory(address_space), 0, current)?;
                self.scratch.expression_operands.push(memory);
            }

            let PCodeToECodeExprKind::Operation(opcode) = expression.kind() else {
                return Err(IlError::unsupported_opcode(ECodeIr::FORM));
            };
            let mut spec =
                ECodeOpSpec::new(opcode, expression.width()).with_immediate(expression.immediate());
            if let Some(address_space) = expression.address_space() {
                spec.set_address_space(address_space);
            }
            let (_, results) = self.builder.emitter().emit(
                spec,
                self.scratch.expression_operands.iter().copied(),
                1,
            )?;
            let value = IlValueId::try_from_index(results.start())?;
            self.values[expression_id.index()] = Some(value);
            self.built_expressions.push(expression_id);
        }

        self.values[id.index()]
            .ok_or_else(|| IlError::missing_component(ECodeIr::FORM, "expression value"))
    }

    fn current_value(
        &mut self,
        domain: ECodeDomain,
        width: u32,
        current: &mut ECodeRenameState,
    ) -> Result<IlValueId, IlError> {
        if let Some(value) = current.value(domain) {
            return Ok(value);
        }

        let value = self.push_undefined(domain, width)?;

        current.define(domain, value);

        Ok(value)
    }

    fn push_undefined(&mut self, domain: ECodeDomain, width: u32) -> Result<IlValueId, IlError> {
        let immediate = match domain {
            ECodeDomain::Flag(flag) => flag.value(),
            ECodeDomain::Memory(space) => u64::from(space.value()),
            ECodeDomain::Register(register) => register.value(),
        };
        let spec = ECodeOpSpec::new(ECodeOpcode::Undefined, width).with_immediate(immediate);
        let (_, results) = self.builder.emitter().emit(spec, [], 1)?;
        let value = IlValueId::try_from_index(results.start())?;
        self.builder.emitter().set_value_domain(value, domain)?;

        Ok(value)
    }

    fn place_block_args(
        &mut self,
        domains: &ECodeDomains,
        dominance: &IlDominance,
    ) -> Result<(), IlError> {
        let frontiers = dominance.frontiers(self.graph.blocks(), self.graph.successors());
        let block_count = self.graph.blocks().len();
        let mut placed = BTreeSet::new();

        for (domain, definitions) in &domains.definitions {
            let width = domains.widths[domain];
            let placement = frontiers.place_phis(block_count, definitions.iter().copied())?;

            for block in placement.blocks() {
                if !placed.insert((*block, *domain)) {
                    continue;
                }

                let value = self.builder.emitter().emit_block_arg(*block, width)?;
                self.builder.emitter().set_value_domain(value, *domain)?;
                self.block_args[block.index()].push((*domain, value));
            }
        }

        for args in &mut self.block_args {
            args.sort_by_key(|(domain, _)| *domain);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test;
