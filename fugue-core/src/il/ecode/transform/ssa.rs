use std::collections::{BTreeMap, BTreeSet};
use std::mem;

use rustc_hash::FxHashMap;

use super::buffer::{PCodeToECodeBuffer, PCodeToECodeEffect, PCodeToECodeExprKind};
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

            for operation_index in block.ops().start()..block.ops().end() {
                let operation = &source.ops()[operation_index];

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
                        PCodeToECodeExprKind::Op(_) => unreachable!(),
                    };
                    domains.record_width(domain, expression.width())?;
                    domains.reads.insert(domain);
                }
                PCodeToECodeExprKind::Op(ECodeOpcode::Load) => {
                    let space = expression.address_space().ok_or_else(|| {
                        IlError::missing_component(ECodeIr::FORM, "address space")
                    })?;
                    domains.record_width(ECodeDomain::Memory(space), 0)?;
                }
                PCodeToECodeExprKind::Op(_) => {}
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
        let operation_count = source.ops().len();
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

    pub(crate) fn lift(mut self) -> Result<ECodeIr, IlError> {
        match self.graph.entry_block() {
            Some(entry) => self.lift_blocks(entry)?,
            None => self.lift_linear()?,
        }

        self.builder.build()
    }

    fn lift_linear(&mut self) -> Result<(), IlError> {
        let mut current = ECodeRenameState::default();

        for index in 0..self.source.ops().len() {
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

    fn lift_blocks(&mut self, entry: IlBlockId) -> Result<(), IlError> {
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
        self.lift_block_tree(entry, &dominance, ECodeRenameState::default())?;

        for block_index in 0..self.graph.blocks().len() {
            let block_id = IlBlockId::try_from_index(block_index)?;

            if self.blocks[block_index].is_none() {
                self.lift_block(block_id, &mut ECodeRenameState::default())?;
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
            .with_op_ranges(blocks.into_iter().map(|block| block.ops()))?;
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
    ) -> Result<(), IlError> {
        let mut checkpoints = Vec::new();
        for event in dominance.events_from(root) {
            match event {
                IlDominanceEvent::Enter(block) => {
                    checkpoints.push(current.checkpoint());
                    self.lift_block(block, &mut current)?;
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
    ) -> Result<(), IlError> {
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
        let start = self.builder.emitter().op_count();

        if self.entry_block == Some(block) {
            self.allocate_input_values(current)?;
        }

        self.reset_expression_cache();

        for statement_index in source_block.ops().start()..source_block.ops().end() {
            self.lift_statement_at(statement_index, current)?;
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
        let start = self.builder.emitter().op_count();
        let statement = self.source.ops()[index];

        self.lift_statement(&statement, current)?;

        let end = self.builder.emitter().op_count();
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

        let operand_count = self.source.op_operands_for(statement).len();
        for index in 0..operand_count {
            let operand = self.source.op_operands_for(statement)[index];
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
                                PCodeToECodeExprKind::Op(_) => unreachable!(),
                            };
                            let value = self.current_value(domain, expression.width(), current)?;
                            self.values[expression_id.index()] = Some(value);
                            self.built_expressions.push(expression_id);
                            continue;
                        }
                        PCodeToECodeExprKind::Op(_) => {}
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
            if expression.kind() == PCodeToECodeExprKind::Op(ECodeOpcode::Load) {
                let address_space = expression
                    .address_space()
                    .ok_or_else(|| IlError::missing_component(ECodeIr::FORM, "address space"))?;
                let memory = self.current_value(ECodeDomain::Memory(address_space), 0, current)?;
                self.scratch.expression_operands.push(memory);
            }

            let PCodeToECodeExprKind::Op(opcode) = expression.kind() else {
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
mod test {
    use super::*;
    use crate::il::common::{
        FlagId, IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlGraph, IlMetadata, IlOpId,
        IlParentSpan, IlSourceSpan, RegisterId,
    };
    use crate::il::ecode::transform::buffer::{
        PCodeToECodeBuffer, PCodeToECodeEffect, PCodeToECodeExpr, PCodeToECodeExprKind,
    };
    use crate::il::ecode::{ECodeOpcode, ECodeOptimiser};
    use crate::ir::{Address, FunctionId};
    use crate::storage::segments::space::AddressSpaceId;

    struct PCodeToECodeBufferFixture {
        metadata: IlMetadata,
        graph: IlGraph,
        source_spans: Vec<IlSourceSpan>,
        parent_spans: Vec<IlParentSpan>,
        buffer: PCodeToECodeBuffer,
    }

    struct PCodeToECodeBufferFixtureBuilder {
        fixture: PCodeToECodeBufferFixture,
    }

    impl PCodeToECodeBufferFixtureBuilder {
        fn new(metadata: IlMetadata, graph: IlGraph) -> Self {
            Self {
                fixture: PCodeToECodeBufferFixture {
                    metadata,
                    graph,
                    source_spans: Vec::new(),
                    parent_spans: Vec::new(),
                    buffer: PCodeToECodeBuffer::default(),
                },
            }
        }

        fn push_expression(&mut self, expression: PCodeToECodeExpr) -> Result<IlExprId, IlError> {
            self.fixture.buffer.push_expression(expression)
        }

        fn push_expression_operands(
            &mut self,
            operands: impl IntoIterator<Item = IlExprId>,
        ) -> Result<IlIndexRange, IlError> {
            self.fixture.buffer.push_expression_operands(operands)
        }

        fn push_statement(&mut self, operation: PCodeToECodeEffect) -> Result<IlOpId, IlError> {
            self.fixture.buffer.push_op(operation)
        }

        fn push_effect_operands(
            &mut self,
            operands: impl IntoIterator<Item = IlExprId>,
        ) -> Result<IlIndexRange, IlError> {
            self.fixture.buffer.push_op_operands(operands)
        }

        fn set_call_preserved_registers(&mut self, registers: Vec<RegisterId>) {
            self.fixture.buffer.set_call_preserved_registers(registers);
        }

        fn set_parent_spans(&mut self, spans: Vec<IlParentSpan>) {
            self.fixture.parent_spans = spans;
        }

        fn set_source_spans(&mut self, spans: Vec<IlSourceSpan>) {
            self.fixture.source_spans = spans;
        }

        fn build(self) -> PCodeToECodeBufferFixture {
            self.fixture
        }
    }

    #[derive(Default)]
    struct ECodeFixtureBuilder {
        scratch: PCodeToECodeSsaScratch,
    }

    impl ECodeFixtureBuilder {
        fn build(&mut self, fixture: PCodeToECodeBufferFixture) -> Result<ECodeIr, IlError> {
            let builder = ECodeBuilder::new(fixture.metadata, IlGraph::default());
            PCodeToECodeSsaLifter::new(
                fixture.buffer,
                fixture.graph,
                fixture.source_spans,
                fixture.parent_spans,
                builder,
                &mut self.scratch,
            )
            .lift()
        }

        fn build_optimised(
            &mut self,
            fixture: PCodeToECodeBufferFixture,
        ) -> Result<ECodeIr, IlError> {
            let mut ir = self.build(fixture)?;
            ir.rewrite(ECodeOptimiser);
            Ok(ir)
        }
    }

    #[test]
    fn empty_ecode_constructs_empty_body() {
        let source_metadata = IlMetadata::new(FunctionId::default(), 11);
        let source =
            PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default()).build();
        let mut transform = ECodeFixtureBuilder::default();

        let ir = transform.build(source).unwrap();

        assert_eq!(ir.metadata().input_revision().value(), 11);
        assert!(ir.ops().is_empty());
    }

    #[test]
    fn register_read_after_write_uses_current_value() {
        let source_metadata = IlMetadata::new(FunctionId::default(), 11);
        let mut builder =
            PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());
        let value = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                0x2a,
                None,
            ))
            .unwrap();

        builder
            .push_statement(
                PCodeToECodeEffect::new(
                    ECodeOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(value),
                    None,
                    None,
                )
                .with_immediate(7),
            )
            .unwrap();

        let read = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::ReadRegister,
                64,
                IlIndexRange::EMPTY,
                7,
                None,
            ))
            .unwrap();
        let operands = builder.push_effect_operands([read]).unwrap();

        builder
            .push_statement(PCodeToECodeEffect::new(
                ECodeOpcode::Return,
                operands,
                None,
                None,
                None,
            ))
            .unwrap();
        builder.set_parent_spans(vec![IlParentSpan::new(
            IlIndexRange::new(0, 2).unwrap(),
            IlIndexRange::new(4, 6).unwrap(),
        )]);

        let source = builder.build();
        let mut transform = ECodeFixtureBuilder::default();
        let ir = transform.build(source).unwrap();

        assert_eq!(ir.ops()[0].opcode(), ECodeOpcode::Constant);
        assert_eq!(ir.ops()[1].opcode(), ECodeOpcode::WriteRegister);
        assert_eq!(ir.ops()[2].opcode(), ECodeOpcode::Return);
        assert_eq!(ir.op_operands().len(), 2);
        assert_eq!(
            ir.op_operands_for(&ir.ops()[2]),
            &[IlValueId::try_from_index(ir.ops()[1].results().start()).unwrap()]
        );
        assert_eq!(
            ir.parent_spans(),
            &[IlParentSpan::new(
                IlIndexRange::new(0, 3).unwrap(),
                IlIndexRange::new(4, 6).unwrap(),
            )]
        );
    }

    #[test]
    fn call_preserves_only_declared_register_state() {
        let source_metadata = IlMetadata::new(FunctionId::default(), 11);
        let mut builder =
            PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());
        builder.set_call_preserved_registers(vec![RegisterId::new(7)]);
        let preserved = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                0x2a,
                None,
            ))
            .unwrap();
        builder
            .push_statement(
                PCodeToECodeEffect::new(
                    ECodeOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(preserved),
                    None,
                    None,
                )
                .with_immediate(7),
            )
            .unwrap();
        let clobbered = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                0x2b,
                None,
            ))
            .unwrap();
        builder
            .push_statement(
                PCodeToECodeEffect::new(
                    ECodeOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(clobbered),
                    None,
                    None,
                )
                .with_immediate(8),
            )
            .unwrap();
        builder
            .push_statement(PCodeToECodeEffect::new(
                ECodeOpcode::Call,
                IlIndexRange::EMPTY,
                None,
                Some(Address::from(0x2000u64)),
                None,
            ))
            .unwrap();
        let read_preserved = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::ReadRegister,
                64,
                IlIndexRange::EMPTY,
                7,
                None,
            ))
            .unwrap();
        let read_clobbered = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::ReadRegister,
                64,
                IlIndexRange::EMPTY,
                8,
                None,
            ))
            .unwrap();
        let operands = builder
            .push_effect_operands([read_preserved, read_clobbered])
            .unwrap();
        builder
            .push_statement(PCodeToECodeEffect::new(
                ECodeOpcode::Return,
                operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.build();
        let ir = ECodeFixtureBuilder::default().build(source).unwrap();

        assert_eq!(ir.ops()[0].opcode(), ECodeOpcode::Constant);
        assert_eq!(ir.ops()[1].opcode(), ECodeOpcode::WriteRegister);
        assert_eq!(ir.ops()[2].opcode(), ECodeOpcode::Constant);
        assert_eq!(ir.ops()[3].opcode(), ECodeOpcode::WriteRegister);
        assert_eq!(ir.ops()[4].opcode(), ECodeOpcode::Call);
        assert_eq!(ir.ops()[5].opcode(), ECodeOpcode::Undefined);
        assert_eq!(ir.ops()[6].opcode(), ECodeOpcode::Return);
        assert_eq!(
            ir.op_operands_for(&ir.ops()[6]),
            &[
                IlValueId::try_from_index(ir.ops()[1].results().start()).unwrap(),
                IlValueId::try_from_index(ir.ops()[5].results().start()).unwrap(),
            ]
        );
    }

    #[test]
    fn insn_wide_expression_is_not_rebuilt_after_register_write() {
        let source_metadata = IlMetadata::new(FunctionId::default(), 11);
        let mut builder =
            PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());
        let register = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::ReadRegister,
                64,
                IlIndexRange::EMPTY,
                7,
                None,
            ))
            .unwrap();
        let decrement = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                8,
                None,
            ))
            .unwrap();
        let subtract_operands = builder
            .push_expression_operands([register, decrement])
            .unwrap();
        let address = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Sub),
                64,
                subtract_operands,
                0,
                None,
            ))
            .unwrap();
        builder
            .push_statement(
                PCodeToECodeEffect::new(
                    ECodeOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(address),
                    None,
                    None,
                )
                .with_immediate(7),
            )
            .unwrap();

        let value = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                0x2a,
                None,
            ))
            .unwrap();
        let store_operands = builder.push_effect_operands([address, value]).unwrap();
        builder
            .push_statement(PCodeToECodeEffect::new(
                ECodeOpcode::Store,
                store_operands,
                None,
                None,
                Some(AddressSpaceId::new(1)),
            ))
            .unwrap();
        builder.set_source_spans(vec![IlSourceSpan::new(
            IlIndexRange::new(0, 2).unwrap(),
            Address::from(0x1000u64),
            0,
            1,
        )]);

        let source = builder.build();
        let ir = ECodeFixtureBuilder::default().build(source).unwrap();
        let subtracts = ir
            .ops()
            .iter()
            .enumerate()
            .filter(|(_, operation)| operation.opcode() == ECodeOpcode::Sub)
            .collect::<Vec<_>>();
        assert_eq!(subtracts.len(), 1);
        let address_value =
            IlValueId::try_from_index(subtracts[0].1.results().start()).expect("result must exist");
        let store = ir
            .ops()
            .iter()
            .find(|operation| operation.opcode() == ECodeOpcode::Store)
            .expect("store must exist");
        assert_eq!(ir.op_operands_for(store)[0], address_value);
    }

    #[test]
    fn register_read_without_write_becomes_undefined() {
        let source_metadata = IlMetadata::new(FunctionId::default(), 11);
        let mut builder =
            PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());
        let read = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::ReadRegister,
                32,
                IlIndexRange::EMPTY,
                9,
                None,
            ))
            .unwrap();
        let operands = builder.push_effect_operands([read]).unwrap();

        builder
            .push_statement(PCodeToECodeEffect::new(
                ECodeOpcode::Return,
                operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.build();
        let mut transform = ECodeFixtureBuilder::default();
        let ir = transform.build(source).unwrap();

        assert_eq!(ir.ops()[0].opcode(), ECodeOpcode::Undefined);
        assert_eq!(ir.ops()[0].width(), 32);
        assert_eq!(ir.ops()[0].immediate(), 9);
        assert_eq!(ir.ops()[1].opcode(), ECodeOpcode::Return);
    }

    #[test]
    fn load_preserves_fugue_address_space() {
        let source_metadata = IlMetadata::new(FunctionId::default(), 11);
        let mut builder =
            PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());
        let offset = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let load_operands = builder.push_expression_operands([offset]).unwrap();
        let space = AddressSpaceId::new(3);
        let load = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Load),
                8,
                load_operands,
                0,
                Some(space),
            ))
            .unwrap();
        let return_operands = builder.push_effect_operands([load]).unwrap();

        builder
            .push_statement(PCodeToECodeEffect::new(
                ECodeOpcode::Return,
                return_operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.build();
        let mut transform = ECodeFixtureBuilder::default();
        let ir = transform.build(source).unwrap();

        let load_index = ir
            .ops()
            .iter()
            .position(|operation| operation.opcode() == ECodeOpcode::Load)
            .unwrap();

        assert_eq!(ir.ops()[load_index].address_space(), Some(space));
        assert_eq!(ir.memory_domains().len(), 1);
        assert_eq!(ir.memory_domains()[0].space(), space);

        let memory = ir.values()[ir.memory_operand(&ir.ops()[load_index]).unwrap().index()];

        assert_eq!(memory.width(), 0);
    }

    #[test]
    fn load_after_store_uses_store_memory_result() {
        let source_metadata = IlMetadata::new(FunctionId::default(), 11);
        let mut builder =
            PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());
        let space = AddressSpaceId::new(3);
        let store_address = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let store_value = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                32,
                IlIndexRange::EMPTY,
                0x2a,
                None,
            ))
            .unwrap();
        let store_operands = builder
            .push_effect_operands([store_address, store_value])
            .unwrap();

        builder
            .push_statement(PCodeToECodeEffect::new(
                ECodeOpcode::Store,
                store_operands,
                None,
                None,
                Some(space),
            ))
            .unwrap();

        let load_address = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let load_operands = builder.push_expression_operands([load_address]).unwrap();
        let load = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Load),
                32,
                load_operands,
                0,
                Some(space),
            ))
            .unwrap();
        let return_operands = builder.push_effect_operands([load]).unwrap();

        builder
            .push_statement(PCodeToECodeEffect::new(
                ECodeOpcode::Return,
                return_operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.build();
        let mut transform = ECodeFixtureBuilder::default();
        let ir = transform.build(source).unwrap();
        let store_index = ir
            .ops()
            .iter()
            .position(|operation| operation.opcode() == ECodeOpcode::Store)
            .unwrap();
        let load_index = ir
            .ops()
            .iter()
            .position(|operation| operation.opcode() == ECodeOpcode::Load)
            .unwrap();
        let store_memory =
            IlValueId::try_from_index(ir.ops()[store_index].results().start()).unwrap();
        let load_operands = ir.op_operands_for(&ir.ops()[load_index]);

        assert_eq!(ir.memory_domains().len(), 1);
        assert_eq!(ir.memory_domains()[0].space(), space);
        assert_eq!(ir.values()[store_memory.index()].width(), 0);
        assert_eq!(*load_operands.last().unwrap(), store_memory);
    }

    #[test]
    fn store_without_load_registers_memory_domain() {
        let source_metadata = IlMetadata::new(FunctionId::default(), 11);
        let mut builder =
            PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());
        let space = AddressSpaceId::new(3);
        let address = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let value = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                32,
                IlIndexRange::EMPTY,
                0x2a,
                None,
            ))
            .unwrap();
        let operands = builder.push_effect_operands([address, value]).unwrap();

        builder
            .push_statement(PCodeToECodeEffect::new(
                ECodeOpcode::Store,
                operands,
                None,
                None,
                Some(space),
            ))
            .unwrap();

        let source = builder.build();
        let mut transform = ECodeFixtureBuilder::default();
        let ir = transform.build_optimised(source).unwrap();

        ir.verify().unwrap();

        assert_eq!(ir.memory_domains().len(), 1);
        assert_eq!(ir.memory_domains()[0].space(), space);
    }

    #[test]
    fn direct_branch_preserves_fugue_address() {
        let source_metadata = IlMetadata::new(FunctionId::default(), 11);
        let mut builder =
            PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());
        let condition = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                1,
                IlIndexRange::EMPTY,
                1,
                None,
            ))
            .unwrap();
        let target_expression = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                0x2000,
                None,
            ))
            .unwrap();
        let operands = builder
            .push_effect_operands([condition, target_expression])
            .unwrap();
        let target = Address::new(AddressSpaceId::new(4), 0x2000u64);

        builder
            .push_statement(PCodeToECodeEffect::new(
                ECodeOpcode::ConditionalBranch,
                operands,
                None,
                Some(target),
                None,
            ))
            .unwrap();

        let source = builder.build();
        let mut transform = ECodeFixtureBuilder::default();
        let ir = transform.build(source).unwrap();

        assert_eq!(ir.ops()[2].opcode(), ECodeOpcode::ConditionalBranch);
        assert_eq!(ir.ops()[2].address(), Some(target));
    }

    #[test]
    fn deep_dominance_chain_constructs_iteratively() {
        let source_metadata = IlMetadata::new(FunctionId::default(), 11);
        let block_count = 128usize;
        let mut successors = Vec::new();
        let mut blocks = Vec::new();

        for index in 0..block_count {
            let mut flags = IlBlockProperties::empty();
            if index == 0 {
                flags |= IlBlockProperties::ENTRY;
            }
            if index + 1 == block_count {
                flags |= IlBlockProperties::EXIT;
            }

            let successor_range = if index + 1 == block_count {
                IlIndexRange::EMPTY
            } else {
                successors.push(IlBlockId::try_from_index(index + 1).unwrap());
                IlIndexRange::new(successors.len() - 1, successors.len()).unwrap()
            };

            blocks.push(IlBlock::new(
                IlIndexRange::new(index, index + 1).unwrap(),
                successor_range,
                flags,
            ));
        }

        let successor_kinds = vec![IlEdgeKinds::UNCONDITIONAL; successors.len()];
        let graph = IlGraph::new(blocks, successors, successor_kinds);
        let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, graph);

        for index in 0..block_count {
            let value = builder
                .push_expression(PCodeToECodeExpr::new(
                    PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                    64,
                    IlIndexRange::EMPTY,
                    index as u64,
                    None,
                ))
                .unwrap();

            builder
                .push_statement(
                    PCodeToECodeEffect::new(
                        ECodeOpcode::WriteRegister,
                        IlIndexRange::EMPTY,
                        Some(value),
                        None,
                        None,
                    )
                    .with_immediate(7),
                )
                .unwrap();
        }

        let source = builder.build();
        let mut transform = ECodeFixtureBuilder::default();
        let ir = transform.build(source).unwrap();

        assert_eq!(ir.graph().blocks().len(), block_count);
        assert_eq!(ir.graph().successors().len(), block_count - 1);
        assert_eq!(ir.ops().len(), block_count * 2);
        assert!(ir.block_args().is_empty());
    }

    #[test]
    fn branch_heavy_ssa_restores_live_domains_between_siblings() {
        const DOMAIN_COUNT: usize = 64;

        let left = IlBlockId::try_from_index(1).unwrap();
        let right = IlBlockId::try_from_index(2).unwrap();
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::new(0, DOMAIN_COUNT).unwrap(),
                    IlIndexRange::new(0, 2).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::new(DOMAIN_COUNT, DOMAIN_COUNT * 2).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
                IlBlock::new(
                    IlIndexRange::new(DOMAIN_COUNT * 2, DOMAIN_COUNT * 2 + 1).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            vec![left, right],
            vec![IlEdgeKinds::FALL_THROUGH, IlEdgeKinds::TAKEN],
        );
        let metadata = IlMetadata::new(FunctionId::default(), 11);
        let mut builder = PCodeToECodeBufferFixtureBuilder::new(metadata, graph);

        for register in 0..DOMAIN_COUNT {
            let value = builder
                .push_expression(PCodeToECodeExpr::new(
                    PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                    64,
                    IlIndexRange::EMPTY,
                    register as u64,
                    None,
                ))
                .unwrap();
            builder
                .push_statement(
                    PCodeToECodeEffect::new(
                        ECodeOpcode::WriteRegister,
                        IlIndexRange::EMPTY,
                        Some(value),
                        None,
                        None,
                    )
                    .with_immediate(register as u64),
                )
                .unwrap();
        }
        for register in 0..DOMAIN_COUNT {
            let value = builder
                .push_expression(PCodeToECodeExpr::new(
                    PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                    64,
                    IlIndexRange::EMPTY,
                    0x1000 + register as u64,
                    None,
                ))
                .unwrap();
            builder
                .push_statement(
                    PCodeToECodeEffect::new(
                        ECodeOpcode::WriteRegister,
                        IlIndexRange::EMPTY,
                        Some(value),
                        None,
                        None,
                    )
                    .with_immediate(register as u64),
                )
                .unwrap();
        }
        let reads = (0..DOMAIN_COUNT)
            .map(|register| {
                builder.push_expression(PCodeToECodeExpr::new(
                    PCodeToECodeExprKind::ReadRegister,
                    64,
                    IlIndexRange::EMPTY,
                    register as u64,
                    None,
                ))
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let operands = builder.push_effect_operands(reads).unwrap();
        builder
            .push_statement(PCodeToECodeEffect::new(
                ECodeOpcode::Return,
                operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.build();
        let ir = ECodeFixtureBuilder::default().build(source).unwrap();
        let returned = ir
            .ops()
            .iter()
            .find(|operation| operation.opcode() == ECodeOpcode::Return)
            .map(|operation| ir.op_operands_for(operation))
            .expect("the right sibling retains its return");

        assert_eq!(returned.len(), DOMAIN_COUNT);
        for (register, value) in returned.iter().copied().enumerate() {
            let write = ir
                .defining_op(value)
                .expect("each returned register has a reaching definition");
            let source = ir.op_operands_for(write)[0];
            let constant = ir
                .defining_op(source)
                .expect("each reaching definition has a constant source");
            assert_eq!(constant.immediate(), register as u64);
        }
    }

    #[test]
    fn merge_block_register_read_becomes_block_arg() {
        let source_metadata = IlMetadata::new(FunctionId::default(), 11);
        let successors = vec![
            IlBlockId::try_from_index(1).unwrap(),
            IlBlockId::try_from_index(2).unwrap(),
            IlBlockId::try_from_index(3).unwrap(),
            IlBlockId::try_from_index(3).unwrap(),
        ];
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(0, 2).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::new(2, 3).unwrap(),
                    IlBlockProperties::empty(),
                ),
                IlBlock::new(
                    IlIndexRange::new(1, 2).unwrap(),
                    IlIndexRange::new(3, 4).unwrap(),
                    IlBlockProperties::empty(),
                ),
                IlBlock::new(
                    IlIndexRange::new(2, 3).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            successors.clone(),
            vec![IlEdgeKinds::UNCONDITIONAL; successors.len()],
        );
        let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, graph);
        let left = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                1,
                None,
            ))
            .unwrap();
        let right = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                2,
                None,
            ))
            .unwrap();
        let read = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::ReadRegister,
                64,
                IlIndexRange::EMPTY,
                7,
                None,
            ))
            .unwrap();

        builder
            .push_statement(
                PCodeToECodeEffect::new(
                    ECodeOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(left),
                    None,
                    None,
                )
                .with_immediate(7),
            )
            .unwrap();
        builder
            .push_statement(
                PCodeToECodeEffect::new(
                    ECodeOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(right),
                    None,
                    None,
                )
                .with_immediate(7),
            )
            .unwrap();
        let operands = builder.push_effect_operands([read]).unwrap();
        builder
            .push_statement(PCodeToECodeEffect::new(
                ECodeOpcode::Return,
                operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.build();
        let mut transform = ECodeFixtureBuilder::default();
        let ir = transform.build(source).unwrap();

        assert_eq!(ir.block_args().len(), 1);
        assert_eq!(
            ir.block_args()[0].block(),
            IlBlockId::try_from_index(3).unwrap()
        );
        let return_operation = ir
            .ops()
            .iter()
            .find(|operation| operation.opcode() == ECodeOpcode::Return)
            .unwrap();
        assert_eq!(
            ir.op_operands_for(return_operation),
            &[ir.block_args()[0].value()]
        );
        assert_eq!(ir.edge_args().len(), 4);
        assert_eq!(ir.edge_arg_values().len(), 2);
        assert!(ir.edge_args()[0].is_empty());
        assert!(ir.edge_args()[1].is_empty());
        assert_eq!(ir.args_for_edge(2).len(), 1);
        assert_eq!(ir.args_for_edge(3).len(), 1);
    }

    #[test]
    fn merge_block_load_uses_memory_block_arg() {
        let source_metadata = IlMetadata::new(FunctionId::default(), 11);
        let join = IlBlockId::try_from_index(3).unwrap();
        let successors = vec![
            IlBlockId::try_from_index(1).unwrap(),
            IlBlockId::try_from_index(2).unwrap(),
            join,
            join,
        ];
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(0, 2).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::new(2, 3).unwrap(),
                    IlBlockProperties::empty(),
                ),
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(3, 4).unwrap(),
                    IlBlockProperties::empty(),
                ),
                IlBlock::new(
                    IlIndexRange::new(1, 2).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            successors.clone(),
            vec![IlEdgeKinds::UNCONDITIONAL; successors.len()],
        );
        let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, graph);
        let space = AddressSpaceId::new(3);
        let store_address = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let store_value = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                32,
                IlIndexRange::EMPTY,
                0x2a,
                None,
            ))
            .unwrap();
        let load_address = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let load_operands = builder.push_expression_operands([load_address]).unwrap();
        let load = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Load),
                32,
                load_operands,
                0,
                Some(space),
            ))
            .unwrap();
        let store_operands = builder
            .push_effect_operands([store_address, store_value])
            .unwrap();

        builder
            .push_statement(PCodeToECodeEffect::new(
                ECodeOpcode::Store,
                store_operands,
                None,
                None,
                Some(space),
            ))
            .unwrap();

        let return_operands = builder.push_effect_operands([load]).unwrap();

        builder
            .push_statement(PCodeToECodeEffect::new(
                ECodeOpcode::Return,
                return_operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.build();
        let mut transform = ECodeFixtureBuilder::default();
        let ir = transform.build(source).unwrap();
        let load_index = ir
            .ops()
            .iter()
            .position(|operation| operation.opcode() == ECodeOpcode::Load)
            .unwrap();
        let load_operands = ir.op_operands_for(&ir.ops()[load_index]);

        assert_eq!(ir.memory_domains().len(), 1);
        assert_eq!(ir.memory_domains()[0].space(), space);
        assert_eq!(ir.block_args().len(), 1);
        assert_eq!(ir.block_args()[0].block(), join);
        assert_eq!(ir.values()[ir.block_args()[0].value().index()].width(), 0);
        assert_eq!(*load_operands.last().unwrap(), ir.block_args()[0].value());
        assert!(ir.args_for_edge(0).is_empty());
        assert!(ir.args_for_edge(1).is_empty());
        assert_eq!(ir.args_for_edge(2).len(), 1);
        assert_eq!(ir.args_for_edge(3).len(), 1);
    }

    #[test]
    fn loop_carried_register_uses_header_block_arg() {
        let source_metadata = IlMetadata::new(FunctionId::default(), 11);
        let loop_header = IlBlockId::try_from_index(1).unwrap();
        let loop_body = IlBlockId::try_from_index(2).unwrap();
        let exit = IlBlockId::try_from_index(3).unwrap();
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(0, 1).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::new(1, 2).unwrap(),
                    IlBlockProperties::empty(),
                ),
                IlBlock::new(
                    IlIndexRange::new(1, 2).unwrap(),
                    IlIndexRange::new(2, 4).unwrap(),
                    IlBlockProperties::empty(),
                ),
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            vec![loop_header, loop_body, loop_header, exit],
            vec![IlEdgeKinds::UNCONDITIONAL; 4],
        );
        let mut builder = PCodeToECodeBufferFixtureBuilder::new(source_metadata, graph);
        let read = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::ReadRegister,
                32,
                IlIndexRange::EMPTY,
                9,
                None,
            ))
            .unwrap();
        let constant = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                32,
                IlIndexRange::EMPTY,
                1,
                None,
            ))
            .unwrap();
        let return_operands = builder.push_effect_operands([read]).unwrap();

        builder
            .push_statement(PCodeToECodeEffect::new(
                ECodeOpcode::Return,
                return_operands,
                None,
                None,
                None,
            ))
            .unwrap();
        builder
            .push_statement(
                PCodeToECodeEffect::new(
                    ECodeOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(constant),
                    None,
                    None,
                )
                .with_immediate(9),
            )
            .unwrap();

        let source = builder.build();
        let mut transform = ECodeFixtureBuilder::default();
        let ir = transform.build(source).unwrap();

        assert_eq!(ir.block_args().len(), 1);
        assert_eq!(ir.block_args()[0].block(), loop_header);
        assert_eq!(ir.op_operands()[0], ir.block_args()[0].value());
        assert_eq!(ir.args_for_edge(0).len(), 1);
        assert_eq!(ir.args_for_edge(2).len(), 1);

        let entry_value = ir.args_for_edge(0)[0];
        let back_edge_value = ir.args_for_edge(2)[0];

        assert_eq!(
            ir.defining_op(entry_value).unwrap().opcode(),
            ECodeOpcode::Undefined
        );
        assert_eq!(
            ir.defining_op(back_edge_value).unwrap().opcode(),
            ECodeOpcode::WriteRegister
        );
    }

    #[test]
    fn value_domains_create_distinct_register_and_flag_definitions() {
        let source_metadata = IlMetadata::new(FunctionId::default(), 11);
        let mut builder =
            PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());

        let source_value = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                8,
                IlIndexRange::EMPTY,
                0x2a,
                None,
            ))
            .unwrap();
        builder
            .push_statement(
                PCodeToECodeEffect::new(
                    ECodeOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(source_value),
                    None,
                    None,
                )
                .with_immediate(7),
            )
            .unwrap();

        builder
            .push_statement(
                PCodeToECodeEffect::new(
                    ECodeOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(source_value),
                    None,
                    None,
                )
                .with_immediate(8),
            )
            .unwrap();
        builder
            .push_statement(
                PCodeToECodeEffect::new(
                    ECodeOpcode::WriteFlag,
                    IlIndexRange::EMPTY,
                    Some(source_value),
                    None,
                    None,
                )
                .with_immediate(3),
            )
            .unwrap();

        let register_seven = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::ReadRegister,
                8,
                IlIndexRange::EMPTY,
                7,
                None,
            ))
            .unwrap();
        let register_eight = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::ReadRegister,
                8,
                IlIndexRange::EMPTY,
                8,
                None,
            ))
            .unwrap();
        let flag = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::ReadFlag,
                8,
                IlIndexRange::EMPTY,
                3,
                None,
            ))
            .unwrap();
        let operands = builder
            .push_effect_operands([register_seven, register_eight, flag])
            .unwrap();
        builder
            .push_statement(PCodeToECodeEffect::new(
                ECodeOpcode::Return,
                operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.build();
        let mut transform = ECodeFixtureBuilder::default();
        let ir = transform.build_optimised(source).unwrap();

        assert_eq!(ir.ops()[0].opcode(), ECodeOpcode::Constant);
        assert_eq!(ir.ops()[1].opcode(), ECodeOpcode::WriteRegister);
        assert_eq!(ir.ops()[2].opcode(), ECodeOpcode::WriteRegister);
        assert_eq!(ir.ops()[3].opcode(), ECodeOpcode::WriteFlag);
        assert_eq!(ir.ops()[4].opcode(), ECodeOpcode::Return);

        let register_seven = IlValueId::try_from_index(ir.ops()[1].results().start()).unwrap();
        let register_eight = IlValueId::try_from_index(ir.ops()[2].results().start()).unwrap();
        let flag = IlValueId::try_from_index(ir.ops()[3].results().start()).unwrap();

        assert_eq!(
            ir.value_domain(register_seven),
            Some(ECodeDomain::Register(RegisterId::new(7)))
        );
        assert_eq!(
            ir.value_domain(register_eight),
            Some(ECodeDomain::Register(RegisterId::new(8)))
        );
        assert_eq!(
            ir.value_domain(flag),
            Some(ECodeDomain::Flag(FlagId::new(3)))
        );
        assert_eq!(
            ir.constant_value(register_seven)
                .and_then(|value| value.to_u64()),
            Some(0x2a)
        );
        assert_eq!(
            ir.op_operands_for(&ir.ops()[4]),
            &[register_seven, register_eight, flag]
        );

        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&ir).unwrap();
        let restored = rkyv::from_bytes::<ECodeIr, rkyv::rancor::Error>(&bytes).unwrap();

        assert_eq!(restored, ir);
    }

    #[test]
    fn value_domains_survive_compaction_and_rkyv() {
        let source_metadata = IlMetadata::new(FunctionId::default(), 11);
        let mut builder =
            PCodeToECodeBufferFixtureBuilder::new(source_metadata, IlGraph::default());

        let written = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
                64,
                IlIndexRange::EMPTY,
                0x2a,
                None,
            ))
            .unwrap();
        builder
            .push_statement(
                PCodeToECodeEffect::new(
                    ECodeOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(written),
                    None,
                    None,
                )
                .with_immediate(7),
            )
            .unwrap();

        let read = builder
            .push_expression(PCodeToECodeExpr::new(
                PCodeToECodeExprKind::ReadRegister,
                64,
                IlIndexRange::EMPTY,
                7,
                None,
            ))
            .unwrap();
        let operands = builder.push_effect_operands([read]).unwrap();
        builder
            .push_statement(PCodeToECodeEffect::new(
                ECodeOpcode::Return,
                operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.build();
        let mut transform = ECodeFixtureBuilder::default();
        let ir = transform.build_optimised(source).unwrap();

        let carries_register = |ir: &ECodeIr| {
            (0..ir.values().len()).any(|index| {
                ir.value_domain(IlValueId::try_from_index(index).unwrap())
                    == Some(ECodeDomain::Register(RegisterId::new(7)))
            })
        };

        assert!(carries_register(&ir));

        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&ir).unwrap();
        let restored = rkyv::from_bytes::<ECodeIr, rkyv::rancor::Error>(&bytes).unwrap();

        assert!(carries_register(&restored));
    }
}
