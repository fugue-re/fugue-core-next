use std::collections::{BTreeMap, BTreeSet};
use std::mem;

use fugue_lifter::runtime::language::Language;

use crate::analysis::control::CancellationToken;
use crate::analysis::function::recovery::PartialFunction;
use crate::il::common::{
    IlBlock, IlBlockId, IlDominance, IlError, IlExprId, IlGraph, IlHeader, IlIndexRange, IlLevel,
    IlParentSpan, IlSourceSpan, IlValueId,
};
use crate::il::ecode::ssa::{
    ECODE_SSA_SCHEMA_VERSION, ECodeSsaBuilder, ECodeSsaIr, ECodeSsaOp, ECodeSsaOpcode,
};
use crate::il::ecode::{
    ECodeExpr, ECodeExprOpcode, ECodeIr, ECodeStmt, ECodeStmtOpcode, PCodeToECode,
};
use crate::il::pcode::{PCodeCanonicaliser, PCodeError};
use crate::ir::Address;
use crate::storage::SegmentStorage;
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Default)]
pub struct ECodeToSsa;

pub(crate) struct PartialECodeSsaBuild {
    ir: Option<ECodeSsaIr>,
    omitted_blocks: Vec<Address>,
}

impl PartialECodeSsaBuild {
    pub(crate) fn ir(&self) -> Option<&ECodeSsaIr> {
        self.ir.as_ref()
    }

    pub(crate) fn omits(&self, address: Address) -> bool {
        self.omitted_blocks.binary_search(&address).is_ok()
    }
}

impl ECodeToSsa {
    pub fn transform(
        &mut self,
        source: &ECodeIr,
        cancellation: &CancellationToken,
    ) -> Result<ECodeSsaIr, IlError> {
        cancellation.check()?;

        let header = IlHeader::new(
            source.header().function(),
            ECODE_SSA_SCHEMA_VERSION,
            source.header().input_revision(),
        );
        let mut builder = ECodeSsaBuilder::new(header, source.graph().clone());
        let mut construction = SsaConstruction::new(source, &mut builder);

        construction.construct(cancellation)?;
        drop(construction);

        builder.build(cancellation)
    }

    pub(crate) fn build_partial_function_tolerant(
        &mut self,
        language: &'static Language,
        function: &PartialFunction,
        segments: &SegmentStorage,
        input_revision: u64,
        cancellation: &CancellationToken,
    ) -> Result<PartialECodeSsaBuild, PCodeError> {
        let mut canonicaliser = PCodeCanonicaliser::default();
        let partial = canonicaliser.build_partial_function_tolerant(
            language,
            function,
            segments,
            input_revision,
            cancellation,
        )?;
        let (pcode, omitted_blocks) = partial.into_parts();
        if omitted_blocks.binary_search(&function.entry()).is_ok() {
            return Ok(PartialECodeSsaBuild {
                ir: None,
                omitted_blocks,
            });
        }

        let ecode = PCodeToECode.transform(&pcode, cancellation)?;
        let mut ir = self.transform(&ecode, cancellation)?;
        ir.fold_constants();
        ir.eliminate_dead_code();
        ir.compact();

        Ok(PartialECodeSsaBuild {
            ir: Some(ir),
            omitted_blocks,
        })
    }
}

struct SsaConstruction<'a, 'b> {
    source: &'a ECodeIr,
    builder: &'b mut ECodeSsaBuilder,
    values: Vec<Option<IlValueId>>,
    block_argument_domains: BTreeMap<IlValueId, SsaDomain>,
    block_arguments: Vec<Vec<(SsaDomain, IlValueId)>>,
    domain_widths: BTreeMap<SsaDomain, u32>,
    entry_block: Option<IlBlockId>,
    input_domains: Vec<(SsaDomain, u32)>,
    blocks: Vec<Option<IlBlock>>,
    edge_arguments: Vec<Vec<IlValueId>>,
    statement_ranges: Vec<IlIndexRange>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SsaDomain {
    Flag(u64),
    Memory(AddressSpaceId),
    Register(u64),
}

impl SsaDomain {
    const fn undefined_immediate(&self) -> u64 {
        match self {
            Self::Register(register) | Self::Flag(register) => *register,
            Self::Memory(space) => space.index() as u64,
        }
    }
}

#[derive(Debug, Default)]
struct SsaDomains {
    widths: BTreeMap<SsaDomain, u32>,
    definitions: BTreeMap<SsaDomain, Vec<IlBlockId>>,
    reads: BTreeSet<SsaDomain>,
}

impl<'a, 'b> SsaConstruction<'a, 'b> {
    fn new(source: &'a ECodeIr, builder: &'b mut ECodeSsaBuilder) -> Self {
        Self {
            source,
            builder,
            values: vec![None; source.expressions().len()],
            block_argument_domains: BTreeMap::new(),
            block_arguments: vec![Vec::new(); source.graph().blocks().len()],
            domain_widths: BTreeMap::new(),
            entry_block: None,
            input_domains: Vec::new(),
            blocks: vec![None; source.graph().blocks().len()],
            edge_arguments: vec![Vec::new(); source.graph().successors().len()],
            statement_ranges: vec![IlIndexRange::EMPTY; source.statements().len()],
        }
    }

    fn construct(&mut self, cancellation: &CancellationToken) -> Result<(), IlError> {
        match self.source.graph().entry_block() {
            Some(entry) => self.construct_blocks(entry, cancellation),
            None => self.construct_linear(cancellation),
        }
    }

    fn construct_linear(&mut self, cancellation: &CancellationToken) -> Result<(), IlError> {
        let mut current = BTreeMap::new();

        for index in 0..self.source.statements().len() {
            cancellation.check()?;
            self.construct_statement_at(index, &mut current)?;
        }

        self.builder.replace_graph(IlGraph::new(
            self.source.graph().blocks().to_vec(),
            self.source.graph().successors().to_vec(),
        ));
        self.builder
            .replace_source_spans(self.remap_source_spans()?);
        self.builder
            .replace_parent_spans(self.remap_parent_spans()?);

        Ok(())
    }

    fn construct_blocks(
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
        self.construct_block_tree(entry, &dominance, BTreeMap::new(), cancellation)?;

        for block_index in 0..source_graph.blocks().len() {
            let block_id = IlBlockId::try_from_index(block_index)?;

            if self.blocks[block_index].is_none() {
                self.construct_block(block_id, BTreeMap::new(), cancellation)?;
            }
        }

        self.builder.clear_edge_arguments();
        for arguments in mem::take(&mut self.edge_arguments) {
            self.builder.push_edge_arguments(arguments)?;
        }
        self.builder.replace_graph(IlGraph::new(
            mem::take(&mut self.blocks)
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .expect("every block is constructed before the graph is replaced"),
            source_graph.successors().to_vec(),
        ));
        self.builder
            .replace_source_spans(self.remap_source_spans()?);
        self.builder
            .replace_parent_spans(self.remap_parent_spans()?);

        Ok(())
    }

    fn discover_domains(&self) -> Result<SsaDomains, IlError> {
        let mut domains = SsaDomains::default();

        for (block_index, block) in self.source.graph().blocks().iter().enumerate() {
            let block_id = IlBlockId::try_from_index(block_index)?;

            for statement_index in block.operations().start()..block.operations().end() {
                let statement = &self.source.statements()[statement_index];

                match statement.opcode() {
                    ECodeStmtOpcode::WriteRegister => {
                        let width = self.statement_value_width(statement)?;
                        let domain = SsaDomain::Register(statement.immediate());

                        Self::record_domain_width(&mut domains.widths, domain, width)?;
                        domains
                            .definitions
                            .entry(domain)
                            .or_default()
                            .push(block_id);
                    }
                    ECodeStmtOpcode::WriteFlag => {
                        let width = self.statement_value_width(statement)?;
                        let domain = SsaDomain::Flag(statement.immediate());

                        Self::record_domain_width(&mut domains.widths, domain, width)?;
                        domains
                            .definitions
                            .entry(domain)
                            .or_default()
                            .push(block_id);
                    }
                    ECodeStmtOpcode::Store => {
                        let space = statement
                            .address_space()
                            .ok_or(IlError::missing_component(IlLevel::ECode, "address space"))?;
                        let domain = SsaDomain::Memory(space);

                        Self::record_domain_width(&mut domains.widths, domain, 0)?;
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

        for expression in self.source.expressions() {
            match expression.opcode() {
                ECodeExprOpcode::ReadRegister => {
                    let domain = SsaDomain::Register(expression.immediate());
                    Self::record_domain_width(&mut domains.widths, domain, expression.width())?;
                    domains.reads.insert(domain);
                }
                ECodeExprOpcode::ReadFlag => {
                    let domain = SsaDomain::Flag(expression.immediate());
                    Self::record_domain_width(&mut domains.widths, domain, expression.width())?;
                    domains.reads.insert(domain);
                }
                ECodeExprOpcode::Load => {
                    let space = expression
                        .address_space()
                        .ok_or(IlError::missing_component(IlLevel::ECode, "address space"))?;

                    Self::record_domain_width(&mut domains.widths, SsaDomain::Memory(space), 0)?;
                }
                _ => {}
            }
        }

        for definitions in domains.definitions.values_mut() {
            definitions.sort();
            definitions.dedup();
        }

        Ok(domains)
    }

    fn statement_value_width(&self, statement: &ECodeStmt) -> Result<u32, IlError> {
        let value = statement
            .value()
            .ok_or(IlError::missing_component(IlLevel::ECode, "value"))?;
        Ok(self.source.expressions()[value.index()].width())
    }

    fn record_domain_width(
        widths: &mut BTreeMap<SsaDomain, u32>,
        domain: SsaDomain,
        width: u32,
    ) -> Result<(), IlError> {
        if let Some(existing) = widths.get(&domain) {
            if *existing != width {
                return Err(IlError::width_mismatch(IlLevel::ECodeSsa));
            }
        } else {
            widths.insert(domain, width);
        }

        Ok(())
    }

    fn place_block_arguments(
        &mut self,
        domains: &SsaDomains,
        dominance: &IlDominance,
    ) -> Result<(), IlError> {
        let frontiers = dominance.frontiers(
            self.source.graph().blocks(),
            self.source.graph().successors(),
        );
        let block_count = self.source.graph().blocks().len();
        let mut placed = BTreeSet::new();

        for (domain, definitions) in &domains.definitions {
            let width = domains.widths[domain];
            let placement = frontiers.place_phis(block_count, definitions.iter().copied());

            for block in placement.blocks() {
                if !placed.insert((*block, *domain)) {
                    continue;
                }

                let value = self.builder.push_block_argument_value(*block, width)?;
                self.block_argument_domains.insert(value, *domain);
                self.block_arguments[block.index()].push((*domain, value));
            }
        }

        for arguments in &mut self.block_arguments {
            arguments.sort_by_key(|(domain, _)| *domain);
        }

        Ok(())
    }

    fn construct_block_tree(
        &mut self,
        block: IlBlockId,
        dominance: &IlDominance,
        current: BTreeMap<SsaDomain, IlValueId>,
        cancellation: &CancellationToken,
    ) -> Result<(), IlError> {
        let mut stack = Vec::new();
        stack.push((block, current));

        while let Some((block, current)) = stack.pop() {
            let current = self.construct_block(block, current, cancellation)?;

            for child in dominance.children(block).iter().rev() {
                stack.push((*child, current.clone()));
            }
        }

        Ok(())
    }

    fn construct_block(
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
            self.construct_statement_at(statement_index, &mut current)?;
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
            let block_arguments = self.block_arguments[successor.index()].clone();

            for (domain, _) in block_arguments {
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

    fn construct_statement_at(
        &mut self,
        index: usize,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<(), IlError> {
        self.values.fill(None);
        let start = self.builder.operation_count();
        let statement = &self.source.statements()[index];

        self.construct_statement(statement, current)?;

        let end = self.builder.operation_count();
        self.statement_ranges[index] = IlIndexRange::new(start, end)?;

        Ok(())
    }

    fn construct_statement(
        &mut self,
        statement: &ECodeStmt,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<(), IlError> {
        match statement.opcode() {
            ECodeStmtOpcode::WriteRegister => {
                let value = self.construct_statement_value(statement, current)?;
                current.insert(SsaDomain::Register(statement.immediate()), value);
            }
            ECodeStmtOpcode::WriteFlag => {
                let value = self.construct_statement_value(statement, current)?;
                current.insert(SsaDomain::Flag(statement.immediate()), value);
            }
            ECodeStmtOpcode::Store => {
                let address_space = statement
                    .address_space()
                    .ok_or(IlError::missing_component(IlLevel::ECode, "address space"))?;
                let mut operands = self.construct_statement_operands(statement, current)?;
                let memory = self.current_memory(address_space, current)?;

                operands.push(memory);

                let operands = self.builder.push_value_operands(operands)?;
                let (memory, results) = self.builder.push_result_value(0)?;
                let operation = ECodeSsaOp::new(ECodeSsaOpcode::Store, results, operands, 0)
                    .with_address_space(address_space)
                    .with_immediate(statement.immediate());

                self.builder.push_operation(operation)?;
                current.insert(SsaDomain::Memory(address_space), memory);
            }
            opcode => {
                let invalidates_state = matches!(
                    statement.opcode(),
                    ECodeStmtOpcode::Call | ECodeStmtOpcode::CallIndirect
                );
                let operands = self.construct_statement_operands(statement, current)?;
                let operands = self.builder.push_value_operands(operands)?;
                let opcode = ECodeSsaOpcode::from_statement(opcode)
                    .ok_or(IlError::unsupported_opcode(IlLevel::ECodeSsa))?;
                let mut operation = ECodeSsaOp::new(opcode, IlIndexRange::EMPTY, operands, 0)
                    .with_immediate(statement.immediate());

                if let Some(address) = statement.address() {
                    operation = operation.with_address(address);
                }

                if let Some(address_space) = statement.address_space() {
                    if opcode.requires_memory_domain() {
                        self.builder.ensure_memory_domain(address_space);
                    }

                    operation = operation.with_address_space(address_space);
                }

                self.builder.push_operation(operation)?;
                if invalidates_state {
                    current.clear();
                }
            }
        }

        Ok(())
    }

    fn construct_statement_value(
        &mut self,
        statement: &ECodeStmt,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<IlValueId, IlError> {
        let value = statement
            .value()
            .ok_or(IlError::missing_component(IlLevel::ECode, "value"))?;

        self.construct_expression(value, current)
    }

    fn construct_statement_operands(
        &mut self,
        statement: &ECodeStmt,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<Vec<IlValueId>, IlError> {
        let mut operands = Vec::new();

        if let Some(value) = statement.value() {
            operands.push(self.construct_expression(value, current)?);
        }

        for operand in self.source.statement_operands_for(statement) {
            operands.push(self.construct_expression(*operand, current)?);
        }

        Ok(operands)
    }

    fn construct_expression(
        &mut self,
        id: IlExprId,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<IlValueId, IlError> {
        if let Some(value) = self.values.get(id.index()).and_then(|value| *value) {
            return Ok(value);
        }

        let expression = self.source.expressions()[id.index()];

        let value = match expression.opcode() {
            ECodeExprOpcode::ReadRegister => self.construct_read_register(&expression, current)?,
            ECodeExprOpcode::ReadFlag => self.construct_read_flag(&expression, current)?,
            opcode => self.construct_value_expression(&expression, opcode, current)?,
        };

        if let Some(slot) = self.values.get_mut(id.index()) {
            *slot = Some(value);
        }

        Ok(value)
    }

    fn construct_read_register(
        &mut self,
        expression: &ECodeExpr,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<IlValueId, IlError> {
        let domain = SsaDomain::Register(expression.immediate());

        if let Some(value) = current.get(&domain).copied() {
            return Ok(value);
        }

        let value = self.push_undefined(domain, expression.width())?;

        current.insert(domain, value);

        Ok(value)
    }

    fn construct_read_flag(
        &mut self,
        expression: &ECodeExpr,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<IlValueId, IlError> {
        let domain = SsaDomain::Flag(expression.immediate());

        if let Some(value) = current.get(&domain).copied() {
            return Ok(value);
        }

        let value = self.push_undefined(domain, expression.width())?;

        current.insert(domain, value);

        Ok(value)
    }

    fn construct_value_expression(
        &mut self,
        expression: &ECodeExpr,
        opcode: ECodeExprOpcode,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<IlValueId, IlError> {
        let operands = self.construct_expression_operands(expression, current)?;
        let mut operands = operands;
        if opcode == ECodeExprOpcode::Load {
            let address_space = expression
                .address_space()
                .ok_or(IlError::missing_component(IlLevel::ECode, "address space"))?;
            let memory = self.current_memory(address_space, current)?;

            operands.push(memory);
        }

        let operands = self.builder.push_value_operands(operands)?;
        let opcode = ECodeSsaOpcode::from_expression(opcode)
            .ok_or(IlError::unsupported_opcode(IlLevel::ECodeSsa))?;

        self.push_value_operation(
            opcode,
            expression.width(),
            operands,
            expression.immediate(),
            expression.address_space(),
        )
    }

    fn construct_expression_operands(
        &mut self,
        expression: &ECodeExpr,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<Vec<IlValueId>, IlError> {
        let mut operands = Vec::new();

        for operand in self.source.expression_operands_for(expression) {
            operands.push(self.construct_expression(*operand, current)?);
        }

        Ok(operands)
    }

    fn current_memory(
        &mut self,
        address_space: AddressSpaceId,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<IlValueId, IlError> {
        let domain = SsaDomain::Memory(address_space);

        if let Some(value) = current.get(&domain).copied() {
            return Ok(value);
        }

        let value = self.push_undefined(domain, 0)?;

        current.insert(domain, value);

        Ok(value)
    }

    fn push_undefined(&mut self, domain: SsaDomain, width: u32) -> Result<IlValueId, IlError> {
        self.push_value_operation(
            ECodeSsaOpcode::Undefined,
            width,
            IlIndexRange::EMPTY,
            domain.undefined_immediate(),
            None,
        )
    }

    fn push_value_operation(
        &mut self,
        opcode: ECodeSsaOpcode,
        width: u32,
        operands: IlIndexRange,
        immediate: u64,
        address_space: Option<AddressSpaceId>,
    ) -> Result<IlValueId, IlError> {
        let (value, results) = self.builder.push_result_value(width)?;
        let mut operation =
            ECodeSsaOp::new(opcode, results, operands, width).with_immediate(immediate);

        if let Some(address_space) = address_space {
            if opcode.requires_memory_domain() {
                self.builder.ensure_memory_domain(address_space);
            }

            operation = operation.with_address_space(address_space);
        }

        self.builder.push_operation(operation)?;

        Ok(value)
    }

    fn remap_source_spans(&self) -> Result<Vec<IlSourceSpan>, IlError> {
        let mut destinations = Vec::new();
        let mut runs = Vec::new();

        for run in self.source.source_spans() {
            self.remap_destination_runs(run.destination(), &mut destinations)?;
            for &destination in &destinations {
                runs.push(IlSourceSpan::new(
                    destination,
                    run.address(),
                    run.first_pcode_index(),
                    run.pcode_count(),
                ));
            }
        }

        runs.sort_unstable_by_key(|run| run.destination().start());
        let mut merged = Vec::<IlSourceSpan>::with_capacity(runs.len());
        for run in runs {
            if let Some(previous) = merged.last_mut()
                && previous.try_merge(run)?
            {
                continue;
            }
            merged.push(run);
        }
        Ok(merged)
    }

    fn remap_parent_spans(&self) -> Result<Vec<IlParentSpan>, IlError> {
        let mut destinations = Vec::new();
        let mut runs = Vec::new();

        for run in self.source.parent_spans() {
            self.remap_destination_runs(run.destination(), &mut destinations)?;
            for &destination in &destinations {
                runs.push(IlParentSpan::new(destination, run.source()));
            }
        }

        runs.sort_unstable_by_key(|run| run.destination().start());
        Ok(runs)
    }

    fn remap_destination_runs(
        &self,
        destination: IlIndexRange,
        runs: &mut Vec<IlIndexRange>,
    ) -> Result<(), IlError> {
        runs.clear();

        for statement_index in destination.start()..destination.end() {
            let range = self.statement_ranges[statement_index];

            if range.is_empty() {
                continue;
            }

            if let Some(previous) = runs.last_mut()
                && previous.end() == range.start()
            {
                *previous = IlIndexRange::new(previous.start(), range.end())?;
            } else {
                runs.push(range);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::{IlBlock, IlBlockId, IlBlockProperties, IlGraph};
    use crate::il::ecode::{ECODE_SCHEMA_VERSION, ECodeBuilder, ECodeExpr, ECodeStmt};
    use crate::ir::{Address, FunctionId};
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn empty_ecode_constructs_empty_ssa() {
        let source_header = IlHeader::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
        let source = ECodeBuilder::new(source_header, IlGraph::default())
            .build(&CancellationToken::default())
            .unwrap();
        let cancellation = CancellationToken::default();
        let mut transform = ECodeToSsa;

        let ssa = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(ssa.header().input_revision(), 11);
        assert!(ssa.operations().is_empty());
    }

    #[test]
    fn register_read_after_write_uses_current_value() {
        let source_header = IlHeader::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
        let mut builder = ECodeBuilder::new(source_header, IlGraph::default());
        let value = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                64,
                IlIndexRange::EMPTY,
                0x2a,
                None,
            ))
            .unwrap();

        builder
            .push_statement(
                ECodeStmt::new(
                    ECodeStmtOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(value),
                    None,
                    None,
                )
                .with_immediate(7),
            )
            .unwrap();

        let read = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::ReadRegister,
                64,
                IlIndexRange::EMPTY,
                7,
                None,
            ))
            .unwrap();
        let operands = builder.push_statement_operands([read]).unwrap();

        builder
            .push_statement(ECodeStmt::new(
                ECodeStmtOpcode::Return,
                operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.build(&CancellationToken::default()).unwrap();
        let cancellation = CancellationToken::default();
        let mut transform = ECodeToSsa;
        let ssa = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(ssa.operations()[0].opcode(), ECodeSsaOpcode::Constant);
        assert_eq!(ssa.operations()[1].opcode(), ECodeSsaOpcode::Return);
        assert_eq!(ssa.value_operands().len(), 1);
        assert_eq!(
            ssa.value_operands()[0],
            IlValueId::try_from_index(ssa.operations()[0].results().start()).unwrap()
        );
    }

    #[test]
    fn register_read_without_write_becomes_undefined() {
        let source_header = IlHeader::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
        let mut builder = ECodeBuilder::new(source_header, IlGraph::default());
        let read = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::ReadRegister,
                32,
                IlIndexRange::EMPTY,
                9,
                None,
            ))
            .unwrap();
        let operands = builder.push_statement_operands([read]).unwrap();

        builder
            .push_statement(ECodeStmt::new(
                ECodeStmtOpcode::Return,
                operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.build(&CancellationToken::default()).unwrap();
        let cancellation = CancellationToken::default();
        let mut transform = ECodeToSsa;
        let ssa = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(ssa.operations()[0].opcode(), ECodeSsaOpcode::Undefined);
        assert_eq!(ssa.operations()[0].width(), 32);
        assert_eq!(ssa.operations()[0].immediate(), 9);
        assert_eq!(ssa.operations()[1].opcode(), ECodeSsaOpcode::Return);
    }

    #[test]
    fn load_preserves_fugue_address_space() {
        let source_header = IlHeader::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
        let mut builder = ECodeBuilder::new(source_header, IlGraph::default());
        let offset = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                64,
                IlIndexRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let load_operands = builder.push_expression_operands([offset]).unwrap();
        let space = AddressSpaceId::new(3);
        let load = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Load,
                8,
                load_operands,
                0,
                Some(space),
            ))
            .unwrap();
        let return_operands = builder.push_statement_operands([load]).unwrap();

        builder
            .push_statement(ECodeStmt::new(
                ECodeStmtOpcode::Return,
                return_operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.build(&CancellationToken::default()).unwrap();
        let cancellation = CancellationToken::default();
        let mut transform = ECodeToSsa;
        let ssa = transform.transform(&source, &cancellation).unwrap();

        let load_index = ssa
            .operations()
            .iter()
            .position(|operation| operation.opcode() == ECodeSsaOpcode::Load)
            .unwrap();

        assert_eq!(ssa.operations()[load_index].address_space(), Some(space));
        assert_eq!(ssa.memory_domains().len(), 1);
        assert_eq!(ssa.memory_domains()[0].space(), space);

        let operands = ssa.operation_operands(&ssa.operations()[load_index]);
        let memory = ssa.values()[operands.last().unwrap().index()];

        assert_eq!(memory.width(), 0);
    }

    #[test]
    fn load_after_store_uses_store_memory_result() {
        let source_header = IlHeader::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
        let mut builder = ECodeBuilder::new(source_header, IlGraph::default());
        let space = AddressSpaceId::new(3);
        let store_address = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                64,
                IlIndexRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let store_value = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                32,
                IlIndexRange::EMPTY,
                0x2a,
                None,
            ))
            .unwrap();
        let store_operands = builder
            .push_statement_operands([store_address, store_value])
            .unwrap();

        builder
            .push_statement(ECodeStmt::new(
                ECodeStmtOpcode::Store,
                store_operands,
                None,
                None,
                Some(space),
            ))
            .unwrap();

        let load_address = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                64,
                IlIndexRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let load_operands = builder.push_expression_operands([load_address]).unwrap();
        let load = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Load,
                32,
                load_operands,
                0,
                Some(space),
            ))
            .unwrap();
        let return_operands = builder.push_statement_operands([load]).unwrap();

        builder
            .push_statement(ECodeStmt::new(
                ECodeStmtOpcode::Return,
                return_operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.build(&CancellationToken::default()).unwrap();
        let cancellation = CancellationToken::default();
        let mut transform = ECodeToSsa;
        let ssa = transform.transform(&source, &cancellation).unwrap();
        let store_index = ssa
            .operations()
            .iter()
            .position(|operation| operation.opcode() == ECodeSsaOpcode::Store)
            .unwrap();
        let load_index = ssa
            .operations()
            .iter()
            .position(|operation| operation.opcode() == ECodeSsaOpcode::Load)
            .unwrap();
        let store_memory =
            IlValueId::try_from_index(ssa.operations()[store_index].results().start()).unwrap();
        let load_operands = ssa.operation_operands(&ssa.operations()[load_index]);

        assert_eq!(ssa.memory_domains().len(), 1);
        assert_eq!(ssa.memory_domains()[0].space(), space);
        assert_eq!(ssa.values()[store_memory.index()].width(), 0);
        assert_eq!(*load_operands.last().unwrap(), store_memory);
    }

    #[test]
    fn direct_branch_preserves_fugue_address() {
        let source_header = IlHeader::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
        let mut builder = ECodeBuilder::new(source_header, IlGraph::default());
        let condition = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                1,
                IlIndexRange::EMPTY,
                1,
                None,
            ))
            .unwrap();
        let target_expression = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                64,
                IlIndexRange::EMPTY,
                0x2000,
                None,
            ))
            .unwrap();
        let operands = builder
            .push_statement_operands([condition, target_expression])
            .unwrap();
        let target = Address::new(AddressSpaceId::new(4), 0x2000u64);

        builder
            .push_statement(ECodeStmt::new(
                ECodeStmtOpcode::ConditionalBranch,
                operands,
                None,
                Some(target),
                None,
            ))
            .unwrap();

        let source = builder.build(&CancellationToken::default()).unwrap();
        let cancellation = CancellationToken::default();
        let mut transform = ECodeToSsa;
        let ssa = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(
            ssa.operations()[2].opcode(),
            ECodeSsaOpcode::ConditionalBranch
        );
        assert_eq!(ssa.operations()[2].address(), Some(target));
    }

    #[test]
    fn deep_dominance_chain_constructs_iteratively() {
        let source_header = IlHeader::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
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

        let graph = IlGraph::new(blocks, successors);
        let mut builder = ECodeBuilder::new(source_header, graph);

        for index in 0..block_count {
            let value = builder
                .push_expression(ECodeExpr::new(
                    ECodeExprOpcode::Constant,
                    64,
                    IlIndexRange::EMPTY,
                    index as u64,
                    None,
                ))
                .unwrap();

            builder
                .push_statement(
                    ECodeStmt::new(
                        ECodeStmtOpcode::WriteRegister,
                        IlIndexRange::EMPTY,
                        Some(value),
                        None,
                        None,
                    )
                    .with_immediate(7),
                )
                .unwrap();
        }

        let source = builder.build(&CancellationToken::default()).unwrap();
        let cancellation = CancellationToken::default();
        let mut transform = ECodeToSsa;
        let ssa = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(ssa.graph().blocks().len(), block_count);
        assert_eq!(ssa.graph().successors().len(), block_count - 1);
        assert_eq!(ssa.operations().len(), block_count);
        assert!(ssa.block_arguments().is_empty());
    }

    #[test]
    fn merge_block_register_read_becomes_block_argument() {
        let source_header = IlHeader::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
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
            successors,
        );
        let mut builder = ECodeBuilder::new(source_header, graph);
        let left = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                64,
                IlIndexRange::EMPTY,
                1,
                None,
            ))
            .unwrap();
        let right = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                64,
                IlIndexRange::EMPTY,
                2,
                None,
            ))
            .unwrap();
        let read = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::ReadRegister,
                64,
                IlIndexRange::EMPTY,
                7,
                None,
            ))
            .unwrap();

        builder
            .push_statement(
                ECodeStmt::new(
                    ECodeStmtOpcode::WriteRegister,
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
                ECodeStmt::new(
                    ECodeStmtOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(right),
                    None,
                    None,
                )
                .with_immediate(7),
            )
            .unwrap();
        let operands = builder.push_statement_operands([read]).unwrap();
        builder
            .push_statement(ECodeStmt::new(
                ECodeStmtOpcode::Return,
                operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.build(&CancellationToken::default()).unwrap();
        let cancellation = CancellationToken::default();
        let mut transform = ECodeToSsa;
        let ssa = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(ssa.block_arguments().len(), 1);
        assert_eq!(
            ssa.block_arguments()[0].block(),
            IlBlockId::try_from_index(3).unwrap()
        );
        assert_eq!(ssa.operations()[2].opcode(), ECodeSsaOpcode::Return);
        assert_eq!(ssa.value_operands()[0], ssa.block_arguments()[0].value());
        assert_eq!(ssa.edge_arguments().len(), 4);
        assert_eq!(ssa.edge_argument_values().len(), 2);
        assert!(ssa.edge_arguments()[0].is_empty());
        assert!(ssa.edge_arguments()[1].is_empty());
        assert_eq!(ssa.arguments_for_edge(2).len(), 1);
        assert_eq!(ssa.arguments_for_edge(3).len(), 1);
    }

    #[test]
    fn merge_block_load_uses_memory_block_argument() {
        let source_header = IlHeader::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
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
            successors,
        );
        let mut builder = ECodeBuilder::new(source_header, graph);
        let space = AddressSpaceId::new(3);
        let store_address = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                64,
                IlIndexRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let store_value = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                32,
                IlIndexRange::EMPTY,
                0x2a,
                None,
            ))
            .unwrap();
        let load_address = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                64,
                IlIndexRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let load_operands = builder.push_expression_operands([load_address]).unwrap();
        let load = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Load,
                32,
                load_operands,
                0,
                Some(space),
            ))
            .unwrap();
        let store_operands = builder
            .push_statement_operands([store_address, store_value])
            .unwrap();

        builder
            .push_statement(ECodeStmt::new(
                ECodeStmtOpcode::Store,
                store_operands,
                None,
                None,
                Some(space),
            ))
            .unwrap();

        let return_operands = builder.push_statement_operands([load]).unwrap();

        builder
            .push_statement(ECodeStmt::new(
                ECodeStmtOpcode::Return,
                return_operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.build(&CancellationToken::default()).unwrap();
        let cancellation = CancellationToken::default();
        let mut transform = ECodeToSsa;
        let ssa = transform.transform(&source, &cancellation).unwrap();
        let load_index = ssa
            .operations()
            .iter()
            .position(|operation| operation.opcode() == ECodeSsaOpcode::Load)
            .unwrap();
        let load_operands = ssa.operation_operands(&ssa.operations()[load_index]);

        assert_eq!(ssa.memory_domains().len(), 1);
        assert_eq!(ssa.memory_domains()[0].space(), space);
        assert_eq!(ssa.block_arguments().len(), 1);
        assert_eq!(ssa.block_arguments()[0].block(), join);
        assert_eq!(
            ssa.values()[ssa.block_arguments()[0].value().index()].width(),
            0
        );
        assert_eq!(
            *load_operands.last().unwrap(),
            ssa.block_arguments()[0].value()
        );
        assert!(ssa.arguments_for_edge(0).is_empty());
        assert!(ssa.arguments_for_edge(1).is_empty());
        assert_eq!(ssa.arguments_for_edge(2).len(), 1);
        assert_eq!(ssa.arguments_for_edge(3).len(), 1);
    }

    #[test]
    fn loop_carried_register_uses_header_block_argument() {
        let source_header = IlHeader::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 11);
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
        );
        let mut builder = ECodeBuilder::new(source_header, graph);
        let read = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::ReadRegister,
                32,
                IlIndexRange::EMPTY,
                9,
                None,
            ))
            .unwrap();
        let constant = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                32,
                IlIndexRange::EMPTY,
                1,
                None,
            ))
            .unwrap();
        let return_operands = builder.push_statement_operands([read]).unwrap();

        builder
            .push_statement(ECodeStmt::new(
                ECodeStmtOpcode::Return,
                return_operands,
                None,
                None,
                None,
            ))
            .unwrap();
        builder
            .push_statement(
                ECodeStmt::new(
                    ECodeStmtOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(constant),
                    None,
                    None,
                )
                .with_immediate(9),
            )
            .unwrap();

        let source = builder.build(&CancellationToken::default()).unwrap();
        let cancellation = CancellationToken::default();
        let mut transform = ECodeToSsa;
        let ssa = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(ssa.block_arguments().len(), 1);
        assert_eq!(ssa.block_arguments()[0].block(), loop_header);
        assert_eq!(ssa.value_operands()[0], ssa.block_arguments()[0].value());
        assert_eq!(ssa.arguments_for_edge(0).len(), 1);
        assert_eq!(ssa.arguments_for_edge(2).len(), 1);

        let entry_value = ssa.arguments_for_edge(0)[0];
        let back_edge_value = ssa.arguments_for_edge(2)[0];

        assert_eq!(
            ssa.operations()[ssa.values()[entry_value.index()].definition_index() as usize]
                .opcode(),
            ECodeSsaOpcode::Undefined
        );
        assert_eq!(
            ssa.operations()[ssa.values()[back_edge_value.index()].definition_index() as usize]
                .opcode(),
            ECodeSsaOpcode::Constant
        );
    }
}
