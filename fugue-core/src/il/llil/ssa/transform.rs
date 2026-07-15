use std::collections::{BTreeMap, BTreeSet};
use std::mem;

use crate::il::common::{
    ArtefactHeader, Block, BlockId, CommonBody, ExpressionId, Finish, IlError, IrLevel, MappingRun,
    PackedRange, SourceRun, Transform, TransformContext, ValueId,
};
use crate::il::llil::ssa::{
    Dominance, LLIL_SSA_SCHEMA_VERSION, SsaBody, SsaBuilder, SsaOpcode, SsaOperation,
};
use crate::il::llil::{Expression, ExpressionOpcode, LlilBody, Statement, StatementOpcode};
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Default)]
pub struct LlilToSsa;

impl Transform<LlilBody, SsaBody> for LlilToSsa {
    fn transform(
        &mut self,
        source: &LlilBody,
        context: &mut TransformContext<'_>,
    ) -> Result<SsaBody, IlError> {
        context.check_cancelled()?;

        let mut header = ArtefactHeader::new(
            source.header().function(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            source.header().input_revision(),
        );
        header.set_parent_digest(source.header().content_digest());
        let mut builder = SsaBuilder::new(header, source.common().clone());
        let mut lowering = SsaLowering::new(source, &mut builder);

        let body = match lowering.lower(context) {
            Ok(()) => {
                drop(lowering);
                builder.finish(context.cancellation())
            }
            Err(error) => Err(error),
        };

        context.finish(body)
    }
}

struct SsaLowering<'a, 'b> {
    source: &'a LlilBody,
    builder: &'b mut SsaBuilder,
    values: Vec<Option<ValueId>>,
    block_argument_domains: BTreeMap<ValueId, SsaDomain>,
    block_arguments: Vec<Vec<(SsaDomain, ValueId)>>,
    domain_widths: BTreeMap<SsaDomain, u32>,
    blocks: Vec<Option<Block>>,
    edge_arguments: Vec<Vec<ValueId>>,
    statement_ranges: Vec<PackedRange>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SsaDomain {
    Register(u64),
    Flag(u64),
    Memory(AddressSpaceId),
}

impl SsaDomain {
    const fn width_source(&self) -> &'static str {
        match self {
            Self::Register(_) => "SSA register domain width",
            Self::Flag(_) => "SSA flag domain width",
            Self::Memory(_) => "SSA memory domain width",
        }
    }

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
    definitions: BTreeMap<SsaDomain, Vec<BlockId>>,
}

impl<'a, 'b> SsaLowering<'a, 'b> {
    fn new(source: &'a LlilBody, builder: &'b mut SsaBuilder) -> Self {
        Self {
            source,
            builder,
            values: vec![None; source.expressions().len()],
            block_argument_domains: BTreeMap::new(),
            block_arguments: vec![Vec::new(); source.common().blocks().len()],
            domain_widths: BTreeMap::new(),
            blocks: vec![None; source.common().blocks().len()],
            edge_arguments: vec![Vec::new(); source.common().successors().len()],
            statement_ranges: vec![PackedRange::EMPTY; source.statements().len()],
        }
    }

    fn lower(&mut self, context: &mut TransformContext<'_>) -> Result<(), IlError> {
        if self.source.common().blocks().is_empty() {
            self.lower_linear(context)?;
        } else {
            self.lower_blocks(context)?;
        }

        Ok(())
    }

    fn lower_linear(&mut self, context: &mut TransformContext<'_>) -> Result<(), IlError> {
        let mut current = BTreeMap::new();

        for index in 0..self.source.statements().len() {
            context.check_cancelled()?;
            self.lower_statement_at(index, &mut current)?;
        }

        let common = CommonBody::new(
            self.source.common().blocks().to_vec(),
            self.source.common().successors().to_vec(),
            self.remap_source_runs()?,
            self.remap_mapping_runs()?,
        );
        self.builder.replace_common(common);

        Ok(())
    }

    fn lower_blocks(&mut self, context: &mut TransformContext<'_>) -> Result<(), IlError> {
        let source_common = self.source.common();
        let entry = self.source.common().entry_block()?;
        let dominance =
            Dominance::from_blocks(source_common.blocks(), source_common.successors(), entry)?;
        let domains = self.discover_domains()?;

        self.place_block_arguments(&domains, &dominance)?;
        self.domain_widths = domains.widths;
        self.blocks = vec![None; source_common.blocks().len()];
        self.edge_arguments = vec![Vec::new(); source_common.successors().len()];
        self.lower_block_tree(entry, &dominance, BTreeMap::new(), context)?;

        for block_index in 0..source_common.blocks().len() {
            let block_id = BlockId::try_from_index(block_index)?;

            if self.blocks[block_index].is_none() {
                self.lower_block(block_id, BTreeMap::new(), context)?;
            }
        }

        self.builder.clear_edge_arguments();
        for arguments in mem::take(&mut self.edge_arguments) {
            self.builder.push_edge_arguments(arguments)?;
        }
        let common = CommonBody::new(
            mem::take(&mut self.blocks)
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .ok_or(IlError::llil_ssa_invalid_operation_placement(u32::MAX))?,
            source_common.successors().to_vec(),
            self.remap_source_runs()?,
            self.remap_mapping_runs()?,
        );
        self.builder.replace_common(common);

        Ok(())
    }

    fn discover_domains(&self) -> Result<SsaDomains, IlError> {
        let mut domains = SsaDomains::default();

        for (block_index, block) in self.source.common().blocks().iter().enumerate() {
            let block_id = BlockId::try_from_index(block_index)?;

            for statement_index in block.operations().start()..block.operations().end() {
                let statement = self.source.statements().get(statement_index).ok_or(
                    IlError::range_out_of_bounds(
                        u32::try_from(statement_index).unwrap_or(u32::MAX),
                        self.source.statements().len(),
                    ),
                )?;

                match statement.opcode() {
                    StatementOpcode::WriteRegister => {
                        let width = self.statement_value_width(statement)?;
                        let domain = SsaDomain::Register(statement.immediate());

                        Self::record_domain_width(&mut domains.widths, domain, width)?;
                        domains
                            .definitions
                            .entry(domain)
                            .or_default()
                            .push(block_id);
                    }
                    StatementOpcode::WriteFlag => {
                        let width = self.statement_value_width(statement)?;
                        let domain = SsaDomain::Flag(statement.immediate());

                        Self::record_domain_width(&mut domains.widths, domain, width)?;
                        domains
                            .definitions
                            .entry(domain)
                            .or_default()
                            .push(block_id);
                    }
                    StatementOpcode::Store => {
                        let space = statement
                            .address_space()
                            .ok_or(IlError::llil_missing_address_space())?;
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
                ExpressionOpcode::ReadRegister => Self::record_domain_width(
                    &mut domains.widths,
                    SsaDomain::Register(expression.immediate()),
                    expression.width(),
                )?,
                ExpressionOpcode::ReadFlag => Self::record_domain_width(
                    &mut domains.widths,
                    SsaDomain::Flag(expression.immediate()),
                    expression.width(),
                )?,
                ExpressionOpcode::Load => {
                    let space = expression
                        .address_space()
                        .ok_or(IlError::llil_missing_address_space())?;

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

    fn statement_value_width(&self, statement: &Statement) -> Result<u32, IlError> {
        let value = statement.value().ok_or(IlError::llil_missing_value())?;
        let expression =
            self.source
                .expressions()
                .get(value.index())
                .ok_or(IlError::range_out_of_bounds(
                    value.value(),
                    self.source.expressions().len(),
                ))?;

        Ok(expression.width())
    }

    fn record_domain_width(
        widths: &mut BTreeMap<SsaDomain, u32>,
        domain: SsaDomain,
        width: u32,
    ) -> Result<(), IlError> {
        if let Some(existing) = widths.get(&domain) {
            if *existing != width {
                return Err(IlError::llil_ssa_width_mismatch());
            }
        } else {
            widths.insert(domain, width);
        }

        Ok(())
    }

    fn place_block_arguments(
        &mut self,
        domains: &SsaDomains,
        dominance: &Dominance,
    ) -> Result<(), IlError> {
        let frontiers = dominance.frontiers(
            self.source.common().blocks(),
            self.source.common().successors(),
        )?;
        let block_count = self.source.common().blocks().len();
        let mut placed = BTreeSet::new();

        for (domain, definitions) in &domains.definitions {
            let width = *domains
                .widths
                .get(domain)
                .ok_or(IlError::integer_overflow(domain.width_source()))?;
            let placement = frontiers.place_phis(block_count, definitions.iter().copied())?;

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

    fn lower_block_tree(
        &mut self,
        block: BlockId,
        dominance: &Dominance,
        current: BTreeMap<SsaDomain, ValueId>,
        context: &mut TransformContext<'_>,
    ) -> Result<(), IlError> {
        let mut stack = Vec::new();
        stack.push((block, current));

        while let Some((block, current)) = stack.pop() {
            let current = self.lower_block(block, current, context)?;

            for child in dominance.children(block).iter().rev() {
                stack.push((*child, current.clone()));
            }
        }

        Ok(())
    }

    fn lower_block(
        &mut self,
        block: BlockId,
        mut current: BTreeMap<SsaDomain, ValueId>,
        context: &mut TransformContext<'_>,
    ) -> Result<BTreeMap<SsaDomain, ValueId>, IlError> {
        context.check_cancelled()?;

        for (domain, value) in &self.block_arguments[block.index()] {
            current.insert(*domain, *value);
        }

        let source_block = *self.source.common().blocks().get(block.index()).ok_or(
            IlError::range_out_of_bounds(block.value(), self.source.common().blocks().len()),
        )?;
        let start = self.builder.operation_count();

        for statement_index in source_block.operations().start()..source_block.operations().end() {
            context.check_cancelled()?;
            self.lower_statement_at(statement_index, &mut current)?;
        }

        self.fill_successor_edges(block, &mut current, source_block)?;

        let end = self.builder.operation_count();
        self.blocks[block.index()] = Some(Block::new(
            PackedRange::new(start, end)?,
            source_block.successors(),
            source_block.flags(),
        ));

        Ok(current)
    }

    fn fill_successor_edges(
        &mut self,
        block: BlockId,
        current: &mut BTreeMap<SsaDomain, ValueId>,
        source_block: Block,
    ) -> Result<(), IlError> {
        for (successor_offset, successor) in source_block
            .successors()
            .checked_slice(self.source.common().successors())?
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
                        let width = *self
                            .domain_widths
                            .get(&domain)
                            .ok_or(IlError::integer_overflow(domain.width_source()))?;
                        let value = self.push_undefined(domain, width)?;

                        current.insert(domain, value);

                        value
                    }
                };

                arguments.push(value);
            }

            let edge_count = self.edge_arguments.len();
            let destination =
                self.edge_arguments
                    .get_mut(edge)
                    .ok_or(IlError::range_out_of_bounds(
                        u32::try_from(edge).unwrap_or(u32::MAX),
                        edge_count,
                    ))?;

            *destination = arguments;
        }

        if block.index() >= self.source.common().blocks().len() {
            return Err(IlError::range_out_of_bounds(
                block.value(),
                self.source.common().blocks().len(),
            ));
        }

        Ok(())
    }

    fn lower_statement_at(
        &mut self,
        index: usize,
        current: &mut BTreeMap<SsaDomain, ValueId>,
    ) -> Result<(), IlError> {
        self.values.fill(None);
        let start = self.builder.operation_count();
        let statement = self
            .source
            .statements()
            .get(index)
            .ok_or(IlError::range_out_of_bounds(
                u32::try_from(index).unwrap_or(u32::MAX),
                self.source.statements().len(),
            ))?;

        self.lower_statement(statement, current)?;

        let end = self.builder.operation_count();
        self.statement_ranges[index] = PackedRange::new(start, end)?;

        Ok(())
    }

    fn lower_statement(
        &mut self,
        statement: &Statement,
        current: &mut BTreeMap<SsaDomain, ValueId>,
    ) -> Result<(), IlError> {
        match statement.opcode() {
            StatementOpcode::WriteRegister => {
                let value = self.lower_statement_value(statement, current)?;
                current.insert(SsaDomain::Register(statement.immediate()), value);
            }
            StatementOpcode::WriteFlag => {
                let value = self.lower_statement_value(statement, current)?;
                current.insert(SsaDomain::Flag(statement.immediate()), value);
            }
            StatementOpcode::Store => {
                let address_space = statement
                    .address_space()
                    .ok_or(IlError::llil_missing_address_space())?;
                let mut operands = self.lower_statement_operands(statement, current)?;
                let memory = self.current_memory(address_space, current)?;

                operands.push(memory);

                let operands = self.builder.push_value_operands(operands)?;
                let (memory, results) = self.builder.push_result_value(0)?;
                let operation = SsaOperation::new(SsaOpcode::Store, results, operands, 0)
                    .with_address_space(address_space)
                    .with_immediate(statement.immediate());

                self.builder.push_operation(operation)?;
                current.insert(SsaDomain::Memory(address_space), memory);
            }
            opcode => {
                let operands = self.lower_statement_operands(statement, current)?;
                let operands = self.builder.push_value_operands(operands)?;
                let opcode = SsaOpcode::from_statement(opcode)
                    .ok_or(IlError::llil_statement_opcode_in_ssa())?;
                let mut operation = SsaOperation::new(opcode, PackedRange::EMPTY, operands, 0)
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
            }
        }

        Ok(())
    }

    fn lower_statement_value(
        &mut self,
        statement: &Statement,
        current: &mut BTreeMap<SsaDomain, ValueId>,
    ) -> Result<ValueId, IlError> {
        let value = statement.value().ok_or(IlError::llil_missing_value())?;

        self.lower_expression(value, current)
    }

    fn lower_statement_operands(
        &mut self,
        statement: &Statement,
        current: &mut BTreeMap<SsaDomain, ValueId>,
    ) -> Result<Vec<ValueId>, IlError> {
        let mut operands = Vec::new();

        if let Some(value) = statement.value() {
            operands.push(self.lower_expression(value, current)?);
        }

        for operand in self.source.statement_operands_for(statement)? {
            operands.push(self.lower_expression(*operand, current)?);
        }

        Ok(operands)
    }

    fn lower_expression(
        &mut self,
        id: ExpressionId,
        current: &mut BTreeMap<SsaDomain, ValueId>,
    ) -> Result<ValueId, IlError> {
        if let Some(value) = self.values.get(id.index()).and_then(|value| *value) {
            return Ok(value);
        }

        let expression =
            *self
                .source
                .expressions()
                .get(id.index())
                .ok_or(IlError::range_out_of_bounds(
                    id.value(),
                    self.source.expressions().len(),
                ))?;

        let value = match expression.opcode() {
            ExpressionOpcode::ReadRegister => self.lower_read_register(&expression, current)?,
            ExpressionOpcode::ReadFlag => self.lower_read_flag(&expression, current)?,
            opcode => self.lower_value_expression(&expression, opcode, current)?,
        };

        if let Some(slot) = self.values.get_mut(id.index()) {
            *slot = Some(value);
        }

        Ok(value)
    }

    fn lower_read_register(
        &mut self,
        expression: &Expression,
        current: &mut BTreeMap<SsaDomain, ValueId>,
    ) -> Result<ValueId, IlError> {
        let domain = SsaDomain::Register(expression.immediate());

        if let Some(value) = current.get(&domain).copied() {
            return Ok(value);
        }

        let value = self.push_undefined(domain, expression.width())?;

        current.insert(domain, value);

        Ok(value)
    }

    fn lower_read_flag(
        &mut self,
        expression: &Expression,
        current: &mut BTreeMap<SsaDomain, ValueId>,
    ) -> Result<ValueId, IlError> {
        let domain = SsaDomain::Flag(expression.immediate());

        if let Some(value) = current.get(&domain).copied() {
            return Ok(value);
        }

        let value = self.push_undefined(domain, expression.width())?;

        current.insert(domain, value);

        Ok(value)
    }

    fn lower_value_expression(
        &mut self,
        expression: &Expression,
        opcode: ExpressionOpcode,
        current: &mut BTreeMap<SsaDomain, ValueId>,
    ) -> Result<ValueId, IlError> {
        let operands = self.lower_expression_operands(expression, current)?;
        let mut operands = operands;
        if opcode == ExpressionOpcode::Load {
            let address_space = expression
                .address_space()
                .ok_or(IlError::llil_missing_address_space())?;
            let memory = self.current_memory(address_space, current)?;

            operands.push(memory);
        }

        let operands = self.builder.push_value_operands(operands)?;
        let opcode =
            SsaOpcode::from_expression(opcode).ok_or(IlError::llil_expression_opcode_in_ssa())?;

        self.push_value_operation(
            opcode,
            expression.width(),
            operands,
            expression.immediate(),
            expression.address_space(),
        )
    }

    fn lower_expression_operands(
        &mut self,
        expression: &Expression,
        current: &mut BTreeMap<SsaDomain, ValueId>,
    ) -> Result<Vec<ValueId>, IlError> {
        let mut operands = Vec::new();

        for operand in self.source.expression_operands_for(expression)? {
            operands.push(self.lower_expression(*operand, current)?);
        }

        Ok(operands)
    }

    fn current_memory(
        &mut self,
        address_space: AddressSpaceId,
        current: &mut BTreeMap<SsaDomain, ValueId>,
    ) -> Result<ValueId, IlError> {
        let domain = SsaDomain::Memory(address_space);

        if let Some(value) = current.get(&domain).copied() {
            return Ok(value);
        }

        let value = self.push_undefined(domain, 0)?;

        current.insert(domain, value);

        Ok(value)
    }

    fn push_undefined(&mut self, domain: SsaDomain, width: u32) -> Result<ValueId, IlError> {
        self.push_value_operation(
            SsaOpcode::Undefined,
            width,
            PackedRange::EMPTY,
            domain.undefined_immediate(),
            None,
        )
    }

    fn push_value_operation(
        &mut self,
        opcode: SsaOpcode,
        width: u32,
        operands: PackedRange,
        immediate: u64,
        address_space: Option<AddressSpaceId>,
    ) -> Result<ValueId, IlError> {
        let (value, results) = self.builder.push_result_value(width)?;
        let mut operation =
            SsaOperation::new(opcode, results, operands, width).with_immediate(immediate);

        if let Some(address_space) = address_space {
            if opcode.requires_memory_domain() {
                self.builder.ensure_memory_domain(address_space);
            }

            operation = operation.with_address_space(address_space);
        }

        self.builder.push_operation(operation)?;

        Ok(value)
    }

    fn remap_source_runs(&self) -> Result<Vec<SourceRun>, IlError> {
        let mut runs = Vec::<SourceRun>::new();

        for run in self.source.common().source_runs() {
            let destination = self.remap_destination(run.destination())?;

            if destination.is_empty() {
                continue;
            }

            let run = SourceRun::new(
                destination,
                run.machine_address(),
                run.first_pcode_index(),
                run.pcode_count(),
            );

            if let Some(previous) = runs.last_mut()
                && previous.try_merge(run)?
            {
                continue;
            }

            runs.push(run);
        }

        Ok(runs)
    }

    fn remap_mapping_runs(&self) -> Result<Vec<MappingRun>, IlError> {
        let mut runs = Vec::<MappingRun>::new();

        for run in self.source.common().mapping_runs() {
            let destination = self.remap_destination(run.destination())?;

            if destination.is_empty() {
                continue;
            }

            let run = MappingRun::new(destination, run.source());

            if let Some(previous) = runs.last_mut()
                && previous.try_merge(run)?
            {
                continue;
            }

            runs.push(run);
        }

        Ok(runs)
    }

    fn remap_destination(&self, destination: PackedRange) -> Result<PackedRange, IlError> {
        let mut start = None;
        let mut end = None;

        for statement_index in destination.start()..destination.end() {
            let range =
                self.statement_ranges
                    .get(statement_index)
                    .ok_or(IlError::range_out_of_bounds(
                        u32::try_from(statement_index).unwrap_or(u32::MAX),
                        self.statement_ranges.len(),
                    ))?;

            if range.is_empty() {
                continue;
            }

            start.get_or_insert(range.start());
            end = Some(range.end());
        }

        match (start, end) {
            (Some(start), Some(end)) => PackedRange::new(start, end),
            _ => Ok(PackedRange::EMPTY),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::common::{Block, BlockId, BuildStatus, CommonBody, Scratch};
    use crate::il::llil::{Expression, LLIL_SCHEMA_VERSION, LlilBuilder, Statement};
    use crate::ir::{Address, FunctionId};
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn empty_llil_lowers_to_empty_ssa() {
        let source_header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::Llil,
            LLIL_SCHEMA_VERSION,
            11,
        );
        let source = LlilBuilder::new(source_header, CommonBody::default())
            .finish(&BuildStatus::new())
            .unwrap();
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(1024);
        let mut context = TransformContext::new(&status, &mut scratch);
        let mut transform = LlilToSsa;

        let lowered = transform.transform(&source, &mut context).unwrap();

        assert_eq!(lowered.header().level(), IrLevel::LlilSsa);
        assert!(lowered.operations().is_empty());
    }

    #[test]
    fn register_read_after_write_uses_current_value() {
        let source_header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::Llil,
            LLIL_SCHEMA_VERSION,
            11,
        );
        let mut builder = LlilBuilder::new(source_header, CommonBody::default());
        let value = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                64,
                PackedRange::EMPTY,
                0x2a,
                None,
            ))
            .unwrap();

        builder
            .push_statement(
                Statement::new(
                    StatementOpcode::WriteRegister,
                    PackedRange::EMPTY,
                    Some(value),
                    None,
                    None,
                )
                .with_immediate(7),
            )
            .unwrap();

        let read = builder
            .push_expression(Expression::new(
                ExpressionOpcode::ReadRegister,
                64,
                PackedRange::EMPTY,
                7,
                None,
            ))
            .unwrap();
        let operands = builder.push_statement_operands([read]).unwrap();

        builder
            .push_statement(Statement::new(
                StatementOpcode::Return,
                operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.finish(&BuildStatus::new()).unwrap();
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(1024);
        let mut context = TransformContext::new(&status, &mut scratch);
        let mut transform = LlilToSsa;
        let lowered = transform.transform(&source, &mut context).unwrap();

        assert_eq!(lowered.operations()[0].opcode(), SsaOpcode::Constant);
        assert_eq!(lowered.operations()[1].opcode(), SsaOpcode::Return);
        assert_eq!(lowered.value_operands().len(), 1);
        assert_eq!(
            lowered.value_operands()[0],
            ValueId::try_from_index(lowered.operations()[0].results().start()).unwrap()
        );
    }

    #[test]
    fn register_read_without_write_becomes_undefined() {
        let source_header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::Llil,
            LLIL_SCHEMA_VERSION,
            11,
        );
        let mut builder = LlilBuilder::new(source_header, CommonBody::default());
        let read = builder
            .push_expression(Expression::new(
                ExpressionOpcode::ReadRegister,
                32,
                PackedRange::EMPTY,
                9,
                None,
            ))
            .unwrap();
        let operands = builder.push_statement_operands([read]).unwrap();

        builder
            .push_statement(Statement::new(
                StatementOpcode::Return,
                operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.finish(&BuildStatus::new()).unwrap();
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(1024);
        let mut context = TransformContext::new(&status, &mut scratch);
        let mut transform = LlilToSsa;
        let lowered = transform.transform(&source, &mut context).unwrap();

        assert_eq!(lowered.operations()[0].opcode(), SsaOpcode::Undefined);
        assert_eq!(lowered.operations()[0].width(), 32);
        assert_eq!(lowered.operations()[0].immediate(), 9);
        assert_eq!(lowered.operations()[1].opcode(), SsaOpcode::Return);
    }

    #[test]
    fn load_preserves_fugue_address_space() {
        let source_header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::Llil,
            LLIL_SCHEMA_VERSION,
            11,
        );
        let mut builder = LlilBuilder::new(source_header, CommonBody::default());
        let offset = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                64,
                PackedRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let load_operands = builder.push_expression_operands([offset]).unwrap();
        let space = AddressSpaceId::new(3);
        let load = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Load,
                8,
                load_operands,
                0,
                Some(space),
            ))
            .unwrap();
        let return_operands = builder.push_statement_operands([load]).unwrap();

        builder
            .push_statement(Statement::new(
                StatementOpcode::Return,
                return_operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.finish(&BuildStatus::new()).unwrap();
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(1024);
        let mut context = TransformContext::new(&status, &mut scratch);
        let mut transform = LlilToSsa;
        let lowered = transform.transform(&source, &mut context).unwrap();

        let load_index = lowered
            .operations()
            .iter()
            .position(|operation| operation.opcode() == SsaOpcode::Load)
            .unwrap();

        assert_eq!(
            lowered.operations()[load_index].address_space(),
            Some(space)
        );
        assert_eq!(lowered.memory_domains().len(), 1);
        assert_eq!(lowered.memory_domains()[0].space(), space);

        let operands = lowered
            .operation_operands(&lowered.operations()[load_index])
            .unwrap();
        let memory = lowered.values()[operands.last().unwrap().index()];

        assert_eq!(memory.width(), 0);
    }

    #[test]
    fn load_after_store_uses_store_memory_result() {
        let source_header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::Llil,
            LLIL_SCHEMA_VERSION,
            11,
        );
        let mut builder = LlilBuilder::new(source_header, CommonBody::default());
        let space = AddressSpaceId::new(3);
        let store_address = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                64,
                PackedRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let store_value = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                32,
                PackedRange::EMPTY,
                0x2a,
                None,
            ))
            .unwrap();
        let store_operands = builder
            .push_statement_operands([store_address, store_value])
            .unwrap();

        builder
            .push_statement(Statement::new(
                StatementOpcode::Store,
                store_operands,
                None,
                None,
                Some(space),
            ))
            .unwrap();

        let load_address = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                64,
                PackedRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let load_operands = builder.push_expression_operands([load_address]).unwrap();
        let load = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Load,
                32,
                load_operands,
                0,
                Some(space),
            ))
            .unwrap();
        let return_operands = builder.push_statement_operands([load]).unwrap();

        builder
            .push_statement(Statement::new(
                StatementOpcode::Return,
                return_operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.finish(&BuildStatus::new()).unwrap();
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(1024);
        let mut context = TransformContext::new(&status, &mut scratch);
        let mut transform = LlilToSsa;
        let lowered = transform.transform(&source, &mut context).unwrap();
        let store_index = lowered
            .operations()
            .iter()
            .position(|operation| operation.opcode() == SsaOpcode::Store)
            .unwrap();
        let load_index = lowered
            .operations()
            .iter()
            .position(|operation| operation.opcode() == SsaOpcode::Load)
            .unwrap();
        let store_memory =
            ValueId::try_from_index(lowered.operations()[store_index].results().start()).unwrap();
        let load_operands = lowered
            .operation_operands(&lowered.operations()[load_index])
            .unwrap();

        assert_eq!(lowered.memory_domains().len(), 1);
        assert_eq!(lowered.memory_domains()[0].space(), space);
        assert_eq!(lowered.values()[store_memory.index()].width(), 0);
        assert_eq!(*load_operands.last().unwrap(), store_memory);
    }

    #[test]
    fn direct_branch_preserves_fugue_address() {
        let source_header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::Llil,
            LLIL_SCHEMA_VERSION,
            11,
        );
        let mut builder = LlilBuilder::new(source_header, CommonBody::default());
        let condition = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                1,
                PackedRange::EMPTY,
                1,
                None,
            ))
            .unwrap();
        let target_expression = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                64,
                PackedRange::EMPTY,
                0x2000,
                None,
            ))
            .unwrap();
        let operands = builder
            .push_statement_operands([condition, target_expression])
            .unwrap();
        let target = Address::new(AddressSpaceId::new(4), 0x2000u64);

        builder
            .push_statement(Statement::new(
                StatementOpcode::ConditionalBranch,
                operands,
                None,
                Some(target),
                None,
            ))
            .unwrap();

        let source = builder.finish(&BuildStatus::new()).unwrap();
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(1024);
        let mut context = TransformContext::new(&status, &mut scratch);
        let mut transform = LlilToSsa;
        let lowered = transform.transform(&source, &mut context).unwrap();

        assert_eq!(
            lowered.operations()[2].opcode(),
            SsaOpcode::ConditionalBranch
        );
        assert_eq!(lowered.operations()[2].address(), Some(target));
    }

    #[test]
    fn deep_dominance_chain_lowers_iteratively() {
        let source_header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::Llil,
            LLIL_SCHEMA_VERSION,
            11,
        );
        let block_count = 128usize;
        let mut successors = Vec::new();
        let mut blocks = Vec::new();

        for index in 0..block_count {
            let mut flags = 0u16;
            if index == 0 {
                flags |= Block::ENTRY;
            }
            if index + 1 == block_count {
                flags |= Block::EXIT;
            }

            let successor_range = if index + 1 == block_count {
                PackedRange::EMPTY
            } else {
                successors.push(BlockId::try_from_index(index + 1).unwrap());
                PackedRange::new(successors.len() - 1, successors.len()).unwrap()
            };

            blocks.push(Block::new(
                PackedRange::new(index, index + 1).unwrap(),
                successor_range,
                flags,
            ));
        }

        let common = CommonBody::new(blocks, successors, Vec::new(), Vec::new());
        let mut builder = LlilBuilder::new(source_header, common);

        for index in 0..block_count {
            let value = builder
                .push_expression(Expression::new(
                    ExpressionOpcode::Constant,
                    64,
                    PackedRange::EMPTY,
                    index as u64,
                    None,
                ))
                .unwrap();

            builder
                .push_statement(
                    Statement::new(
                        StatementOpcode::WriteRegister,
                        PackedRange::EMPTY,
                        Some(value),
                        None,
                        None,
                    )
                    .with_immediate(7),
                )
                .unwrap();
        }

        let source = builder.finish(&BuildStatus::new()).unwrap();
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(1024);
        let mut context = TransformContext::new(&status, &mut scratch);
        let mut transform = LlilToSsa;
        let lowered = transform.transform(&source, &mut context).unwrap();

        assert_eq!(lowered.common().blocks().len(), block_count);
        assert_eq!(lowered.common().successors().len(), block_count - 1);
        assert_eq!(lowered.operations().len(), block_count);
        assert!(lowered.block_arguments().is_empty());
    }

    #[test]
    fn merge_block_register_read_becomes_block_argument() {
        let source_header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::Llil,
            LLIL_SCHEMA_VERSION,
            11,
        );
        let successors = vec![
            BlockId::try_from_index(1).unwrap(),
            BlockId::try_from_index(2).unwrap(),
            BlockId::try_from_index(3).unwrap(),
            BlockId::try_from_index(3).unwrap(),
        ];
        let common = CommonBody::new(
            vec![
                Block::new(
                    PackedRange::EMPTY,
                    PackedRange::new(0, 2).unwrap(),
                    Block::ENTRY,
                ),
                Block::new(
                    PackedRange::new(0, 1).unwrap(),
                    PackedRange::new(2, 3).unwrap(),
                    0,
                ),
                Block::new(
                    PackedRange::new(1, 2).unwrap(),
                    PackedRange::new(3, 4).unwrap(),
                    0,
                ),
                Block::new(
                    PackedRange::new(2, 3).unwrap(),
                    PackedRange::EMPTY,
                    Block::EXIT,
                ),
            ],
            successors,
            Vec::new(),
            Vec::new(),
        );
        let mut builder = LlilBuilder::new(source_header, common);
        let left = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                64,
                PackedRange::EMPTY,
                1,
                None,
            ))
            .unwrap();
        let right = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                64,
                PackedRange::EMPTY,
                2,
                None,
            ))
            .unwrap();
        let read = builder
            .push_expression(Expression::new(
                ExpressionOpcode::ReadRegister,
                64,
                PackedRange::EMPTY,
                7,
                None,
            ))
            .unwrap();

        builder
            .push_statement(
                Statement::new(
                    StatementOpcode::WriteRegister,
                    PackedRange::EMPTY,
                    Some(left),
                    None,
                    None,
                )
                .with_immediate(7),
            )
            .unwrap();
        builder
            .push_statement(
                Statement::new(
                    StatementOpcode::WriteRegister,
                    PackedRange::EMPTY,
                    Some(right),
                    None,
                    None,
                )
                .with_immediate(7),
            )
            .unwrap();
        let operands = builder.push_statement_operands([read]).unwrap();
        builder
            .push_statement(Statement::new(
                StatementOpcode::Return,
                operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.finish(&BuildStatus::new()).unwrap();
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(1024);
        let mut context = TransformContext::new(&status, &mut scratch);
        let mut transform = LlilToSsa;
        let lowered = transform.transform(&source, &mut context).unwrap();

        assert_eq!(lowered.block_arguments().len(), 1);
        assert_eq!(
            lowered.block_arguments()[0].block(),
            BlockId::try_from_index(3).unwrap()
        );
        assert_eq!(lowered.operations()[2].opcode(), SsaOpcode::Return);
        assert_eq!(
            lowered.value_operands()[0],
            lowered.block_arguments()[0].value()
        );
        assert_eq!(lowered.edge_arguments().len(), 4);
        assert_eq!(lowered.edge_argument_values().len(), 2);
        assert!(lowered.edge_arguments()[0].is_empty());
        assert!(lowered.edge_arguments()[1].is_empty());
        assert_eq!(lowered.arguments_for_edge(2).unwrap().len(), 1);
        assert_eq!(lowered.arguments_for_edge(3).unwrap().len(), 1);
    }

    #[test]
    fn merge_block_load_uses_memory_block_argument() {
        let source_header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::Llil,
            LLIL_SCHEMA_VERSION,
            11,
        );
        let join = BlockId::try_from_index(3).unwrap();
        let successors = vec![
            BlockId::try_from_index(1).unwrap(),
            BlockId::try_from_index(2).unwrap(),
            join,
            join,
        ];
        let common = CommonBody::new(
            vec![
                Block::new(
                    PackedRange::EMPTY,
                    PackedRange::new(0, 2).unwrap(),
                    Block::ENTRY,
                ),
                Block::new(
                    PackedRange::new(0, 1).unwrap(),
                    PackedRange::new(2, 3).unwrap(),
                    0,
                ),
                Block::new(PackedRange::EMPTY, PackedRange::new(3, 4).unwrap(), 0),
                Block::new(
                    PackedRange::new(1, 2).unwrap(),
                    PackedRange::EMPTY,
                    Block::EXIT,
                ),
            ],
            successors,
            Vec::new(),
            Vec::new(),
        );
        let mut builder = LlilBuilder::new(source_header, common);
        let space = AddressSpaceId::new(3);
        let store_address = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                64,
                PackedRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let store_value = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                32,
                PackedRange::EMPTY,
                0x2a,
                None,
            ))
            .unwrap();
        let load_address = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                64,
                PackedRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let load_operands = builder.push_expression_operands([load_address]).unwrap();
        let load = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Load,
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
            .push_statement(Statement::new(
                StatementOpcode::Store,
                store_operands,
                None,
                None,
                Some(space),
            ))
            .unwrap();

        let return_operands = builder.push_statement_operands([load]).unwrap();

        builder
            .push_statement(Statement::new(
                StatementOpcode::Return,
                return_operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let source = builder.finish(&BuildStatus::new()).unwrap();
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(1024);
        let mut context = TransformContext::new(&status, &mut scratch);
        let mut transform = LlilToSsa;
        let lowered = transform.transform(&source, &mut context).unwrap();
        let load_index = lowered
            .operations()
            .iter()
            .position(|operation| operation.opcode() == SsaOpcode::Load)
            .unwrap();
        let load_operands = lowered
            .operation_operands(&lowered.operations()[load_index])
            .unwrap();

        assert_eq!(lowered.memory_domains().len(), 1);
        assert_eq!(lowered.memory_domains()[0].space(), space);
        assert_eq!(lowered.block_arguments().len(), 1);
        assert_eq!(lowered.block_arguments()[0].block(), join);
        assert_eq!(
            lowered.values()[lowered.block_arguments()[0].value().index()].width(),
            0
        );
        assert_eq!(
            *load_operands.last().unwrap(),
            lowered.block_arguments()[0].value()
        );
        assert!(lowered.arguments_for_edge(0).unwrap().is_empty());
        assert!(lowered.arguments_for_edge(1).unwrap().is_empty());
        assert_eq!(lowered.arguments_for_edge(2).unwrap().len(), 1);
        assert_eq!(lowered.arguments_for_edge(3).unwrap().len(), 1);
    }

    #[test]
    fn loop_carried_register_uses_header_block_argument() {
        let source_header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::Llil,
            LLIL_SCHEMA_VERSION,
            11,
        );
        let loop_header = BlockId::try_from_index(1).unwrap();
        let loop_body = BlockId::try_from_index(2).unwrap();
        let exit = BlockId::try_from_index(3).unwrap();
        let common = CommonBody::new(
            vec![
                Block::new(
                    PackedRange::EMPTY,
                    PackedRange::new(0, 1).unwrap(),
                    Block::ENTRY,
                ),
                Block::new(
                    PackedRange::new(0, 1).unwrap(),
                    PackedRange::new(1, 2).unwrap(),
                    0,
                ),
                Block::new(
                    PackedRange::new(1, 2).unwrap(),
                    PackedRange::new(2, 4).unwrap(),
                    0,
                ),
                Block::new(PackedRange::EMPTY, PackedRange::EMPTY, Block::EXIT),
            ],
            vec![loop_header, loop_body, loop_header, exit],
            Vec::new(),
            Vec::new(),
        );
        let mut builder = LlilBuilder::new(source_header, common);
        let read = builder
            .push_expression(Expression::new(
                ExpressionOpcode::ReadRegister,
                32,
                PackedRange::EMPTY,
                9,
                None,
            ))
            .unwrap();
        let constant = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                32,
                PackedRange::EMPTY,
                1,
                None,
            ))
            .unwrap();
        let return_operands = builder.push_statement_operands([read]).unwrap();

        builder
            .push_statement(Statement::new(
                StatementOpcode::Return,
                return_operands,
                None,
                None,
                None,
            ))
            .unwrap();
        builder
            .push_statement(
                Statement::new(
                    StatementOpcode::WriteRegister,
                    PackedRange::EMPTY,
                    Some(constant),
                    None,
                    None,
                )
                .with_immediate(9),
            )
            .unwrap();

        let source = builder.finish(&BuildStatus::new()).unwrap();
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(1024);
        let mut context = TransformContext::new(&status, &mut scratch);
        let mut transform = LlilToSsa;
        let lowered = transform.transform(&source, &mut context).unwrap();

        assert_eq!(lowered.block_arguments().len(), 1);
        assert_eq!(lowered.block_arguments()[0].block(), loop_header);
        assert_eq!(
            lowered.value_operands()[0],
            lowered.block_arguments()[0].value()
        );
        assert_eq!(lowered.arguments_for_edge(0).unwrap().len(), 1);
        assert_eq!(lowered.arguments_for_edge(2).unwrap().len(), 1);

        let entry_value = lowered.arguments_for_edge(0).unwrap()[0];
        let back_edge_value = lowered.arguments_for_edge(2).unwrap()[0];

        assert_eq!(
            lowered.operations()[lowered.values()[entry_value.index()].definition_index() as usize]
                .opcode(),
            SsaOpcode::Undefined
        );
        assert_eq!(
            lowered.operations()
                [lowered.values()[back_edge_value.index()].definition_index() as usize]
                .opcode(),
            SsaOpcode::Constant
        );
    }
}
