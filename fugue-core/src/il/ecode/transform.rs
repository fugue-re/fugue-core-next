use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::analysis::control::CancellationToken;
use crate::arch::Arch;
use crate::il::common::{
    IlBlock, IlBlockId, IlBlockProperties, IlError, IlExprId, IlGraph, IlIndexRange, IlLevel,
    IlMetadata, IlParentSpan, IlSourceSpan,
};
use crate::il::ecode::{
    ECODE_SCHEMA_VERSION, ECodeBuilder, ECodeExpr, ECodeExprOpcode, ECodeIr, ECodeStmt,
    ECodeStmtOpcode,
};
use crate::il::pcode::{
    FlagId, PCodeIr, PCodeLocation, PCodeLocationId, PCodeOp, PCodeOpcode, RegisterBank,
    RegisterId, RegisterSlice,
};
use crate::ir::Address;
use crate::lifter::Varnode;

#[derive(Debug, Default)]
pub struct PCodeToECode {
    intrinsic_args: Vec<Varnode>,
    operands: Vec<IlExprId>,
    source_spans_by_address: FxHashMap<Address, SmallVec<[IlSourceSpan; 1]>>,
}

impl PCodeToECode {
    pub fn transform(
        &mut self,
        source: &PCodeIr,
        arch: &Arch,
        cancellation: &CancellationToken,
    ) -> Result<ECodeIr, IlError> {
        cancellation.check()?;

        let metadata = IlMetadata::new(
            source.metadata().function(),
            ECODE_SCHEMA_VERSION,
            source.metadata().input_revision(),
        );
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
        let mut lifting = ECodeLifting::new(
            source,
            arch,
            &mut builder,
            &mut self.intrinsic_args,
            &mut self.operands,
        )?;

        let offsets = lifting.lift(cancellation)?;
        drop(lifting);

        builder.replace_graph(self.remap_graph(source, &offsets)?);
        builder.replace_parent_spans(Self::remap_parent_spans(&offsets)?);
        builder.replace_source_spans(Self::remap_source_spans(source, &offsets)?);

        builder.build(cancellation)
    }

    fn remap_graph(&mut self, source: &PCodeIr, offsets: &[u32]) -> Result<IlGraph, IlError> {
        let mut partitions = Vec::new();
        let mut partition_ranges = Vec::with_capacity(source.graph().blocks().len());
        let mut first_blocks = Vec::with_capacity(source.graph().blocks().len());
        let mut refined_block_count = 0usize;
        let mut boundaries = Vec::new();
        self.source_spans_by_address.clear();
        for &span in source.source_spans() {
            self.source_spans_by_address
                .entry(span.address())
                .or_default()
                .push(span);
        }

        for block in source.graph().blocks() {
            let operations = block.operations();
            boundaries.clear();
            boundaries.push(operations.start());
            boundaries.push(operations.end());

            for operation_index in operations.start()..operations.end() {
                let operation = &source.operations()[operation_index];
                if matches!(
                    operation.opcode(),
                    PCodeOpcode::Branch
                        | PCodeOpcode::CBranch
                        | PCodeOpcode::IBranch
                        | PCodeOpcode::Return
                ) {
                    boundaries.push(operation_index + 1);
                }
                if let Some(target) =
                    self.internal_target(source, operations, operation_index, operation)
                {
                    boundaries.push(target);
                }
            }

            boundaries.sort_unstable();
            boundaries.dedup();
            let partition_start = partitions.len();
            for pair in boundaries.windows(2) {
                partitions.push(IlIndexRange::new(pair[0], pair[1])?);
            }
            if partition_start == partitions.len() {
                partitions.push(operations);
            }

            first_blocks.push(IlBlockId::try_from_index(refined_block_count)?);
            refined_block_count += partitions.len() - partition_start;
            partition_ranges.push(IlIndexRange::new(partition_start, partitions.len())?);
        }

        let mut blocks = Vec::with_capacity(refined_block_count);
        let mut successors = Vec::new();
        let mut block_sources = (!source.graph().block_sources().is_empty())
            .then(|| Vec::with_capacity(refined_block_count));

        for (block_index, (source_block, ranges)) in source
            .graph()
            .blocks()
            .iter()
            .zip(&partition_ranges)
            .enumerate()
        {
            let ranges = ranges.slice(&partitions);
            for (range_index, range) in ranges.iter().copied().enumerate() {
                let mut block_successors = SmallVec::<[IlBlockId; 2]>::new();
                let next = (range_index + 1 < ranges.len()).then(|| {
                    IlBlockId::try_from_index(first_blocks[block_index].index() + range_index + 1)
                        .expect("refined block id was validated while partitioning")
                });
                let original_successors =
                    source_block.successors().slice(source.graph().successors());

                match range.end().checked_sub(1).and_then(|index| {
                    source
                        .operations()
                        .get(index)
                        .map(|operation| (index, operation))
                }) {
                    Some((operation_index, operation))
                        if matches!(
                            operation.opcode(),
                            PCodeOpcode::Branch | PCodeOpcode::CBranch
                        ) =>
                    {
                        if let Some(target) = self
                            .internal_target(
                                source,
                                source_block.operations(),
                                operation_index,
                                operation,
                            )
                            .and_then(|target| {
                                Self::refined_target(first_blocks[block_index], ranges, target)
                            })
                        {
                            Self::push_successor(&mut block_successors, target);
                        } else {
                            Self::push_mapped_successors(
                                &mut block_successors,
                                original_successors,
                                &first_blocks,
                            );
                        }
                        if operation.opcode() == PCodeOpcode::CBranch {
                            if let Some(next) = next {
                                Self::push_successor(&mut block_successors, next);
                            } else {
                                Self::push_mapped_successors(
                                    &mut block_successors,
                                    original_successors,
                                    &first_blocks,
                                );
                            }
                        }
                    }
                    Some((_, operation)) if operation.opcode() == PCodeOpcode::IBranch => {
                        Self::push_mapped_successors(
                            &mut block_successors,
                            original_successors,
                            &first_blocks,
                        );
                    }
                    Some((_, operation)) if operation.opcode() == PCodeOpcode::Return => {}
                    _ => {
                        if let Some(next) = next {
                            Self::push_successor(&mut block_successors, next);
                        } else {
                            Self::push_mapped_successors(
                                &mut block_successors,
                                original_successors,
                                &first_blocks,
                            );
                        }
                    }
                }

                let successor_start = successors.len();
                successors.extend(block_successors);
                let mut properties = IlBlockProperties::empty();
                if source_block.is_entry() && range_index == 0 {
                    properties |= IlBlockProperties::ENTRY;
                }
                if successor_start == successors.len() {
                    properties |= IlBlockProperties::EXIT;
                }
                blocks.push(IlBlock::new(
                    IlIndexRange::new(
                        offsets[range.start()] as usize,
                        offsets[range.end()] as usize,
                    )?,
                    IlIndexRange::new(successor_start, successors.len())?,
                    properties,
                ));
                if let Some(block_sources) = block_sources.as_mut() {
                    let source_address = if range_index == 0 {
                        source.graph().block_sources()[block_index]
                    } else {
                        source
                            .source_span_for(range.start())
                            .map(|span| span.address())
                            .unwrap_or(source.graph().block_sources()[block_index])
                    };
                    block_sources.push(source_address);
                }
            }
        }

        let graph = IlGraph::new(blocks, successors);
        Ok(match block_sources {
            Some(block_sources) => graph.with_block_sources(block_sources),
            None => graph,
        })
    }

    fn push_successor(successors: &mut SmallVec<[IlBlockId; 2]>, successor: IlBlockId) {
        if !successors.contains(&successor) {
            successors.push(successor);
        }
    }

    fn push_mapped_successors(
        successors: &mut SmallVec<[IlBlockId; 2]>,
        additions: &[IlBlockId],
        first_blocks: &[IlBlockId],
    ) {
        for successor in additions {
            Self::push_successor(successors, first_blocks[successor.index()]);
        }
    }

    fn refined_target(
        first: IlBlockId,
        ranges: &[IlIndexRange],
        operation: usize,
    ) -> Option<IlBlockId> {
        let offset = ranges
            .binary_search_by_key(&operation, IlIndexRange::start)
            .ok()?;
        IlBlockId::try_from_index(first.index() + offset).ok()
    }

    fn internal_target(
        &self,
        source: &PCodeIr,
        block: IlIndexRange,
        operation_index: usize,
        operation: &PCodeOp,
    ) -> Option<usize> {
        if !matches!(
            operation.opcode(),
            PCodeOpcode::Branch | PCodeOpcode::CBranch
        ) {
            return None;
        }
        let target = source.target(operation.immediate())?;
        let source_span = source.source_span_for(operation_index)?;

        if target.address() != source_span.address() {
            return self
                .source_spans_by_address
                .get(&target.address())?
                .iter()
                .find(|span| {
                    block.start() <= span.destination().start()
                        && span.destination().start() < block.end()
                })
                .map(|span| span.destination().start());
        }

        let relative = u32::from(target.position()).checked_sub(source_span.first_pcode_index())?;
        let relative = usize::try_from(relative).ok()?;
        let target_operation = source_span.destination().start().checked_add(relative)?;
        (block.start() <= target_operation && target_operation <= block.end())
            .then_some(target_operation)
    }

    fn remap_parent_spans(offsets: &[u32]) -> Result<Vec<IlParentSpan>, IlError> {
        let mut spans = Vec::<IlParentSpan>::new();
        for (source, offsets) in offsets.windows(2).enumerate() {
            let destination = IlIndexRange::new(offsets[0] as usize, offsets[1] as usize)?;
            if destination.is_empty() {
                continue;
            }
            let span = IlParentSpan::new(destination, IlIndexRange::new(source, source + 1)?);
            if let Some(previous) = spans.last_mut()
                && previous.try_merge(span)?
            {
                continue;
            }
            spans.push(span);
        }
        Ok(spans)
    }

    fn remap_source_spans(source: &PCodeIr, offsets: &[u32]) -> Result<Vec<IlSourceSpan>, IlError> {
        source
            .source_spans()
            .iter()
            .map(|span| {
                let destination = span.destination();
                Ok(IlSourceSpan::new(
                    IlIndexRange::new(
                        offsets[destination.start()] as usize,
                        offsets[destination.end()] as usize,
                    )?,
                    span.address(),
                    span.first_pcode_index(),
                    span.pcode_count(),
                ))
            })
            .collect()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum LocationRole {
    Address,
    Value,
}

struct ECodeLifting<'a, 'b> {
    arch: &'a Arch,
    source: &'a PCodeIr,
    builder: &'b mut ECodeBuilder,
    register_bank: RegisterBank,
    flags: FxHashMap<PCodeLocation, FlagId>,
    values: FxHashMap<(PCodeLocationId, LocationRole), IlExprId>,
    register_values: FxHashMap<RegisterId, IlExprId>,
    register_reads: FxHashMap<PCodeLocationId, IlExprId>,
    flag_values: FxHashMap<FlagId, IlExprId>,
    intrinsic_args: &'b mut Vec<Varnode>,
    operands: &'b mut Vec<IlExprId>,
}

impl<'a, 'b> ECodeLifting<'a, 'b> {
    fn new(
        source: &'a PCodeIr,
        arch: &'a Arch,
        builder: &'b mut ECodeBuilder,
        intrinsic_args: &'b mut Vec<Varnode>,
        operands: &'b mut Vec<IlExprId>,
    ) -> Result<Self, IlError> {
        let language = arch.language();
        let flags = arch
            .flags()
            .iter()
            .map(|flag| {
                let variable = flag.variable();
                (
                    PCodeLocation::from_varnode(language, &variable),
                    FlagId::new(variable.offset()),
                )
            })
            .collect();

        Ok(Self {
            arch,
            source,
            builder,
            register_bank: RegisterBank::new(language, source)?,
            flags,
            values: FxHashMap::default(),
            register_values: FxHashMap::default(),
            register_reads: FxHashMap::default(),
            flag_values: FxHashMap::default(),
            intrinsic_args,
            operands,
        })
    }

    fn lift(&mut self, cancellation: &CancellationToken) -> Result<Vec<u32>, IlError> {
        let mut offsets = Vec::with_capacity(self.source.operations().len() + 1);
        let mut source_span = 0usize;

        for (index, operation) in self.source.operations().iter().enumerate() {
            cancellation.check()?;
            if self
                .source
                .source_spans()
                .get(source_span)
                .is_some_and(|span| span.destination().start() == index)
            {
                self.values.clear();
                self.register_values.clear();
                self.register_reads.clear();
                self.flag_values.clear();
                source_span += 1;
            }
            offsets.push(self.builder.statement_count() as u32);
            self.lift_operation(operation)?;
        }

        offsets.push(self.builder.statement_count() as u32);

        Ok(offsets)
    }

    fn lift_operation(&mut self, operation: &PCodeOp) -> Result<(), IlError> {
        match operation.opcode() {
            PCodeOpcode::Store => self.lift_store(operation),
            PCodeOpcode::Branch => self.lift_direct_flow(operation, ECodeStmtOpcode::Branch),
            PCodeOpcode::CBranch => {
                self.lift_direct_flow(operation, ECodeStmtOpcode::ConditionalBranch)
            }
            PCodeOpcode::IBranch => {
                self.lift_indirect_flow(operation, ECodeStmtOpcode::BranchIndirect)
            }
            PCodeOpcode::Call => self.lift_direct_flow(operation, ECodeStmtOpcode::Call),
            PCodeOpcode::ICall => self.lift_indirect_flow(operation, ECodeStmtOpcode::CallIndirect),
            PCodeOpcode::Return => self.lift_indirect_flow(operation, ECodeStmtOpcode::Return),
            PCodeOpcode::UserOp if operation.output().is_none() => self.lift_intrinsic(operation),
            opcode => self.lift_expression_operation(operation, opcode),
        }
    }

    fn lift_intrinsic(&mut self, operation: &PCodeOp) -> Result<(), IlError> {
        let (opcode, operands) = if self.is_trap_intrinsic(operation) {
            (ECodeStmtOpcode::Trap, IlIndexRange::EMPTY)
        } else {
            (
                ECodeStmtOpcode::Intrinsic,
                self.lift_statement_operands(operation, None)?,
            )
        };
        self.builder.push_statement(
            ECodeStmt::new(opcode, operands, None, None, operation.effect_space())
                .with_immediate(u64::from(operation.immediate())),
        )?;

        Ok(())
    }

    fn is_trap_intrinsic(&mut self, operation: &PCodeOp) -> bool {
        self.intrinsic_args.clear();
        for operand in self.source.operation_operands(operation) {
            let location = self.location(*operand);
            self.intrinsic_args.push(Varnode::new(
                location.lifter_space().value(),
                location.offset(),
                location.size(),
            ));
        }
        self.arch.is_trap_intrinsic(
            u16::try_from(operation.immediate())
                .expect("PCode user-op identifier originated as u16"),
            self.intrinsic_args,
        )
    }

    fn lift_expression_operation(
        &mut self,
        operation: &PCodeOp,
        opcode: PCodeOpcode,
    ) -> Result<(), IlError> {
        let Some(output) = operation.output() else {
            return Err(IlError::missing_component(IlLevel::PCode, "output"));
        };
        let output_width = u32::from(self.location(output).size()) * 8;
        let address_operand = (opcode == PCodeOpcode::Load).then_some(0);
        self.lift_operand_values(operation, address_operand)?;
        if opcode == PCodeOpcode::Subpiece {
            let offset = self.source.operation_operands(operation)[1];
            let location = *self.location(offset);
            if !location.is_constant() {
                return Err(IlError::missing_component(
                    IlLevel::PCode,
                    "constant subpiece offset",
                ));
            }
            let bits = location
                .offset()
                .checked_mul(8)
                .ok_or(IlError::integer_overflow("subpiece offset"))?;
            self.operands[1] = self.builder.push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                u32::from(location.size()) * 8,
                IlIndexRange::EMPTY,
                bits,
                None,
            ))?;
        }
        let operands = self
            .builder
            .push_expression_operands(self.operands.iter().copied())?;
        let expression_opcode = self.expression_opcode(opcode)?;
        let expression = ECodeExpr::new(
            expression_opcode,
            output_width,
            operands,
            u64::from(operation.immediate()),
            operation.effect_space(),
        );
        let expression = self.builder.push_expression(expression)?;

        self.assign_output(output, expression)?;

        Ok(())
    }

    fn assign_output(
        &mut self,
        output: PCodeLocationId,
        expression: IlExprId,
    ) -> Result<(), IlError> {
        let location = *self.location(output);
        if let Some(flag) = self.flags.get(&location).copied() {
            self.flag_values.insert(flag, expression);
            self.builder.push_statement(
                ECodeStmt::new(
                    ECodeStmtOpcode::WriteFlag,
                    IlIndexRange::EMPTY,
                    Some(expression),
                    None,
                    None,
                )
                .with_immediate(flag.value()),
            )?;
        } else if location.is_register() {
            self.assign_register(&location, expression)?;
        } else {
            self.values
                .insert((output, LocationRole::Value), expression);
        }

        Ok(())
    }

    fn assign_register(
        &mut self,
        location: &PCodeLocation,
        expression: IlExprId,
    ) -> Result<(), IlError> {
        let slice = self.register_bank.slice(location, self.arch.endian())?;
        let value = if slice.is_root() {
            expression
        } else {
            let root = self.register_value(slice)?;
            let operands = self.builder.push_expression_operands([root, expression])?;
            self.builder.push_expression(ECodeExpr::new(
                ECodeExprOpcode::Insert,
                slice.root_bits(),
                operands,
                u64::from(slice.offset()) * 8,
                None,
            ))?
        };

        self.register_reads.clear();
        self.register_values.insert(slice.root(), value);
        self.builder.push_statement(
            ECodeStmt::new(
                ECodeStmtOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(value),
                None,
                None,
            )
            .with_immediate(slice.root().value()),
        )?;

        Ok(())
    }

    fn lift_store(&mut self, operation: &PCodeOp) -> Result<(), IlError> {
        let operands = self.lift_statement_operands(operation, Some(0))?;

        self.builder.push_statement(ECodeStmt::new(
            ECodeStmtOpcode::Store,
            operands,
            None,
            None,
            operation.effect_space(),
        ))?;

        Ok(())
    }

    fn lift_direct_flow(
        &mut self,
        operation: &PCodeOp,
        opcode: ECodeStmtOpcode,
    ) -> Result<(), IlError> {
        let operands = self.lift_direct_flow_operands(operation)?;
        let target = self
            .source
            .target(operation.immediate())
            .expect("direct flow target is within the target pool");

        self.builder.push_statement(ECodeStmt::new(
            opcode,
            operands,
            None,
            Some(target.address()),
            None,
        ))?;

        Ok(())
    }

    fn lift_indirect_flow(
        &mut self,
        operation: &PCodeOp,
        opcode: ECodeStmtOpcode,
    ) -> Result<(), IlError> {
        let operands = self.lift_statement_operands(operation, Some(0))?;

        self.builder.push_statement(ECodeStmt::new(
            opcode,
            operands,
            None,
            None,
            operation.effect_space(),
        ))?;

        Ok(())
    }

    fn lift_statement_operands(
        &mut self,
        operation: &PCodeOp,
        address_operand: Option<usize>,
    ) -> Result<IlIndexRange, IlError> {
        self.lift_operand_values(operation, address_operand)?;

        self.builder
            .push_statement_operands(self.operands.iter().copied())
    }

    fn lift_direct_flow_operands(&mut self, operation: &PCodeOp) -> Result<IlIndexRange, IlError> {
        self.operands.clear();
        for operand_index in 1..self.source.operation_operands(operation).len() {
            let operand = self.source.operation_operands(operation)[operand_index];
            let operand = self.lift_location(operand, LocationRole::Value)?;
            self.operands.push(operand);
        }

        self.builder
            .push_statement_operands(self.operands.iter().copied())
    }

    fn lift_operand_values(
        &mut self,
        operation: &PCodeOp,
        address_operand: Option<usize>,
    ) -> Result<(), IlError> {
        self.operands.clear();
        for operand_index in 0..self.source.operation_operands(operation).len() {
            let operand = self.source.operation_operands(operation)[operand_index];
            let role = if address_operand == Some(operand_index) {
                LocationRole::Address
            } else {
                LocationRole::Value
            };
            let operand = self.lift_location(operand, role)?;
            self.operands.push(operand);
        }

        Ok(())
    }

    fn lift_location(
        &mut self,
        id: PCodeLocationId,
        role: LocationRole,
    ) -> Result<IlExprId, IlError> {
        let location = *self.location(id);
        let key = if location.is_constant() {
            (id, role)
        } else {
            (id, LocationRole::Value)
        };
        if let Some(expression) = self.values.get(&key).copied() {
            return Ok(expression);
        }

        let expression = if location.is_constant() {
            ECodeExpr::new(
                match role {
                    LocationRole::Address => ECodeExprOpcode::Address,
                    LocationRole::Value => ECodeExprOpcode::Constant,
                },
                u32::from(location.size()) * 8,
                IlIndexRange::EMPTY,
                location.offset(),
                None,
            )
        } else if let Some(flag) = self.flags.get(&location).copied() {
            if let Some(expression) = self.flag_values.get(&flag).copied() {
                return Ok(expression);
            }
            let expression = self.builder.push_expression(ECodeExpr::new(
                ECodeExprOpcode::ReadFlag,
                u32::from(location.size()) * 8,
                IlIndexRange::EMPTY,
                flag.value(),
                None,
            ))?;
            self.flag_values.insert(flag, expression);
            return Ok(expression);
        } else if location.is_register() {
            return self.lift_register(id, &location);
        } else {
            ECodeExpr::new(
                ECodeExprOpcode::Undefined,
                u32::from(location.size()) * 8,
                IlIndexRange::EMPTY,
                u64::from(id.value()),
                None,
            )
        };
        let expression = self.builder.push_expression(expression)?;

        self.values.insert(key, expression);

        Ok(expression)
    }

    fn lift_register(
        &mut self,
        id: PCodeLocationId,
        location: &PCodeLocation,
    ) -> Result<IlExprId, IlError> {
        if let Some(expression) = self.register_reads.get(&id).copied() {
            return Ok(expression);
        }

        let slice = self.register_bank.slice(location, self.arch.endian())?;
        let root = self.register_value(slice)?;
        let expression = if slice.is_root() {
            root
        } else {
            let offset = self.builder.push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                u64::BITS,
                IlIndexRange::EMPTY,
                u64::from(slice.offset()) * 8,
                None,
            ))?;
            let operands = self.builder.push_expression_operands([root, offset])?;
            self.builder.push_expression(ECodeExpr::new(
                ECodeExprOpcode::Extract,
                slice.bits(),
                operands,
                0,
                None,
            ))?
        };
        self.register_reads.insert(id, expression);

        Ok(expression)
    }

    fn register_value(&mut self, slice: RegisterSlice) -> Result<IlExprId, IlError> {
        if let Some(expression) = self.register_values.get(&slice.root()).copied() {
            return Ok(expression);
        }

        let expression = self.builder.push_expression(ECodeExpr::new(
            ECodeExprOpcode::ReadRegister,
            slice.root_bits(),
            IlIndexRange::EMPTY,
            slice.root().value(),
            None,
        ))?;
        self.register_values.insert(slice.root(), expression);

        Ok(expression)
    }

    fn location(&self, id: PCodeLocationId) -> &PCodeLocation {
        self.source
            .location(id)
            .expect("location id is within the location pool")
    }

    fn expression_opcode(&self, opcode: PCodeOpcode) -> Result<ECodeExprOpcode, IlError> {
        match opcode {
            PCodeOpcode::Copy => Ok(ECodeExprOpcode::Copy),
            PCodeOpcode::Load => Ok(ECodeExprOpcode::Load),
            PCodeOpcode::IntAdd => Ok(ECodeExprOpcode::Add),
            PCodeOpcode::IntSub => Ok(ECodeExprOpcode::Sub),
            PCodeOpcode::IntMul => Ok(ECodeExprOpcode::Mul),
            PCodeOpcode::IntDiv => Ok(ECodeExprOpcode::UnsignedDiv),
            PCodeOpcode::IntSignedDiv => Ok(ECodeExprOpcode::SignedDiv),
            PCodeOpcode::IntRem => Ok(ECodeExprOpcode::UnsignedRem),
            PCodeOpcode::IntSignedRem => Ok(ECodeExprOpcode::SignedRem),
            PCodeOpcode::IntLeftShift => Ok(ECodeExprOpcode::LeftShift),
            PCodeOpcode::IntRightShift => Ok(ECodeExprOpcode::LogicalRightShift),
            PCodeOpcode::IntSignedRightShift => Ok(ECodeExprOpcode::ArithmeticRightShift),
            PCodeOpcode::IntEq => Ok(ECodeExprOpcode::IntEqual),
            PCodeOpcode::IntNotEq => Ok(ECodeExprOpcode::IntNotEqual),
            PCodeOpcode::IntLess => Ok(ECodeExprOpcode::IntLess),
            PCodeOpcode::IntSignedLess => Ok(ECodeExprOpcode::IntSignedLess),
            PCodeOpcode::IntLessEq => Ok(ECodeExprOpcode::IntLessEqual),
            PCodeOpcode::IntSignedLessEq => Ok(ECodeExprOpcode::IntSignedLessEqual),
            PCodeOpcode::IntCarry => Ok(ECodeExprOpcode::Carry),
            PCodeOpcode::IntSignedCarry => Ok(ECodeExprOpcode::SignedCarry),
            PCodeOpcode::IntSignedBorrow => Ok(ECodeExprOpcode::SignedBorrow),
            PCodeOpcode::IntAnd => Ok(ECodeExprOpcode::And),
            PCodeOpcode::IntOr => Ok(ECodeExprOpcode::Or),
            PCodeOpcode::IntXor => Ok(ECodeExprOpcode::Xor),
            PCodeOpcode::IntNot => Ok(ECodeExprOpcode::Not),
            PCodeOpcode::BoolAnd => Ok(ECodeExprOpcode::BoolAnd),
            PCodeOpcode::BoolOr => Ok(ECodeExprOpcode::BoolOr),
            PCodeOpcode::BoolXor => Ok(ECodeExprOpcode::BoolXor),
            PCodeOpcode::BoolNot => Ok(ECodeExprOpcode::BoolNot),
            PCodeOpcode::IntNeg => Ok(ECodeExprOpcode::Negate),
            PCodeOpcode::CountOnes => Ok(ECodeExprOpcode::CountOnes),
            PCodeOpcode::CountLeadingZeros => Ok(ECodeExprOpcode::CountLeadingZeros),
            PCodeOpcode::ZeroExt => Ok(ECodeExprOpcode::ZeroExtend),
            PCodeOpcode::SignExt => Ok(ECodeExprOpcode::SignExtend),
            PCodeOpcode::Subpiece => Ok(ECodeExprOpcode::Extract),
            PCodeOpcode::FloatAdd => Ok(ECodeExprOpcode::FloatAdd),
            PCodeOpcode::FloatSub => Ok(ECodeExprOpcode::FloatSub),
            PCodeOpcode::FloatMul => Ok(ECodeExprOpcode::FloatMul),
            PCodeOpcode::FloatDiv => Ok(ECodeExprOpcode::FloatDiv),
            PCodeOpcode::FloatNeg => Ok(ECodeExprOpcode::FloatNegate),
            PCodeOpcode::FloatAbs => Ok(ECodeExprOpcode::FloatAbs),
            PCodeOpcode::FloatSqrt => Ok(ECodeExprOpcode::FloatSqrt),
            PCodeOpcode::FloatCeiling => Ok(ECodeExprOpcode::FloatCeiling),
            PCodeOpcode::FloatFloor => Ok(ECodeExprOpcode::FloatFloor),
            PCodeOpcode::FloatRound => Ok(ECodeExprOpcode::FloatRound),
            PCodeOpcode::FloatIsNan => Ok(ECodeExprOpcode::FloatIsNan),
            PCodeOpcode::FloatEq => Ok(ECodeExprOpcode::FloatEqual),
            PCodeOpcode::FloatNotEq => Ok(ECodeExprOpcode::FloatNotEqual),
            PCodeOpcode::FloatLess => Ok(ECodeExprOpcode::FloatLess),
            PCodeOpcode::FloatLessEq => Ok(ECodeExprOpcode::FloatLessEqual),
            PCodeOpcode::FloatToInt => Ok(ECodeExprOpcode::FloatToInt),
            PCodeOpcode::FloatToFloat => Ok(ECodeExprOpcode::FloatToFloat),
            PCodeOpcode::IntToFloat => Ok(ECodeExprOpcode::IntToFloat),
            PCodeOpcode::UserOp => Ok(ECodeExprOpcode::IntrinsicResult),
            PCodeOpcode::Store
            | PCodeOpcode::Branch
            | PCodeOpcode::CBranch
            | PCodeOpcode::IBranch
            | PCodeOpcode::Call
            | PCodeOpcode::ICall
            | PCodeOpcode::Return => Err(IlError::unsupported_opcode(IlLevel::ECode)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::{IlBlock, IlBlockId, IlBlockProperties, IlGraph, IlIndexRange};
    use crate::il::ecode::ssa::ECodeToSsa;
    use crate::il::pcode::{
        LifterSpaceHandle, PCODE_SCHEMA_VERSION, PCodeBuilder, PCodeLocation,
        PCodeLocationProperties, PCodeOp, PCodeOpcode,
    };
    use crate::ir::{Address, FunctionId};
    use crate::lifter::{Language, resolve_language};
    use crate::storage::segments::space::AddressSpaceId;

    fn language() -> &'static Language {
        resolve_language("x86:LE:64").expect("test language should resolve")
    }

    fn arch() -> Arch {
        Arch::new(language())
    }

    #[test]
    fn empty_pcode_lifts_to_empty_ecode() {
        let source_header = IlMetadata::new(FunctionId::default(), PCODE_SCHEMA_VERSION, 11);
        let source = PCodeBuilder::new(language(), source_header, IlGraph::default())
            .build(&CancellationToken::default())
            .unwrap();
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode::default();

        let lifted = transform
            .transform(&source, &arch(), &cancellation)
            .unwrap();

        assert_eq!(lifted.metadata().input_revision().value(), 11);
        assert!(lifted.statements().is_empty());
    }

    #[test]
    fn copy_pcode_lifts_to_ecode_write() {
        let source = copy_source();
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode::default();

        let lifted = transform
            .transform(&source, &arch(), &cancellation)
            .unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        assert_eq!(lifted.expressions()[1].opcode(), ECodeExprOpcode::Copy);
        assert_eq!(lifted.statements().len(), 1);
        assert_eq!(
            lifted.statements()[0].opcode(),
            ECodeStmtOpcode::WriteRegister
        );
        assert_eq!(lifted.statements()[0].immediate(), 8);
        assert_eq!(
            lifted.parent_spans(),
            &[IlParentSpan::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::new(0, 1).unwrap(),
            )]
        );
    }

    #[test]
    fn partial_registers_share_one_full_width_domain() {
        let language = language();
        let rax = language.register_by_name("RAX").expect("RAX should exist");
        let al = language.register_by_name("AL").expect("AL should exist");
        let ah = language.register_by_name("AH").expect("AH should exist");
        let ax = language.register_by_name("AX").expect("AX should exist");
        let mut builder = PCodeBuilder::new(language, pcode_header(), IlGraph::default());
        let constant = builder
            .push_location(PCodeLocation::from_varnode(
                language,
                &Varnode::constant(0x12, 1),
            ))
            .unwrap();
        let al = builder
            .push_location(PCodeLocation::from_varnode(language, &al))
            .unwrap();
        let ah = builder
            .push_location(PCodeLocation::from_varnode(language, &ah))
            .unwrap();
        let ax = builder
            .push_location(PCodeLocation::from_varnode(language, &ax))
            .unwrap();
        let high = builder
            .push_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x100, 1),
            ))
            .unwrap();
        let word = builder
            .push_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x200, 2),
            ))
            .unwrap();
        let operands = builder.push_operands([constant]).unwrap();
        builder.push_operation(PCodeOp::new(PCodeOpcode::Copy, Some(ah), operands, 0, None));
        let operands = builder.push_operands([al]).unwrap();
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(high),
            operands,
            0,
            None,
        ));
        let operands = builder.push_operands([ax]).unwrap();
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(word),
            operands,
            0,
            None,
        ));
        let source = builder.build(&CancellationToken::default()).unwrap();
        let mut transform = PCodeToECode::default();

        let lifted = transform
            .transform(&source, &arch(), &CancellationToken::default())
            .unwrap();
        let register_reads = lifted
            .expressions()
            .iter()
            .filter(|expression| expression.opcode() == ECodeExprOpcode::ReadRegister)
            .collect::<Vec<_>>();
        let extracts = lifted
            .expressions()
            .iter()
            .filter(|expression| expression.opcode() == ECodeExprOpcode::Extract)
            .collect::<Vec<_>>();
        let insert = lifted
            .expressions()
            .iter()
            .find(|expression| expression.opcode() == ECodeExprOpcode::Insert)
            .expect("partial write should insert into the root");

        assert_eq!(register_reads.len(), 1);
        assert_eq!(register_reads[0].immediate(), rax.offset());
        assert_eq!(register_reads[0].width(), 64);
        assert_eq!(insert.width(), 64);
        assert_eq!(insert.immediate(), 8);
        assert_eq!(
            extracts
                .iter()
                .map(|extract| extract.width())
                .collect::<Vec<_>>(),
            vec![8, 16]
        );
        assert_eq!(lifted.statements().len(), 1);
        assert_eq!(
            lifted.statements()[0].opcode(),
            ECodeStmtOpcode::WriteRegister
        );
        assert_eq!(lifted.statements()[0].immediate(), rax.offset());
        lifted.verify().unwrap();

        let ssa = ECodeToSsa::default()
            .transform(&lifted, &CancellationToken::default())
            .unwrap();
        ssa.verify().unwrap();
    }

    #[test]
    fn architectural_flags_use_flag_operations() {
        let language = language();
        let cf = language.register_by_name("CF").expect("CF should exist");
        let mut builder = PCodeBuilder::new(language, pcode_header(), IlGraph::default());
        let flag = builder
            .push_location(PCodeLocation::from_varnode(language, &cf))
            .unwrap();
        let read = builder
            .push_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x100, cf.size),
            ))
            .unwrap();
        let constant = builder
            .push_location(PCodeLocation::from_varnode(
                language,
                &Varnode::constant(1, cf.size),
            ))
            .unwrap();
        let operands = builder.push_operands([flag]).unwrap();
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(read),
            operands,
            0,
            None,
        ));
        let operands = builder.push_operands([constant]).unwrap();
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(flag),
            operands,
            0,
            None,
        ));
        let source = builder.build(&CancellationToken::default()).unwrap();

        let lifted = PCodeToECode::default()
            .transform(&source, &arch(), &CancellationToken::default())
            .unwrap();

        assert!(lifted.expressions().iter().any(|expression| {
            expression.opcode() == ECodeExprOpcode::ReadFlag
                && expression.immediate() == cf.offset()
        }));
        assert!(lifted.statements().iter().any(|statement| {
            statement.opcode() == ECodeStmtOpcode::WriteFlag && statement.immediate() == cf.offset()
        }));
        assert!(
            !lifted
                .expressions()
                .iter()
                .any(|expression| expression.opcode() == ECodeExprOpcode::ReadRegister)
        );
        lifted.verify().unwrap();
    }

    #[test]
    fn unresolved_unique_input_lifts_to_undefined() {
        let language = language();
        let mut builder = PCodeBuilder::new(language, pcode_header(), IlGraph::default());
        let input = builder
            .push_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x100, 8),
            ))
            .unwrap();
        let output = builder
            .push_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x200, 8),
            ))
            .unwrap();
        let operands = builder.push_operands([input]).unwrap();
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(output),
            operands,
            0,
            None,
        ));
        let source = builder.build(&CancellationToken::default()).unwrap();

        let lifted = PCodeToECode::default()
            .transform(&source, &arch(), &CancellationToken::default())
            .unwrap();

        assert_eq!(lifted.expressions()[0].opcode(), ECodeExprOpcode::Undefined);
        lifted.verify().unwrap();
    }

    #[test]
    fn trap_intrinsic_lifts_to_trap_statement() {
        let language = language();
        let trap = language
            .user_op_by_name("invalidInstructionException")
            .expect("x86 trap intrinsic should exist");
        let mut builder = PCodeBuilder::new(language, pcode_header(), IlGraph::default());
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::UserOp,
            None,
            IlIndexRange::EMPTY,
            u32::from(trap),
            None,
        ));
        let source = builder.build(&CancellationToken::default()).unwrap();

        let lifted = PCodeToECode::default()
            .transform(&source, &arch(), &CancellationToken::default())
            .unwrap();

        assert!(lifted.expressions().is_empty());
        assert_eq!(lifted.statements().len(), 1);
        assert_eq!(lifted.statements()[0].opcode(), ECodeStmtOpcode::Trap);
        assert_eq!(lifted.statements()[0].immediate(), u64::from(trap));
        lifted.verify().unwrap();
    }

    #[test]
    fn unique_output_pcode_does_not_lift_to_register_write() {
        let source = unique_copy_source();
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode::default();

        let lifted = transform
            .transform(&source, &arch(), &cancellation)
            .unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        assert!(lifted.statements().is_empty());
        assert!(lifted.parent_spans().is_empty());
    }

    #[test]
    fn user_op_result_preserves_operands() {
        let mut builder = PCodeBuilder::new(language(), pcode_header(), IlGraph::default());
        let input = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(1),
                8,
                8,
                PCodeLocationProperties::UNIQUE,
            ))
            .unwrap();
        let operands = builder.push_operands([input]).unwrap();
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::UserOp,
            Some(output),
            operands,
            7,
            None,
        ));
        let source = builder.build(&CancellationToken::default()).unwrap();
        let mut transform = PCodeToECode::default();

        let lifted = transform
            .transform(&source, &arch(), &CancellationToken::default())
            .unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        assert_eq!(
            lifted.expressions()[1].opcode(),
            ECodeExprOpcode::IntrinsicResult
        );
        assert_eq!(lifted.expressions()[1].operands().len(), 1);
        lifted.verify().unwrap();
    }

    #[test]
    fn store_pcode_lifts_to_ecode_store_with_fugue_space() {
        let source = store_source();
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode::default();

        let lifted = transform
            .transform(&source, &arch(), &cancellation)
            .unwrap();

        assert_eq!(lifted.statements().len(), 1);
        assert_eq!(lifted.statements()[0].opcode(), ECodeStmtOpcode::Store);
        let operands = lifted.statement_operands_for(&lifted.statements()[0]);
        assert_eq!(
            lifted.expressions()[operands[0].index()].opcode(),
            ECodeExprOpcode::Address
        );
        assert_eq!(
            lifted.expressions()[operands[1].index()].opcode(),
            ECodeExprOpcode::Constant
        );
        assert_eq!(
            lifted.statements()[0].address_space(),
            Some(AddressSpaceId::new(7))
        );
    }

    #[test]
    fn constant_cache_distinguishes_address_and_value_roles() {
        let mut builder = PCodeBuilder::new(language(), pcode_header(), IlGraph::default());
        let constant = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                0x1000,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let operands = builder.push_operands([constant, constant]).unwrap();
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Store,
            None,
            operands,
            0,
            Some(AddressSpaceId::new(7)),
        ));
        let source = builder.build(&CancellationToken::default()).unwrap();

        let lifted = PCodeToECode::default()
            .transform(&source, &arch(), &CancellationToken::default())
            .unwrap();
        let operands = lifted.statement_operands_for(&lifted.statements()[0]);

        assert_ne!(operands[0], operands[1]);
        assert_eq!(
            lifted.expressions()[operands[0].index()].opcode(),
            ECodeExprOpcode::Address
        );
        assert_eq!(
            lifted.expressions()[operands[1].index()].opcode(),
            ECodeExprOpcode::Constant
        );
        lifted.verify().unwrap();
    }

    #[test]
    fn branch_pcode_lifts_to_ecode_branch_with_target() {
        let target = Address::new(AddressSpaceId::new(3), 0x2000u64);
        let source = branch_source(target);
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode::default();

        let lifted = transform
            .transform(&source, &arch(), &cancellation)
            .unwrap();

        assert_eq!(lifted.statements().len(), 1);
        assert_eq!(lifted.statements()[0].opcode(), ECodeStmtOpcode::Branch);
        assert_eq!(lifted.statements()[0].address(), Some(target));
        lifted.verify().unwrap();
    }

    #[test]
    fn indirect_branch_preserves_recovered_successors() {
        let mut builder = PCodeBuilder::new(language(), pcode_header(), IlGraph::default());
        let target = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(1),
                8,
                8,
                PCodeLocationProperties::REGISTER,
            ))
            .unwrap();
        let operands = builder.push_operands([target]).unwrap();
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::IBranch,
            None,
            operands,
            0,
            Some(AddressSpaceId::new(3)),
        ));
        builder.replace_graph(IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::new(0, 1).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            vec![IlBlockId::try_from_index(1).unwrap()],
        ));
        let source = builder.build(&CancellationToken::default()).unwrap();
        let mut transform = PCodeToECode::default();

        let lifted = transform
            .transform(&source, &arch(), &CancellationToken::default())
            .unwrap();
        let entry = &lifted.graph().blocks()[0];

        assert_eq!(
            entry.successors().slice(lifted.graph().successors()),
            &[IlBlockId::try_from_index(1).unwrap()]
        );
        assert!(!entry.is_exit());
        lifted.verify().unwrap();
    }

    #[test]
    fn return_pcode_lifts_to_ecode_return_with_fugue_space() {
        let source = return_source(AddressSpaceId::new(9));
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode::default();

        let lifted = transform
            .transform(&source, &arch(), &cancellation)
            .unwrap();

        assert_eq!(lifted.statements().len(), 1);
        assert_eq!(lifted.statements()[0].opcode(), ECodeStmtOpcode::Return);
        let target = lifted.statement_operands_for(&lifted.statements()[0])[0];
        assert_eq!(
            lifted.expressions()[target.index()].opcode(),
            ECodeExprOpcode::Address
        );
        assert_eq!(
            lifted.statements()[0].address_space(),
            Some(AddressSpaceId::new(9))
        );
    }

    fn pcode_header() -> IlMetadata {
        IlMetadata::new(FunctionId::default(), PCODE_SCHEMA_VERSION, 11)
    }

    fn copy_source() -> PCodeIr {
        let mut builder = PCodeBuilder::new(language(), pcode_header(), IlGraph::default());
        let input = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(1),
                8,
                8,
                PCodeLocationProperties::REGISTER,
            ))
            .unwrap();
        let operands = builder.push_operands([input]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(output),
            operands,
            0,
            None,
        ));

        builder.build(&CancellationToken::default()).unwrap()
    }

    fn unique_copy_source() -> PCodeIr {
        let mut builder = PCodeBuilder::new(language(), pcode_header(), IlGraph::default());
        let input = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(2),
                8,
                8,
                PCodeLocationProperties::UNIQUE,
            ))
            .unwrap();
        let operands = builder.push_operands([input]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(output),
            operands,
            0,
            None,
        ));

        builder.build(&CancellationToken::default()).unwrap()
    }

    fn store_source() -> PCodeIr {
        let mut builder = PCodeBuilder::new(language(), pcode_header(), IlGraph::default());
        let offset = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                0x1000,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let value = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                0xff,
                1,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let operands = builder.push_operands([offset, value]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Store,
            None,
            operands,
            0,
            Some(AddressSpaceId::new(7)),
        ));

        builder.build(&CancellationToken::default()).unwrap()
    }

    fn branch_source(target: Address) -> PCodeIr {
        let mut builder = PCodeBuilder::new(language(), pcode_header(), IlGraph::default());
        let target_location = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                target.offset(),
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let operands = builder.push_operands([target_location]).unwrap();
        let target = builder.push_target(target.into()).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Branch,
            None,
            operands,
            target,
            None,
        ));

        builder.build(&CancellationToken::default()).unwrap()
    }

    fn return_source(space: AddressSpaceId) -> PCodeIr {
        let mut builder = PCodeBuilder::new(language(), pcode_header(), IlGraph::default());
        let target = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                0x1000,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let operands = builder.push_operands([target]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Return,
            None,
            operands,
            0,
            Some(space),
        ));

        builder.build(&CancellationToken::default()).unwrap()
    }
}
