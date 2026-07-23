use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlBlock, IlBlockId, IlBlockProperties, IlError, IlExprId, IlGraph, IlHeader, IlIndexRange,
    IlLevel, IlSourceSpan,
};
use crate::il::ecode::{
    ECODE_SCHEMA_VERSION, ECodeBuilder, ECodeExpr, ECodeExprOpcode, ECodeIr, ECodeStmt,
    ECodeStmtOpcode,
};
use crate::il::pcode::{PCodeIr, PCodeLocation, PCodeLocationId, PCodeOp, PCodeOpcode};

#[derive(Debug, Default)]
pub struct PCodeToECode;

impl PCodeToECode {
    pub fn transform(
        &mut self,
        source: &PCodeIr,
        cancellation: &CancellationToken,
    ) -> Result<ECodeIr, IlError> {
        cancellation.check()?;

        let header = IlHeader::new(
            source.header().function(),
            ECODE_SCHEMA_VERSION,
            source.header().input_revision(),
        );
        let mut builder = ECodeBuilder::new(header, IlGraph::default());
        let mut lifting = ECodeLifting::new(source, &mut builder);

        let offsets = lifting.lift(cancellation)?;
        drop(lifting);

        builder.replace_graph(Self::remap_graph(source, &offsets)?);
        builder.replace_source_spans(Self::remap_source_spans(source, &offsets)?);

        builder.build(cancellation)
    }

    fn remap_graph(source: &PCodeIr, offsets: &[u32]) -> Result<IlGraph, IlError> {
        let mut partitions = Vec::new();
        let mut partition_ranges = Vec::with_capacity(source.graph().blocks().len());
        let mut first_blocks = Vec::with_capacity(source.graph().blocks().len());
        let mut refined_block_count = 0usize;
        let mut boundaries = Vec::new();

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
                    Self::internal_target(source, operations, operation_index, operation)
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
                        if operation.opcode() == PCodeOpcode::Branch =>
                    {
                        if let Some(target) = Self::internal_target(
                            source,
                            source_block.operations(),
                            operation_index,
                            operation,
                        )
                        .and_then(|target| {
                            Self::refined_target(first_blocks[block_index], ranges, target)
                        }) {
                            Self::push_successor(&mut block_successors, target);
                        } else {
                            Self::push_mapped_successors(
                                &mut block_successors,
                                original_successors,
                                &first_blocks,
                            );
                        }
                    }
                    Some((operation_index, operation))
                        if operation.opcode() == PCodeOpcode::CBranch =>
                    {
                        if let Some(target) = Self::internal_target(
                            source,
                            source_block.operations(),
                            operation_index,
                            operation,
                        )
                        .and_then(|target| {
                            Self::refined_target(first_blocks[block_index], ranges, target)
                        }) {
                            Self::push_successor(&mut block_successors, target);
                        } else {
                            Self::push_mapped_successors(
                                &mut block_successors,
                                original_successors,
                                &first_blocks,
                            );
                        }
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
                    Some((_, operation)) if operation.opcode() == PCodeOpcode::IBranch => {}
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
                        u32::try_from(range.start())
                            .ok()
                            .and_then(|operation| source.source_span_for(operation))
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
        let source_span = source.source_span_for(u32::try_from(operation_index).ok()?)?;

        if target.address() != source_span.address() {
            return source
                .source_spans()
                .iter()
                .find(|span| {
                    span.address() == target.address()
                        && block.start() <= span.destination().start()
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

struct ECodeLifting<'a, 'b> {
    source: &'a PCodeIr,
    builder: &'b mut ECodeBuilder,
    values: FxHashMap<PCodeLocationId, IlExprId>,
}

impl<'a, 'b> ECodeLifting<'a, 'b> {
    fn new(source: &'a PCodeIr, builder: &'b mut ECodeBuilder) -> Self {
        Self {
            source,
            builder,
            values: FxHashMap::default(),
        }
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
        let operands = self.lift_statement_operands(operation)?;
        self.builder.push_statement(
            ECodeStmt::new(
                ECodeStmtOpcode::Intrinsic,
                operands,
                None,
                None,
                operation.effect_space(),
            )
            .with_immediate(operation.immediate() as u64),
        )?;

        Ok(())
    }

    fn lift_expression_operation(
        &mut self,
        operation: &PCodeOp,
        opcode: PCodeOpcode,
    ) -> Result<(), IlError> {
        let Some(output) = operation.output() else {
            return Err(IlError::missing_component(IlLevel::PCode, "output"));
        };
        let output_width = self.location(output).width() as u32 * 8;
        let operands = self.lift_expression_operands(operation)?;
        let expression_opcode = self.expression_opcode(opcode)?;
        let expression = ECodeExpr::new(
            expression_opcode,
            output_width,
            operands,
            operation.immediate() as u64,
            operation.effect_space(),
        );
        let expression = self.builder.push_expression(expression)?;

        self.values.insert(output, expression);

        if self.location(output).is_register() {
            self.builder.push_statement(
                ECodeStmt::new(
                    ECodeStmtOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(expression),
                    None,
                    None,
                )
                .with_immediate(output.value() as u64),
            )?;
        }

        Ok(())
    }

    fn lift_store(&mut self, operation: &PCodeOp) -> Result<(), IlError> {
        let operands = self.lift_statement_operands(operation)?;

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
        let operands = self.lift_statement_operands(operation)?;

        self.builder.push_statement(ECodeStmt::new(
            opcode,
            operands,
            None,
            None,
            operation.effect_space(),
        ))?;

        Ok(())
    }

    fn lift_expression_operands(&mut self, operation: &PCodeOp) -> Result<IlIndexRange, IlError> {
        let operands = self.lift_operand_values(operation)?;

        self.builder.push_expression_operands(operands)
    }

    fn lift_statement_operands(&mut self, operation: &PCodeOp) -> Result<IlIndexRange, IlError> {
        let operands = self.lift_operand_values(operation)?;

        self.builder.push_statement_operands(operands)
    }

    fn lift_direct_flow_operands(&mut self, operation: &PCodeOp) -> Result<IlIndexRange, IlError> {
        let operands = self
            .source
            .operation_operands(operation)
            .iter()
            .skip(1)
            .copied()
            .map(|operand| self.lift_location(operand))
            .collect::<Result<Vec<_>, IlError>>()?;

        self.builder.push_statement_operands(operands)
    }

    fn lift_operand_values(&mut self, operation: &PCodeOp) -> Result<Vec<IlExprId>, IlError> {
        let operands = self
            .source
            .operation_operands(operation)
            .iter()
            .map(|operand| self.lift_location(*operand))
            .collect::<Result<Vec<_>, IlError>>()?;

        Ok(operands)
    }

    fn lift_location(&mut self, id: PCodeLocationId) -> Result<IlExprId, IlError> {
        let location = *self.location(id);
        if let Some(expression) = self.values.get(&id).copied() {
            return Ok(expression);
        }

        let expression = if location.is_constant() {
            ECodeExpr::new(
                ECodeExprOpcode::Constant,
                location.width() as u32 * 8,
                IlIndexRange::EMPTY,
                location.offset(),
                None,
            )
        } else {
            ECodeExpr::new(
                ECodeExprOpcode::ReadRegister,
                location.width() as u32 * 8,
                IlIndexRange::EMPTY,
                id.value() as u64,
                None,
            )
        };
        let expression = self.builder.push_expression(expression)?;

        self.values.insert(id, expression);

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
    use crate::il::common::IlGraph;
    use crate::il::ecode::verify;
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

    #[test]
    fn empty_pcode_lifts_to_empty_ecode() {
        let source_header = IlHeader::new(FunctionId::default(), PCODE_SCHEMA_VERSION, 11);
        let source = PCodeBuilder::new(language(), source_header, IlGraph::default())
            .build(&CancellationToken::default())
            .unwrap();
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode;

        let lifted = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(lifted.header().input_revision(), 11);
        assert!(lifted.statements().is_empty());
    }

    #[test]
    fn copy_pcode_lifts_to_ecode_write() {
        let source = copy_source();
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode;

        let lifted = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        assert_eq!(lifted.expressions()[1].opcode(), ECodeExprOpcode::Copy);
        assert_eq!(lifted.statements().len(), 1);
        assert_eq!(
            lifted.statements()[0].opcode(),
            ECodeStmtOpcode::WriteRegister
        );
        assert_eq!(lifted.statements()[0].immediate(), 2);
    }

    #[test]
    fn unique_output_pcode_does_not_lift_to_register_write() {
        let source = unique_copy_source();
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode;

        let lifted = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        assert!(lifted.statements().is_empty());
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
        let mut transform = PCodeToECode;

        let lifted = transform
            .transform(&source, &CancellationToken::default())
            .unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        assert_eq!(
            lifted.expressions()[1].opcode(),
            ECodeExprOpcode::IntrinsicResult
        );
        assert_eq!(lifted.expressions()[1].operands().len(), 1);
        verify(&lifted).unwrap();
    }

    #[test]
    fn store_pcode_lifts_to_ecode_store_with_fugue_space() {
        let source = store_source();
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode;

        let lifted = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(lifted.statements().len(), 1);
        assert_eq!(lifted.statements()[0].opcode(), ECodeStmtOpcode::Store);
        assert_eq!(
            lifted.statements()[0].address_space(),
            Some(AddressSpaceId::new(7))
        );
    }

    #[test]
    fn branch_pcode_lifts_to_ecode_branch_with_target() {
        let target = Address::new(AddressSpaceId::new(3), 0x2000u64);
        let source = branch_source(target);
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode;

        let lifted = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(lifted.statements().len(), 1);
        assert_eq!(lifted.statements()[0].opcode(), ECodeStmtOpcode::Branch);
        assert_eq!(lifted.statements()[0].address(), Some(target));
        verify(&lifted).unwrap();
    }

    #[test]
    fn return_pcode_lifts_to_ecode_return_with_fugue_space() {
        let source = return_source(AddressSpaceId::new(9));
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode;

        let lifted = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(lifted.statements().len(), 1);
        assert_eq!(lifted.statements()[0].opcode(), ECodeStmtOpcode::Return);
        assert_eq!(
            lifted.statements()[0].address_space(),
            Some(AddressSpaceId::new(9))
        );
    }

    fn pcode_header() -> IlHeader {
        IlHeader::new(FunctionId::default(), PCODE_SCHEMA_VERSION, 11)
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
