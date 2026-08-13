use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::analysis::control::CancellationToken;
use crate::arch::Arch;
use crate::il::common::{
    IlBlock, IlBlockId, IlBlockProperties, IlConverter, IlEdgeKinds, IlError, IlExprId,
    IlGenerationContext, IlGenerationError, IlGraph, IlIndexMapper, IlIndexRange, IlMetadata,
    IlParentSpan, IlSourceSpan,
};
use crate::il::ecode::{ECodeBuilder, ECodeIr, ECodeLiftScratch, ECodeLifter};
use crate::il::pcode::{PCodeIr, PCodeOp, PCodeOpcode};
use crate::ir::Address;
use crate::platform::Platform;

#[derive(Debug, Default)]
struct BlockSuccessors {
    targets: SmallVec<[IlBlockId; 2]>,
    kinds: SmallVec<[IlEdgeKinds; 2]>,
}

impl BlockSuccessors {
    fn push(&mut self, target: IlBlockId, kind: IlEdgeKinds) {
        match self.targets.iter().position(|entry| *entry == target) {
            Some(index) => self.kinds[index] |= kind,
            None => {
                self.targets.push(target);
                self.kinds.push(kind);
            }
        }
    }

    fn extend_mapped_within(
        &mut self,
        additions: &[IlBlockId],
        addition_kinds: &[IlEdgeKinds],
        first_blocks: &[IlBlockId],
        permitted: IlEdgeKinds,
    ) {
        for (successor, kind) in additions.iter().zip(addition_kinds) {
            let narrowed = *kind & permitted;
            let kind = if narrowed.is_empty() {
                permitted
            } else {
                narrowed
            };
            self.push(first_blocks[successor.index()], kind);
        }
    }
}

#[derive(Debug, Default)]
pub struct PCodeToECode {
    scratch: ECodeLiftScratch<IlExprId>,
    source_spans_by_address: FxHashMap<Address, SmallVec<[IlSourceSpan; 1]>>,
}

impl IlConverter for PCodeToECode {
    type Input = PCodeIr;
    type Output = ECodeIr;

    fn convert(
        &mut self,
        source: &Self::Input,
        context: &IlGenerationContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<Self::Output, IlGenerationError> {
        let ecode = self.transform(source, context.arch(), context.platform(), cancellation)?;

        #[cfg(debug_assertions)]
        if !context.is_speculative() {
            ecode
                .verify()
                .expect("transformed ecode fails verification");
        }

        Ok(ecode)
    }
}

impl PCodeToECode {
    pub fn transform(
        &mut self,
        source: &PCodeIr,
        arch: &Arch,
        platform: &Platform,
        cancellation: &CancellationToken,
    ) -> Result<ECodeIr, IlError> {
        cancellation.check()?;

        let metadata = IlMetadata::new(
            source.metadata().function(),
            source.metadata().input_revision(),
        );
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
        let mut lifter = ECodeLifter::new(source, arch, &mut builder, &mut self.scratch)?;

        let operation_map = lifter.lift(cancellation)?;
        let call_preserved_registers = lifter.register_bank().call_preserved_registers(
            arch.language(),
            arch.endian(),
            platform.compiler_spec_id(),
        )?;

        builder.set_call_preserved_registers(call_preserved_registers);
        builder.set_graph(self.remap_graph(source, &operation_map)?);
        builder.set_parent_spans(Self::remap_parent_spans(source, &operation_map)?);
        builder.set_source_spans(Self::remap_source_spans(source, &operation_map)?);

        builder.build(cancellation)
    }

    fn remap_graph(
        &mut self,
        source: &PCodeIr,
        operation_map: &IlIndexMapper,
    ) -> Result<IlGraph, IlError> {
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
        let mut successor_kinds = Vec::new();
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
                let mut block_successors = BlockSuccessors::default();
                let next = (range_index + 1 < ranges.len()).then(|| {
                    IlBlockId::try_from_index(first_blocks[block_index].index() + range_index + 1)
                        .expect("refined block id was validated while partitioning")
                });
                let original_successors =
                    source_block.successors().slice(source.graph().successors());
                let original_kinds = source_block
                    .successors()
                    .slice(source.graph().successor_kinds());

                match range
                    .end()
                    .checked_sub(1)
                    .filter(|index| *index >= range.start())
                    .and_then(|index| {
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
                        let conditional = operation.opcode() == PCodeOpcode::CBranch;
                        let permitted = match (conditional, next) {
                            (false, _) => IlEdgeKinds::UNCONDITIONAL,
                            (true, Some(_)) => IlEdgeKinds::TAKEN,
                            (true, None) => IlEdgeKinds::TAKEN | IlEdgeKinds::FALL_THROUGH,
                        };

                        let taken_arm = self
                            .internal_target(
                                source,
                                source_block.operations(),
                                operation_index,
                                operation,
                            )
                            .and_then(|target| {
                                Self::refined_target(first_blocks[block_index], ranges, target)
                            })
                            .or_else(|| {
                                Self::external_target(
                                    source,
                                    operation,
                                    original_successors,
                                    &first_blocks,
                                )
                            });

                        if let Some(target) = taken_arm {
                            let taken = if conditional {
                                IlEdgeKinds::TAKEN
                            } else {
                                IlEdgeKinds::UNCONDITIONAL
                            };
                            block_successors.push(target, taken);
                        } else {
                            block_successors.extend_mapped_within(
                                original_successors,
                                original_kinds,
                                &first_blocks,
                                permitted,
                            );
                        }
                        if conditional {
                            match next {
                                Some(next) => {
                                    block_successors.push(next, IlEdgeKinds::FALL_THROUGH)
                                }
                                None => block_successors.extend_mapped_within(
                                    original_successors,
                                    original_kinds,
                                    &first_blocks,
                                    permitted,
                                ),
                            }
                        }
                    }
                    Some((_, operation)) if operation.opcode() == PCodeOpcode::IBranch => {
                        block_successors.extend_mapped_within(
                            original_successors,
                            original_kinds,
                            &first_blocks,
                            IlEdgeKinds::COMPUTED,
                        );
                    }
                    Some((_, operation)) if operation.opcode() == PCodeOpcode::Return => {}
                    _ => match next {
                        Some(next) => block_successors.push(next, IlEdgeKinds::FALL_THROUGH),
                        None => block_successors.extend_mapped_within(
                            original_successors,
                            original_kinds,
                            &first_blocks,
                            IlEdgeKinds::FALL_THROUGH | IlEdgeKinds::UNCONDITIONAL,
                        ),
                    },
                }

                let successor_start = successors.len();
                successors.extend(block_successors.targets);
                successor_kinds.extend(block_successors.kinds);
                let mut properties = IlBlockProperties::empty();
                if source_block.is_entry() && range_index == 0 {
                    properties |= IlBlockProperties::ENTRY;
                }
                if successor_start == successors.len() {
                    properties |= IlBlockProperties::EXIT;
                }
                blocks.push(IlBlock::new(
                    operation_map.map_range(range),
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

        let graph = IlGraph::new(blocks, successors, successor_kinds);
        Ok(match block_sources {
            Some(block_sources) => graph.with_block_sources(block_sources),
            None => graph,
        })
    }

    fn external_target(
        source: &PCodeIr,
        operation: &PCodeOp,
        successors: &[IlBlockId],
        first_blocks: &[IlBlockId],
    ) -> Option<IlBlockId> {
        let address = source.target(operation.immediate())?.address();
        let sources = source.graph().block_sources();
        let mut resolved = successors
            .iter()
            .filter(|successor| sources.get(successor.index()).copied() == Some(address));
        let target = resolved.next()?;
        resolved
            .next()
            .is_none()
            .then(|| first_blocks[target.index()])
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

    fn remap_parent_spans(
        source: &PCodeIr,
        operation_map: &IlIndexMapper,
    ) -> Result<Vec<IlParentSpan>, IlError> {
        let mut spans = Vec::<IlParentSpan>::new();
        for source in 0..source.operations().len() {
            let source_range = IlIndexRange::new(source, source + 1)?;
            let destination = operation_map.map_range(source_range);
            if destination.is_empty() {
                continue;
            }
            let span = IlParentSpan::new(destination, source_range);
            if let Some(previous) = spans.last_mut()
                && previous.try_merge(span)?
            {
                continue;
            }
            spans.push(span);
        }
        Ok(spans)
    }

    fn remap_source_spans(
        source: &PCodeIr,
        operation_map: &IlIndexMapper,
    ) -> Result<Vec<IlSourceSpan>, IlError> {
        source
            .source_spans()
            .iter()
            .map(|span| {
                let destination = span.destination();
                Ok(IlSourceSpan::new(
                    operation_map.map_range(destination),
                    span.address(),
                    span.first_pcode_index(),
                    span.pcode_count(),
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::{FlagId, IlError, RegisterId};
    use crate::il::ecode::ssa::ECodeToSsa;
    use crate::il::ecode::{ECodeExpr, ECodeExprOpcode, ECodeSink, ECodeStmt, ECodeStmtOpcode};
    use crate::il::pcode::{
        LifterSpaceHandle, PCodeBuilder, PCodeLocation, PCodeLocationProperties, PCodeOp,
        PCodeOpcode,
    };
    use crate::ir::{Address, FunctionId};
    use crate::lifter::{Language, Varnode, resolve_language};
    use crate::storage::segments::space::AddressSpaceId;

    fn language() -> &'static Language {
        resolve_language("x86:LE:64").expect("test language should resolve")
    }

    fn arch() -> Arch {
        Arch::new(language())
    }

    fn platform() -> Platform {
        arch().platform()
    }

    #[test]
    fn empty_pcode_lifts_to_empty_ecode() {
        let pcode_metadata = IlMetadata::new(FunctionId::default(), 11);
        let source = PCodeBuilder::new(language(), pcode_metadata, IlGraph::default())
            .build(&CancellationToken::default())
            .unwrap();
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode::default();

        let lifted = transform
            .transform(&source, &arch(), &platform(), &cancellation)
            .unwrap();

        assert_eq!(lifted.metadata().input_revision().value(), 11);
        assert!(lifted.statements().is_empty());
    }

    #[test]
    fn empty_source_span_does_not_desynchronise_instruction_cache_clears() {
        let mut builder = PCodeBuilder::new(language(), pcode_metadata(), IlGraph::default());
        let constant = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                7,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        for offset in 0..3 {
            let output = builder
                .push_location(PCodeLocation::new(
                    LifterSpaceHandle::new(1),
                    offset,
                    8,
                    PCodeLocationProperties::UNIQUE,
                ))
                .unwrap();
            let operands = builder.push_operands([constant]).unwrap();
            builder.push_operation(PCodeOp::new(
                PCodeOpcode::Copy,
                Some(output),
                operands,
                0,
                None,
            ));
        }
        builder.set_source_spans(vec![
            IlSourceSpan::new(
                IlIndexRange::new(0, 1).unwrap(),
                Address::from(0x1000u64),
                0,
                1,
            ),
            IlSourceSpan::new(
                IlIndexRange::new(1, 1).unwrap(),
                Address::from(0x1001u64),
                0,
                1,
            ),
            IlSourceSpan::new(
                IlIndexRange::new(1, 2).unwrap(),
                Address::from(0x1002u64),
                0,
                1,
            ),
            IlSourceSpan::new(
                IlIndexRange::new(2, 3).unwrap(),
                Address::from(0x1003u64),
                0,
                1,
            ),
        ]);
        let source = builder.build(&CancellationToken::default()).unwrap();

        let lifted = PCodeToECode::default()
            .transform(&source, &arch(), &platform(), &CancellationToken::default())
            .unwrap();
        assert_eq!(
            lifted
                .expressions()
                .iter()
                .filter(|expression| expression.opcode() == ECodeExprOpcode::Constant)
                .count(),
            3
        );
    }

    #[test]
    fn copy_pcode_lifts_to_ecode_write() {
        let source = copy_source();
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode::default();

        let lifted = transform
            .transform(&source, &arch(), &platform(), &cancellation)
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
    fn large_subpiece_offset_is_not_truncated_to_operand_width() {
        let mut builder = PCodeBuilder::new(language(), pcode_metadata(), IlGraph::default());
        let input = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                0x1234,
                64,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let offset = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                32,
                1,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(1),
                0,
                32,
                PCodeLocationProperties::UNIQUE,
            ))
            .unwrap();
        let operands = builder.push_operands([input, offset]).unwrap();
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Subpiece,
            Some(output),
            operands,
            0,
            None,
        ));
        let source = builder.build(&CancellationToken::default()).unwrap();

        let lifted = PCodeToECode::default()
            .transform(&source, &arch(), &platform(), &CancellationToken::default())
            .unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        let extract = &lifted.expressions()[1];
        assert_eq!(extract.opcode(), ECodeExprOpcode::Extract);
        assert_eq!(extract.immediate(), 256);
        assert_eq!(extract.operands().len(), 1);
    }

    #[test]
    fn partial_registers_share_one_full_width_domain() {
        let language = language();
        let rax = language.register_by_name("RAX").expect("RAX should exist");
        let al = language.register_by_name("AL").expect("AL should exist");
        let ah = language.register_by_name("AH").expect("AH should exist");
        let ax = language.register_by_name("AX").expect("AX should exist");
        let mut builder = PCodeBuilder::new(language, pcode_metadata(), IlGraph::default());
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
            .transform(&source, &arch(), &platform(), &CancellationToken::default())
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
        let wide_register = Varnode::new(cf.space(), cf.offset(), cf.size + 1);
        let mut builder = PCodeBuilder::new(language, pcode_metadata(), IlGraph::default());
        let flag = builder
            .push_location(PCodeLocation::from_varnode(language, &cf))
            .unwrap();
        let read_before = builder
            .push_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x100, cf.size),
            ))
            .unwrap();
        let read_after = builder
            .push_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x200, cf.size),
            ))
            .unwrap();
        let wide_register = builder
            .push_location(PCodeLocation::from_varnode(language, &wide_register))
            .unwrap();
        let wide_constant = builder
            .push_location(PCodeLocation::from_varnode(
                language,
                &Varnode::constant(0, cf.size + 1),
            ))
            .unwrap();
        let flag_constant = builder
            .push_location(PCodeLocation::from_varnode(
                language,
                &Varnode::constant(1, cf.size),
            ))
            .unwrap();
        let operands = builder.push_operands([flag]).unwrap();
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(read_before),
            operands,
            0,
            None,
        ));
        let operands = builder.push_operands([wide_constant]).unwrap();
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(wide_register),
            operands,
            0,
            None,
        ));
        let operands = builder.push_operands([flag]).unwrap();
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(read_after),
            operands,
            0,
            None,
        ));
        let operands = builder.push_operands([flag_constant]).unwrap();
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(flag),
            operands,
            0,
            None,
        ));
        let source = builder.build(&CancellationToken::default()).unwrap();

        let lifted = PCodeToECode::default()
            .transform(&source, &arch(), &platform(), &CancellationToken::default())
            .unwrap();

        assert_eq!(
            lifted
                .expressions()
                .iter()
                .filter(|expression| {
                    expression.opcode() == ECodeExprOpcode::ReadFlag
                        && expression.immediate() == cf.offset()
                })
                .count(),
            2
        );
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
        let mut builder = PCodeBuilder::new(language, pcode_metadata(), IlGraph::default());
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
            .transform(&source, &arch(), &platform(), &CancellationToken::default())
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
        let mut builder = PCodeBuilder::new(language, pcode_metadata(), IlGraph::default());
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::UserOp,
            None,
            IlIndexRange::EMPTY,
            u32::from(trap),
            None,
        ));
        let source = builder.build(&CancellationToken::default()).unwrap();

        let lifted = PCodeToECode::default()
            .transform(&source, &arch(), &platform(), &CancellationToken::default())
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
            .transform(&source, &arch(), &platform(), &cancellation)
            .unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        assert!(lifted.statements().is_empty());
        assert!(lifted.parent_spans().is_empty());
    }

    #[test]
    fn user_op_result_preserves_operands() {
        let mut builder = PCodeBuilder::new(language(), pcode_metadata(), IlGraph::default());
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
            .transform(&source, &arch(), &platform(), &CancellationToken::default())
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
            .transform(&source, &arch(), &platform(), &cancellation)
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
        let mut builder = PCodeBuilder::new(language(), pcode_metadata(), IlGraph::default());
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
            .transform(&source, &arch(), &platform(), &CancellationToken::default())
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
            .transform(&source, &arch(), &platform(), &cancellation)
            .unwrap();

        assert_eq!(lifted.statements().len(), 1);
        assert_eq!(lifted.statements()[0].opcode(), ECodeStmtOpcode::Branch);
        assert_eq!(lifted.statements()[0].address(), Some(target));
        lifted.verify().unwrap();
    }

    #[test]
    fn indirect_branch_preserves_recovered_successors() {
        let mut builder = PCodeBuilder::new(language(), pcode_metadata(), IlGraph::default());
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
        builder.set_graph(IlGraph::new(
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
            vec![IlEdgeKinds::UNCONDITIONAL; 1],
        ));
        let source = builder.build(&CancellationToken::default()).unwrap();
        let mut transform = PCodeToECode::default();

        let lifted = transform
            .transform(&source, &arch(), &platform(), &CancellationToken::default())
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
            .transform(&source, &arch(), &platform(), &cancellation)
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

    #[derive(Default)]
    struct WidthProbe {
        addresses: Vec<Address>,
        widths: Vec<u32>,
        effects: usize,
    }

    impl ECodeSink for WidthProbe {
        type Value = u32;

        fn begin_instruction(&mut self, address: Address) -> Result<(), IlError> {
            self.addresses.push(address);
            Ok(())
        }

        fn constant(&mut self, width: u32, _value: u64) -> Result<Self::Value, IlError> {
            self.widths.push(width);
            Ok(width)
        }

        fn address(&mut self, width: u32, _offset: u64) -> Result<Self::Value, IlError> {
            self.widths.push(width);
            Ok(width)
        }

        fn undefined(&mut self, width: u32, _discriminant: u64) -> Result<Self::Value, IlError> {
            self.widths.push(width);
            Ok(width)
        }

        fn read_register(
            &mut self,
            _register: RegisterId,
            width: u32,
        ) -> Result<Self::Value, IlError> {
            self.widths.push(width);
            Ok(width)
        }

        fn read_flag(&mut self, _flag: FlagId, width: u32) -> Result<Self::Value, IlError> {
            self.widths.push(width);
            Ok(width)
        }

        fn apply(
            &mut self,
            _opcode: ECodeExprOpcode,
            width: u32,
            _operands: &[Self::Value],
            _immediate: u64,
            _address_space: Option<AddressSpaceId>,
        ) -> Result<Self::Value, IlError> {
            self.widths.push(width);
            Ok(width)
        }

        fn write_register(
            &mut self,
            _register: RegisterId,
            _value: Self::Value,
        ) -> Result<(), IlError> {
            self.effects += 1;
            Ok(())
        }

        fn write_flag(&mut self, _flag: FlagId, _value: Self::Value) -> Result<(), IlError> {
            self.effects += 1;
            Ok(())
        }

        fn store(
            &mut self,
            _operands: &[Self::Value],
            _address_space: Option<AddressSpaceId>,
        ) -> Result<(), IlError> {
            self.effects += 1;
            Ok(())
        }

        fn direct_flow(
            &mut self,
            _opcode: ECodeStmtOpcode,
            _target: Address,
            _operands: &[Self::Value],
        ) -> Result<(), IlError> {
            self.effects += 1;
            Ok(())
        }

        fn indirect_flow(
            &mut self,
            _opcode: ECodeStmtOpcode,
            _operands: &[Self::Value],
            _address_space: Option<AddressSpaceId>,
        ) -> Result<(), IlError> {
            self.effects += 1;
            Ok(())
        }

        fn intrinsic(
            &mut self,
            _intrinsic: u64,
            _operands: &[Self::Value],
            _address_space: Option<AddressSpaceId>,
        ) -> Result<(), IlError> {
            self.effects += 1;
            Ok(())
        }

        fn trap(
            &mut self,
            _intrinsic: u64,
            _address_space: Option<AddressSpaceId>,
        ) -> Result<(), IlError> {
            self.effects += 1;
            Ok(())
        }
    }

    fn assert_pairing_matches(source: &PCodeIr) {
        let cancellation = CancellationToken::default();
        let arch = arch();
        let solo = PCodeToECode::default()
            .transform(source, &arch, &platform(), &cancellation)
            .unwrap();

        let builder = ECodeBuilder::new(
            IlMetadata::new(
                source.metadata().function(),
                source.metadata().input_revision(),
            ),
            IlGraph::default(),
        );
        let mut paired = (builder, WidthProbe::default());
        let mut scratch = ECodeLiftScratch::default();
        let mut lifter = ECodeLifter::new(source, &arch, &mut paired, &mut scratch).unwrap();
        lifter.lift(&cancellation).unwrap();
        drop(lifter);

        let (mut builder, probe) = paired;
        builder.set_graph(solo.graph().clone());
        builder.set_parent_spans(solo.parent_spans().to_vec());
        builder.set_source_spans(solo.source_spans().to_vec());
        builder.set_call_preserved_registers(solo.call_preserved_registers().to_vec());
        let mirrored = builder.build(&cancellation).unwrap();

        assert_eq!(mirrored, solo);
        assert_eq!(probe.effects, solo.statements().len());
        assert_eq!(
            probe.addresses,
            solo.source_spans()
                .iter()
                .map(IlSourceSpan::address)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            probe.widths,
            solo.expressions()
                .iter()
                .map(ECodeExpr::width)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_paired_sink_observes_every_effect_without_changing_the_built_ir() {
        let sources = [
            copy_source(),
            unique_copy_source(),
            flag_source(),
            store_source(),
            branch_source(Address::new(AddressSpaceId::new(3), 0x2000u64)),
            return_source(AddressSpaceId::new(9)),
            trap_source(),
            intrinsic_source(),
        ];
        let mut seen = Vec::new();
        for source in &sources {
            assert_pairing_matches(source);
            let lifted = PCodeToECode::default()
                .transform(source, &arch(), &platform(), &CancellationToken::default())
                .unwrap();
            seen.extend(lifted.statements().iter().map(ECodeStmt::opcode));
        }

        for opcode in [
            ECodeStmtOpcode::Branch,
            ECodeStmtOpcode::Intrinsic,
            ECodeStmtOpcode::Return,
            ECodeStmtOpcode::Store,
            ECodeStmtOpcode::Trap,
            ECodeStmtOpcode::WriteFlag,
            ECodeStmtOpcode::WriteRegister,
        ] {
            assert!(seen.contains(&opcode), "{opcode:?} is not exercised");
        }
    }

    fn pcode_metadata() -> IlMetadata {
        IlMetadata::new(FunctionId::default(), 11)
    }

    fn flag_source() -> PCodeIr {
        let language = language();
        let cf = language.register_by_name("CF").expect("CF should exist");
        let mut builder = PCodeBuilder::new(language, pcode_metadata(), IlGraph::default());
        let flag = builder
            .push_location(PCodeLocation::from_varnode(language, &cf))
            .unwrap();
        let flag_constant = builder
            .push_location(PCodeLocation::from_varnode(
                language,
                &Varnode::constant(1, cf.size),
            ))
            .unwrap();
        let operands = builder.push_operands([flag_constant]).unwrap();
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(flag),
            operands,
            0,
            None,
        ));

        builder.build(&CancellationToken::default()).unwrap()
    }

    fn trap_source() -> PCodeIr {
        let language = language();
        let trap = language
            .user_op_by_name("invalidInstructionException")
            .expect("x86 trap intrinsic should exist");
        let mut builder = PCodeBuilder::new(language, pcode_metadata(), IlGraph::default());
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::UserOp,
            None,
            IlIndexRange::EMPTY,
            u32::from(trap),
            None,
        ));

        builder.build(&CancellationToken::default()).unwrap()
    }

    fn intrinsic_source() -> PCodeIr {
        let language = language();
        let swi = language
            .user_op_by_name("swi")
            .expect("x86 software-interrupt intrinsic should exist");
        let mut builder = PCodeBuilder::new(language, pcode_metadata(), IlGraph::default());
        let argument = builder
            .push_location(PCodeLocation::from_varnode(
                language,
                &Varnode::constant(0x80, 8),
            ))
            .unwrap();
        let operands = builder.push_operands([argument]).unwrap();
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::UserOp,
            None,
            operands,
            u32::from(swi),
            None,
        ));

        builder.build(&CancellationToken::default()).unwrap()
    }

    fn copy_source() -> PCodeIr {
        let mut builder = PCodeBuilder::new(language(), pcode_metadata(), IlGraph::default());
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
        let mut builder = PCodeBuilder::new(language(), pcode_metadata(), IlGraph::default());
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
        let mut builder = PCodeBuilder::new(language(), pcode_metadata(), IlGraph::default());
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
        let mut builder = PCodeBuilder::new(language(), pcode_metadata(), IlGraph::default());
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
        let mut builder = PCodeBuilder::new(language(), pcode_metadata(), IlGraph::default());
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
