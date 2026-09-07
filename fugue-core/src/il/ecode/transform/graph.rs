use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::il::common::{
    IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlError, IlGraph, IlIndexMapper,
    IlIndexRange, IlSourceSpan,
};
use crate::il::pcode::{PCodeIr, PCodeOp, PCodeOpcode};
use crate::ir::Address;

#[derive(Debug, Default)]
struct BlockSuccessors {
    targets: SmallVec<[IlBlockId; 2]>,
    kinds: SmallVec<[IlEdgeKinds; 2]>,
}

impl BlockSuccessors {
    fn from_partition(
        mapper: &PCodeToECodeGraphMapper,
        source: &PCodeIr,
        source_block: &IlBlock,
        ranges: &[IlIndexRange],
        range_index: usize,
        first_block: IlBlockId,
        first_blocks: &[IlBlockId],
    ) -> Self {
        let range = ranges[range_index];
        let next = (range_index + 1 < ranges.len()).then(|| {
            IlBlockId::try_from_index(first_block.index() + range_index + 1)
                .expect("refined block id was validated while partitioning")
        });
        let original_successors = source_block.successors().slice(source.graph().successors());
        let original_kinds = source_block
            .successors()
            .slice(source.graph().successor_kinds());
        let terminal = range
            .end()
            .checked_sub(1)
            .filter(|index| *index >= range.start())
            .and_then(|index| source.ops().get(index).map(|operation| (index, operation)));

        let mut successors = Self::default();
        match terminal {
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
                let taken_arm = mapper
                    .internal_target(source, source_block.ops(), operation_index, operation)
                    .and_then(|target| refined_target(first_block, ranges, target))
                    .or_else(|| {
                        external_target(source, operation, original_successors, first_blocks)
                    });

                match taken_arm {
                    Some(target) => {
                        let kind = if conditional {
                            IlEdgeKinds::TAKEN
                        } else {
                            IlEdgeKinds::UNCONDITIONAL
                        };
                        successors.push(target, kind);
                    }
                    None => successors.extend_mapped_within(
                        original_successors,
                        original_kinds,
                        first_blocks,
                        permitted,
                    ),
                }
                if conditional {
                    match next {
                        Some(next) => successors.push(next, IlEdgeKinds::FALL_THROUGH),
                        None => successors.extend_mapped_within(
                            original_successors,
                            original_kinds,
                            first_blocks,
                            permitted,
                        ),
                    }
                }
            }
            Some((_, operation)) if operation.opcode() == PCodeOpcode::IBranch => {
                successors.extend_mapped_within(
                    original_successors,
                    original_kinds,
                    first_blocks,
                    IlEdgeKinds::COMPUTED,
                );
            }
            Some((_, operation)) if operation.opcode() == PCodeOpcode::Return => {}
            _ => match next {
                Some(next) => successors.push(next, IlEdgeKinds::FALL_THROUGH),
                None => successors.extend_mapped_within(
                    original_successors,
                    original_kinds,
                    first_blocks,
                    IlEdgeKinds::FALL_THROUGH | IlEdgeKinds::UNCONDITIONAL,
                ),
            },
        }

        successors
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

    fn push(&mut self, target: IlBlockId, kind: IlEdgeKinds) {
        match self.targets.iter().position(|entry| *entry == target) {
            Some(index) => self.kinds[index] |= kind,
            None => {
                self.targets.push(target);
                self.kinds.push(kind);
            }
        }
    }
}

fn external_target(
    source: &PCodeIr,
    operation: &PCodeOp,
    successors: &[IlBlockId],
    first_blocks: &[IlBlockId],
) -> Option<IlBlockId> {
    let address = source.target(operation.target()?)?.address();
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

#[derive(Debug, Default)]
pub(crate) struct PCodeToECodeGraphMapper {
    source_spans_by_address: FxHashMap<Address, SmallVec<[IlSourceSpan; 1]>>,
}

struct PCodeBlockPartitions {
    ranges: Vec<IlIndexRange>,
    ranges_for_block: Vec<IlIndexRange>,
    first_blocks: Vec<IlBlockId>,
}

impl PCodeToECodeGraphMapper {
    pub(crate) fn remap(
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
            let operations = block.ops();
            boundaries.clear();
            boundaries.push(operations.start());
            boundaries.push(operations.end());

            for operation_index in operations.start()..operations.end() {
                let operation = &source.ops()[operation_index];
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

        let partitions = PCodeBlockPartitions {
            ranges: partitions,
            ranges_for_block: partition_ranges,
            first_blocks,
        };
        self.remap_edges(source, operation_map, &partitions)
    }

    fn remap_edges(
        &self,
        source: &PCodeIr,
        operation_map: &IlIndexMapper,
        partitions: &PCodeBlockPartitions,
    ) -> Result<IlGraph, IlError> {
        let mut blocks = Vec::with_capacity(partitions.ranges.len());
        let mut successors = Vec::new();
        let mut successor_kinds = Vec::new();
        let mut block_sources = (!source.graph().block_sources().is_empty())
            .then(|| Vec::with_capacity(partitions.ranges.len()));

        for (block_index, (source_block, ranges)) in source
            .graph()
            .blocks()
            .iter()
            .zip(&partitions.ranges_for_block)
            .enumerate()
        {
            let ranges = ranges.slice(&partitions.ranges);
            for (range_index, range) in ranges.iter().copied().enumerate() {
                let block_successors = BlockSuccessors::from_partition(
                    self,
                    source,
                    source_block,
                    ranges,
                    range_index,
                    partitions.first_blocks[block_index],
                    &partitions.first_blocks,
                );

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
        let target = source.target(operation.target()?)?;
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

        let relative =
            u32::from(target.position()).checked_sub(source_span.first_source_index())?;
        let relative = usize::try_from(relative).ok()?;
        let target_operation = source_span.destination().start().checked_add(relative)?;
        (block.start() <= target_operation && target_operation <= block.end())
            .then_some(target_operation)
    }
}

pub(crate) fn remap_source_spans(
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
                span.first_source_index(),
                span.source_count(),
            ))
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::super::PCodeToECode;
    use super::super::buffer::{
        PCodeToECodeBuffer, PCodeToECodeEffect, PCodeToECodeExpr, PCodeToECodeExprKind,
    };
    use super::super::lifter::PCodeToECodeLifter;
    use super::super::ssa::{PCodeToECodeSsaLifter, PCodeToECodeSsaScratch};
    use super::*;
    use crate::arch::Arch;
    use crate::il::common::{IlExprId, IlMetadata, IlParentSpan};
    use crate::il::ecode::{ECodeBuilder, ECodeIr, ECodeOpcode};
    use crate::il::pcode::{
        PCodeBuilder, PCodeLifterSpaceHandle, PCodeLocation, PCodeLocationProperties, PCodeOpSpec,
        PCodeOpcode,
    };
    use crate::ir::{Address, FunctionId};
    use crate::lifter::{Language, Varnode, resolve_language};
    use crate::platform::Platform;
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

    struct PCodeToECodeBufferFixture {
        metadata: IlMetadata,
        graph: IlGraph,
        parent_spans: Vec<IlParentSpan>,
        source_spans: Vec<IlSourceSpan>,
        buffer: PCodeToECodeBuffer,
    }

    impl PCodeToECodeBufferFixture {
        fn metadata(&self) -> &IlMetadata {
            &self.metadata
        }

        fn graph(&self) -> &IlGraph {
            &self.graph
        }

        fn parent_spans(&self) -> &[IlParentSpan] {
            &self.parent_spans
        }

        fn expressions(&self) -> &[PCodeToECodeExpr] {
            self.buffer.expressions()
        }

        fn ops(&self) -> &[PCodeToECodeEffect] {
            self.buffer.ops()
        }

        fn op_operands_for(&self, operation: &PCodeToECodeEffect) -> &[IlExprId] {
            self.buffer.op_operands_for(operation)
        }

        fn build(self) -> Result<ECodeIr, IlError> {
            let builder = ECodeBuilder::new(self.metadata, IlGraph::default());
            PCodeToECodeSsaLifter::new(
                self.buffer,
                self.graph,
                self.source_spans,
                self.parent_spans,
                builder,
                &mut PCodeToECodeSsaScratch::default(),
            )
            .lift()
        }
    }

    fn lift_buffer(
        transform: &mut PCodeToECode,
        source: &PCodeIr,
        arch: &Arch,
        platform: &Platform,
    ) -> Result<PCodeToECodeBufferFixture, IlError> {
        let metadata = IlMetadata::new(
            source.metadata().function(),
            source.metadata().input_revision(),
        );
        let (buffer, operation_map) =
            PCodeToECodeLifter::new(source, arch, &mut transform.lift_scratch)?.lift(platform)?;

        Ok(PCodeToECodeBufferFixture {
            metadata,
            graph: transform.graph_mapper.remap(source, &operation_map)?,
            parent_spans: operation_map.parent_spans()?,
            source_spans: remap_source_spans(source, &operation_map)?,
            buffer,
        })
    }

    #[test]
    fn empty_pcode_lifts_to_empty_ecode() {
        let pcode_metadata = IlMetadata::new(FunctionId::default(), 11);
        let source = PCodeBuilder::new(pcode_metadata, IlGraph::default())
            .build()
            .unwrap();
        let mut transform = PCodeToECode::default();

        let lifted = lift_buffer(&mut transform, &source, &arch(), &platform()).unwrap();

        assert_eq!(lifted.metadata().input_revision().value(), 11);
        assert!(lifted.ops().is_empty());
    }

    #[test]
    fn empty_source_span_does_not_desynchronise_instruction_cache_clears() {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let constant = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                7,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        for offset in 0..3 {
            let output = builder
                .emitter()
                .intern_location(PCodeLocation::new(
                    PCodeLifterSpaceHandle::new(1),
                    offset,
                    8,
                    PCodeLocationProperties::UNIQUE,
                ))
                .unwrap();
            builder
                .emitter()
                .emit(
                    PCodeOpSpec::new(PCodeOpcode::Copy),
                    Some(output),
                    [constant],
                )
                .unwrap();
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
        let source = builder.build().unwrap();

        let lifted =
            lift_buffer(&mut PCodeToECode::default(), &source, &arch(), &platform()).unwrap();
        assert_eq!(
            lifted
                .expressions()
                .iter()
                .filter(|expression| expression.kind()
                    == PCodeToECodeExprKind::Op(ECodeOpcode::Constant))
                .count(),
            3
        );
    }

    #[test]
    fn copy_pcode_lifts_to_ecode_write() {
        let source = copy_source();
        let mut transform = PCodeToECode::default();

        let lifted = lift_buffer(&mut transform, &source, &arch(), &platform()).unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        assert_eq!(
            lifted.expressions()[1].kind(),
            PCodeToECodeExprKind::Op(ECodeOpcode::Copy)
        );
        assert_eq!(lifted.ops().len(), 1);
        assert_eq!(lifted.ops()[0].opcode(), ECodeOpcode::WriteRegister);
        assert_eq!(lifted.ops()[0].immediate(), 8);
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
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let input = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                0x1234,
                64,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let offset = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                32,
                1,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                0,
                32,
                PCodeLocationProperties::UNIQUE,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Subpiece),
                Some(output),
                [input, offset],
            )
            .unwrap();
        let source = builder.build().unwrap();

        let lifted =
            lift_buffer(&mut PCodeToECode::default(), &source, &arch(), &platform()).unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        let extract = &lifted.expressions()[1];
        assert_eq!(
            extract.kind(),
            PCodeToECodeExprKind::Op(ECodeOpcode::Extract)
        );
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
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let constant = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::constant(0x12, 1),
            ))
            .unwrap();
        let al = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(language, &al))
            .unwrap();
        let ah = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(language, &ah))
            .unwrap();
        let ax = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(language, &ax))
            .unwrap();
        let high = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x100, 1),
            ))
            .unwrap();
        let word = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x200, 2),
            ))
            .unwrap();
        builder
            .emitter()
            .emit(PCodeOpSpec::new(PCodeOpcode::Copy), Some(ah), [constant])
            .unwrap();
        builder
            .emitter()
            .emit(PCodeOpSpec::new(PCodeOpcode::Copy), Some(high), [al])
            .unwrap();
        builder
            .emitter()
            .emit(PCodeOpSpec::new(PCodeOpcode::Copy), Some(word), [ax])
            .unwrap();
        let source = builder.build().unwrap();
        let mut transform = PCodeToECode::default();

        let lifted = lift_buffer(&mut transform, &source, &arch(), &platform()).unwrap();
        let register_reads = lifted
            .expressions()
            .iter()
            .filter(|expression| expression.kind() == PCodeToECodeExprKind::ReadRegister)
            .collect::<Vec<_>>();
        let extracts = lifted
            .expressions()
            .iter()
            .filter(|expression| {
                expression.kind() == PCodeToECodeExprKind::Op(ECodeOpcode::Extract)
            })
            .collect::<Vec<_>>();
        let insert = lifted
            .expressions()
            .iter()
            .find(|expression| expression.kind() == PCodeToECodeExprKind::Op(ECodeOpcode::Insert))
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
        assert_eq!(lifted.ops().len(), 1);
        assert_eq!(lifted.ops()[0].opcode(), ECodeOpcode::WriteRegister);
        assert_eq!(lifted.ops()[0].immediate(), rax.offset());

        let ir = lifted.build().unwrap();
        ir.verify().unwrap();
    }

    #[test]
    fn architectural_flags_use_flag_operations() {
        let language = language();
        let cf = language.register_by_name("CF").expect("CF should exist");
        let wide_register = Varnode::new(cf.space(), cf.offset(), cf.size + 1);
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let flag = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(language, &cf))
            .unwrap();
        let read_before = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x100, cf.size),
            ))
            .unwrap();
        let read_after = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x200, cf.size),
            ))
            .unwrap();
        let wide_register = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(language, &wide_register))
            .unwrap();
        let wide_constant = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::constant(0, cf.size + 1),
            ))
            .unwrap();
        let flag_constant = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::constant(1, cf.size),
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Copy),
                Some(read_before),
                [flag],
            )
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Copy),
                Some(wide_register),
                [wide_constant],
            )
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Copy),
                Some(read_after),
                [flag],
            )
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Copy),
                Some(flag),
                [flag_constant],
            )
            .unwrap();
        let source = builder.build().unwrap();

        let lifted =
            lift_buffer(&mut PCodeToECode::default(), &source, &arch(), &platform()).unwrap();

        assert_eq!(
            lifted
                .expressions()
                .iter()
                .filter(|expression| {
                    expression.kind() == PCodeToECodeExprKind::ReadFlag
                        && expression.immediate() == cf.offset()
                })
                .count(),
            2
        );
        assert!(lifted.ops().iter().any(|statement| {
            statement.opcode() == ECodeOpcode::WriteFlag && statement.immediate() == cf.offset()
        }));
        assert!(
            !lifted
                .expressions()
                .iter()
                .any(|expression| expression.kind() == PCodeToECodeExprKind::ReadRegister)
        );
    }

    #[test]
    fn unresolved_unique_input_lifts_to_undefined() {
        let language = language();
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let input = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x100, 8),
            ))
            .unwrap();
        let output = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x200, 8),
            ))
            .unwrap();
        builder
            .emitter()
            .emit(PCodeOpSpec::new(PCodeOpcode::Copy), Some(output), [input])
            .unwrap();
        let source = builder.build().unwrap();

        let lifted =
            lift_buffer(&mut PCodeToECode::default(), &source, &arch(), &platform()).unwrap();

        assert_eq!(
            lifted.expressions()[0].kind(),
            PCodeToECodeExprKind::Op(ECodeOpcode::Undefined)
        );
    }

    #[test]
    fn trap_intrinsic_lifts_to_trap_statement() {
        let language = language();
        let trap = language
            .user_op_by_name("invalidInstructionException")
            .expect("x86 trap intrinsic should exist");
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::UserOp).with_immediate(u32::from(trap)),
                None,
                [],
            )
            .unwrap();
        let source = builder.build().unwrap();

        let lifted =
            lift_buffer(&mut PCodeToECode::default(), &source, &arch(), &platform()).unwrap();

        assert!(lifted.expressions().is_empty());
        assert_eq!(lifted.ops().len(), 1);
        assert_eq!(lifted.ops()[0].opcode(), ECodeOpcode::Trap);
        assert_eq!(lifted.ops()[0].immediate(), u64::from(trap));
    }

    #[test]
    fn unique_output_pcode_does_not_lift_to_register_write() {
        let source = unique_copy_source();
        let mut transform = PCodeToECode::default();

        let lifted = lift_buffer(&mut transform, &source, &arch(), &platform()).unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        assert!(lifted.ops().is_empty());
        assert!(lifted.parent_spans().is_empty());
    }

    #[test]
    fn user_op_result_preserves_operands() {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let input = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                8,
                8,
                PCodeLocationProperties::UNIQUE,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::UserOp).with_immediate(7),
                Some(output),
                [input],
            )
            .unwrap();
        let source = builder.build().unwrap();
        let mut transform = PCodeToECode::default();

        let lifted = lift_buffer(&mut transform, &source, &arch(), &platform()).unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        assert_eq!(
            lifted.expressions()[1].kind(),
            PCodeToECodeExprKind::Op(ECodeOpcode::IntrinsicResult)
        );
        assert_eq!(lifted.expressions()[1].operands().len(), 1);
    }

    #[test]
    fn store_pcode_lifts_to_ecode_store_with_fugue_space() {
        let source = store_source();
        let mut transform = PCodeToECode::default();

        let lifted = lift_buffer(&mut transform, &source, &arch(), &platform()).unwrap();

        assert_eq!(lifted.ops().len(), 1);
        assert_eq!(lifted.ops()[0].opcode(), ECodeOpcode::Store);
        let operands = lifted.op_operands_for(&lifted.ops()[0]);
        assert_eq!(
            lifted.expressions()[operands[0].index()].kind(),
            PCodeToECodeExprKind::Op(ECodeOpcode::Address)
        );
        assert_eq!(
            lifted.expressions()[operands[1].index()].kind(),
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant)
        );
        assert_eq!(
            lifted.ops()[0].address_space(),
            Some(AddressSpaceId::new(7))
        );
    }

    #[test]
    fn constant_cache_distinguishes_address_and_value_roles() {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let constant = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                0x1000,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Store).with_address_space(AddressSpaceId::new(7)),
                None,
                [constant, constant],
            )
            .unwrap();
        let source = builder.build().unwrap();

        let lifted =
            lift_buffer(&mut PCodeToECode::default(), &source, &arch(), &platform()).unwrap();
        let operands = lifted.op_operands_for(&lifted.ops()[0]);

        assert_ne!(operands[0], operands[1]);
        assert_eq!(
            lifted.expressions()[operands[0].index()].kind(),
            PCodeToECodeExprKind::Op(ECodeOpcode::Address)
        );
        assert_eq!(
            lifted.expressions()[operands[1].index()].kind(),
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant)
        );
    }

    #[test]
    fn branch_pcode_lifts_to_ecode_branch_with_target() {
        let target = Address::new(AddressSpaceId::new(3), 0x2000u64);
        let source = branch_source(target);
        let mut transform = PCodeToECode::default();

        let lifted = lift_buffer(&mut transform, &source, &arch(), &platform()).unwrap();

        assert_eq!(lifted.ops().len(), 1);
        assert_eq!(lifted.ops()[0].opcode(), ECodeOpcode::Branch);
        assert_eq!(lifted.ops()[0].address(), Some(target));
    }

    #[test]
    fn indirect_branch_preserves_recovered_successors() {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let target = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                8,
                8,
                PCodeLocationProperties::REGISTER,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::IBranch).with_address_space(AddressSpaceId::new(3)),
                None,
                [target],
            )
            .unwrap();
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
        let source = builder.build().unwrap();
        let mut transform = PCodeToECode::default();

        let lifted = lift_buffer(&mut transform, &source, &arch(), &platform()).unwrap();
        let entry = &lifted.graph().blocks()[0];

        assert_eq!(
            entry.successors().slice(lifted.graph().successors()),
            &[IlBlockId::try_from_index(1).unwrap()]
        );
        assert!(!entry.is_exit());
    }

    #[test]
    fn return_pcode_lifts_to_ecode_return_with_fugue_space() {
        let source = return_source(AddressSpaceId::new(9));
        let mut transform = PCodeToECode::default();

        let lifted = lift_buffer(&mut transform, &source, &arch(), &platform()).unwrap();

        assert_eq!(lifted.ops().len(), 1);
        assert_eq!(lifted.ops()[0].opcode(), ECodeOpcode::Return);
        let target = lifted.op_operands_for(&lifted.ops()[0])[0];
        assert_eq!(
            lifted.expressions()[target.index()].kind(),
            PCodeToECodeExprKind::Op(ECodeOpcode::Address)
        );
        assert_eq!(
            lifted.ops()[0].address_space(),
            Some(AddressSpaceId::new(9))
        );
    }

    #[test]
    fn concrete_lifter_emits_each_effect_class() {
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
            let lifted =
                lift_buffer(&mut PCodeToECode::default(), source, &arch(), &platform()).unwrap();
            seen.extend(lifted.ops().iter().map(PCodeToECodeEffect::opcode));
        }

        for opcode in [
            ECodeOpcode::Branch,
            ECodeOpcode::Intrinsic,
            ECodeOpcode::Return,
            ECodeOpcode::Store,
            ECodeOpcode::Trap,
            ECodeOpcode::WriteFlag,
            ECodeOpcode::WriteRegister,
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
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let flag = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(language, &cf))
            .unwrap();
        let flag_constant = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::constant(1, cf.size),
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Copy),
                Some(flag),
                [flag_constant],
            )
            .unwrap();

        builder.build().unwrap()
    }

    fn trap_source() -> PCodeIr {
        let language = language();
        let trap = language
            .user_op_by_name("invalidInstructionException")
            .expect("x86 trap intrinsic should exist");
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::UserOp).with_immediate(u32::from(trap)),
                None,
                [],
            )
            .unwrap();

        builder.build().unwrap()
    }

    fn intrinsic_source() -> PCodeIr {
        let language = language();
        let swi = language
            .user_op_by_name("swi")
            .expect("x86 software-interrupt intrinsic should exist");
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let arg = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::constant(0x80, 8),
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::UserOp).with_immediate(u32::from(swi)),
                None,
                [arg],
            )
            .unwrap();

        builder.build().unwrap()
    }

    fn copy_source() -> PCodeIr {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let input = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                8,
                8,
                PCodeLocationProperties::REGISTER,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(PCodeOpSpec::new(PCodeOpcode::Copy), Some(output), [input])
            .unwrap();

        builder.build().unwrap()
    }

    fn unique_copy_source() -> PCodeIr {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let input = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(2),
                8,
                8,
                PCodeLocationProperties::UNIQUE,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(PCodeOpSpec::new(PCodeOpcode::Copy), Some(output), [input])
            .unwrap();

        builder.build().unwrap()
    }

    fn store_source() -> PCodeIr {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let offset = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                0x1000,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let value = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                0xff,
                1,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Store).with_address_space(AddressSpaceId::new(7)),
                None,
                [offset, value],
            )
            .unwrap();

        builder.build().unwrap()
    }

    fn branch_source(target: Address) -> PCodeIr {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let target_location = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                target.offset(),
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let target = builder.emitter().emit_target(target.into()).unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Branch).with_target(target),
                None,
                [target_location],
            )
            .unwrap();

        builder.build().unwrap()
    }

    fn return_source(space: AddressSpaceId) -> PCodeIr {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let target = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                0x1000,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Return).with_address_space(space),
                None,
                [target],
            )
            .unwrap();

        builder.build().unwrap()
    }
}
