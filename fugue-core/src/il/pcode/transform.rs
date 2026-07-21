use std::collections::{BTreeMap, VecDeque};

use fugue_lifter::runtime::language::Language;
use fugue_lifter::{Op, PCodeOp as RawPCodeOp};
use smallvec::SmallVec;

use crate::analysis::control::CancellationToken;
use crate::analysis::function::recovery::PartialFunction;
use crate::il::common::{
    IlBlock, IlBlockId, IlBlockProperties, IlError, IlGraph, IlHeader, IlIndexRange, IlLevel,
    IlOpId, IlSourceSpan,
};
use crate::il::pcode::{
    AddressAnnotation, AddressAnnotationValue, PCODE_SCHEMA_VERSION, PCodeAddressContext,
    PCodeBuilder, PCodeError, PCodeIr,
};
use crate::ir::{
    Address, CodeBlockId, CodeBlockTable, FunctionId, FunctionTable, Insn, InsnTarget, Location,
};
use crate::lifter::Lifter;
use crate::storage::SegmentStorageError;
use crate::storage::segments::{SegmentReader, SegmentStorage};

#[derive(Debug, Default)]
pub struct PCodeCanonicaliser {
    code_block_ids: Vec<CodeBlockId>,
    block_id_by_code_block: BTreeMap<CodeBlockId, IlBlockId>,
    annotations: Vec<AddressAnnotation<'static>>,
    operations: Vec<RawPCodeOp>,
}

pub(crate) struct PartialPCodeBuild {
    ir: PCodeIr,
    omitted_blocks: Vec<Address>,
}

impl PartialPCodeBuild {
    pub(crate) fn into_parts(self) -> (PCodeIr, Vec<Address>) {
        (self.ir, self.omitted_blocks)
    }
}

impl PCodeCanonicaliser {
    #[allow(clippy::too_many_arguments)]
    pub fn build_function(
        &mut self,
        language: &'static Language,
        functions: &FunctionTable,
        blocks: &CodeBlockTable,
        segments: &SegmentStorage,
        function: FunctionId,
        input_revision: u64,
        cancellation: &CancellationToken,
    ) -> Result<PCodeIr, PCodeError> {
        let Some(function_body) = functions.get_by_id(function) else {
            return Err(IlError::missing_artefact(function, IlLevel::PCode).into());
        };

        let mut lifter = Lifter::new(language);
        self.code_block_ids.clear();
        self.block_id_by_code_block.clear();

        for (_, code_block) in function_body.blocks() {
            let block_id = IlBlockId::try_from_index(self.code_block_ids.len())?;
            self.block_id_by_code_block.insert(code_block, block_id);
            self.code_block_ids.push(code_block);
        }

        let header = IlHeader::new(function, PCODE_SCHEMA_VERSION, input_revision);
        let mut builder = PCodeBuilder::new(language, header, IlGraph::default());
        let mut cfg_blocks = Vec::new();
        let mut successors = Vec::new();
        let mut source_spans = Vec::new();
        let mut reader = SegmentReader::new(segments);

        for index in 0..self.code_block_ids.len() {
            cancellation.check()?;

            let code_block_id = self.code_block_ids[index];
            let Some(code_block) = blocks.get_by_id(code_block_id) else {
                return Err(IlError::missing_artefact(function, IlLevel::PCode).into());
            };

            let block_start = builder.operation_count();

            code_block
                .context()
                .apply(code_block.address(), lifter.context_mut());

            self.append_instructions(
                language,
                &mut builder,
                &mut reader,
                &mut lifter,
                code_block.instructions(),
                &mut source_spans,
            )?;

            let successor_start = successors.len();

            for successor in code_block.successors().iter() {
                if let Some(successor) = self.block_id_by_code_block.get(&successor).copied() {
                    successors.push(successor);
                }
            }

            let mut props = IlBlockProperties::empty();
            if code_block.address() == function_body.entry() {
                props |= IlBlockProperties::ENTRY;
            }
            if code_block.successors().is_empty() {
                props |= IlBlockProperties::EXIT;
            }

            cfg_blocks.push(IlBlock::new(
                IlIndexRange::new(block_start, builder.operation_count())?,
                IlIndexRange::new(successor_start, successors.len())?,
                props,
            ));
        }

        self.code_block_ids.clear();

        builder.replace_graph(IlGraph::new(cfg_blocks, successors));
        builder.replace_source_spans(source_spans);

        Ok(builder.build(cancellation)?)
    }

    pub fn build_partial_function(
        &mut self,
        language: &'static Language,
        function: &PartialFunction,
        segments: &SegmentStorage,
        input_revision: u64,
        cancellation: &CancellationToken,
    ) -> Result<PCodeIr, PCodeError> {
        let mut lifter = Lifter::new(language);

        let header = IlHeader::new(FunctionId::INVALID, PCODE_SCHEMA_VERSION, input_revision);
        let mut builder = PCodeBuilder::new(language, header, IlGraph::default());
        let mut cfg_blocks = Vec::new();
        let mut successors = Vec::new();
        let mut source_spans = Vec::new();
        let mut reader = SegmentReader::new(segments);

        for block in function.blocks() {
            cancellation.check()?;

            let block_start = builder.operation_count();

            block.context().apply(block.address(), lifter.context_mut());

            self.append_instructions(
                language,
                &mut builder,
                &mut reader,
                &mut lifter,
                block.insns().iter().map(|&insn| &function.insns()[insn]),
                &mut source_spans,
            )?;

            let successor_start = successors.len();

            for &successor in block.successors() {
                successors.push(IlBlockId::try_from_index(successor)?);
            }

            let mut props = IlBlockProperties::empty();
            if block.address() == function.entry() {
                props |= IlBlockProperties::ENTRY;
            }
            if block.successors().is_empty() {
                props |= IlBlockProperties::EXIT;
            }

            cfg_blocks.push(IlBlock::new(
                IlIndexRange::new(block_start, builder.operation_count())?,
                IlIndexRange::new(successor_start, successors.len())?,
                props,
            ));
        }

        builder.replace_graph(IlGraph::new(cfg_blocks, successors));
        builder.replace_source_spans(source_spans);

        Ok(builder.build(cancellation)?)
    }

    pub(crate) fn build_partial_function_tolerant(
        &mut self,
        language: &'static Language,
        function: &PartialFunction,
        segments: &SegmentStorage,
        input_revision: u64,
        cancellation: &CancellationToken,
    ) -> Result<PartialPCodeBuild, PCodeError> {
        let block_count = function.blocks().len();
        let entry = function
            .blocks()
            .iter()
            .position(|block| block.address() == function.entry())
            .ok_or_else(|| IlError::missing_component(IlLevel::PCode, "entry block"))?;
        let mut omitted = vec![false; block_count];
        let mut failed = VecDeque::new();
        let mut reader = SegmentReader::new(segments);

        for (index, block) in function.blocks().iter().enumerate() {
            cancellation.check()?;

            let header = IlHeader::new(FunctionId::INVALID, PCODE_SCHEMA_VERSION, input_revision);
            let mut scratch = PCodeBuilder::new(language, header, IlGraph::default());
            let mut lifter = Lifter::new(language);
            let mut source_spans = Vec::new();
            block.context().apply(block.address(), lifter.context_mut());
            let result = self.append_instructions(
                language,
                &mut scratch,
                &mut reader,
                &mut lifter,
                block.insns().iter().map(|&insn| &function.insns()[insn]),
                &mut source_spans,
            );

            match result {
                Ok(()) => {}
                Err(error) if Self::is_omittable_partial_error(&error) => {
                    omitted[index] = true;
                    failed.push_back(index);
                }
                Err(error) => return Err(error),
            }
        }

        while let Some(index) = failed.pop_front() {
            for &successor in function.blocks()[index].successors() {
                let Some(successor_omitted) = omitted.get_mut(successor) else {
                    return Err(IlError::range_out_of_bounds(successor as u32, block_count).into());
                };
                if !*successor_omitted {
                    *successor_omitted = true;
                    failed.push_back(successor);
                }
            }
        }

        let mut retained = vec![false; block_count];
        if !omitted[entry] {
            let mut reachable = VecDeque::from([entry]);
            while let Some(index) = reachable.pop_front() {
                if retained[index] {
                    continue;
                }
                retained[index] = true;
                for &successor in function.blocks()[index].successors() {
                    let Some(&successor_omitted) = omitted.get(successor) else {
                        return Err(
                            IlError::range_out_of_bounds(successor as u32, block_count).into()
                        );
                    };
                    if !successor_omitted {
                        reachable.push_back(successor);
                    }
                }
            }
        }

        let mut remapped = vec![None; block_count];
        let mut retained_count = 0usize;
        for (index, is_retained) in retained.iter().copied().enumerate() {
            if is_retained {
                remapped[index] = Some(IlBlockId::try_from_index(retained_count)?);
                retained_count += 1;
            }
        }

        let header = IlHeader::new(FunctionId::INVALID, PCODE_SCHEMA_VERSION, input_revision);
        let mut builder = PCodeBuilder::new(language, header, IlGraph::default());
        let mut cfg_blocks = Vec::with_capacity(retained_count);
        let mut successors = Vec::new();
        let mut source_spans = Vec::new();
        let mut lifter = Lifter::new(language);

        for (index, block) in function.blocks().iter().enumerate() {
            if !retained[index] {
                continue;
            }

            cancellation.check()?;
            let block_start = builder.operation_count();
            block.context().apply(block.address(), lifter.context_mut());
            self.append_instructions(
                language,
                &mut builder,
                &mut reader,
                &mut lifter,
                block.insns().iter().map(|&insn| &function.insns()[insn]),
                &mut source_spans,
            )?;

            let successor_start = successors.len();
            for &successor in block.successors() {
                if let Some(successor) = remapped.get(successor).copied().flatten() {
                    successors.push(successor);
                }
            }

            let mut properties = IlBlockProperties::empty();
            if index == entry {
                properties |= IlBlockProperties::ENTRY;
            }
            if successor_start == successors.len() {
                properties |= IlBlockProperties::EXIT;
            }
            cfg_blocks.push(IlBlock::new(
                IlIndexRange::new(block_start, builder.operation_count())?,
                IlIndexRange::new(successor_start, successors.len())?,
                properties,
            ));
        }

        builder.replace_graph(IlGraph::new(cfg_blocks, successors));
        builder.replace_source_spans(source_spans);
        let ir = builder.build(cancellation)?;
        let mut omitted_blocks = function
            .blocks()
            .iter()
            .zip(retained)
            .filter_map(|(block, retained)| (!retained).then_some(block.address()))
            .collect::<Vec<_>>();
        omitted_blocks.sort_unstable();

        Ok(PartialPCodeBuild { ir, omitted_blocks })
    }

    fn is_omittable_partial_error(error: &PCodeError) -> bool {
        !matches!(error, PCodeError::Common(_))
    }

    fn append_instructions<'i>(
        &mut self,
        language: &'static Language,
        builder: &mut PCodeBuilder,
        reader: &mut SegmentReader,
        lifter: &mut Lifter,
        instructions: impl IntoIterator<Item = &'i Insn>,
        source_spans: &mut Vec<IlSourceSpan>,
    ) -> Result<(), PCodeError> {
        for insn in instructions {
            self.operations.clear();

            let Some(window) = reader
                .view(insn.address())
                .and_then(|view| view.bytes_from(insn.address()))
            else {
                return Err(SegmentStorageError::InvalidAddress.into());
            };
            let Some(bytes) = window.as_contiguous() else {
                return Err(SegmentStorageError::InvalidAddress.into());
            };

            let lifted_len = lifter.lift_into(insn.address(), bytes, &mut self.operations)?;
            let source_start = builder.operation_count();

            self.annotations.clear();
            let emitted = Self::push_address_annotations(
                language,
                insn.address(),
                lifted_len,
                &self.operations,
                source_start,
                &mut self.annotations,
            )?;
            let mut context = PCodeAddressContext::new(insn.address(), &self.annotations);
            builder.push_lifted_operations(&self.operations, &mut context)?;

            source_spans.push(IlSourceSpan::new(
                IlIndexRange::new(source_start, builder.operation_count())?,
                insn.address(),
                0,
                u32::try_from(emitted).expect("instruction pcode count fits in u32"),
            ));
        }

        Ok(())
    }

    fn push_address_annotations(
        language: &'static Language,
        address: Address,
        length: usize,
        operations: &[RawPCodeOp],
        starting_ordinal: usize,
        annotations: &mut Vec<AddressAnnotation<'static>>,
    ) -> Result<usize, PCodeError> {
        let mut targets = SmallVec::<[(u16, InsnTarget); 2]>::new();
        Insn::push_targets_for_operations(language, address, length, operations, &mut targets);
        let mut semantic_count = 0usize;
        let mut index = 0usize;

        while let Some(operation) = operations.get(index) {
            let ordinal_index = starting_ordinal + semantic_count;
            let ordinal = IlOpId::try_from_index(ordinal_index)?;

            if operation.is_arg() {
                return Err(PCodeError::misplaced_arg(ordinal.value()));
            }

            match operation.op() {
                Op::Branch | Op::CBranch | Op::Call => {
                    if let Some(target) = targets
                        .iter()
                        .find(|(target_index, _)| usize::from(*target_index) == index)
                        .and_then(|(_, target)| match target {
                            InsnTarget::IntraIns(location, _)
                            | InsnTarget::IntraBlk(location, _) => Some(*location),
                            InsnTarget::InterBlk(address)
                            | InsnTarget::InterSub(Some(address))
                            | InsnTarget::InterRet(Some(address), _) => Some((*address).into()),
                            InsnTarget::InterSub(None)
                            | InsnTarget::InterRet(None, _)
                            | InsnTarget::Intrinsic
                            | InsnTarget::Unresolved => None,
                        })
                    {
                        let target = Self::remap_target_position(operations, address, target)
                            .ok_or_else(|| {
                                PCodeError::invalid_local_target(ordinal.value(), target.position())
                            })?;
                        annotations.push(AddressAnnotation::new(
                            ordinal,
                            AddressAnnotationValue::DirectTarget(target),
                        ));
                    }
                }
                Op::Load(_) | Op::Store(_) | Op::IBranch | Op::ICall | Op::Return => {
                    annotations.push(AddressAnnotation::new(
                        ordinal,
                        AddressAnnotationValue::ComputedSpace(address.space()),
                    ));
                }
                _ => {}
            }

            semantic_count += 1;
            index += operation.spill() + 1;
        }

        Ok(semantic_count)
    }

    fn remap_target_position(
        operations: &[RawPCodeOp],
        address: Address,
        target: Location,
    ) -> Option<Location> {
        if target.address() != address {
            return Some(target);
        }

        let raw_target = usize::from(target.position());
        let mut raw_index = 0usize;
        let mut semantic_index = 0u16;

        while raw_index < raw_target {
            let operation = operations.get(raw_index)?;
            raw_index += operation.spill() + 1;
            semantic_index = semantic_index.checked_add(1)?;
        }

        (raw_index == raw_target).then(|| Location::new(target.address(), semantic_index))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::pcode::PCODE_SCHEMA_VERSION;
    use crate::ir::FunctionId;
    use crate::lifter::resolve_language;
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn canonicaliser_builds_empty_stream() {
        let header = IlHeader::new(FunctionId::default(), PCODE_SCHEMA_VERSION, 3);
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let mut context = PCodeAddressContext::new(source, &[]);
        let language = resolve_language("x86:LE:64").expect("test language should resolve");
        let mut builder = PCodeBuilder::new(language, header, IlGraph::default());

        builder.push_lifted_operations(&[], &mut context).unwrap();
        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert!(ir.operations().is_empty());
        assert_eq!(ir.header().input_revision(), 3);
    }
}
