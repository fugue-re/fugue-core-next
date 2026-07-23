use std::collections::BTreeMap;

use fugue_lifter::runtime::language::Language;
use fugue_lifter::{Op, PCodeOp as RawPCodeOp};
use smallvec::SmallVec;

use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlBlock, IlBlockId, IlBlockProperties, IlError, IlGraph, IlHeader, IlIndexRange, IlLevel,
    IlOpId, IlSourceSpan,
};
use crate::il::pcode::{
    AddressAnnotation, AddressAnnotationValue, PCODE_SCHEMA_VERSION, PCodeAddressContext,
    PCodeBuilder, PCodeError, PCodeIr,
};
use crate::ir::{
    Address, CodeBlockId, CodeBlockTable, FunctionId, FunctionTable, IncompleteFunction, Insn,
    InsnTarget, Location,
};
use crate::lifter::{ContextSet, Lifter};
use crate::storage::SegmentStorageError;
use crate::storage::segments::{SegmentMappingCache, SegmentStorage};

#[derive(Debug, Default)]
pub struct PCodeCanonicaliser {
    code_block_ids: Vec<CodeBlockId>,
    block_id_by_code_block: BTreeMap<CodeBlockId, IlBlockId>,
}

struct PCodeFunctionBuilder<'a> {
    language: &'static Language,
    builder: PCodeBuilder,
    mapping_cache: SegmentMappingCache<'a>,
    lifter: Lifter,
    blocks: Vec<IlBlock>,
    successors: Vec<IlBlockId>,
    block_sources: Vec<Address>,
    source_spans: Vec<IlSourceSpan>,
    annotations: Vec<AddressAnnotation<'static>>,
    operations: Vec<RawPCodeOp>,
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

        self.code_block_ids.clear();
        self.block_id_by_code_block.clear();

        for (_, code_block) in function_body.blocks() {
            let block_id = IlBlockId::try_from_index(self.code_block_ids.len())?;
            self.block_id_by_code_block.insert(code_block, block_id);
            self.code_block_ids.push(code_block);
        }

        let header = IlHeader::new(function, PCODE_SCHEMA_VERSION, input_revision);
        let mut builder = PCodeFunctionBuilder::new(language, header, segments);
        let mut successors = Vec::new();

        for index in 0..self.code_block_ids.len() {
            cancellation.check()?;

            let code_block_id = self.code_block_ids[index];
            let Some(code_block) = blocks.get_by_id(code_block_id) else {
                return Err(IlError::missing_artefact(function, IlLevel::PCode).into());
            };

            successors.clear();
            successors.extend(
                code_block
                    .successors()
                    .iter()
                    .filter_map(|successor| self.block_id_by_code_block.get(&successor).copied()),
            );
            builder.append_block(
                code_block.address(),
                code_block.context(),
                code_block.instructions(),
                &successors,
                code_block.address() == function_body.entry(),
            )?;
        }

        self.code_block_ids.clear();

        builder.build(cancellation)
    }

    pub fn build_incomplete_function(
        &mut self,
        language: &'static Language,
        function: &IncompleteFunction,
        segments: &SegmentStorage,
        input_revision: u64,
        cancellation: &CancellationToken,
    ) -> Result<PCodeIr, PCodeError> {
        let header = IlHeader::new(FunctionId::INVALID, PCODE_SCHEMA_VERSION, input_revision);
        let mut builder = PCodeFunctionBuilder::new(language, header, segments);
        let mut successors = Vec::new();

        for block in function.blocks() {
            cancellation.check()?;

            successors.clear();
            for successor in block.successors().iter() {
                successors.push(IlBlockId::try_from_index(successor.index())?);
            }
            builder.append_block(
                block.address(),
                block.context(),
                block
                    .insns()
                    .iter()
                    .map(|&insn| function.insn(insn).expect("block instruction must exist")),
                &successors,
                block.address() == function.entry(),
            )?;
        }

        builder.build(cancellation)
    }
}

impl<'a> PCodeFunctionBuilder<'a> {
    fn new(language: &'static Language, header: IlHeader, segments: &'a SegmentStorage) -> Self {
        Self {
            language,
            builder: PCodeBuilder::new(language, header, IlGraph::default()),
            mapping_cache: SegmentMappingCache::new(segments),
            lifter: Lifter::new(language),
            blocks: Vec::new(),
            successors: Vec::new(),
            block_sources: Vec::new(),
            source_spans: Vec::new(),
            annotations: Vec::new(),
            operations: Vec::new(),
        }
    }

    fn append_block<'i>(
        &mut self,
        source: Address,
        context: &ContextSet,
        instructions: impl IntoIterator<Item = &'i Insn>,
        successors: &[IlBlockId],
        is_entry: bool,
    ) -> Result<(), PCodeError> {
        let operation_start = self.builder.operation_count();
        context.apply(source, self.lifter.context_mut());
        self.append_instructions(instructions)?;

        let successor_start = self.successors.len();
        self.successors.extend_from_slice(successors);

        let mut properties = IlBlockProperties::empty();
        if is_entry {
            properties |= IlBlockProperties::ENTRY;
        }
        if successors.is_empty() {
            properties |= IlBlockProperties::EXIT;
        }

        self.blocks.push(IlBlock::new(
            IlIndexRange::new(operation_start, self.builder.operation_count())?,
            IlIndexRange::new(successor_start, self.successors.len())?,
            properties,
        ));
        self.block_sources.push(source);

        Ok(())
    }

    fn append_instructions<'i>(
        &mut self,
        instructions: impl IntoIterator<Item = &'i Insn>,
    ) -> Result<(), PCodeError> {
        for insn in instructions {
            self.operations.clear();

            let Some(view) = self.mapping_cache.view_containing(insn.address()) else {
                return Err(SegmentStorageError::InvalidAddress.into());
            };
            let Some(window) = view.bytes_from(insn.address()) else {
                return Err(SegmentStorageError::InvalidAddress.into());
            };
            let Some(bytes) = window.as_contiguous() else {
                return Err(SegmentStorageError::InvalidAddress.into());
            };

            let lifted_len = self
                .lifter
                .lift(insn.address(), bytes, &mut self.operations)?;
            let source_start = self.builder.operation_count();

            self.annotations.clear();
            let emitted = Self::push_address_annotations(
                self.language,
                insn.address(),
                lifted_len,
                &self.operations,
                source_start,
                &mut self.annotations,
            )?;
            let mut context = PCodeAddressContext::new(insn.address(), &self.annotations);
            self.builder
                .push_lifted_operations(&self.operations, &mut context)?;

            self.source_spans.push(IlSourceSpan::new(
                IlIndexRange::new(source_start, self.builder.operation_count())?,
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

    fn build(mut self, cancellation: &CancellationToken) -> Result<PCodeIr, PCodeError> {
        self.builder.replace_graph(
            IlGraph::new(self.blocks, self.successors).with_block_sources(self.block_sources),
        );
        self.builder.replace_source_spans(self.source_spans);

        Ok(self.builder.build(cancellation)?)
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
