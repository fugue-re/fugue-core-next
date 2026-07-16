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
    Address, CodeBlockId, CodeBlockTable, FunctionId, FunctionTable, Insn, InsnTarget,
};
use crate::lifter::Lifter;
use crate::storage::segments::SegmentStorage;

/// Scratch buffers survive across function lifts so repeated
/// canonicalisation does not reallocate per call.
#[derive(Debug, Default)]
pub struct PCodeCanonicaliser {
    code_block_ids: Vec<CodeBlockId>,
    block_id_by_code_block: BTreeMap<CodeBlockId, IlBlockId>,
    annotations: Vec<AddressAnnotation<'static>>,
    operations: Vec<RawPCodeOp>,
    insn_bytes: Vec<u8>,
}

impl PCodeCanonicaliser {
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

        for code_block_id in self.code_block_ids.drain(..) {
            cancellation.check()?;

            let Some(code_block) = blocks.get_by_id(code_block_id) else {
                return Err(IlError::missing_artefact(function, IlLevel::PCode).into());
            };

            let block_start = builder.operation_count();

            for insn in code_block.instructions() {
                self.operations.clear();
                self.insn_bytes.clear();
                self.insn_bytes.resize(insn.len(), 0);
                segments.read_bytes(insn.address(), &mut self.insn_bytes)?;
                let lifted_len =
                    lifter.lift_into(insn.address(), &self.insn_bytes, &mut self.operations)?;
                let source_start = builder.operation_count();

                self.annotations.clear();
                let emitted = Self::push_direct_target_annotations(
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

        builder.replace_graph(IlGraph::new(cfg_blocks, successors));
        builder.replace_source_spans(source_spans);

        Ok(builder.build(cancellation)?)
    }

    fn push_direct_target_annotations(
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

            if matches!(operation.op(), Op::Branch | Op::CBranch | Op::Call)
                && let Some(target) = targets
                    .iter()
                    .find(|(target_index, _)| usize::from(*target_index) == index)
                    .and_then(|(_, target)| target.address())
            {
                annotations.push(AddressAnnotation::new(
                    ordinal,
                    AddressAnnotationValue::DirectTarget(target),
                ));
            }

            semantic_count += 1;
            index += operation.spill() + 1;
        }

        Ok(semantic_count)
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
