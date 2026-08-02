use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlError, IlGraph, IlIndexRange, IlLevel,
    IlMetadata, IlOpId, IlSourceSpan,
};
use crate::il::pcode::{
    AddressAnnotation, AddressAnnotationValue, PCODE_SCHEMA_VERSION, PCodeAddressContext,
    PCodeBuilder, PCodeError, PCodeIr, PCodeOpcode,
};
use crate::ir::{
    Address, CodeBlockId, CodeBlockTable, FlowTarget, FunctionId, FunctionTable,
    IncompleteFunction, Insn, InsnTarget, Location,
};
use crate::lifter::{ContextSet, Language, Lifter, RawPCodeOp};
use crate::storage::segments::{SegmentMappingCache, SegmentStorage};
use crate::types::common::Revision;

#[derive(Debug, Default)]
pub struct PCodeCanonicaliser {
    code_block_ids: Vec<CodeBlockId>,
    block_id_by_code_block: FxHashMap<CodeBlockId, IlBlockId>,
    block_addresses: Vec<Address>,
}

impl PCodeCanonicaliser {
    fn edge_kinds_into(
        &self,
        flows: impl Iterator<Item = FlowTarget>,
        successors: &[IlBlockId],
        kinds: &mut Vec<IlEdgeKinds>,
    ) {
        let mut by_target = SmallVec::<[(Address, IlEdgeKinds); 4]>::new();
        for flow in flows {
            let Some(kind) = IlEdgeKinds::from_flow(flow.kind()) else {
                continue;
            };
            match by_target.iter_mut().find(|(to, _)| *to == flow.to()) {
                Some((_, kinds)) => *kinds |= kind,
                None => by_target.push((flow.to(), kind)),
            }
        }

        kinds.clear();
        kinds.extend(successors.iter().map(|successor| {
            let target = self.block_addresses.get(successor.index()).copied();
            by_target
                .iter()
                .find(|(to, _)| Some(*to) == target)
                .map_or(IlEdgeKinds::UNCONDITIONAL, |(_, kinds)| *kinds)
        }));
    }
}

pub struct PCodeFunctionInput<'a> {
    language: &'static Language,
    functions: &'a FunctionTable,
    blocks: &'a CodeBlockTable,
    segments: &'a SegmentStorage,
    function: FunctionId,
    input_revision: Revision,
    cancellation: &'a CancellationToken,
}

impl<'a> PCodeFunctionInput<'a> {
    pub fn new(
        language: &'static Language,
        functions: &'a FunctionTable,
        blocks: &'a CodeBlockTable,
        segments: &'a SegmentStorage,
        function: FunctionId,
        input_revision: Revision,
        cancellation: &'a CancellationToken,
    ) -> Self {
        Self {
            language,
            functions,
            blocks,
            segments,
            function,
            input_revision,
            cancellation,
        }
    }
}

struct PCodeConstruction<'a> {
    language: &'static Language,
    builder: PCodeBuilder,
    mapping_cache: SegmentMappingCache,
    segments: &'a SegmentStorage,
    lifter: Lifter,
    blocks: Vec<IlBlock>,
    successors: Vec<IlBlockId>,
    successor_kinds: Vec<IlEdgeKinds>,
    block_sources: Vec<Address>,
    source_spans: Vec<IlSourceSpan>,
    annotations: Vec<AddressAnnotation>,
    operations: Vec<RawPCodeOp>,
}

impl PCodeCanonicaliser {
    pub fn build_function(&mut self, input: PCodeFunctionInput<'_>) -> Result<PCodeIr, PCodeError> {
        let Some(function_body) = input.functions.get_by_id(input.function) else {
            return Err(IlError::missing_artefact(input.function, IlLevel::PCode).into());
        };

        self.code_block_ids.clear();
        self.block_id_by_code_block.clear();
        self.block_addresses.clear();

        for (_, code_block) in function_body.blocks() {
            let block_id = IlBlockId::try_from_index(self.code_block_ids.len())?;
            self.block_id_by_code_block.insert(code_block, block_id);
            self.code_block_ids.push(code_block);
        }

        for &code_block_id in &self.code_block_ids {
            let Some(code_block) = input.blocks.get_by_id(code_block_id) else {
                return Err(IlError::missing_artefact(input.function, IlLevel::PCode).into());
            };
            self.block_addresses.push(code_block.address());
        }

        let metadata = IlMetadata::new(input.function, PCODE_SCHEMA_VERSION, input.input_revision);
        let mut construction = PCodeConstruction::new(input.language, metadata, input.segments);
        let mut successors = Vec::new();
        let mut successor_kinds = Vec::new();

        for index in 0..self.code_block_ids.len() {
            input.cancellation.check()?;

            let code_block_id = self.code_block_ids[index];
            let Some(code_block) = input.blocks.get_by_id(code_block_id) else {
                return Err(IlError::missing_artefact(input.function, IlLevel::PCode).into());
            };

            successors.clear();
            successors.extend(
                function_body
                    .successors(code_block_id)
                    .filter_map(|successor| self.block_id_by_code_block.get(&successor).copied()),
            );
            self.edge_kinds_into(code_block.flow_targets(), &successors, &mut successor_kinds);
            construction.append_block(
                code_block.address(),
                code_block.context(),
                code_block.size(),
                &successors,
                &successor_kinds,
                code_block.address() == function_body.entry(),
            )?;
        }

        self.code_block_ids.clear();
        self.block_addresses.clear();

        construction.build(input.cancellation)
    }

    pub fn build_incomplete_function(
        &mut self,
        language: &'static Language,
        function: &IncompleteFunction,
        segments: &SegmentStorage,
        input_revision: Revision,
        cancellation: &CancellationToken,
    ) -> Result<PCodeIr, PCodeError> {
        let metadata = IlMetadata::new(FunctionId::INVALID, PCODE_SCHEMA_VERSION, input_revision);
        let mut construction = PCodeConstruction::new(language, metadata, segments);
        let mut successors = Vec::new();
        let mut successor_kinds = Vec::new();

        self.block_addresses.clear();
        self.block_addresses
            .extend(function.blocks().iter().map(|block| block.address()));

        for block in function.blocks() {
            cancellation.check()?;

            successors.clear();
            for successor in block.successors().iter() {
                successors.push(IlBlockId::try_from_index(successor.index())?);
            }
            self.edge_kinds_into(
                function.block_flow_targets(block),
                &successors,
                &mut successor_kinds,
            );
            construction.append_block(
                block.address(),
                block.context(),
                block.size(),
                &successors,
                &successor_kinds,
                block.address() == function.entry(),
            )?;
        }

        self.block_addresses.clear();

        construction.build(cancellation)
    }
}

impl<'a> PCodeConstruction<'a> {
    fn new(
        language: &'static Language,
        metadata: IlMetadata,
        segments: &'a SegmentStorage,
    ) -> Self {
        Self {
            language,
            builder: PCodeBuilder::new(language, metadata, IlGraph::default()),
            mapping_cache: SegmentMappingCache::new(),
            segments,
            lifter: Lifter::new(language),
            blocks: Vec::new(),
            successors: Vec::new(),
            successor_kinds: Vec::new(),
            block_sources: Vec::new(),
            source_spans: Vec::new(),
            annotations: Vec::new(),
            operations: Vec::new(),
        }
    }

    fn append_block(
        &mut self,
        source: Address,
        context: &ContextSet,
        size: usize,
        successors: &[IlBlockId],
        successor_kinds: &[IlEdgeKinds],
        is_entry: bool,
    ) -> Result<(), PCodeError> {
        debug_assert_eq!(
            successors.len(),
            successor_kinds.len(),
            "each successor edge carries exactly one kind"
        );

        let operation_start = self.builder.operation_count();
        context.apply(source, self.lifter.context_mut());
        let view = self
            .mapping_cache
            .contiguous_view_from(self.segments, source)?;
        let available = view
            .as_contiguous()
            .ok_or_else(|| PCodeError::insufficient_bytes(source, 0, size))?;
        let bytes = available
            .get(..size)
            .ok_or_else(|| PCodeError::insufficient_bytes(source, available.len(), size))?;
        self.append_extent(source, bytes)?;

        let successor_start = self.successors.len();
        self.successors.extend_from_slice(successors);
        self.successor_kinds.extend_from_slice(successor_kinds);

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

    fn append_extent(&mut self, mut address: Address, bytes: &[u8]) -> Result<(), PCodeError> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            self.operations.clear();
            let remaining = bytes.len() - offset;
            let lifted_size = self
                .lifter
                .lift(address, &bytes[offset..], &mut self.operations)?;
            if lifted_size == 0 || lifted_size > remaining {
                return Err(PCodeError::invalid_insn_size(
                    address,
                    lifted_size,
                    remaining,
                ));
            }
            let source_start = self.builder.operation_count();

            self.annotations.clear();
            let emitted = Self::push_address_annotations(
                self.language,
                address,
                lifted_size,
                &self.operations,
                source_start,
                &mut self.annotations,
            )?;
            let mut context = PCodeAddressContext::new(address, &self.annotations);
            self.builder
                .push_lifted_operations(&self.operations, &mut context)?;

            self.source_spans.push(IlSourceSpan::new(
                IlIndexRange::new(source_start, self.builder.operation_count())?,
                address,
                0,
                u32::try_from(emitted).expect("instruction pcode count fits in u32"),
            ));

            address += lifted_size;
            offset += lifted_size;
        }

        Ok(())
    }

    fn push_address_annotations(
        language: &'static Language,
        address: Address,
        length: usize,
        operations: &[RawPCodeOp],
        starting_ordinal: usize,
        annotations: &mut Vec<AddressAnnotation>,
    ) -> Result<usize, PCodeError> {
        let mut targets = SmallVec::<[(u16, InsnTarget); 1]>::new();
        Insn::push_targets_for_operations(language, address, length, operations, &mut targets);
        let mut semantic_count = 0usize;
        let mut index = 0usize;

        while let Some(operation) = operations.get(index) {
            let ordinal_index = starting_ordinal + semantic_count;
            let ordinal = IlOpId::try_from_index(ordinal_index)?;

            if operation.is_arg() {
                return Err(PCodeError::misplaced_arg(ordinal.value()));
            }

            let opcode = PCodeOpcode::from_op(operation.op())
                .ok_or_else(|| PCodeError::invalid_opcode(ordinal.value()))?;

            if opcode.requires_address() {
                if let Some(target) = targets
                    .iter()
                    .find(|(target_index, _)| usize::from(*target_index) == index)
                    .and_then(|(_, target)| match target {
                        InsnTarget::IntraIns(location, _) | InsnTarget::IntraBlk(location, _) => {
                            Some(*location)
                        }
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
            } else if opcode.requires_address_space() {
                annotations.push(AddressAnnotation::new(
                    ordinal,
                    AddressAnnotationValue::ComputedSpace(address.space()),
                ));
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
        self.builder.set_graph(
            IlGraph::new(self.blocks, self.successors, self.successor_kinds)
                .with_block_sources(self.block_sources),
        );
        self.builder.set_source_spans(self.source_spans);

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
        let metadata = IlMetadata::new(FunctionId::default(), PCODE_SCHEMA_VERSION, 3);
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let mut context = PCodeAddressContext::new(source, &[]);
        let language = resolve_language("x86:LE:64").expect("test language should resolve");
        let mut builder = PCodeBuilder::new(language, metadata, IlGraph::default());

        builder.push_lifted_operations(&[], &mut context).unwrap();
        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert!(ir.operations().is_empty());
        assert_eq!(ir.metadata().input_revision().value(), 3);
    }
}
