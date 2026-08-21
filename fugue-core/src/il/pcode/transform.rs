use std::mem;

use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlError, IlGenerationContext,
    IlGenerationError, IlGraph, IlIndexRange, IlMetadata, IlOpId, IlProducer, IlSourceSpan,
    IlSubject,
};
use crate::il::pcode::raw::remap_target_position;
use crate::il::pcode::{
    PCodeAddressAnnotationRole, PCodeBuilder, PCodeError, PCodeIr, PCodeLocation, PCodeLocationId,
    PCodeOpSpec, PCodeOpcode, RawPCodeFlow, RawPCodeFlows,
};
use crate::ir::{
    Address, CodeBlockId, CodeBlockTable, FlowTarget, FunctionId, FunctionTable,
    IncompleteFunction, Location,
};
use crate::lifter::{ContextSet, Language, Lifter, Op, RawPCodeOp, Varnode};
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::segments::{SegmentMappingCache, SegmentStorage};
use crate::types::common::Revision;

#[derive(Debug, Default)]
pub struct PCodeCanonicaliser {
    scratch: PCodeCanonicaliserScratch,
}

#[derive(Debug, Default)]
struct PCodeCanonicaliserScratch {
    code_block_ids: Vec<CodeBlockId>,
    block_id_by_code_block: FxHashMap<CodeBlockId, IlBlockId>,
    block_addresses: Vec<Address>,
    block_successors: Vec<IlBlockId>,
    block_successor_kinds: Vec<IlEdgeKinds>,
}

impl PCodeCanonicaliserScratch {
    fn collect_edge_kinds(&mut self, flows: impl Iterator<Item = FlowTarget>) {
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

        self.block_successor_kinds.clear();
        self.block_successor_kinds
            .extend(self.block_successors.iter().map(|successor| {
                let target = self.block_addresses.get(successor.index()).copied();
                by_target
                    .iter()
                    .find(|(to, _)| Some(*to) == target)
                    .map_or(IlEdgeKinds::FALL_THROUGH, |(_, kinds)| *kinds)
            }));
    }
}

impl PCodeCanonicaliser {
    pub fn canonicalise_function(
        &mut self,
        input: PCodeFunctionInput<'_>,
    ) -> Result<PCodeIr, PCodeError> {
        PCodeFunctionLifter::new(PCodeFunctionSource::Admitted(input), &mut self.scratch).lift()
    }

    pub fn canonicalise_incomplete_function(
        &mut self,
        language: &'static Language,
        function: &IncompleteFunction,
        segments: &SegmentStorage,
        input_revision: Revision,
        cancellation: &CancellationToken,
    ) -> Result<PCodeIr, PCodeError> {
        let source = PCodeFunctionSource::Speculative {
            language,
            function,
            segments,
            input_revision,
            cancellation,
        };
        PCodeFunctionLifter::new(source, &mut self.scratch).lift()
    }
}

impl IlProducer for PCodeCanonicaliser {
    type Output = PCodeIr;

    fn produce(
        &mut self,
        context: &IlGenerationContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<Self::Output, IlGenerationError> {
        let pcode = match context.subject() {
            IlSubject::Admitted(function) => {
                self.canonicalise_function(PCodeFunctionInput::new(
                    context.language(),
                    context.functions(),
                    context.blocks(),
                    context.segments(),
                    function,
                    context.input_revision(),
                    cancellation,
                ))?
            }
            IlSubject::Speculative {
                function,
                input_revision,
            } => self.canonicalise_incomplete_function(
                context.language(),
                function,
                context.segments(),
                input_revision,
                cancellation,
            )?,
        };

        #[cfg(debug_assertions)]
        if !context.is_speculative()
            && let Err(error) = pcode.verify()
        {
            let function = context.function();
            panic!("canonicalised pcode for {function:?} fails verification: {error}");
        }

        Ok(pcode)
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

enum PCodeFunctionSource<'a> {
    Admitted(PCodeFunctionInput<'a>),
    Speculative {
        language: &'static Language,
        function: &'a IncompleteFunction,
        segments: &'a SegmentStorage,
        input_revision: Revision,
        cancellation: &'a CancellationToken,
    },
}

impl<'a> PCodeFunctionSource<'a> {
    const fn language(&self) -> &'static Language {
        match self {
            Self::Admitted(input) => input.language,
            Self::Speculative { language, .. } => language,
        }
    }

    const fn segments(&self) -> &'a SegmentStorage {
        match self {
            Self::Admitted(input) => input.segments,
            Self::Speculative { segments, .. } => segments,
        }
    }

    fn metadata(&self) -> IlMetadata {
        match self {
            Self::Admitted(input) => IlMetadata::new(input.function, input.input_revision),
            Self::Speculative { input_revision, .. } => {
                IlMetadata::new(FunctionId::INVALID, *input_revision)
            }
        }
    }

    const fn cancellation(&self) -> &'a CancellationToken {
        match self {
            Self::Admitted(input) => input.cancellation,
            Self::Speculative { cancellation, .. } => cancellation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PCodeAddressAnnotationValue {
    ComputedSpace(AddressSpaceId),
    DirectTarget(Location),
}

impl PCodeAddressAnnotationValue {
    const fn role(&self) -> PCodeAddressAnnotationRole {
        match self {
            Self::DirectTarget(_) => PCodeAddressAnnotationRole::DirectTarget,
            Self::ComputedSpace(_) => PCodeAddressAnnotationRole::ComputedSpace,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PCodeAddressAnnotation {
    ordinal: IlOpId,
    value: PCodeAddressAnnotationValue,
}

impl PCodeAddressAnnotation {
    const fn new(ordinal: IlOpId, value: PCodeAddressAnnotationValue) -> Self {
        Self { ordinal, value }
    }
}

#[derive(Debug)]
struct PCodeAddressContext<'a> {
    annotations: &'a [PCodeAddressAnnotation],
    cursor: usize,
}

impl<'a> PCodeAddressContext<'a> {
    const fn new(annotations: &'a [PCodeAddressAnnotation]) -> Self {
        Self {
            annotations,
            cursor: 0,
        }
    }

    fn take(
        &mut self,
        ordinal: IlOpId,
        role: PCodeAddressAnnotationRole,
    ) -> Result<PCodeAddressAnnotationValue, PCodeError> {
        let Some(annotation) = self.annotations.get(self.cursor) else {
            return Err(PCodeError::missing_annotation(ordinal.value(), role));
        };

        if annotation.ordinal < ordinal {
            Err(PCodeError::out_of_order_annotation(
                annotation.ordinal.value(),
                annotation.value.role(),
            ))
        } else if annotation.ordinal == ordinal && annotation.value.role() == role {
            if let Some(next) = self.annotations.get(self.cursor + 1)
                && next.ordinal == ordinal
                && next.value.role() == role
            {
                return Err(PCodeError::duplicate_annotation(ordinal.value(), role));
            }

            self.cursor += 1;
            Ok(annotation.value.clone())
        } else if annotation.ordinal == ordinal {
            Err(PCodeError::wrong_annotation_role(
                ordinal.value(),
                role,
                annotation.value.role(),
            ))
        } else {
            Err(PCodeError::missing_annotation(ordinal.value(), role))
        }
    }

    fn ensure_consumed(&self) -> Result<(), PCodeError> {
        if let Some(annotation) = self.annotations.get(self.cursor) {
            Err(PCodeError::unused_annotation(
                annotation.ordinal.value(),
                annotation.value.role(),
            ))
        } else {
            Ok(())
        }
    }
}

struct PCodeFunctionLifter<'source, 'scratch> {
    source: Option<PCodeFunctionSource<'source>>,
    scratch: &'scratch mut PCodeCanonicaliserScratch,
    language: &'static Language,
    cancellation: &'source CancellationToken,
    builder: PCodeBuilder,
    mapping_cache: SegmentMappingCache,
    segments: &'source SegmentStorage,
    lifter: Lifter,
    blocks: Vec<IlBlock>,
    successors: Vec<IlBlockId>,
    successor_kinds: Vec<IlEdgeKinds>,
    block_sources: Vec<Address>,
    source_spans: Vec<IlSourceSpan>,
    annotations: Vec<PCodeAddressAnnotation>,
    operations: Vec<RawPCodeOp>,
    inputs: Vec<Varnode>,
    operands: Vec<PCodeLocationId>,
}

impl<'source, 'scratch> PCodeFunctionLifter<'source, 'scratch> {
    fn new(
        source: PCodeFunctionSource<'source>,
        scratch: &'scratch mut PCodeCanonicaliserScratch,
    ) -> Self {
        let language = source.language();
        let cancellation = source.cancellation();
        let metadata = source.metadata();
        let segments = source.segments();
        Self {
            source: Some(source),
            scratch,
            language,
            cancellation,
            builder: PCodeBuilder::new(metadata, IlGraph::default()),
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
            inputs: Vec::new(),
            operands: Vec::new(),
        }
    }

    fn lift_admitted(&mut self, input: PCodeFunctionInput<'source>) -> Result<(), PCodeError> {
        let Some(function_body) = input.functions.get_by_id(input.function) else {
            return Err(IlError::missing_artefact(input.function, PCodeIr::FORM).into());
        };

        self.scratch.code_block_ids.clear();
        self.scratch.block_id_by_code_block.clear();
        self.scratch.block_addresses.clear();

        for (_, code_block) in function_body.blocks() {
            let block_id = IlBlockId::try_from_index(self.scratch.code_block_ids.len())?;
            self.scratch
                .block_id_by_code_block
                .insert(code_block, block_id);
            self.scratch.code_block_ids.push(code_block);
        }

        for &code_block_id in &self.scratch.code_block_ids {
            let Some(code_block) = input.blocks.get_by_id(code_block_id) else {
                return Err(IlError::missing_artefact(input.function, PCodeIr::FORM).into());
            };
            self.scratch.block_addresses.push(code_block.address());
        }

        for index in 0..self.scratch.code_block_ids.len() {
            self.cancellation.check()?;

            let code_block_id = self.scratch.code_block_ids[index];
            let Some(code_block) = input.blocks.get_by_id(code_block_id) else {
                return Err(IlError::missing_artefact(input.function, PCodeIr::FORM).into());
            };

            self.scratch.block_successors.clear();
            self.scratch.block_successors.extend(
                function_body
                    .successors(code_block_id)
                    .filter_map(|successor| {
                        self.scratch.block_id_by_code_block.get(&successor).copied()
                    }),
            );
            self.scratch.collect_edge_kinds(code_block.flow_targets());
            let successors = mem::take(&mut self.scratch.block_successors);
            let successor_kinds = mem::take(&mut self.scratch.block_successor_kinds);
            let result = self.lift_block(
                code_block.address(),
                code_block.context(),
                code_block.size(),
                &successors,
                &successor_kinds,
                code_block.address() == function_body.entry(),
            );
            self.scratch.block_successors = successors;
            self.scratch.block_successor_kinds = successor_kinds;
            result?;
        }

        Ok(())
    }

    fn lift_speculative(&mut self, function: &IncompleteFunction) -> Result<(), PCodeError> {
        self.scratch.block_addresses.clear();
        self.scratch
            .block_addresses
            .extend(function.blocks().iter().map(|block| block.address()));

        for block in function.blocks() {
            self.cancellation.check()?;

            self.scratch.block_successors.clear();
            for successor in block.successors().iter() {
                self.scratch
                    .block_successors
                    .push(IlBlockId::try_from_index(successor.index())?);
            }
            self.scratch
                .collect_edge_kinds(function.block_flow_targets(block));
            let successors = mem::take(&mut self.scratch.block_successors);
            let successor_kinds = mem::take(&mut self.scratch.block_successor_kinds);
            let result = self.lift_block(
                block.address(),
                block.context(),
                block.size(),
                &successors,
                &successor_kinds,
                block.address() == function.entry(),
            );
            self.scratch.block_successors = successors;
            self.scratch.block_successor_kinds = successor_kinds;
            result?;
        }

        Ok(())
    }

    fn lift_block(
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

        let operation_start = self.builder.emitter().op_count();
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
            IlIndexRange::new(operation_start, self.builder.emitter().op_count())?,
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
            let source_start = self.builder.emitter().op_count();

            self.annotations.clear();
            let emitted = self.push_address_annotations(address, lifted_size, source_start)?;
            let annotations = mem::take(&mut self.annotations);
            let mut context = PCodeAddressContext::new(&annotations);
            let result = self.lift_ops(&mut context);
            self.annotations = annotations;
            result?;

            let emitted = u32::try_from(emitted)
                .map_err(|_| IlError::integer_overflow("instruction PCode count"))?;
            self.source_spans.push(IlSourceSpan::new(
                IlIndexRange::new(source_start, self.builder.emitter().op_count())?,
                address,
                0,
                emitted,
            ));

            address += lifted_size;
            offset += lifted_size;
        }

        Ok(())
    }

    fn push_address_annotations(
        &mut self,
        address: Address,
        length: usize,
        starting_ordinal: usize,
    ) -> Result<usize, PCodeError> {
        let flows = RawPCodeFlows::new(self.language, address, length, &self.operations);
        let mut semantic_count = 0usize;
        let mut index = 0usize;

        while let Some(operation) = self.operations.get(index) {
            let ordinal_index = starting_ordinal + semantic_count;
            let ordinal = IlOpId::try_from_index(ordinal_index)?;

            if operation.is_arg() {
                return Err(PCodeError::misplaced_arg(ordinal.value()));
            }

            let opcode = PCodeOpcode::from_op(operation.op())
                .ok_or_else(|| PCodeError::invalid_opcode(ordinal.value()))?;

            if opcode.requires_address() {
                if let Some(target) = u16::try_from(index)
                    .ok()
                    .and_then(|index| flows.flow_for(index))
                    .and_then(|flow| match flow {
                        RawPCodeFlow::Branch(Some(location))
                        | RawPCodeFlow::Call(Some(location))
                        | RawPCodeFlow::FallThrough(location) => Some(*location),
                        RawPCodeFlow::Return(Some(return_address)) => {
                            Some((*return_address).into())
                        }
                        RawPCodeFlow::Branch(None)
                        | RawPCodeFlow::Call(None)
                        | RawPCodeFlow::Return(None)
                        | RawPCodeFlow::Intrinsic => None,
                    })
                {
                    let target = remap_target_position(&self.operations, address, target)
                        .ok_or_else(|| {
                            PCodeError::invalid_local_target(ordinal.value(), target.position())
                        })?;
                    self.annotations.push(PCodeAddressAnnotation::new(
                        ordinal,
                        PCodeAddressAnnotationValue::DirectTarget(target),
                    ));
                }
            } else if opcode.requires_address_space() {
                self.annotations.push(PCodeAddressAnnotation::new(
                    ordinal,
                    PCodeAddressAnnotationValue::ComputedSpace(address.space()),
                ));
            }

            semantic_count += 1;
            index += operation.spill() + 1;
        }

        Ok(semantic_count)
    }

    fn lift_ops(&mut self, context: &mut PCodeAddressContext<'_>) -> Result<(), PCodeError> {
        let mut ordinal = self.builder.emitter().op_count();
        let mut index = 0usize;

        while let Some(operation) = self.operations.get(index).copied() {
            let operation_id = IlOpId::try_from_index(ordinal)?;
            if operation.is_arg() {
                return Err(PCodeError::misplaced_arg(operation_id.value()));
            }

            let opcode = PCodeOpcode::from_op(operation.op())
                .ok_or_else(|| PCodeError::invalid_opcode(operation_id.value()))?;
            self.inputs.clear();
            self.inputs.extend(operation.inputs().iter().copied());

            if let Op::UserOp(_, arity) = operation.op() {
                let spill = operation.spill();

                for spill_index in 0..spill {
                    let Some(arg) = self.operations.get(index + spill_index + 1) else {
                        return Err(PCodeError::missing_arg(
                            operation_id.value(),
                            (spill - spill_index) as u8,
                        ));
                    };

                    if !arg.is_arg() {
                        return Err(PCodeError::missing_arg(
                            operation_id.value(),
                            (spill - spill_index) as u8,
                        ));
                    }

                    self.inputs.extend(arg.inputs().iter().copied());
                }

                let expected = usize::from(arity);
                self.inputs.truncate(expected);
                if self.inputs.len() != expected {
                    return Err(PCodeError::invalid_arg_count(
                        operation_id.value(),
                        arity,
                        u8::try_from(self.inputs.len())
                            .expect("PCode argument count is representable"),
                    ));
                }

                index += spill;
            }

            self.operands.clear();
            for input_index in 0..self.inputs.len() {
                let input = self.inputs[input_index];
                let location = PCodeLocation::from_varnode(self.language, &input);
                self.operands
                    .push(self.builder.emitter().intern_location(location)?);
            }

            let output = operation
                .output()
                .map(|output| PCodeLocation::from_varnode(self.language, output))
                .map(|location| self.builder.emitter().intern_location(location))
                .transpose()?;
            let mut emitter = self.builder.emitter();
            let mut spec = PCodeOpSpec::new(opcode);
            if opcode.requires_address_space() {
                match context.take(operation_id, PCodeAddressAnnotationRole::ComputedSpace)? {
                    PCodeAddressAnnotationValue::ComputedSpace(space) => {
                        spec.set_address_space(space)
                    }
                    _ => unreachable!(),
                }
            }
            match operation.op() {
                Op::Load(space) | Op::Store(space) => spec.set_immediate(u32::from(space)),
                Op::UserOp(user_op, _) => spec.set_immediate(u32::from(user_op)),
                _ if opcode.requires_address() => {
                    match context.take(operation_id, PCodeAddressAnnotationRole::DirectTarget)? {
                        PCodeAddressAnnotationValue::DirectTarget(target) => {
                            spec.set_target(emitter.emit_target(target)?);
                        }
                        _ => unreachable!(),
                    }
                }
                _ => {}
            }
            emitter.emit(spec, output, self.operands.iter().copied())?;

            ordinal += 1;
            index += 1;
        }

        context.ensure_consumed()?;

        Ok(())
    }

    fn lift(mut self) -> Result<PCodeIr, PCodeError> {
        match self
            .source
            .take()
            .expect("a PCode function lifter owns exactly one source")
        {
            PCodeFunctionSource::Admitted(input) => self.lift_admitted(input)?,
            PCodeFunctionSource::Speculative { function, .. } => self.lift_speculative(function)?,
        }
        self.builder.set_graph(
            IlGraph::new(self.blocks, self.successors, self.successor_kinds)
                .with_block_sources(self.block_sources),
        );
        self.builder.set_source_spans(self.source_spans);

        Ok(self.builder.build(self.cancellation)?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ir::{FunctionId, RawAddress};

    #[test]
    fn address_context_consumes_annotations_in_order() {
        let ordinal = IlOpId::try_from_index(0).unwrap();
        let target = Address::new(AddressSpaceId::new(1), RawAddress::from(0x401000u64));
        let annotations = [PCodeAddressAnnotation::new(
            ordinal,
            PCodeAddressAnnotationValue::DirectTarget(target.into()),
        )];
        let mut context = PCodeAddressContext::new(&annotations);

        assert!(matches!(
            context.take(ordinal, PCodeAddressAnnotationRole::DirectTarget),
            Ok(PCodeAddressAnnotationValue::DirectTarget(taken)) if taken == target.into()
        ));
        assert!(context.ensure_consumed().is_ok());
    }

    #[test]
    fn address_context_rejects_duplicate_role() {
        let ordinal = IlOpId::try_from_index(0).unwrap();
        let source = Address::new(AddressSpaceId::new(1), RawAddress::from(0x401000u64));
        let annotations = [
            PCodeAddressAnnotation::new(
                ordinal,
                PCodeAddressAnnotationValue::DirectTarget(source.into()),
            ),
            PCodeAddressAnnotation::new(
                ordinal,
                PCodeAddressAnnotationValue::DirectTarget(source.into()),
            ),
        ];
        let mut context = PCodeAddressContext::new(&annotations);

        assert!(matches!(
            context.take(ordinal, PCodeAddressAnnotationRole::DirectTarget),
            Err(PCodeError::DuplicateAnnotation { .. })
        ));
    }

    #[test]
    fn address_context_rejects_out_of_order_annotation() {
        let first = IlOpId::try_from_index(0).unwrap();
        let second = IlOpId::try_from_index(1).unwrap();
        let source = Address::new(AddressSpaceId::new(1), RawAddress::from(0x401000u64));
        let annotations = [PCodeAddressAnnotation::new(
            first,
            PCodeAddressAnnotationValue::DirectTarget(source.into()),
        )];
        let mut context = PCodeAddressContext::new(&annotations);

        assert!(matches!(
            context.take(second, PCodeAddressAnnotationRole::DirectTarget),
            Err(PCodeError::OutOfOrderAnnotation { .. })
        ));
    }

    #[test]
    fn address_context_rejects_wrong_role() {
        let ordinal = IlOpId::try_from_index(0).unwrap();
        let source = Address::new(AddressSpaceId::new(1), RawAddress::from(0x401000u64));
        let annotations = [PCodeAddressAnnotation::new(
            ordinal,
            PCodeAddressAnnotationValue::DirectTarget(source.into()),
        )];
        let mut context = PCodeAddressContext::new(&annotations);

        assert!(matches!(
            context.take(ordinal, PCodeAddressAnnotationRole::ComputedSpace),
            Err(PCodeError::WrongAnnotationRole { .. })
        ));
    }

    #[test]
    fn target_builder_builds_empty_pcode() {
        let metadata = IlMetadata::new(FunctionId::default(), 3);
        let builder = PCodeBuilder::new(metadata, IlGraph::default());

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert!(ir.ops().is_empty());
        assert_eq!(ir.metadata().input_revision().value(), 3);
    }
}
