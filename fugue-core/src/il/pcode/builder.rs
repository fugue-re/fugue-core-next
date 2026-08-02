use std::mem::{self, size_of};

use rustc_hash::FxHashMap;

use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlError, IlGraph, IlIndexRange, IlLevel, IlMetadata, IlOpId, IlPool,
    IlSchemaVersion, IlSourceSpan,
};
use crate::il::pcode::{
    AddressAnnotationRole, AddressAnnotationValue, PCodeAddressContext, PCodeError, PCodeLocation,
    PCodeLocationId, PCodeOp, PCodeOpcode,
};
use crate::ir::{
    Address, AddressRange, AddressRangeSet, FunctionId, Location, Reference, ReferenceOrigin,
    ReferenceProperties,
};
use crate::lifter::{Language, Op, RawPCodeOp, Varnode};
use crate::storage::entities::schema::ENTITY_IL_PCODE_ID;
use crate::storage::entities::{Entity, EntityId, MutableEntity};
use crate::storage::segments::space::AddressSpaceId;
use crate::types::EstimateSize;

pub const PCODE_SCHEMA_VERSION: IlSchemaVersion = IlSchemaVersion::new(1);

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct PCodeIr {
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    locations: Vec<PCodeLocation>,
    operations: Vec<PCodeOp>,
    operands: Vec<PCodeLocationId>,
    targets: Vec<Location>,
}

impl PCodeIr {
    pub(crate) fn new(
        metadata: IlMetadata,
        graph: IlGraph,
        source_spans: Vec<IlSourceSpan>,
        locations: Vec<PCodeLocation>,
        operations: Vec<PCodeOp>,
        operands: Vec<PCodeLocationId>,
        targets: Vec<Location>,
    ) -> Self {
        Self {
            metadata,
            graph,
            source_spans,
            locations,
            operations,
            operands,
            targets,
        }
    }

    pub const fn metadata(&self) -> &IlMetadata {
        &self.metadata
    }

    pub const fn graph(&self) -> &IlGraph {
        &self.graph
    }

    pub fn source_spans(&self) -> &[IlSourceSpan] {
        &self.source_spans
    }

    pub fn source_span_for(&self, node: usize) -> Option<IlSourceSpan> {
        IlSourceSpan::find(&self.source_spans, node)
    }

    pub fn source_spans_for(
        &self,
        address: Address,
        pcode_index: u32,
    ) -> impl Iterator<Item = IlSourceSpan> + '_ {
        IlSourceSpan::find_all(&self.source_spans, address, pcode_index)
    }

    pub fn locations(&self) -> &[PCodeLocation] {
        &self.locations
    }

    pub fn operations(&self) -> &[PCodeOp] {
        &self.operations
    }

    pub fn operation_operands(&self) -> &[PCodeLocationId] {
        &self.operands
    }

    pub fn targets(&self) -> &[Location] {
        &self.targets
    }

    pub fn target(&self, index: u32) -> Option<Location> {
        index
            .checked_sub(1)
            .and_then(|index| self.targets.get(index as usize))
            .copied()
    }

    pub fn location(&self, id: PCodeLocationId) -> Option<&PCodeLocation> {
        self.locations.get(id.index())
    }

    pub fn operation_operands_for(&self, operation: &PCodeOp) -> &[PCodeLocationId] {
        operation.operands().slice(&self.operands)
    }

    pub fn operations_for_source(
        &self,
        address: Address,
    ) -> impl Iterator<Item = (IlOpId, &PCodeOp)> + '_ {
        self.source_spans
            .iter()
            .filter(move |span| span.address() == address)
            .flat_map(move |span| {
                let start = span.destination().start();
                span.destination()
                    .slice(&self.operations)
                    .iter()
                    .enumerate()
                    .map(move |(index, operation)| {
                        (
                            IlOpId::try_from_index(start + index)
                                .expect("operation count fits the operation id space"),
                            operation,
                        )
                    })
            })
    }

    pub fn data_references(&self) -> impl Iterator<Item = Reference> + '_ {
        self.operations
            .iter()
            .enumerate()
            .filter_map(move |(index, operation)| {
                let props = match operation.opcode() {
                    PCodeOpcode::Load => ReferenceProperties::READ,
                    PCodeOpcode::Store => ReferenceProperties::WRITE,
                    _ => return None,
                };
                let from = self.source_span_for(index)?;
                let pointer = self.operation_operands_for(operation).first().copied()?;
                let pointer = self.location(pointer)?;
                if !pointer.is_constant() {
                    return None;
                }
                let space = operation.address_space()?;
                Some(
                    Reference::data(from.address(), Address::new(space, pointer.offset()), props)
                        .with_origin(ReferenceOrigin::Derived),
                )
            })
    }

    pub fn shrink_to_fit(&mut self) {
        self.graph.shrink_to_fit();
        self.source_spans.shrink_to_fit();
        self.locations.shrink_to_fit();
        self.operations.shrink_to_fit();
        self.operands.shrink_to_fit();
        self.targets.shrink_to_fit();
    }

    pub fn reference_coverage_into(&self, coverage: &mut AddressRangeSet) {
        for span in &self.source_spans {
            coverage.insert_range(AddressRange::point(span.address()));
        }
    }
}

impl Entity for PCodeIr {
    const ID: EntityId = ENTITY_IL_PCODE_ID;
}

impl MutableEntity for PCodeIr {
    type Key = FunctionId;

    fn entity_key(&self) -> FunctionId {
        self.metadata.function()
    }
}

impl IlArtefact for PCodeIr {
    const LEVEL: IlLevel = IlLevel::PCode;
    const SCHEMA: IlSchemaVersion = PCODE_SCHEMA_VERSION;

    fn metadata(&self) -> &IlMetadata {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut IlMetadata {
        &mut self.metadata
    }

    fn graph(&self) -> &IlGraph {
        &self.graph
    }
}

impl EstimateSize for PCodeIr {
    fn estimate_size(&self) -> usize {
        [
            self.graph.estimate_size(),
            self.source_spans
                .capacity()
                .saturating_mul(size_of::<IlSourceSpan>()),
            self.locations
                .capacity()
                .saturating_mul(size_of::<PCodeLocation>()),
            self.operations
                .capacity()
                .saturating_mul(size_of::<PCodeOp>()),
            self.operands
                .capacity()
                .saturating_mul(size_of::<PCodeLocationId>()),
            self.targets
                .capacity()
                .saturating_mul(size_of::<Location>()),
        ]
        .into_iter()
        .fold(
            size_of::<Self>().saturating_sub(size_of::<IlGraph>()),
            usize::saturating_add,
        )
    }
}

#[derive(Debug)]
pub(crate) struct PCodeBuilder {
    language: &'static Language,
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    locations: Vec<PCodeLocation>,
    location_ids: FxHashMap<PCodeLocation, PCodeLocationId>,
    operations: Vec<PCodeOp>,
    input_scratch: Vec<Varnode>,
    operand_scratch: Vec<PCodeLocationId>,
    operands: IlPool<PCodeLocationId>,
    targets: Vec<Location>,
}

impl PCodeBuilder {
    pub(crate) fn new(language: &'static Language, metadata: IlMetadata, graph: IlGraph) -> Self {
        Self {
            language,
            metadata,
            graph,
            source_spans: Vec::new(),
            locations: Vec::new(),
            location_ids: FxHashMap::default(),
            operations: Vec::new(),
            input_scratch: Vec::new(),
            operand_scratch: Vec::new(),
            operands: IlPool::new(),
            targets: Vec::new(),
        }
    }

    pub(crate) fn push_location(
        &mut self,
        location: PCodeLocation,
    ) -> Result<PCodeLocationId, IlError> {
        if let Some(id) = self.location_ids.get(&location).copied() {
            return Ok(id);
        }

        let id = PCodeLocationId::try_from_index(self.locations.len())?;
        self.locations.push(location);
        self.location_ids.insert(location, id);
        Ok(id)
    }

    pub(crate) fn push_operands(
        &mut self,
        operands: impl IntoIterator<Item = PCodeLocationId>,
    ) -> Result<IlIndexRange, IlError> {
        self.operands.append(operands)
    }

    pub(crate) fn push_operation(&mut self, operation: PCodeOp) {
        self.operations.push(operation);
    }

    pub(crate) fn operation_count(&self) -> usize {
        self.operations.len()
    }

    pub(crate) fn set_graph(&mut self, graph: IlGraph) {
        self.graph = graph;
    }

    pub(crate) fn set_source_spans(&mut self, source_spans: Vec<IlSourceSpan>) {
        self.source_spans = source_spans;
    }

    pub(crate) fn push_target(&mut self, target: Location) -> Result<u32, IlError> {
        let index = self.targets.len();
        self.targets.push(target);
        u32::try_from(index + 1).map_err(|_| IlError::id_exhausted("PCode target"))
    }

    pub(crate) fn push_lifted_operations(
        &mut self,
        operations: &[RawPCodeOp],
        context: &mut PCodeAddressContext<'_>,
    ) -> Result<(), PCodeError> {
        let language = self.language;
        let mut ordinal = self.operation_count();
        let mut index = 0usize;

        while let Some(operation) = operations.get(index) {
            let operation_id = IlOpId::try_from_index(ordinal)?;
            if operation.is_arg() {
                return Err(PCodeError::misplaced_arg(operation_id.value()));
            }

            let opcode = PCodeOpcode::from_op(operation.op())
                .ok_or_else(|| PCodeError::invalid_opcode(operation_id.value()))?;
            self.input_scratch.clear();
            self.input_scratch
                .extend(operation.inputs().iter().copied());

            if let Op::UserOp(_, arity) = operation.op() {
                let spill = operation.spill();

                for spill_index in 0..spill {
                    let Some(arg) = operations.get(index + spill_index + 1) else {
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

                    self.input_scratch.extend(arg.inputs().iter().copied());
                }

                self.input_scratch.truncate(arity as usize);

                if self.input_scratch.len() != arity as usize {
                    return Err(PCodeError::invalid_argument_count(
                        operation_id.value(),
                        arity,
                        self.input_scratch.len() as u8,
                    ));
                }

                index += spill;
            }

            self.operand_scratch.clear();
            for input_index in 0..self.input_scratch.len() {
                let input = self.input_scratch[input_index];
                let location = PCodeLocation::from_varnode(language, &input);
                let operand = self.push_location(location)?;
                self.operand_scratch.push(operand);
            }
            let operand_scratch = mem::take(&mut self.operand_scratch);
            let operands = self.push_operands(operand_scratch.iter().copied());
            self.operand_scratch = operand_scratch;
            let operands = operands?;
            let output = operation
                .output()
                .map(|output| PCodeLocation::from_varnode(language, output))
                .map(|location| self.push_location(location))
                .transpose()?;
            let address_space = self.address_space_for(opcode, operation_id, context)?;
            let immediate = self.immediate_for(operation, opcode, operation_id, context)?;

            self.push_operation(PCodeOp::new(
                opcode,
                output,
                operands,
                immediate,
                address_space,
            ));

            ordinal += 1;
            index += 1;
        }

        context.ensure_consumed()?;

        Ok(())
    }

    fn address_space_for(
        &self,
        opcode: PCodeOpcode,
        ordinal: IlOpId,
        context: &mut PCodeAddressContext<'_>,
    ) -> Result<Option<AddressSpaceId>, PCodeError> {
        if !opcode.requires_address_space() {
            return Ok(None);
        }

        match context.take(ordinal, AddressAnnotationRole::ComputedSpace)? {
            AddressAnnotationValue::ComputedSpace(space) => Ok(Some(space)),
            _ => unreachable!(),
        }
    }

    fn immediate_for(
        &mut self,
        operation: &RawPCodeOp,
        opcode: PCodeOpcode,
        ordinal: IlOpId,
        context: &mut PCodeAddressContext<'_>,
    ) -> Result<u32, PCodeError> {
        match operation.op() {
            Op::Load(space) | Op::Store(space) => Ok(u32::from(space)),
            Op::UserOp(user_op, _) => Ok(u32::from(user_op)),
            _ if opcode.requires_address() => {
                match context.take(ordinal, AddressAnnotationRole::DirectTarget)? {
                    AddressAnnotationValue::DirectTarget(target) => {
                        self.push_target(target).map_err(PCodeError::from)
                    }
                    _ => unreachable!(),
                }
            }
            _ => Ok(0),
        }
    }

    pub(crate) fn build(self, cancellation: &CancellationToken) -> Result<PCodeIr, IlError> {
        cancellation.check()?;

        let mut ir = PCodeIr::new(
            self.metadata,
            self.graph,
            self.source_spans,
            self.locations,
            self.operations,
            self.operands.into_values(),
            self.targets,
        );

        ir.shrink_to_fit();

        Ok(ir)
    }
}

#[cfg(test)]
mod test {
    use fugue_lifter::runtime::pcode::Inputs;

    use super::*;
    use crate::il::common::{IlBlock, IlBlockProperties, IlSourceSpan};
    use crate::il::pcode::verify::VerifyError;
    use crate::il::pcode::{
        AddressAnnotation, AddressAnnotationValue, LifterSpaceHandle, PCodeAddressContext,
        PCodeLocationProperties,
    };
    use crate::lifter::{Op, Varnode};
    use crate::storage::segments::space::AddressSpaceId;

    fn pcode_op(op: Op, inputs: Inputs, output: Varnode) -> RawPCodeOp {
        RawPCodeOp { op, inputs, output }
    }

    fn language() -> &'static Language {
        crate::lifter::resolve_language("x86:LE:64").expect("test language should resolve")
    }

    fn metadata() -> IlMetadata {
        IlMetadata::new(FunctionId::default(), PCODE_SCHEMA_VERSION, 0)
    }

    #[test]
    fn pcode_builder_finishes_verified_ir() {
        let mut builder = PCodeBuilder::new(language(), metadata(), IlGraph::default());
        let location = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let operands = builder.push_operands([location]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(location),
            operands,
            0,
            None,
        ));

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert!(ir.verify().is_ok());
        assert_eq!(ir.operations().len(), 1);
        assert_eq!(ir.locations().len(), 1);
    }

    #[test]
    fn pcode_verify_rejects_multi_flag_location_properties() {
        let mut builder = PCodeBuilder::new(language(), metadata(), IlGraph::default());
        let location = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT | PCodeLocationProperties::REGISTER,
            ))
            .unwrap();
        let operands = builder.push_operands([location]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(location),
            operands,
            0,
            None,
        ));

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::InvalidLocationProperties)
        ));
    }

    #[test]
    fn pcode_verify_rejects_address_space_on_non_requiring_opcode() {
        let mut builder = PCodeBuilder::new(language(), metadata(), IlGraph::default());
        let location = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let operands = builder.push_operands([location]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(location),
            operands,
            0,
            Some(AddressSpaceId::new(1)),
        ));

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::ForbiddenEffectSpace)
        ));
    }

    #[test]
    fn pcode_builder_finish_shrinks_spare_capacity() {
        let mut builder = PCodeBuilder::new(language(), metadata(), IlGraph::default());

        builder.locations.reserve(16);
        builder.operations.reserve(16);
        builder.targets.reserve(16);

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert_eq!(ir.locations.len(), ir.locations.capacity());
        assert_eq!(ir.operations.len(), ir.operations.capacity());
        assert_eq!(ir.targets.len(), ir.targets.capacity());
    }

    #[test]
    fn pcode_ir_round_trips_through_archive() {
        let mut builder = PCodeBuilder::new(language(), metadata(), IlGraph::default());
        let location = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let operands = builder.push_operands([location]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(location),
            operands,
            0,
            None,
        ));

        let ir = builder.build(&CancellationToken::default()).unwrap();
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&ir).unwrap();
        let decoded = rkyv::from_bytes::<PCodeIr, rkyv::rancor::Error>(&bytes).unwrap();

        assert_eq!(decoded, ir);
    }

    #[test]
    fn pcode_ir_derives_constant_data_references() {
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let data_space = AddressSpaceId::new(2);
        let data = 0x4000u64;
        let mut builder = PCodeBuilder::new(language(), metadata(), IlGraph::default());

        builder.set_source_spans(vec![IlSourceSpan::new(
            IlIndexRange::new(0, 2).unwrap(),
            source,
            0,
            2,
        )]);
        let pointer = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                data,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let value = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(1),
                0,
                8,
                PCodeLocationProperties::empty(),
            ))
            .unwrap();
        let load_operands = builder.push_operands([pointer]).unwrap();
        let store_operands = builder.push_operands([pointer, value]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Load,
            Some(value),
            load_operands,
            0,
            Some(data_space),
        ));
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Store,
            None,
            store_operands,
            0,
            Some(data_space),
        ));

        let ir = builder.build(&CancellationToken::default()).unwrap();
        let references = ir.data_references().collect::<Vec<_>>();

        assert_eq!(references.len(), 2);
        assert!(references[0].is_read());
        assert_eq!(references[0].from(), source);
        assert_eq!(
            references[0].target().address(),
            Some(Address::new(data_space, data))
        );
        assert!(references[0].origin().is_derived());
        assert!(references[1].is_write());
        assert_eq!(
            references[1].target().address(),
            Some(Address::new(data_space, data))
        );
    }

    #[test]
    fn pcode_ir_ignores_non_constant_data_references() {
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let data_space = AddressSpaceId::new(2);
        let mut builder = PCodeBuilder::new(language(), metadata(), IlGraph::default());

        builder.set_source_spans(vec![IlSourceSpan::new(
            IlIndexRange::new(0, 1).unwrap(),
            source,
            0,
            1,
        )]);
        let pointer = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(1),
                0x20,
                8,
                PCodeLocationProperties::empty(),
            ))
            .unwrap();
        let output = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(1),
                0,
                8,
                PCodeLocationProperties::empty(),
            ))
            .unwrap();
        let operands = builder.push_operands([pointer]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Load,
            Some(output),
            operands,
            0,
            Some(data_space),
        ));

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert!(ir.data_references().next().is_none());
    }

    #[test]
    fn pcode_verifier_rejects_out_of_range_source_span() {
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let ir = PCodeIr::new(
            metadata(),
            IlGraph::default(),
            vec![IlSourceSpan::new(
                IlIndexRange::new(0, 1).unwrap(),
                source,
                0,
                1,
            )],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::Il(IlError::RangeOutOfBounds { .. }))
        ));
    }

    #[test]
    fn pcode_verifier_rejects_out_of_range_block_operations() {
        let graph = IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::empty(),
            )],
            Vec::new(),
        );
        let ir = PCodeIr::new(
            metadata(),
            graph,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::Il(IlError::RangeOutOfBounds { .. }))
        ));
    }

    #[test]
    fn lifter_stream_interns_repeated_locations() {
        let language = language();
        let mut builder = PCodeBuilder::new(language, metadata(), IlGraph::default());
        let varnode = Varnode::new(language.register_space(), 8, 8);
        let operation = pcode_op(Op::Copy, Inputs::one(varnode), varnode);
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let mut context = PCodeAddressContext::new(source, &[]);

        builder
            .push_lifted_operations(&[operation], &mut context)
            .unwrap();
        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert_eq!(ir.locations().len(), 1);
        assert_eq!(ir.operation_operands().len(), 1);
    }

    #[test]
    fn lifter_stream_classifies_locations_from_language_spaces() {
        let language = language();
        let mut builder = PCodeBuilder::new(language, metadata(), IlGraph::default());
        let constant = Varnode::constant(7, 8);
        let register = Varnode::new(language.register_space(), 8, 8);
        let unique = Varnode::new(language.unique_space(), 16, 8);
        let first = pcode_op(Op::Copy, Inputs::one(constant), register);
        let second = pcode_op(Op::Copy, Inputs::one(register), unique);
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let mut context = PCodeAddressContext::new(source, &[]);

        builder
            .push_lifted_operations(&[first, second], &mut context)
            .unwrap();
        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert!(ir.locations().iter().any(PCodeLocation::is_constant));
        assert!(ir.locations().iter().any(PCodeLocation::is_register));
        assert!(ir.locations().iter().any(PCodeLocation::is_unique));
    }

    #[test]
    fn lifter_stream_folds_user_op_args() {
        let language = language();
        let mut builder = PCodeBuilder::new(language, metadata(), IlGraph::default());
        let first = Varnode::new(language.register_space(), 8, 8);
        let second = Varnode::new(language.register_space(), 16, 8);
        let third = Varnode::new(language.register_space(), 24, 8);
        let output = Varnode::new(language.unique_space(), 32, 8);
        let user_op = pcode_op(Op::UserOp(7, 3), Inputs::two(first, second), output);
        let arg = pcode_op(Op::Arg, Inputs::one(third), Varnode::INVALID);
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let mut context = PCodeAddressContext::new(source, &[]);

        builder
            .push_lifted_operations(&[user_op, arg], &mut context)
            .unwrap();
        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert_eq!(ir.operations().len(), 1);
        assert_eq!(ir.operation_operands().len(), 3);
        assert_eq!(ir.operations()[0].immediate(), 7);
    }

    #[test]
    fn lifter_stream_requires_computed_space_annotation() {
        let language = language();
        let mut builder = PCodeBuilder::new(language, metadata(), IlGraph::default());
        let offset = Varnode::new(language.register_space(), 8, 8);
        let output = Varnode::new(language.unique_space(), 16, 8);
        let load = pcode_op(
            Op::Load(language.default_space()),
            Inputs::one(offset),
            output,
        );
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let annotation = [AddressAnnotation::new(
            IlOpId::try_from_index(0).unwrap(),
            AddressAnnotationValue::ComputedSpace(AddressSpaceId::new(9)),
        )];
        let mut context = PCodeAddressContext::new(source, &annotation);

        builder
            .push_lifted_operations(&[load], &mut context)
            .unwrap();
        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert_eq!(
            ir.operations()[0].address_space(),
            Some(AddressSpaceId::new(9))
        );
        assert_eq!(
            ir.operations()[0].immediate(),
            language.default_space() as u32
        );
    }

    #[test]
    fn lifter_stream_records_direct_target_annotation() {
        let language = language();
        let mut builder = PCodeBuilder::new(language, metadata(), IlGraph::default());
        let target_varnode = Varnode::constant(0x2000, 8);
        let branch = pcode_op(Op::Branch, Inputs::one(target_varnode), Varnode::INVALID);
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target = Address::new(AddressSpaceId::new(2), 0x2000u64);
        let annotation = [AddressAnnotation::new(
            IlOpId::try_from_index(0).unwrap(),
            AddressAnnotationValue::DirectTarget(target.into()),
        )];
        let mut context = PCodeAddressContext::new(source, &annotation);

        builder
            .push_lifted_operations(&[branch], &mut context)
            .unwrap();
        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert_eq!(ir.targets(), &[target.into()]);
        assert_eq!(ir.operations()[0].immediate(), 1);
    }

    #[test]
    fn verifier_rejects_copy_width_mismatch() {
        let mut builder = PCodeBuilder::new(language(), metadata(), IlGraph::default());
        let input = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                1,
                4,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(1),
                8,
                8,
                PCodeLocationProperties::empty(),
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

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::Il(IlError::WidthMismatch { .. }))
        ));
    }

    #[test]
    fn verifier_accepts_float_width_conversion() {
        let mut builder = PCodeBuilder::new(language(), metadata(), IlGraph::default());
        let input = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(1),
                0,
                10,
                PCodeLocationProperties::empty(),
            ))
            .unwrap();
        let output = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(1),
                16,
                8,
                PCodeLocationProperties::empty(),
            ))
            .unwrap();
        let operands = builder.push_operands([input]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::FloatToFloat,
            Some(output),
            operands,
            0,
            None,
        ));

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert!(ir.verify().is_ok());
    }

    #[test]
    fn verifier_rejects_missing_output() {
        let mut builder = PCodeBuilder::new(language(), metadata(), IlGraph::default());
        let input = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let operands = builder.push_operands([input]).unwrap();

        builder.push_operation(PCodeOp::new(PCodeOpcode::Copy, None, operands, 0, None));

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::Il(IlError::MissingComponent { .. }))
        ));
    }

    #[test]
    fn verifier_rejects_invalid_operand_count() {
        let mut builder = PCodeBuilder::new(language(), metadata(), IlGraph::default());
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
                PCodeLocationProperties::empty(),
            ))
            .unwrap();
        let operands = builder.push_operands([input]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::IntAdd,
            Some(output),
            operands,
            0,
            None,
        ));

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::InvalidOperandCount { .. })
        ));
    }
}
