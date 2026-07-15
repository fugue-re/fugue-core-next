use fugue_lifter::runtime::language::Language;
use fugue_lifter::{Op, PCodeOp};
use rustc_hash::FxHashMap;

use crate::il::common::{
    ArtefactHeader, BuildCancellation, CommonBody, Finish, IlError, IrArtefact, IrLevel,
    OperationId, PackedRange, Pool, RawIrArtefact, SchemaVersion, Verify,
};
use crate::il::pcode::format::{PCodeBodyDisplay, PCodeSourceDisplay};
use crate::il::pcode::{
    AddressAnnotationPayload, AddressAnnotationRole, Location, LocationId, Opcode, Operation,
    PCodeAddressContext, PCodeError,
};
use crate::ir::{
    Address, AddressRange, AddressRangeSet, Reference, ReferenceKind, ReferenceOrigin,
};
use crate::storage::segments::space::AddressSpaceId;

pub const PCODE_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1);

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct PCodeBody {
    header: ArtefactHeader,
    common: CommonBody,
    locations: Vec<Location>,
    operations: Vec<Operation>,
    operands: Vec<LocationId>,
    targets: Vec<Address>,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct PCodePayload {
    locations: Vec<Location>,
    operations: Vec<Operation>,
    operands: Vec<LocationId>,
    targets: Vec<Address>,
}

impl PCodePayload {
    fn new(
        locations: Vec<Location>,
        operations: Vec<Operation>,
        operands: Vec<LocationId>,
        targets: Vec<Address>,
    ) -> Self {
        Self {
            locations,
            operations,
            operands,
            targets,
        }
    }
}

impl PCodeBody {
    pub fn new(
        header: ArtefactHeader,
        common: CommonBody,
        locations: Vec<Location>,
        operations: Vec<Operation>,
        operands: Vec<LocationId>,
        targets: Vec<Address>,
    ) -> Self {
        Self {
            header,
            common,
            locations,
            operations,
            operands,
            targets,
        }
    }

    pub const fn header(&self) -> &ArtefactHeader {
        &self.header
    }

    pub const fn common(&self) -> &CommonBody {
        &self.common
    }

    pub fn locations(&self) -> &[Location] {
        &self.locations
    }

    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }

    pub fn operands(&self) -> &[LocationId] {
        &self.operands
    }

    pub fn targets(&self) -> &[Address] {
        &self.targets
    }

    pub fn target(&self, index: u32) -> Option<Address> {
        index
            .checked_sub(1)
            .and_then(|index| self.targets.get(index as usize))
            .copied()
    }

    pub fn location(&self, id: LocationId) -> Option<&Location> {
        self.locations.get(id.index())
    }

    pub fn operation_operands(&self, operation: &Operation) -> Result<&[LocationId], IlError> {
        operation.operands().checked_slice(&self.operands)
    }

    pub const fn display(&self) -> PCodeBodyDisplay<'_> {
        PCodeBodyDisplay::new(self)
    }

    pub const fn display_source(&self, machine_address: Address) -> PCodeSourceDisplay<'_> {
        PCodeSourceDisplay::new(self, machine_address)
    }

    pub fn operations_for_source(
        &self,
        machine_address: Address,
    ) -> impl Iterator<Item = (usize, &Operation)> + '_ {
        self.common
            .source_runs()
            .iter()
            .filter(move |run| run.machine_address() == machine_address)
            .flat_map(move |run| {
                let start = run.destination().start();
                run.destination()
                    .checked_slice(&self.operations)
                    .ok()
                    .into_iter()
                    .flat_map(move |operations| {
                        operations
                            .iter()
                            .enumerate()
                            .map(move |(index, operation)| (start + index, operation))
                    })
            })
    }

    pub fn data_references(&self) -> impl Iterator<Item = Reference> + '_ {
        self.operations
            .iter()
            .enumerate()
            .filter_map(move |(index, operation)| {
                let kind = match operation.opcode() {
                    Opcode::Load => ReferenceKind::read(),
                    Opcode::Store => ReferenceKind::write(),
                    _ => return None,
                };
                let from = self.common.source_for_destination(index as u32)?;
                let pointer = self.operation_operands(operation).ok()?.first().copied()?;
                let pointer = self.location(pointer)?;
                if !pointer.is_constant() {
                    return None;
                }
                let space = operation.effect_space()?;
                Some(
                    Reference::new(
                        from.machine_address(),
                        Address::new(space, pointer.offset()),
                        kind,
                    )
                    .with_origin(ReferenceOrigin::Derived),
                )
            })
    }

    pub fn shrink_to_fit(&mut self) {
        self.common.shrink_to_fit();
        self.locations.shrink_to_fit();
        self.operations.shrink_to_fit();
        self.operands.shrink_to_fit();
        self.targets.shrink_to_fit();
    }

    fn decode_payload(bytes: &[u8]) -> Result<PCodePayload, IlError> {
        rkyv::from_bytes::<PCodePayload, rkyv::rancor::Error>(bytes)
            .map_err(|_| IlError::artefact_decode(Self::LEVEL))
    }
}

impl Verify for PCodeBody {
    fn verify(&self) -> Result<(), IlError> {
        self.verify_header()?;
        self.common.verify()?;
        self.common.verify_node_bounds(self.operations.len())?;

        for operation in &self.operations {
            self.verify_operation(operation)?;
        }

        Ok(())
    }
}

impl PCodeBody {
    fn verify_operation(&self, operation: &Operation) -> Result<(), IlError> {
        operation.operands().verify_bounds(self.operands.len())?;

        if let Some(count) = operation.opcode().fixed_operand_count() {
            let found = operation.operands().len();

            if found != count {
                return Err(IlError::pcode_invalid_operand_count(count, found));
            }
        }

        let output = operation.output();

        if operation.opcode().requires_output() && output.is_none() {
            return Err(IlError::pcode_missing_output());
        }

        if operation.opcode().forbids_output() && output.is_some() {
            return Err(IlError::pcode_forbidden_output());
        }

        if let Some(output) = output {
            self.location(output).ok_or(IlError::range_out_of_bounds(
                output.value(),
                self.locations.len(),
            ))?;
        }

        for operand in self.operation_operands(operation)? {
            self.location(*operand).ok_or(IlError::range_out_of_bounds(
                operand.value(),
                self.locations.len(),
            ))?;
        }

        if matches!(
            operation.opcode(),
            Opcode::Load | Opcode::Store | Opcode::IBranch | Opcode::ICall | Opcode::Return
        ) && operation.effect_space().is_none()
        {
            return Err(IlError::pcode_missing_address_space());
        }

        if matches!(
            operation.opcode(),
            Opcode::Branch | Opcode::CBranch | Opcode::Call
        ) && operation.immediate() == 0
        {
            return Err(IlError::pcode_missing_address());
        }

        if matches!(
            operation.opcode(),
            Opcode::Branch | Opcode::CBranch | Opcode::Call
        ) && operation.immediate() as usize > self.targets.len()
        {
            return Err(IlError::range_out_of_bounds(
                operation.immediate(),
                self.targets.len(),
            ));
        }

        self.verify_operation_widths(operation)
    }

    fn verify_operation_widths(&self, operation: &Operation) -> Result<(), IlError> {
        let operands = self.operation_operands(operation)?;
        let output = operation.output().and_then(|output| self.location(output));

        if let Some(output) = output
            && operation.opcode().preserves_first_operand_width()
            && let Some(first) = operands.first().and_then(|operand| self.location(*operand))
            && output.width() != first.width()
        {
            return Err(IlError::pcode_width_mismatch());
        }

        if operation.opcode().compares_operands()
            && let [left, right] = operands
            && self.location(*left).map(Location::width)
                != self.location(*right).map(Location::width)
        {
            return Err(IlError::pcode_width_mismatch());
        }

        Ok(())
    }
}

impl IrArtefact for PCodeBody {
    const LEVEL: IrLevel = IrLevel::PCode;
    const SCHEMA: SchemaVersion = PCODE_SCHEMA_VERSION;

    fn header(&self) -> &ArtefactHeader {
        &self.header
    }

    fn header_mut(&mut self) -> &mut ArtefactHeader {
        &mut self.header
    }

    fn common(&self) -> &CommonBody {
        &self.common
    }

    fn collect_reference_coverage(&self, coverage: &mut AddressRangeSet) {
        for run in self.common.source_runs() {
            coverage.insert_range(AddressRange::point(run.machine_address()));
        }
    }

    fn collect_derived_references(&self, references: &mut Vec<Reference>) {
        references.extend(self.data_references());
    }

    fn to_raw_artefact(&self) -> Result<RawIrArtefact, IlError> {
        self.verify()?;

        let payload = PCodePayload::new(
            self.locations.clone(),
            self.operations.clone(),
            self.operands.clone(),
            self.targets.clone(),
        );
        let payload = rkyv::to_bytes::<rkyv::rancor::Error>(&payload)
            .map(|bytes| bytes.to_vec())
            .map_err(|_| IlError::artefact_encode(Self::LEVEL))?;

        Ok(RawIrArtefact::new(
            self.header,
            self.common.clone(),
            payload,
        ))
    }

    fn from_raw_artefact(artefact: RawIrArtefact) -> Result<Self, IlError> {
        artefact.verify()?;
        artefact.header().verify_schema(Self::LEVEL, Self::SCHEMA)?;

        let payload = Self::decode_payload(artefact.payload())?;
        let body = Self::new(
            *artefact.header(),
            artefact.body().clone(),
            payload.locations,
            payload.operations,
            payload.operands,
            payload.targets,
        );

        body.verify()?;

        Ok(body)
    }

    fn verify_raw_artefact(artefact: &RawIrArtefact) -> Result<(), IlError> {
        artefact.verify()?;
        artefact.header().verify_schema(Self::LEVEL, Self::SCHEMA)?;

        let payload = Self::decode_payload(artefact.payload())?;
        let body = Self::new(
            *artefact.header(),
            artefact.body().clone(),
            payload.locations,
            payload.operations,
            payload.operands,
            payload.targets,
        );

        body.verify()
    }
}

#[derive(Debug)]
pub struct PCodeBuilder {
    header: ArtefactHeader,
    common: CommonBody,
    locations: Vec<Location>,
    location_ids: FxHashMap<Location, LocationId>,
    operations: Vec<Operation>,
    operands: Pool<LocationId>,
    targets: Vec<Address>,
}

impl PCodeBuilder {
    pub fn new(header: ArtefactHeader, common: CommonBody) -> Self {
        Self {
            header,
            common,
            locations: Vec::new(),
            location_ids: FxHashMap::default(),
            operations: Vec::new(),
            operands: Pool::new(),
            targets: Vec::new(),
        }
    }

    pub fn push_location(&mut self, location: Location) -> Result<LocationId, IlError> {
        if let Some(id) = self.location_ids.get(&location).copied() {
            return Ok(id);
        }

        let id = LocationId::try_from_index(self.locations.len())?;
        self.locations.push(location);
        self.location_ids.insert(location, id);
        Ok(id)
    }

    pub fn push_operands(
        &mut self,
        operands: impl IntoIterator<Item = LocationId>,
    ) -> Result<PackedRange, IlError> {
        self.operands.append(operands)
    }

    pub fn push_operation(&mut self, operation: Operation) {
        self.operations.push(operation);
    }

    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }

    pub fn replace_common(&mut self, common: CommonBody) {
        self.common = common;
    }

    pub fn push_target(&mut self, target: Address) -> Result<u32, IlError> {
        let index = self.targets.len();
        self.targets.push(target);
        u32::try_from(index + 1).map_err(|_| IlError::id_exhausted("PCode target"))
    }

    pub fn push_lifter_stream(
        &mut self,
        operations: &[PCodeOp],
        language: &'static Language,
        context: &mut PCodeAddressContext<'_>,
    ) -> Result<(), PCodeError> {
        self.push_lifter_stream_at(operations, language, context, 0)
    }

    pub fn push_lifter_stream_next(
        &mut self,
        operations: &[PCodeOp],
        language: &'static Language,
        context: &mut PCodeAddressContext<'_>,
    ) -> Result<(), PCodeError> {
        self.push_lifter_stream_at(operations, language, context, self.operation_count())
    }

    fn push_lifter_stream_at(
        &mut self,
        operations: &[PCodeOp],
        language: &'static Language,
        context: &mut PCodeAddressContext<'_>,
        starting_ordinal: usize,
    ) -> Result<(), PCodeError> {
        let mut ordinal = starting_ordinal;
        let mut index = 0usize;

        while let Some(operation) = operations.get(index) {
            if operation.is_arg() {
                return Err(PCodeError::misplaced_arg(ordinal as u32));
            }

            let operation_id = OperationId::try_from_index(ordinal)?;
            let opcode = Opcode::try_from(operation.op())
                .map_err(|()| PCodeError::invalid_opcode(ordinal as u32))?;
            let mut inputs = Vec::new();
            inputs.extend(operation.inputs().iter().copied());

            if let Op::UserOp(_, arity) = operation.op() {
                let spill = operation.spill();

                for spill_index in 0..spill {
                    let Some(arg) = operations.get(index + spill_index + 1) else {
                        return Err(PCodeError::missing_arg(
                            ordinal as u32,
                            (spill - spill_index) as u8,
                        ));
                    };

                    if !arg.is_arg() {
                        return Err(PCodeError::missing_arg(
                            ordinal as u32,
                            (spill - spill_index) as u8,
                        ));
                    }

                    inputs.extend(arg.inputs().iter().copied());
                }

                inputs.truncate(arity as usize);

                if inputs.len() != arity as usize {
                    return Err(PCodeError::invalid_argument_count(
                        ordinal as u32,
                        arity,
                        inputs.len() as u8,
                    ));
                }

                index += spill;
            }

            let operands = inputs
                .into_iter()
                .map(|input| self.push_location(Location::from_varnode(&input, language)))
                .collect::<Result<Vec<_>, _>>()?;
            let operands = self.push_operands(operands)?;
            let output = operation
                .output()
                .map(|output| Location::from_varnode(output, language))
                .map(|location| self.push_location(location))
                .transpose()?;
            let effect_space = self.effect_space_for(operation, operation_id, context)?;
            let immediate = self.immediate_for(operation, operation_id, context)?;

            self.push_operation(Operation::new(
                opcode,
                output,
                operands,
                immediate,
                effect_space,
            ));

            ordinal += 1;
            index += 1;
        }

        context.finish()?;

        Ok(())
    }

    fn effect_space_for(
        &self,
        operation: &PCodeOp,
        ordinal: OperationId,
        context: &mut PCodeAddressContext<'_>,
    ) -> Result<Option<AddressSpaceId>, PCodeError> {
        match operation.op() {
            Op::Load(_) | Op::Store(_) | Op::IBranch | Op::ICall | Op::Return => {
                match context.take(ordinal, AddressAnnotationRole::ComputedSpace)? {
                    AddressAnnotationPayload::ComputedSpace(space) => Ok(Some(space)),
                    _ => unreachable!(),
                }
            }
            _ => Ok(None),
        }
    }

    fn immediate_for(
        &mut self,
        operation: &PCodeOp,
        ordinal: OperationId,
        context: &mut PCodeAddressContext<'_>,
    ) -> Result<u32, PCodeError> {
        match operation.op() {
            Op::Load(space) | Op::Store(space) => Ok(u32::from(space)),
            Op::UserOp(user_op, _) => Ok(u32::from(user_op)),
            Op::Branch | Op::CBranch | Op::Call => {
                match context.take(ordinal, AddressAnnotationRole::DirectTarget)? {
                    AddressAnnotationPayload::DirectTarget(target) => {
                        self.push_target(target).map_err(PCodeError::from)
                    }
                    _ => unreachable!(),
                }
            }
            _ => Ok(0),
        }
    }
}

impl Finish for PCodeBuilder {
    type Output = PCodeBody;

    fn finish(self, status: &(impl BuildCancellation + ?Sized)) -> Result<Self::Output, IlError> {
        if status.is_cancelled() {
            return Err(IlError::cancelled());
        }

        let mut body = PCodeBody::new(
            self.header,
            self.common,
            self.locations,
            self.operations,
            self.operands.into_values(),
            self.targets,
        );

        body.shrink_to_fit();
        body.verify()?;

        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use fugue_lifter::runtime::pcode::Inputs;
    use fugue_lifter::{Op, PCodeOp, Varnode};

    use super::*;
    use crate::il::common::{Block, BuildStatus, IrLevel, OperationId, SourceRun};
    use crate::il::pcode::{
        AddressAnnotation, AddressAnnotationPayload, LifterSpaceHandle, PCodeAddressContext,
    };
    use crate::ir::FunctionId;
    use crate::lifter::resolve_language;
    use crate::storage::segments::space::AddressSpaceId;

    fn pcode_op(op: Op, inputs: Inputs, output: Varnode) -> PCodeOp {
        PCodeOp { op, inputs, output }
    }

    fn language() -> &'static Language {
        resolve_language("x86:LE:64").expect("test language should resolve")
    }

    #[test]
    fn pcode_builder_finishes_verified_body() {
        assert!(std::mem::size_of::<Operation>() <= 24);
        assert!(std::mem::size_of::<Location>() <= 16);

        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            0,
        );
        let mut builder = PCodeBuilder::new(header, CommonBody::default());
        let location = builder
            .push_location(Location::new(
                LifterSpaceHandle::new(0),
                1,
                8,
                Location::CONSTANT,
            ))
            .unwrap();
        let operands = builder.push_operands([location]).unwrap();

        builder.push_operation(Operation::new(
            Opcode::Copy,
            Some(location),
            operands,
            0,
            None,
        ));

        let body = builder.finish(&BuildStatus::new()).unwrap();
        let raw = body.to_raw_artefact().unwrap();

        assert_eq!(body.operations().len(), 1);
        assert_eq!(body.locations().len(), 1);
        assert!(raw.verify_as::<PCodeBody>().is_ok());
    }

    #[test]
    fn pcode_builder_finish_shrinks_spare_capacity() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            0,
        );
        let mut builder = PCodeBuilder::new(header, CommonBody::default());

        builder.locations.reserve(16);
        builder.operations.reserve(16);
        builder.targets.reserve(16);

        let body = builder.finish(&BuildStatus::new()).unwrap();

        assert_eq!(body.locations.len(), body.locations.capacity());
        assert_eq!(body.operations.len(), body.operations.capacity());
        assert_eq!(body.targets.len(), body.targets.capacity());
    }

    #[test]
    fn pcode_body_derives_constant_data_references() {
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let data_space = AddressSpaceId::new(2);
        let data = 0x4000u64;
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            0,
        );
        let common = CommonBody::new(
            Vec::new(),
            Vec::new(),
            vec![SourceRun::new(
                PackedRange::new(0, 2).unwrap(),
                source,
                0,
                2,
            )],
            Vec::new(),
        );
        let mut builder = PCodeBuilder::new(header, common);
        let pointer = builder
            .push_location(Location::new(
                LifterSpaceHandle::new(0),
                data,
                8,
                Location::CONSTANT,
            ))
            .unwrap();
        let value = builder
            .push_location(Location::new(LifterSpaceHandle::new(1), 0, 8, 0))
            .unwrap();
        let load_operands = builder.push_operands([pointer]).unwrap();
        let store_operands = builder.push_operands([pointer, value]).unwrap();

        builder.push_operation(Operation::new(
            Opcode::Load,
            Some(value),
            load_operands,
            0,
            Some(data_space),
        ));
        builder.push_operation(Operation::new(
            Opcode::Store,
            None,
            store_operands,
            0,
            Some(data_space),
        ));

        let body = builder.finish(&BuildStatus::new()).unwrap();
        let references = body.data_references().collect::<Vec<_>>();

        assert_eq!(references.len(), 2);
        assert!(references[0].kind().is_read());
        assert_eq!(references[0].from(), source);
        assert_eq!(
            references[0].target().address(),
            Some(Address::new(data_space, data))
        );
        assert!(references[0].origin().is_derived());
        assert!(references[1].kind().is_write());
        assert_eq!(
            references[1].target().address(),
            Some(Address::new(data_space, data))
        );
    }

    #[test]
    fn pcode_body_ignores_non_constant_data_references() {
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let data_space = AddressSpaceId::new(2);
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            0,
        );
        let common = CommonBody::new(
            Vec::new(),
            Vec::new(),
            vec![SourceRun::new(
                PackedRange::new(0, 1).unwrap(),
                source,
                0,
                1,
            )],
            Vec::new(),
        );
        let mut builder = PCodeBuilder::new(header, common);
        let pointer = builder
            .push_location(Location::new(LifterSpaceHandle::new(1), 0x20, 8, 0))
            .unwrap();
        let output = builder
            .push_location(Location::new(LifterSpaceHandle::new(1), 0, 8, 0))
            .unwrap();
        let operands = builder.push_operands([pointer]).unwrap();

        builder.push_operation(Operation::new(
            Opcode::Load,
            Some(output),
            operands,
            0,
            Some(data_space),
        ));

        let body = builder.finish(&BuildStatus::new()).unwrap();

        assert!(body.data_references().next().is_none());
    }

    #[test]
    fn pcode_verifier_rejects_out_of_range_source_run() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            0,
        );
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let common = CommonBody::new(
            Vec::new(),
            Vec::new(),
            vec![SourceRun::new(
                PackedRange::new(0, 1).unwrap(),
                source,
                0,
                1,
            )],
            Vec::new(),
        );
        let body = PCodeBody::new(
            header,
            common,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        assert!(matches!(
            body.verify(),
            Err(IlError::RangeOutOfBounds { .. })
        ));
    }

    #[test]
    fn pcode_verifier_rejects_out_of_range_block_operations() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            0,
        );
        let common = CommonBody::new(
            vec![Block::new(
                PackedRange::new(0, 1).unwrap(),
                PackedRange::EMPTY,
                0,
            )],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let body = PCodeBody::new(
            header,
            common,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        assert!(matches!(
            body.verify(),
            Err(IlError::RangeOutOfBounds { .. })
        ));
    }

    #[test]
    fn lifter_stream_interns_repeated_locations() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            0,
        );
        let language = language();
        let mut builder = PCodeBuilder::new(header, CommonBody::default());
        let varnode = Varnode::new(language.register_space(), 8, 8);
        let operation = pcode_op(Op::Copy, Inputs::one(varnode), varnode);
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let mut context = PCodeAddressContext::new(source, &[]);

        builder
            .push_lifter_stream(&[operation], language, &mut context)
            .unwrap();
        let body = builder.finish(&BuildStatus::new()).unwrap();

        assert_eq!(body.locations().len(), 1);
        assert_eq!(body.operands().len(), 1);
    }

    #[test]
    fn lifter_stream_classifies_locations_from_language_spaces() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            0,
        );
        let language = language();
        let mut builder = PCodeBuilder::new(header, CommonBody::default());
        let constant = Varnode::constant(7, 8);
        let register = Varnode::new(language.register_space(), 8, 8);
        let unique = Varnode::new(language.unique_space(), 16, 8);
        let first = pcode_op(Op::Copy, Inputs::one(constant), register);
        let second = pcode_op(Op::Copy, Inputs::one(register), unique);
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let mut context = PCodeAddressContext::new(source, &[]);

        builder
            .push_lifter_stream(&[first, second], language, &mut context)
            .unwrap();
        let body = builder.finish(&BuildStatus::new()).unwrap();

        assert!(body.locations().iter().any(Location::is_constant));
        assert!(body.locations().iter().any(Location::is_register));
        assert!(body.locations().iter().any(Location::is_unique));
    }

    #[test]
    fn lifter_stream_folds_user_op_args() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            0,
        );
        let language = language();
        let mut builder = PCodeBuilder::new(header, CommonBody::default());
        let first = Varnode::new(language.register_space(), 8, 8);
        let second = Varnode::new(language.register_space(), 16, 8);
        let third = Varnode::new(language.register_space(), 24, 8);
        let output = Varnode::new(language.unique_space(), 32, 8);
        let user_op = pcode_op(Op::UserOp(7, 3), Inputs::two(first, second), output);
        let arg = pcode_op(Op::Arg, Inputs::one(third), Varnode::INVALID);
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let mut context = PCodeAddressContext::new(source, &[]);

        builder
            .push_lifter_stream(&[user_op, arg], language, &mut context)
            .unwrap();
        let body = builder.finish(&BuildStatus::new()).unwrap();

        assert_eq!(body.operations().len(), 1);
        assert_eq!(body.operands().len(), 3);
        assert_eq!(body.operations()[0].immediate(), 7);
    }

    #[test]
    fn lifter_stream_requires_computed_space_annotation() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            0,
        );
        let language = language();
        let mut builder = PCodeBuilder::new(header, CommonBody::default());
        let offset = Varnode::new(language.register_space(), 8, 8);
        let output = Varnode::new(language.unique_space(), 16, 8);
        let load = pcode_op(
            Op::Load(language.default_space()),
            Inputs::one(offset),
            output,
        );
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let annotation = [AddressAnnotation::new(
            OperationId::try_from_index(0).unwrap(),
            AddressAnnotationPayload::ComputedSpace(AddressSpaceId::new(9)),
        )];
        let mut context = PCodeAddressContext::new(source, &annotation);

        builder
            .push_lifter_stream(&[load], language, &mut context)
            .unwrap();
        let body = builder.finish(&BuildStatus::new()).unwrap();

        assert_eq!(
            body.operations()[0].effect_space(),
            Some(AddressSpaceId::new(9))
        );
        assert_eq!(
            body.operations()[0].immediate(),
            language.default_space() as u32
        );
    }

    #[test]
    fn lifter_stream_records_direct_target_annotation() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            0,
        );
        let language = language();
        let mut builder = PCodeBuilder::new(header, CommonBody::default());
        let target_varnode = Varnode::constant(0x2000, 8);
        let branch = pcode_op(Op::Branch, Inputs::one(target_varnode), Varnode::INVALID);
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target = Address::new(AddressSpaceId::new(2), 0x2000u64);
        let annotation = [AddressAnnotation::new(
            OperationId::try_from_index(0).unwrap(),
            AddressAnnotationPayload::DirectTarget(target),
        )];
        let mut context = PCodeAddressContext::new(source, &annotation);

        builder
            .push_lifter_stream(&[branch], language, &mut context)
            .unwrap();
        let body = builder.finish(&BuildStatus::new()).unwrap();

        assert_eq!(body.targets(), &[target]);
        assert_eq!(body.operations()[0].immediate(), 1);
    }

    #[test]
    fn verifier_rejects_copy_width_mismatch() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            0,
        );
        let mut builder = PCodeBuilder::new(header, CommonBody::default());
        let input = builder
            .push_location(Location::new(
                LifterSpaceHandle::new(0),
                1,
                4,
                Location::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .push_location(Location::new(LifterSpaceHandle::new(1), 8, 8, 0))
            .unwrap();
        let operands = builder.push_operands([input]).unwrap();

        builder.push_operation(Operation::new(
            Opcode::Copy,
            Some(output),
            operands,
            0,
            None,
        ));

        assert!(matches!(
            builder.finish(&BuildStatus::new()),
            Err(IlError::WidthMismatch { .. })
        ));
    }

    #[test]
    fn verifier_rejects_missing_output() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            0,
        );
        let mut builder = PCodeBuilder::new(header, CommonBody::default());
        let input = builder
            .push_location(Location::new(
                LifterSpaceHandle::new(0),
                1,
                8,
                Location::CONSTANT,
            ))
            .unwrap();
        let operands = builder.push_operands([input]).unwrap();

        builder.push_operation(Operation::new(Opcode::Copy, None, operands, 0, None));

        assert!(matches!(
            builder.finish(&BuildStatus::new()),
            Err(IlError::MissingOutput { .. })
        ));
    }

    #[test]
    fn verifier_rejects_invalid_operand_count() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            0,
        );
        let mut builder = PCodeBuilder::new(header, CommonBody::default());
        let input = builder
            .push_location(Location::new(
                LifterSpaceHandle::new(0),
                1,
                8,
                Location::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .push_location(Location::new(LifterSpaceHandle::new(1), 8, 8, 0))
            .unwrap();
        let operands = builder.push_operands([input]).unwrap();

        builder.push_operation(Operation::new(
            Opcode::IntAdd,
            Some(output),
            operands,
            0,
            None,
        ));

        assert!(matches!(
            builder.finish(&BuildStatus::new()),
            Err(IlError::InvalidOperandCount { .. })
        ));
    }
}
