use fugue_lifter::runtime::language::Language;
use fugue_lifter::{Op, PCodeOp as RawPCodeOp};
use rustc_hash::FxHashMap;

use crate::analysis::control::CancellationToken;
use crate::il::common::verify::{
    VerifyError, verify_bounds, verify_graph, verify_graph_bounds, verify_source_spans,
};
use crate::il::common::{
    IlArtefact, IlError, IlGraph, IlHeader, IlIndexRange, IlLevel, IlOpId, IlPool, IlSchemaVersion,
    IlSourceSpan,
};
use crate::il::pcode::format::{PCodeIrDisplay, PCodeSourceDisplay};
use crate::il::pcode::{
    AddressAnnotationRole, AddressAnnotationValue, PCodeAddressContext, PCodeError, PCodeLocation,
    PCodeLocationId, PCodeOp, PCodeOpcode,
};
use crate::ir::{
    Address, AddressRange, AddressRangeSet, FunctionId, Location, Reference, ReferenceOrigin,
    ReferenceProperties,
};
use crate::storage::entities::schema::ENTITY_IL_PCODE_ID;
use crate::storage::entities::{Entity, EntityId, MutableEntity};
use crate::storage::segments::space::AddressSpaceId;

pub const PCODE_SCHEMA_VERSION: IlSchemaVersion = IlSchemaVersion::new(2);

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct PCodeIr {
    header: IlHeader,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    locations: Vec<PCodeLocation>,
    operations: Vec<PCodeOp>,
    operands: Vec<PCodeLocationId>,
    targets: Vec<Location>,
}

impl PCodeIr {
    pub(crate) fn new(
        header: IlHeader,
        graph: IlGraph,
        source_spans: Vec<IlSourceSpan>,
        locations: Vec<PCodeLocation>,
        operations: Vec<PCodeOp>,
        operands: Vec<PCodeLocationId>,
        targets: Vec<Location>,
    ) -> Self {
        Self {
            header,
            graph,
            source_spans,
            locations,
            operations,
            operands,
            targets,
        }
    }

    pub const fn header(&self) -> &IlHeader {
        &self.header
    }

    pub const fn graph(&self) -> &IlGraph {
        &self.graph
    }

    pub fn source_spans(&self) -> &[IlSourceSpan] {
        &self.source_spans
    }

    pub fn source_span_for(&self, node: u32) -> Option<IlSourceSpan> {
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

    pub fn operands(&self) -> &[PCodeLocationId] {
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

    pub fn operation_operands(&self, operation: &PCodeOp) -> &[PCodeLocationId] {
        operation.operands().slice(&self.operands)
    }

    pub const fn display(&self) -> PCodeIrDisplay<'_> {
        PCodeIrDisplay::new(self)
    }

    pub const fn display_source(&self, address: Address) -> PCodeSourceDisplay<'_> {
        PCodeSourceDisplay::new(self, address)
    }

    pub fn operations_for_source(
        &self,
        address: Address,
    ) -> impl Iterator<Item = (usize, &PCodeOp)> + '_ {
        self.source_spans
            .iter()
            .filter(move |span| span.address() == address)
            .flat_map(move |span| {
                let start = span.destination().start();
                span.destination()
                    .slice(&self.operations)
                    .iter()
                    .enumerate()
                    .map(move |(index, operation)| (start + index, operation))
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
                let from = self.source_span_for(index as u32)?;
                let pointer = self.operation_operands(operation).first().copied()?;
                let pointer = self.location(pointer)?;
                if !pointer.is_constant() {
                    return None;
                }
                let space = operation.effect_space()?;
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
        self.header.function()
    }
}

impl IlArtefact for PCodeIr {
    const LEVEL: IlLevel = IlLevel::PCode;
    const SCHEMA: IlSchemaVersion = PCODE_SCHEMA_VERSION;

    fn header(&self) -> &IlHeader {
        &self.header
    }

    fn header_mut(&mut self) -> &mut IlHeader {
        &mut self.header
    }

    fn graph(&self) -> &IlGraph {
        &self.graph
    }
}

#[derive(Debug)]
pub(crate) struct PCodeBuilder {
    language: &'static Language,
    header: IlHeader,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    locations: Vec<PCodeLocation>,
    location_ids: FxHashMap<PCodeLocation, PCodeLocationId>,
    operations: Vec<PCodeOp>,
    operands: IlPool<PCodeLocationId>,
    targets: Vec<Location>,
}

impl PCodeBuilder {
    pub(crate) fn new(language: &'static Language, header: IlHeader, graph: IlGraph) -> Self {
        Self {
            language,
            header,
            graph,
            source_spans: Vec::new(),
            locations: Vec::new(),
            location_ids: FxHashMap::default(),
            operations: Vec::new(),
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

    pub(crate) fn replace_graph(&mut self, graph: IlGraph) {
        self.graph = graph;
    }

    pub(crate) fn replace_source_spans(&mut self, source_spans: Vec<IlSourceSpan>) {
        self.source_spans = source_spans;
    }

    pub(crate) fn push_target(&mut self, target: Location) -> Result<u32, IlError> {
        let index = self.targets.len();
        self.targets.push(target);
        u32::try_from(index + 1).map_err(|_| IlError::id_exhausted("PCode target"))
    }

    /// Canonicalises the operations the lifter emitted for one instruction, appending them
    /// after whatever has already been built.
    pub(crate) fn push_lifted_operations(
        &mut self,
        operations: &[RawPCodeOp],
        context: &mut PCodeAddressContext<'_>,
    ) -> Result<(), PCodeError> {
        let language = self.language;
        let mut ordinal = self.operation_count();
        let mut index = 0usize;

        while let Some(operation) = operations.get(index) {
            if operation.is_arg() {
                return Err(PCodeError::misplaced_arg(ordinal as u32));
            }

            let operation_id = IlOpId::try_from_index(ordinal)?;
            let opcode = PCodeOpcode::try_from(operation.op())
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
                .map(|input| self.push_location(PCodeLocation::from_varnode(language, &input)))
                .collect::<Result<Vec<_>, _>>()?;
            let operands = self.push_operands(operands)?;
            let output = operation
                .output()
                .map(|output| PCodeLocation::from_varnode(language, output))
                .map(|location| self.push_location(location))
                .transpose()?;
            let effect_space = self.effect_space_for(operation, operation_id, context)?;
            let immediate = self.immediate_for(operation, operation_id, context)?;

            self.push_operation(PCodeOp::new(
                opcode,
                output,
                operands,
                immediate,
                effect_space,
            ));

            ordinal += 1;
            index += 1;
        }

        context.ensure_consumed()?;

        Ok(())
    }

    fn effect_space_for(
        &self,
        operation: &RawPCodeOp,
        ordinal: IlOpId,
        context: &mut PCodeAddressContext<'_>,
    ) -> Result<Option<AddressSpaceId>, PCodeError> {
        match operation.op() {
            Op::Load(_) | Op::Store(_) | Op::IBranch | Op::ICall | Op::Return => {
                match context.take(ordinal, AddressAnnotationRole::ComputedSpace)? {
                    AddressAnnotationValue::ComputedSpace(space) => Ok(Some(space)),
                    _ => unreachable!(),
                }
            }
            _ => Ok(None),
        }
    }

    fn immediate_for(
        &mut self,
        operation: &RawPCodeOp,
        ordinal: IlOpId,
        context: &mut PCodeAddressContext<'_>,
    ) -> Result<u32, PCodeError> {
        match operation.op() {
            Op::Load(space) | Op::Store(space) => Ok(u32::from(space)),
            Op::UserOp(user_op, _) => Ok(u32::from(user_op)),
            Op::Branch | Op::CBranch | Op::Call => {
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
            self.header,
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

pub(crate) fn verify(ir: &PCodeIr) -> Result<(), VerifyError> {
    if ir.header().schema() != PCodeIr::SCHEMA {
        return Err(IlError::schema_mismatch(
            PCodeIr::LEVEL,
            PCodeIr::SCHEMA.value(),
            ir.header().schema().value(),
        )
        .into());
    }

    verify_graph(ir.graph())?;
    verify_graph_bounds(ir.graph(), ir.operations().len())?;
    verify_source_spans(ir.source_spans(), ir.operations().len())?;

    for operation in ir.operations() {
        verify_operation(ir, operation)?;
    }

    Ok(())
}

fn verify_operation(ir: &PCodeIr, operation: &PCodeOp) -> Result<(), VerifyError> {
    verify_bounds(operation.operands(), ir.operands().len())?;

    if let Some(count) = operation.opcode().fixed_operand_count() {
        let found = operation.operands().len();

        if found != count {
            return Err(VerifyError::InvalidOperandCount {
                level: PCodeIr::LEVEL,
                expected: count,
                found,
            });
        }
    }

    let output = operation.output();

    if operation.opcode().requires_output() && output.is_none() {
        return Err(IlError::missing_component(PCodeIr::LEVEL, "output").into());
    }

    if operation.opcode().forbids_output() && output.is_some() {
        return Err(VerifyError::ForbiddenOutput {
            level: PCodeIr::LEVEL,
        });
    }

    if let Some(output) = output {
        ir.location(output).ok_or(IlError::range_out_of_bounds(
            output.value(),
            ir.locations().len(),
        ))?;
    }

    for operand in ir.operation_operands(operation) {
        ir.location(*operand).ok_or(IlError::range_out_of_bounds(
            operand.value(),
            ir.locations().len(),
        ))?;
    }

    if matches!(
        operation.opcode(),
        PCodeOpcode::Load
            | PCodeOpcode::Store
            | PCodeOpcode::IBranch
            | PCodeOpcode::ICall
            | PCodeOpcode::Return
    ) && operation.effect_space().is_none()
    {
        return Err(IlError::missing_component(PCodeIr::LEVEL, "address space").into());
    }

    if matches!(
        operation.opcode(),
        PCodeOpcode::Branch | PCodeOpcode::CBranch | PCodeOpcode::Call
    ) && operation.immediate() == 0
    {
        return Err(IlError::missing_component(PCodeIr::LEVEL, "address").into());
    }

    if matches!(
        operation.opcode(),
        PCodeOpcode::Branch | PCodeOpcode::CBranch | PCodeOpcode::Call
    ) && operation.immediate() as usize > ir.targets().len()
    {
        return Err(IlError::range_out_of_bounds(operation.immediate(), ir.targets().len()).into());
    }

    verify_operation_widths(ir, operation)
}

fn verify_operation_widths(ir: &PCodeIr, operation: &PCodeOp) -> Result<(), VerifyError> {
    let operands = ir.operation_operands(operation);
    let output = operation.output().and_then(|output| ir.location(output));

    if let Some(output) = output
        && operation.opcode().preserves_first_operand_width()
        && let Some(first) = operands.first().and_then(|operand| ir.location(*operand))
        && output.width() != first.width()
    {
        return Err(IlError::width_mismatch(PCodeIr::LEVEL).into());
    }

    if operation.opcode().compares_operands()
        && let [left, right] = operands
        && ir.location(*left).map(PCodeLocation::width)
            != ir.location(*right).map(PCodeLocation::width)
    {
        return Err(IlError::width_mismatch(PCodeIr::LEVEL).into());
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use fugue_lifter::runtime::pcode::Inputs;
    use fugue_lifter::{Op, Varnode};

    use super::*;
    use crate::il::common::verify::VerifyError;
    use crate::il::common::{IlBlock, IlBlockProperties, IlSourceSpan};
    use crate::il::pcode::{
        AddressAnnotation, AddressAnnotationValue, LifterSpaceHandle, PCodeAddressContext,
        PCodeLocationProperties,
    };
    use crate::storage::segments::space::AddressSpaceId;

    fn pcode_op(op: Op, inputs: Inputs, output: Varnode) -> RawPCodeOp {
        RawPCodeOp { op, inputs, output }
    }

    fn language() -> &'static Language {
        crate::lifter::resolve_language("x86:LE:64").expect("test language should resolve")
    }

    fn header() -> IlHeader {
        IlHeader::new(FunctionId::default(), PCODE_SCHEMA_VERSION, 0)
    }

    #[test]
    fn pcode_builder_finishes_verified_ir() {
        assert!(std::mem::size_of::<PCodeOp>() <= 24);
        assert!(std::mem::size_of::<PCodeLocation>() <= 16);

        let mut builder = PCodeBuilder::new(language(), header(), IlGraph::default());
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

        assert!(verify(&ir).is_ok());
        assert_eq!(ir.operations().len(), 1);
        assert_eq!(ir.locations().len(), 1);
    }

    #[test]
    fn pcode_builder_finish_shrinks_spare_capacity() {
        let mut builder = PCodeBuilder::new(language(), header(), IlGraph::default());

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
        let mut builder = PCodeBuilder::new(language(), header(), IlGraph::default());
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
        let mut builder = PCodeBuilder::new(language(), header(), IlGraph::default());

        builder.replace_source_spans(vec![IlSourceSpan::new(
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
        let mut builder = PCodeBuilder::new(language(), header(), IlGraph::default());

        builder.replace_source_spans(vec![IlSourceSpan::new(
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
            header(),
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
            verify(&ir),
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
            header(),
            graph,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        assert!(matches!(
            verify(&ir),
            Err(VerifyError::Il(IlError::RangeOutOfBounds { .. }))
        ));
    }

    #[test]
    fn lifter_stream_interns_repeated_locations() {
        let language = language();
        let mut builder = PCodeBuilder::new(language, header(), IlGraph::default());
        let varnode = Varnode::new(language.register_space(), 8, 8);
        let operation = pcode_op(Op::Copy, Inputs::one(varnode), varnode);
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let mut context = PCodeAddressContext::new(source, &[]);

        builder
            .push_lifted_operations(&[operation], &mut context)
            .unwrap();
        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert_eq!(ir.locations().len(), 1);
        assert_eq!(ir.operands().len(), 1);
    }

    #[test]
    fn lifter_stream_classifies_locations_from_language_spaces() {
        let language = language();
        let mut builder = PCodeBuilder::new(language, header(), IlGraph::default());
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
        let mut builder = PCodeBuilder::new(language, header(), IlGraph::default());
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
        assert_eq!(ir.operands().len(), 3);
        assert_eq!(ir.operations()[0].immediate(), 7);
    }

    #[test]
    fn lifter_stream_requires_computed_space_annotation() {
        let language = language();
        let mut builder = PCodeBuilder::new(language, header(), IlGraph::default());
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
            ir.operations()[0].effect_space(),
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
        let mut builder = PCodeBuilder::new(language, header(), IlGraph::default());
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
        let mut builder = PCodeBuilder::new(language(), header(), IlGraph::default());
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
            verify(&ir),
            Err(VerifyError::Il(IlError::WidthMismatch { .. }))
        ));
    }

    #[test]
    fn verifier_accepts_float_width_conversion() {
        let mut builder = PCodeBuilder::new(language(), header(), IlGraph::default());
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

        assert!(verify(&ir).is_ok());
    }

    #[test]
    fn verifier_rejects_missing_output() {
        let mut builder = PCodeBuilder::new(language(), header(), IlGraph::default());
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
            verify(&ir),
            Err(VerifyError::Il(IlError::MissingComponent { .. }))
        ));
    }

    #[test]
    fn verifier_rejects_invalid_operand_count() {
        let mut builder = PCodeBuilder::new(language(), header(), IlGraph::default());
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
            verify(&ir),
            Err(VerifyError::InvalidOperandCount { .. })
        ));
    }
}
