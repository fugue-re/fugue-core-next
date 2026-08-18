use rustc_hash::FxHashMap;

use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlError, IlGraph, IlIndexRange, IlMetadata, IlOpId, IlPool, IlSourceSpan,
};
use crate::il::pcode::{
    PCodeIr, PCodeLocation, PCodeLocationId, PCodeOp, PCodeOpSpec, PCodeTargetId,
};
use crate::ir::Location;

#[derive(Debug)]
pub struct PCodeBuilder {
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    locations: Vec<PCodeLocation>,
    location_ids: FxHashMap<PCodeLocation, PCodeLocationId>,
    operations: Vec<PCodeOp>,
    operands: IlPool<PCodeLocationId>,
    targets: Vec<Location>,
}

impl PCodeBuilder {
    pub fn new(metadata: IlMetadata, graph: IlGraph) -> Self {
        Self {
            metadata,
            graph,
            source_spans: Vec::new(),
            locations: Vec::new(),
            location_ids: FxHashMap::default(),
            operations: Vec::new(),
            operands: IlPool::new(),
            targets: Vec::new(),
        }
    }

    pub fn emitter(&mut self) -> PCodeEmitter<'_> {
        PCodeEmitter { builder: self }
    }

    fn intern_location(&mut self, location: PCodeLocation) -> Result<PCodeLocationId, IlError> {
        if let Some(id) = self.location_ids.get(&location).copied() {
            return Ok(id);
        }

        let id = PCodeLocationId::try_from_index(self.locations.len())?;
        self.locations.push(location);
        self.location_ids.insert(location, id);
        Ok(id)
    }

    fn push_operands(
        &mut self,
        operands: impl IntoIterator<Item = PCodeLocationId>,
    ) -> Result<IlIndexRange, IlError> {
        self.operands.append(operands)
    }

    fn push_op(&mut self, operation: PCodeOp) {
        self.operations.push(operation);
    }

    fn op_count(&self) -> usize {
        self.operations.len()
    }

    pub fn set_graph(&mut self, graph: IlGraph) {
        self.graph = graph;
    }

    pub fn with_graph(mut self, graph: IlGraph) -> Self {
        self.set_graph(graph);
        self
    }

    pub fn set_source_spans(&mut self, source_spans: Vec<IlSourceSpan>) {
        self.source_spans = source_spans;
    }

    pub fn with_source_spans(mut self, source_spans: Vec<IlSourceSpan>) -> Self {
        self.set_source_spans(source_spans);
        self
    }

    fn push_target(&mut self, target: Location) -> Result<PCodeTargetId, IlError> {
        let index = self.targets.len();
        self.targets.push(target);
        PCodeTargetId::try_from_index(index)
    }

    pub fn build(self, cancellation: &CancellationToken) -> Result<PCodeIr, IlError> {
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

        if ir.verify().is_err() {
            return Err(IlError::invalid_artefact(PCodeIr::FORM));
        }

        Ok(ir)
    }
}

pub struct PCodeEmitter<'a> {
    builder: &'a mut PCodeBuilder,
}

impl PCodeEmitter<'_> {
    pub fn op_count(&self) -> usize {
        self.builder.op_count()
    }

    pub fn intern_location(&mut self, location: PCodeLocation) -> Result<PCodeLocationId, IlError> {
        self.builder.intern_location(location)
    }

    pub fn emit_target(&mut self, target: Location) -> Result<PCodeTargetId, IlError> {
        self.builder.push_target(target)
    }

    pub fn emit(
        &mut self,
        spec: PCodeOpSpec,
        output: Option<PCodeLocationId>,
        operands: impl IntoIterator<Item = PCodeLocationId>,
    ) -> Result<IlOpId, IlError> {
        let id = IlOpId::try_from_index(self.builder.operations.len())?;
        let operands = self.builder.push_operands(operands)?;
        self.builder
            .push_op(PCodeOp::new(spec, output, operands));
        Ok(id)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::{IlBlock, IlBlockProperties, IlSourceSpan};
    use crate::il::pcode::verify::VerifyError;
    use crate::il::pcode::{PCodeLifterSpaceHandle, PCodeLocationProperties, PCodeOpcode};
    use crate::ir::{Address, FunctionId};
    use crate::storage::segments::space::AddressSpaceId;
    use crate::types::EstimateSize;

    fn metadata() -> IlMetadata {
        IlMetadata::new(FunctionId::default(), 0)
    }

    #[test]
    fn pcode_builder_finishes_verified_ir() {
        let mut builder = PCodeBuilder::new(metadata(), IlGraph::default());
        let location = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Copy),
                Some(location),
                [location],
            )
            .unwrap();

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert!(ir.verify().is_ok());
        assert_eq!(ir.ops().len(), 1);
        assert_eq!(ir.locations().len(), 1);
    }

    #[test]
    fn pcode_verify_rejects_multi_flag_location_properties() {
        let mut builder = PCodeBuilder::new(metadata(), IlGraph::default());
        let location = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT | PCodeLocationProperties::REGISTER,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Copy),
                Some(location),
                [location],
            )
            .unwrap();

        assert!(matches!(
            builder.build(&CancellationToken::default()),
            Err(IlError::InvalidArtefact { .. })
        ));
    }

    #[test]
    fn pcode_verify_rejects_address_space_on_non_requiring_opcode() {
        let mut builder = PCodeBuilder::new(metadata(), IlGraph::default());
        let location = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Copy).with_address_space(AddressSpaceId::new(1)),
                Some(location),
                [location],
            )
            .unwrap();

        assert!(matches!(
            builder.build(&CancellationToken::default()),
            Err(IlError::InvalidArtefact { .. })
        ));
    }

    #[test]
    fn pcode_builder_finish_shrinks_spare_capacity() {
        let baseline = PCodeBuilder::new(metadata(), IlGraph::default())
            .build(&CancellationToken::default())
            .unwrap();
        let mut builder = PCodeBuilder::new(metadata(), IlGraph::default());

        builder.locations.reserve(16);
        builder.operations.reserve(16);
        builder.targets.reserve(16);

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert_eq!(ir.estimate_size(), baseline.estimate_size());
    }

    #[test]
    fn pcode_ir_round_trips_through_archive() {
        let mut builder = PCodeBuilder::new(metadata(), IlGraph::default());
        let location = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Copy),
                Some(location),
                [location],
            )
            .unwrap();

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
        let mut builder = PCodeBuilder::new(metadata(), IlGraph::default());

        builder.set_source_spans(vec![IlSourceSpan::new(
            IlIndexRange::new(0, 2).unwrap(),
            source,
            0,
            2,
        )]);
        let pointer = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                data,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let value = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                0,
                8,
                PCodeLocationProperties::empty(),
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Load).with_address_space(data_space),
                Some(value),
                [pointer],
            )
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Store).with_address_space(data_space),
                None,
                [pointer, value],
            )
            .unwrap();

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
        let mut builder = PCodeBuilder::new(metadata(), IlGraph::default());

        builder.set_source_spans(vec![IlSourceSpan::new(
            IlIndexRange::new(0, 1).unwrap(),
            source,
            0,
            1,
        )]);
        let pointer = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                0x20,
                8,
                PCodeLocationProperties::empty(),
            ))
            .unwrap();
        let output = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                0,
                8,
                PCodeLocationProperties::empty(),
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Load).with_address_space(data_space),
                Some(output),
                [pointer],
            )
            .unwrap();

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
    fn verifier_rejects_copy_width_mismatch() {
        let mut builder = PCodeBuilder::new(metadata(), IlGraph::default());
        let input = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                1,
                4,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                8,
                8,
                PCodeLocationProperties::empty(),
            ))
            .unwrap();
        builder
            .emitter()
            .emit(PCodeOpSpec::new(PCodeOpcode::Copy), Some(output), [input])
            .unwrap();

        assert!(matches!(
            builder.build(&CancellationToken::default()),
            Err(IlError::InvalidArtefact { .. })
        ));
    }

    #[test]
    fn verifier_accepts_float_width_conversion() {
        let mut builder = PCodeBuilder::new(metadata(), IlGraph::default());
        let input = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                0,
                10,
                PCodeLocationProperties::empty(),
            ))
            .unwrap();
        let output = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                16,
                8,
                PCodeLocationProperties::empty(),
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::FloatToFloat),
                Some(output),
                [input],
            )
            .unwrap();

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert!(ir.verify().is_ok());
    }

    #[test]
    fn verifier_rejects_missing_output() {
        let mut builder = PCodeBuilder::new(metadata(), IlGraph::default());
        let input = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(PCodeOpSpec::new(PCodeOpcode::Copy), None, [input])
            .unwrap();

        assert!(matches!(
            builder.build(&CancellationToken::default()),
            Err(IlError::InvalidArtefact { .. })
        ));
    }

    #[test]
    fn verifier_rejects_invalid_operand_count() {
        let mut builder = PCodeBuilder::new(metadata(), IlGraph::default());
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
                PCodeLocationProperties::empty(),
            ))
            .unwrap();
        builder
            .emitter()
            .emit(PCodeOpSpec::new(PCodeOpcode::IntAdd), Some(output), [input])
            .unwrap();

        assert!(matches!(
            builder.build(&CancellationToken::default()),
            Err(IlError::InvalidArtefact { .. })
        ));
    }
}
