use std::mem::size_of;

use crate::il::common::{
    ControlFlowIl, IlArtefact, IlGraph, IlMetadata, IlOpId, IlSchemaVersion, IlSourceSpan,
    PersistableIl,
};
use crate::il::pcode::verify::{VerifyError, verify};
use crate::il::pcode::{
    PCodeIrDisplay, PCodeLocation, PCodeLocationId, PCodeOp, PCodeOpcode, PCodeSourceDisplay,
    PCodeTargetId,
};
use crate::ir::{
    Address, AddressRange, AddressRangeSet, Location, Reference, ReferenceOrigin,
    ReferenceProperties,
};
use crate::types::EstimateSize;

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
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

    pub(crate) fn verify(&self) -> Result<(), VerifyError> {
        verify(self)
    }

    pub const fn display(&self) -> PCodeIrDisplay<'_> {
        PCodeIrDisplay::new(self)
    }

    pub const fn display_source(&self, address: Address) -> PCodeSourceDisplay<'_> {
        PCodeSourceDisplay::new(self, address)
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

    pub fn ops(&self) -> &[PCodeOp] {
        &self.operations
    }

    pub fn op_operands(&self) -> &[PCodeLocationId] {
        &self.operands
    }

    pub fn targets(&self) -> &[Location] {
        &self.targets
    }

    pub fn target(&self, id: PCodeTargetId) -> Option<Location> {
        self.targets.get(id.index()).copied()
    }

    pub fn location(&self, id: PCodeLocationId) -> Option<&PCodeLocation> {
        self.locations.get(id.index())
    }

    pub fn op_operands_for(&self, operation: &PCodeOp) -> &[PCodeLocationId] {
        operation.operands().slice(&self.operands)
    }

    pub fn ops_for_source(
        &self,
        address: Address,
    ) -> impl Iterator<Item = (IlOpId, &PCodeOp)> + '_ {
        IlSourceSpan::ops(&self.source_spans, &self.operations, address)
    }

    pub fn data_references(&self) -> impl Iterator<Item = Reference> + '_ {
        self.operations
            .iter()
            .enumerate()
            .filter_map(move |(index, operation)| {
                let properties = match operation.opcode() {
                    PCodeOpcode::Load => ReferenceProperties::READ,
                    PCodeOpcode::Store => ReferenceProperties::WRITE,
                    _ => return None,
                };
                let source = self.source_span_for(index)?;
                let pointer = self.op_operands_for(operation).first().copied()?;
                let pointer = self.location(pointer)?;
                if !pointer.is_constant() {
                    return None;
                }
                let space = operation.address_space()?;
                Some(
                    Reference::data(
                        source.address(),
                        Address::new(space, pointer.offset()),
                        properties,
                    )
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

impl IlArtefact for PCodeIr {
    const FORM_IDENTIFIER: &str = "fugue.pcode.cfg";

    fn metadata(&self) -> &IlMetadata {
        &self.metadata
    }
}

impl ControlFlowIl for PCodeIr {
    fn graph(&self) -> &IlGraph {
        &self.graph
    }
}

impl PersistableIl for PCodeIr {
    const SCHEMA: IlSchemaVersion = IlSchemaVersion::new(1);

    fn metadata_mut(&mut self) -> &mut IlMetadata {
        &mut self.metadata
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
