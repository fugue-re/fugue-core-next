use fugue_bv::BitVec;

use crate::il::common::{
    IlArtefact, IlGraph, IlHeader, IlIndexRange, IlLevel, IlParentSpan, IlSchemaVersion,
    IlSourceSpan, IlValueId,
};
use crate::il::ecode::ssa::{
    ECodeSsaBlockArg, ECodeSsaMemoryDomain, ECodeSsaOp, ECodeSsaValue, ECodeSsaValueKind,
};
use crate::ir::{Address, FunctionId};
use crate::storage::entities::schema::ENTITY_IL_ECODE_SSA_ID;
use crate::storage::entities::{Entity, EntityId, MutableEntity};
use crate::storage::segments::space::AddressSpaceId;

pub const ECODE_SSA_SCHEMA_VERSION: IlSchemaVersion = IlSchemaVersion::new(2);

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ECodeSsaIr {
    pub(crate) header: IlHeader,
    pub(crate) graph: IlGraph,
    pub(crate) source_spans: Vec<IlSourceSpan>,
    pub(crate) parent_spans: Vec<IlParentSpan>,
    pub(crate) values: Vec<ECodeSsaValue>,
    pub(crate) block_arguments: Vec<ECodeSsaBlockArg>,
    pub(crate) edge_arguments: Vec<IlIndexRange>,
    pub(crate) edge_argument_values: Vec<IlValueId>,
    pub(crate) operations: Vec<ECodeSsaOp>,
    pub(crate) value_operands: Vec<IlValueId>,
    pub(crate) memory_domains: Vec<ECodeSsaMemoryDomain>,
    pub(crate) constants: Vec<u8>,
}

impl ECodeSsaIr {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        header: IlHeader,
        graph: IlGraph,
        source_spans: Vec<IlSourceSpan>,
        parent_spans: Vec<IlParentSpan>,
        values: Vec<ECodeSsaValue>,
        block_arguments: Vec<ECodeSsaBlockArg>,
        operations: Vec<ECodeSsaOp>,
        value_operands: Vec<IlValueId>,
        memory_domains: Vec<ECodeSsaMemoryDomain>,
    ) -> Self {
        let edge_arguments = vec![IlIndexRange::EMPTY; graph.successors().len()];

        Self {
            header,
            graph,
            source_spans,
            parent_spans,
            values,
            block_arguments,
            edge_arguments,
            edge_argument_values: Vec::new(),
            operations,
            value_operands,
            memory_domains,
            constants: Vec::new(),
        }
    }

    pub(crate) fn with_edge_argument_storage(
        mut self,
        edge_arguments: Vec<IlIndexRange>,
        edge_argument_values: Vec<IlValueId>,
    ) -> Self {
        self.edge_arguments = edge_arguments;
        self.edge_argument_values = edge_argument_values;
        self
    }

    pub(crate) fn with_constants(mut self, constants: Vec<u8>) -> Self {
        self.constants = constants;
        self
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

    pub fn parent_spans(&self) -> &[IlParentSpan] {
        &self.parent_spans
    }

    pub fn source_span_for(&self, node: u32) -> Option<IlSourceSpan> {
        IlSourceSpan::find(&self.source_spans, node)
    }

    pub fn parent_span_for(&self, node: u32) -> Option<IlParentSpan> {
        IlParentSpan::find(&self.parent_spans, node)
    }

    pub fn values(&self) -> &[ECodeSsaValue] {
        &self.values
    }

    pub fn block_arguments(&self) -> &[ECodeSsaBlockArg] {
        &self.block_arguments
    }

    pub fn edge_arguments(&self) -> &[IlIndexRange] {
        &self.edge_arguments
    }

    pub fn edge_argument_values(&self) -> &[IlValueId] {
        &self.edge_argument_values
    }

    pub fn operations(&self) -> &[ECodeSsaOp] {
        &self.operations
    }

    pub fn value_operands(&self) -> &[IlValueId] {
        &self.value_operands
    }

    pub fn memory_domains(&self) -> &[ECodeSsaMemoryDomain] {
        &self.memory_domains
    }

    pub(crate) fn constant_storage(&self) -> &[u8] {
        &self.constants
    }

    pub fn memory_domain(&self, space: AddressSpaceId) -> Option<&ECodeSsaMemoryDomain> {
        self.memory_domains
            .iter()
            .find(|domain| domain.space() == space)
    }

    pub fn operation_operands(&self, operation: &ECodeSsaOp) -> &[IlValueId] {
        operation.operands().slice(&self.value_operands)
    }

    pub(crate) fn defining_operation(&self, value: IlValueId) -> Option<&ECodeSsaOp> {
        self.operations.get(self.defining_operation_index(value)?)
    }

    pub(crate) fn value_width(&self, value: IlValueId) -> Option<u32> {
        self.values.get(value.index()).map(ECodeSsaValue::width)
    }

    pub(crate) fn constant_value(&self, value: IlValueId) -> Option<BitVec> {
        self.defining_operation(value)?.constant(&self.constants)
    }

    fn defining_operation_index(&self, value: IlValueId) -> Option<usize> {
        let record = self.values.get(value.index())?;
        (record.definition_kind() == ECodeSsaValueKind::Operation)
            .then(|| record.definition_index() as usize)
    }

    pub fn arguments_for_edge(&self, edge: usize) -> &[IlValueId] {
        self.edge_arguments
            .get(edge)
            .expect("edge index is within the edge argument table")
            .slice(&self.edge_argument_values)
    }

    pub fn operations_for_source(
        &self,
        address: Address,
    ) -> impl Iterator<Item = (usize, &ECodeSsaOp)> + '_ {
        self.source_spans
            .iter()
            .filter(move |run| run.address() == address)
            .flat_map(move |run| {
                let start = run.destination().start();
                run.destination()
                    .slice(&self.operations)
                    .iter()
                    .enumerate()
                    .map(move |(index, operation)| (start + index, operation))
            })
    }

    pub fn shrink_to_fit(&mut self) {
        self.graph.shrink_to_fit();
        self.source_spans.shrink_to_fit();
        self.parent_spans.shrink_to_fit();
        self.values.shrink_to_fit();
        self.block_arguments.shrink_to_fit();
        self.edge_arguments.shrink_to_fit();
        self.edge_argument_values.shrink_to_fit();
        self.operations.shrink_to_fit();
        self.value_operands.shrink_to_fit();
        self.memory_domains.shrink_to_fit();
        self.constants.shrink_to_fit();
    }
}

impl Entity for ECodeSsaIr {
    const ID: EntityId = ENTITY_IL_ECODE_SSA_ID;
}

impl MutableEntity for ECodeSsaIr {
    type Key = FunctionId;

    fn entity_key(&self) -> FunctionId {
        self.header.function()
    }
}

impl IlArtefact for ECodeSsaIr {
    const LEVEL: IlLevel = IlLevel::ECodeSsa;
    const SCHEMA: IlSchemaVersion = ECODE_SSA_SCHEMA_VERSION;

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
