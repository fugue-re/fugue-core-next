use fugue_bv::BitVec;

use crate::il::common::{
    IlArtefact, IlBlockId, IlGraph, IlIndexRange, IlLevel, IlMetadata, IlOpId, IlParentSpan,
    IlSchemaVersion, IlSourceSpan, IlValueId,
};
use crate::il::ecode::ssa::{
    ECodeSsaBlockArg, ECodeSsaMemoryDomain, ECodeSsaOp, ECodeSsaOpcode, ECodeSsaValue,
    ECodeSsaValueKind,
};
use crate::ir::{Address, FunctionId};
use crate::storage::entities::schema::ENTITY_IL_ECODE_SSA_ID;
use crate::storage::entities::{Entity, EntityId, MutableEntity};
use crate::storage::segments::space::AddressSpaceId;

pub const ECODE_SSA_SCHEMA_VERSION: IlSchemaVersion = IlSchemaVersion::new(1);

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ECodeSsaIr {
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    values: Vec<ECodeSsaValue>,
    block_arguments: Vec<ECodeSsaBlockArg>,
    edge_arguments: Vec<IlIndexRange>,
    edge_argument_values: Vec<IlValueId>,
    operations: Vec<ECodeSsaOp>,
    value_operands: Vec<IlValueId>,
    memory_domains: Vec<ECodeSsaMemoryDomain>,
    constant_storage: Vec<u8>,
}

impl ECodeSsaIr {
    pub(crate) fn new(metadata: IlMetadata, graph: IlGraph) -> Self {
        let edge_arguments = vec![IlIndexRange::EMPTY; graph.successors().len()];

        Self {
            metadata,
            graph,
            source_spans: Vec::new(),
            parent_spans: Vec::new(),
            values: Vec::new(),
            block_arguments: Vec::new(),
            edge_arguments,
            edge_argument_values: Vec::new(),
            operations: Vec::new(),
            value_operands: Vec::new(),
            memory_domains: Vec::new(),
            constant_storage: Vec::new(),
        }
    }

    pub(crate) fn with_spans(
        mut self,
        source_spans: Vec<IlSourceSpan>,
        parent_spans: Vec<IlParentSpan>,
    ) -> Self {
        self.source_spans = source_spans;
        self.parent_spans = parent_spans;
        self
    }

    pub(crate) fn with_values(
        mut self,
        values: Vec<ECodeSsaValue>,
        block_arguments: Vec<ECodeSsaBlockArg>,
    ) -> Self {
        self.values = values;
        self.block_arguments = block_arguments;
        self
    }

    pub(crate) fn with_operations(
        mut self,
        operations: Vec<ECodeSsaOp>,
        value_operands: Vec<IlValueId>,
    ) -> Self {
        self.operations = operations;
        self.value_operands = value_operands;
        self
    }

    pub(crate) fn with_memory_domains(mut self, memory_domains: Vec<ECodeSsaMemoryDomain>) -> Self {
        self.memory_domains = memory_domains;
        self
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

    pub(crate) fn with_constant_storage(mut self, constant_storage: Vec<u8>) -> Self {
        self.constant_storage = constant_storage;
        self
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

    pub fn parent_spans(&self) -> &[IlParentSpan] {
        &self.parent_spans
    }

    pub fn source_span_for(&self, node: usize) -> Option<IlSourceSpan> {
        IlSourceSpan::find(&self.source_spans, node)
    }

    pub fn parent_span_for(&self, node: usize) -> Option<IlParentSpan> {
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
        &self.constant_storage
    }

    pub fn memory_domain(&self, space: AddressSpaceId) -> Option<&ECodeSsaMemoryDomain> {
        self.memory_domains
            .iter()
            .find(|domain| domain.space() == space)
    }

    pub fn operation_operands(&self, operation: &ECodeSsaOp) -> &[IlValueId] {
        operation.operands().slice(&self.value_operands)
    }

    pub(crate) fn operations_and_constants_mut(&mut self) -> (&mut [ECodeSsaOp], &mut Vec<u8>) {
        (&mut self.operations, &mut self.constant_storage)
    }

    pub(crate) fn replace_graph(&mut self, graph: IlGraph) {
        self.graph = graph;
    }

    pub(crate) fn replace_source_spans(&mut self, source_spans: Vec<IlSourceSpan>) {
        self.source_spans = source_spans;
    }

    pub(crate) fn replace_parent_spans(&mut self, parent_spans: Vec<IlParentSpan>) {
        self.parent_spans = parent_spans;
    }

    pub(crate) fn replace_values(
        &mut self,
        values: Vec<ECodeSsaValue>,
        block_arguments: Vec<ECodeSsaBlockArg>,
    ) {
        self.values = values;
        self.block_arguments = block_arguments;
    }

    pub(crate) fn replace_operation_storage(
        &mut self,
        operations: Vec<ECodeSsaOp>,
        value_operands: Vec<IlValueId>,
    ) {
        self.operations = operations;
        self.value_operands = value_operands;
    }

    pub(crate) fn replace_edge_argument_storage(
        &mut self,
        edge_arguments: Vec<IlIndexRange>,
        edge_argument_values: Vec<IlValueId>,
    ) {
        self.edge_arguments = edge_arguments;
        self.edge_argument_values = edge_argument_values;
    }

    pub(crate) fn replace_constant_storage(&mut self, constant_storage: Vec<u8>) {
        self.constant_storage = constant_storage;
    }

    pub(crate) fn block_for_operation(&self, operation: IlOpId) -> Option<IlBlockId> {
        self.graph
            .blocks()
            .iter()
            .position(|block| block.operations().contains_index(operation.index()))
            .and_then(|index| IlBlockId::try_from_index(index).ok())
    }

    pub(crate) fn block_address(&self, block: IlBlockId) -> Option<Address> {
        if let Some(address) = self.graph.block_source(block) {
            return Some(address);
        }
        let range = self.graph.blocks().get(block.index())?.operations();
        self.source_span_for(range.start())
            .map(|span| span.address())
    }

    pub(crate) fn defining_operation(&self, value: IlValueId) -> Option<&ECodeSsaOp> {
        self.operations.get(self.defining_operation_index(value)?)
    }

    pub(crate) fn memory_operand(&self, operation: &ECodeSsaOp) -> Option<IlValueId> {
        if !operation.opcode().requires_memory_domain() {
            return None;
        }

        self.operation_operands(operation).last().copied()
    }

    pub(crate) fn pointer_operand(&self, operation: &ECodeSsaOp) -> Option<IlValueId> {
        if !matches!(
            operation.opcode(),
            ECodeSsaOpcode::Load | ECodeSsaOpcode::Store
        ) {
            return None;
        }

        self.operation_operands(operation).first().copied()
    }

    pub(crate) fn underlying_value(&self, value: IlValueId) -> IlValueId {
        let mut current = value;
        for _ in 0..self.values.len() {
            let Some(operation) = self.defining_operation(current) else {
                return current;
            };
            match operation.opcode() {
                ECodeSsaOpcode::Copy
                | ECodeSsaOpcode::SignExtend
                | ECodeSsaOpcode::Truncate
                | ECodeSsaOpcode::ZeroExtend => {
                    let Some(inner) = self.operation_operands(operation).first().copied() else {
                        return current;
                    };
                    current = inner;
                }
                _ => return current,
            }
        }
        current
    }

    pub(crate) fn inserted_value_for_exact_extract(&self, value: IlValueId) -> Option<IlValueId> {
        let extract = self.defining_operation(value)?;
        if extract.opcode() != ECodeSsaOpcode::Extract {
            return None;
        }
        let extract_operands = self.operation_operands(extract);
        let (&source, &extract_offset) = (extract_operands.first()?, extract_operands.get(1)?);
        let extract_offset = self.constant_value(extract_offset)?.to_u64()?;

        let insert = self.defining_operation(source)?;
        if insert.opcode() != ECodeSsaOpcode::Insert || insert.immediate() != extract_offset {
            return None;
        }

        let inserted = *self.operation_operands(insert).get(1)?;
        (self.value_width(inserted)? == extract.width()).then_some(inserted)
    }

    pub(crate) fn value_width(&self, value: IlValueId) -> Option<u32> {
        self.values.get(value.index()).map(ECodeSsaValue::width)
    }

    pub(crate) fn constant_value(&self, value: IlValueId) -> Option<BitVec> {
        self.defining_operation(value)?
            .constant(&self.constant_storage)
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
        self.constant_storage.shrink_to_fit();
    }
}

impl Entity for ECodeSsaIr {
    const ID: EntityId = ENTITY_IL_ECODE_SSA_ID;
}

impl MutableEntity for ECodeSsaIr {
    type Key = FunctionId;

    fn entity_key(&self) -> FunctionId {
        self.metadata.function()
    }
}

impl IlArtefact for ECodeSsaIr {
    const LEVEL: IlLevel = IlLevel::ECodeSsa;
    const SCHEMA: IlSchemaVersion = ECODE_SSA_SCHEMA_VERSION;

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
