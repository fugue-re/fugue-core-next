use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlBlockId, IlError, IlGraph, IlIndexRange, IlMetadata, IlOpId, IlParentSpan, IlPool,
    IlSourceSpan, IlValueId,
};
use crate::il::ecode::ssa::{
    ECodeSsaBlockArg, ECodeSsaIr, ECodeSsaIrParts, ECodeSsaMemoryDomain, ECodeSsaOp, ECodeSsaValue,
};
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug)]
pub(crate) struct ECodeSsaBuilder {
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    values: Vec<ECodeSsaValue>,
    block_arguments: Vec<ECodeSsaBlockArg>,
    edge_arguments: Vec<IlIndexRange>,
    edge_argument_values: IlPool<IlValueId>,
    operations: Vec<ECodeSsaOp>,
    value_operands: IlPool<IlValueId>,
    memory_domains: Vec<ECodeSsaMemoryDomain>,
    constant_storage: Vec<u8>,
}

impl ECodeSsaBuilder {
    pub(crate) fn new(metadata: IlMetadata, graph: IlGraph) -> Self {
        Self {
            metadata,
            graph,
            source_spans: Vec::new(),
            parent_spans: Vec::new(),
            values: Vec::new(),
            block_arguments: Vec::new(),
            edge_arguments: Vec::new(),
            edge_argument_values: IlPool::new(),
            operations: Vec::new(),
            value_operands: IlPool::new(),
            memory_domains: Vec::new(),
            constant_storage: Vec::new(),
        }
    }

    pub(crate) fn push_result_value(
        &mut self,
        width: u32,
    ) -> Result<(IlValueId, IlIndexRange), IlError> {
        let id = IlValueId::try_from_index(self.values.len())?;
        let operation = IlOpId::try_from_index(self.operations.len())?;
        let results = IlIndexRange::new(self.values.len(), self.values.len() + 1)?;

        self.values
            .push(ECodeSsaValue::operation_result(width, operation));

        Ok((id, results))
    }

    pub(crate) fn push_block_argument_value(
        &mut self,
        block: IlBlockId,
        width: u32,
    ) -> Result<IlValueId, IlError> {
        self.graph
            .blocks()
            .get(block.index())
            .ok_or(IlError::range_out_of_bounds(
                block.value(),
                self.graph.blocks().len(),
            ))?;

        let argument_index = u32::try_from(self.block_arguments.len())
            .map_err(|_| IlError::id_exhausted("SSA block argument"))?;
        let value = IlValueId::try_from_index(self.values.len())?;

        self.values
            .push(ECodeSsaValue::block_argument(width, argument_index));
        self.block_arguments
            .push(ECodeSsaBlockArg::new(block, value, width));

        Ok(value)
    }

    pub(crate) fn push_operation(&mut self, operation: ECodeSsaOp) -> Result<IlOpId, IlError> {
        let id = IlOpId::try_from_index(self.operations.len())?;
        self.operations.push(operation);
        Ok(id)
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

    pub(crate) fn set_parent_spans(&mut self, parent_spans: Vec<IlParentSpan>) {
        self.parent_spans = parent_spans;
    }

    pub(crate) fn push_value_operands(
        &mut self,
        operands: impl IntoIterator<Item = IlValueId>,
    ) -> Result<IlIndexRange, IlError> {
        self.value_operands.append(operands)
    }

    pub(crate) fn push_edge_arguments(
        &mut self,
        operands: impl IntoIterator<Item = IlValueId>,
    ) -> Result<IlIndexRange, IlError> {
        let range = self.edge_argument_values.append(operands)?;

        self.edge_arguments.push(range);

        Ok(range)
    }

    pub(crate) fn clear_edge_arguments(&mut self) {
        self.edge_arguments.clear();
        self.edge_argument_values = IlPool::new();
    }

    pub(crate) fn ensure_memory_domain(&mut self, space: AddressSpaceId) -> usize {
        if let Some(index) = self
            .memory_domains
            .iter()
            .position(|domain| domain.space() == space)
        {
            return index;
        }

        self.memory_domains.push(ECodeSsaMemoryDomain::new(space));
        self.memory_domains.len() - 1
    }

    pub(crate) fn build(mut self, cancellation: &CancellationToken) -> Result<ECodeSsaIr, IlError> {
        cancellation.check()?;

        if self.edge_arguments.is_empty() && !self.graph.successors().is_empty() {
            self.edge_arguments = vec![IlIndexRange::EMPTY; self.graph.successors().len()];
        }

        let mut ir = ECodeSsaIr::new(ECodeSsaIrParts {
            metadata: self.metadata,
            graph: self.graph,
            source_spans: self.source_spans,
            parent_spans: self.parent_spans,
            values: self.values,
            block_arguments: self.block_arguments,
            edge_arguments: self.edge_arguments,
            edge_argument_values: self.edge_argument_values.into_values(),
            operations: self.operations,
            value_operands: self.value_operands.into_values(),
            memory_domains: self.memory_domains,
            constant_storage: self.constant_storage,
        });

        ir.shrink_to_fit();

        Ok(ir)
    }
}
