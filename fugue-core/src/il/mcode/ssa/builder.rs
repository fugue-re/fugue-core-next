use fugue_bv::BitVec;
use rustc_hash::FxHashMap;

use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlBlockArgId, IlBlockId, IlConstantInterner, IlError, IlGraph, IlIndexRange, IlMetadata,
    IlOpId, IlParentSpan, IlPool, IlSourceSpan, IlValueId,
};
use crate::il::mcode::ssa::{
    MCodeSsaBlockArg, MCodeSsaBuilderContext, MCodeSsaIr, MCodeSsaMemoryDomain, MCodeSsaOp,
    MCodeSsaValue, MCodeSsaVersion,
};
use crate::il::mcode::{MCodeVar, MCodeVarId};
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug)]
pub(crate) struct MCodeSsaBuilder {
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    variables: Vec<MCodeVar>,
    variable_ids: FxHashMap<MCodeVar, MCodeVarId>,
    aliased_variables: Vec<MCodeVarId>,
    values: Vec<MCodeSsaValue>,
    block_arguments: Vec<MCodeSsaBlockArg>,
    edge_arguments: Vec<IlIndexRange>,
    edge_argument_values: IlPool<IlValueId>,
    operations: Vec<MCodeSsaOp>,
    value_operands: IlPool<IlValueId>,
    memory_domains: Vec<MCodeSsaMemoryDomain>,
    constant_storage: Vec<u8>,
    constants: IlConstantInterner,
}

impl MCodeSsaBuilder {
    pub(crate) fn new(metadata: IlMetadata, graph: IlGraph) -> Self {
        Self {
            metadata,
            graph,
            source_spans: Vec::new(),
            parent_spans: Vec::new(),
            variables: Vec::new(),
            variable_ids: FxHashMap::default(),
            aliased_variables: Vec::new(),
            values: Vec::new(),
            block_arguments: Vec::new(),
            edge_arguments: Vec::new(),
            edge_argument_values: IlPool::new(),
            operations: Vec::new(),
            value_operands: IlPool::new(),
            memory_domains: Vec::new(),
            constant_storage: Vec::new(),
            constants: IlConstantInterner::new(),
        }
    }

    pub(crate) fn intern_constant(&mut self, value: &BitVec) -> u64 {
        self.constants.intern(&mut self.constant_storage, value)
    }

    pub(crate) fn intern_variable(&mut self, variable: MCodeVar) -> Result<MCodeVarId, IlError> {
        if let Some(id) = self.variable_ids.get(&variable) {
            return Ok(*id);
        }
        let id = MCodeVarId::try_from_index(self.variables.len())?;
        self.variables.push(variable);
        self.variable_ids.insert(variable, id);
        Ok(id)
    }

    pub(crate) fn push_result_values(
        &mut self,
        widths: impl IntoIterator<Item = u32>,
    ) -> Result<IlIndexRange, IlError> {
        let start = self.values.len();
        let operation = IlOpId::try_from_index(self.operations.len())?;
        for width in widths {
            self.values
                .push(MCodeSsaValue::operation_result(width, operation));
        }

        IlIndexRange::new(start, self.values.len())
    }

    pub(crate) fn push_block_argument_value(
        &mut self,
        block: IlBlockId,
        width: u32,
    ) -> Result<IlValueId, IlError> {
        self.graph.blocks().get(block.index()).ok_or_else(|| {
            IlError::range_out_of_bounds(block.value(), self.graph.blocks().len())
        })?;

        let argument = IlBlockArgId::try_from_index(self.block_arguments.len())?;
        let value = IlValueId::try_from_index(self.values.len())?;

        self.values
            .push(MCodeSsaValue::block_argument(width, argument));
        self.block_arguments
            .push(MCodeSsaBlockArg::new(block, value, width));

        Ok(value)
    }

    pub(crate) fn bind_value(
        &mut self,
        value: IlValueId,
        variable: MCodeVarId,
        version: MCodeSsaVersion,
    ) {
        self.values[value.index()].set_binding(variable, version);
    }

    pub(crate) fn push_operation(&mut self, operation: MCodeSsaOp) -> Result<IlOpId, IlError> {
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

    pub(crate) fn set_aliased_variables(&mut self, mut aliased_variables: Vec<MCodeVarId>) {
        aliased_variables.sort_unstable();
        aliased_variables.dedup();
        self.aliased_variables = aliased_variables;
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

        self.memory_domains.push(MCodeSsaMemoryDomain::new(space));
        self.memory_domains.len() - 1
    }

    pub(crate) fn build(mut self, cancellation: &CancellationToken) -> Result<MCodeSsaIr, IlError> {
        cancellation.check()?;

        if self.edge_arguments.is_empty() && !self.graph.successors().is_empty() {
            self.edge_arguments = vec![IlIndexRange::EMPTY; self.graph.successors().len()];
        }

        let mut ir = MCodeSsaIr::new(MCodeSsaBuilderContext {
            metadata: self.metadata,
            graph: self.graph,
            source_spans: self.source_spans,
            parent_spans: self.parent_spans,
            variables: self.variables,
            aliased_variables: self.aliased_variables,
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
