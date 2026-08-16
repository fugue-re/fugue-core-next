use fugue_bv::BitVec;
use rustc_hash::FxHashMap;

use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlBlockArgId, IlBlockId, IlConstantInterner, IlError, IlGraph, IlIndexRange,
    IlMetadata, IlOpId, IlParentSpan, IlPool, IlSourceSpan, IlValueId,
};
use crate::il::mcode::ir::MCodeIrStorage;
use crate::il::mcode::{
    MCodeBlockArg, MCodeIr, MCodeMemoryDomain, MCodeOp, MCodeOpSpec, MCodeValue, MCodeVar,
    MCodeVarId, MCodeVersion,
};
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug)]
pub struct MCodeBuilder {
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    variables: Vec<MCodeVar>,
    variable_ids: FxHashMap<MCodeVar, MCodeVarId>,
    aliased_variables: Vec<MCodeVarId>,
    values: Vec<MCodeValue>,
    block_args: Vec<MCodeBlockArg>,
    edge_args: Vec<IlIndexRange>,
    edge_arg_values: IlPool<IlValueId>,
    operations: Vec<MCodeOp>,
    value_operands: IlPool<IlValueId>,
    memory_domains: Vec<MCodeMemoryDomain>,
    constant_storage: Vec<u8>,
    constants: IlConstantInterner,
}

impl MCodeBuilder {
    pub fn new(metadata: IlMetadata, graph: IlGraph) -> Self {
        Self {
            metadata,
            graph,
            source_spans: Vec::new(),
            parent_spans: Vec::new(),
            variables: Vec::new(),
            variable_ids: FxHashMap::default(),
            aliased_variables: Vec::new(),
            values: Vec::new(),
            block_args: Vec::new(),
            edge_args: Vec::new(),
            edge_arg_values: IlPool::new(),
            operations: Vec::new(),
            value_operands: IlPool::new(),
            memory_domains: Vec::new(),
            constant_storage: Vec::new(),
            constants: IlConstantInterner::new(),
        }
    }

    pub fn emitter(&mut self) -> MCodeEmitter<'_> {
        MCodeEmitter { builder: self }
    }

    fn intern_constant(&mut self, value: &BitVec) -> u64 {
        self.constants.intern(&mut self.constant_storage, value)
    }

    fn intern_variable(&mut self, variable: MCodeVar) -> Result<MCodeVarId, IlError> {
        if let Some(id) = self.variable_ids.get(&variable) {
            return Ok(*id);
        }
        let id = MCodeVarId::try_from_index(self.variables.len())?;
        self.variables.push(variable);
        self.variable_ids.insert(variable, id);
        Ok(id)
    }

    fn push_result_values(
        &mut self,
        widths: impl IntoIterator<Item = u32>,
    ) -> Result<IlIndexRange, IlError> {
        let start = self.values.len();
        let operation = IlOpId::try_from_index(self.operations.len())?;
        for width in widths {
            self.values
                .push(MCodeValue::operation_result(width, operation));
        }

        IlIndexRange::new(start, self.values.len())
    }

    fn push_block_arg_value(&mut self, block: IlBlockId, width: u32) -> Result<IlValueId, IlError> {
        let arg = IlBlockArgId::try_from_index(self.block_args.len())?;
        let value = IlValueId::try_from_index(self.values.len())?;

        self.values.push(MCodeValue::block_arg(width, arg));
        self.block_args
            .push(MCodeBlockArg::new(block, value, width));

        Ok(value)
    }

    fn bind_value(
        &mut self,
        value: IlValueId,
        variable: MCodeVarId,
        version: MCodeVersion,
    ) -> Result<(), IlError> {
        let value_count = self.values.len();
        let value = self
            .values
            .get_mut(value.index())
            .ok_or_else(|| IlError::range_out_of_bounds(value.index(), value_count))?;
        value.set_binding(variable, version);
        Ok(())
    }

    fn push_operation(&mut self, operation: MCodeOp) -> Result<IlOpId, IlError> {
        let id = IlOpId::try_from_index(self.operations.len())?;
        self.operations.push(operation);
        Ok(id)
    }

    fn operation_count(&self) -> usize {
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

    pub fn set_parent_spans(&mut self, parent_spans: Vec<IlParentSpan>) {
        self.parent_spans = parent_spans;
    }

    pub fn with_parent_spans(mut self, parent_spans: Vec<IlParentSpan>) -> Self {
        self.set_parent_spans(parent_spans);
        self
    }

    pub fn set_aliased_variables(&mut self, mut aliased_variables: Vec<MCodeVarId>) {
        aliased_variables.sort_unstable();
        aliased_variables.dedup();
        self.aliased_variables = aliased_variables;
    }

    pub fn with_aliased_variables(mut self, aliased_variables: Vec<MCodeVarId>) -> Self {
        self.set_aliased_variables(aliased_variables);
        self
    }

    fn push_value_operands(
        &mut self,
        operands: impl IntoIterator<Item = IlValueId>,
    ) -> Result<IlIndexRange, IlError> {
        self.value_operands.append(operands)
    }

    fn push_edge_args(
        &mut self,
        operands: impl IntoIterator<Item = IlValueId>,
    ) -> Result<IlIndexRange, IlError> {
        let range = self.edge_arg_values.append(operands)?;

        self.edge_args.push(range);

        Ok(range)
    }

    fn intern_memory_domain(&mut self, space: AddressSpaceId) {
        if self
            .memory_domains
            .iter()
            .any(|domain| domain.space() == space)
        {
            return;
        }

        self.memory_domains.push(MCodeMemoryDomain::new(space));
    }

    pub fn build(self, cancellation: &CancellationToken) -> Result<MCodeIr, IlError> {
        let ir = self.build_unchecked(cancellation)?;

        if ir.verify().is_err() {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }

        Ok(ir)
    }

    pub(crate) fn build_unchecked(
        mut self,
        cancellation: &CancellationToken,
    ) -> Result<MCodeIr, IlError> {
        cancellation.check()?;

        if self.edge_args.is_empty() && !self.graph.successors().is_empty() {
            self.edge_args = vec![IlIndexRange::EMPTY; self.graph.successors().len()];
        }

        let mut ir = MCodeIr::new(MCodeIrStorage {
            metadata: self.metadata,
            graph: self.graph,
            source_spans: self.source_spans,
            parent_spans: self.parent_spans,
            variables: self.variables,
            aliased_variables: self.aliased_variables,
            values: self.values,
            block_args: self.block_args,
            edge_args: self.edge_args,
            edge_arg_values: self.edge_arg_values.into_values(),
            operations: self.operations,
            value_operands: self.value_operands.into_values(),
            memory_domains: self.memory_domains,
            constant_storage: self.constant_storage,
        });

        ir.shrink_to_fit();

        Ok(ir)
    }
}

pub struct MCodeEmitter<'a> {
    builder: &'a mut MCodeBuilder,
}

impl MCodeEmitter<'_> {
    pub fn operation_count(&self) -> usize {
        self.builder.operation_count()
    }

    pub fn intern_constant(&mut self, value: &BitVec) -> u64 {
        self.builder.intern_constant(value)
    }

    pub fn intern_memory_domain(&mut self, space: AddressSpaceId) {
        self.builder.intern_memory_domain(space);
    }

    pub fn intern_variable(&mut self, variable: MCodeVar) -> Result<MCodeVarId, IlError> {
        self.builder.intern_variable(variable)
    }

    pub fn emit(
        &mut self,
        spec: MCodeOpSpec,
        operands: impl IntoIterator<Item = IlValueId>,
        result_widths: impl IntoIterator<Item = u32>,
    ) -> Result<(IlOpId, IlIndexRange), IlError> {
        let operation = IlOpId::try_from_index(self.builder.operations.len())?;
        let results = self.builder.push_result_values(result_widths)?;
        let operands = self.builder.push_value_operands(operands)?;
        let mut record = MCodeOp::new(spec.opcode(), results, operands, spec.width());
        if let Some(variable) = spec.variable() {
            record.set_variable(variable);
        }
        record.set_immediate(spec.immediate());
        if let Some(address) = spec.address() {
            record.set_address(address);
        }
        if let Some(address_space) = spec.address_space() {
            if spec.opcode().requires_memory_domain() {
                self.builder.intern_memory_domain(address_space);
            }
            record.set_address_space(address_space);
        }
        self.builder.push_operation(record)?;

        Ok((operation, results))
    }

    pub fn emit_block_arg(&mut self, block: IlBlockId, width: u32) -> Result<IlValueId, IlError> {
        self.builder.push_block_arg_value(block, width)
    }

    pub fn bind_value(
        &mut self,
        value: IlValueId,
        variable: MCodeVarId,
        version: MCodeVersion,
    ) -> Result<(), IlError> {
        self.builder.bind_value(value, variable, version)
    }

    pub fn emit_edge_args(
        &mut self,
        args: impl IntoIterator<Item = IlValueId>,
    ) -> Result<IlIndexRange, IlError> {
        self.builder.push_edge_args(args)
    }
}
