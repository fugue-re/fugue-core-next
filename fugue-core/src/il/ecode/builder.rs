use fugue_bv::BitVec;

use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlBlockArgId, IlBlockId, IlConstantInterner, IlError, IlGraph, IlIndexRange,
    IlMetadata, IlOpId, IlParentSpan, IlPool, IlSourceSpan, IlValueId,
};
use crate::il::ecode::ir::ECodeIrStorage;
use crate::il::ecode::{
    ECodeBlockArg, ECodeDomain, ECodeIr, ECodeMemoryDomain, ECodeOp, ECodeOpSpec, ECodeValue,
};
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug)]
pub struct ECodeBuilder {
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    values: Vec<ECodeValue>,
    value_domains: Vec<Option<ECodeDomain>>,
    block_args: Vec<ECodeBlockArg>,
    edge_args: Vec<IlIndexRange>,
    edge_arg_values: IlPool<IlValueId>,
    operations: Vec<ECodeOp>,
    value_operands: IlPool<IlValueId>,
    memory_domains: Vec<ECodeMemoryDomain>,
    constant_storage: Vec<u8>,
    constants: IlConstantInterner,
}

impl ECodeBuilder {
    pub fn new(metadata: IlMetadata, graph: IlGraph) -> Self {
        Self {
            metadata,
            graph,
            source_spans: Vec::new(),
            parent_spans: Vec::new(),
            values: Vec::new(),
            value_domains: Vec::new(),
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

    pub fn set_parent_spans(&mut self, parent_spans: Vec<IlParentSpan>) {
        self.parent_spans = parent_spans;
    }

    pub fn with_parent_spans(mut self, parent_spans: Vec<IlParentSpan>) -> Self {
        self.set_parent_spans(parent_spans);
        self
    }

    pub fn emitter(&mut self) -> ECodeEmitter<'_> {
        ECodeEmitter { builder: self }
    }

    fn push_block_arg_value(&mut self, block: IlBlockId, width: u32) -> Result<IlValueId, IlError> {
        let arg = IlBlockArgId::try_from_index(self.block_args.len())?;
        let value = IlValueId::try_from_index(self.values.len())?;

        self.values.push(ECodeValue::block_arg(width, arg));
        self.value_domains.push(None);
        self.block_args
            .push(ECodeBlockArg::new(block, value, width));

        Ok(value)
    }

    fn push_op(&mut self, operation: ECodeOp) -> Result<IlOpId, IlError> {
        let id = IlOpId::try_from_index(self.operations.len())?;
        self.operations.push(operation);
        Ok(id)
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

        self.memory_domains.push(ECodeMemoryDomain::new(space));
    }

    pub fn build(self, cancellation: &CancellationToken) -> Result<ECodeIr, IlError> {
        let ir = self.build_unchecked(cancellation)?;

        if ir.verify().is_err() {
            return Err(IlError::invalid_artefact(ECodeIr::FORM));
        }

        Ok(ir)
    }

    pub(crate) fn build_unchecked(
        mut self,
        cancellation: &CancellationToken,
    ) -> Result<ECodeIr, IlError> {
        cancellation.check()?;

        if self.edge_args.is_empty() && !self.graph.successors().is_empty() {
            self.edge_args = vec![IlIndexRange::EMPTY; self.graph.successors().len()];
        }

        let mut ir = ECodeIr::new(ECodeIrStorage {
            metadata: self.metadata,
            graph: self.graph,
            source_spans: self.source_spans,
            parent_spans: self.parent_spans,
            values: self.values,
            value_domains: self.value_domains,
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

pub struct ECodeEmitter<'a> {
    builder: &'a mut ECodeBuilder,
}

impl ECodeEmitter<'_> {
    pub fn op_count(&self) -> usize {
        self.builder.op_count()
    }

    pub fn set_value_domain(
        &mut self,
        value: IlValueId,
        domain: ECodeDomain,
    ) -> Result<(), IlError> {
        let value_count = self.builder.value_domains.len();
        let slot = self
            .builder
            .value_domains
            .get_mut(value.index())
            .ok_or_else(|| IlError::range_out_of_bounds(value.index(), value_count))?;
        if slot.is_some() {
            return Err(IlError::invalid_artefact(ECodeIr::FORM));
        }
        *slot = Some(domain);
        if let ECodeDomain::Memory(space) = domain {
            self.builder.intern_memory_domain(space);
        }
        Ok(())
    }

    pub fn intern_constant(&mut self, value: &BitVec) -> u64 {
        self.builder
            .constants
            .intern(&mut self.builder.constant_storage, value)
    }

    pub fn intern_memory_domain(&mut self, space: AddressSpaceId) {
        self.builder.intern_memory_domain(space);
    }

    pub fn emit(
        &mut self,
        spec: ECodeOpSpec,
        operands: impl IntoIterator<Item = IlValueId>,
        result_count: usize,
    ) -> Result<(IlOpId, IlIndexRange), IlError> {
        let operation = IlOpId::try_from_index(self.builder.operations.len())?;
        let result_start = self.builder.values.len();
        for _ in 0..result_count {
            self.builder
                .values
                .push(ECodeValue::op_result(spec.width(), operation));
            self.builder.value_domains.push(None);
        }
        let results = IlIndexRange::new(result_start, self.builder.values.len())?;
        let operands = self.builder.push_value_operands(operands)?;
        let mut record = ECodeOp::new(spec.opcode(), results, operands, spec.width())
            .with_immediate(spec.immediate());
        if let Some(address) = spec.address() {
            record.set_address(address);
        }
        if let Some(address_space) = spec.address_space() {
            if spec.opcode().requires_memory_domain() {
                self.builder.intern_memory_domain(address_space);
            }
            record.set_address_space(address_space);
        }
        self.builder.push_op(record)?;

        Ok((operation, results))
    }

    pub fn emit_block_arg(&mut self, block: IlBlockId, width: u32) -> Result<IlValueId, IlError> {
        self.builder.push_block_arg_value(block, width)
    }

    pub fn emit_edge_args(
        &mut self,
        args: impl IntoIterator<Item = IlValueId>,
    ) -> Result<IlIndexRange, IlError> {
        self.builder.push_edge_args(args)
    }
}
