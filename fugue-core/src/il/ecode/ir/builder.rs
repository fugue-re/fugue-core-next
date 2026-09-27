use fixedbitset::FixedBitSet;
use fugue_bv::BitVec;
use smallvec::SmallVec;

use crate::il::common::{
    IlArtefact, IlBlock, IlBlockArgId, IlBlockId, IlBlockProperties, IlConstantInterner,
    IlEdgeKinds, IlError, IlGraph, IlIndexRange, IlMetadata, IlOpId, IlParentSpan, IlPool,
    IlSourceSpan, IlValueId,
};
use crate::il::ecode::ir::ECodeIr;
use crate::il::ecode::{
    ECodeBlockArg, ECodeDomain, ECodeMemoryDomain, ECodeOp, ECodeOpSpec, ECodeValue,
};
use crate::ir::Address;
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug)]
struct ECodeBlockBuilder {
    block_args: SmallVec<[IlValueId; 2]>,
    properties: IlBlockProperties,
    source: Option<Address>,
    state: ECodeBlockBuilderState,
    successors: SmallVec<[ECodeBlockSuccessor; 2]>,
}

#[derive(Debug, Copy, Clone)]
enum ECodeBlockBuilderState {
    Pending,
    Started { operation_start: usize },
    Ended { operations: IlIndexRange },
}

impl ECodeBlockBuilderState {
    const fn pending() -> Self {
        Self::Pending
    }

    const fn started(operation_start: usize) -> Self {
        Self::Started { operation_start }
    }

    const fn ended(operations: IlIndexRange) -> Self {
        Self::Ended { operations }
    }

    const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    const fn is_started(&self) -> bool {
        matches!(self, Self::Started { .. })
    }

    const fn is_ended(&self) -> bool {
        matches!(self, Self::Ended { .. })
    }

    const fn ops(&self) -> Option<IlIndexRange> {
        match self {
            Self::Ended { operations } => Some(*operations),
            Self::Pending | Self::Started { .. } => None,
        }
    }
}

#[derive(Debug)]
struct ECodeBlockSuccessor {
    args: SmallVec<[IlValueId; 2]>,
    kinds: IlEdgeKinds,
    successor: IlBlockId,
}

impl ECodeBlockBuilder {
    fn new(properties: IlBlockProperties, source: impl Into<Option<Address>>) -> Self {
        Self {
            block_args: SmallVec::new(),
            properties,
            source: source.into(),
            state: ECodeBlockBuilderState::pending(),
            successors: SmallVec::new(),
        }
    }

    fn from_graph(graph: &IlGraph, id: IlBlockId) -> Self {
        let block = &graph.blocks()[id.index()];
        Self::new(block.properties(), graph.block_source(id))
    }

    fn block_args(&self) -> &[IlValueId] {
        &self.block_args
    }

    const fn is_ended(&self) -> bool {
        self.state.is_ended()
    }

    const fn is_pending(&self) -> bool {
        self.state.is_pending()
    }

    const fn is_started(&self) -> bool {
        self.state.is_started()
    }

    const fn ops(&self) -> Option<IlIndexRange> {
        self.state.ops()
    }

    const fn properties(&self) -> IlBlockProperties {
        self.properties
    }

    const fn source(&self) -> Option<Address> {
        self.source
    }

    fn successors(&self) -> &[ECodeBlockSuccessor] {
        &self.successors
    }

    fn add_block_arg(&mut self, value: IlValueId) -> Result<(), IlError> {
        if !self.state.is_pending() {
            return Err(IlError::invalid_artefact(ECodeIr::FORM));
        }
        self.block_args.push(value);
        Ok(())
    }

    fn add_successor(
        &mut self,
        successor: IlBlockId,
        kinds: IlEdgeKinds,
        args: SmallVec<[IlValueId; 2]>,
    ) -> Result<(), IlError> {
        if !self.state.is_started() {
            return Err(IlError::invalid_artefact(ECodeIr::FORM));
        }
        if let Some(edge) = self
            .successors
            .iter_mut()
            .find(|edge| edge.successor() == successor)
        {
            return edge.merge(kinds, args);
        }
        self.successors
            .push(ECodeBlockSuccessor::new(successor, kinds, args)?);
        Ok(())
    }

    fn begin(&mut self, operation_start: usize) -> Result<(), IlError> {
        if !self.state.is_pending() {
            return Err(IlError::invalid_artefact(ECodeIr::FORM));
        }
        self.state = ECodeBlockBuilderState::started(operation_start);
        Ok(())
    }

    fn end(&mut self, operation_end: usize) -> Result<(), IlError> {
        let ECodeBlockBuilderState::Started { operation_start } = self.state else {
            return Err(IlError::invalid_artefact(ECodeIr::FORM));
        };
        let operations = IlIndexRange::new(operation_start, operation_end)?;
        self.state = ECodeBlockBuilderState::ended(operations);
        Ok(())
    }
}

impl ECodeBlockSuccessor {
    fn new(
        successor: IlBlockId,
        kinds: IlEdgeKinds,
        args: SmallVec<[IlValueId; 2]>,
    ) -> Result<Self, IlError> {
        if kinds.is_empty() {
            return Err(IlError::invalid_artefact(ECodeIr::FORM));
        }
        Ok(Self {
            args,
            kinds,
            successor,
        })
    }

    fn args(&self) -> &[IlValueId] {
        &self.args
    }

    const fn kinds(&self) -> IlEdgeKinds {
        self.kinds
    }

    const fn successor(&self) -> IlBlockId {
        self.successor
    }

    fn merge(&mut self, kinds: IlEdgeKinds, args: SmallVec<[IlValueId; 2]>) -> Result<(), IlError> {
        if self.args != args {
            return Err(IlError::invalid_artefact(ECodeIr::FORM));
        }
        self.kinds |= kinds;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ECodeBuilder {
    metadata: IlMetadata,
    graph: IlGraph,
    blocks: Option<Vec<ECodeBlockBuilder>>,
    current_block: Option<IlBlockId>,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    values: Vec<ECodeValue>,
    value_domains: Vec<Option<ECodeDomain>>,
    block_args: Vec<ECodeBlockArg>,
    edge_args: Vec<IlIndexRange>,
    edge_args_set: FixedBitSet,
    edge_arg_values: IlPool<IlValueId>,
    operations: Vec<ECodeOp>,
    value_operands: IlPool<IlValueId>,
    memory_domains: Vec<ECodeMemoryDomain>,
    constant_storage: Vec<u8>,
    constants: IlConstantInterner,
}

impl ECodeBuilder {
    pub fn new(metadata: IlMetadata) -> Self {
        Self {
            metadata,
            graph: IlGraph::default(),
            blocks: None,
            current_block: None,
            source_spans: Vec::new(),
            parent_spans: Vec::new(),
            values: Vec::new(),
            value_domains: Vec::new(),
            block_args: Vec::new(),
            edge_args: Vec::new(),
            edge_args_set: FixedBitSet::new(),
            edge_arg_values: IlPool::new(),
            operations: Vec::new(),
            value_operands: IlPool::new(),
            memory_domains: Vec::new(),
            constant_storage: Vec::new(),
            constants: IlConstantInterner::new(),
        }
    }

    pub fn new_with(metadata: IlMetadata, graph: IlGraph) -> Self {
        let blocks = graph
            .blocks()
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let block = IlBlockId::try_from_index(index)
                    .expect("imported ECode block id is representable");
                ECodeBlockBuilder::from_graph(&graph, block)
            })
            .collect::<Vec<_>>();
        let successor_count = graph.successors().len();
        let mut builder = Self::new(metadata);
        builder.graph = graph;
        builder.blocks = (!blocks.is_empty()).then_some(blocks);
        builder.edge_args = vec![IlIndexRange::EMPTY; successor_count];
        builder.edge_args_set = FixedBitSet::with_capacity(successor_count);
        builder
    }

    pub fn op_count(&self) -> usize {
        self.operations.len()
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

    pub fn set_value_domain(
        &mut self,
        value: IlValueId,
        domain: ECodeDomain,
    ) -> Result<(), IlError> {
        let value_count = self.value_domains.len();
        let slot = self
            .value_domains
            .get_mut(value.index())
            .ok_or_else(|| IlError::range_out_of_bounds(value.index(), value_count))?;
        if slot.is_some() {
            return Err(IlError::invalid_artefact(ECodeIr::FORM));
        }
        *slot = Some(domain);
        if let ECodeDomain::Memory(space) = domain {
            self.intern_memory_domain(space);
        }
        Ok(())
    }

    pub fn add_block(&mut self, properties: IlBlockProperties) -> Result<IlBlockId, IlError> {
        self.add_block_with_source(properties, None::<Address>)
    }

    pub fn add_block_with_source(
        &mut self,
        properties: IlBlockProperties,
        source: impl Into<Option<Address>>,
    ) -> Result<IlBlockId, IlError> {
        if !self.graph.blocks().is_empty() || !self.operations.is_empty() {
            return Err(IlError::invalid_artefact(ECodeIr::FORM));
        }
        let definition = ECodeBlockBuilder::new(properties, source);
        let blocks = self.blocks.get_or_insert_with(Vec::new);
        if blocks
            .first()
            .is_some_and(|block| block.source().is_some() != definition.source().is_some())
        {
            return Err(IlError::inconsistent_block_sources());
        }
        let block = IlBlockId::try_from_index(blocks.len())?;
        blocks.push(definition);
        Ok(block)
    }

    pub fn switch_to_block(&mut self, block: IlBlockId) -> Result<(), IlError> {
        if let Some(current) = self.current_block {
            let blocks = self
                .blocks
                .as_ref()
                .ok_or_else(|| IlError::invalid_artefact(ECodeIr::FORM))?;
            if blocks[current.index()].is_started() {
                return Err(IlError::invalid_artefact(ECodeIr::FORM));
            }
        }

        let blocks = self
            .blocks
            .as_ref()
            .ok_or_else(|| IlError::invalid_artefact(ECodeIr::FORM))?;
        let block_count = blocks.len();
        let definition = blocks
            .get(block.index())
            .ok_or_else(|| IlError::range_out_of_bounds(block.index(), block_count))?;
        if !definition.is_pending() {
            return Err(IlError::invalid_artefact(ECodeIr::FORM));
        }

        self.current_block = Some(block);
        Ok(())
    }

    pub fn begin_block(&mut self) -> Result<(), IlError> {
        let block = self
            .current_block
            .ok_or_else(|| IlError::invalid_artefact(ECodeIr::FORM))?;
        let blocks = self
            .blocks
            .as_mut()
            .ok_or_else(|| IlError::invalid_artefact(ECodeIr::FORM))?;
        blocks[block.index()].begin(self.operations.len())
    }

    pub fn end_block(&mut self) -> Result<(), IlError> {
        let block = self
            .current_block
            .ok_or_else(|| IlError::invalid_artefact(ECodeIr::FORM))?;
        let blocks = self
            .blocks
            .as_mut()
            .ok_or_else(|| IlError::invalid_artefact(ECodeIr::FORM))?;
        blocks[block.index()].end(self.operations.len())
    }

    pub fn add_block_arg(&mut self, block: IlBlockId, width: u32) -> Result<IlValueId, IlError> {
        let blocks = self
            .blocks
            .as_ref()
            .ok_or_else(|| IlError::invalid_artefact(ECodeIr::FORM))?;
        let definition = blocks
            .get(block.index())
            .ok_or_else(|| IlError::range_out_of_bounds(block.index(), blocks.len()))?;
        if !definition.is_pending() {
            return Err(IlError::invalid_artefact(ECodeIr::FORM));
        }
        let value = self.push_block_arg_value(block, width)?;
        self.blocks
            .as_mut()
            .expect("block construction was checked before block-argument emission")[block.index()]
        .add_block_arg(value)?;
        Ok(value)
    }

    pub fn add_successor(
        &mut self,
        successor: IlBlockId,
        kinds: IlEdgeKinds,
        args: impl IntoIterator<Item = IlValueId>,
    ) -> Result<(), IlError> {
        let block = self
            .current_block
            .ok_or_else(|| IlError::invalid_artefact(ECodeIr::FORM))?;
        let blocks = self
            .blocks
            .as_ref()
            .ok_or_else(|| IlError::invalid_artefact(ECodeIr::FORM))?;
        let block_count = blocks.len();
        let source_block = blocks
            .get(block.index())
            .ok_or_else(|| IlError::range_out_of_bounds(block.index(), block_count))?;
        if !source_block.is_started() {
            return Err(IlError::invalid_artefact(ECodeIr::FORM));
        }
        let destination_block = blocks
            .get(successor.index())
            .ok_or_else(|| IlError::range_out_of_bounds(successor.index(), block_count))?;
        let args = args.into_iter().collect::<SmallVec<[_; 2]>>();
        let mut expected_block_args = destination_block.block_args().iter().copied();
        for &source_value_id in &args {
            let destination_value_id = expected_block_args
                .next()
                .ok_or_else(|| IlError::invalid_artefact(ECodeIr::FORM))?;
            let source_value = self.values.get(source_value_id.index()).ok_or_else(|| {
                IlError::range_out_of_bounds(source_value_id.index(), self.values.len())
            })?;
            let destination_value = &self.values[destination_value_id.index()];
            if source_value.width() != destination_value.width()
                || self.value_domains[source_value_id.index()]
                    != self.value_domains[destination_value_id.index()]
            {
                return Err(IlError::invalid_artefact(ECodeIr::FORM));
            }
        }
        if expected_block_args.next().is_some() {
            return Err(IlError::invalid_artefact(ECodeIr::FORM));
        }

        if !self.graph.blocks().is_empty() {
            let source_block = &self.graph.blocks()[block.index()];
            let successor_offset = source_block
                .successors()
                .slice(self.graph.successors())
                .iter()
                .position(|&target| target == successor)
                .ok_or_else(|| IlError::invalid_artefact(ECodeIr::FORM))?;
            let edge = source_block.successors().start() + successor_offset;
            if self.graph.successor_kinds()[edge] != kinds {
                return Err(IlError::invalid_artefact(ECodeIr::FORM));
            }
            if self.edge_args_set.contains(edge) {
                if self.edge_args[edge].slice(self.edge_arg_values.values()) != args.as_slice() {
                    return Err(IlError::invalid_artefact(ECodeIr::FORM));
                }
            } else {
                self.edge_args[edge] = self.edge_arg_values.append(args)?;
                self.edge_args_set.insert(edge);
            }
            return Ok(());
        }

        let source_block = self
            .blocks
            .as_mut()
            .expect("block construction was checked before successor validation")
            .get_mut(block.index())
            .ok_or_else(|| IlError::range_out_of_bounds(block.index(), block_count))?;
        source_block.add_successor(successor, kinds, args)
    }

    pub fn emit(
        &mut self,
        spec: ECodeOpSpec,
        operands: impl IntoIterator<Item = IlValueId>,
        result_count: usize,
    ) -> Result<ECodeOp, IlError> {
        if let Some(blocks) = &self.blocks {
            let block = self
                .current_block
                .ok_or_else(|| IlError::invalid_artefact(ECodeIr::FORM))?;
            if !blocks[block.index()].is_started() {
                return Err(IlError::invalid_artefact(ECodeIr::FORM));
            }
        }
        let operation = IlOpId::try_from_index(self.operations.len())?;
        let result_start = self.values.len();
        for _ in 0..result_count {
            self.values
                .push(ECodeValue::op_result(operation, spec.width()));
            self.value_domains.push(None);
        }
        let results = IlIndexRange::new(result_start, self.values.len())?;
        let operands = self.push_value_operands(operands)?;
        let mut record = ECodeOp::new(spec.opcode(), results, operands, spec.width())
            .with_immediate(spec.immediate());
        if let Some(address) = spec.address() {
            record.set_address(address);
        }
        if let Some(address_space) = spec.address_space() {
            if spec.opcode().requires_memory_domain() {
                self.intern_memory_domain(address_space);
            }
            record.set_address_space(address_space);
        }
        self.push_op(record)?;

        Ok(record)
    }

    pub fn emit_value(
        &mut self,
        spec: ECodeOpSpec,
        operands: impl IntoIterator<Item = IlValueId>,
    ) -> Result<IlValueId, IlError> {
        self.emit(spec, operands, 1)?
            .single_result()
            .ok_or_else(|| IlError::missing_component(ECodeIr::FORM, "single operation result"))
    }

    pub fn emit_effect(
        &mut self,
        spec: ECodeOpSpec,
        operands: impl IntoIterator<Item = IlValueId>,
    ) -> Result<ECodeOp, IlError> {
        self.emit(spec, operands, 0)
    }

    pub(crate) fn intern_memory_domain(&mut self, space: AddressSpaceId) {
        if self
            .memory_domains
            .iter()
            .any(|domain| domain.space() == space)
        {
            return;
        }

        self.memory_domains.push(ECodeMemoryDomain::new(space));
    }

    pub(crate) fn intern_constant(&mut self, value: &BitVec) -> u64 {
        self.constants.intern(&mut self.constant_storage, value)
    }

    fn push_block_arg_value(&mut self, block: IlBlockId, width: u32) -> Result<IlValueId, IlError> {
        let arg = IlBlockArgId::try_from_index(self.block_args.len())?;
        let value = IlValueId::try_from_index(self.values.len())?;

        self.values.push(ECodeValue::block_arg(arg, width));
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

    fn build_graph(&mut self) {
        let Some(blocks) = self.blocks.take() else {
            return;
        };
        if !self.graph.blocks().is_empty() {
            self.graph
                .set_op_ranges(
                    blocks
                        .iter()
                        .map(|block| block.ops().expect("ECode block construction was ended")),
                )
                .expect("imported ECode block count is unchanged");
            return;
        }
        let successor_count = blocks.iter().map(|block| block.successors().len()).sum();
        let mut graph_blocks = Vec::with_capacity(blocks.len());
        let mut successors = Vec::with_capacity(successor_count);
        let mut successor_kinds = Vec::with_capacity(successor_count);
        let mut block_sources = blocks
            .first()
            .and_then(ECodeBlockBuilder::source)
            .map(|_| Vec::with_capacity(blocks.len()));
        self.edge_args.reserve(successor_count);
        for block in blocks {
            let operations = block.ops().expect("ECode block construction was ended");
            let successor_start = successors.len();
            for edge in block.successors() {
                successors.push(edge.successor());
                successor_kinds.push(edge.kinds());
                self.push_edge_args(edge.args().iter().copied())
                    .expect("declared ECode edge arguments are representable");
            }
            let successor_range = IlIndexRange::new(successor_start, successors.len())
                .expect("declared ECode successor range is representable");
            graph_blocks.push(IlBlock::new(
                operations,
                successor_range,
                block.properties(),
            ));
            if let Some(sources) = &mut block_sources {
                sources.push(
                    block
                        .source()
                        .expect("declared ECode block source mode is consistent"),
                );
            }
        }
        let graph = IlGraph::new(graph_blocks, successors, successor_kinds);
        self.graph = match block_sources {
            Some(sources) => graph.with_block_sources(sources),
            None => graph,
        };
    }

    pub fn build(self) -> Result<ECodeIr, IlError> {
        if self
            .blocks
            .as_ref()
            .is_some_and(|blocks| blocks.iter().any(|block| !block.is_ended()))
        {
            return Err(IlError::invalid_artefact(ECodeIr::FORM));
        }
        let ir = self.build_unchecked();

        if ir.verify().is_err() {
            return Err(IlError::invalid_artefact(ECodeIr::FORM));
        }

        Ok(ir)
    }

    pub fn build_unchecked(mut self) -> ECodeIr {
        self.build_graph();
        if self.edge_args.is_empty() && !self.graph.successors().is_empty() {
            self.edge_args = vec![IlIndexRange::EMPTY; self.graph.successors().len()];
        }

        let mut ir = ECodeIr {
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
        };

        ir.shrink_to_fit();

        ir
    }
}
