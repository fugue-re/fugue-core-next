use fixedbitset::FixedBitSet;
use fugue_bv::BitVec;
use itertools::Itertools;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::il::common::{
    IlArtefact, IlBlock, IlBlockArgId, IlBlockId, IlBlockProperties, IlConstantInterner,
    IlEdgeKinds, IlError, IlGraph, IlIndexRange, IlMetadata, IlOpId, IlParentSpan, IlPool,
    IlSourceSpan, IlValueId,
};
use crate::il::mcode::ir::MCodeIr;
use crate::il::mcode::{
    MCodeBlockArg, MCodeMemoryDomain, MCodeOp, MCodeOpSpec, MCodeOpcode, MCodeResultSpec,
    MCodeValue, MCodeVar, MCodeVarId, MCodeVarKind, MCodeVersion,
};
use crate::ir::Address;
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug)]
struct MCodeBlockBuilder {
    block_args: SmallVec<[IlValueId; 2]>,
    properties: IlBlockProperties,
    source: Option<Address>,
    state: MCodeBlockBuilderState,
    successors: SmallVec<[MCodeBlockSuccessor; 2]>,
}

#[derive(Debug, Copy, Clone)]
enum MCodeBlockBuilderState {
    Pending,
    Started { operation_start: usize },
    Ended { operations: IlIndexRange },
}

impl MCodeBlockBuilderState {
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
struct MCodeBlockSuccessor {
    args: SmallVec<[IlValueId; 2]>,
    kinds: IlEdgeKinds,
    successor: IlBlockId,
}

impl MCodeBlockBuilder {
    fn new(properties: IlBlockProperties, source: impl Into<Option<Address>>) -> Self {
        Self {
            block_args: SmallVec::new(),
            properties,
            source: source.into(),
            state: MCodeBlockBuilderState::pending(),
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

    fn successors(&self) -> &[MCodeBlockSuccessor] {
        &self.successors
    }

    fn add_block_arg(&mut self, value: IlValueId) -> Result<(), IlError> {
        if !self.state.is_pending() {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
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
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        let combined_kinds = self
            .successors
            .iter()
            .find(|edge| edge.successor() == successor)
            .map_or(kinds, |edge| edge.kinds() | kinds);
        let has_repeated_singular_kind = self
            .successors
            .iter()
            .filter(|edge| edge.successor() != successor)
            .any(|edge| {
                edge.kinds()
                    .intersects(combined_kinds & IlEdgeKinds::SINGULAR)
            });
        if combined_kinds.is_empty() || has_repeated_singular_kind {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        if let Some(edge) = self
            .successors
            .iter_mut()
            .find(|edge| edge.successor() == successor)
        {
            return edge.merge(kinds, args);
        }
        self.successors
            .push(MCodeBlockSuccessor::new(successor, kinds, args)?);
        Ok(())
    }

    fn begin(&mut self, operation_start: usize) -> Result<(), IlError> {
        if !self.state.is_pending() {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        self.state = MCodeBlockBuilderState::started(operation_start);
        Ok(())
    }

    fn end(&mut self, operation_end: usize) -> Result<(), IlError> {
        let MCodeBlockBuilderState::Started { operation_start } = self.state else {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        };
        let operations = IlIndexRange::new(operation_start, operation_end)?;
        self.state = MCodeBlockBuilderState::ended(operations);
        Ok(())
    }
}

impl MCodeBlockSuccessor {
    fn new(
        successor: IlBlockId,
        kinds: IlEdgeKinds,
        args: SmallVec<[IlValueId; 2]>,
    ) -> Result<Self, IlError> {
        if kinds.is_empty() {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
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
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        self.kinds |= kinds;
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MCodeAliasedWriteResults {
    memory: IlValueId,
    variable: IlValueId,
}

impl MCodeAliasedWriteResults {
    fn new(results: IlIndexRange) -> Result<Self, IlError> {
        let Some((memory, variable)) = results.collect_tuple() else {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        };
        Ok(Self {
            memory: IlValueId::try_from_index(memory)?,
            variable: IlValueId::try_from_index(variable)?,
        })
    }

    pub const fn memory(&self) -> IlValueId {
        self.memory
    }

    pub const fn variable(&self) -> IlValueId {
        self.variable
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MCodeCallResults {
    memory: IlValueId,
    outputs: IlIndexRange,
}

impl MCodeCallResults {
    fn new(mut outputs: IlIndexRange) -> Result<Self, IlError> {
        let Some(memory) = outputs.next() else {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        };
        Ok(Self {
            memory: IlValueId::try_from_index(memory)?,
            outputs,
        })
    }

    pub const fn memory(&self) -> IlValueId {
        self.memory
    }

    pub const fn outputs(&self) -> IlIndexRange {
        self.outputs
    }
}

#[derive(Debug)]
pub struct MCodeBuilder {
    metadata: IlMetadata,
    graph: IlGraph,
    blocks: Option<Vec<MCodeBlockBuilder>>,
    current_block: Option<IlBlockId>,
    primary_source_spans: Vec<IlSourceSpan>,
    supplemental_source_spans: Vec<IlSourceSpan>,
    primary_parent_spans: Vec<IlParentSpan>,
    supplemental_parent_spans: Vec<IlParentSpan>,
    variables: Vec<MCodeVar>,
    variable_ids: FxHashMap<MCodeVar, MCodeVarId>,
    variable_versions: Vec<MCodeVersion>,
    variable_widths: Vec<Option<u32>>,
    aliased_variables: Vec<MCodeVarId>,
    values: Vec<MCodeValue>,
    block_args: Vec<MCodeBlockArg>,
    edge_args: Vec<IlIndexRange>,
    edge_args_set: FixedBitSet,
    edge_arg_values: IlPool<IlValueId>,
    operations: Vec<MCodeOp>,
    value_operands: IlPool<IlValueId>,
    memory_domains: Vec<MCodeMemoryDomain>,
    constant_storage: Vec<u8>,
    constants: IlConstantInterner,
}

impl MCodeBuilder {
    pub fn new(metadata: IlMetadata) -> Self {
        Self {
            metadata,
            graph: IlGraph::default(),
            blocks: None,
            current_block: None,
            primary_source_spans: Vec::new(),
            supplemental_source_spans: Vec::new(),
            primary_parent_spans: Vec::new(),
            supplemental_parent_spans: Vec::new(),
            variables: Vec::new(),
            variable_ids: FxHashMap::default(),
            variable_versions: Vec::new(),
            variable_widths: Vec::new(),
            aliased_variables: Vec::new(),
            values: Vec::new(),
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
                    .expect("imported MCode block id is representable");
                MCodeBlockBuilder::from_graph(&graph, block)
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

    fn is_aliased(&self, variable: MCodeVarId) -> bool {
        self.aliased_variables.binary_search(&variable).is_ok()
    }

    pub fn op_count(&self) -> usize {
        self.operations.len()
    }

    fn value(&self, value: IlValueId) -> Result<&MCodeValue, IlError> {
        self.values
            .get(value.index())
            .ok_or_else(|| IlError::range_out_of_bounds(value.index(), self.values.len()))
    }

    fn variable_width(&self, variable: MCodeVarId) -> Result<Option<u32>, IlError> {
        self.variable_widths
            .get(variable.index())
            .copied()
            .ok_or_else(|| IlError::range_out_of_bounds(variable.index(), self.variables.len()))
    }

    pub fn set_source_spans(&mut self, source_spans: Vec<IlSourceSpan>) {
        self.primary_source_spans = source_spans;
    }

    pub fn with_source_spans(mut self, source_spans: Vec<IlSourceSpan>) -> Self {
        self.set_source_spans(source_spans);
        self
    }

    pub fn set_parent_spans(&mut self, parent_spans: Vec<IlParentSpan>) {
        self.primary_parent_spans = parent_spans;
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

    pub fn add_variable(&mut self, variable: MCodeVar) -> Result<MCodeVarId, IlError> {
        self.intern_variable(variable)
    }

    pub fn add_aliased_variable(&mut self, variable: MCodeVarId) -> Result<(), IlError> {
        let variable_kind = self
            .variables
            .get(variable.index())
            .map(MCodeVar::kind)
            .ok_or_else(|| IlError::range_out_of_bounds(variable.index(), self.variables.len()))?;
        if variable_kind != MCodeVarKind::Stack {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        match self.aliased_variables.binary_search(&variable) {
            Ok(_) => {}
            Err(index) => self.aliased_variables.insert(index, variable),
        }
        Ok(())
    }

    pub(crate) fn add_memory_domain(&mut self, space: AddressSpaceId) {
        self.intern_memory_domain(space);
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
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        let definition = MCodeBlockBuilder::new(properties, source);
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
                .ok_or_else(|| IlError::invalid_artefact(MCodeIr::FORM))?;
            if blocks[current.index()].is_started() {
                return Err(IlError::invalid_artefact(MCodeIr::FORM));
            }
        }

        let blocks = self
            .blocks
            .as_ref()
            .ok_or_else(|| IlError::invalid_artefact(MCodeIr::FORM))?;
        let block_count = blocks.len();
        let definition = blocks
            .get(block.index())
            .ok_or_else(|| IlError::range_out_of_bounds(block.index(), block_count))?;
        if !definition.is_pending() {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }

        self.current_block = Some(block);
        Ok(())
    }

    pub fn begin_block(&mut self) -> Result<(), IlError> {
        let block = self
            .current_block
            .ok_or_else(|| IlError::invalid_artefact(MCodeIr::FORM))?;
        let blocks = self
            .blocks
            .as_mut()
            .ok_or_else(|| IlError::invalid_artefact(MCodeIr::FORM))?;
        blocks[block.index()].begin(self.operations.len())
    }

    pub fn end_block(&mut self) -> Result<(), IlError> {
        let block = self
            .current_block
            .ok_or_else(|| IlError::invalid_artefact(MCodeIr::FORM))?;
        let blocks = self
            .blocks
            .as_mut()
            .ok_or_else(|| IlError::invalid_artefact(MCodeIr::FORM))?;
        blocks[block.index()].end(self.operations.len())
    }

    pub fn add_block_arg(&mut self, block: IlBlockId, width: u32) -> Result<IlValueId, IlError> {
        let blocks = self
            .blocks
            .as_ref()
            .ok_or_else(|| IlError::invalid_artefact(MCodeIr::FORM))?;
        let definition = blocks
            .get(block.index())
            .ok_or_else(|| IlError::range_out_of_bounds(block.index(), blocks.len()))?;
        if !definition.is_pending() {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        let arg = IlBlockArgId::try_from_index(self.block_args.len())?;
        let value = IlValueId::try_from_index(self.values.len())?;
        let value_record = MCodeValue::block_arg(arg, width)
            .ok_or_else(|| IlError::width_mismatch(MCodeIr::FORM))?;
        self.values.push(value_record);
        self.block_args
            .push(MCodeBlockArg::new(block, value, width));
        self.blocks
            .as_mut()
            .expect("block construction was checked before block-argument emission")[block.index()]
        .add_block_arg(value)?;
        Ok(value)
    }

    pub fn add_variable_block_arg(
        &mut self,
        block: IlBlockId,
        variable: MCodeVarId,
        width: u32,
    ) -> Result<IlValueId, IlError> {
        let variable_width = self.variable_width(variable)?;
        if variable_width.is_some_and(|variable_width| variable_width != width) {
            return Err(IlError::width_mismatch(MCodeIr::FORM));
        }
        let version = self.variable_versions[variable.index()]
            .checked_next()
            .ok_or_else(|| IlError::id_exhausted("MCode version"))?;
        let value = self.add_block_arg(block, width)?;
        self.values[value.index()].set_binding(variable, version);
        self.variable_versions[variable.index()] = version;
        self.variable_widths[variable.index()] = Some(width);
        Ok(value)
    }

    pub fn add_memory_block_arg(
        &mut self,
        block: IlBlockId,
        space: AddressSpaceId,
    ) -> Result<IlValueId, IlError> {
        let value = self.add_block_arg(block, 0)?;
        self.values[value.index()].set_memory_domain(space);
        self.intern_memory_domain(space);
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
            .ok_or_else(|| IlError::invalid_artefact(MCodeIr::FORM))?;
        let blocks = self
            .blocks
            .as_ref()
            .ok_or_else(|| IlError::invalid_artefact(MCodeIr::FORM))?;
        let block_count = blocks.len();
        let source_block = blocks
            .get(block.index())
            .ok_or_else(|| IlError::range_out_of_bounds(block.index(), block_count))?;
        if !source_block.is_started() {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        let destination_block = blocks
            .get(successor.index())
            .ok_or_else(|| IlError::range_out_of_bounds(successor.index(), block_count))?;
        let args = args.into_iter().collect::<SmallVec<[_; 2]>>();
        let mut expected_block_args = destination_block.block_args().iter().copied();
        for &source_value_id in &args {
            let destination_value_id = expected_block_args
                .next()
                .ok_or_else(|| IlError::invalid_artefact(MCodeIr::FORM))?;
            let source_value = self.values.get(source_value_id.index()).ok_or_else(|| {
                IlError::range_out_of_bounds(source_value_id.index(), self.values.len())
            })?;
            let destination_value = &self.values[destination_value_id.index()];
            if source_value.width() != destination_value.width()
                || source_value.variable() != destination_value.variable()
                || source_value.memory_domain() != destination_value.memory_domain()
            {
                return Err(IlError::invalid_artefact(MCodeIr::FORM));
            }
        }
        if expected_block_args.next().is_some() {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }

        if !self.graph.blocks().is_empty() {
            let source_block = &self.graph.blocks()[block.index()];
            let successor_offset = source_block
                .successors()
                .slice(self.graph.successors())
                .iter()
                .position(|&target| target == successor)
                .ok_or_else(|| IlError::invalid_artefact(MCodeIr::FORM))?;
            let edge = source_block.successors().start() + successor_offset;
            if self.graph.successor_kinds()[edge] != kinds {
                return Err(IlError::invalid_artefact(MCodeIr::FORM));
            }
            if self.edge_args_set.contains(edge) {
                if self.edge_args[edge].slice(self.edge_arg_values.values()) != args.as_slice() {
                    return Err(IlError::invalid_artefact(MCodeIr::FORM));
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

    pub fn emit_constant(&mut self, value: &BitVec) -> Result<IlValueId, IlError> {
        let immediate = self.intern_constant(value);
        self.emit_value(
            MCodeOpSpec::new(MCodeOpcode::Constant, value.bits()).with_immediate(immediate),
            [],
            MCodeResultSpec::new(value.bits()),
        )
    }

    pub fn emit_undefined(&mut self, discriminant: u64, width: u32) -> Result<IlValueId, IlError> {
        if width == 0 {
            return Err(IlError::width_mismatch(MCodeIr::FORM));
        }
        self.emit_op(
            MCodeOpSpec::new(MCodeOpcode::Undefined, width).with_immediate(discriminant),
            [],
            [MCodeResultSpec::new(width)],
        )?
        .single_result()
        .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "single operation result"))
    }

    pub fn emit_variable_undefined(
        &mut self,
        variable: MCodeVarId,
        width: u32,
    ) -> Result<IlValueId, IlError> {
        if width == 0 {
            return Err(IlError::width_mismatch(MCodeIr::FORM));
        }
        self.emit_op(
            MCodeOpSpec::new(MCodeOpcode::Undefined, width),
            [],
            [MCodeResultSpec::new(width).with_variable(variable)],
        )?
        .single_result()
        .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "single operation result"))
    }

    pub fn emit_memory_undefined(&mut self, space: AddressSpaceId) -> Result<IlValueId, IlError> {
        self.emit_op(
            MCodeOpSpec::new(MCodeOpcode::Undefined, 0).with_immediate(u64::from(space.value())),
            [],
            [MCodeResultSpec::new(0)],
        )?
        .single_result()
        .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "single operation result"))
    }

    pub fn emit_variable_assignment(
        &mut self,
        variable: MCodeVarId,
        value: IlValueId,
    ) -> Result<IlValueId, IlError> {
        if self.is_aliased(variable) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        let width = self.value(value)?.width();
        self.emit_value(
            MCodeOpSpec::new(MCodeOpcode::SetVar, width).with_variable(variable),
            [value],
            MCodeResultSpec::new(width).with_variable(variable),
        )
    }

    pub fn emit_variable_field_assignment(
        &mut self,
        previous: IlValueId,
        value: IlValueId,
        field_offset: u64,
    ) -> Result<IlValueId, IlError> {
        let previous_value = self.value(previous)?;
        let variable = previous_value
            .variable()
            .ok_or_else(|| IlError::invalid_artefact(MCodeIr::FORM))?;
        let full_width = previous_value.width();
        if self.is_aliased(variable) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        let width = self.value(value)?.width();
        if !field_offset
            .checked_add(u64::from(width))
            .is_some_and(|end| end <= u64::from(full_width))
        {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        self.emit_value(
            MCodeOpSpec::new(MCodeOpcode::SetVarField, width)
                .with_variable(variable)
                .with_immediate(field_offset),
            [previous, value],
            MCodeResultSpec::new(full_width).with_variable(variable),
        )
    }

    pub fn emit_aliased_variable_read(
        &mut self,
        variable: MCodeVarId,
        width: u32,
        memory: IlValueId,
        space: AddressSpaceId,
    ) -> Result<IlValueId, IlError> {
        self.variable_width(variable)?;
        if !self.is_aliased(variable) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        let memory_value = self.value(memory)?;
        if memory_value.width() != 0 {
            return Err(IlError::width_mismatch(MCodeIr::FORM));
        }
        if memory_value.memory_domain() != Some(space) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        self.emit_value(
            MCodeOpSpec::new(MCodeOpcode::VarAliased, width)
                .with_variable(variable)
                .with_address_space(space),
            [memory],
            MCodeResultSpec::new(width).with_variable(variable),
        )
    }

    pub fn emit_aliased_variable_field_read(
        &mut self,
        variable: MCodeVarId,
        field_offset: u64,
        width: u32,
        memory: IlValueId,
        space: AddressSpaceId,
    ) -> Result<IlValueId, IlError> {
        let full_width = self
            .variable_width(variable)?
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "variable width"))?;
        if !self.is_aliased(variable) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        let memory_value = self.value(memory)?;
        if memory_value.width() != 0 {
            return Err(IlError::width_mismatch(MCodeIr::FORM));
        }
        if memory_value.memory_domain() != Some(space) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        if !field_offset
            .checked_add(u64::from(width))
            .is_some_and(|end| end <= u64::from(full_width))
        {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        self.emit_value(
            MCodeOpSpec::new(MCodeOpcode::VarAliasedField, width)
                .with_variable(variable)
                .with_immediate(field_offset)
                .with_address_space(space),
            [memory],
            MCodeResultSpec::new(width),
        )
    }

    pub fn emit_aliased_variable_write(
        &mut self,
        variable: MCodeVarId,
        value: IlValueId,
        memory: IlValueId,
        space: AddressSpaceId,
    ) -> Result<MCodeAliasedWriteResults, IlError> {
        self.variable_width(variable)?;
        if !self.is_aliased(variable) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        let width = self.value(value)?.width();
        let memory_value = self.value(memory)?;
        if memory_value.width() != 0 {
            return Err(IlError::width_mismatch(MCodeIr::FORM));
        }
        if memory_value.memory_domain() != Some(space) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        let operation = self.emit_op(
            MCodeOpSpec::new(MCodeOpcode::SetVarAliased, width)
                .with_variable(variable)
                .with_address_space(space),
            [value, memory],
            [
                MCodeResultSpec::new(0),
                MCodeResultSpec::new(width).with_variable(variable),
            ],
        )?;
        let results = MCodeAliasedWriteResults::new(operation.results())?;
        Ok(results)
    }

    pub fn emit_aliased_variable_field_write(
        &mut self,
        variable: MCodeVarId,
        value: IlValueId,
        field_offset: u64,
        full_width: u32,
        memory: IlValueId,
        space: AddressSpaceId,
    ) -> Result<MCodeAliasedWriteResults, IlError> {
        let existing_width = self.variable_width(variable)?;
        if !self.is_aliased(variable) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        let width = self.value(value)?.width();
        let memory_value = self.value(memory)?;
        if memory_value.width() != 0 {
            return Err(IlError::width_mismatch(MCodeIr::FORM));
        }
        if memory_value.memory_domain() != Some(space) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        if existing_width.is_some_and(|existing_width| existing_width != full_width) {
            return Err(IlError::width_mismatch(MCodeIr::FORM));
        }
        if !field_offset
            .checked_add(u64::from(width))
            .is_some_and(|end| end <= u64::from(full_width))
        {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        let operation = self.emit_op(
            MCodeOpSpec::new(MCodeOpcode::SetVarAliasedField, width)
                .with_variable(variable)
                .with_immediate(field_offset)
                .with_address_space(space),
            [value, memory],
            [
                MCodeResultSpec::new(0),
                MCodeResultSpec::new(full_width).with_variable(variable),
            ],
        )?;
        let results = MCodeAliasedWriteResults::new(operation.results())?;
        Ok(results)
    }

    pub fn emit_variable_address(
        &mut self,
        variable: MCodeVarId,
        pointer_width: u32,
    ) -> Result<IlValueId, IlError> {
        self.variable_width(variable)?;
        if !self.is_aliased(variable) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        self.emit_value(
            MCodeOpSpec::new(MCodeOpcode::AddressOf, pointer_width).with_variable(variable),
            [],
            MCodeResultSpec::new(pointer_width),
        )
    }

    pub fn emit_variable_field_address(
        &mut self,
        variable: MCodeVarId,
        field_offset: u64,
        pointer_width: u32,
    ) -> Result<IlValueId, IlError> {
        let full_width = self
            .variable_width(variable)?
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "variable width"))?;
        if !self.is_aliased(variable) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        if field_offset >= u64::from(full_width) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        self.emit_value(
            MCodeOpSpec::new(MCodeOpcode::AddressOfField, pointer_width)
                .with_variable(variable)
                .with_immediate(field_offset),
            [],
            MCodeResultSpec::new(pointer_width),
        )
    }

    pub fn emit_load(
        &mut self,
        pointer: IlValueId,
        width: u32,
        memory: IlValueId,
        space: AddressSpaceId,
    ) -> Result<IlValueId, IlError> {
        self.value(pointer)?;
        let memory_value = self.value(memory)?;
        if memory_value.width() != 0 {
            return Err(IlError::width_mismatch(MCodeIr::FORM));
        }
        if memory_value.memory_domain() != Some(space) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        self.emit_value(
            MCodeOpSpec::new(MCodeOpcode::Load, width).with_address_space(space),
            [pointer, memory],
            MCodeResultSpec::new(width),
        )
    }

    pub fn emit_store(
        &mut self,
        pointer: IlValueId,
        value: IlValueId,
        memory: IlValueId,
        space: AddressSpaceId,
    ) -> Result<IlValueId, IlError> {
        self.value(pointer)?;
        self.value(value)?;
        let memory_value = self.value(memory)?;
        if memory_value.width() != 0 {
            return Err(IlError::width_mismatch(MCodeIr::FORM));
        }
        if memory_value.memory_domain() != Some(space) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        let value = self.emit_value(
            MCodeOpSpec::new(MCodeOpcode::Store, 0).with_address_space(space),
            [pointer, value, memory],
            MCodeResultSpec::new(0),
        )?;
        Ok(value)
    }

    pub fn emit_call(
        &mut self,
        target: Address,
        args: impl IntoIterator<Item = IlValueId>,
        memory: IlValueId,
        outputs: impl IntoIterator<Item = MCodeResultSpec>,
    ) -> Result<MCodeCallResults, IlError> {
        let space = target.space();
        let memory_value = self.value(memory)?;
        if memory_value.width() != 0 {
            return Err(IlError::width_mismatch(MCodeIr::FORM));
        }
        if memory_value.memory_domain() != Some(space) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        let mut results = SmallVec::<[_; 4]>::new();
        results.push(MCodeResultSpec::new(0));
        results.extend(outputs);
        let operation = self.emit_op(
            MCodeOpSpec::new(MCodeOpcode::Call, 0)
                .with_address(target)
                .with_address_space(space),
            args.into_iter().chain([memory]),
            &results,
        )?;
        let results = MCodeCallResults::new(operation.results())?;
        Ok(results)
    }

    pub fn emit_call_indirect(
        &mut self,
        target: IlValueId,
        args: impl IntoIterator<Item = IlValueId>,
        memory: IlValueId,
        space: AddressSpaceId,
        outputs: impl IntoIterator<Item = MCodeResultSpec>,
    ) -> Result<MCodeCallResults, IlError> {
        self.value(target)?;
        let memory_value = self.value(memory)?;
        if memory_value.width() != 0 {
            return Err(IlError::width_mismatch(MCodeIr::FORM));
        }
        if memory_value.memory_domain() != Some(space) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        let mut results = SmallVec::<[_; 4]>::new();
        results.push(MCodeResultSpec::new(0));
        results.extend(outputs);
        let operation = self.emit_op(
            MCodeOpSpec::new(MCodeOpcode::CallIndirect, 0).with_address_space(space),
            [target].into_iter().chain(args).chain([memory]),
            &results,
        )?;
        let results = MCodeCallResults::new(operation.results())?;
        Ok(results)
    }

    pub fn emit_tail_call(
        &mut self,
        target: Address,
        args: impl IntoIterator<Item = IlValueId>,
        memory: IlValueId,
    ) -> Result<MCodeOp, IlError> {
        let space = target.space();
        let memory_value = self.value(memory)?;
        if memory_value.width() != 0 {
            return Err(IlError::width_mismatch(MCodeIr::FORM));
        }
        if memory_value.memory_domain() != Some(space) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        self.emit_op(
            MCodeOpSpec::new(MCodeOpcode::TailCall, 0)
                .with_address(target)
                .with_address_space(space),
            args.into_iter().chain([memory]),
            [],
        )
    }

    pub fn emit_tail_call_indirect(
        &mut self,
        target: IlValueId,
        args: impl IntoIterator<Item = IlValueId>,
        memory: IlValueId,
        space: AddressSpaceId,
    ) -> Result<MCodeOp, IlError> {
        self.value(target)?;
        let memory_value = self.value(memory)?;
        if memory_value.width() != 0 {
            return Err(IlError::width_mismatch(MCodeIr::FORM));
        }
        if memory_value.memory_domain() != Some(space) {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        self.emit_op(
            MCodeOpSpec::new(MCodeOpcode::TailCallIndirect, 0).with_address_space(space),
            [target].into_iter().chain(args).chain([memory]),
            [],
        )
    }

    pub(crate) fn emit_op(
        &mut self,
        spec: MCodeOpSpec,
        operands: impl IntoIterator<Item = IlValueId>,
        results: impl AsRef<[MCodeResultSpec]>,
    ) -> Result<MCodeOp, IlError> {
        if let Some(blocks) = &self.blocks {
            let block = self
                .current_block
                .ok_or_else(|| IlError::invalid_artefact(MCodeIr::FORM))?;
            if !blocks[block.index()].is_started() {
                return Err(IlError::invalid_artefact(MCodeIr::FORM));
            }
        }
        let results = results.as_ref();
        let result_start = self.values.len();
        let result_end = result_start
            .checked_add(results.len())
            .ok_or_else(|| IlError::integer_overflow("MCode result range"))?;
        let result_range = IlIndexRange::new(result_start, result_end)?;
        let operation = IlOpId::try_from_index(self.operations.len())?;
        let memory_result_domain = match spec.opcode() {
            MCodeOpcode::Undefined if spec.width() == 0 => {
                let space = u16::try_from(spec.immediate())
                    .map(AddressSpaceId::from)
                    .map_err(|_| IlError::invalid_artefact(MCodeIr::FORM))?;
                Some(space)
            }
            MCodeOpcode::Store
            | MCodeOpcode::SetVarAliased
            | MCodeOpcode::SetVarAliasedField
            | MCodeOpcode::Call
            | MCodeOpcode::CallIndirect => spec.address_space(),
            _ => None,
        };
        let memory_domain = if spec.opcode().requires_memory_domain() {
            spec.address_space()
        } else {
            memory_result_domain
        };
        if memory_result_domain.is_some()
            && results.first().is_some_and(|result| result.width() != 0)
        {
            return Err(IlError::width_mismatch(MCodeIr::FORM));
        }
        match results {
            [] => {}
            [result] => {
                let mut value = MCodeValue::op_result(operation, result.width())
                    .ok_or_else(|| IlError::width_mismatch(MCodeIr::FORM))?;
                if let Some(space) = memory_result_domain {
                    value.set_memory_domain(space);
                }
                let binding = match result.variable() {
                    Some(variable) => {
                        let width =
                            self.variable_widths.get(variable.index()).ok_or_else(|| {
                                IlError::range_out_of_bounds(variable.index(), self.variables.len())
                            })?;
                        if width.is_some_and(|width| width != result.width()) {
                            return Err(IlError::width_mismatch(MCodeIr::FORM));
                        }
                        let version = self.variable_versions[variable.index()]
                            .checked_next()
                            .ok_or_else(|| IlError::id_exhausted("MCode version"))?;
                        Some((variable, version))
                    }
                    None => None,
                };
                if let Some((variable, version)) = binding {
                    value.set_binding(variable, version);
                    self.variable_versions[variable.index()] = version;
                    self.variable_widths[variable.index()] = Some(result.width());
                }
                self.values.push(value);
            }
            _ => {
                for result in results {
                    if MCodeValue::op_result(operation, result.width()).is_none() {
                        return Err(IlError::width_mismatch(MCodeIr::FORM));
                    }
                }
                let mut bindings = results
                    .iter()
                    .filter_map(|result| {
                        result.variable().map(|variable| (variable, result.width()))
                    })
                    .collect::<SmallVec<[_; 2]>>();
                bindings.sort_unstable_by_key(|(variable, _)| *variable);
                let mut binding_start = 0;
                while binding_start < bindings.len() {
                    let (variable, width) = bindings[binding_start];
                    let variable_width =
                        self.variable_widths.get(variable.index()).ok_or_else(|| {
                            IlError::range_out_of_bounds(variable.index(), self.variables.len())
                        })?;
                    let mut binding_end = binding_start + 1;
                    while binding_end < bindings.len() && bindings[binding_end].0 == variable {
                        if bindings[binding_end].1 != width {
                            return Err(IlError::width_mismatch(MCodeIr::FORM));
                        }
                        binding_end += 1;
                    }
                    if variable_width.is_some_and(|variable_width| variable_width != width) {
                        return Err(IlError::width_mismatch(MCodeIr::FORM));
                    }
                    let mut version = self.variable_versions[variable.index()];
                    for _ in binding_start..binding_end {
                        version = version
                            .checked_next()
                            .ok_or_else(|| IlError::id_exhausted("MCode version"))?;
                    }
                    binding_start = binding_end;
                }
                self.values.reserve(results.len());
                for (offset, result) in results.iter().enumerate() {
                    let mut value = MCodeValue::op_result(operation, result.width())
                        .expect("MCode result widths were validated before emission");
                    if offset == 0
                        && let Some(space) = memory_result_domain
                    {
                        value.set_memory_domain(space);
                    }
                    if let Some(variable) = result.variable() {
                        let version = self.variable_versions[variable.index()]
                            .checked_next()
                            .expect("MCode result versions were validated before emission");
                        value.set_binding(variable, version);
                        self.variable_versions[variable.index()] = version;
                        self.variable_widths[variable.index()] = Some(result.width());
                    }
                    self.values.push(value);
                }
            }
        }
        let operands = self.push_value_operands(operands)?;
        if let Some(space) = memory_domain {
            self.intern_memory_domain(space);
        }
        let mut record = MCodeOp::new(spec.opcode(), result_range, operands, spec.width());
        if let Some(variable) = spec.variable() {
            record.set_variable(variable);
        }
        record.set_immediate(spec.immediate());
        if let Some(address) = spec.address() {
            record.set_address(address);
        }
        if let Some(address_space) = spec.address_space() {
            record.set_address_space(address_space);
        }
        self.push_op(record)?;

        Ok(record)
    }

    pub fn emit_value(
        &mut self,
        spec: MCodeOpSpec,
        operands: impl IntoIterator<Item = IlValueId>,
        result: MCodeResultSpec,
    ) -> Result<IlValueId, IlError> {
        if spec.opcode() == MCodeOpcode::Undefined {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        self.emit_op(spec, operands, [result])?
            .single_result()
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "single operation result"))
    }

    pub fn emit_effect(
        &mut self,
        spec: MCodeOpSpec,
        operands: impl IntoIterator<Item = IlValueId>,
    ) -> Result<MCodeOp, IlError> {
        self.emit_op(spec, operands, [])
    }

    pub(crate) fn add_source_span(&mut self, source_span: IlSourceSpan) {
        self.supplemental_source_spans.push(source_span);
    }

    pub(crate) fn extend_source_spans(
        &mut self,
        source_spans: impl IntoIterator<Item = IlSourceSpan>,
    ) {
        let source_spans = source_spans.into_iter();
        self.supplemental_source_spans
            .reserve(source_spans.size_hint().0);
        for source_span in source_spans {
            self.add_source_span(source_span);
        }
    }

    pub(crate) fn add_parent_span(&mut self, parent_span: IlParentSpan) {
        self.supplemental_parent_spans.push(parent_span);
    }

    pub(crate) fn extend_parent_spans(
        &mut self,
        parent_spans: impl IntoIterator<Item = IlParentSpan>,
    ) {
        let parent_spans = parent_spans.into_iter();
        self.supplemental_parent_spans
            .reserve(parent_spans.size_hint().0);
        for parent_span in parent_spans {
            self.add_parent_span(parent_span);
        }
    }

    pub(crate) fn intern_constant(&mut self, value: &BitVec) -> u64 {
        self.constants.intern(&mut self.constant_storage, value)
    }

    fn intern_variable(&mut self, variable: MCodeVar) -> Result<MCodeVarId, IlError> {
        if let Some(id) = self.variable_ids.get(&variable) {
            return Ok(*id);
        }
        let id = MCodeVarId::try_from_index(self.variables.len())?;
        self.variables.push(variable);
        self.variable_ids.insert(variable, id);
        self.variable_versions.push(MCodeVersion::new(0));
        self.variable_widths.push(None);
        Ok(id)
    }

    fn push_op(&mut self, operation: MCodeOp) -> Result<IlOpId, IlError> {
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

    pub(crate) fn intern_memory_domain(&mut self, space: AddressSpaceId) {
        if self
            .memory_domains
            .iter()
            .any(|domain| domain.space() == space)
        {
            return;
        }

        self.memory_domains.push(MCodeMemoryDomain::new(space));
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
                        .map(|block| block.ops().expect("MCode block construction was ended")),
                )
                .expect("imported MCode block count is unchanged");
            return;
        }
        let successor_count = blocks.iter().map(|block| block.successors().len()).sum();
        let mut graph_blocks = Vec::with_capacity(blocks.len());
        let mut successors = Vec::with_capacity(successor_count);
        let mut successor_kinds = Vec::with_capacity(successor_count);
        let mut block_sources = blocks
            .first()
            .and_then(MCodeBlockBuilder::source)
            .map(|_| Vec::with_capacity(blocks.len()));
        self.edge_args.reserve(successor_count);
        for block in blocks {
            let operations = block.ops().expect("MCode block construction was ended");
            let successor_start = successors.len();
            for edge in block.successors() {
                successors.push(edge.successor());
                successor_kinds.push(edge.kinds());
                self.push_edge_args(edge.args().iter().copied())
                    .expect("declared MCode edge arguments are representable");
            }
            let successor_range = IlIndexRange::new(successor_start, successors.len())
                .expect("declared MCode successor range is representable");
            graph_blocks.push(IlBlock::new(
                operations,
                successor_range,
                block.properties(),
            ));
            if let Some(sources) = &mut block_sources {
                sources.push(
                    block
                        .source()
                        .expect("declared MCode block source mode is consistent"),
                );
            }
        }
        let graph = IlGraph::new(graph_blocks, successors, successor_kinds);
        self.graph = match block_sources {
            Some(sources) => graph.with_block_sources(sources),
            None => graph,
        };
    }

    pub fn build(self) -> Result<MCodeIr, IlError> {
        if self
            .blocks
            .as_ref()
            .is_some_and(|blocks| blocks.iter().any(|block| !block.is_ended()))
        {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }
        let ir = self.build_unchecked();

        if ir.verify().is_err() {
            return Err(IlError::invalid_artefact(MCodeIr::FORM));
        }

        Ok(ir)
    }

    pub fn build_unchecked(mut self) -> MCodeIr {
        self.build_graph();
        if self.edge_args.is_empty() && !self.graph.successors().is_empty() {
            self.edge_args = vec![IlIndexRange::EMPTY; self.graph.successors().len()];
        }

        let mut ir = MCodeIr {
            metadata: self.metadata,
            graph: self.graph,
            primary_source_spans: self.primary_source_spans,
            supplemental_source_spans: self.supplemental_source_spans,
            primary_parent_spans: self.primary_parent_spans,
            supplemental_parent_spans: self.supplemental_parent_spans,
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
        };

        ir.shrink_to_fit();

        ir
    }
}
