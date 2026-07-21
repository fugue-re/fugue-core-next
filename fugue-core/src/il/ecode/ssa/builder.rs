use fugue_bv::BitVec;
use rustc_hash::FxHashMap;

use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlBlock, IlBlockId, IlDominance, IlDominanceFrontier, IlError, IlGraph, IlHeader,
    IlIndexRange, IlLevel, IlOpId, IlParentSpan, IlPool, IlSchemaVersion, IlSourceSpan, IlValueId,
};
use crate::il::ecode::ssa::format::ECodeSsaIrDisplay;
use crate::il::ecode::ssa::{
    ECodeSsaBlockArg, ECodeSsaLiveness, ECodeSsaMemoryDomain, ECodeSsaOp, ECodeSsaOpcode,
    ECodeSsaUses, ECodeSsaValue, ECodeSsaValueKind,
};
use crate::ir::{Address, FunctionId};
use crate::storage::entities::schema::ENTITY_IL_ECODE_SSA_ID;
use crate::storage::entities::{Entity, EntityId, MutableEntity};
use crate::storage::segments::space::AddressSpaceId;

pub const ECODE_SSA_SCHEMA_VERSION: IlSchemaVersion = IlSchemaVersion::new(1);

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ECodeSsaIr {
    header: IlHeader,
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
    constants: Vec<u8>,
}

struct LiveEntities {
    operations: Vec<bool>,
    block_arguments: Vec<bool>,
}

#[derive(Clone, Copy)]
enum LiveEntity {
    BlockArgument(usize),
    Operation(usize),
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

    pub(super) fn constant_storage(&self) -> &[u8] {
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

    pub fn defining_operation(&self, value: IlValueId) -> Option<&ECodeSsaOp> {
        self.operations.get(self.defining_operation_index(value)?)
    }

    pub fn value_width(&self, value: IlValueId) -> Option<u32> {
        self.values.get(value.index()).map(ECodeSsaValue::width)
    }

    pub fn constant_value(&self, value: IlValueId) -> Option<BitVec> {
        self.defining_operation(value)?.constant(&self.constants)
    }

    pub fn fold_constants(&mut self) {
        let uses = ECodeSsaUses::build(self);
        let sources = self.block_argument_sources();
        let mut feeds = vec![Vec::<IlValueId>::new(); self.values.len()];
        for (&argument, feeders) in &sources {
            for feeder in feeders {
                feeds[feeder.index()].push(argument);
            }
        }

        let mut folded = vec![None::<BitVec>; self.values.len()];
        let mut worklist = Vec::new();
        let mut operands = Vec::new();

        for op in &self.operations {
            if op.results().len() != 1 || !matches!(op.opcode(), ECodeSsaOpcode::Constant) {
                continue;
            }
            if let Some(value) = op.constant(&self.constants) {
                let result = op.results().start();
                folded[result] = Some(value);
                worklist.push(result);
            }
        }

        while let Some(value_index) = worklist.pop() {
            let defined =
                IlValueId::try_from_index(value_index).expect("value id is representable");

            for used in uses.uses_for(defined) {
                let op = &self.operations[used.user().index()];
                if op.results().len() != 1 || matches!(op.opcode(), ECodeSsaOpcode::Constant) {
                    continue;
                }
                let result = op.results().start();
                if folded[result].is_some() {
                    continue;
                }
                operands.clear();
                if op
                    .operands()
                    .slice(&self.value_operands)
                    .iter()
                    .all(|value| match &folded[value.index()] {
                        Some(constant) => {
                            operands.push(constant.clone());
                            true
                        }
                        None => false,
                    })
                    && let Some(value) = op.opcode().evaluate(op.width(), &operands)
                {
                    folded[result] = Some(value);
                    worklist.push(result);
                }
            }

            for &argument in &feeds[value_index] {
                let result = argument.index();
                if folded[result].is_some() {
                    continue;
                }
                let feeders = &sources[&argument];
                let Some(first) = feeders.first() else {
                    continue;
                };
                let Some(value) = folded[first.index()].clone() else {
                    continue;
                };
                if feeders
                    .iter()
                    .all(|feeder| folded[feeder.index()].as_ref() == Some(&value))
                {
                    folded[result] = Some(value);
                    worklist.push(result);
                }
            }
        }

        let mut interned = self.seed_interned();
        for op_index in 0..self.operations.len() {
            let op = &self.operations[op_index];
            if matches!(op.opcode(), ECodeSsaOpcode::Constant) || op.results().len() != 1 {
                continue;
            }
            let result = op.results().start();
            let Some(value) = folded[result].clone() else {
                continue;
            };
            let immediate = self.intern_constant(&value, &mut interned);
            self.operations[op_index].replace_with_constant(immediate);
        }
    }

    fn intern_constant(&mut self, value: &BitVec, interned: &mut FxHashMap<Box<[u8]>, u64>) -> u64 {
        Self::intern_into(value, &mut self.constants, interned)
    }

    fn intern_into(
        value: &BitVec,
        constants: &mut Vec<u8>,
        interned: &mut FxHashMap<Box<[u8]>, u64>,
    ) -> u64 {
        let width_bytes = value.bits().div_ceil(8) as usize;
        if value.bits() <= 64 {
            let mut inline = [0u8; 8];
            value.to_le_bytes(&mut inline[..width_bytes]);
            return u64::from_le_bytes(inline);
        }

        let mut bytes = vec![0u8; width_bytes];
        value.to_le_bytes(&mut bytes);
        if let Some(&offset) = interned.get(bytes.as_slice()) {
            return offset;
        }
        let offset = constants.len() as u64;
        constants.extend_from_slice(&bytes);
        interned.insert(bytes.into_boxed_slice(), offset);
        offset
    }

    fn seed_interned(&self) -> FxHashMap<Box<[u8]>, u64> {
        let mut interned = FxHashMap::default();
        for op in &self.operations {
            if !matches!(op.opcode(), ECodeSsaOpcode::Constant) || op.width() <= 64 {
                continue;
            }
            if let Some(value) = op.constant(&self.constants) {
                let width_bytes = value.bits().div_ceil(8) as usize;
                let mut bytes = vec![0u8; width_bytes];
                value.to_le_bytes(&mut bytes);
                interned.insert(bytes.into_boxed_slice(), op.immediate());
            }
        }
        interned
    }

    pub fn eliminate_dead_code(&mut self) {
        let live = self.compute_liveness();
        for (index, operation) in self.operations.iter_mut().enumerate() {
            if !live.operations[index] {
                operation.make_undefined();
            }
        }
    }

    pub fn compact(&mut self) {
        let live = self.compute_liveness();

        let mut operation_index = vec![0u32; self.operations.len() + 1];
        for index in 0..self.operations.len() {
            operation_index[index + 1] = operation_index[index] + u32::from(live.operations[index]);
        }

        let mut block_argument_index = vec![0u32; self.block_arguments.len() + 1];
        for index in 0..self.block_arguments.len() {
            block_argument_index[index + 1] =
                block_argument_index[index] + u32::from(live.block_arguments[index]);
        }

        let mut value_kept = vec![false; self.values.len()];
        for (index, value) in self.values.iter().enumerate() {
            value_kept[index] = match value.definition_kind() {
                ECodeSsaValueKind::BlockArgument => {
                    live.block_arguments[value.definition_index() as usize]
                }
                ECodeSsaValueKind::Operation => live.operations[value.definition_index() as usize],
            };
        }
        let mut value_index = vec![0u32; self.values.len() + 1];
        for index in 0..self.values.len() {
            value_index[index + 1] = value_index[index] + u32::from(value_kept[index]);
        }

        let remap_value = |value: IlValueId| {
            IlValueId::try_from_index(value_index[value.index()] as usize)
                .expect("remapped value id is representable")
        };
        let remap_range = |range: IlIndexRange, map: &[u32]| {
            IlIndexRange::new(map[range.start()] as usize, map[range.end()] as usize)
                .expect("remapped range stays ordered")
        };

        let values = self
            .values
            .iter()
            .enumerate()
            .filter(|(index, _)| value_kept[*index])
            .map(|(_, value)| {
                let definition = match value.definition_kind() {
                    ECodeSsaValueKind::Operation => {
                        operation_index[value.definition_index() as usize]
                    }
                    ECodeSsaValueKind::BlockArgument => {
                        block_argument_index[value.definition_index() as usize]
                    }
                };
                ECodeSsaValue::new(value.width(), value.definition_kind(), definition)
            })
            .collect::<Vec<_>>();

        let mut operations = Vec::new();
        let mut value_operands = Vec::new();
        for (index, operation) in self.operations.iter().enumerate() {
            if !live.operations[index] {
                continue;
            }
            let operand_start = value_operands.len();
            for &operand in operation.operands().slice(&self.value_operands) {
                value_operands.push(remap_value(operand));
            }
            let operands = IlIndexRange::new(operand_start, value_operands.len())
                .expect("operand range stays ordered");
            let mut compacted = *operation;
            compacted.set_results(remap_range(operation.results(), &value_index));
            compacted.set_operands(operands);
            operations.push(compacted);
        }

        let mut constants = Vec::new();
        let mut interned = FxHashMap::<Box<[u8]>, u64>::default();
        for operation in &mut operations {
            if !matches!(operation.opcode(), ECodeSsaOpcode::Constant) || operation.width() <= 64 {
                continue;
            }
            if let Some(value) = operation.constant(&self.constants) {
                let immediate = Self::intern_into(&value, &mut constants, &mut interned);
                operation.replace_with_constant(immediate);
            }
        }

        let block_arguments = self
            .block_arguments
            .iter()
            .enumerate()
            .filter(|(index, _)| live.block_arguments[*index])
            .map(|(_, argument)| {
                ECodeSsaBlockArg::new(
                    argument.block(),
                    remap_value(argument.value()),
                    argument.width(),
                )
            })
            .collect::<Vec<_>>();

        let mut block_argument_kept = vec![Vec::new(); self.graph.blocks().len()];
        for (index, argument) in self.block_arguments.iter().enumerate() {
            block_argument_kept[argument.block().index()].push(live.block_arguments[index]);
        }

        let mut edge_arguments = Vec::with_capacity(self.edge_arguments.len());
        let mut edge_argument_values = Vec::new();
        for (edge, target) in self.graph.successors().iter().enumerate() {
            let kept = &block_argument_kept[target.index()];
            let start = edge_argument_values.len();
            for (position, &value) in self.arguments_for_edge(edge).iter().enumerate() {
                if kept.get(position).copied().unwrap_or(false) {
                    edge_argument_values.push(remap_value(value));
                }
            }
            edge_arguments.push(
                IlIndexRange::new(start, edge_argument_values.len())
                    .expect("edge argument range stays ordered"),
            );
        }

        let source_spans = self
            .source_spans
            .iter()
            .filter(|span| {
                operation_index[span.destination().start()]
                    != operation_index[span.destination().end()]
            })
            .map(|span| {
                IlSourceSpan::new(
                    remap_range(span.destination(), &operation_index),
                    span.address(),
                    span.first_pcode_index(),
                    span.pcode_count(),
                )
            })
            .collect::<Vec<_>>();

        let parent_spans = self
            .parent_spans
            .iter()
            .filter(|span| {
                operation_index[span.destination().start()]
                    != operation_index[span.destination().end()]
            })
            .map(|span| {
                IlParentSpan::new(
                    remap_range(span.destination(), &operation_index),
                    span.source(),
                )
            })
            .collect::<Vec<_>>();

        let blocks = self
            .graph
            .blocks()
            .iter()
            .map(|block| {
                IlBlock::new(
                    remap_range(block.operations(), &operation_index),
                    block.successors(),
                    block.properties(),
                )
            })
            .collect::<Vec<_>>();
        let graph = IlGraph::new(blocks, self.graph.successors().to_vec());

        self.graph = graph;
        self.source_spans = source_spans;
        self.parent_spans = parent_spans;
        self.values = values;
        self.block_arguments = block_arguments;
        self.operations = operations;
        self.value_operands = value_operands;
        self.edge_arguments = edge_arguments;
        self.edge_argument_values = edge_argument_values;
        self.constants = constants;
    }

    fn compute_liveness(&self) -> LiveEntities {
        let sources = self.block_argument_sources();
        let mut operations = vec![false; self.operations.len()];
        let mut block_arguments = vec![false; self.block_arguments.len()];
        let mut worklist = Vec::new();

        for (index, operation) in self.operations.iter().enumerate() {
            if operation.opcode().is_dce_root() {
                operations[index] = true;
                worklist.push(LiveEntity::Operation(index));
            }
        }

        while let Some(entity) = worklist.pop() {
            match entity {
                LiveEntity::Operation(op_index) => {
                    let operands = self.operations[op_index].operands();
                    for &operand in operands.slice(&self.value_operands) {
                        self.mark_value_live(
                            operand,
                            &mut operations,
                            &mut block_arguments,
                            &mut worklist,
                        );
                    }
                }
                LiveEntity::BlockArgument(argument_index) => {
                    let value = self.block_arguments[argument_index].value();
                    if let Some(feeders) = sources.get(&value) {
                        for &feeder in feeders {
                            self.mark_value_live(
                                feeder,
                                &mut operations,
                                &mut block_arguments,
                                &mut worklist,
                            );
                        }
                    }
                }
            }
        }

        LiveEntities {
            operations,
            block_arguments,
        }
    }

    fn mark_value_live(
        &self,
        value: IlValueId,
        operations: &mut [bool],
        block_arguments: &mut [bool],
        worklist: &mut Vec<LiveEntity>,
    ) {
        let Some(record) = self.values.get(value.index()) else {
            return;
        };
        let index = record.definition_index() as usize;
        match record.definition_kind() {
            ECodeSsaValueKind::Operation => {
                if !operations[index] {
                    operations[index] = true;
                    worklist.push(LiveEntity::Operation(index));
                }
            }
            ECodeSsaValueKind::BlockArgument => {
                if !block_arguments[index] {
                    block_arguments[index] = true;
                    worklist.push(LiveEntity::BlockArgument(index));
                }
            }
        }
    }

    fn defining_operation_index(&self, value: IlValueId) -> Option<usize> {
        let record = self.values.get(value.index())?;
        (record.definition_kind() == ECodeSsaValueKind::Operation)
            .then(|| record.definition_index() as usize)
    }

    pub fn underlying_value(&self, value: IlValueId) -> IlValueId {
        let mut current = value;
        for _ in 0..self.values.len() {
            let Some(operation) = self.defining_operation(current) else {
                return current;
            };
            match operation.opcode() {
                ECodeSsaOpcode::Copy
                | ECodeSsaOpcode::ZeroExtend
                | ECodeSsaOpcode::SignExtend
                | ECodeSsaOpcode::Truncate => {
                    let Some(&inner) = self.operation_operands(operation).first() else {
                        return current;
                    };
                    current = inner;
                }
                _ => return current,
            }
        }
        current
    }

    pub fn first_non_constant_operand(&self, operation: &ECodeSsaOp) -> Option<IlValueId> {
        self.operation_operands(operation)
            .iter()
            .copied()
            .find(|&value| self.constant_value(value).is_none())
    }

    pub fn indirect_branch_input(&self, address: Address) -> Option<IlValueId> {
        self.operations_for_source(address)
            .find(|(_, operation)| matches!(operation.opcode(), ECodeSsaOpcode::BranchIndirect))
            .and_then(|(_, operation)| self.operation_operands(operation).first().copied())
    }

    pub fn arguments_for_edge(&self, edge: usize) -> &[IlValueId] {
        self.edge_arguments
            .get(edge)
            .expect("edge index is within the edge argument table")
            .slice(&self.edge_argument_values)
    }

    pub fn block_argument_sources(&self) -> FxHashMap<IlValueId, Vec<IlValueId>> {
        let block_count = self.graph.blocks().len();
        let mut arguments = vec![Vec::new(); block_count];
        for argument in &self.block_arguments {
            arguments[argument.block().index()].push(argument.value());
        }

        let mut incoming = vec![Vec::new(); block_count];
        for (edge, target) in self.graph.successors().iter().enumerate() {
            incoming[target.index()].push(edge);
        }

        let mut sources = FxHashMap::default();
        for (block, positions) in arguments.iter().enumerate() {
            for (position, &argument) in positions.iter().enumerate() {
                let feeders = incoming[block]
                    .iter()
                    .filter_map(|&edge| self.arguments_for_edge(edge).get(position).copied())
                    .collect();
                sources.insert(argument, feeders);
            }
        }

        sources
    }

    pub const fn display(&self) -> ECodeSsaIrDisplay<'_> {
        ECodeSsaIrDisplay::new(self)
    }

    pub fn dominance(&self) -> IlDominance {
        let Some(entry) = self.graph.entry_block() else {
            return IlDominance::default();
        };

        IlDominance::from_blocks(self.graph.blocks(), self.graph.successors(), entry)
    }

    pub fn dominance_frontiers(&self) -> IlDominanceFrontier {
        self.dominance()
            .frontiers(self.graph.blocks(), self.graph.successors())
    }

    pub fn uses(&self) -> ECodeSsaUses {
        ECodeSsaUses::build(self)
    }

    pub fn liveness(&self) -> ECodeSsaLiveness {
        ECodeSsaLiveness::build(self)
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

#[derive(Debug)]
pub(crate) struct ECodeSsaBuilder {
    header: IlHeader,
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
    constants: Vec<u8>,
}

impl ECodeSsaBuilder {
    pub(crate) fn new(header: IlHeader, graph: IlGraph) -> Self {
        Self {
            header,
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
            constants: Vec::new(),
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

    pub(crate) fn replace_graph(&mut self, graph: IlGraph) {
        self.graph = graph;
    }

    pub(crate) fn replace_source_spans(&mut self, source_spans: Vec<IlSourceSpan>) {
        self.source_spans = source_spans;
    }

    pub(crate) fn replace_parent_spans(&mut self, parent_spans: Vec<IlParentSpan>) {
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
        self.edge_argument_values.clear();
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

        let mut body = ECodeSsaIr::new(
            self.header,
            self.graph,
            self.source_spans,
            self.parent_spans,
            self.values,
            self.block_arguments,
            self.operations,
            self.value_operands.into_values(),
            self.memory_domains,
        )
        .with_edge_argument_storage(self.edge_arguments, self.edge_argument_values.into_values())
        .with_constants(self.constants);

        body.shrink_to_fit();

        Ok(body)
    }
}

#[cfg(test)]
#[path = "builder/test.rs"]
mod test;
