use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlBlockId, IlDominance, IlDominanceFrontier, IlError, IlGraph, IlHeader,
    IlIndexRange, IlLevel, IlOpId, IlParentSpan, IlPool, IlSchemaVersion, IlSourceSpan, IlValueId,
};
use crate::il::ecode::ssa::format::ECodeSsaIrDisplay;
use crate::il::ecode::ssa::{
    ECodeSsaBlockArg, ECodeSsaLiveness, ECodeSsaMemoryDomain, ECodeSsaOp, ECodeSsaUses,
    ECodeSsaValue,
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
}

impl ECodeSsaIr {
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

    pub fn memory_domain(&self, space: AddressSpaceId) -> Option<&ECodeSsaMemoryDomain> {
        self.memory_domains
            .iter()
            .find(|domain| domain.space() == space)
    }

    pub fn operation_operands(&self, operation: &ECodeSsaOp) -> &[IlValueId] {
        operation.operands().slice(&self.value_operands)
    }

    pub fn arguments_for_edge(&self, edge: usize) -> &[IlValueId] {
        self.edge_arguments
            .get(edge)
            .expect("edge index is within the edge argument table")
            .slice(&self.edge_argument_values)
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
        .with_edge_argument_storage(self.edge_arguments, self.edge_argument_values.into_values());

        body.shrink_to_fit();

        Ok(body)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::verify::{
        VerifyError, checked_slice, verify_bounds, verify_graph, verify_graph_bounds,
        verify_parent_spans, verify_source_spans,
    };
    use crate::il::common::{IlBlock, IlBlockProperties, IlSourceSpan};
    use crate::il::ecode::ssa::{ECodeSsaOpcode, ECodeSsaValueKind};
    use crate::ir::{Address, FunctionId};
    use crate::storage::segments::space::AddressSpaceId;

    pub(crate) fn verify(ir: &ECodeSsaIr) -> Result<(), VerifyError> {
        if ir.header().schema() != ECodeSsaIr::SCHEMA {
            return Err(IlError::schema_mismatch(
                ECodeSsaIr::LEVEL,
                ECodeSsaIr::SCHEMA.value(),
                ir.header().schema().value(),
            )
            .into());
        }

        verify_graph(ir.graph())?;
        verify_graph_bounds(ir.graph(), ir.operations().len())?;
        verify_source_spans(ir.source_spans(), ir.operations().len())?;
        verify_parent_spans(ir.parent_spans(), ir.operations().len())?;
        verify_memory_domains(ir)?;
        verify_edge_arguments(ir)?;

        for (argument_index, argument) in ir.block_arguments().iter().enumerate() {
            ir.graph().blocks().get(argument.block().index()).ok_or(
                IlError::range_out_of_bounds(argument.block().value(), ir.graph().blocks().len()),
            )?;

            ir.values()
                .get(argument.value().index())
                .ok_or(IlError::range_out_of_bounds(
                    argument.value().value(),
                    ir.values().len(),
                ))?;

            let value = ir.values()[argument.value().index()];

            if value.definition_kind() != ECodeSsaValueKind::BlockArgument
                || value.definition_index() != argument_index as u32
                || value.width() != argument.width()
            {
                return Err(VerifyError::InvalidValueDefinition {
                    level: IlLevel::ECodeSsa,
                });
            }
        }

        for (operation_index, operation) in ir.operations().iter().enumerate() {
            verify_bounds(operation.results(), ir.values().len())?;
            verify_bounds(operation.operands(), ir.value_operands().len())?;

            for result_index in operation.results().start()..operation.results().end() {
                let value = ir.values()[result_index];

                if value.definition_kind() != ECodeSsaValueKind::Operation
                    || value.definition_index() != operation_index as u32
                {
                    return Err(VerifyError::InvalidValueDefinition {
                        level: IlLevel::ECodeSsa,
                    });
                }

                if value.width() != operation.width() {
                    return Err(IlError::width_mismatch(IlLevel::ECodeSsa).into());
                }
            }

            for operand in checked_slice(operation.operands(), ir.value_operands())? {
                ir.values()
                    .get(operand.index())
                    .ok_or(IlError::range_out_of_bounds(
                        operand.value(),
                        ir.values().len(),
                    ))?;
            }

            if operation.opcode().requires_memory_domain() {
                let Some(address_space) = operation.address_space() else {
                    return Err(
                        IlError::missing_component(IlLevel::ECodeSsa, "memory domain").into(),
                    );
                };

                if ir.memory_domain(address_space).is_none() {
                    return Err(
                        IlError::missing_component(IlLevel::ECodeSsa, "memory domain").into(),
                    );
                }

                verify_memory_operation(ir, operation)?;
            }
        }

        for (value_index, value) in ir.values().iter().enumerate() {
            let value_id = IlValueId::try_from_index(value_index)?;

            match value.definition_kind() {
                ECodeSsaValueKind::Operation => {
                    let Some(operation) = ir.operations().get(value.definition_index() as usize)
                    else {
                        return Err(VerifyError::InvalidValueDefinition {
                            level: IlLevel::ECodeSsa,
                        });
                    };

                    if !operation.results().contains_index(value_id.index()) {
                        return Err(VerifyError::InvalidValueDefinition {
                            level: IlLevel::ECodeSsa,
                        });
                    }
                }
                ECodeSsaValueKind::BlockArgument => {
                    let Some(argument) =
                        ir.block_arguments().get(value.definition_index() as usize)
                    else {
                        return Err(VerifyError::InvalidValueDefinition {
                            level: IlLevel::ECodeSsa,
                        });
                    };

                    if argument.value() != value_id || argument.width() != value.width() {
                        return Err(VerifyError::InvalidValueDefinition {
                            level: IlLevel::ECodeSsa,
                        });
                    }
                }
            }
        }

        verify_dominating_uses(ir)?;

        Ok(())
    }

    fn verify_memory_domains(ir: &ECodeSsaIr) -> Result<(), VerifyError> {
        for (index, domain) in ir.memory_domains().iter().enumerate() {
            if ir.memory_domains()[..index]
                .iter()
                .any(|existing| existing.space() == domain.space())
            {
                return Err(VerifyError::DuplicateMemoryDomain {
                    level: IlLevel::ECodeSsa,
                });
            }
        }

        Ok(())
    }

    fn verify_memory_operation(ir: &ECodeSsaIr, operation: &ECodeSsaOp) -> Result<(), VerifyError> {
        let operands = ir.operation_operands(operation);
        let Some(memory) = operands.last() else {
            return Err(IlError::missing_component(IlLevel::ECodeSsa, "memory domain").into());
        };
        let memory = ir.values()[memory.index()];

        if memory.width() != 0 {
            return Err(IlError::width_mismatch(IlLevel::ECodeSsa).into());
        }

        if operation.opcode() == ECodeSsaOpcode::Store {
            if operation.results().len() != 1 {
                return Err(IlError::missing_component(IlLevel::ECodeSsa, "memory domain").into());
            }

            let result = ir.values()[operation.results().start()];

            if result.width() != 0 {
                return Err(IlError::width_mismatch(IlLevel::ECodeSsa).into());
            }
        }

        Ok(())
    }

    fn verify_edge_arguments(ir: &ECodeSsaIr) -> Result<(), VerifyError> {
        if ir.edge_arguments().len() != ir.graph().successors().len() {
            return Err(VerifyError::BlockArgumentCount {
                block: 0,
                expected: ir.graph().successors().len(),
                found: ir.edge_arguments().len(),
            });
        }

        for range in ir.edge_arguments() {
            verify_bounds(*range, ir.edge_argument_values().len())?;
        }

        for value in ir.edge_argument_values() {
            ir.values()
                .get(value.index())
                .ok_or(IlError::range_out_of_bounds(
                    value.value(),
                    ir.values().len(),
                ))?;
        }

        Ok(())
    }

    fn verify_dominating_uses(ir: &ECodeSsaIr) -> Result<(), VerifyError> {
        if ir.graph().blocks().is_empty() {
            return verify_linear_dominating_uses(ir);
        }

        let operation_blocks = operation_blocks(ir)?;
        let dominance = ir.dominance();

        verify_edge_argument_uses(ir, &operation_blocks, &dominance)?;

        for (operation_index, operation) in ir.operations().iter().enumerate() {
            let operation_id = IlOpId::try_from_index(operation_index)?;
            let Some(user_block) = operation_blocks[operation_index] else {
                return Err(VerifyError::InvalidOperationPlacement {
                    level: IlLevel::ECodeSsa,
                    operation: operation_id.value(),
                });
            };

            if !dominance.is_reachable(user_block) {
                continue;
            }

            for operand in ir.operation_operands(operation) {
                if !value_dominates_operation(
                    ir,
                    *operand,
                    user_block,
                    operation_index,
                    &operation_blocks,
                    &dominance,
                )? {
                    return Err(VerifyError::NonDominatingUse {
                        level: IlLevel::ECodeSsa,
                        value: operand.value(),
                        user: operation_id.value(),
                    });
                }
            }
        }

        Ok(())
    }

    fn verify_edge_argument_uses(
        ir: &ECodeSsaIr,
        operation_blocks: &[Option<IlBlockId>],
        dominance: &IlDominance,
    ) -> Result<(), VerifyError> {
        for (predecessor_index, predecessor) in ir.graph().blocks().iter().enumerate() {
            let predecessor_id = IlBlockId::try_from_index(predecessor_index)?;

            for (successor_offset, successor) in
                checked_slice(predecessor.successors(), ir.graph().successors())?
                    .iter()
                    .enumerate()
            {
                let edge = predecessor.successors().start() + successor_offset;
                let arguments = ir.arguments_for_edge(edge);
                let block_arguments = block_arguments_for_block(ir, *successor);

                if arguments.len() != block_arguments.len() {
                    return Err(VerifyError::BlockArgumentCount {
                        block: successor.value(),
                        expected: block_arguments.len(),
                        found: arguments.len(),
                    });
                }

                if !dominance.is_reachable(predecessor_id) {
                    continue;
                }

                for (value, argument) in arguments.iter().zip(block_arguments) {
                    let incoming = ir.values()[value.index()];

                    if incoming.width() != argument.width() {
                        return Err(IlError::width_mismatch(IlLevel::ECodeSsa).into());
                    }

                    if !value_dominates_edge(
                        ir,
                        *value,
                        predecessor_id,
                        operation_blocks,
                        dominance,
                    )? {
                        return Err(VerifyError::NonDominatingEdgeArgument {
                            level: IlLevel::ECodeSsa,
                            value: value.value(),
                            predecessor: predecessor_id.value(),
                            successor: successor.value(),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn block_arguments_for_block(ir: &ECodeSsaIr, block: IlBlockId) -> Vec<ECodeSsaBlockArg> {
        ir.block_arguments()
            .iter()
            .copied()
            .filter(|argument| argument.block() == block)
            .collect()
    }

    fn verify_linear_dominating_uses(ir: &ECodeSsaIr) -> Result<(), VerifyError> {
        for (operation_index, operation) in ir.operations().iter().enumerate() {
            let operation_id = IlOpId::try_from_index(operation_index)?;

            for operand in ir.operation_operands(operation) {
                let value = ir.values()[operand.index()];

                if value.definition_kind() == ECodeSsaValueKind::Operation
                    && value.definition_index() as usize >= operation_index
                {
                    return Err(VerifyError::NonDominatingUse {
                        level: IlLevel::ECodeSsa,
                        value: operand.value(),
                        user: operation_id.value(),
                    });
                }
            }
        }

        Ok(())
    }

    fn operation_blocks(ir: &ECodeSsaIr) -> Result<Vec<Option<IlBlockId>>, VerifyError> {
        let mut operation_blocks = vec![None; ir.operations().len()];

        for (block_index, block) in ir.graph().blocks().iter().enumerate() {
            let block_id = IlBlockId::try_from_index(block_index)?;
            verify_bounds(block.operations(), ir.operations().len())?;

            for (operation_index, operation_block) in operation_blocks
                .iter_mut()
                .enumerate()
                .take(block.operations().end())
                .skip(block.operations().start())
            {
                if operation_block.is_some() {
                    let operation_id = IlOpId::try_from_index(operation_index)?;
                    return Err(VerifyError::InvalidOperationPlacement {
                        level: IlLevel::ECodeSsa,
                        operation: operation_id.value(),
                    });
                }

                *operation_block = Some(block_id);
            }
        }

        Ok(operation_blocks)
    }

    fn value_dominates_operation(
        ir: &ECodeSsaIr,
        value_id: IlValueId,
        user_block: IlBlockId,
        user_operation: usize,
        operation_blocks: &[Option<IlBlockId>],
        dominance: &IlDominance,
    ) -> Result<bool, VerifyError> {
        let value = ir.values()[value_id.index()];

        match value.definition_kind() {
            ECodeSsaValueKind::Operation => {
                let definition_operation = value.definition_index() as usize;
                let Some(definition_block) = operation_blocks
                    .get(definition_operation)
                    .copied()
                    .flatten()
                else {
                    let operation_id = IlOpId::try_from_index(definition_operation)?;
                    return Err(VerifyError::InvalidOperationPlacement {
                        level: IlLevel::ECodeSsa,
                        operation: operation_id.value(),
                    });
                };

                if definition_block == user_block {
                    Ok(definition_operation < user_operation)
                } else {
                    Ok(dominance.dominates(definition_block, user_block))
                }
            }
            ECodeSsaValueKind::BlockArgument => {
                let argument = ir.block_arguments()[value.definition_index() as usize];

                Ok(dominance.dominates(argument.block(), user_block))
            }
        }
    }

    fn value_dominates_edge(
        ir: &ECodeSsaIr,
        value_id: IlValueId,
        predecessor: IlBlockId,
        operation_blocks: &[Option<IlBlockId>],
        dominance: &IlDominance,
    ) -> Result<bool, VerifyError> {
        let value = ir.values()[value_id.index()];

        match value.definition_kind() {
            ECodeSsaValueKind::Operation => {
                let definition_operation = value.definition_index() as usize;
                let Some(definition_block) = operation_blocks
                    .get(definition_operation)
                    .copied()
                    .flatten()
                else {
                    let operation_id = IlOpId::try_from_index(definition_operation)?;
                    return Err(VerifyError::InvalidOperationPlacement {
                        level: IlLevel::ECodeSsa,
                        operation: operation_id.value(),
                    });
                };

                Ok(definition_block == predecessor
                    || dominance.dominates(definition_block, predecessor))
            }
            ECodeSsaValueKind::BlockArgument => {
                let argument = ir.block_arguments()[value.definition_index() as usize];

                Ok(dominance.dominates(argument.block(), predecessor))
            }
        }
    }

    #[test]
    fn ssa_builder_finishes_verified_body() {
        assert!(std::mem::size_of::<ECodeSsaValue>() <= 12);
        assert!(std::mem::size_of::<ECodeSsaBlockArg>() <= 12);
        assert!(std::mem::size_of::<ECodeSsaOp>() <= 64);
        assert!(std::mem::size_of::<ECodeSsaMemoryDomain>() <= 4);

        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let mut builder = ECodeSsaBuilder::new(header, IlGraph::default());
        let (value, results) = builder.push_result_value(64).unwrap();

        builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                results,
                IlIndexRange::EMPTY,
                64,
            ))
            .unwrap();

        let operands = builder.push_value_operands([value]).unwrap();

        builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::Return,
                IlIndexRange::EMPTY,
                operands,
                0,
            ))
            .unwrap();

        let body = builder.build(&CancellationToken::default()).unwrap();
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&body).unwrap();
        let decoded = rkyv::from_bytes::<ECodeSsaIr, rkyv::rancor::Error>(&bytes).unwrap();

        assert_eq!(body.values().len(), 1);
        assert_eq!(body.operations().len(), 2);
        assert_eq!(decoded, body);
    }

    #[test]
    fn ssa_body_returns_operations_for_source() {
        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let address = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let other = Address::new(AddressSpaceId::new(1), 0x2000u64);
        let body = ECodeSsaIr::new(
            header,
            IlGraph::default(),
            vec![
                IlSourceSpan::new(IlIndexRange::new(0, 1).unwrap(), address, 0, 1),
                IlSourceSpan::new(IlIndexRange::new(1, 2).unwrap(), other, 0, 1),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![
                ECodeSsaOp::new(
                    ECodeSsaOpcode::Trap,
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    0,
                ),
                ECodeSsaOp::new(
                    ECodeSsaOpcode::Trap,
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    0,
                ),
            ],
            Vec::new(),
            Vec::new(),
        );

        let operations = body.operations_for_source(other).collect::<Vec<_>>();

        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].0, 1);
        assert_eq!(operations[0].1.opcode(), ECodeSsaOpcode::Trap);
    }

    #[test]
    fn ssa_builder_records_block_argument_definition() {
        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let block = IlBlockId::try_from_index(0).unwrap();
        let graph = IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::EMPTY,
                IlBlockProperties::ENTRY,
            )],
            Vec::new(),
        );
        let mut builder = ECodeSsaBuilder::new(header, graph);
        let value = builder.push_block_argument_value(block, 32).unwrap();

        let body = builder.build(&CancellationToken::default()).unwrap();

        assert_eq!(body.block_arguments().len(), 1);
        assert_eq!(body.block_arguments()[0].block(), block);
        assert_eq!(body.block_arguments()[0].value(), value);
        assert_eq!(
            body.values()[value.index()].definition_kind(),
            ECodeSsaValueKind::BlockArgument
        );
    }

    #[test]
    fn ssa_verifier_rejects_invalid_value_definition() {
        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let body = ECodeSsaIr::new(
            header,
            IlGraph::default(),
            Vec::new(),
            Vec::new(),
            vec![ECodeSsaValue::new(64, ECodeSsaValueKind::Operation, 3)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        assert!(matches!(
            verify(&body),
            Err(VerifyError::InvalidValueDefinition { .. })
        ));
    }

    #[test]
    fn ssa_builder_interns_memory_domains() {
        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let mut builder = ECodeSsaBuilder::new(header, IlGraph::default());
        let space = AddressSpaceId::new(7);

        assert_eq!(builder.ensure_memory_domain(space), 0);
        assert_eq!(builder.ensure_memory_domain(space), 0);

        let body = builder.build(&CancellationToken::default()).unwrap();

        assert_eq!(body.memory_domains().len(), 1);
        assert_eq!(body.memory_domains()[0].space(), space);
    }

    #[test]
    fn ssa_verifier_rejects_duplicate_memory_domains() {
        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let space = AddressSpaceId::new(7);
        let body = ECodeSsaIr::new(
            header,
            IlGraph::default(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![
                ECodeSsaMemoryDomain::new(space),
                ECodeSsaMemoryDomain::new(space),
            ],
        );

        assert!(matches!(
            verify(&body),
            Err(VerifyError::DuplicateMemoryDomain { .. })
        ));
    }

    #[test]
    fn ssa_verifier_rejects_load_without_memory_domain() {
        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let space = AddressSpaceId::new(7);
        let mut builder = ECodeSsaBuilder::new(header, IlGraph::default());
        let (_value, results) = builder.push_result_value(8).unwrap();

        builder
            .push_operation(
                ECodeSsaOp::new(ECodeSsaOpcode::Load, results, IlIndexRange::EMPTY, 8)
                    .with_address_space(space),
            )
            .unwrap();

        let body = builder.build(&CancellationToken::default()).unwrap();

        assert!(matches!(
            verify(&body),
            Err(VerifyError::Il(IlError::MissingComponent { .. }))
        ));
    }

    #[test]
    fn ssa_verifier_rejects_non_dominating_linear_use() {
        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let value = IlValueId::try_from_index(0).unwrap();
        let result = IlIndexRange::new(0, 1).unwrap();
        let operands = IlIndexRange::new(0, 1).unwrap();
        let body = ECodeSsaIr::new(
            header,
            IlGraph::default(),
            Vec::new(),
            Vec::new(),
            vec![ECodeSsaValue::operation_result(
                32,
                IlOpId::try_from_index(1).unwrap(),
            )],
            Vec::new(),
            vec![
                ECodeSsaOp::new(ECodeSsaOpcode::Return, IlIndexRange::EMPTY, operands, 0),
                ECodeSsaOp::new(ECodeSsaOpcode::Constant, result, IlIndexRange::EMPTY, 32),
            ],
            vec![value],
            Vec::new(),
        );

        assert!(matches!(
            verify(&body),
            Err(VerifyError::NonDominatingUse { .. })
        ));
    }

    #[test]
    fn ssa_verifier_rejects_non_dominating_block_use() {
        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let left = IlBlockId::try_from_index(1).unwrap();
        let right = IlBlockId::try_from_index(2).unwrap();
        let value = IlValueId::try_from_index(0).unwrap();
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(0, 2).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::empty(),
                ),
                IlBlock::new(
                    IlIndexRange::new(1, 2).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::empty(),
                ),
            ],
            vec![left, right],
        );
        let body = ECodeSsaIr::new(
            header,
            graph,
            Vec::new(),
            Vec::new(),
            vec![ECodeSsaValue::operation_result(
                32,
                IlOpId::try_from_index(0).unwrap(),
            )],
            Vec::new(),
            vec![
                ECodeSsaOp::new(
                    ECodeSsaOpcode::Constant,
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::EMPTY,
                    32,
                ),
                ECodeSsaOp::new(
                    ECodeSsaOpcode::Return,
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(0, 1).unwrap(),
                    0,
                ),
            ],
            vec![value],
            Vec::new(),
        );

        assert!(matches!(
            verify(&body),
            Err(VerifyError::NonDominatingUse { .. })
        ));
    }

    #[test]
    fn ssa_verifier_rejects_wrong_edge_argument_count() {
        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let successor = IlBlockId::try_from_index(1).unwrap();
        let argument_value = IlValueId::try_from_index(0).unwrap();
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(0, 1).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            vec![successor],
        );
        let body = ECodeSsaIr::new(
            header,
            graph,
            Vec::new(),
            Vec::new(),
            vec![ECodeSsaValue::block_argument(32, 0)],
            vec![ECodeSsaBlockArg::new(successor, argument_value, 32)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .with_edge_argument_storage(vec![IlIndexRange::EMPTY], Vec::new());

        assert!(matches!(
            verify(&body),
            Err(VerifyError::BlockArgumentCount { .. })
        ));
    }

    #[test]
    fn ssa_verifier_rejects_non_dominating_edge_argument() {
        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let left = IlBlockId::try_from_index(1).unwrap();
        let right = IlBlockId::try_from_index(2).unwrap();
        let value = IlValueId::try_from_index(0).unwrap();
        let argument_value = IlValueId::try_from_index(1).unwrap();
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(0, 2).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::empty(),
                ),
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            vec![left, right],
        );
        let body = ECodeSsaIr::new(
            header,
            graph,
            Vec::new(),
            Vec::new(),
            vec![
                ECodeSsaValue::operation_result(32, IlOpId::try_from_index(0).unwrap()),
                ECodeSsaValue::block_argument(32, 0),
            ],
            vec![ECodeSsaBlockArg::new(right, argument_value, 32)],
            vec![ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::EMPTY,
                32,
            )],
            Vec::new(),
            Vec::new(),
        )
        .with_edge_argument_storage(
            vec![IlIndexRange::EMPTY, IlIndexRange::new(0, 1).unwrap()],
            vec![value],
        );

        assert!(matches!(
            verify(&body),
            Err(VerifyError::NonDominatingEdgeArgument { .. })
        ));
    }

    #[test]
    fn ssa_verifier_rejects_duplicate_operation_placement() {
        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::empty(),
                ),
            ],
            Vec::new(),
        );
        let body = ECodeSsaIr::new(
            header,
            graph,
            Vec::new(),
            Vec::new(),
            vec![ECodeSsaValue::operation_result(
                32,
                IlOpId::try_from_index(0).unwrap(),
            )],
            Vec::new(),
            vec![ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::EMPTY,
                32,
            )],
            Vec::new(),
            Vec::new(),
        );

        assert!(matches!(
            verify(&body),
            Err(VerifyError::OverlappingBlockOperations { .. })
        ));
    }
}
