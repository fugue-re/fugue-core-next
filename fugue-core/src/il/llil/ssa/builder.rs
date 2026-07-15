use crate::il::common::{
    ArtefactHeader, BlockId, BuildCancellation, CommonBody, Finish, IlError, IrArtefact, IrLevel,
    OperationId, PackedRange, Pool, RawIrArtefact, SchemaVersion, ValueId, Verify,
};
use crate::il::llil::ssa::format::SsaBodyDisplay;
use crate::il::llil::ssa::{
    BlockArgument, Dominance, DominanceFrontier, Liveness, MemoryDomain, SsaOpcode, SsaOperation,
    UseIndex, Value, ValueDefinitionKind,
};
use crate::ir::Address;
use crate::storage::segments::space::AddressSpaceId;

pub const LLIL_SSA_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(2);

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct SsaBody {
    header: ArtefactHeader,
    common: CommonBody,
    values: Vec<Value>,
    block_arguments: Vec<BlockArgument>,
    edge_arguments: Vec<PackedRange>,
    edge_argument_values: Vec<ValueId>,
    operations: Vec<SsaOperation>,
    value_operands: Vec<ValueId>,
    memory_domains: Vec<MemoryDomain>,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct SsaPayload {
    values: Vec<Value>,
    block_arguments: Vec<BlockArgument>,
    edge_arguments: Vec<PackedRange>,
    edge_argument_values: Vec<ValueId>,
    operations: Vec<SsaOperation>,
    value_operands: Vec<ValueId>,
    memory_domains: Vec<MemoryDomain>,
}

impl SsaPayload {
    fn new(
        values: Vec<Value>,
        block_arguments: Vec<BlockArgument>,
        edge_arguments: Vec<PackedRange>,
        edge_argument_values: Vec<ValueId>,
        operations: Vec<SsaOperation>,
        value_operands: Vec<ValueId>,
        memory_domains: Vec<MemoryDomain>,
    ) -> Self {
        Self {
            values,
            block_arguments,
            edge_arguments,
            edge_argument_values,
            operations,
            value_operands,
            memory_domains,
        }
    }
}

impl SsaBody {
    pub fn new(
        header: ArtefactHeader,
        common: CommonBody,
        values: Vec<Value>,
        block_arguments: Vec<BlockArgument>,
        operations: Vec<SsaOperation>,
        value_operands: Vec<ValueId>,
        memory_domains: Vec<MemoryDomain>,
    ) -> Self {
        let edge_arguments = vec![PackedRange::EMPTY; common.successors().len()];

        Self {
            header,
            common,
            values,
            block_arguments,
            edge_arguments,
            edge_argument_values: Vec::new(),
            operations,
            value_operands,
            memory_domains,
        }
    }

    pub fn with_edge_argument_storage(
        mut self,
        edge_arguments: Vec<PackedRange>,
        edge_argument_values: Vec<ValueId>,
    ) -> Self {
        self.edge_arguments = edge_arguments;
        self.edge_argument_values = edge_argument_values;
        self
    }

    pub const fn header(&self) -> &ArtefactHeader {
        &self.header
    }

    pub const fn common(&self) -> &CommonBody {
        &self.common
    }

    pub fn values(&self) -> &[Value] {
        &self.values
    }

    pub fn block_arguments(&self) -> &[BlockArgument] {
        &self.block_arguments
    }

    pub fn edge_arguments(&self) -> &[PackedRange] {
        &self.edge_arguments
    }

    pub fn edge_argument_values(&self) -> &[ValueId] {
        &self.edge_argument_values
    }

    pub fn operations(&self) -> &[SsaOperation] {
        &self.operations
    }

    pub fn value_operands(&self) -> &[ValueId] {
        &self.value_operands
    }

    pub fn memory_domains(&self) -> &[MemoryDomain] {
        &self.memory_domains
    }

    pub fn memory_domain(&self, space: AddressSpaceId) -> Option<&MemoryDomain> {
        self.memory_domains
            .iter()
            .find(|domain| domain.space() == space)
    }

    pub fn operation_operands(&self, operation: &SsaOperation) -> Result<&[ValueId], IlError> {
        operation.operands().checked_slice(&self.value_operands)
    }

    pub fn arguments_for_edge(&self, edge: usize) -> Result<&[ValueId], IlError> {
        let range = self
            .edge_arguments
            .get(edge)
            .ok_or(IlError::range_out_of_bounds(
                u32::try_from(edge).unwrap_or(u32::MAX),
                self.edge_arguments.len(),
            ))?;

        range.checked_slice(&self.edge_argument_values)
    }

    pub const fn display(&self) -> SsaBodyDisplay<'_> {
        SsaBodyDisplay::new(self)
    }

    pub fn dominance(&self) -> Result<Dominance, IlError> {
        if self.common.blocks().is_empty() {
            return Ok(Dominance::default());
        }

        let entry = self.common.entry_block()?;
        Dominance::from_blocks(self.common.blocks(), self.common.successors(), entry)
    }

    pub fn dominance_frontiers(&self) -> Result<DominanceFrontier, IlError> {
        let dominance = self.dominance()?;
        dominance.frontiers(self.common.blocks(), self.common.successors())
    }

    pub fn use_index(&self) -> Result<UseIndex, IlError> {
        UseIndex::build(self)
    }

    pub fn liveness(&self) -> Result<Liveness, IlError> {
        Liveness::build(self)
    }

    pub fn operations_for_source(
        &self,
        machine_address: Address,
    ) -> impl Iterator<Item = (usize, &SsaOperation)> + '_ {
        self.common
            .source_runs()
            .iter()
            .filter(move |run| run.machine_address() == machine_address)
            .flat_map(move |run| {
                let start = run.destination().start();
                run.destination()
                    .checked_slice(&self.operations)
                    .ok()
                    .into_iter()
                    .flat_map(move |operations| {
                        operations
                            .iter()
                            .enumerate()
                            .map(move |(index, operation)| (start + index, operation))
                    })
            })
    }

    pub fn shrink_to_fit(&mut self) {
        self.common.shrink_to_fit();
        self.values.shrink_to_fit();
        self.block_arguments.shrink_to_fit();
        self.edge_arguments.shrink_to_fit();
        self.edge_argument_values.shrink_to_fit();
        self.operations.shrink_to_fit();
        self.value_operands.shrink_to_fit();
        self.memory_domains.shrink_to_fit();
    }

    fn decode_payload(bytes: &[u8]) -> Result<SsaPayload, IlError> {
        rkyv::from_bytes::<SsaPayload, rkyv::rancor::Error>(bytes)
            .map_err(|_| IlError::artefact_decode(Self::LEVEL))
    }
}

impl Verify for SsaBody {
    fn verify(&self) -> Result<(), IlError> {
        self.verify_header()?;
        self.common.verify()?;
        self.common.verify_node_bounds(self.operations.len())?;
        self.verify_memory_domains()?;
        self.verify_edge_arguments()?;

        for (argument_index, argument) in self.block_arguments.iter().enumerate() {
            self.common.blocks().get(argument.block().index()).ok_or(
                IlError::range_out_of_bounds(argument.block().value(), self.common.blocks().len()),
            )?;

            self.values
                .get(argument.value().index())
                .ok_or(IlError::range_out_of_bounds(
                    argument.value().value(),
                    self.values.len(),
                ))?;

            let value = self.values[argument.value().index()];

            if value.definition_kind() != ValueDefinitionKind::BlockArgument
                || value.definition_index() != argument_index as u32
                || value.width() != argument.width()
            {
                return Err(IlError::llil_ssa_invalid_value_definition());
            }
        }

        for (operation_index, operation) in self.operations.iter().enumerate() {
            operation.results().verify_bounds(self.values.len())?;
            operation
                .operands()
                .verify_bounds(self.value_operands.len())?;

            for result_index in operation.results().start()..operation.results().end() {
                let value = self.values[result_index];

                if value.definition_kind() != ValueDefinitionKind::Operation
                    || value.definition_index() != operation_index as u32
                {
                    return Err(IlError::llil_ssa_invalid_value_definition());
                }

                if value.width() != operation.width() {
                    return Err(IlError::llil_ssa_width_mismatch());
                }
            }

            for operand in operation.operands().checked_slice(&self.value_operands)? {
                self.values
                    .get(operand.index())
                    .ok_or(IlError::range_out_of_bounds(
                        operand.value(),
                        self.values.len(),
                    ))?;
            }

            if operation.opcode().requires_memory_domain() {
                let Some(address_space) = operation.address_space() else {
                    return Err(IlError::llil_ssa_missing_memory_domain());
                };

                if self.memory_domain(address_space).is_none() {
                    return Err(IlError::llil_ssa_missing_memory_domain());
                }

                self.verify_memory_operation(operation)?;
            }
        }

        for (value_index, value) in self.values.iter().enumerate() {
            let value_id = ValueId::try_from_index(value_index)?;

            match value.definition_kind() {
                ValueDefinitionKind::Operation => {
                    let Some(operation) = self.operations.get(value.definition_index() as usize)
                    else {
                        return Err(IlError::llil_ssa_invalid_value_definition());
                    };

                    if !operation.results().contains_index(value_id.index()) {
                        return Err(IlError::llil_ssa_invalid_value_definition());
                    }
                }
                ValueDefinitionKind::BlockArgument => {
                    let Some(argument) =
                        self.block_arguments.get(value.definition_index() as usize)
                    else {
                        return Err(IlError::llil_ssa_invalid_value_definition());
                    };

                    if argument.value() != value_id || argument.width() != value.width() {
                        return Err(IlError::llil_ssa_invalid_value_definition());
                    }
                }
            }
        }

        self.verify_dominating_uses()?;

        Ok(())
    }
}

impl SsaBody {
    fn verify_memory_domains(&self) -> Result<(), IlError> {
        for (index, domain) in self.memory_domains.iter().enumerate() {
            if self.memory_domains[..index]
                .iter()
                .any(|existing| existing.space() == domain.space())
            {
                return Err(IlError::llil_ssa_duplicate_memory_domain());
            }
        }

        Ok(())
    }

    fn verify_memory_operation(&self, operation: &SsaOperation) -> Result<(), IlError> {
        let operands = self.operation_operands(operation)?;
        let Some(memory) = operands.last() else {
            return Err(IlError::llil_ssa_missing_memory_domain());
        };
        let memory = self.values[memory.index()];

        if memory.width() != 0 {
            return Err(IlError::llil_ssa_width_mismatch());
        }

        if operation.opcode() == SsaOpcode::Store {
            if operation.results().len() != 1 {
                return Err(IlError::llil_ssa_missing_memory_domain());
            }

            let result = self.values[operation.results().start()];

            if result.width() != 0 {
                return Err(IlError::llil_ssa_width_mismatch());
            }
        }

        Ok(())
    }

    fn verify_edge_arguments(&self) -> Result<(), IlError> {
        if self.edge_arguments.len() != self.common.successors().len() {
            return Err(IlError::llil_ssa_block_argument_count(
                0,
                self.common.successors().len(),
                self.edge_arguments.len(),
            ));
        }

        for range in &self.edge_arguments {
            range.verify_bounds(self.edge_argument_values.len())?;
        }

        for value in &self.edge_argument_values {
            self.values
                .get(value.index())
                .ok_or(IlError::range_out_of_bounds(
                    value.value(),
                    self.values.len(),
                ))?;
        }

        Ok(())
    }

    fn verify_dominating_uses(&self) -> Result<(), IlError> {
        if self.common.blocks().is_empty() {
            return self.verify_linear_dominating_uses();
        }

        let operation_blocks = self.operation_blocks()?;
        let dominance = self.dominance()?;

        self.verify_edge_argument_uses(&operation_blocks, &dominance)?;

        for (operation_index, operation) in self.operations.iter().enumerate() {
            let operation_id = OperationId::try_from_index(operation_index)?;
            let Some(user_block) = operation_blocks[operation_index] else {
                return Err(IlError::llil_ssa_invalid_operation_placement(
                    operation_id.value(),
                ));
            };

            if !dominance.is_reachable(user_block) {
                continue;
            }

            for operand in self.operation_operands(operation)? {
                if !self.value_dominates_operation(
                    *operand,
                    user_block,
                    operation_index,
                    &operation_blocks,
                    &dominance,
                )? {
                    return Err(IlError::llil_ssa_non_dominating_use(
                        operand.value(),
                        operation_id.value(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn verify_edge_argument_uses(
        &self,
        operation_blocks: &[Option<BlockId>],
        dominance: &Dominance,
    ) -> Result<(), IlError> {
        for (predecessor_index, predecessor) in self.common.blocks().iter().enumerate() {
            let predecessor_id = BlockId::try_from_index(predecessor_index)?;

            for (successor_offset, successor) in predecessor
                .successors()
                .checked_slice(self.common.successors())?
                .iter()
                .enumerate()
            {
                let edge = predecessor.successors().start() + successor_offset;
                let arguments = self.arguments_for_edge(edge)?;
                let block_arguments = self.block_arguments_for_block(*successor);

                if arguments.len() != block_arguments.len() {
                    return Err(IlError::llil_ssa_block_argument_count(
                        successor.value(),
                        block_arguments.len(),
                        arguments.len(),
                    ));
                }

                if !dominance.is_reachable(predecessor_id) {
                    continue;
                }

                for (value, argument) in arguments.iter().zip(block_arguments) {
                    let incoming = self.values[value.index()];

                    if incoming.width() != argument.width() {
                        return Err(IlError::llil_ssa_width_mismatch());
                    }

                    if !self.value_dominates_edge(
                        *value,
                        predecessor_id,
                        operation_blocks,
                        dominance,
                    )? {
                        return Err(IlError::llil_ssa_non_dominating_edge_argument(
                            value.value(),
                            predecessor_id.value(),
                            successor.value(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    fn block_arguments_for_block(&self, block: BlockId) -> Vec<BlockArgument> {
        self.block_arguments
            .iter()
            .copied()
            .filter(|argument| argument.block() == block)
            .collect()
    }

    fn verify_linear_dominating_uses(&self) -> Result<(), IlError> {
        for (operation_index, operation) in self.operations.iter().enumerate() {
            let operation_id = OperationId::try_from_index(operation_index)?;

            for operand in self.operation_operands(operation)? {
                let value = self.values[operand.index()];

                if value.definition_kind() == ValueDefinitionKind::Operation
                    && value.definition_index() as usize >= operation_index
                {
                    return Err(IlError::llil_ssa_non_dominating_use(
                        operand.value(),
                        operation_id.value(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn operation_blocks(&self) -> Result<Vec<Option<BlockId>>, IlError> {
        let mut operation_blocks = vec![None; self.operations.len()];

        for (block_index, block) in self.common.blocks().iter().enumerate() {
            let block_id = BlockId::try_from_index(block_index)?;
            block.operations().verify_bounds(self.operations.len())?;

            for (operation_index, operation_block) in operation_blocks
                .iter_mut()
                .enumerate()
                .take(block.operations().end())
                .skip(block.operations().start())
            {
                if operation_block.is_some() {
                    let operation_id = OperationId::try_from_index(operation_index)?;
                    return Err(IlError::llil_ssa_invalid_operation_placement(
                        operation_id.value(),
                    ));
                }

                *operation_block = Some(block_id);
            }
        }

        Ok(operation_blocks)
    }

    fn value_dominates_operation(
        &self,
        value_id: ValueId,
        user_block: BlockId,
        user_operation: usize,
        operation_blocks: &[Option<BlockId>],
        dominance: &Dominance,
    ) -> Result<bool, IlError> {
        let value = self.values[value_id.index()];

        match value.definition_kind() {
            ValueDefinitionKind::Operation => {
                let definition_operation = value.definition_index() as usize;
                let Some(definition_block) = operation_blocks
                    .get(definition_operation)
                    .copied()
                    .flatten()
                else {
                    let operation_id = OperationId::try_from_index(definition_operation)?;
                    return Err(IlError::llil_ssa_invalid_operation_placement(
                        operation_id.value(),
                    ));
                };

                if definition_block == user_block {
                    Ok(definition_operation < user_operation)
                } else {
                    Ok(dominance.dominates(definition_block, user_block))
                }
            }
            ValueDefinitionKind::BlockArgument => {
                let argument = self.block_arguments[value.definition_index() as usize];

                Ok(dominance.dominates(argument.block(), user_block))
            }
        }
    }

    fn value_dominates_edge(
        &self,
        value_id: ValueId,
        predecessor: BlockId,
        operation_blocks: &[Option<BlockId>],
        dominance: &Dominance,
    ) -> Result<bool, IlError> {
        let value = self.values[value_id.index()];

        match value.definition_kind() {
            ValueDefinitionKind::Operation => {
                let definition_operation = value.definition_index() as usize;
                let Some(definition_block) = operation_blocks
                    .get(definition_operation)
                    .copied()
                    .flatten()
                else {
                    let operation_id = OperationId::try_from_index(definition_operation)?;
                    return Err(IlError::llil_ssa_invalid_operation_placement(
                        operation_id.value(),
                    ));
                };

                Ok(definition_block == predecessor
                    || dominance.dominates(definition_block, predecessor))
            }
            ValueDefinitionKind::BlockArgument => {
                let argument = self.block_arguments[value.definition_index() as usize];

                Ok(dominance.dominates(argument.block(), predecessor))
            }
        }
    }
}

impl IrArtefact for SsaBody {
    const LEVEL: IrLevel = IrLevel::LlilSsa;
    const SCHEMA: SchemaVersion = LLIL_SSA_SCHEMA_VERSION;

    fn header(&self) -> &ArtefactHeader {
        &self.header
    }

    fn header_mut(&mut self) -> &mut ArtefactHeader {
        &mut self.header
    }

    fn common(&self) -> &CommonBody {
        &self.common
    }

    fn to_raw_artefact(&self) -> Result<RawIrArtefact, IlError> {
        self.verify()?;

        let payload = SsaPayload::new(
            self.values.clone(),
            self.block_arguments.clone(),
            self.edge_arguments.clone(),
            self.edge_argument_values.clone(),
            self.operations.clone(),
            self.value_operands.clone(),
            self.memory_domains.clone(),
        );
        let payload = rkyv::to_bytes::<rkyv::rancor::Error>(&payload)
            .map(|bytes| bytes.to_vec())
            .map_err(|_| IlError::artefact_encode(Self::LEVEL))?;

        Ok(RawIrArtefact::new(
            self.header,
            self.common.clone(),
            payload,
        ))
    }

    fn from_raw_artefact(artefact: RawIrArtefact) -> Result<Self, IlError> {
        artefact.verify()?;
        artefact.header().verify_schema(Self::LEVEL, Self::SCHEMA)?;

        let payload = Self::decode_payload(artefact.payload())?;
        let body = Self::new(
            *artefact.header(),
            artefact.body().clone(),
            payload.values,
            payload.block_arguments,
            payload.operations,
            payload.value_operands,
            payload.memory_domains,
        );
        let body =
            body.with_edge_argument_storage(payload.edge_arguments, payload.edge_argument_values);

        body.verify()?;

        Ok(body)
    }

    fn verify_raw_artefact(artefact: &RawIrArtefact) -> Result<(), IlError> {
        artefact.verify()?;
        artefact.header().verify_schema(Self::LEVEL, Self::SCHEMA)?;

        let payload = Self::decode_payload(artefact.payload())?;
        let body = Self::new(
            *artefact.header(),
            artefact.body().clone(),
            payload.values,
            payload.block_arguments,
            payload.operations,
            payload.value_operands,
            payload.memory_domains,
        );
        let body =
            body.with_edge_argument_storage(payload.edge_arguments, payload.edge_argument_values);

        body.verify()
    }
}

#[derive(Debug)]
pub struct SsaBuilder {
    header: ArtefactHeader,
    common: CommonBody,
    values: Vec<Value>,
    block_arguments: Vec<BlockArgument>,
    edge_arguments: Vec<PackedRange>,
    edge_argument_values: Pool<ValueId>,
    operations: Vec<SsaOperation>,
    value_operands: Pool<ValueId>,
    memory_domains: Vec<MemoryDomain>,
}

impl SsaBuilder {
    pub fn new(header: ArtefactHeader, common: CommonBody) -> Self {
        Self {
            header,
            common,
            values: Vec::new(),
            block_arguments: Vec::new(),
            edge_arguments: Vec::new(),
            edge_argument_values: Pool::new(),
            operations: Vec::new(),
            value_operands: Pool::new(),
            memory_domains: Vec::new(),
        }
    }

    pub fn push_result_value(&mut self, width: u32) -> Result<(ValueId, PackedRange), IlError> {
        let id = ValueId::try_from_index(self.values.len())?;
        let operation = OperationId::try_from_index(self.operations.len())?;
        let results = PackedRange::new(self.values.len(), self.values.len() + 1)?;

        self.values.push(Value::operation_result(width, operation));

        Ok((id, results))
    }

    pub fn push_block_argument_value(
        &mut self,
        block: BlockId,
        width: u32,
    ) -> Result<ValueId, IlError> {
        self.common
            .blocks()
            .get(block.index())
            .ok_or(IlError::range_out_of_bounds(
                block.value(),
                self.common.blocks().len(),
            ))?;

        let argument_index = u32::try_from(self.block_arguments.len())
            .map_err(|_| IlError::integer_overflow("SSA block argument index"))?;
        let value = ValueId::try_from_index(self.values.len())?;

        self.values
            .push(Value::block_argument(width, argument_index));
        self.block_arguments
            .push(BlockArgument::new(block, value, width));

        Ok(value)
    }

    pub fn block_arguments_for_block(
        &self,
        block: BlockId,
    ) -> impl Iterator<Item = &BlockArgument> {
        self.block_arguments
            .iter()
            .filter(move |argument| argument.block() == block)
    }

    pub fn push_operation(&mut self, operation: SsaOperation) -> Result<OperationId, IlError> {
        let id = OperationId::try_from_index(self.operations.len())?;
        self.operations.push(operation);
        Ok(id)
    }

    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }

    pub fn replace_common(&mut self, common: CommonBody) {
        self.common = common;
    }

    pub fn push_value_operands(
        &mut self,
        operands: impl IntoIterator<Item = ValueId>,
    ) -> Result<PackedRange, IlError> {
        self.value_operands.append(operands)
    }

    pub fn push_edge_arguments(
        &mut self,
        operands: impl IntoIterator<Item = ValueId>,
    ) -> Result<PackedRange, IlError> {
        let range = self.edge_argument_values.append(operands)?;

        self.edge_arguments.push(range);

        Ok(range)
    }

    pub fn clear_edge_arguments(&mut self) {
        self.edge_arguments.clear();
        self.edge_argument_values.clear();
    }

    pub fn ensure_memory_domain(&mut self, space: AddressSpaceId) -> usize {
        if let Some(index) = self
            .memory_domains
            .iter()
            .position(|domain| domain.space() == space)
        {
            return index;
        }

        self.memory_domains.push(MemoryDomain::new(space));
        self.memory_domains.len() - 1
    }
}

impl Finish for SsaBuilder {
    type Output = SsaBody;

    fn finish(
        mut self,
        status: &(impl BuildCancellation + ?Sized),
    ) -> Result<Self::Output, IlError> {
        if status.is_cancelled() {
            return Err(IlError::cancelled());
        }

        if self.edge_arguments.is_empty() && !self.common.successors().is_empty() {
            self.edge_arguments = vec![PackedRange::EMPTY; self.common.successors().len()];
        }

        let mut body = SsaBody::new(
            self.header,
            self.common,
            self.values,
            self.block_arguments,
            self.operations,
            self.value_operands.into_values(),
            self.memory_domains,
        )
        .with_edge_argument_storage(self.edge_arguments, self.edge_argument_values.into_values());

        body.shrink_to_fit();
        body.verify()?;

        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::common::{Block, BuildStatus, SourceRun};
    use crate::il::llil::ssa::SsaOpcode;
    use crate::ir::{Address, FunctionId};
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn ssa_builder_finishes_verified_body() {
        assert!(std::mem::size_of::<Value>() <= 12);
        assert!(std::mem::size_of::<BlockArgument>() <= 12);
        assert!(std::mem::size_of::<SsaOperation>() <= 64);
        assert!(std::mem::size_of::<MemoryDomain>() <= 4);

        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let mut builder = SsaBuilder::new(header, CommonBody::default());
        let (value, results) = builder.push_result_value(64).unwrap();

        builder
            .push_operation(SsaOperation::new(
                SsaOpcode::Constant,
                results,
                PackedRange::EMPTY,
                64,
            ))
            .unwrap();

        let operands = builder.push_value_operands([value]).unwrap();

        builder
            .push_operation(SsaOperation::new(
                SsaOpcode::Return,
                PackedRange::EMPTY,
                operands,
                0,
            ))
            .unwrap();

        let body = builder.finish(&BuildStatus::new()).unwrap();
        let raw = body.to_raw_artefact().unwrap();

        assert_eq!(body.values().len(), 1);
        assert_eq!(body.operations().len(), 2);
        assert!(raw.verify_as::<SsaBody>().is_ok());
    }

    #[test]
    fn ssa_body_returns_operations_for_source() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let address = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let other = Address::new(AddressSpaceId::new(1), 0x2000u64);
        let common = CommonBody::new(
            Vec::new(),
            Vec::new(),
            vec![
                SourceRun::new(PackedRange::new(0, 1).unwrap(), address, 0, 1),
                SourceRun::new(PackedRange::new(1, 2).unwrap(), other, 0, 1),
            ],
            Vec::new(),
        );
        let body = SsaBody::new(
            header,
            common,
            Vec::new(),
            Vec::new(),
            vec![
                SsaOperation::new(SsaOpcode::Trap, PackedRange::EMPTY, PackedRange::EMPTY, 0),
                SsaOperation::new(SsaOpcode::Trap, PackedRange::EMPTY, PackedRange::EMPTY, 0),
            ],
            Vec::new(),
            Vec::new(),
        );

        let operations = body.operations_for_source(other).collect::<Vec<_>>();

        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].0, 1);
        assert_eq!(operations[0].1.opcode(), SsaOpcode::Trap);
    }

    #[test]
    fn ssa_builder_records_block_argument_definition() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let block = BlockId::try_from_index(0).unwrap();
        let common = CommonBody::new(
            vec![Block::new(
                PackedRange::EMPTY,
                PackedRange::EMPTY,
                Block::ENTRY,
            )],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let mut builder = SsaBuilder::new(header, common);
        let value = builder.push_block_argument_value(block, 32).unwrap();

        let body = builder.finish(&BuildStatus::new()).unwrap();

        assert_eq!(body.block_arguments().len(), 1);
        assert_eq!(body.block_arguments()[0].block(), block);
        assert_eq!(body.block_arguments()[0].value(), value);
        assert_eq!(
            body.values()[value.index()].definition_kind(),
            ValueDefinitionKind::BlockArgument
        );
    }

    #[test]
    fn ssa_verifier_rejects_invalid_value_definition() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let body = SsaBody::new(
            header,
            CommonBody::default(),
            vec![Value::new(64, ValueDefinitionKind::Operation, 3)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        assert!(matches!(
            body.verify(),
            Err(IlError::InvalidValueDefinition { .. })
        ));
    }

    #[test]
    fn ssa_builder_interns_memory_domains() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let mut builder = SsaBuilder::new(header, CommonBody::default());
        let space = AddressSpaceId::new(7);

        assert_eq!(builder.ensure_memory_domain(space), 0);
        assert_eq!(builder.ensure_memory_domain(space), 0);

        let body = builder.finish(&BuildStatus::new()).unwrap();

        assert_eq!(body.memory_domains().len(), 1);
        assert_eq!(body.memory_domains()[0].space(), space);
    }

    #[test]
    fn ssa_verifier_rejects_duplicate_memory_domains() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let space = AddressSpaceId::new(7);
        let body = SsaBody::new(
            header,
            CommonBody::default(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![MemoryDomain::new(space), MemoryDomain::new(space)],
        );

        assert!(matches!(
            body.verify(),
            Err(IlError::DuplicateMemoryDomain { .. })
        ));
    }

    #[test]
    fn ssa_verifier_rejects_load_without_memory_domain() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let space = AddressSpaceId::new(7);
        let mut builder = SsaBuilder::new(header, CommonBody::default());
        let (_value, results) = builder.push_result_value(8).unwrap();

        builder
            .push_operation(
                SsaOperation::new(SsaOpcode::Load, results, PackedRange::EMPTY, 8)
                    .with_address_space(space),
            )
            .unwrap();

        assert!(matches!(
            builder.finish(&BuildStatus::new()),
            Err(IlError::MissingMemoryDomain { .. })
        ));
    }

    #[test]
    fn ssa_verifier_rejects_non_dominating_linear_use() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let value = ValueId::try_from_index(0).unwrap();
        let result = PackedRange::new(0, 1).unwrap();
        let operands = PackedRange::new(0, 1).unwrap();
        let body = SsaBody::new(
            header,
            CommonBody::default(),
            vec![Value::operation_result(
                32,
                OperationId::try_from_index(1).unwrap(),
            )],
            Vec::new(),
            vec![
                SsaOperation::new(SsaOpcode::Return, PackedRange::EMPTY, operands, 0),
                SsaOperation::new(SsaOpcode::Constant, result, PackedRange::EMPTY, 32),
            ],
            vec![value],
            Vec::new(),
        );

        assert!(matches!(
            body.verify(),
            Err(IlError::NonDominatingUse { .. })
        ));
    }

    #[test]
    fn ssa_verifier_rejects_non_dominating_block_use() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let left = BlockId::try_from_index(1).unwrap();
        let right = BlockId::try_from_index(2).unwrap();
        let value = ValueId::try_from_index(0).unwrap();
        let common = CommonBody::new(
            vec![
                Block::new(
                    PackedRange::EMPTY,
                    PackedRange::new(0, 2).unwrap(),
                    Block::ENTRY,
                ),
                Block::new(PackedRange::new(0, 1).unwrap(), PackedRange::EMPTY, 0),
                Block::new(PackedRange::new(1, 2).unwrap(), PackedRange::EMPTY, 0),
            ],
            vec![left, right],
            Vec::new(),
            Vec::new(),
        );
        let body = SsaBody::new(
            header,
            common,
            vec![Value::operation_result(
                32,
                OperationId::try_from_index(0).unwrap(),
            )],
            Vec::new(),
            vec![
                SsaOperation::new(
                    SsaOpcode::Constant,
                    PackedRange::new(0, 1).unwrap(),
                    PackedRange::EMPTY,
                    32,
                ),
                SsaOperation::new(
                    SsaOpcode::Return,
                    PackedRange::EMPTY,
                    PackedRange::new(0, 1).unwrap(),
                    0,
                ),
            ],
            vec![value],
            Vec::new(),
        );

        assert!(matches!(
            body.verify(),
            Err(IlError::NonDominatingUse { .. })
        ));
    }

    #[test]
    fn ssa_verifier_rejects_wrong_edge_argument_count() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let successor = BlockId::try_from_index(1).unwrap();
        let argument_value = ValueId::try_from_index(0).unwrap();
        let common = CommonBody::new(
            vec![
                Block::new(
                    PackedRange::EMPTY,
                    PackedRange::new(0, 1).unwrap(),
                    Block::ENTRY,
                ),
                Block::new(PackedRange::EMPTY, PackedRange::EMPTY, Block::EXIT),
            ],
            vec![successor],
            Vec::new(),
            Vec::new(),
        );
        let body = SsaBody::new(
            header,
            common,
            vec![Value::block_argument(32, 0)],
            vec![BlockArgument::new(successor, argument_value, 32)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .with_edge_argument_storage(vec![PackedRange::EMPTY], Vec::new());

        assert!(matches!(
            body.verify(),
            Err(IlError::BlockArgumentCount { .. })
        ));
    }

    #[test]
    fn ssa_verifier_rejects_non_dominating_edge_argument() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let left = BlockId::try_from_index(1).unwrap();
        let right = BlockId::try_from_index(2).unwrap();
        let value = ValueId::try_from_index(0).unwrap();
        let argument_value = ValueId::try_from_index(1).unwrap();
        let common = CommonBody::new(
            vec![
                Block::new(
                    PackedRange::EMPTY,
                    PackedRange::new(0, 2).unwrap(),
                    Block::ENTRY,
                ),
                Block::new(PackedRange::new(0, 1).unwrap(), PackedRange::EMPTY, 0),
                Block::new(PackedRange::EMPTY, PackedRange::EMPTY, Block::EXIT),
            ],
            vec![left, right],
            Vec::new(),
            Vec::new(),
        );
        let body = SsaBody::new(
            header,
            common,
            vec![
                Value::operation_result(32, OperationId::try_from_index(0).unwrap()),
                Value::block_argument(32, 0),
            ],
            vec![BlockArgument::new(right, argument_value, 32)],
            vec![SsaOperation::new(
                SsaOpcode::Constant,
                PackedRange::new(0, 1).unwrap(),
                PackedRange::EMPTY,
                32,
            )],
            Vec::new(),
            Vec::new(),
        )
        .with_edge_argument_storage(
            vec![PackedRange::EMPTY, PackedRange::new(0, 1).unwrap()],
            vec![value],
        );

        assert!(matches!(
            body.verify(),
            Err(IlError::NonDominatingEdgeArgument { .. })
        ));
    }

    #[test]
    fn ssa_verifier_rejects_duplicate_operation_placement() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let common = CommonBody::new(
            vec![
                Block::new(
                    PackedRange::new(0, 1).unwrap(),
                    PackedRange::EMPTY,
                    Block::ENTRY,
                ),
                Block::new(PackedRange::new(0, 1).unwrap(), PackedRange::EMPTY, 0),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let body = SsaBody::new(
            header,
            common,
            vec![Value::operation_result(
                32,
                OperationId::try_from_index(0).unwrap(),
            )],
            Vec::new(),
            vec![SsaOperation::new(
                SsaOpcode::Constant,
                PackedRange::new(0, 1).unwrap(),
                PackedRange::EMPTY,
                32,
            )],
            Vec::new(),
            Vec::new(),
        );

        assert!(matches!(
            body.verify(),
            Err(IlError::OverlappingBlockOperations { .. })
        ));
    }
}
