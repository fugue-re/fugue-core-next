use std::mem::size_of;

use fugue_bv::BitVec;

use crate::il::common::{
    ControlFlowIl, IlArtefact, IlBlockId, IlConstantInterner, IlGraph, IlIndexRange, IlMetadata,
    IlOpId, IlParentSpan, IlSchemaVersion, IlSourceSpan, IlSsaDef, IlValueId, PersistableIl,
};
use crate::il::mcode::ssa::{
    MCodeSsaBinding, MCodeSsaBlockArg, MCodeSsaBuilderContext, MCodeSsaMemoryDomain, MCodeSsaOp,
    MCodeSsaOpcode, MCodeSsaValue,
};
use crate::il::mcode::{MCodeVar, MCodeVarId};
use crate::ir::{Address, AddressRange};
use crate::storage::segments::space::AddressSpaceId;
use crate::types::EstimateSize;

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct MCodeSsaIr {
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    variables: Vec<MCodeVar>,
    aliased_variables: Vec<MCodeVarId>,
    values: Vec<MCodeSsaValue>,
    block_arguments: Vec<MCodeSsaBlockArg>,
    edge_arguments: Vec<IlIndexRange>,
    edge_argument_values: Vec<IlValueId>,
    operations: Vec<MCodeSsaOp>,
    value_operands: Vec<IlValueId>,
    memory_domains: Vec<MCodeSsaMemoryDomain>,
    constant_storage: Vec<u8>,
}

impl MCodeSsaIr {
    pub(crate) fn new(context: MCodeSsaBuilderContext) -> Self {
        let MCodeSsaBuilderContext {
            metadata,
            graph,
            source_spans,
            parent_spans,
            variables,
            aliased_variables,
            values,
            block_arguments,
            edge_arguments,
            edge_argument_values,
            operations,
            value_operands,
            memory_domains,
            constant_storage,
        } = context;
        Self {
            metadata,
            graph,
            source_spans,
            parent_spans,
            variables,
            aliased_variables,
            values,
            block_arguments,
            edge_arguments,
            edge_argument_values,
            operations,
            value_operands,
            memory_domains,
            constant_storage,
        }
    }

    pub(crate) fn rewriter(&mut self) -> MCodeSsaRewriter<'_> {
        let mut constants = IlConstantInterner::new();
        for operation in &self.operations {
            if let Some(bytes) = operation.constant_bytes(&self.constant_storage) {
                constants.index_existing(bytes, operation.immediate());
            }
        }
        MCodeSsaRewriter {
            operations: &mut self.operations,
            constant_storage: &mut self.constant_storage,
            constants,
        }
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

    pub fn variables(&self) -> &[MCodeVar] {
        &self.variables
    }

    pub fn variable(&self, id: MCodeVarId) -> Option<&MCodeVar> {
        self.variables.get(id.index())
    }

    pub fn aliased_variables(&self) -> &[MCodeVarId] {
        &self.aliased_variables
    }

    pub fn is_aliased(&self, id: MCodeVarId) -> bool {
        self.aliased_variables.binary_search(&id).is_ok()
    }

    pub fn values(&self) -> &[MCodeSsaValue] {
        &self.values
    }

    pub fn binding(&self, value: IlValueId) -> Option<MCodeSsaBinding> {
        self.values
            .get(value.index())
            .and_then(MCodeSsaValue::binding)
    }

    pub fn versions_of(&self, id: MCodeVarId) -> impl Iterator<Item = IlValueId> + '_ {
        self.values
            .iter()
            .enumerate()
            .filter(move |(_, value)| value.variable() == Some(id))
            .map(|(index, _)| IlValueId::try_from_index(index).expect("value id is representable"))
    }

    pub fn block_arguments(&self) -> &[MCodeSsaBlockArg] {
        &self.block_arguments
    }

    pub fn edge_arguments(&self) -> &[IlIndexRange] {
        &self.edge_arguments
    }

    pub fn edge_argument_values(&self) -> &[IlValueId] {
        &self.edge_argument_values
    }

    pub fn operations(&self) -> &[MCodeSsaOp] {
        &self.operations
    }

    pub fn operation_operands(&self) -> &[IlValueId] {
        &self.value_operands
    }

    pub fn memory_domains(&self) -> &[MCodeSsaMemoryDomain] {
        &self.memory_domains
    }

    pub(crate) fn constant_storage(&self) -> &[u8] {
        &self.constant_storage
    }

    pub fn memory_domain(&self, space: AddressSpaceId) -> Option<&MCodeSsaMemoryDomain> {
        self.memory_domains
            .iter()
            .find(|domain| domain.space() == space)
    }

    pub fn operation_operands_for(&self, operation: &MCodeSsaOp) -> &[IlValueId] {
        operation.operands().slice(&self.value_operands)
    }

    pub fn block_for_operation(&self, operation: IlOpId) -> Option<IlBlockId> {
        self.graph
            .blocks()
            .iter()
            .position(|block| block.operations().contains_index(operation.index()))
            .and_then(|index| IlBlockId::try_from_index(index).ok())
    }

    pub(crate) fn operation_blocks(&self) -> Vec<Option<IlBlockId>> {
        let mut operation_blocks = vec![None; self.operations.len()];
        for (index, block) in self.graph.blocks().iter().enumerate() {
            let block_id =
                IlBlockId::try_from_index(index).expect("block count fits the block id space");
            for operation in block.operations().start()..block.operations().end() {
                if let Some(entry) = operation_blocks.get_mut(operation) {
                    *entry = Some(block_id);
                }
            }
        }
        operation_blocks
    }

    pub fn memory_operand(&self, operation: &MCodeSsaOp) -> Option<IlValueId> {
        if !operation.opcode().requires_memory_domain() {
            return None;
        }

        self.operation_operands_for(operation).last().copied()
    }

    pub fn pointer_operand(&self, operation: &MCodeSsaOp) -> Option<IlValueId> {
        if !matches!(
            operation.opcode(),
            MCodeSsaOpcode::Load | MCodeSsaOpcode::Store
        ) {
            return None;
        }

        self.operation_operands_for(operation).first().copied()
    }

    pub fn defining_operation(&self, value: IlValueId) -> Option<&MCodeSsaOp> {
        let record = self.values.get(value.index())?;
        let IlSsaDef::Operation(operation) = record.definition() else {
            return None;
        };
        self.operations.get(operation.index())
    }

    pub fn value_width(&self, value: IlValueId) -> Option<u32> {
        self.values.get(value.index()).map(MCodeSsaValue::width)
    }

    pub fn underlying_value(&self, value: IlValueId) -> IlValueId {
        let mut current = value;
        for _ in 0..self.values.len() {
            let Some(operation) = self.defining_operation(current) else {
                return current;
            };
            match operation.opcode() {
                MCodeSsaOpcode::Copy
                | MCodeSsaOpcode::SetVar
                | MCodeSsaOpcode::SignExtend
                | MCodeSsaOpcode::Truncate
                | MCodeSsaOpcode::ZeroExtend => {
                    let Some(inner) = self.operation_operands_for(operation).first().copied()
                    else {
                        return current;
                    };
                    current = inner;
                }
                _ => return current,
            }
        }
        current
    }

    pub fn constant_value(&self, value: IlValueId) -> Option<BitVec> {
        let mut current = value;
        for _ in 0..self.values.len() {
            let operation = self.defining_operation(current)?;
            if operation.opcode() != MCodeSsaOpcode::SetVar {
                return operation.constant(self.constant_storage());
            }
            current = *self.operation_operands_for(operation).first()?;
        }
        None
    }

    pub fn memory_access_range(&self, operation: &MCodeSsaOp) -> Option<AddressRange> {
        let space = operation.address_space()?;
        let pointer = self.defining_operation(self.pointer_operand(operation)?)?;
        if pointer.opcode() != MCodeSsaOpcode::Address {
            return None;
        }
        let width = match operation.opcode() {
            MCodeSsaOpcode::Load => operation.width(),
            MCodeSsaOpcode::Store => self
                .operation_operands_for(operation)
                .get(1)
                .copied()
                .and_then(|value| self.value_width(value))?,
            _ => return None,
        };
        AddressRange::from_size(
            Address::new(space, pointer.immediate()),
            u64::from(width.div_ceil(8)),
        )
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
    ) -> impl Iterator<Item = (IlOpId, &MCodeSsaOp)> + '_ {
        self.source_spans
            .iter()
            .filter(move |span| span.address() == address)
            .flat_map(move |span| {
                let start = span.destination().start();
                span.destination()
                    .slice(&self.operations)
                    .iter()
                    .enumerate()
                    .map(move |(index, operation)| {
                        (
                            IlOpId::try_from_index(start + index)
                                .expect("operation count fits the operation id space"),
                            operation,
                        )
                    })
            })
    }

    pub fn operations_for_block(
        &self,
        block: IlBlockId,
    ) -> impl DoubleEndedIterator<Item = (IlOpId, &MCodeSsaOp)> + '_ {
        self.graph
            .blocks()
            .get(block.index())
            .into_iter()
            .flat_map(|block| {
                let start = block.operations().start();
                block
                    .operations()
                    .slice(&self.operations)
                    .iter()
                    .enumerate()
                    .map(move |(index, operation)| {
                        (
                            IlOpId::try_from_index(start + index)
                                .expect("operation count fits the operation id space"),
                            operation,
                        )
                    })
            })
    }

    pub fn shrink_to_fit(&mut self) {
        self.graph.shrink_to_fit();
        self.source_spans.shrink_to_fit();
        self.parent_spans.shrink_to_fit();
        self.variables.shrink_to_fit();
        self.aliased_variables.shrink_to_fit();
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

pub(crate) struct MCodeSsaRewriter<'a> {
    operations: &'a mut Vec<MCodeSsaOp>,
    constant_storage: &'a mut Vec<u8>,
    constants: IlConstantInterner,
}

impl MCodeSsaRewriter<'_> {
    pub(crate) fn operations(&self) -> &[MCodeSsaOp] {
        self.operations
    }

    pub(crate) fn replace_with_constant(&mut self, operation: IlOpId, value: &BitVec) {
        let immediate = self.constants.intern(self.constant_storage, value);
        self.operations[operation.index()].replace_with_constant(immediate);
    }
}

impl IlArtefact for MCodeSsaIr {
    const FORM_IDENTIFIER: &str = "fugue.mcode.ssa";

    fn metadata(&self) -> &IlMetadata {
        &self.metadata
    }

    #[cfg(debug_assertions)]
    fn verify_after_rewrite(&self) {
        self.verify()
            .expect("MCode SSA rewrite produced invalid IR");
    }
}

impl ControlFlowIl for MCodeSsaIr {
    fn graph(&self) -> &IlGraph {
        &self.graph
    }
}

impl PersistableIl for MCodeSsaIr {
    const SCHEMA: IlSchemaVersion = IlSchemaVersion::new(2);

    fn metadata_mut(&mut self) -> &mut IlMetadata {
        &mut self.metadata
    }
}

impl EstimateSize for MCodeSsaIr {
    fn estimate_size(&self) -> usize {
        [
            self.graph.estimate_size(),
            self.source_spans
                .capacity()
                .saturating_mul(size_of::<IlSourceSpan>()),
            self.parent_spans
                .capacity()
                .saturating_mul(size_of::<IlParentSpan>()),
            self.variables
                .capacity()
                .saturating_mul(size_of::<MCodeVar>()),
            self.aliased_variables
                .capacity()
                .saturating_mul(size_of::<MCodeVarId>()),
            self.values
                .capacity()
                .saturating_mul(size_of::<MCodeSsaValue>()),
            self.block_arguments
                .capacity()
                .saturating_mul(size_of::<MCodeSsaBlockArg>()),
            self.edge_arguments
                .capacity()
                .saturating_mul(size_of::<IlIndexRange>()),
            self.edge_argument_values
                .capacity()
                .saturating_mul(size_of::<IlValueId>()),
            self.operations
                .capacity()
                .saturating_mul(size_of::<MCodeSsaOp>()),
            self.value_operands
                .capacity()
                .saturating_mul(size_of::<IlValueId>()),
            self.memory_domains
                .capacity()
                .saturating_mul(size_of::<MCodeSsaMemoryDomain>()),
            self.constant_storage.capacity(),
        ]
        .into_iter()
        .fold(
            size_of::<Self>().saturating_sub(size_of::<IlGraph>()),
            usize::saturating_add,
        )
    }
}
