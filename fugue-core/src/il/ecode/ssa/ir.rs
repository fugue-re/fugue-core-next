use std::mem::size_of;

use fugue_bv::BitVec;

use crate::il::common::{
    ControlFlowIl, IlArtefact, IlBlockId, IlConstantInterner, IlGraph, IlIndexRange, IlMetadata,
    IlOpId, IlParentSpan, IlSchemaVersion, IlSourceSpan, IlSsaDef, IlValueId, PersistableIl,
};
use crate::il::ecode::ssa::{
    ECodeSsaBlockArg, ECodeSsaBuilderContext, ECodeSsaDomain, ECodeSsaMemoryDomain, ECodeSsaOp,
    ECodeSsaOpcode, ECodeSsaValue,
};
use crate::ir::{Address, AddressRange};
use crate::storage::segments::space::AddressSpaceId;
use crate::types::EstimateSize;

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ECodeSsaIr {
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    values: Vec<ECodeSsaValue>,
    value_domains: Vec<Option<ECodeSsaDomain>>,
    block_arguments: Vec<ECodeSsaBlockArg>,
    edge_arguments: Vec<IlIndexRange>,
    edge_argument_values: Vec<IlValueId>,
    operations: Vec<ECodeSsaOp>,
    value_operands: Vec<IlValueId>,
    memory_domains: Vec<ECodeSsaMemoryDomain>,
    constant_storage: Vec<u8>,
}

impl ECodeSsaIr {
    pub(crate) fn new(context: ECodeSsaBuilderContext) -> Self {
        let ECodeSsaBuilderContext {
            metadata,
            graph,
            source_spans,
            parent_spans,
            values,
            value_domains,
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
            values,
            value_domains,
            block_arguments,
            edge_arguments,
            edge_argument_values,
            operations,
            value_operands,
            memory_domains,
            constant_storage,
        }
    }

    pub(crate) fn rewriter(&mut self) -> ECodeSsaRewriter<'_> {
        let mut constants = IlConstantInterner::new();
        for operation in &self.operations {
            if let Some(bytes) = operation.constant_bytes(&self.constant_storage) {
                constants.index_existing(bytes, operation.immediate());
            }
        }
        ECodeSsaRewriter {
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

    pub fn values(&self) -> &[ECodeSsaValue] {
        &self.values
    }

    pub fn value_domain(&self, value: IlValueId) -> Option<ECodeSsaDomain> {
        self.value_domains.get(value.index()).copied().flatten()
    }

    pub(crate) fn value_domains(&self) -> &[Option<ECodeSsaDomain>] {
        &self.value_domains
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

    pub fn operation_operands(&self) -> &[IlValueId] {
        &self.value_operands
    }

    pub fn memory_domains(&self) -> &[ECodeSsaMemoryDomain] {
        &self.memory_domains
    }

    pub(crate) fn constant_storage(&self) -> &[u8] {
        &self.constant_storage
    }

    pub fn memory_domain(&self, space: AddressSpaceId) -> Option<&ECodeSsaMemoryDomain> {
        self.memory_domains
            .iter()
            .find(|domain| domain.space() == space)
    }

    pub fn operation_operands_for(&self, operation: &ECodeSsaOp) -> &[IlValueId] {
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

    pub(crate) fn block_address(&self, block: IlBlockId) -> Option<Address> {
        if let Some(address) = self.graph.block_source(block) {
            return Some(address);
        }
        let range = self.graph.blocks().get(block.index())?.operations();
        self.source_span_for(range.start())
            .map(|span| span.address())
    }

    pub fn defining_operation(&self, value: IlValueId) -> Option<&ECodeSsaOp> {
        let record = self.values.get(value.index())?;
        let IlSsaDef::Operation(operation) = record.definition() else {
            return None;
        };
        self.operations.get(operation.index())
    }

    pub fn memory_operand(&self, operation: &ECodeSsaOp) -> Option<IlValueId> {
        if !operation.opcode().requires_memory_domain() {
            return None;
        }

        self.operation_operands_for(operation).last().copied()
    }

    pub fn pointer_operand(&self, operation: &ECodeSsaOp) -> Option<IlValueId> {
        if !matches!(
            operation.opcode(),
            ECodeSsaOpcode::Load | ECodeSsaOpcode::Store
        ) {
            return None;
        }

        self.operation_operands_for(operation).first().copied()
    }

    pub fn underlying_value(&self, value: IlValueId) -> IlValueId {
        let mut current = value;
        for _ in 0..self.values.len() {
            let Some(operation) = self.defining_operation(current) else {
                return current;
            };
            match operation.opcode() {
                ECodeSsaOpcode::Copy
                | ECodeSsaOpcode::SignExtend
                | ECodeSsaOpcode::Truncate
                | ECodeSsaOpcode::WriteFlag
                | ECodeSsaOpcode::WriteRegister
                | ECodeSsaOpcode::ZeroExtend => {
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

    pub(crate) fn extract_source(&self, value: IlValueId) -> Option<IlValueId> {
        let extract = self.defining_operation(value)?;
        if extract.opcode() != ECodeSsaOpcode::Extract {
            return None;
        }
        let &source = self.operation_operands_for(extract).first()?;
        let offset = extract.immediate();

        if let Some(insert) = self.defining_operation(source)
            && insert.opcode() == ECodeSsaOpcode::Insert
            && insert.immediate() == offset
            && let Some(&inserted) = self.operation_operands_for(insert).get(1)
            && self.value_width(inserted) == Some(extract.width())
        {
            return Some(inserted);
        }

        (offset == 0).then_some(source)
    }

    pub fn value_width(&self, value: IlValueId) -> Option<u32> {
        self.values.get(value.index()).map(ECodeSsaValue::width)
    }

    pub fn constant_value(&self, value: IlValueId) -> Option<BitVec> {
        let mut current = value;
        for _ in 0..self.values.len() {
            let operation = self.defining_operation(current)?;
            if !matches!(
                operation.opcode(),
                ECodeSsaOpcode::WriteFlag | ECodeSsaOpcode::WriteRegister
            ) {
                return operation.constant(&self.constant_storage);
            }
            current = *self.operation_operands_for(operation).first()?;
        }
        None
    }

    pub fn memory_access_range(&self, operation: &ECodeSsaOp) -> Option<AddressRange> {
        let space = operation.address_space()?;
        let pointer = self.defining_operation(self.pointer_operand(operation)?)?;
        if pointer.opcode() != ECodeSsaOpcode::Address {
            return None;
        }
        let width = match operation.opcode() {
            ECodeSsaOpcode::Load => operation.width(),
            ECodeSsaOpcode::Store => self
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
    ) -> impl Iterator<Item = (IlOpId, &ECodeSsaOp)> + '_ {
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
    ) -> impl DoubleEndedIterator<Item = (IlOpId, &ECodeSsaOp)> + '_ {
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
        self.values.shrink_to_fit();
        self.value_domains.shrink_to_fit();
        self.block_arguments.shrink_to_fit();
        self.edge_arguments.shrink_to_fit();
        self.edge_argument_values.shrink_to_fit();
        self.operations.shrink_to_fit();
        self.value_operands.shrink_to_fit();
        self.memory_domains.shrink_to_fit();
        self.constant_storage.shrink_to_fit();
    }
}

pub(crate) struct ECodeSsaRewriter<'a> {
    operations: &'a mut Vec<ECodeSsaOp>,
    constant_storage: &'a mut Vec<u8>,
    constants: IlConstantInterner,
}

impl ECodeSsaRewriter<'_> {
    pub(crate) fn operations(&self) -> &[ECodeSsaOp] {
        self.operations
    }

    pub(crate) fn replace_with_constant(&mut self, operation: IlOpId, value: &BitVec) {
        let immediate = self.constants.intern(self.constant_storage, value);
        self.operations[operation.index()].replace_with_constant(immediate);
    }
}

impl IlArtefact for ECodeSsaIr {
    const FORM_IDENTIFIER: &str = "fugue.ecode.ssa";

    fn metadata(&self) -> &IlMetadata {
        &self.metadata
    }

    #[cfg(debug_assertions)]
    fn verify_after_rewrite(&self) {
        self.verify()
            .expect("ECode SSA rewrite produced invalid IR");
    }
}

impl ControlFlowIl for ECodeSsaIr {
    fn graph(&self) -> &IlGraph {
        &self.graph
    }
}

impl PersistableIl for ECodeSsaIr {
    const SCHEMA: IlSchemaVersion = IlSchemaVersion::new(2);

    fn metadata_mut(&mut self) -> &mut IlMetadata {
        &mut self.metadata
    }
}

impl EstimateSize for ECodeSsaIr {
    fn estimate_size(&self) -> usize {
        [
            self.graph.estimate_size(),
            self.source_spans
                .capacity()
                .saturating_mul(size_of::<IlSourceSpan>()),
            self.parent_spans
                .capacity()
                .saturating_mul(size_of::<IlParentSpan>()),
            self.values
                .capacity()
                .saturating_mul(size_of::<ECodeSsaValue>()),
            self.value_domains
                .capacity()
                .saturating_mul(size_of::<Option<ECodeSsaDomain>>()),
            self.block_arguments
                .capacity()
                .saturating_mul(size_of::<ECodeSsaBlockArg>()),
            self.edge_arguments
                .capacity()
                .saturating_mul(size_of::<IlIndexRange>()),
            self.edge_argument_values
                .capacity()
                .saturating_mul(size_of::<IlValueId>()),
            self.operations
                .capacity()
                .saturating_mul(size_of::<ECodeSsaOp>()),
            self.value_operands
                .capacity()
                .saturating_mul(size_of::<IlValueId>()),
            self.memory_domains
                .capacity()
                .saturating_mul(size_of::<ECodeSsaMemoryDomain>()),
            self.constant_storage.capacity(),
        ]
        .into_iter()
        .fold(
            size_of::<Self>().saturating_sub(size_of::<IlGraph>()),
            usize::saturating_add,
        )
    }
}
