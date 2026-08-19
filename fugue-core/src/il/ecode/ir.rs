use std::mem::{self, size_of};

use fugue_bv::BitVec;

use crate::il::common::{
    ControlFlowIl, IlArtefact, IlBlockArgId, IlBlockId, IlConstantInterner, IlGraph, IlIndexRange,
    IlMetadata, IlOpId, IlParentSpan, IlSchemaVersion, IlSourceSpan, IlSsaDef, IlValueId,
    PersistableIl, SsaIl,
};
use crate::il::ecode::verify::{VerifyError, verify};
use crate::il::ecode::{
    ECodeBlockArg, ECodeDomain, ECodeIrDisplay, ECodeMemoryDomain, ECodeOp, ECodeOpcode,
    ECodeSourceDisplay, ECodeValue,
};
use crate::ir::{Address, AddressRange};
use crate::storage::segments::space::AddressSpaceId;
use crate::types::EstimateSize;

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct ECodeIr {
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    values: Vec<ECodeValue>,
    value_domains: Vec<Option<ECodeDomain>>,
    block_args: Vec<ECodeBlockArg>,
    edge_args: Vec<IlIndexRange>,
    edge_arg_values: Vec<IlValueId>,
    operations: Vec<ECodeOp>,
    value_operands: Vec<IlValueId>,
    memory_domains: Vec<ECodeMemoryDomain>,
    constant_storage: Vec<u8>,
}

pub(crate) struct ECodeIrStorage {
    pub(crate) metadata: IlMetadata,
    pub(crate) graph: IlGraph,
    pub(crate) source_spans: Vec<IlSourceSpan>,
    pub(crate) parent_spans: Vec<IlParentSpan>,
    pub(crate) values: Vec<ECodeValue>,
    pub(crate) value_domains: Vec<Option<ECodeDomain>>,
    pub(crate) block_args: Vec<ECodeBlockArg>,
    pub(crate) edge_args: Vec<IlIndexRange>,
    pub(crate) edge_arg_values: Vec<IlValueId>,
    pub(crate) operations: Vec<ECodeOp>,
    pub(crate) value_operands: Vec<IlValueId>,
    pub(crate) memory_domains: Vec<ECodeMemoryDomain>,
    pub(crate) constant_storage: Vec<u8>,
}

impl ECodeIr {
    pub(crate) fn new(storage: ECodeIrStorage) -> Self {
        let ECodeIrStorage {
            metadata,
            graph,
            source_spans,
            parent_spans,
            values,
            value_domains,
            block_args,
            edge_args,
            edge_arg_values,
            operations,
            value_operands,
            memory_domains,
            constant_storage,
        } = storage;
        Self {
            metadata,
            graph,
            source_spans,
            parent_spans,
            values,
            value_domains,
            block_args,
            edge_args,
            edge_arg_values,
            operations,
            value_operands,
            memory_domains,
            constant_storage,
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

    pub fn values(&self) -> &[ECodeValue] {
        &self.values
    }

    pub fn value_domain(&self, value: IlValueId) -> Option<ECodeDomain> {
        self.value_domains.get(value.index()).copied().flatten()
    }

    pub(crate) fn value_domains(&self) -> &[Option<ECodeDomain>] {
        &self.value_domains
    }

    pub fn block_args(&self) -> &[ECodeBlockArg] {
        &self.block_args
    }

    pub fn edge_args(&self) -> &[IlIndexRange] {
        &self.edge_args
    }

    pub fn edge_arg_values(&self) -> &[IlValueId] {
        &self.edge_arg_values
    }

    pub fn ops(&self) -> &[ECodeOp] {
        &self.operations
    }

    pub fn op_operands(&self) -> &[IlValueId] {
        &self.value_operands
    }

    pub fn memory_domains(&self) -> &[ECodeMemoryDomain] {
        &self.memory_domains
    }

    pub(crate) fn constant_storage(&self) -> &[u8] {
        &self.constant_storage
    }

    pub fn memory_domain(&self, space: AddressSpaceId) -> Option<&ECodeMemoryDomain> {
        self.memory_domains
            .iter()
            .find(|domain| domain.space() == space)
    }

    pub fn op_operands_for(&self, operation: &ECodeOp) -> &[IlValueId] {
        operation.operands().slice(&self.value_operands)
    }

    pub fn block_for_op(&self, operation: IlOpId) -> Option<IlBlockId> {
        self.graph.block_for_op(operation)
    }

    pub fn value_width(&self, value: IlValueId) -> Option<u32> {
        self.values.get(value.index()).map(ECodeValue::width)
    }

    pub fn args_for_edge(&self, edge: usize) -> &[IlValueId] {
        self.edge_args
            .get(edge)
            .expect("edge index is within the edge argument table")
            .slice(&self.edge_arg_values)
    }

    pub fn shrink_to_fit(&mut self) {
        self.graph.shrink_to_fit();
        self.source_spans.shrink_to_fit();
        self.parent_spans.shrink_to_fit();
        self.values.shrink_to_fit();
        self.value_domains.shrink_to_fit();
        self.block_args.shrink_to_fit();
        self.edge_args.shrink_to_fit();
        self.edge_arg_values.shrink_to_fit();
        self.operations.shrink_to_fit();
        self.value_operands.shrink_to_fit();
        self.memory_domains.shrink_to_fit();
        self.constant_storage.shrink_to_fit();
    }

    pub(crate) fn op_blocks(&self) -> Vec<Option<IlBlockId>> {
        self.graph.op_blocks(self.operations.len())
    }

    pub(crate) fn block_address(&self, block: IlBlockId) -> Option<Address> {
        if let Some(address) = self.graph.block_source(block) {
            return Some(address);
        }
        let range = self.graph.blocks().get(block.index())?.ops();
        self.source_span_for(range.start())
            .map(|span| span.address())
    }

    pub fn constant_value(&self, value: IlValueId) -> Option<BitVec> {
        let mut current = value;
        for _ in 0..self.values.len() {
            let operation = self.defining_op(current)?;
            if !matches!(
                operation.opcode(),
                ECodeOpcode::WriteFlag | ECodeOpcode::WriteRegister
            ) {
                return operation.constant(&self.constant_storage);
            }
            current = *self.op_operands_for(operation).first()?;
        }
        None
    }

    pub fn memory_access_range(&self, operation: &ECodeOp) -> Option<AddressRange> {
        let space = operation.address_space()?;
        let pointer = self.defining_op(self.pointer_operand(operation)?)?;
        if pointer.opcode() != ECodeOpcode::Address {
            return None;
        }
        let width = match operation.opcode() {
            ECodeOpcode::Load => operation.width(),
            ECodeOpcode::Store => self
                .op_operands_for(operation)
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

    pub fn ops_for_source(
        &self,
        address: Address,
    ) -> impl Iterator<Item = (IlOpId, &ECodeOp)> + '_ {
        IlSourceSpan::ops(&self.source_spans, &self.operations, address)
    }

    pub fn defining_op(&self, value: IlValueId) -> Option<&ECodeOp> {
        let record = self.values.get(value.index())?;
        let IlSsaDef::Op(operation) = record.definition() else {
            return None;
        };
        self.operations.get(operation.index())
    }

    pub fn memory_operand(&self, operation: &ECodeOp) -> Option<IlValueId> {
        if !operation.opcode().requires_memory_domain() {
            return None;
        }

        self.op_operands_for(operation).last().copied()
    }

    pub fn pointer_operand(&self, operation: &ECodeOp) -> Option<IlValueId> {
        if !matches!(operation.opcode(), ECodeOpcode::Load | ECodeOpcode::Store) {
            return None;
        }

        self.op_operands_for(operation).first().copied()
    }

    pub fn underlying_value(&self, value: IlValueId) -> IlValueId {
        let mut current = value;
        for _ in 0..self.values.len() {
            let Some(operation) = self.defining_op(current) else {
                return current;
            };
            match operation.opcode() {
                ECodeOpcode::Copy
                | ECodeOpcode::SignExtend
                | ECodeOpcode::Truncate
                | ECodeOpcode::WriteFlag
                | ECodeOpcode::WriteRegister
                | ECodeOpcode::ZeroExtend => {
                    let Some(inner) = self.op_operands_for(operation).first().copied()
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
        let extract = self.defining_op(value)?;
        if extract.opcode() != ECodeOpcode::Extract {
            return None;
        }
        let &source = self.op_operands_for(extract).first()?;
        let offset = extract.immediate();

        if let Some(insert) = self.defining_op(source)
            && insert.opcode() == ECodeOpcode::Insert
            && insert.immediate() == offset
            && let Some(&inserted) = self.op_operands_for(insert).get(1)
            && self.value_width(inserted) == Some(extract.width())
        {
            return Some(inserted);
        }

        (offset == 0).then_some(source)
    }

    pub const fn display(&self) -> ECodeIrDisplay<'_> {
        ECodeIrDisplay::new(self)
    }

    pub const fn display_source(&self, address: Address) -> ECodeSourceDisplay<'_> {
        ECodeSourceDisplay::new(self, address)
    }

    pub(crate) fn take_graph(&mut self) -> IlGraph {
        mem::take(&mut self.graph)
    }

    pub(crate) fn take_memory_domains(&mut self) -> Vec<ECodeMemoryDomain> {
        mem::take(&mut self.memory_domains)
    }

    pub(crate) fn rewriter(&mut self) -> ECodeRewriter<'_> {
        let mut constants = IlConstantInterner::new();
        for operation in &self.operations {
            if let Some(bytes) = operation.constant_bytes(&self.constant_storage) {
                constants.index_existing(operation.immediate(), bytes);
            }
        }
        ECodeRewriter {
            operations: &mut self.operations,
            constant_storage: &mut self.constant_storage,
            constants,
        }
    }

    pub(crate) fn verify(&self) -> Result<(), VerifyError> {
        verify(self)
    }

}

pub(crate) struct ECodeRewriter<'a> {
    operations: &'a mut Vec<ECodeOp>,
    constant_storage: &'a mut Vec<u8>,
    constants: IlConstantInterner,
}

impl ECodeRewriter<'_> {
    pub(crate) fn ops(&self) -> &[ECodeOp] {
        self.operations
    }

    pub(crate) fn replace_with_constant(&mut self, operation: IlOpId, value: &BitVec) {
        let immediate = self.constants.intern(self.constant_storage, value);
        self.operations[operation.index()].replace_with_constant(immediate);
    }
}

impl IlArtefact for ECodeIr {
    const FORM_IDENTIFIER: &str = "fugue.ecode.cfg";

    fn metadata(&self) -> &IlMetadata {
        &self.metadata
    }

    #[cfg(debug_assertions)]
    fn verify_after_rewrite(&self) {
        self.verify().expect("ECode rewrite produced invalid IR");
    }
}

impl ControlFlowIl for ECodeIr {
    fn graph(&self) -> &IlGraph {
        &self.graph
    }
}

impl SsaIl for ECodeIr {
    fn value_count(&self) -> usize {
        self.values.len()
    }

    fn value_definition(&self, value: IlValueId) -> Option<IlSsaDef> {
        self.values.get(value.index()).map(ECodeValue::definition)
    }

    fn value_width(&self, value: IlValueId) -> Option<u32> {
        self.values.get(value.index()).map(ECodeValue::width)
    }

    fn block_arg_count(&self) -> usize {
        self.block_args.len()
    }

    fn block_arg_block(&self, arg: IlBlockArgId) -> Option<IlBlockId> {
        self.block_args.get(arg.index()).map(ECodeBlockArg::block)
    }

    fn block_arg_value(&self, arg: IlBlockArgId) -> Option<IlValueId> {
        self.block_args.get(arg.index()).map(ECodeBlockArg::value)
    }

    fn block_arg_width(&self, arg: IlBlockArgId) -> Option<u32> {
        self.block_args.get(arg.index()).map(ECodeBlockArg::width)
    }

    fn op_count(&self) -> usize {
        self.operations.len()
    }

    fn op_operands(&self, operation: IlOpId) -> Option<&[IlValueId]> {
        self.operations
            .get(operation.index())
            .map(|operation| self.op_operands_for(operation))
    }

    fn edge_args(&self) -> &[IlIndexRange] {
        &self.edge_args
    }

    fn edge_arg_values(&self) -> &[IlValueId] {
        &self.edge_arg_values
    }

    fn memory_domain_count(&self) -> usize {
        self.memory_domains.len()
    }

    fn memory_domain_space(&self, index: usize) -> Option<AddressSpaceId> {
        self.memory_domains.get(index).map(ECodeMemoryDomain::space)
    }
}

impl PersistableIl for ECodeIr {
    const SCHEMA: IlSchemaVersion = IlSchemaVersion::new(2);

    fn metadata_mut(&mut self) -> &mut IlMetadata {
        &mut self.metadata
    }
}

impl EstimateSize for ECodeIr {
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
                .saturating_mul(size_of::<ECodeValue>()),
            self.value_domains
                .capacity()
                .saturating_mul(size_of::<Option<ECodeDomain>>()),
            self.block_args
                .capacity()
                .saturating_mul(size_of::<ECodeBlockArg>()),
            self.edge_args
                .capacity()
                .saturating_mul(size_of::<IlIndexRange>()),
            self.edge_arg_values
                .capacity()
                .saturating_mul(size_of::<IlValueId>()),
            self.operations
                .capacity()
                .saturating_mul(size_of::<ECodeOp>()),
            self.value_operands
                .capacity()
                .saturating_mul(size_of::<IlValueId>()),
            self.memory_domains
                .capacity()
                .saturating_mul(size_of::<ECodeMemoryDomain>()),
            self.constant_storage.capacity(),
        ]
        .into_iter()
        .fold(
            size_of::<Self>().saturating_sub(size_of::<IlGraph>()),
            usize::saturating_add,
        )
    }
}
