use std::mem::{self, size_of};

use fugue_bv::BitVec;

use crate::il::common::{
    ControlFlowIl, IlArtefact, IlBlockArgId, IlBlockId, IlConstantInterner, IlError, IlGraph,
    IlIndexRange, IlMetadata, IlOpId, IlParentSpan, IlSchemaVersion, IlSourceSpan, IlSsaDef,
    IlValueId, PersistableIl, SsaIl,
};
use crate::il::mcode::verify::{VerifyError, verify};
use crate::il::mcode::{
    MCodeBinding, MCodeBlockArg, MCodeIrDisplay, MCodeMemoryDomain, MCodeOp, MCodeOpcode,
    MCodeSourceDisplay, MCodeValue, MCodeVar, MCodeVarId,
};
use crate::ir::{Address, AddressRange};
use crate::storage::segments::space::AddressSpaceId;
use crate::types::EstimateSize;

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct MCodeIr {
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    variables: Vec<MCodeVar>,
    aliased_variables: Vec<MCodeVarId>,
    values: Vec<MCodeValue>,
    block_args: Vec<MCodeBlockArg>,
    edge_args: Vec<IlIndexRange>,
    edge_arg_values: Vec<IlValueId>,
    operations: Vec<MCodeOp>,
    value_operands: Vec<IlValueId>,
    memory_domains: Vec<MCodeMemoryDomain>,
    constant_storage: Vec<u8>,
}

pub(crate) struct MCodeIrStorage {
    pub(crate) metadata: IlMetadata,
    pub(crate) graph: IlGraph,
    pub(crate) source_spans: Vec<IlSourceSpan>,
    pub(crate) parent_spans: Vec<IlParentSpan>,
    pub(crate) variables: Vec<MCodeVar>,
    pub(crate) aliased_variables: Vec<MCodeVarId>,
    pub(crate) values: Vec<MCodeValue>,
    pub(crate) block_args: Vec<MCodeBlockArg>,
    pub(crate) edge_args: Vec<IlIndexRange>,
    pub(crate) edge_arg_values: Vec<IlValueId>,
    pub(crate) operations: Vec<MCodeOp>,
    pub(crate) value_operands: Vec<IlValueId>,
    pub(crate) memory_domains: Vec<MCodeMemoryDomain>,
    pub(crate) constant_storage: Vec<u8>,
}

impl MCodeIr {
    pub(crate) fn new(storage: MCodeIrStorage) -> Self {
        let MCodeIrStorage {
            metadata,
            graph,
            source_spans,
            parent_spans,
            variables,
            aliased_variables,
            values,
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
            variables,
            aliased_variables,
            values,
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

    pub fn variables(&self) -> &[MCodeVar] {
        &self.variables
    }

    pub fn variable(&self, variable: MCodeVarId) -> Option<&MCodeVar> {
        self.variables.get(variable.index())
    }

    pub fn aliased_variables(&self) -> &[MCodeVarId] {
        &self.aliased_variables
    }

    pub fn is_aliased(&self, variable: MCodeVarId) -> bool {
        self.aliased_variables.binary_search(&variable).is_ok()
    }

    pub fn values(&self) -> &[MCodeValue] {
        &self.values
    }

    pub fn binding(&self, value: IlValueId) -> Option<MCodeBinding> {
        self.values.get(value.index()).and_then(MCodeValue::binding)
    }

    pub fn versions_of(&self, variable: MCodeVarId) -> impl Iterator<Item = IlValueId> + '_ {
        self.values
            .iter()
            .enumerate()
            .filter(move |(_, value)| value.variable() == Some(variable))
            .map(|(index, _)| IlValueId::try_from_index(index).expect("value id is representable"))
    }

    pub fn block_args(&self) -> &[MCodeBlockArg] {
        &self.block_args
    }

    pub fn edge_args(&self) -> &[IlIndexRange] {
        &self.edge_args
    }

    pub fn edge_arg_values(&self) -> &[IlValueId] {
        &self.edge_arg_values
    }

    pub fn ops(&self) -> &[MCodeOp] {
        &self.operations
    }

    pub fn op_operands(&self) -> &[IlValueId] {
        &self.value_operands
    }

    pub fn memory_domains(&self) -> &[MCodeMemoryDomain] {
        &self.memory_domains
    }

    pub(crate) fn constant_storage(&self) -> &[u8] {
        &self.constant_storage
    }

    pub fn memory_domain(&self, space: AddressSpaceId) -> Option<&MCodeMemoryDomain> {
        self.memory_domains
            .iter()
            .find(|domain| domain.space() == space)
    }

    pub fn op_operands_for(&self, operation: &MCodeOp) -> &[IlValueId] {
        operation.operands().slice(&self.value_operands)
    }

    pub fn block_for_op(&self, operation: IlOpId) -> Option<IlBlockId> {
        self.graph.block_for_op(operation)
    }

    pub fn value_width(&self, value: IlValueId) -> Option<u32> {
        self.values.get(value.index()).map(MCodeValue::width)
    }

    pub fn args_for_edge(&self, edge: usize) -> &[IlValueId] {
        self.edge_args
            .get(edge)
            .expect("edge index is within the edge argument table")
            .slice(&self.edge_arg_values)
    }

    pub fn ops_for_source(
        &self,
        address: Address,
    ) -> impl Iterator<Item = (IlOpId, &MCodeOp)> + '_ {
        IlSourceSpan::ops(&self.source_spans, &self.operations, address)
    }

    pub fn defining_op(&self, value: IlValueId) -> Option<&MCodeOp> {
        let record = self.values.get(value.index())?;
        let IlSsaDef::Op(operation) = record.definition() else {
            return None;
        };
        self.operations.get(operation.index())
    }

    pub fn underlying_value(&self, value: IlValueId) -> IlValueId {
        let mut current = value;
        for _ in 0..self.values.len() {
            let Some(operation) = self.defining_op(current) else {
                return current;
            };
            match operation.opcode() {
                MCodeOpcode::Copy
                | MCodeOpcode::SetVar
                | MCodeOpcode::SignExtend
                | MCodeOpcode::Truncate
                | MCodeOpcode::ZeroExtend => {
                    let Some(inner) = self.op_operands_for(operation).first().copied() else {
                        return current;
                    };
                    current = inner;
                }
                _ => return current,
            }
        }
        current
    }

    pub fn shrink_to_fit(&mut self) {
        self.graph.shrink_to_fit();
        self.source_spans.shrink_to_fit();
        self.parent_spans.shrink_to_fit();
        self.variables.shrink_to_fit();
        self.aliased_variables.shrink_to_fit();
        self.values.shrink_to_fit();
        self.block_args.shrink_to_fit();
        self.edge_args.shrink_to_fit();
        self.edge_arg_values.shrink_to_fit();
        self.operations.shrink_to_fit();
        self.value_operands.shrink_to_fit();
        self.memory_domains.shrink_to_fit();
        self.constant_storage.shrink_to_fit();
    }

    pub(crate) fn take_graph(&mut self) -> IlGraph {
        mem::take(&mut self.graph)
    }

    pub(crate) fn take_memory_domains(&mut self) -> Vec<MCodeMemoryDomain> {
        mem::take(&mut self.memory_domains)
    }

    pub(crate) fn rewriter(&mut self) -> MCodeRewriter<'_> {
        let mut constants = IlConstantInterner::new();
        for operation in &self.operations {
            if let Some(bytes) = operation.constant_bytes(&self.constant_storage) {
                constants.index_existing(operation.immediate(), bytes);
            }
        }
        MCodeRewriter {
            operations: &mut self.operations,
            value_operands: &mut self.value_operands,
            constant_storage: &mut self.constant_storage,
            constants,
        }
    }

    pub(crate) fn verify(&self) -> Result<(), VerifyError> {
        verify(self)
    }

    pub fn memory_operand(&self, operation: &MCodeOp) -> Option<IlValueId> {
        if !operation.opcode().requires_memory_domain() {
            return None;
        }

        self.op_operands_for(operation).last().copied()
    }

    pub fn constant_value(&self, value: IlValueId) -> Option<BitVec> {
        let mut current = value;
        for _ in 0..self.values.len() {
            let operation = self.defining_op(current)?;
            if operation.opcode() != MCodeOpcode::SetVar {
                return operation.constant(self.constant_storage());
            }
            current = *self.op_operands_for(operation).first()?;
        }
        None
    }

    pub fn memory_access_range(&self, operation: &MCodeOp) -> Option<AddressRange> {
        let space = operation.address_space()?;
        let pointer = self.defining_op(self.pointer_operand(operation)?)?;
        if pointer.opcode() != MCodeOpcode::Address {
            return None;
        }
        let width = match operation.opcode() {
            MCodeOpcode::Load => operation.width(),
            MCodeOpcode::Store => self
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

    pub fn pointer_operand(&self, operation: &MCodeOp) -> Option<IlValueId> {
        if !matches!(operation.opcode(), MCodeOpcode::Load | MCodeOpcode::Store) {
            return None;
        }

        self.op_operands_for(operation).first().copied()
    }

    pub const fn display(&self) -> MCodeIrDisplay<'_> {
        MCodeIrDisplay::new(self)
    }

    pub const fn display_source(&self, address: Address) -> MCodeSourceDisplay<'_> {
        MCodeSourceDisplay::new(self, address)
    }
}

pub(crate) struct MCodeRewriter<'a> {
    operations: &'a mut Vec<MCodeOp>,
    value_operands: &'a mut Vec<IlValueId>,
    constant_storage: &'a mut Vec<u8>,
    constants: IlConstantInterner,
}

impl MCodeRewriter<'_> {
    pub(crate) fn ops(&self) -> &[MCodeOp] {
        self.operations
    }

    pub(crate) fn replace_scalar(
        &mut self,
        operation: IlOpId,
        opcode: MCodeOpcode,
        operands: &[IlValueId],
    ) -> Result<(), IlError> {
        let operands_range = if operands.is_empty() {
            IlIndexRange::EMPTY
        } else {
            let start = self.value_operands.len();
            let end = start
                .checked_add(operands.len())
                .ok_or_else(|| IlError::integer_overflow("MCode operand count"))?;
            let range = IlIndexRange::new(start, end)?;
            self.value_operands.extend_from_slice(operands);
            range
        };
        self.operations[operation.index()].replace(opcode, operands_range);
        Ok(())
    }

    pub(crate) fn replace_with_constant(&mut self, operation: IlOpId, value: &BitVec) {
        let immediate = self.constants.intern(self.constant_storage, value);
        self.replace_scalar(operation, MCodeOpcode::Constant, &[])
            .expect("an empty operand range is representable");
        self.operations[operation.index()].set_immediate(immediate);
    }
}

impl IlArtefact for MCodeIr {
    const FORM_IDENTIFIER: &str = "fugue.mcode.cfg";

    fn metadata(&self) -> &IlMetadata {
        &self.metadata
    }

    #[cfg(debug_assertions)]
    fn verify_after_rewrite(&self) {
        self.verify().expect("MCode rewrite produced invalid IR");
    }
}

impl ControlFlowIl for MCodeIr {
    fn graph(&self) -> &IlGraph {
        &self.graph
    }
}

impl SsaIl for MCodeIr {
    fn value_count(&self) -> usize {
        self.values.len()
    }

    fn value_definition(&self, value: IlValueId) -> Option<IlSsaDef> {
        self.values.get(value.index()).map(MCodeValue::definition)
    }

    fn value_width(&self, value: IlValueId) -> Option<u32> {
        self.values.get(value.index()).map(MCodeValue::width)
    }

    fn block_arg_count(&self) -> usize {
        self.block_args.len()
    }

    fn block_arg_block(&self, arg: IlBlockArgId) -> Option<IlBlockId> {
        self.block_args.get(arg.index()).map(MCodeBlockArg::block)
    }

    fn block_arg_value(&self, arg: IlBlockArgId) -> Option<IlValueId> {
        self.block_args.get(arg.index()).map(MCodeBlockArg::value)
    }

    fn block_arg_width(&self, arg: IlBlockArgId) -> Option<u32> {
        self.block_args.get(arg.index()).map(MCodeBlockArg::width)
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
        self.memory_domains.get(index).map(MCodeMemoryDomain::space)
    }
}

impl PersistableIl for MCodeIr {
    const SCHEMA: IlSchemaVersion = IlSchemaVersion::new(2);

    fn metadata_mut(&mut self) -> &mut IlMetadata {
        &mut self.metadata
    }
}

impl EstimateSize for MCodeIr {
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
                .saturating_mul(size_of::<MCodeValue>()),
            self.block_args
                .capacity()
                .saturating_mul(size_of::<MCodeBlockArg>()),
            self.edge_args
                .capacity()
                .saturating_mul(size_of::<IlIndexRange>()),
            self.edge_arg_values
                .capacity()
                .saturating_mul(size_of::<IlValueId>()),
            self.operations
                .capacity()
                .saturating_mul(size_of::<MCodeOp>()),
            self.value_operands
                .capacity()
                .saturating_mul(size_of::<IlValueId>()),
            self.memory_domains
                .capacity()
                .saturating_mul(size_of::<MCodeMemoryDomain>()),
            self.constant_storage.capacity(),
        ]
        .into_iter()
        .fold(
            size_of::<Self>().saturating_sub(size_of::<IlGraph>()),
            usize::saturating_add,
        )
    }
}
