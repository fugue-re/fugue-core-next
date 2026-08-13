use std::mem::size_of;

use crate::analysis::control::CancellationToken;
use crate::il::common::{
    ControlFlowIl, FlagId, IlArtefact, IlError, IlExprId, IlGraph, IlIndexRange, IlMetadata,
    IlOpId, IlParentSpan, IlPool, IlSchemaVersion, IlSourceSpan, PersistableIl, RegisterId,
};
use crate::il::ecode::{ECodeExpr, ECodeExprOpcode, ECodeSink, ECodeStmt, ECodeStmtOpcode};
use crate::ir::Address;
use crate::storage::segments::space::AddressSpaceId;
use crate::types::EstimateSize;

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ECodeIr {
    call_preserved_registers: Vec<RegisterId>,
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    expressions: Vec<ECodeExpr>,
    expression_operands: Vec<IlExprId>,
    statements: Vec<ECodeStmt>,
    statement_operands: Vec<IlExprId>,
}

struct ECodeIrParts {
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    expressions: Vec<ECodeExpr>,
    expression_operands: Vec<IlExprId>,
    statements: Vec<ECodeStmt>,
    statement_operands: Vec<IlExprId>,
    call_preserved_registers: Vec<RegisterId>,
}

impl ECodeIr {
    fn new(parts: ECodeIrParts) -> Self {
        let ECodeIrParts {
            metadata,
            graph,
            source_spans,
            parent_spans,
            expressions,
            expression_operands,
            statements,
            statement_operands,
            mut call_preserved_registers,
        } = parts;
        call_preserved_registers.sort_unstable();
        call_preserved_registers.dedup();
        Self {
            call_preserved_registers,
            metadata,
            graph,
            source_spans,
            parent_spans,
            expressions,
            expression_operands,
            statements,
            statement_operands,
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

    pub fn expressions(&self) -> &[ECodeExpr] {
        &self.expressions
    }

    pub fn expression_operands(&self) -> &[IlExprId] {
        &self.expression_operands
    }

    pub fn statements(&self) -> &[ECodeStmt] {
        &self.statements
    }

    pub fn statement_operands(&self) -> &[IlExprId] {
        &self.statement_operands
    }

    pub(crate) fn call_preserved_registers(&self) -> &[RegisterId] {
        &self.call_preserved_registers
    }

    pub fn expression_operands_for(&self, expression: &ECodeExpr) -> &[IlExprId] {
        expression.operands().slice(&self.expression_operands)
    }

    pub fn statement_operands_for(&self, statement: &ECodeStmt) -> &[IlExprId] {
        statement.operands().slice(&self.statement_operands)
    }

    pub fn statements_for_source(
        &self,
        address: Address,
    ) -> impl Iterator<Item = (IlOpId, &ECodeStmt)> + '_ {
        self.source_spans
            .iter()
            .filter(move |span| span.address() == address)
            .flat_map(move |span| {
                let start = span.destination().start();
                span.destination()
                    .slice(&self.statements)
                    .iter()
                    .enumerate()
                    .map(move |(index, statement)| {
                        (
                            IlOpId::try_from_index(start + index)
                                .expect("statement count fits the operation id space"),
                            statement,
                        )
                    })
            })
    }

    pub fn shrink_to_fit(&mut self) {
        self.call_preserved_registers.shrink_to_fit();
        self.graph.shrink_to_fit();
        self.source_spans.shrink_to_fit();
        self.parent_spans.shrink_to_fit();
        self.expressions.shrink_to_fit();
        self.expression_operands.shrink_to_fit();
        self.statements.shrink_to_fit();
        self.statement_operands.shrink_to_fit();
    }
}

impl IlArtefact for ECodeIr {
    const FORM_IDENTIFIER: &str = "fugue.ecode.cfg";

    fn metadata(&self) -> &IlMetadata {
        &self.metadata
    }
}

impl ControlFlowIl for ECodeIr {
    fn graph(&self) -> &IlGraph {
        &self.graph
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
            self.call_preserved_registers
                .capacity()
                .saturating_mul(size_of::<RegisterId>()),
            self.source_spans
                .capacity()
                .saturating_mul(size_of::<IlSourceSpan>()),
            self.parent_spans
                .capacity()
                .saturating_mul(size_of::<IlParentSpan>()),
            self.expressions
                .capacity()
                .saturating_mul(size_of::<ECodeExpr>()),
            self.expression_operands
                .capacity()
                .saturating_mul(size_of::<IlExprId>()),
            self.statements
                .capacity()
                .saturating_mul(size_of::<ECodeStmt>()),
            self.statement_operands
                .capacity()
                .saturating_mul(size_of::<IlExprId>()),
        ]
        .into_iter()
        .fold(
            size_of::<Self>().saturating_sub(size_of::<IlGraph>()),
            usize::saturating_add,
        )
    }
}

#[derive(Debug)]
pub(crate) struct ECodeBuilder {
    call_preserved_registers: Vec<RegisterId>,
    metadata: IlMetadata,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    expressions: Vec<ECodeExpr>,
    expression_operands: IlPool<IlExprId>,
    statements: Vec<ECodeStmt>,
    statement_operands: IlPool<IlExprId>,
}

impl ECodeBuilder {
    pub(crate) fn new(metadata: IlMetadata, graph: IlGraph) -> Self {
        Self {
            call_preserved_registers: Vec::new(),
            metadata,
            graph,
            source_spans: Vec::new(),
            parent_spans: Vec::new(),
            expressions: Vec::new(),
            expression_operands: IlPool::new(),
            statements: Vec::new(),
            statement_operands: IlPool::new(),
        }
    }

    pub(crate) fn push_expression(&mut self, expression: ECodeExpr) -> Result<IlExprId, IlError> {
        let id = IlExprId::try_from_index(self.expressions.len())?;
        self.expressions.push(expression);
        Ok(id)
    }

    pub(crate) fn push_expression_operands(
        &mut self,
        operands: impl IntoIterator<Item = IlExprId>,
    ) -> Result<IlIndexRange, IlError> {
        self.expression_operands.append(operands)
    }

    pub(crate) fn push_statement(&mut self, statement: ECodeStmt) -> Result<IlOpId, IlError> {
        let id = IlOpId::try_from_index(self.statements.len())?;
        self.statements.push(statement);
        Ok(id)
    }

    pub(crate) fn set_graph(&mut self, graph: IlGraph) {
        self.graph = graph;
    }

    pub(crate) fn set_call_preserved_registers(&mut self, registers: Vec<RegisterId>) {
        self.call_preserved_registers = registers;
    }

    pub(crate) fn set_parent_spans(&mut self, parent_spans: Vec<IlParentSpan>) {
        self.parent_spans = parent_spans;
    }

    pub(crate) fn push_statement_operands(
        &mut self,
        operands: impl IntoIterator<Item = IlExprId>,
    ) -> Result<IlIndexRange, IlError> {
        self.statement_operands.append(operands)
    }

    pub(crate) fn set_source_spans(&mut self, source_spans: Vec<IlSourceSpan>) {
        self.source_spans = source_spans;
    }

    pub(crate) fn build(self, cancellation: &CancellationToken) -> Result<ECodeIr, IlError> {
        cancellation.check()?;

        let mut ir = ECodeIr::new(ECodeIrParts {
            metadata: self.metadata,
            graph: self.graph,
            source_spans: self.source_spans,
            parent_spans: self.parent_spans,
            expressions: self.expressions,
            expression_operands: self.expression_operands.into_values(),
            statements: self.statements,
            statement_operands: self.statement_operands.into_values(),
            call_preserved_registers: self.call_preserved_registers,
        });

        ir.shrink_to_fit();

        Ok(ir)
    }

    fn push_nullary(
        &mut self,
        opcode: ECodeExprOpcode,
        width: u32,
        immediate: u64,
    ) -> Result<IlExprId, IlError> {
        self.push_expression(ECodeExpr::new(
            opcode,
            width,
            IlIndexRange::EMPTY,
            immediate,
            None,
        ))
    }
}

impl ECodeSink for ECodeBuilder {
    type Value = IlExprId;

    fn constant(&mut self, width: u32, value: u64) -> Result<Self::Value, IlError> {
        self.push_nullary(ECodeExprOpcode::Constant, width, value)
    }

    fn address(&mut self, width: u32, offset: u64) -> Result<Self::Value, IlError> {
        self.push_nullary(ECodeExprOpcode::Address, width, offset)
    }

    fn undefined(&mut self, width: u32, discriminant: u64) -> Result<Self::Value, IlError> {
        self.push_nullary(ECodeExprOpcode::Undefined, width, discriminant)
    }

    fn read_register(&mut self, register: RegisterId, width: u32) -> Result<Self::Value, IlError> {
        self.push_nullary(ECodeExprOpcode::ReadRegister, width, register.value())
    }

    fn read_flag(&mut self, flag: FlagId, width: u32) -> Result<Self::Value, IlError> {
        self.push_nullary(ECodeExprOpcode::ReadFlag, width, flag.value())
    }

    fn apply(
        &mut self,
        opcode: ECodeExprOpcode,
        width: u32,
        operands: &[Self::Value],
        immediate: u64,
        address_space: Option<AddressSpaceId>,
    ) -> Result<Self::Value, IlError> {
        let operands = self.push_expression_operands(operands.iter().copied())?;
        self.push_expression(ECodeExpr::new(
            opcode,
            width,
            operands,
            immediate,
            address_space,
        ))
    }

    fn write_register(&mut self, register: RegisterId, value: Self::Value) -> Result<(), IlError> {
        self.push_statement(
            ECodeStmt::new(
                ECodeStmtOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(value),
                None,
                None,
            )
            .with_immediate(register.value()),
        )?;

        Ok(())
    }

    fn write_flag(&mut self, flag: FlagId, value: Self::Value) -> Result<(), IlError> {
        self.push_statement(
            ECodeStmt::new(
                ECodeStmtOpcode::WriteFlag,
                IlIndexRange::EMPTY,
                Some(value),
                None,
                None,
            )
            .with_immediate(flag.value()),
        )?;

        Ok(())
    }

    fn store(
        &mut self,
        operands: &[Self::Value],
        address_space: Option<AddressSpaceId>,
    ) -> Result<(), IlError> {
        let operands = self.push_statement_operands(operands.iter().copied())?;
        self.push_statement(ECodeStmt::new(
            ECodeStmtOpcode::Store,
            operands,
            None,
            None,
            address_space,
        ))?;

        Ok(())
    }

    fn direct_flow(
        &mut self,
        opcode: ECodeStmtOpcode,
        target: Address,
        operands: &[Self::Value],
    ) -> Result<(), IlError> {
        let operands = self.push_statement_operands(operands.iter().copied())?;
        self.push_statement(ECodeStmt::new(opcode, operands, None, Some(target), None))?;

        Ok(())
    }

    fn indirect_flow(
        &mut self,
        opcode: ECodeStmtOpcode,
        operands: &[Self::Value],
        address_space: Option<AddressSpaceId>,
    ) -> Result<(), IlError> {
        let operands = self.push_statement_operands(operands.iter().copied())?;
        self.push_statement(ECodeStmt::new(opcode, operands, None, None, address_space))?;

        Ok(())
    }

    fn intrinsic(
        &mut self,
        intrinsic: u64,
        operands: &[Self::Value],
        address_space: Option<AddressSpaceId>,
    ) -> Result<(), IlError> {
        let operands = self.push_statement_operands(operands.iter().copied())?;
        self.push_statement(
            ECodeStmt::new(
                ECodeStmtOpcode::Intrinsic,
                operands,
                None,
                None,
                address_space,
            )
            .with_immediate(intrinsic),
        )?;

        Ok(())
    }

    fn trap(
        &mut self,
        intrinsic: u64,
        address_space: Option<AddressSpaceId>,
    ) -> Result<(), IlError> {
        self.push_statement(
            ECodeStmt::new(
                ECodeStmtOpcode::Trap,
                IlIndexRange::EMPTY,
                None,
                None,
                address_space,
            )
            .with_immediate(intrinsic),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::IlSourceSpan;
    use crate::il::ecode::verify::VerifyError;
    use crate::il::ecode::{ECodeExprOpcode, ECodeStmtOpcode};
    use crate::ir::{Address, FunctionId};
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn ecode_builder_finishes_verified_body() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
        let expression = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                64,
                IlIndexRange::EMPTY,
                1,
                None,
            ))
            .unwrap();
        let operands = builder.push_statement_operands([expression]).unwrap();

        builder
            .push_statement(ECodeStmt::new(
                ECodeStmtOpcode::Return,
                operands,
                Some(expression),
                None,
                None,
            ))
            .unwrap();

        let ir = builder.build(&CancellationToken::default()).unwrap();
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&ir).unwrap();
        let decoded = rkyv::from_bytes::<ECodeIr, rkyv::rancor::Error>(&bytes).unwrap();

        assert!(ir.verify().is_ok());
        assert_eq!(ir.expressions().len(), 1);
        assert_eq!(ir.statements().len(), 1);
        assert_eq!(decoded, ir);
    }

    #[test]
    fn ecode_body_returns_statements_for_source() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let address = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let other = Address::new(AddressSpaceId::new(1), 0x2000u64);
        let ir = ECodeIr::new(ECodeIrParts {
            metadata,
            graph: IlGraph::default(),
            source_spans: vec![
                IlSourceSpan::new(IlIndexRange::new(0, 1).unwrap(), address, 0, 1),
                IlSourceSpan::new(IlIndexRange::new(1, 2).unwrap(), other, 0, 1),
            ],
            parent_spans: Vec::new(),
            expressions: Vec::new(),
            expression_operands: Vec::new(),
            statements: vec![
                ECodeStmt::new(ECodeStmtOpcode::Trap, IlIndexRange::EMPTY, None, None, None),
                ECodeStmt::new(ECodeStmtOpcode::Trap, IlIndexRange::EMPTY, None, None, None),
            ],
            statement_operands: Vec::new(),
            call_preserved_registers: Vec::new(),
        });

        let statements = ir.statements_for_source(address).collect::<Vec<_>>();

        assert_eq!(statements.len(), 1);
        assert_eq!(statements[0].0, IlOpId::try_from_index(0).unwrap());
        assert_eq!(statements[0].1.opcode(), ECodeStmtOpcode::Trap);
    }

    #[test]
    fn ecode_verifier_rejects_store_without_space() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
        let offset = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                64,
                IlIndexRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let value = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                8,
                IlIndexRange::EMPTY,
                0xff,
                None,
            ))
            .unwrap();
        let operands = builder.push_statement_operands([offset, value]).unwrap();

        builder
            .push_statement(ECodeStmt::new(
                ECodeStmtOpcode::Store,
                operands,
                None,
                None,
                None,
            ))
            .unwrap();

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::Il(IlError::MissingComponent { .. }))
        ));
    }

    #[test]
    fn ecode_verifier_rejects_load_without_space() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
        let offset = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                64,
                IlIndexRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let operands = builder.push_expression_operands([offset]).unwrap();

        builder
            .push_expression(ECodeExpr::new(ECodeExprOpcode::Load, 8, operands, 0, None))
            .unwrap();

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::Il(IlError::MissingComponent { .. }))
        ));
    }

    #[test]
    fn ecode_verifier_rejects_non_preceding_expression_operand() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let ir = ECodeIr::new(ECodeIrParts {
            metadata,
            graph: IlGraph::default(),
            source_spans: Vec::new(),
            parent_spans: Vec::new(),
            expressions: vec![
                ECodeExpr::new(
                    ECodeExprOpcode::Copy,
                    64,
                    IlIndexRange::new(0, 1).unwrap(),
                    0,
                    None,
                ),
                ECodeExpr::new(ECodeExprOpcode::Constant, 64, IlIndexRange::EMPTY, 1, None),
            ],
            expression_operands: vec![IlExprId::try_from_index(1).unwrap()],
            statements: Vec::new(),
            statement_operands: Vec::new(),
            call_preserved_registers: Vec::new(),
        });

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::InvalidOperandOrdering { expression: 0 })
        ));
    }
}
