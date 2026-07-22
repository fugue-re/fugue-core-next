use crate::analysis::control::CancellationToken;
use crate::il::common::verify::{
    VerifyError, verify_bounds, verify_graph, verify_graph_bounds, verify_parent_spans,
    verify_source_spans,
};
use crate::il::common::{
    IlArtefact, IlError, IlExprId, IlGraph, IlHeader, IlIndexRange, IlLevel, IlOpId, IlParentSpan,
    IlPool, IlSchemaVersion, IlSourceSpan,
};
use crate::il::ecode::format::ECodeIrDisplay;
use crate::il::ecode::{ECodeExpr, ECodeStmt};
use crate::ir::{Address, FunctionId};
use crate::storage::entities::schema::ENTITY_IL_ECODE_ID;
use crate::storage::entities::{Entity, EntityId, MutableEntity};

pub const ECODE_SCHEMA_VERSION: IlSchemaVersion = IlSchemaVersion::new(1);

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ECodeIr {
    header: IlHeader,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    expressions: Vec<ECodeExpr>,
    expression_operands: Vec<IlExprId>,
    statements: Vec<ECodeStmt>,
    statement_operands: Vec<IlExprId>,
}

impl ECodeIr {
    #[allow(clippy::too_many_arguments)]
    fn new(
        header: IlHeader,
        graph: IlGraph,
        source_spans: Vec<IlSourceSpan>,
        parent_spans: Vec<IlParentSpan>,
        expressions: Vec<ECodeExpr>,
        expression_operands: Vec<IlExprId>,
        statements: Vec<ECodeStmt>,
        statement_operands: Vec<IlExprId>,
    ) -> Self {
        Self {
            header,
            graph,
            source_spans,
            parent_spans,
            expressions,
            expression_operands,
            statements,
            statement_operands,
        }
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

    pub fn expression_operands_for(&self, expression: &ECodeExpr) -> &[IlExprId] {
        expression.operands().slice(&self.expression_operands)
    }

    pub fn statement_operands_for(&self, statement: &ECodeStmt) -> &[IlExprId] {
        statement.operands().slice(&self.statement_operands)
    }

    pub const fn display(&self) -> ECodeIrDisplay<'_> {
        ECodeIrDisplay::new(self)
    }

    pub fn statements_for_source(
        &self,
        address: Address,
    ) -> impl Iterator<Item = (usize, &ECodeStmt)> + '_ {
        self.source_spans
            .iter()
            .filter(move |run| run.address() == address)
            .flat_map(move |run| {
                let start = run.destination().start();
                run.destination()
                    .slice(&self.statements)
                    .iter()
                    .enumerate()
                    .map(move |(index, statement)| (start + index, statement))
            })
    }

    pub fn shrink_to_fit(&mut self) {
        self.graph.shrink_to_fit();
        self.source_spans.shrink_to_fit();
        self.parent_spans.shrink_to_fit();
        self.expressions.shrink_to_fit();
        self.expression_operands.shrink_to_fit();
        self.statements.shrink_to_fit();
        self.statement_operands.shrink_to_fit();
    }
}

impl Entity for ECodeIr {
    const ID: EntityId = ENTITY_IL_ECODE_ID;
}

impl MutableEntity for ECodeIr {
    type Key = FunctionId;

    fn entity_key(&self) -> FunctionId {
        self.header.function()
    }
}

impl IlArtefact for ECodeIr {
    const LEVEL: IlLevel = IlLevel::ECode;
    const SCHEMA: IlSchemaVersion = ECODE_SCHEMA_VERSION;

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
pub(crate) struct ECodeBuilder {
    header: IlHeader,
    graph: IlGraph,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
    expressions: Vec<ECodeExpr>,
    expression_operands: IlPool<IlExprId>,
    statements: Vec<ECodeStmt>,
    statement_operands: IlPool<IlExprId>,
}

impl ECodeBuilder {
    pub(crate) fn new(header: IlHeader, graph: IlGraph) -> Self {
        Self {
            header,
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

    pub(crate) fn statement_count(&self) -> usize {
        self.statements.len()
    }

    pub(crate) fn replace_graph(&mut self, graph: IlGraph) {
        self.graph = graph;
    }

    pub(crate) fn push_statement_operands(
        &mut self,
        operands: impl IntoIterator<Item = IlExprId>,
    ) -> Result<IlIndexRange, IlError> {
        self.statement_operands.append(operands)
    }

    pub(crate) fn replace_source_spans(&mut self, source_spans: Vec<IlSourceSpan>) {
        self.source_spans = source_spans;
    }

    pub(crate) fn build(self, cancellation: &CancellationToken) -> Result<ECodeIr, IlError> {
        cancellation.check()?;

        let mut body = ECodeIr::new(
            self.header,
            self.graph,
            self.source_spans,
            self.parent_spans,
            self.expressions,
            self.expression_operands.into_values(),
            self.statements,
            self.statement_operands.into_values(),
        );

        body.shrink_to_fit();

        Ok(body)
    }
}

pub(crate) fn verify(ir: &ECodeIr) -> Result<(), VerifyError> {
    if ir.header().schema() != ECodeIr::SCHEMA {
        return Err(IlError::schema_mismatch(
            ECodeIr::LEVEL,
            ECodeIr::SCHEMA.value(),
            ir.header().schema().value(),
        )
        .into());
    }

    verify_graph(ir.graph())?;
    verify_graph_bounds(ir.graph(), ir.statements().len())?;
    verify_source_spans(ir.source_spans(), ir.statements().len())?;
    verify_parent_spans(ir.parent_spans(), ir.statements().len())?;

    for expression in ir.expressions() {
        verify_expr(ir, expression)?;
    }

    for statement in ir.statements() {
        verify_stmt(ir, statement)?;
    }

    Ok(())
}

fn verify_expr(ir: &ECodeIr, expression: &ECodeExpr) -> Result<(), VerifyError> {
    verify_bounds(expression.operands(), ir.expression_operands().len())?;

    if let Some(count) = expression.opcode().fixed_operand_count()
        && expression.operands().len() != count
    {
        return Err(VerifyError::InvalidOperandCount {
            level: IlLevel::ECode,
            expected: count,
            found: expression.operands().len(),
        });
    }

    if expression.opcode().requires_address_space() && expression.address_space().is_none() {
        return Err(IlError::missing_component(IlLevel::ECode, "address space").into());
    }

    for operand in ir.expression_operands_for(expression) {
        ir.expressions()
            .get(operand.index())
            .ok_or(IlError::range_out_of_bounds(
                operand.value(),
                ir.expressions().len(),
            ))?;
    }

    Ok(())
}

fn verify_stmt(ir: &ECodeIr, statement: &ECodeStmt) -> Result<(), VerifyError> {
    verify_bounds(statement.operands(), ir.statement_operands().len())?;

    if let Some(count) = statement.opcode().fixed_operand_count()
        && statement.operands().len() != count
    {
        return Err(VerifyError::InvalidOperandCount {
            level: IlLevel::ECode,
            expected: count,
            found: statement.operands().len(),
        });
    }

    if statement.opcode().requires_address() && statement.address().is_none() {
        return Err(IlError::missing_component(IlLevel::ECode, "address").into());
    }

    if statement.opcode().requires_address_space() && statement.address_space().is_none() {
        return Err(IlError::missing_component(IlLevel::ECode, "address space").into());
    }

    if statement.opcode().requires_immediate() && statement.immediate() == 0 {
        return Err(IlError::missing_component(IlLevel::ECode, "immediate").into());
    }

    if let Some(value) = statement.value() {
        ir.expressions()
            .get(value.index())
            .ok_or(IlError::range_out_of_bounds(
                value.value(),
                ir.expressions().len(),
            ))?;
    }

    for operand in ir.statement_operands_for(statement) {
        ir.expressions()
            .get(operand.index())
            .ok_or(IlError::range_out_of_bounds(
                operand.value(),
                ir.expressions().len(),
            ))?;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::IlSourceSpan;
    use crate::il::common::verify::VerifyError;
    use crate::il::ecode::{ECodeExprOpcode, ECodeStmtOpcode};
    use crate::ir::{Address, FunctionId};
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn ecode_builder_finishes_verified_body() {
        assert!(std::mem::size_of::<ECodeExpr>() <= 40);
        assert!(std::mem::size_of::<ECodeStmt>() <= 64);

        let header = IlHeader::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 0);
        let mut builder = ECodeBuilder::new(header, IlGraph::default());
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

        let body = builder.build(&CancellationToken::default()).unwrap();
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&body).unwrap();
        let decoded = rkyv::from_bytes::<ECodeIr, rkyv::rancor::Error>(&bytes).unwrap();

        assert!(verify(&body).is_ok());
        assert_eq!(body.expressions().len(), 1);
        assert_eq!(body.statements().len(), 1);
        assert_eq!(decoded, body);
    }

    #[test]
    fn ecode_body_returns_statements_for_source() {
        let header = IlHeader::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 0);
        let address = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let other = Address::new(AddressSpaceId::new(1), 0x2000u64);
        let body = ECodeIr::new(
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
                ECodeStmt::new(ECodeStmtOpcode::Trap, IlIndexRange::EMPTY, None, None, None),
                ECodeStmt::new(ECodeStmtOpcode::Trap, IlIndexRange::EMPTY, None, None, None),
            ],
            Vec::new(),
        );

        let statements = body.statements_for_source(address).collect::<Vec<_>>();

        assert_eq!(statements.len(), 1);
        assert_eq!(statements[0].0, 0);
        assert_eq!(statements[0].1.opcode(), ECodeStmtOpcode::Trap);
    }

    #[test]
    fn ecode_verifier_rejects_store_without_space() {
        let header = IlHeader::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 0);
        let mut builder = ECodeBuilder::new(header, IlGraph::default());
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

        let body = builder.build(&CancellationToken::default()).unwrap();

        assert!(matches!(
            verify(&body),
            Err(VerifyError::Il(IlError::MissingComponent { .. }))
        ));
    }

    #[test]
    fn ecode_verifier_rejects_load_without_space() {
        let header = IlHeader::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 0);
        let mut builder = ECodeBuilder::new(header, IlGraph::default());
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

        let body = builder.build(&CancellationToken::default()).unwrap();

        assert!(matches!(
            verify(&body),
            Err(VerifyError::Il(IlError::MissingComponent { .. }))
        ));
    }
}
