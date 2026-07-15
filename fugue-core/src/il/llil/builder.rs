use crate::il::common::{
    ArtefactHeader, BuildCancellation, CommonBody, ExpressionId, Finish, IlError, IrArtefact,
    IrLevel, OperationId, PackedRange, Pool, RawIrArtefact, SchemaVersion, Verify,
};
use crate::il::llil::format::LlilBodyDisplay;
use crate::il::llil::{Expression, Statement};
use crate::ir::Address;

pub const LLIL_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1);

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct LlilBody {
    header: ArtefactHeader,
    common: CommonBody,
    expressions: Vec<Expression>,
    expression_operands: Vec<ExpressionId>,
    statements: Vec<Statement>,
    statement_operands: Vec<ExpressionId>,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct LlilPayload {
    expressions: Vec<Expression>,
    expression_operands: Vec<ExpressionId>,
    statements: Vec<Statement>,
    statement_operands: Vec<ExpressionId>,
}

impl LlilPayload {
    fn new(
        expressions: Vec<Expression>,
        expression_operands: Vec<ExpressionId>,
        statements: Vec<Statement>,
        statement_operands: Vec<ExpressionId>,
    ) -> Self {
        Self {
            expressions,
            expression_operands,
            statements,
            statement_operands,
        }
    }
}

impl LlilBody {
    pub fn new(
        header: ArtefactHeader,
        common: CommonBody,
        expressions: Vec<Expression>,
        expression_operands: Vec<ExpressionId>,
        statements: Vec<Statement>,
        statement_operands: Vec<ExpressionId>,
    ) -> Self {
        Self {
            header,
            common,
            expressions,
            expression_operands,
            statements,
            statement_operands,
        }
    }

    pub const fn header(&self) -> &ArtefactHeader {
        &self.header
    }

    pub const fn common(&self) -> &CommonBody {
        &self.common
    }

    pub fn expressions(&self) -> &[Expression] {
        &self.expressions
    }

    pub fn expression_operands(&self) -> &[ExpressionId] {
        &self.expression_operands
    }

    pub fn statements(&self) -> &[Statement] {
        &self.statements
    }

    pub fn statement_operands(&self) -> &[ExpressionId] {
        &self.statement_operands
    }

    pub fn expression_operands_for(
        &self,
        expression: &Expression,
    ) -> Result<&[ExpressionId], IlError> {
        expression
            .operands()
            .checked_slice(&self.expression_operands)
    }

    pub fn statement_operands_for(
        &self,
        statement: &Statement,
    ) -> Result<&[ExpressionId], IlError> {
        statement.operands().checked_slice(&self.statement_operands)
    }

    pub const fn display(&self) -> LlilBodyDisplay<'_> {
        LlilBodyDisplay::new(self)
    }

    pub fn statements_for_source(
        &self,
        machine_address: Address,
    ) -> impl Iterator<Item = (usize, &Statement)> + '_ {
        self.common
            .source_runs()
            .iter()
            .filter(move |run| run.machine_address() == machine_address)
            .flat_map(move |run| {
                let start = run.destination().start();
                run.destination()
                    .checked_slice(&self.statements)
                    .ok()
                    .into_iter()
                    .flat_map(move |statements| {
                        statements
                            .iter()
                            .enumerate()
                            .map(move |(index, statement)| (start + index, statement))
                    })
            })
    }

    pub fn shrink_to_fit(&mut self) {
        self.common.shrink_to_fit();
        self.expressions.shrink_to_fit();
        self.expression_operands.shrink_to_fit();
        self.statements.shrink_to_fit();
        self.statement_operands.shrink_to_fit();
    }

    fn decode_payload(bytes: &[u8]) -> Result<LlilPayload, IlError> {
        rkyv::from_bytes::<LlilPayload, rkyv::rancor::Error>(bytes)
            .map_err(|_| IlError::artefact_decode(Self::LEVEL))
    }
}

impl Verify for LlilBody {
    fn verify(&self) -> Result<(), IlError> {
        self.verify_header()?;
        self.common.verify()?;
        self.common.verify_node_bounds(self.statements.len())?;

        for expression in &self.expressions {
            self.verify_expression(expression)?;
        }

        for statement in &self.statements {
            self.verify_statement(statement)?;
        }

        Ok(())
    }
}

impl LlilBody {
    fn verify_expression(&self, expression: &Expression) -> Result<(), IlError> {
        expression
            .operands()
            .verify_bounds(self.expression_operands.len())?;

        if let Some(count) = expression.opcode().fixed_operand_count()
            && expression.operands().len() != count
        {
            return Err(IlError::llil_invalid_operand_count(
                count,
                expression.operands().len(),
            ));
        }

        if expression.opcode().requires_address_space() && expression.address_space().is_none() {
            return Err(IlError::llil_missing_address_space());
        }

        for operand in self.expression_operands_for(expression)? {
            self.expressions
                .get(operand.index())
                .ok_or(IlError::range_out_of_bounds(
                    operand.value(),
                    self.expressions.len(),
                ))?;
        }

        Ok(())
    }

    fn verify_statement(&self, statement: &Statement) -> Result<(), IlError> {
        statement
            .operands()
            .verify_bounds(self.statement_operands.len())?;

        if let Some(count) = statement.opcode().fixed_operand_count()
            && statement.operands().len() != count
        {
            return Err(IlError::llil_invalid_operand_count(
                count,
                statement.operands().len(),
            ));
        }

        if statement.opcode().requires_address() && statement.address().is_none() {
            return Err(IlError::llil_missing_address());
        }

        if statement.opcode().requires_address_space() && statement.address_space().is_none() {
            return Err(IlError::llil_missing_address_space());
        }

        if statement.opcode().requires_immediate() && statement.immediate() == 0 {
            return Err(IlError::llil_missing_immediate());
        }

        if let Some(value) = statement.value() {
            self.expressions
                .get(value.index())
                .ok_or(IlError::range_out_of_bounds(
                    value.value(),
                    self.expressions.len(),
                ))?;
        }

        for operand in self.statement_operands_for(statement)? {
            self.expressions
                .get(operand.index())
                .ok_or(IlError::range_out_of_bounds(
                    operand.value(),
                    self.expressions.len(),
                ))?;
        }

        Ok(())
    }
}

impl IrArtefact for LlilBody {
    const LEVEL: IrLevel = IrLevel::Llil;
    const SCHEMA: SchemaVersion = LLIL_SCHEMA_VERSION;

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

        let payload = LlilPayload::new(
            self.expressions.clone(),
            self.expression_operands.clone(),
            self.statements.clone(),
            self.statement_operands.clone(),
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
            payload.expressions,
            payload.expression_operands,
            payload.statements,
            payload.statement_operands,
        );

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
            payload.expressions,
            payload.expression_operands,
            payload.statements,
            payload.statement_operands,
        );

        body.verify()
    }
}

#[derive(Debug)]
pub struct LlilBuilder {
    header: ArtefactHeader,
    common: CommonBody,
    expressions: Vec<Expression>,
    expression_operands: Pool<ExpressionId>,
    statements: Vec<Statement>,
    statement_operands: Pool<ExpressionId>,
}

impl LlilBuilder {
    pub fn new(header: ArtefactHeader, common: CommonBody) -> Self {
        Self {
            header,
            common,
            expressions: Vec::new(),
            expression_operands: Pool::new(),
            statements: Vec::new(),
            statement_operands: Pool::new(),
        }
    }

    pub fn push_expression(&mut self, expression: Expression) -> Result<ExpressionId, IlError> {
        let id = ExpressionId::try_from_index(self.expressions.len())?;
        self.expressions.push(expression);
        Ok(id)
    }

    pub fn push_expression_operands(
        &mut self,
        operands: impl IntoIterator<Item = ExpressionId>,
    ) -> Result<PackedRange, IlError> {
        self.expression_operands.append(operands)
    }

    pub fn push_statement(&mut self, statement: Statement) -> Result<OperationId, IlError> {
        let id = OperationId::try_from_index(self.statements.len())?;
        self.statements.push(statement);
        Ok(id)
    }

    pub fn push_statement_operands(
        &mut self,
        operands: impl IntoIterator<Item = ExpressionId>,
    ) -> Result<PackedRange, IlError> {
        self.statement_operands.append(operands)
    }
}

impl Finish for LlilBuilder {
    type Output = LlilBody;

    fn finish(self, status: &(impl BuildCancellation + ?Sized)) -> Result<Self::Output, IlError> {
        if status.is_cancelled() {
            return Err(IlError::cancelled());
        }

        let mut body = LlilBody::new(
            self.header,
            self.common,
            self.expressions,
            self.expression_operands.into_values(),
            self.statements,
            self.statement_operands.into_values(),
        );

        body.shrink_to_fit();
        body.verify()?;

        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::common::{BuildStatus, SourceRun};
    use crate::il::llil::{ExpressionOpcode, StatementOpcode};
    use crate::ir::{Address, FunctionId};
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn llil_builder_finishes_verified_body() {
        assert!(std::mem::size_of::<Expression>() <= 40);
        assert!(std::mem::size_of::<Statement>() <= 64);

        let header =
            ArtefactHeader::new(FunctionId::default(), IrLevel::Llil, LLIL_SCHEMA_VERSION, 0);
        let mut builder = LlilBuilder::new(header, CommonBody::default());
        let expression = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                64,
                PackedRange::EMPTY,
                1,
                None,
            ))
            .unwrap();
        let operands = builder.push_statement_operands([expression]).unwrap();

        builder
            .push_statement(Statement::new(
                StatementOpcode::Return,
                operands,
                Some(expression),
                None,
                None,
            ))
            .unwrap();

        let body = builder.finish(&BuildStatus::new()).unwrap();
        let raw = body.to_raw_artefact().unwrap();

        assert_eq!(body.expressions().len(), 1);
        assert_eq!(body.statements().len(), 1);
        assert!(raw.verify_as::<LlilBody>().is_ok());
    }

    #[test]
    fn llil_body_returns_statements_for_source() {
        let header =
            ArtefactHeader::new(FunctionId::default(), IrLevel::Llil, LLIL_SCHEMA_VERSION, 0);
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
        let body = LlilBody::new(
            header,
            common,
            Vec::new(),
            Vec::new(),
            vec![
                Statement::new(StatementOpcode::Trap, PackedRange::EMPTY, None, None, None),
                Statement::new(StatementOpcode::Trap, PackedRange::EMPTY, None, None, None),
            ],
            Vec::new(),
        );

        let statements = body.statements_for_source(address).collect::<Vec<_>>();

        assert_eq!(statements.len(), 1);
        assert_eq!(statements[0].0, 0);
        assert_eq!(statements[0].1.opcode(), StatementOpcode::Trap);
    }

    #[test]
    fn llil_verifier_rejects_store_without_space() {
        let header =
            ArtefactHeader::new(FunctionId::default(), IrLevel::Llil, LLIL_SCHEMA_VERSION, 0);
        let mut builder = LlilBuilder::new(header, CommonBody::default());
        let offset = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                64,
                PackedRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let value = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                8,
                PackedRange::EMPTY,
                0xff,
                None,
            ))
            .unwrap();
        let operands = builder.push_statement_operands([offset, value]).unwrap();

        builder
            .push_statement(Statement::new(
                StatementOpcode::Store,
                operands,
                None,
                None,
                None,
            ))
            .unwrap();

        assert!(matches!(
            builder.finish(&BuildStatus::new()),
            Err(IlError::MissingAddressSpace { .. })
        ));
    }

    #[test]
    fn llil_verifier_rejects_load_without_space() {
        let header =
            ArtefactHeader::new(FunctionId::default(), IrLevel::Llil, LLIL_SCHEMA_VERSION, 0);
        let mut builder = LlilBuilder::new(header, CommonBody::default());
        let offset = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                64,
                PackedRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let operands = builder.push_expression_operands([offset]).unwrap();

        builder
            .push_expression(Expression::new(
                ExpressionOpcode::Load,
                8,
                operands,
                0,
                None,
            ))
            .unwrap();

        assert!(matches!(
            builder.finish(&BuildStatus::new()),
            Err(IlError::MissingAddressSpace { .. })
        ));
    }
}
