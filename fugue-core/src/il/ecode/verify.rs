use thiserror::Error;

use crate::il::common::verify::{StructureError, verify_parent_spans, verify_source_spans};
use crate::il::common::{IlArtefact, IlError};
use crate::il::ecode::{ECodeExpr, ECodeIr, ECodeStmt};

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum VerifyError {
    #[error(transparent)]
    Il(#[from] IlError),
    #[error("ECode operation has an invalid operand count: expected {expected}, found {found}")]
    InvalidOperandCount { expected: usize, found: usize },
    #[error(transparent)]
    Structure(StructureError),
}

impl From<StructureError> for VerifyError {
    fn from(error: StructureError) -> Self {
        match error {
            StructureError::Il(error) => Self::Il(error),
            error => Self::Structure(error),
        }
    }
}

impl ECodeIr {
    pub(crate) fn verify(&self) -> Result<(), VerifyError> {
        if self.metadata().schema() != Self::SCHEMA {
            return Err(IlError::schema_mismatch(
                Self::LEVEL,
                Self::SCHEMA.value(),
                self.metadata().schema().value(),
            )
            .into());
        }

        self.graph().verify()?;
        self.graph().verify_node_bounds(self.statements().len())?;
        verify_source_spans(self.source_spans(), self.statements().len())?;
        verify_parent_spans(self.parent_spans(), self.statements().len())?;

        for expression in self.expressions() {
            self.verify_expression(expression)?;
        }

        for statement in self.statements() {
            self.verify_statement(statement)?;
        }

        Ok(())
    }

    fn verify_expression(&self, expression: &ECodeExpr) -> Result<(), VerifyError> {
        expression
            .operands()
            .verify_bounds(self.expression_operands().len())?;

        if let Some(count) = expression.opcode().fixed_operand_count()
            && expression.operands().len() != count
        {
            return Err(VerifyError::InvalidOperandCount {
                expected: count,
                found: expression.operands().len(),
            });
        }

        if expression.opcode().requires_address_space() && expression.address_space().is_none() {
            return Err(IlError::missing_component(Self::LEVEL, "address space").into());
        }

        for operand in self.expression_operands_for(expression) {
            self.expressions()
                .get(operand.index())
                .ok_or(IlError::range_out_of_bounds(
                    operand.value(),
                    self.expressions().len(),
                ))?;
        }

        Ok(())
    }

    fn verify_statement(&self, statement: &ECodeStmt) -> Result<(), VerifyError> {
        statement
            .operands()
            .verify_bounds(self.statement_operands().len())?;

        if let Some(count) = statement.opcode().fixed_operand_count()
            && statement.operands().len() != count
        {
            return Err(VerifyError::InvalidOperandCount {
                expected: count,
                found: statement.operands().len(),
            });
        }

        if statement.opcode().requires_address() && statement.address().is_none() {
            return Err(IlError::missing_component(Self::LEVEL, "address").into());
        }

        if statement.opcode().requires_address_space() && statement.address_space().is_none() {
            return Err(IlError::missing_component(Self::LEVEL, "address space").into());
        }

        if let Some(value) = statement.value() {
            self.expressions()
                .get(value.index())
                .ok_or(IlError::range_out_of_bounds(
                    value.value(),
                    self.expressions().len(),
                ))?;
        }

        for operand in self.statement_operands_for(statement) {
            self.expressions()
                .get(operand.index())
                .ok_or(IlError::range_out_of_bounds(
                    operand.value(),
                    self.expressions().len(),
                ))?;
        }

        Ok(())
    }
}
