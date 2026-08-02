use thiserror::Error;

use crate::il::common::verify::{StructureError, StructureVerifierError};
use crate::il::common::{IlArtefact, IlBlock, IlBlockId, IlEdgeKinds, IlError};
use crate::il::ecode::{ECodeExpr, ECodeIr, ECodeStmt, ECodeStmtOpcode};

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum VerifyError {
    #[error(transparent)]
    Il(#[from] IlError),
    #[error("ECode operation has an invalid operand count: expected {expected}, found {found}")]
    InvalidOperandCount { expected: usize, found: usize },
    #[error("ECode expression {expression} references a non-preceding operand")]
    InvalidOperandOrdering { expression: usize },
    #[error(transparent)]
    Structure(StructureError),
}

impl StructureVerifierError for VerifyError {
    fn structure(error: StructureError) -> Self {
        Self::Structure(error)
    }
}

impl ECodeIr {
    pub(crate) fn verify(&self) -> Result<(), VerifyError> {
        self.verify_structure::<VerifyError>(
            self.source_spans(),
            Some(self.parent_spans()),
            self.statements().len(),
        )?;

        for (index, expression) in self.expressions().iter().enumerate() {
            self.verify_expression(index, expression)?;
        }

        for statement in self.statements() {
            self.verify_statement(statement)?;
        }

        for (index, block) in self.graph().blocks().iter().enumerate() {
            let block_id = IlBlockId::try_from_index(index)?;
            self.verify_edge_kinds(block, block_id)?;
        }

        Ok(())
    }

    fn verify_edge_kinds(&self, block: &IlBlock, block_id: IlBlockId) -> Result<(), VerifyError> {
        let kinds = block.successors().slice(self.graph().successor_kinds());
        if kinds.is_empty() {
            return Ok(());
        }

        let terminator = block
            .operations()
            .end()
            .checked_sub(1)
            .and_then(|index| self.statements().get(index))
            .map(ECodeStmt::opcode);
        let permitted = match terminator {
            Some(ECodeStmtOpcode::Branch) => IlEdgeKinds::UNCONDITIONAL,
            Some(ECodeStmtOpcode::BranchIndirect) => IlEdgeKinds::COMPUTED,
            Some(ECodeStmtOpcode::ConditionalBranch) => {
                IlEdgeKinds::FALL_THROUGH | IlEdgeKinds::TAKEN
            }
            Some(ECodeStmtOpcode::Return) => IlEdgeKinds::empty(),
            _ => IlEdgeKinds::FALL_THROUGH | IlEdgeKinds::UNCONDITIONAL,
        };

        let start = block.successors().start() as u32;
        for (edge, kinds) in kinds.iter().enumerate() {
            if !kinds.is_empty() && permitted.contains(*kinds) {
                continue;
            }
            return Err(VerifyError::Structure(StructureError::EdgeKindMismatch {
                block: block_id.value(),
                edge: start.saturating_add(edge as u32),
                kinds: *kinds,
            }));
        }

        Ok(())
    }

    fn verify_expression(
        &self,
        expression_index: usize,
        expression: &ECodeExpr,
    ) -> Result<(), VerifyError> {
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
            if operand.index() >= expression_index {
                return Err(VerifyError::InvalidOperandOrdering {
                    expression: expression_index,
                });
            }
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
