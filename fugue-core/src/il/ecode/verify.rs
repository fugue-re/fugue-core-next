use thiserror::Error;

use crate::il::common::verify::{StructureError, StructureVerifierError};
use crate::il::common::{ControlFlowIl, IlArtefact, IlBlock, IlBlockId, IlEdgeKinds, IlError};
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

        let terminator = (!block.operations().is_empty())
            .then(|| block.operations().end() - 1)
            .and_then(|index| self.statements().get(index))
            .map(ECodeStmt::opcode);
        let (permitted, required) = match terminator {
            Some(ECodeStmtOpcode::Branch) => {
                (IlEdgeKinds::UNCONDITIONAL, IlEdgeKinds::UNCONDITIONAL)
            }
            Some(ECodeStmtOpcode::BranchIndirect) => (IlEdgeKinds::COMPUTED, IlEdgeKinds::COMPUTED),
            Some(ECodeStmtOpcode::ConditionalBranch) => (
                IlEdgeKinds::FALL_THROUGH | IlEdgeKinds::TAKEN,
                IlEdgeKinds::FALL_THROUGH | IlEdgeKinds::TAKEN,
            ),
            Some(ECodeStmtOpcode::Return) => (IlEdgeKinds::empty(), IlEdgeKinds::empty()),
            _ => (
                IlEdgeKinds::FALL_THROUGH | IlEdgeKinds::UNCONDITIONAL,
                IlEdgeKinds::empty(),
            ),
        };

        let start = block.successors().start() as u32;
        let mut covered = IlEdgeKinds::empty();
        for (edge, kinds) in kinds.iter().enumerate() {
            let repeated = covered.intersects(*kinds & IlEdgeKinds::SINGULAR);
            if !kinds.is_empty() && permitted.contains(*kinds) && !repeated {
                covered |= *kinds;
                continue;
            }
            return Err(VerifyError::Structure(StructureError::EdgeKindMismatch {
                block: block_id.value(),
                edge: start.saturating_add(edge as u32),
                kinds: *kinds,
            }));
        }

        if !covered.contains(required) {
            return Err(VerifyError::Structure(StructureError::EdgeKindMissing {
                block: block_id.value(),
                covered,
                required,
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
            return Err(IlError::missing_component(Self::FORM, "address space").into());
        }

        for operand in self.expression_operands_for(expression) {
            if operand.index() >= expression_index {
                return Err(VerifyError::InvalidOperandOrdering {
                    expression: expression_index,
                });
            }
            self.expressions().get(operand.index()).ok_or_else(|| {
                IlError::range_out_of_bounds(operand.value(), self.expressions().len())
            })?;
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
            return Err(IlError::missing_component(Self::FORM, "address").into());
        }

        if statement.opcode().requires_address_space() && statement.address_space().is_none() {
            return Err(IlError::missing_component(Self::FORM, "address space").into());
        }

        if let Some(value) = statement.value() {
            self.expressions().get(value.index()).ok_or_else(|| {
                IlError::range_out_of_bounds(value.value(), self.expressions().len())
            })?;
        }

        for operand in self.statement_operands_for(statement) {
            self.expressions().get(operand.index()).ok_or_else(|| {
                IlError::range_out_of_bounds(operand.value(), self.expressions().len())
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::analysis::control::CancellationToken;
    use crate::il::common::{IlBlockProperties, IlGraph, IlIndexRange, IlMetadata};
    use crate::il::ecode::{ECodeBuilder, ECodeExpr, ECodeExprOpcode};
    use crate::ir::{Address, FunctionId};
    use crate::storage::segments::space::AddressSpaceId;

    fn conditional_branch(kinds: Vec<IlEdgeKinds>) -> ECodeIr {
        let mut builder = ECodeBuilder::new(
            IlMetadata::new(FunctionId::default(), 0),
            IlGraph::default(),
        );
        let condition = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                8,
                IlIndexRange::EMPTY,
                1,
                None,
            ))
            .unwrap();
        let operands = builder.push_statement_operands([condition]).unwrap();
        builder
            .push_statement(ECodeStmt::new(
                ECodeStmtOpcode::ConditionalBranch,
                operands,
                None,
                Some(Address::new(AddressSpaceId::new(1), 0x1000u64)),
                None,
            ))
            .unwrap();

        let successors = kinds.len();
        let mut blocks = vec![IlBlock::new(
            IlIndexRange::new(0, 1).unwrap(),
            IlIndexRange::new(0, successors).unwrap(),
            IlBlockProperties::ENTRY,
        )];
        blocks.extend((0..successors).map(|_| {
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            )
        }));
        let targets = (0..successors)
            .map(|index| IlBlockId::try_from_index(index + 1).unwrap())
            .collect();
        builder.set_graph(IlGraph::new(blocks, targets, kinds));

        builder.build(&CancellationToken::default()).unwrap()
    }

    #[test]
    fn a_conditional_branch_carries_one_taken_and_one_fall_through_edge() {
        let ir = conditional_branch(vec![IlEdgeKinds::TAKEN, IlEdgeKinds::FALL_THROUGH]);

        assert!(ir.verify().is_ok());
    }

    #[test]
    fn a_collapsed_conditional_edge_carries_both_kinds() {
        let ir = conditional_branch(vec![IlEdgeKinds::TAKEN | IlEdgeKinds::FALL_THROUGH]);

        assert!(ir.verify().is_ok());
    }

    #[test]
    fn a_conditional_branch_cannot_take_two_arms() {
        let ir = conditional_branch(vec![
            IlEdgeKinds::TAKEN,
            IlEdgeKinds::TAKEN,
            IlEdgeKinds::FALL_THROUGH,
        ]);

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::Structure(StructureError::EdgeKindMismatch {
                edge: 1,
                ..
            }))
        ));
    }

    #[test]
    fn a_block_cannot_fall_through_to_two_successors() {
        let ir = conditional_branch(vec![IlEdgeKinds::FALL_THROUGH, IlEdgeKinds::FALL_THROUGH]);

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::Structure(StructureError::EdgeKindMismatch {
                edge: 1,
                ..
            }))
        ));
    }

    #[test]
    fn a_conditional_branch_without_a_fall_through_edge_is_rejected() {
        let ir = conditional_branch(vec![IlEdgeKinds::TAKEN]);

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::Structure(StructureError::EdgeKindMissing {
                covered: IlEdgeKinds::TAKEN,
                ..
            }))
        ));
    }
}
