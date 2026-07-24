use thiserror::Error;

use crate::il::common::verify::{StructureError, verify_source_spans};
use crate::il::common::{IlArtefact, IlError};
use crate::il::pcode::{PCodeIr, PCodeLocation, PCodeOp};

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum VerifyError {
    #[error("PCode operation has a forbidden output")]
    ForbiddenOutput,
    #[error(transparent)]
    Il(#[from] IlError),
    #[error("PCode operation has an invalid operand count: expected {expected}, found {found}")]
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

impl PCodeIr {
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
        self.graph().verify_node_bounds(self.operations().len())?;
        verify_source_spans(self.source_spans(), self.operations().len())?;

        for operation in self.operations() {
            self.verify_operation(operation)?;
        }

        Ok(())
    }

    fn verify_operation(&self, operation: &PCodeOp) -> Result<(), VerifyError> {
        operation.operands().verify_bounds(self.operands().len())?;

        if let Some(count) = operation.opcode().fixed_operand_count() {
            let found = operation.operands().len();

            if found != count {
                return Err(VerifyError::InvalidOperandCount {
                    expected: count,
                    found,
                });
            }
        }

        let output = operation.output();

        if operation.opcode().requires_output() && output.is_none() {
            return Err(IlError::missing_component(Self::LEVEL, "output").into());
        }

        if operation.opcode().forbids_output() && output.is_some() {
            return Err(VerifyError::ForbiddenOutput);
        }

        if let Some(output) = output {
            self.location(output).ok_or(IlError::range_out_of_bounds(
                output.value(),
                self.locations().len(),
            ))?;
        }

        for operand in self.operation_operands(operation) {
            self.location(*operand).ok_or(IlError::range_out_of_bounds(
                operand.value(),
                self.locations().len(),
            ))?;
        }

        if operation.opcode().requires_effect_space() && operation.effect_space().is_none() {
            return Err(IlError::missing_component(Self::LEVEL, "address space").into());
        }

        if operation.opcode().requires_target() && operation.immediate() == 0 {
            return Err(IlError::missing_component(Self::LEVEL, "address").into());
        }

        if operation.opcode().requires_target()
            && operation.immediate() as usize > self.targets().len()
        {
            return Err(
                IlError::range_out_of_bounds(operation.immediate(), self.targets().len()).into(),
            );
        }

        self.verify_operation_widths(operation)
    }

    fn verify_operation_widths(&self, operation: &PCodeOp) -> Result<(), VerifyError> {
        let operands = self.operation_operands(operation);
        let output = operation.output().and_then(|output| self.location(output));

        if let Some(output) = output
            && operation.opcode().preserves_first_operand_width()
            && let Some(first) = operands.first().and_then(|operand| self.location(*operand))
            && output.size() != first.size()
        {
            return Err(IlError::width_mismatch(Self::LEVEL).into());
        }

        if operation.opcode().compares_operands()
            && let [left, right] = operands
            && self.location(*left).map(PCodeLocation::size)
                != self.location(*right).map(PCodeLocation::size)
        {
            return Err(IlError::width_mismatch(Self::LEVEL).into());
        }

        Ok(())
    }
}
