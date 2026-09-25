use thiserror::Error;

use crate::il::common::verify::{StructureError, StructureVerifierError};
use crate::il::common::{ControlFlowIl, IlArtefact, IlError};
use crate::il::pcode::{PCodeIr, PCodeLocation, PCodeOp};

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum VerifyError {
    #[error("PCode operation has a forbidden effect space")]
    ForbiddenEffectSpace,
    #[error("PCode operation has a forbidden output")]
    ForbiddenOutput,
    #[error(transparent)]
    Il(#[from] IlError),
    #[error("PCode location has conflicting properties")]
    InvalidLocationProperties,
    #[error("PCode operation has an invalid operand count: expected {expected}, found {found}")]
    InvalidOperandCount { expected: usize, found: usize },
    #[error(transparent)]
    Structure(StructureError),
}

impl StructureVerifierError for VerifyError {
    fn structure(error: StructureError) -> Self {
        Self::Structure(error)
    }
}

pub(crate) fn verify(ir: &PCodeIr) -> Result<(), VerifyError> {
    PCodeVerifier { ir }.verify()
}

struct PCodeVerifier<'a> {
    ir: &'a PCodeIr,
}

impl PCodeVerifier<'_> {
    fn verify(&self) -> Result<(), VerifyError> {
        self.ir.verify_structure::<VerifyError>(
            self.ir.source_spans(),
            None,
            self.ir.ops().len(),
        )?;

        if self
            .ir
            .locations()
            .iter()
            .any(|location| location.properties().bits().count_ones() > 1)
        {
            return Err(VerifyError::InvalidLocationProperties);
        }

        for operation in self.ir.ops() {
            self.verify_op(operation)?;
        }

        Ok(())
    }

    fn verify_op(&self, operation: &PCodeOp) -> Result<(), VerifyError> {
        operation
            .operands()
            .verify_bounds(self.ir.op_operands().len())?;

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
            return Err(IlError::missing_component(PCodeIr::FORM, "output").into());
        }

        if operation.opcode().forbids_output() && output.is_some() {
            return Err(VerifyError::ForbiddenOutput);
        }

        if let Some(output) = output {
            self.ir.location(output).ok_or_else(|| {
                IlError::range_out_of_bounds(output.index(), self.ir.locations().len())
            })?;
        }

        for operand in self.ir.op_operands_for(operation) {
            self.ir.location(*operand).ok_or_else(|| {
                IlError::range_out_of_bounds(operand.index(), self.ir.locations().len())
            })?;
        }

        if operation.opcode().requires_address_space() && operation.address_space().is_none() {
            return Err(IlError::missing_component(PCodeIr::FORM, "address space").into());
        }
        if !operation.opcode().requires_address_space() && operation.address_space().is_some() {
            return Err(VerifyError::ForbiddenEffectSpace);
        }

        if operation.opcode().requires_address() && operation.target().is_none() {
            return Err(IlError::missing_component(PCodeIr::FORM, "address").into());
        }

        if let Some(target) = operation.target()
            && self.ir.target(target).is_none()
        {
            return Err(
                IlError::range_out_of_bounds(target.index(), self.ir.targets().len()).into(),
            );
        }

        self.verify_op_sizes(operation)
    }

    fn verify_op_sizes(&self, operation: &PCodeOp) -> Result<(), VerifyError> {
        let operands = self.ir.op_operands_for(operation);
        let output = operation
            .output()
            .and_then(|output| self.ir.location(output));

        if let Some(output) = output
            && operation.opcode().preserves_first_operand_size()
            && let Some(first) = operands
                .first()
                .and_then(|operand| self.ir.location(*operand))
            && output.size() != first.size()
        {
            return Err(IlError::width_mismatch(PCodeIr::FORM).into());
        }

        if operation.opcode().compares_operands()
            && let [left, right] = operands
            && self.ir.location(*left).map(PCodeLocation::size)
                != self.ir.location(*right).map(PCodeLocation::size)
        {
            return Err(IlError::width_mismatch(PCodeIr::FORM).into());
        }

        Ok(())
    }
}
