use thiserror::Error;

use crate::il::common::verify::{StructureError, StructureVerifierError};
use crate::il::common::{
    ControlFlowIl, FlagId, IlArtefact, IlBlockArgId, IlError, IlOpId, IlSsaDef, IlValueId,
    RegisterId, SsaVerifier, SsaVerifyError,
};
use crate::il::ecode::{ECodeDomain, ECodeIr, ECodeOp, ECodeOpcode};

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum VerifyError {
    #[error("block {block} argument count mismatch: expected {expected}, found {found}")]
    BlockArgCount {
        block: u32,
        expected: usize,
        found: usize,
    },
    #[error("ECode operation has a duplicate memory domain")]
    DuplicateMemoryDomain,
    #[error("ECode edge-argument table count mismatch: expected {expected}, found {found}")]
    EdgeArgTableCount { expected: usize, found: usize },
    #[error(transparent)]
    Il(#[from] IlError),
    #[error("ECode value {value} has an inconsistent domain")]
    InconsistentValueDomain { value: u32 },
    #[error(
        "ECode operation {operation} has an invalid operand count: expected {expected}, found {found}"
    )]
    InvalidOperandCount {
        operation: u32,
        expected: usize,
        found: usize,
    },
    #[error("ECode operation {operation} has invalid block placement")]
    InvalidOperationPlacement { operation: u32 },
    #[error(
        "ECode operation {operation} has an invalid result count: expected {expected}, found {found}"
    )]
    InvalidResultCount {
        operation: u32,
        expected: usize,
        found: usize,
    },
    #[error("ECode value has an invalid definition")]
    InvalidValueDefinition,
    #[error(
        "ECode value {value} does not dominate edge from block {predecessor} to block {successor}"
    )]
    NonDominatingEdgeArg {
        value: u32,
        predecessor: u32,
        successor: u32,
    },
    #[error("ECode value {value} does not dominate use by operation {user}")]
    NonDominatingUse { value: u32, user: u32 },
    #[error(transparent)]
    Structure(StructureError),
    #[error("ECode value-domain count mismatch: expected {expected}, found {found}")]
    ValueDomainCount { expected: usize, found: usize },
}

impl VerifyError {
    const fn inconsistent_value_domain(value: IlValueId) -> Self {
        Self::InconsistentValueDomain {
            value: value.value(),
        }
    }

    const fn invalid_operand_count(operation: IlOpId, expected: usize, found: usize) -> Self {
        Self::InvalidOperandCount {
            operation: operation.value(),
            expected,
            found,
        }
    }

    const fn invalid_result_count(operation: IlOpId, expected: usize, found: usize) -> Self {
        Self::InvalidResultCount {
            operation: operation.value(),
            expected,
            found,
        }
    }

    const fn invalid_value_definition() -> Self {
        Self::InvalidValueDefinition
    }

    const fn value_domain_count(expected: usize, found: usize) -> Self {
        Self::ValueDomainCount { expected, found }
    }
}

impl StructureVerifierError for VerifyError {
    fn structure(error: StructureError) -> Self {
        Self::Structure(error)
    }
}

impl From<SsaVerifyError> for VerifyError {
    fn from(error: SsaVerifyError) -> Self {
        match error {
            SsaVerifyError::BlockArgCount {
                block,
                expected,
                found,
            } => Self::BlockArgCount {
                block,
                expected,
                found,
            },
            SsaVerifyError::DuplicateMemoryDomain => Self::DuplicateMemoryDomain,
            SsaVerifyError::EdgeArgTableCount { expected, found } => {
                Self::EdgeArgTableCount { expected, found }
            }
            SsaVerifyError::Il(error) => Self::Il(error),
            SsaVerifyError::InvalidOperationPlacement { operation } => {
                Self::InvalidOperationPlacement { operation }
            }
            SsaVerifyError::InvalidValueDefinition => Self::InvalidValueDefinition,
            SsaVerifyError::NonDominatingEdgeArg {
                value,
                predecessor,
                successor,
            } => Self::NonDominatingEdgeArg {
                value,
                predecessor,
                successor,
            },
            SsaVerifyError::NonDominatingUse { value, user } => {
                Self::NonDominatingUse { value, user }
            }
        }
    }
}

pub(crate) fn verify(ir: &ECodeIr) -> Result<(), VerifyError> {
    ECodeVerifier { ir }.verify()
}

struct ECodeVerifier<'a> {
    ir: &'a ECodeIr,
}

impl ECodeVerifier<'_> {
    fn verify(&self) -> Result<(), VerifyError> {
        self.ir.verify_structure::<VerifyError>(
            self.ir.source_spans(),
            Some(self.ir.parent_spans()),
            self.ir.operations().len(),
        )?;
        SsaVerifier::new(self.ir).verify_memory_domains()?;
        self.verify_value_domains()?;
        SsaVerifier::new(self.ir).verify_edge_args()?;

        for (arg_index, arg) in self.ir.block_args().iter().enumerate() {
            let arg_id = IlBlockArgId::try_from_index(arg_index)?;
            self.ir.graph().blocks().get(arg.block().index()).ok_or(
                IlError::range_out_of_bounds(arg.block().index(), self.ir.graph().blocks().len()),
            )?;

            self.ir.values().get(arg.value().index()).ok_or_else(|| {
                IlError::range_out_of_bounds(arg.value().index(), self.ir.values().len())
            })?;

            let value = self.ir.values()[arg.value().index()];

            if value.definition() != IlSsaDef::BlockArg(arg_id) || value.width() != arg.width() {
                return Err(VerifyError::invalid_value_definition());
            }
        }

        for (operation_index, operation) in self.ir.operations().iter().enumerate() {
            let operation_id = IlOpId::try_from_index(operation_index)?;
            operation.results().verify_bounds(self.ir.values().len())?;
            operation
                .operands()
                .verify_bounds(self.ir.operation_operands().len())?;

            for result_index in operation.results().start()..operation.results().end() {
                let value = self.ir.values()[result_index];

                if value.definition() != IlSsaDef::Operation(operation_id) {
                    return Err(VerifyError::invalid_value_definition());
                }

                if value.width() != operation.width() {
                    return Err(IlError::width_mismatch(ECodeIr::FORM).into());
                }
            }

            if operation.opcode() == ECodeOpcode::Constant && operation.width() > 64 {
                let bytes = usize::try_from(operation.width().div_ceil(8))
                    .map_err(|_| IlError::integer_overflow("ECode constant width"))?;
                let start = usize::try_from(operation.immediate())
                    .map_err(|_| IlError::integer_overflow("ECode constant offset"))?;
                let end = start.saturating_add(bytes);
                if end > self.ir.constant_storage().len() {
                    return Err(IlError::range_out_of_bounds(
                        end,
                        self.ir.constant_storage().len(),
                    )
                    .into());
                }
            }

            self.verify_domain_write(operation_id, operation)?;

            let uniform_operand_width = operation.opcode().has_uniform_operand_width();
            for operand in operation
                .operands()
                .checked_slice(self.ir.operation_operands())?
            {
                let value = self.ir.values().get(operand.index()).ok_or_else(|| {
                    IlError::range_out_of_bounds(operand.index(), self.ir.values().len())
                })?;

                if uniform_operand_width && value.width() != operation.width() {
                    return Err(IlError::width_mismatch(ECodeIr::FORM).into());
                }
            }

            if operation.opcode().requires_memory_domain() {
                let Some(address_space) = operation.address_space() else {
                    return Err(IlError::missing_component(ECodeIr::FORM, "memory domain").into());
                };

                if self.ir.memory_domain(address_space).is_none() {
                    return Err(IlError::missing_component(ECodeIr::FORM, "memory domain").into());
                }

                self.verify_memory_operation(operation_id, operation)?;
            }
        }

        for (value_index, value) in self.ir.values().iter().enumerate() {
            let value_id = IlValueId::try_from_index(value_index)?;

            match value.definition() {
                IlSsaDef::Operation(operation) => {
                    let Some(operation) = self.ir.operations().get(operation.index()) else {
                        return Err(VerifyError::invalid_value_definition());
                    };

                    if !operation.results().contains_index(value_id.index()) {
                        return Err(VerifyError::invalid_value_definition());
                    }
                }
                IlSsaDef::BlockArg(arg) => {
                    let Some(arg) = self.ir.block_args().get(arg.index()) else {
                        return Err(VerifyError::invalid_value_definition());
                    };

                    if arg.value() != value_id || arg.width() != value.width() {
                        return Err(VerifyError::invalid_value_definition());
                    }
                }
            }
        }

        SsaVerifier::new(self.ir).verify_uses(|incoming, destination| {
            if self.ir.value_domain(incoming) != self.ir.value_domain(destination) {
                return Err(VerifyError::inconsistent_value_domain(destination));
            }
            Ok(())
        })?;

        Ok(())
    }

    fn verify_value_domains(&self) -> Result<(), VerifyError> {
        if self.ir.value_domains().len() != self.ir.values().len() {
            return Err(VerifyError::value_domain_count(
                self.ir.values().len(),
                self.ir.value_domains().len(),
            ));
        }

        for (index, value) in self.ir.values().iter().enumerate() {
            let value_id = IlValueId::try_from_index(index)?;
            let Some(domain) = self.ir.value_domain(value_id) else {
                continue;
            };
            let consistent = match value.definition() {
                IlSsaDef::BlockArg(_) => {
                    if domain.is_register_or_flag() {
                        value.width() != 0
                    } else {
                        value.width() == 0
                    }
                }
                IlSsaDef::Operation(operation) => {
                    let operation = self.ir.operations().get(operation.index());
                    match (domain, operation) {
                        (ECodeDomain::Flag(storage), Some(operation)) => {
                            value.width() != 0
                                && operation.immediate() == storage.value()
                                && matches!(
                                    operation.opcode(),
                                    ECodeOpcode::Undefined | ECodeOpcode::WriteFlag
                                )
                        }
                        (ECodeDomain::Memory(space), Some(operation)) => {
                            value.width() == 0
                                && match operation.opcode() {
                                    ECodeOpcode::Store => operation.address_space() == Some(space),
                                    ECodeOpcode::Undefined => {
                                        operation.immediate() == u64::from(space.value())
                                    }
                                    _ => false,
                                }
                        }
                        (ECodeDomain::Register(storage), Some(operation)) => {
                            value.width() != 0
                                && operation.immediate() == storage.value()
                                && matches!(
                                    operation.opcode(),
                                    ECodeOpcode::Undefined | ECodeOpcode::WriteRegister
                                )
                        }
                        (_, None) => false,
                    }
                }
            };
            if !consistent {
                return Err(VerifyError::inconsistent_value_domain(value_id));
            }
        }

        Ok(())
    }

    fn verify_domain_write(
        &self,
        operation_id: IlOpId,
        operation: &ECodeOp,
    ) -> Result<(), VerifyError> {
        let expected_domain = match operation.opcode() {
            ECodeOpcode::WriteFlag => ECodeDomain::Flag(FlagId::new(operation.immediate())),
            ECodeOpcode::WriteRegister => {
                ECodeDomain::Register(RegisterId::new(operation.immediate()))
            }
            _ => return Ok(()),
        };

        if operation.operands().len() != 1 {
            return Err(VerifyError::invalid_operand_count(
                operation_id,
                1,
                operation.operands().len(),
            ));
        }
        if operation.results().len() != 1 {
            return Err(VerifyError::invalid_result_count(
                operation_id,
                1,
                operation.results().len(),
            ));
        }

        let result = IlValueId::try_from_index(operation.results().start())?;
        if self.ir.value_domain(result) != Some(expected_domain) {
            return Err(VerifyError::inconsistent_value_domain(result));
        }

        Ok(())
    }

    fn verify_memory_operation(
        &self,
        operation_id: IlOpId,
        operation: &ECodeOp,
    ) -> Result<(), VerifyError> {
        if self.ir.pointer_operand(operation).is_none() {
            return Err(IlError::missing_component(ECodeIr::FORM, "pointer").into());
        }

        let Some(memory) = self.ir.memory_operand(operation) else {
            return Err(IlError::missing_component(ECodeIr::FORM, "memory domain").into());
        };
        let memory = self.ir.values()[memory.index()];

        if memory.width() != 0 {
            return Err(IlError::width_mismatch(ECodeIr::FORM).into());
        }

        if operation.opcode() == ECodeOpcode::Store {
            if operation.results().len() != 1 {
                return Err(VerifyError::invalid_result_count(
                    operation_id,
                    1,
                    operation.results().len(),
                ));
            }

            let result = self.ir.values()[operation.results().start()];

            if result.width() != 0 {
                return Err(IlError::width_mismatch(ECodeIr::FORM).into());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test;
