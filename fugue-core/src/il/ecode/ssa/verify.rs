use thiserror::Error;

use crate::il::common::verify::{StructureError, StructureVerifierError};
use crate::il::common::{
    ControlFlowIl, IlArtefact, IlBlockId, IlDominance, IlError, IlOpId, IlValueId,
};
use crate::il::ecode::ssa::{ECodeSsaIr, ECodeSsaOp, ECodeSsaOpcode, ECodeSsaValueKind};

#[cfg(test)]
mod test;

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum VerifyError {
    #[error("block {block} argument count mismatch: expected {expected}, found {found}")]
    BlockArgumentCount {
        block: u32,
        expected: usize,
        found: usize,
    },
    #[error("ECode SSA operation has a duplicate memory domain")]
    DuplicateMemoryDomain,
    #[error(transparent)]
    Il(#[from] IlError),
    #[error("ECode SSA operation {operation} has invalid block placement")]
    InvalidOperationPlacement { operation: u32 },
    #[error(
        "ECode SSA operation {operation} has an invalid result count: expected {expected}, found {found}"
    )]
    InvalidResultCount {
        operation: u32,
        expected: usize,
        found: usize,
    },
    #[error("ECode SSA value has an invalid definition")]
    InvalidValueDefinition,
    #[error(
        "ECode SSA value {value} does not dominate edge from block {predecessor} to block {successor}"
    )]
    NonDominatingEdgeArgument {
        value: u32,
        predecessor: u32,
        successor: u32,
    },
    #[error("ECode SSA value {value} does not dominate use by operation {user}")]
    NonDominatingUse { value: u32, user: u32 },
    #[error(transparent)]
    Structure(StructureError),
}

impl StructureVerifierError for VerifyError {
    fn structure(error: StructureError) -> Self {
        Self::Structure(error)
    }
}

impl ECodeSsaIr {
    pub(crate) fn verify(&self) -> Result<(), VerifyError> {
        self.verify_structure::<VerifyError>(
            self.source_spans(),
            Some(self.parent_spans()),
            self.operations().len(),
        )?;
        self.verify_memory_domains()?;
        self.verify_edge_arguments()?;

        for (argument_index, argument) in self.block_arguments().iter().enumerate() {
            self.graph().blocks().get(argument.block().index()).ok_or(
                IlError::range_out_of_bounds(argument.block().value(), self.graph().blocks().len()),
            )?;

            self.values().get(argument.value().index()).ok_or_else(|| {
                IlError::range_out_of_bounds(argument.value().value(), self.values().len())
            })?;

            let value = self.values()[argument.value().index()];

            if value.definition_kind() != ECodeSsaValueKind::BlockArgument
                || value.definition_index() != argument_index as u32
                || value.width() != argument.width()
            {
                return Err(VerifyError::InvalidValueDefinition);
            }
        }

        for (operation_index, operation) in self.operations().iter().enumerate() {
            let operation_id = IlOpId::try_from_index(operation_index)?;
            operation.results().verify_bounds(self.values().len())?;
            operation
                .operands()
                .verify_bounds(self.operation_operands().len())?;

            for result_index in operation.results().start()..operation.results().end() {
                let value = self.values()[result_index];

                if value.definition_kind() != ECodeSsaValueKind::Operation
                    || value.definition_index() != operation_index as u32
                {
                    return Err(VerifyError::InvalidValueDefinition);
                }

                if value.width() != operation.width() {
                    return Err(IlError::width_mismatch(ECodeSsaIr::FORM).into());
                }
            }

            if operation.opcode() == ECodeSsaOpcode::Constant && operation.width() > 64 {
                let bytes = operation.width().div_ceil(8) as usize;
                let end = (operation.immediate() as usize).saturating_add(bytes);
                if end > self.constant_storage().len() {
                    return Err(IlError::range_out_of_bounds(
                        u32::try_from(end).unwrap_or(u32::MAX),
                        self.constant_storage().len(),
                    )
                    .into());
                }
            }

            let uniform_operand_width = operation.opcode().has_uniform_operand_width();
            for operand in operation
                .operands()
                .checked_slice(self.operation_operands())?
            {
                let value = self.values().get(operand.index()).ok_or_else(|| {
                    IlError::range_out_of_bounds(operand.value(), self.values().len())
                })?;

                if uniform_operand_width && value.width() != operation.width() {
                    return Err(IlError::width_mismatch(ECodeSsaIr::FORM).into());
                }
            }

            if operation.opcode().requires_memory_domain() {
                let Some(address_space) = operation.address_space() else {
                    return Err(
                        IlError::missing_component(ECodeSsaIr::FORM, "memory domain").into(),
                    );
                };

                if self.memory_domain(address_space).is_none() {
                    return Err(
                        IlError::missing_component(ECodeSsaIr::FORM, "memory domain").into(),
                    );
                }

                self.verify_memory_operation(operation_id, operation)?;
            }
        }

        for (value_index, value) in self.values().iter().enumerate() {
            let value_id = IlValueId::try_from_index(value_index)?;

            match value.definition_kind() {
                ECodeSsaValueKind::Operation => {
                    let Some(operation) = self.operations().get(value.definition_index() as usize)
                    else {
                        return Err(VerifyError::InvalidValueDefinition);
                    };

                    if !operation.results().contains_index(value_id.index()) {
                        return Err(VerifyError::InvalidValueDefinition);
                    }
                }
                ECodeSsaValueKind::BlockArgument => {
                    let Some(argument) = self
                        .block_arguments()
                        .get(value.definition_index() as usize)
                    else {
                        return Err(VerifyError::InvalidValueDefinition);
                    };

                    if argument.value() != value_id || argument.width() != value.width() {
                        return Err(VerifyError::InvalidValueDefinition);
                    }
                }
            }
        }

        self.verify_dominating_uses()?;

        Ok(())
    }
    fn verify_memory_domains(&self) -> Result<(), VerifyError> {
        for (index, domain) in self.memory_domains().iter().enumerate() {
            if self.memory_domains()[..index]
                .iter()
                .any(|existing| existing.space() == domain.space())
            {
                return Err(VerifyError::DuplicateMemoryDomain);
            }
        }

        Ok(())
    }

    fn verify_memory_operation(
        &self,
        operation_id: IlOpId,
        operation: &ECodeSsaOp,
    ) -> Result<(), VerifyError> {
        if self.pointer_operand(operation).is_none() {
            return Err(IlError::missing_component(ECodeSsaIr::FORM, "pointer").into());
        }

        let Some(memory) = self.memory_operand(operation) else {
            return Err(IlError::missing_component(ECodeSsaIr::FORM, "memory domain").into());
        };
        let memory = self.values()[memory.index()];

        if memory.width() != 0 {
            return Err(IlError::width_mismatch(ECodeSsaIr::FORM).into());
        }

        if operation.opcode() == ECodeSsaOpcode::Store {
            if operation.results().len() != 1 {
                return Err(VerifyError::InvalidResultCount {
                    operation: operation_id.value(),
                    expected: 1,
                    found: operation.results().len(),
                });
            }

            let result = self.values()[operation.results().start()];

            if result.width() != 0 {
                return Err(IlError::width_mismatch(ECodeSsaIr::FORM).into());
            }
        }

        Ok(())
    }

    fn verify_edge_arguments(&self) -> Result<(), VerifyError> {
        if self.edge_arguments().len() != self.graph().successors().len() {
            return Err(VerifyError::BlockArgumentCount {
                block: 0,
                expected: self.graph().successors().len(),
                found: self.edge_arguments().len(),
            });
        }

        for range in self.edge_arguments() {
            range.verify_bounds(self.edge_argument_values().len())?;
        }

        for value in self.edge_argument_values() {
            self.values()
                .get(value.index())
                .ok_or_else(|| IlError::range_out_of_bounds(value.value(), self.values().len()))?;
        }

        Ok(())
    }

    fn verify_dominating_uses(&self) -> Result<(), VerifyError> {
        if self.graph().blocks().is_empty() {
            return self.verify_linear_dominating_uses();
        }

        let dominance = self.analyse::<IlDominance>();
        let operation_blocks = self.operation_blocks();

        self.verify_edge_argument_uses(&dominance, &operation_blocks)?;

        for (operation_index, operation) in self.operations().iter().enumerate() {
            let operation_id = IlOpId::try_from_index(operation_index)?;
            let Some(user_block) = operation_blocks[operation_index] else {
                return Err(VerifyError::InvalidOperationPlacement {
                    operation: operation_id.value(),
                });
            };

            if !dominance.is_reachable(user_block) {
                self.verify_operands_precede(operation, operation_index)?;
                continue;
            }

            for operand in self.operation_operands_for(operation) {
                if !self.value_dominates_operation(
                    *operand,
                    user_block,
                    operation_index,
                    &dominance,
                    &operation_blocks,
                )? {
                    return Err(VerifyError::NonDominatingUse {
                        value: operand.value(),
                        user: operation_id.value(),
                    });
                }
            }
        }

        Ok(())
    }

    fn verify_operands_precede(
        &self,
        operation: &ECodeSsaOp,
        operation_index: usize,
    ) -> Result<(), VerifyError> {
        let operation_id = IlOpId::try_from_index(operation_index)?;

        for operand in self.operation_operands_for(operation) {
            let value = self.values()[operand.index()];

            if value.definition_kind() == ECodeSsaValueKind::Operation
                && value.definition_index() as usize >= operation_index
            {
                return Err(VerifyError::NonDominatingUse {
                    value: operand.value(),
                    user: operation_id.value(),
                });
            }
        }

        Ok(())
    }

    fn verify_edge_argument_uses(
        &self,
        dominance: &IlDominance,
        operation_blocks: &[Option<IlBlockId>],
    ) -> Result<(), VerifyError> {
        for (predecessor_index, predecessor) in self.graph().blocks().iter().enumerate() {
            let predecessor_id = IlBlockId::try_from_index(predecessor_index)?;

            for (successor_offset, successor) in predecessor
                .successors()
                .checked_slice(self.graph().successors())?
                .iter()
                .enumerate()
            {
                let edge = predecessor.successors().start() + successor_offset;
                let arguments = self.arguments_for_edge(edge);
                let block_arguments = self
                    .block_arguments()
                    .iter()
                    .filter(|argument| argument.block() == *successor);
                let expected = block_arguments.clone().count();

                if arguments.len() != expected {
                    return Err(VerifyError::BlockArgumentCount {
                        block: successor.value(),
                        expected,
                        found: arguments.len(),
                    });
                }

                if !dominance.is_reachable(predecessor_id) {
                    continue;
                }

                for (value, argument) in arguments.iter().zip(block_arguments) {
                    let incoming = self.values()[value.index()];

                    if incoming.width() != argument.width() {
                        return Err(IlError::width_mismatch(ECodeSsaIr::FORM).into());
                    }

                    if !self.value_dominates_edge(
                        *value,
                        predecessor_id,
                        dominance,
                        operation_blocks,
                    )? {
                        return Err(VerifyError::NonDominatingEdgeArgument {
                            value: value.value(),
                            predecessor: predecessor_id.value(),
                            successor: successor.value(),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn verify_linear_dominating_uses(&self) -> Result<(), VerifyError> {
        for (operation_index, operation) in self.operations().iter().enumerate() {
            self.verify_operands_precede(operation, operation_index)?;
        }

        Ok(())
    }

    fn value_dominates_operation(
        &self,
        value_id: IlValueId,
        user_block: IlBlockId,
        user_operation: usize,
        dominance: &IlDominance,
        operation_blocks: &[Option<IlBlockId>],
    ) -> Result<bool, VerifyError> {
        let value = self.values()[value_id.index()];

        match value.definition_kind() {
            ECodeSsaValueKind::Operation => {
                let definition_operation = value.definition_index() as usize;
                let operation_id = IlOpId::try_from_index(definition_operation)?;
                let Some(definition_block) = operation_blocks
                    .get(definition_operation)
                    .copied()
                    .flatten()
                else {
                    return Err(VerifyError::InvalidOperationPlacement {
                        operation: operation_id.value(),
                    });
                };

                if definition_block == user_block {
                    Ok(definition_operation < user_operation)
                } else {
                    Ok(dominance.dominates(definition_block, user_block))
                }
            }
            ECodeSsaValueKind::BlockArgument => {
                let argument = self.block_arguments()[value.definition_index() as usize];

                Ok(dominance.dominates(argument.block(), user_block))
            }
        }
    }

    fn value_dominates_edge(
        &self,
        value_id: IlValueId,
        predecessor: IlBlockId,
        dominance: &IlDominance,
        operation_blocks: &[Option<IlBlockId>],
    ) -> Result<bool, VerifyError> {
        let value = self.values()[value_id.index()];

        match value.definition_kind() {
            ECodeSsaValueKind::Operation => {
                let definition_operation = value.definition_index() as usize;
                let operation_id = IlOpId::try_from_index(definition_operation)?;
                let Some(definition_block) = operation_blocks
                    .get(definition_operation)
                    .copied()
                    .flatten()
                else {
                    return Err(VerifyError::InvalidOperationPlacement {
                        operation: operation_id.value(),
                    });
                };

                Ok(definition_block == predecessor
                    || dominance.dominates(definition_block, predecessor))
            }
            ECodeSsaValueKind::BlockArgument => {
                let argument = self.block_arguments()[value.definition_index() as usize];

                Ok(dominance.dominates(argument.block(), predecessor))
            }
        }
    }
}
