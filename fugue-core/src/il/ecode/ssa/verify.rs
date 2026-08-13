use thiserror::Error;

use crate::il::common::verify::{StructureError, StructureVerifierError};
use crate::il::common::{
    ControlFlowIl, FlagId, IlArtefact, IlBlockArgId, IlBlockId, IlDominance, IlError, IlOpId,
    IlSsaDef, IlValueId, RegisterId,
};
use crate::il::ecode::ssa::{ECodeSsaDomain, ECodeSsaIr, ECodeSsaOp, ECodeSsaOpcode};

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
    #[error("ECode SSA value {value} has an inconsistent domain")]
    InconsistentValueDomain { value: u32 },
    #[error(
        "ECode SSA operation {operation} has an invalid operand count: expected {expected}, found {found}"
    )]
    InvalidOperandCount {
        operation: u32,
        expected: usize,
        found: usize,
    },
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
    #[error("ECode SSA value-domain count mismatch: expected {expected}, found {found}")]
    ValueDomainCount { expected: usize, found: usize },
}

impl VerifyError {
    const fn block_argument_count(block: u32, expected: usize, found: usize) -> Self {
        Self::BlockArgumentCount {
            block,
            expected,
            found,
        }
    }

    const fn duplicate_memory_domain() -> Self {
        Self::DuplicateMemoryDomain
    }

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

    const fn invalid_operation_placement(operation: IlOpId) -> Self {
        Self::InvalidOperationPlacement {
            operation: operation.value(),
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

    const fn non_dominating_edge_argument(
        value: IlValueId,
        predecessor: IlBlockId,
        successor: IlBlockId,
    ) -> Self {
        Self::NonDominatingEdgeArgument {
            value: value.value(),
            predecessor: predecessor.value(),
            successor: successor.value(),
        }
    }

    const fn non_dominating_use(value: IlValueId, user: IlOpId) -> Self {
        Self::NonDominatingUse {
            value: value.value(),
            user: user.value(),
        }
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

impl ECodeSsaIr {
    pub(crate) fn verify(&self) -> Result<(), VerifyError> {
        self.verify_structure::<VerifyError>(
            self.source_spans(),
            Some(self.parent_spans()),
            self.operations().len(),
        )?;
        self.verify_memory_domains()?;
        self.verify_value_domains()?;
        self.verify_edge_arguments()?;

        for (argument_index, argument) in self.block_arguments().iter().enumerate() {
            let argument_id = IlBlockArgId::try_from_index(argument_index)?;
            self.graph().blocks().get(argument.block().index()).ok_or(
                IlError::range_out_of_bounds(argument.block().value(), self.graph().blocks().len()),
            )?;

            self.values().get(argument.value().index()).ok_or_else(|| {
                IlError::range_out_of_bounds(argument.value().value(), self.values().len())
            })?;

            let value = self.values()[argument.value().index()];

            if value.definition() != IlSsaDef::BlockArgument(argument_id)
                || value.width() != argument.width()
            {
                return Err(VerifyError::invalid_value_definition());
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

                if value.definition() != IlSsaDef::Operation(operation_id) {
                    return Err(VerifyError::invalid_value_definition());
                }

                if value.width() != operation.width() {
                    return Err(IlError::width_mismatch(ECodeSsaIr::FORM).into());
                }
            }

            if operation.opcode() == ECodeSsaOpcode::Constant && operation.width() > 64 {
                let bytes = usize::try_from(operation.width().div_ceil(8))
                    .map_err(|_| IlError::integer_overflow("ECode SSA constant width"))?;
                let start = usize::try_from(operation.immediate())
                    .map_err(|_| IlError::integer_overflow("ECode SSA constant offset"))?;
                let end = start.saturating_add(bytes);
                if end > self.constant_storage().len() {
                    return Err(IlError::range_out_of_bounds(
                        u32::try_from(end).unwrap_or(u32::MAX),
                        self.constant_storage().len(),
                    )
                    .into());
                }
            }

            self.verify_domain_write(operation_id, operation)?;

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

            match value.definition() {
                IlSsaDef::Operation(operation) => {
                    let Some(operation) = self.operations().get(operation.index()) else {
                        return Err(VerifyError::invalid_value_definition());
                    };

                    if !operation.results().contains_index(value_id.index()) {
                        return Err(VerifyError::invalid_value_definition());
                    }
                }
                IlSsaDef::BlockArgument(argument) => {
                    let Some(argument) = self.block_arguments().get(argument.index()) else {
                        return Err(VerifyError::invalid_value_definition());
                    };

                    if argument.value() != value_id || argument.width() != value.width() {
                        return Err(VerifyError::invalid_value_definition());
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
                return Err(VerifyError::duplicate_memory_domain());
            }
        }

        Ok(())
    }

    fn verify_value_domains(&self) -> Result<(), VerifyError> {
        if self.value_domains().len() != self.values().len() {
            return Err(VerifyError::value_domain_count(
                self.values().len(),
                self.value_domains().len(),
            ));
        }

        for (index, value) in self.values().iter().enumerate() {
            let value_id = IlValueId::try_from_index(index)?;
            let Some(domain) = self.value_domain(value_id) else {
                continue;
            };
            let consistent = match value.definition() {
                IlSsaDef::BlockArgument(_) => {
                    if domain.is_register_or_flag() {
                        value.width() != 0
                    } else {
                        value.width() == 0
                    }
                }
                IlSsaDef::Operation(operation) => {
                    let operation = self.operations().get(operation.index());
                    match (domain, operation) {
                        (ECodeSsaDomain::Flag(storage), Some(operation)) => {
                            value.width() != 0
                                && operation.immediate() == storage.value()
                                && matches!(
                                    operation.opcode(),
                                    ECodeSsaOpcode::Undefined | ECodeSsaOpcode::WriteFlag
                                )
                        }
                        (ECodeSsaDomain::Memory(space), Some(operation)) => {
                            value.width() == 0
                                && match operation.opcode() {
                                    ECodeSsaOpcode::Store => {
                                        operation.address_space() == Some(space)
                                    }
                                    ECodeSsaOpcode::Undefined => u64::try_from(space.index())
                                        .is_ok_and(|space| operation.immediate() == space),
                                    _ => false,
                                }
                        }
                        (ECodeSsaDomain::Register(storage), Some(operation)) => {
                            value.width() != 0
                                && operation.immediate() == storage.value()
                                && matches!(
                                    operation.opcode(),
                                    ECodeSsaOpcode::Undefined | ECodeSsaOpcode::WriteRegister
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
        operation: &ECodeSsaOp,
    ) -> Result<(), VerifyError> {
        let expected_domain = match operation.opcode() {
            ECodeSsaOpcode::WriteFlag => ECodeSsaDomain::Flag(FlagId::new(operation.immediate())),
            ECodeSsaOpcode::WriteRegister => {
                ECodeSsaDomain::Register(RegisterId::new(operation.immediate()))
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
        if self.value_domain(result) != Some(expected_domain) {
            return Err(VerifyError::inconsistent_value_domain(result));
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
                return Err(VerifyError::invalid_result_count(
                    operation_id,
                    1,
                    operation.results().len(),
                ));
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
            return Err(VerifyError::block_argument_count(
                0,
                self.graph().successors().len(),
                self.edge_arguments().len(),
            ));
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
                return Err(VerifyError::invalid_operation_placement(operation_id));
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
                    return Err(VerifyError::non_dominating_use(*operand, operation_id));
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

            if let IlSsaDef::Operation(definition) = value.definition()
                && definition.index() >= operation_index
            {
                return Err(VerifyError::non_dominating_use(*operand, operation_id));
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
                    return Err(VerifyError::block_argument_count(
                        successor.value(),
                        expected,
                        arguments.len(),
                    ));
                }

                for (value, argument) in arguments.iter().zip(block_arguments) {
                    let incoming = self.values()[value.index()];

                    if incoming.width() != argument.width() {
                        return Err(IlError::width_mismatch(ECodeSsaIr::FORM).into());
                    }
                    if self.value_domain(*value) != self.value_domain(argument.value()) {
                        return Err(VerifyError::inconsistent_value_domain(argument.value()));
                    }

                    if dominance.is_reachable(predecessor_id)
                        && !self.value_dominates_edge(
                            *value,
                            predecessor_id,
                            dominance,
                            operation_blocks,
                        )?
                    {
                        return Err(VerifyError::non_dominating_edge_argument(
                            *value,
                            predecessor_id,
                            *successor,
                        ));
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

        match value.definition() {
            IlSsaDef::Operation(operation_id) => {
                let definition_operation = operation_id.index();
                let Some(definition_block) = operation_blocks
                    .get(definition_operation)
                    .copied()
                    .flatten()
                else {
                    return Err(VerifyError::invalid_operation_placement(operation_id));
                };

                if definition_block == user_block {
                    Ok(definition_operation < user_operation)
                } else {
                    Ok(dominance.dominates(definition_block, user_block))
                }
            }
            IlSsaDef::BlockArgument(argument) => {
                let argument = self
                    .block_arguments()
                    .get(argument.index())
                    .ok_or_else(VerifyError::invalid_value_definition)?;

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

        match value.definition() {
            IlSsaDef::Operation(operation_id) => {
                let definition_operation = operation_id.index();
                let Some(definition_block) = operation_blocks
                    .get(definition_operation)
                    .copied()
                    .flatten()
                else {
                    return Err(VerifyError::invalid_operation_placement(operation_id));
                };

                Ok(definition_block == predecessor
                    || dominance.dominates(definition_block, predecessor))
            }
            IlSsaDef::BlockArgument(argument) => {
                let argument = self
                    .block_arguments()
                    .get(argument.index())
                    .ok_or_else(VerifyError::invalid_value_definition)?;

                Ok(dominance.dominates(argument.block(), predecessor))
            }
        }
    }
}
