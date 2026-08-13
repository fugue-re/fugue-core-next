use rustc_hash::FxHashMap;
use thiserror::Error;

use crate::il::common::verify::{StructureError, StructureVerifierError};
use crate::il::common::{
    ControlFlowIl, IlArtefact, IlBlock, IlBlockArgId, IlBlockId, IlDominance, IlEdgeKinds, IlError,
    IlOpId, IlSsaDef, IlValueId,
};
use crate::il::mcode::ssa::{
    MCodeSsaIr, MCodeSsaOp, MCodeSsaOpcode, MCodeSsaValue, MCodeSsaVersion,
};
use crate::il::mcode::{MCodeVarId, MCodeVarKind};

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum VerifyError {
    #[error("MCode SSA operation {operation} references a variable inconsistent with its aliasing")]
    AliasedVariableMismatch { operation: u32 },
    #[error("MCode SSA block {block} argument count mismatch: expected {expected}, found {found}")]
    BlockArgumentCount {
        block: u32,
        expected: usize,
        found: usize,
    },
    #[error("MCode SSA operation has a duplicate memory domain")]
    DuplicateMemoryDomain,
    #[error("MCode SSA variable {variable} has a duplicate version")]
    DuplicateVersion { variable: u32 },
    #[error("MCode SSA operation {operation} accesses a field outside its variable")]
    FieldOutOfBounds { operation: u32 },
    #[error(transparent)]
    Il(#[from] IlError),
    #[error("MCode SSA value {value} has an inconsistent variable binding")]
    InconsistentBinding { value: u32 },
    #[error("MCode SSA call operation {operation} is malformed")]
    InvalidCall { operation: u32 },
    #[error(
        "MCode SSA operation {operation} has an invalid operand count: expected {expected}, found {found}"
    )]
    InvalidOperandCount {
        operation: u32,
        expected: usize,
        found: usize,
    },
    #[error("MCode SSA operation {operation} has invalid block placement")]
    InvalidOperationPlacement { operation: u32 },
    #[error(
        "MCode SSA operation {operation} has an invalid result count: expected {expected}, found {found}"
    )]
    InvalidResultCount {
        operation: u32,
        expected: usize,
        found: usize,
    },
    #[error("MCode SSA split operation {operation} is malformed")]
    InvalidSplit { operation: u32 },
    #[error("MCode SSA value has an invalid definition")]
    InvalidValueDefinition,
    #[error(
        "MCode SSA variable {variable} has an invalid version: expected {expected}, found {found}"
    )]
    InvalidVersion {
        variable: u32,
        expected: u32,
        found: u32,
    },
    #[error("MCode SSA aliased variable set is malformed")]
    MalformedAliasSet,
    #[error("MCode SSA operation {operation} is missing a required variable")]
    MissingVariable { operation: u32 },
    #[error(
        "MCode SSA value {value} does not dominate edge from block {predecessor} to block {successor}"
    )]
    NonDominatingEdgeArgument {
        value: u32,
        predecessor: u32,
        successor: u32,
    },
    #[error("MCode SSA value {value} does not dominate use by operation {user}")]
    NonDominatingUse { value: u32, user: u32 },
    #[error(transparent)]
    Structure(StructureError),
    #[error("MCode SSA operation {operation} carries an unexpected variable")]
    UnexpectedVariable { operation: u32 },
    #[error("MCode SSA operation references unknown variable {variable}")]
    UnknownVariable { variable: u32 },
}

impl VerifyError {
    const fn aliased_variable_mismatch(operation: IlOpId) -> Self {
        Self::AliasedVariableMismatch {
            operation: operation.value(),
        }
    }

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

    const fn duplicate_version(variable: MCodeVarId) -> Self {
        Self::DuplicateVersion {
            variable: variable.value(),
        }
    }

    const fn field_out_of_bounds(operation: IlOpId) -> Self {
        Self::FieldOutOfBounds {
            operation: operation.value(),
        }
    }

    const fn inconsistent_binding(value: IlValueId) -> Self {
        Self::InconsistentBinding {
            value: value.value(),
        }
    }

    const fn invalid_call(operation: IlOpId) -> Self {
        Self::InvalidCall {
            operation: operation.value(),
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

    const fn invalid_split(operation: IlOpId) -> Self {
        Self::InvalidSplit {
            operation: operation.value(),
        }
    }

    const fn invalid_value_definition() -> Self {
        Self::InvalidValueDefinition
    }

    const fn invalid_version(
        variable: MCodeVarId,
        expected: MCodeSsaVersion,
        found: MCodeSsaVersion,
    ) -> Self {
        Self::InvalidVersion {
            variable: variable.value(),
            expected: expected.value(),
            found: found.value(),
        }
    }

    const fn missing_variable(operation: IlOpId) -> Self {
        Self::MissingVariable {
            operation: operation.value(),
        }
    }

    const fn malformed_alias_set() -> Self {
        Self::MalformedAliasSet
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

    const fn unexpected_variable(operation: IlOpId) -> Self {
        Self::UnexpectedVariable {
            operation: operation.value(),
        }
    }

    const fn unknown_variable(variable: MCodeVarId) -> Self {
        Self::UnknownVariable {
            variable: variable.value(),
        }
    }
}

impl StructureVerifierError for VerifyError {
    fn structure(error: StructureError) -> Self {
        Self::Structure(error)
    }
}

impl MCodeSsaIr {
    pub(crate) fn verify(&self) -> Result<(), VerifyError> {
        self.verify_structure::<VerifyError>(
            self.source_spans(),
            Some(self.parent_spans()),
            self.operations().len(),
        )?;
        self.verify_memory_domains()?;
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
            self.verify_operation_shape(operation_id, operation)?;

            for result_index in operation.results().start()..operation.results().end() {
                let value = self.values()[result_index];

                if value.definition() != IlSsaDef::Operation(operation_id) {
                    return Err(VerifyError::invalid_value_definition());
                }
            }

            if operation.opcode() == MCodeSsaOpcode::Constant && operation.width() > 64 {
                let bytes = usize::try_from(operation.width().div_ceil(8))
                    .map_err(|_| IlError::integer_overflow("MCode SSA constant width"))?;
                let start = usize::try_from(operation.immediate())
                    .map_err(|_| IlError::integer_overflow("MCode SSA constant offset"))?;
                let end = start.saturating_add(bytes);
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
                    return Err(IlError::width_mismatch(MCodeSsaIr::FORM).into());
                }
            }

            if operation.opcode().requires_memory_domain() {
                let Some(address_space) = operation.address_space() else {
                    return Err(
                        IlError::missing_component(MCodeSsaIr::FORM, "memory domain").into(),
                    );
                };

                if self.memory_domain(address_space).is_none() {
                    return Err(
                        IlError::missing_component(MCodeSsaIr::FORM, "memory domain").into(),
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

        let variable_widths = self.verify_bindings()?;
        self.verify_variables(&variable_widths)?;
        self.verify_terminators()?;
        self.verify_dominating_uses()?;

        Ok(())
    }

    fn verify_bindings(&self) -> Result<FxHashMap<MCodeVarId, u32>, VerifyError> {
        let mut widths = FxHashMap::default();
        let mut versions = FxHashMap::<MCodeVarId, Vec<MCodeSsaVersion>>::default();
        for (index, value) in self.values().iter().enumerate() {
            let value_id = IlValueId::try_from_index(index)?;
            let Some(variable) = value.variable() else {
                if value.version() != MCodeSsaVersion::new(0) {
                    return Err(VerifyError::inconsistent_binding(value_id));
                }
                continue;
            };
            if self.variable(variable).is_none() {
                return Err(VerifyError::unknown_variable(variable));
            }
            if value.version() == MCodeSsaVersion::new(0) {
                return Err(VerifyError::invalid_version(
                    variable,
                    MCodeSsaVersion::new(1),
                    MCodeSsaVersion::new(0),
                ));
            }
            versions.entry(variable).or_default().push(value.version());
            let width = *widths.entry(variable).or_insert(value.width());
            if width != value.width() {
                return Err(IlError::width_mismatch(MCodeSsaIr::FORM).into());
            }
            self.verify_binding_definition(value_id, value)?;
        }

        for (variable, versions) in &mut versions {
            versions.sort_unstable();
            for (index, &found) in versions.iter().enumerate() {
                let expected = MCodeSsaVersion::new(
                    u32::try_from(index + 1)
                        .map_err(|_| IlError::id_exhausted("MCode SSA version"))?,
                );
                if found < expected {
                    return Err(VerifyError::duplicate_version(*variable));
                }
                if found != expected {
                    return Err(VerifyError::invalid_version(*variable, expected, found));
                }
            }
        }

        Ok(widths)
    }

    fn verify_binding_definition(
        &self,
        value_id: IlValueId,
        value: &MCodeSsaValue,
    ) -> Result<(), VerifyError> {
        let IlSsaDef::Operation(operation_id) = value.definition() else {
            return Ok(());
        };
        let operation_index = operation_id.index();
        let operation = self
            .operations()
            .get(operation_index)
            .ok_or_else(VerifyError::invalid_value_definition)?;
        let result_index = value_id.index() - operation.results().start();
        let valid = match operation.opcode() {
            MCodeSsaOpcode::Constant | MCodeSsaOpcode::Undefined => true,
            MCodeSsaOpcode::SetVar | MCodeSsaOpcode::SetVarField => {
                result_index == 0 && operation.variable() == value.variable()
            }
            MCodeSsaOpcode::SetVarAliased | MCodeSsaOpcode::SetVarAliasedField => {
                result_index == 1 && operation.variable() == value.variable()
            }
            MCodeSsaOpcode::Call | MCodeSsaOpcode::CallIndirect => result_index > 0,
            _ => false,
        };
        if !valid {
            return Err(VerifyError::inconsistent_binding(value_id));
        }

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

    fn verify_operation_shape(
        &self,
        operation_id: IlOpId,
        operation: &MCodeSsaOp,
    ) -> Result<(), VerifyError> {
        if let Some(expected) = operation.opcode().fixed_operand_count()
            && operation.operands().len() != expected
        {
            return Err(VerifyError::invalid_operand_count(
                operation_id,
                expected,
                operation.operands().len(),
            ));
        }
        if let Some(expected) = operation.opcode().fixed_result_count()
            && operation.results().len() != expected
        {
            return Err(VerifyError::invalid_result_count(
                operation_id,
                expected,
                operation.results().len(),
            ));
        }

        let minimum_operands = match operation.opcode() {
            MCodeSsaOpcode::Call | MCodeSsaOpcode::TailCall => Some(1),
            MCodeSsaOpcode::CallIndirect | MCodeSsaOpcode::TailCallIndirect => Some(2),
            _ => None,
        };
        if minimum_operands.is_some_and(|minimum| operation.operands().len() < minimum) {
            return Err(VerifyError::invalid_call(operation_id));
        }
        if matches!(
            operation.opcode(),
            MCodeSsaOpcode::Call | MCodeSsaOpcode::CallIndirect
        ) && operation.results().is_empty()
        {
            return Err(VerifyError::invalid_call(operation_id));
        }

        if matches!(
            operation.opcode(),
            MCodeSsaOpcode::Branch
                | MCodeSsaOpcode::ConditionalBranch
                | MCodeSsaOpcode::Call
                | MCodeSsaOpcode::TailCall
        ) && operation.address().is_none()
        {
            return Err(IlError::missing_component(MCodeSsaIr::FORM, "address").into());
        }
        if matches!(
            operation.opcode(),
            MCodeSsaOpcode::BranchIndirect
                | MCodeSsaOpcode::CallIndirect
                | MCodeSsaOpcode::TailCallIndirect
        ) && operation.address_space().is_none()
        {
            return Err(IlError::missing_component(MCodeSsaIr::FORM, "address space").into());
        }

        for result_index in operation.results().start()..operation.results().end() {
            let result = self.values()[result_index];
            let offset = result_index - operation.results().start();
            let expected_width = match operation.opcode() {
                MCodeSsaOpcode::Store => Some(0),
                MCodeSsaOpcode::SetVarAliased | MCodeSsaOpcode::SetVarAliasedField
                    if offset == 0 =>
                {
                    Some(0)
                }
                MCodeSsaOpcode::SetVarField => None,
                MCodeSsaOpcode::SetVarAliasedField if offset == 1 => None,
                MCodeSsaOpcode::Call | MCodeSsaOpcode::CallIndirect if offset == 0 => Some(0),
                MCodeSsaOpcode::Call | MCodeSsaOpcode::CallIndirect => None,
                _ => Some(operation.width()),
            };
            if expected_width.is_some_and(|width| result.width() != width) {
                return Err(IlError::width_mismatch(MCodeSsaIr::FORM).into());
            }
        }

        Ok(())
    }

    fn verify_memory_operation(
        &self,
        operation_id: IlOpId,
        operation: &MCodeSsaOp,
    ) -> Result<(), VerifyError> {
        if matches!(
            operation.opcode(),
            MCodeSsaOpcode::Load | MCodeSsaOpcode::Store
        ) && self.pointer_operand(operation).is_none()
        {
            return Err(IlError::missing_component(MCodeSsaIr::FORM, "pointer").into());
        }

        let Some(memory) = self.memory_operand(operation) else {
            return Err(IlError::missing_component(MCodeSsaIr::FORM, "memory domain").into());
        };
        if self.values()[memory.index()].width() != 0 {
            return Err(IlError::width_mismatch(MCodeSsaIr::FORM).into());
        }

        if matches!(
            operation.opcode(),
            MCodeSsaOpcode::Store
                | MCodeSsaOpcode::SetVarAliased
                | MCodeSsaOpcode::SetVarAliasedField
                | MCodeSsaOpcode::Call
                | MCodeSsaOpcode::CallIndirect
        ) {
            if operation.results().is_empty() {
                return Err(VerifyError::invalid_result_count(operation_id, 1, 0));
            }

            let result = self.values()[operation.results().start()];

            if result.width() != 0 {
                return Err(IlError::width_mismatch(MCodeSsaIr::FORM).into());
            }
        }

        Ok(())
    }

    fn verify_variables(
        &self,
        variable_widths: &FxHashMap<MCodeVarId, u32>,
    ) -> Result<(), VerifyError> {
        let mut previous = None;
        for id in self.aliased_variables() {
            let variable = self
                .variable(*id)
                .ok_or_else(|| VerifyError::unknown_variable(*id))?;
            if variable.kind() != MCodeVarKind::Stack {
                return Err(VerifyError::malformed_alias_set());
            }
            if previous.is_some_and(|prior| prior >= *id) {
                return Err(VerifyError::malformed_alias_set());
            }
            previous = Some(*id);
        }

        for (operation_index, operation) in self.operations().iter().enumerate() {
            let operation_id = IlOpId::try_from_index(operation_index)?;
            let opcode = operation.opcode();

            match operation.variable() {
                Some(variable) => {
                    if !opcode.requires_variable() {
                        return Err(VerifyError::unexpected_variable(operation_id));
                    }
                    if self.variable(variable).is_none() {
                        return Err(VerifyError::unknown_variable(variable));
                    }
                    if Self::opcode_expects_aliased(opcode) != self.is_aliased(variable) {
                        return Err(VerifyError::aliased_variable_mismatch(operation_id));
                    }
                }
                None => {
                    if opcode.requires_variable() {
                        return Err(VerifyError::missing_variable(operation_id));
                    }
                }
            }

            self.verify_operation_bindings(operation)?;
            self.verify_variable_widths(operation, variable_widths)?;

            match opcode {
                MCodeSsaOpcode::VarSplit => self.verify_split(operation_id, operation)?,
                MCodeSsaOpcode::AddressOfField
                | MCodeSsaOpcode::SetVarField
                | MCodeSsaOpcode::SetVarAliasedField
                | MCodeSsaOpcode::VarAliasedField => {
                    self.verify_field(operation_id, operation, variable_widths)?;
                }
                MCodeSsaOpcode::Call | MCodeSsaOpcode::CallIndirect => {
                    self.verify_call_outputs(operation_id, operation)?;
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn verify_variable_widths(
        &self,
        operation: &MCodeSsaOp,
        variable_widths: &FxHashMap<MCodeVarId, u32>,
    ) -> Result<(), VerifyError> {
        let Some(variable) = operation.variable() else {
            return Ok(());
        };
        let width = variable_widths.get(&variable).copied().unwrap_or(0);
        let operands = self.operation_operands_for(operation);
        let matches = match operation.opcode() {
            MCodeSsaOpcode::SetVar | MCodeSsaOpcode::SetVarAliased => {
                operation.width() == width && self.values()[operands[0].index()].width() == width
            }
            MCodeSsaOpcode::VarAliased => operation.width() == width,
            _ => true,
        };
        if !matches {
            return Err(IlError::width_mismatch(MCodeSsaIr::FORM).into());
        }

        Ok(())
    }

    fn verify_operation_bindings(&self, operation: &MCodeSsaOp) -> Result<(), VerifyError> {
        for result_index in operation.results().start()..operation.results().end() {
            let result = self.values()[result_index];
            let offset = result_index - operation.results().start();
            let expected = match operation.opcode() {
                MCodeSsaOpcode::Constant | MCodeSsaOpcode::Undefined => result.variable(),
                MCodeSsaOpcode::SetVar | MCodeSsaOpcode::SetVarField => operation.variable(),
                MCodeSsaOpcode::SetVarAliased | MCodeSsaOpcode::SetVarAliasedField
                    if offset == 1 =>
                {
                    operation.variable()
                }
                MCodeSsaOpcode::Call | MCodeSsaOpcode::CallIndirect if offset > 0 => {
                    result.variable()
                }
                _ => None,
            };
            if result.variable() != expected || (offset > 0 && expected.is_none()) {
                let value_id = IlValueId::try_from_index(result_index)?;
                return Err(VerifyError::inconsistent_binding(value_id));
            }
        }

        Ok(())
    }

    const fn opcode_expects_aliased(opcode: MCodeSsaOpcode) -> bool {
        matches!(
            opcode,
            MCodeSsaOpcode::AddressOf
                | MCodeSsaOpcode::AddressOfField
                | MCodeSsaOpcode::SetVarAliased
                | MCodeSsaOpcode::SetVarAliasedField
                | MCodeSsaOpcode::VarAliased
                | MCodeSsaOpcode::VarAliasedField
        )
    }

    fn verify_split(
        &self,
        operation_id: IlOpId,
        operation: &MCodeSsaOp,
    ) -> Result<(), VerifyError> {
        let operands = self.operation_operands_for(operation);
        if operands.len() != 2 || operation.results().len() != 1 {
            return Err(VerifyError::invalid_split(operation_id));
        }

        let combined = self.values()[operation.results().start()].width();
        let high = self.values()[operands[0].index()].width();
        let low = self.values()[operands[1].index()].width();
        if high.checked_add(low) != Some(combined) {
            return Err(VerifyError::invalid_split(operation_id));
        }

        Ok(())
    }

    fn verify_field(
        &self,
        operation_id: IlOpId,
        operation: &MCodeSsaOp,
        variable_widths: &FxHashMap<MCodeVarId, u32>,
    ) -> Result<(), VerifyError> {
        let variable = operation
            .variable()
            .expect("field operation has been checked for a variable");
        if operation.opcode() == MCodeSsaOpcode::SetVarField {
            let previous_id = self.operation_operands_for(operation)[0];
            let previous = self.values()[previous_id.index()];
            let result_id = IlValueId::try_from_index(operation.results().start())?;
            let result = self.values()[result_id.index()];

            if previous.variable() != Some(variable)
                || previous.version().checked_next() != Some(result.version())
            {
                return Err(VerifyError::inconsistent_binding(result_id));
            }
        }

        let width = variable_widths.get(&variable).copied().unwrap_or(0);
        let operands = self.operation_operands_for(operation);
        let widths_match = match operation.opcode() {
            MCodeSsaOpcode::SetVarField => {
                self.values()[operands[0].index()].width() == width
                    && self.values()[operands[1].index()].width() == operation.width()
                    && self.values()[operation.results().start()].width() == width
            }
            MCodeSsaOpcode::SetVarAliasedField => {
                self.values()[operands[0].index()].width() == operation.width()
                    && self.values()[operation.results().start() + 1].width() == width
            }
            _ => true,
        };
        if !widths_match {
            return Err(IlError::width_mismatch(MCodeSsaIr::FORM).into());
        }

        let in_bounds = if operation.opcode() == MCodeSsaOpcode::AddressOfField {
            operation.immediate() < u64::from(width)
        } else {
            operation
                .immediate()
                .checked_add(u64::from(operation.width()))
                .is_some_and(|end| end <= u64::from(width))
        };
        if !in_bounds {
            return Err(VerifyError::field_out_of_bounds(operation_id));
        }

        Ok(())
    }

    fn verify_call_outputs(
        &self,
        operation_id: IlOpId,
        operation: &MCodeSsaOp,
    ) -> Result<(), VerifyError> {
        for result_index in (operation.results().start() + 1)..operation.results().end() {
            if self.values()[result_index].variable().is_none() {
                return Err(VerifyError::invalid_call(operation_id));
            }
        }

        Ok(())
    }

    fn verify_terminators(&self) -> Result<(), VerifyError> {
        if self.graph().blocks().is_empty() {
            for (operation_index, operation) in self.operations().iter().enumerate() {
                if operation.opcode().is_terminator()
                    && operation_index + 1 != self.operations().len()
                {
                    let operation_id = IlOpId::try_from_index(operation_index)?;
                    return Err(VerifyError::invalid_operation_placement(operation_id));
                }
            }
            return Ok(());
        }

        for (block_index, block) in self.graph().blocks().iter().enumerate() {
            let block_id = IlBlockId::try_from_index(block_index)?;
            for operation_index in block.operations().start()..block.operations().end() {
                let operation = self.operations()[operation_index];
                if operation.opcode().is_terminator()
                    && operation_index + 1 != block.operations().end()
                {
                    let operation_id = IlOpId::try_from_index(operation_index)?;
                    return Err(VerifyError::invalid_operation_placement(operation_id));
                }
            }
            self.verify_edge_kinds(block, block_id)?;
        }

        Ok(())
    }

    fn verify_edge_kinds(&self, block: &IlBlock, block_id: IlBlockId) -> Result<(), VerifyError> {
        let terminator = (!block.operations().is_empty())
            .then(|| block.operations().end() - 1)
            .and_then(|index| self.operations().get(index))
            .map(MCodeSsaOp::opcode);
        let permitted = match terminator {
            Some(MCodeSsaOpcode::Branch) => IlEdgeKinds::UNCONDITIONAL,
            Some(MCodeSsaOpcode::BranchIndirect | MCodeSsaOpcode::Switch) => IlEdgeKinds::COMPUTED,
            Some(MCodeSsaOpcode::ConditionalBranch) => {
                IlEdgeKinds::FALL_THROUGH | IlEdgeKinds::TAKEN
            }
            Some(
                MCodeSsaOpcode::Return
                | MCodeSsaOpcode::TailCall
                | MCodeSsaOpcode::TailCallIndirect
                | MCodeSsaOpcode::Trap,
            ) => IlEdgeKinds::empty(),
            _ => IlEdgeKinds::FALL_THROUGH | IlEdgeKinds::UNCONDITIONAL,
        };

        let kinds = block.successors().slice(self.graph().successor_kinds());
        let start = u32::try_from(block.successors().start()).unwrap_or(u32::MAX);
        let mut covered = IlEdgeKinds::empty();
        for (edge, kinds) in kinds.iter().enumerate() {
            let repeated = covered.intersects(*kinds & IlEdgeKinds::SINGULAR);
            if !kinds.is_empty() && permitted.contains(*kinds) && !repeated {
                covered |= *kinds;
                continue;
            }
            return Err(VerifyError::Structure(StructureError::EdgeKindMismatch {
                block: block_id.value(),
                edge: start.saturating_add(u32::try_from(edge).unwrap_or(u32::MAX)),
                kinds: *kinds,
            }));
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
        operation: &MCodeSsaOp,
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
                    let destination = self.values()[argument.value().index()];

                    if incoming.width() != argument.width() {
                        return Err(IlError::width_mismatch(MCodeSsaIr::FORM).into());
                    }
                    if incoming.variable() != destination.variable() {
                        return Err(VerifyError::inconsistent_binding(argument.value()));
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
