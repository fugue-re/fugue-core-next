use rustc_hash::FxHashMap;
use thiserror::Error;

use crate::il::common::verify::{StructureError, StructureVerifierError};
use crate::il::common::{
    ControlFlowIl, IlArtefact, IlBlock, IlBlockArgId, IlBlockId, IlEdgeKinds, IlError, IlOpId,
    IlSsaDef, IlValueId, SsaVerifier, SsaVerifyError,
};
use crate::il::mcode::{
    MCodeIr, MCodeOp, MCodeOpcode, MCodeUses, MCodeValue, MCodeVarId, MCodeVarKind, MCodeVersion,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum VerifyError {
    #[error("MCode operation {operation} references a variable inconsistent with its aliasing")]
    AliasedVariableMismatch { operation: u32 },
    #[error("MCode block {block} argument count mismatch: expected {expected}, found {found}")]
    BlockArgCount {
        block: u32,
        expected: usize,
        found: usize,
    },
    #[error("MCode operation has a duplicate memory domain")]
    DuplicateMemoryDomain,
    #[error("MCode variable {variable} has a duplicate version")]
    DuplicateVersion { variable: u32 },
    #[error("MCode edge-argument table count mismatch: expected {expected}, found {found}")]
    EdgeArgTableCount { expected: usize, found: usize },
    #[error("MCode operation {operation} accesses a field outside its variable")]
    FieldOutOfBounds { operation: u32 },
    #[error(transparent)]
    Il(#[from] IlError),
    #[error("MCode value {value} has an inconsistent variable binding")]
    InconsistentBinding { value: u32 },
    #[error("MCode call operation {operation} is malformed")]
    InvalidCall { operation: u32 },
    #[error("MCode operation {operation} has invalid block placement")]
    InvalidOpPlacement { operation: u32 },
    #[error(
        "MCode operation {operation} has an invalid operand count: expected {expected}, found {found}"
    )]
    InvalidOperandCount {
        operation: u32,
        expected: usize,
        found: usize,
    },
    #[error(
        "MCode operation {operation} has an invalid result count: expected {expected}, found {found}"
    )]
    InvalidResultCount {
        operation: u32,
        expected: usize,
        found: usize,
    },
    #[error("MCode split operation {operation} is malformed")]
    InvalidSplit { operation: u32 },
    #[error("MCode value has an invalid definition")]
    InvalidValueDef,
    #[error("MCode variable {variable} has an invalid version: expected {expected}, found {found}")]
    InvalidVersion {
        variable: u32,
        expected: u32,
        found: u32,
    },
    #[error("MCode aliased variable set is malformed")]
    MalformedAliasSet,
    #[error("MCode operation {operation} is missing a required variable")]
    MissingVariable { operation: u32 },
    #[error(
        "MCode value {value} does not dominate edge from block {predecessor} to block {successor}"
    )]
    NonDominatingEdgeArg {
        value: u32,
        predecessor: u32,
        successor: u32,
    },
    #[error("MCode value {value} does not dominate use by operation {user}")]
    NonDominatingUse { value: u32, user: u32 },
    #[error(transparent)]
    Structure(StructureError),
    #[error("MCode operation {operation} carries an unexpected variable")]
    UnexpectedVariable { operation: u32 },
    #[error("MCode operation references unknown variable {variable}")]
    UnknownVariable { variable: u32 },
}

impl VerifyError {
    const fn aliased_variable_mismatch(operation: IlOpId) -> Self {
        Self::AliasedVariableMismatch {
            operation: operation.value(),
        }
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

    const fn invalid_op_placement(operation: IlOpId) -> Self {
        Self::InvalidOpPlacement {
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
        Self::InvalidValueDef
    }

    const fn invalid_version(
        variable: MCodeVarId,
        expected: MCodeVersion,
        found: MCodeVersion,
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
            SsaVerifyError::InvalidOpPlacement { operation } => {
                Self::InvalidOpPlacement { operation }
            }
            SsaVerifyError::InvalidValueDef => Self::InvalidValueDef,
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

pub(crate) fn verify(ir: &MCodeIr) -> Result<(), VerifyError> {
    MCodeVerifier { ir }.verify()
}

struct MCodeVerifier<'a> {
    ir: &'a MCodeIr,
}

impl MCodeVerifier<'_> {
    fn verify(&self) -> Result<(), VerifyError> {
        self.ir.verify_structure::<VerifyError>(
            self.ir.source_spans(),
            Some(self.ir.parent_spans()),
            self.ir.ops().len(),
        )?;
        SsaVerifier::new(self.ir).verify_memory_domains()?;
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

        for (operation_index, operation) in self.ir.ops().iter().enumerate() {
            let operation_id = IlOpId::try_from_index(operation_index)?;
            operation.results().verify_bounds(self.ir.values().len())?;
            operation
                .operands()
                .verify_bounds(self.ir.op_operands().len())?;
            self.verify_op_shape(operation_id, operation)?;

            for result_index in operation.results().start()..operation.results().end() {
                let value = self.ir.values()[result_index];

                if value.definition() != IlSsaDef::Op(operation_id) {
                    return Err(VerifyError::invalid_value_definition());
                }
            }

            if operation.opcode() == MCodeOpcode::Constant && operation.width() > 64 {
                let bytes = usize::try_from(operation.width().div_ceil(8))
                    .map_err(|_| IlError::integer_overflow("MCode constant width"))?;
                let start = usize::try_from(operation.immediate())
                    .map_err(|_| IlError::integer_overflow("MCode constant offset"))?;
                let end = start.saturating_add(bytes);
                if end > self.ir.constant_storage().len() {
                    return Err(IlError::range_out_of_bounds(
                        end,
                        self.ir.constant_storage().len(),
                    )
                    .into());
                }
            }

            let uniform_operand_width = operation.opcode().has_uniform_operand_width();
            for operand in operation.operands().checked_slice(self.ir.op_operands())? {
                let value = self.ir.values().get(operand.index()).ok_or_else(|| {
                    IlError::range_out_of_bounds(operand.index(), self.ir.values().len())
                })?;

                if uniform_operand_width && value.width() != operation.width() {
                    return Err(IlError::width_mismatch(MCodeIr::FORM).into());
                }
            }

            if operation.opcode().requires_memory_domain() {
                let Some(address_space) = operation.address_space() else {
                    return Err(IlError::missing_component(MCodeIr::FORM, "memory domain").into());
                };

                if self.ir.memory_domain(address_space).is_none() {
                    return Err(IlError::missing_component(MCodeIr::FORM, "memory domain").into());
                }

                self.verify_memory_op(operation_id, operation)?;
            }
        }

        for (value_index, value) in self.ir.values().iter().enumerate() {
            let value_id = IlValueId::try_from_index(value_index)?;

            match value.definition() {
                IlSsaDef::Op(operation) => {
                    let Some(operation) = self.ir.ops().get(operation.index()) else {
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

        let variable_widths = self.verify_bindings()?;
        self.verify_variables(&variable_widths)?;
        self.verify_terminators()?;
        SsaVerifier::new(self.ir).verify_uses(|incoming, destination| {
            if self.ir.binding(incoming).map(|binding| binding.variable())
                != self
                    .ir
                    .binding(destination)
                    .map(|binding| binding.variable())
            {
                return Err(VerifyError::inconsistent_binding(destination));
            }
            Ok(())
        })?;

        Ok(())
    }

    fn verify_bindings(&self) -> Result<FxHashMap<MCodeVarId, u32>, VerifyError> {
        let mut widths = FxHashMap::default();
        let mut versions = FxHashMap::<MCodeVarId, Vec<MCodeVersion>>::default();
        for (index, value) in self.ir.values().iter().enumerate() {
            let value_id = IlValueId::try_from_index(index)?;
            let Some(variable) = value.variable() else {
                if value.version() != MCodeVersion::new(0) {
                    return Err(VerifyError::inconsistent_binding(value_id));
                }
                continue;
            };
            if self.ir.variable(variable).is_none() {
                return Err(VerifyError::unknown_variable(variable));
            }
            if value.version() == MCodeVersion::new(0) {
                return Err(VerifyError::invalid_version(
                    variable,
                    MCodeVersion::new(1),
                    MCodeVersion::new(0),
                ));
            }
            versions.entry(variable).or_default().push(value.version());
            let width = *widths.entry(variable).or_insert(value.width());
            if width != value.width() {
                return Err(IlError::width_mismatch(MCodeIr::FORM).into());
            }
            self.verify_binding_definition(value_id, value)?;
        }

        for (variable, versions) in &mut versions {
            versions.sort_unstable();
            for (index, &found) in versions.iter().enumerate() {
                let expected = MCodeVersion::new(
                    u32::try_from(index + 1).map_err(|_| IlError::id_exhausted("MCode version"))?,
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
        value: &MCodeValue,
    ) -> Result<(), VerifyError> {
        let IlSsaDef::Op(operation_id) = value.definition() else {
            return Ok(());
        };
        let operation_index = operation_id.index();
        let operation = self
            .ir
            .ops()
            .get(operation_index)
            .ok_or_else(VerifyError::invalid_value_definition)?;
        let result_index = value_id.index() - operation.results().start();
        let valid = match operation.opcode() {
            MCodeOpcode::Constant | MCodeOpcode::Undefined => true,
            MCodeOpcode::SetVar | MCodeOpcode::SetVarField => {
                result_index == 0 && operation.variable() == value.variable()
            }
            MCodeOpcode::SetVarAliased | MCodeOpcode::SetVarAliasedField => {
                result_index == 1 && operation.variable() == value.variable()
            }
            MCodeOpcode::Call | MCodeOpcode::CallIndirect => result_index > 0,
            _ => false,
        };
        if !valid {
            return Err(VerifyError::inconsistent_binding(value_id));
        }

        Ok(())
    }

    fn verify_op_shape(
        &self,
        operation_id: IlOpId,
        operation: &MCodeOp,
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
            MCodeOpcode::Call | MCodeOpcode::TailCall => Some(1),
            MCodeOpcode::CallIndirect | MCodeOpcode::TailCallIndirect => Some(2),
            _ => None,
        };
        if minimum_operands.is_some_and(|minimum| operation.operands().len() < minimum) {
            return Err(VerifyError::invalid_call(operation_id));
        }
        if matches!(
            operation.opcode(),
            MCodeOpcode::Call | MCodeOpcode::CallIndirect
        ) && operation.results().is_empty()
        {
            return Err(VerifyError::invalid_call(operation_id));
        }

        if matches!(
            operation.opcode(),
            MCodeOpcode::Branch
                | MCodeOpcode::ConditionalBranch
                | MCodeOpcode::Call
                | MCodeOpcode::TailCall
        ) && operation.address().is_none()
        {
            return Err(IlError::missing_component(MCodeIr::FORM, "address").into());
        }
        if matches!(
            operation.opcode(),
            MCodeOpcode::BranchIndirect | MCodeOpcode::CallIndirect | MCodeOpcode::TailCallIndirect
        ) && operation.address_space().is_none()
        {
            return Err(IlError::missing_component(MCodeIr::FORM, "address space").into());
        }

        for result_index in operation.results().start()..operation.results().end() {
            let result = self.ir.values()[result_index];
            let offset = result_index - operation.results().start();
            let expected_width = match operation.opcode() {
                MCodeOpcode::Store => Some(0),
                MCodeOpcode::SetVarAliased | MCodeOpcode::SetVarAliasedField if offset == 0 => {
                    Some(0)
                }
                MCodeOpcode::SetVarField => None,
                MCodeOpcode::SetVarAliasedField if offset == 1 => None,
                MCodeOpcode::Call | MCodeOpcode::CallIndirect if offset == 0 => Some(0),
                MCodeOpcode::Call | MCodeOpcode::CallIndirect => None,
                _ => Some(operation.width()),
            };
            if expected_width.is_some_and(|width| result.width() != width) {
                return Err(IlError::width_mismatch(MCodeIr::FORM).into());
            }
        }

        Ok(())
    }

    fn verify_memory_op(
        &self,
        operation_id: IlOpId,
        operation: &MCodeOp,
    ) -> Result<(), VerifyError> {
        if matches!(operation.opcode(), MCodeOpcode::Load | MCodeOpcode::Store)
            && self.ir.pointer_operand(operation).is_none()
        {
            return Err(IlError::missing_component(MCodeIr::FORM, "pointer").into());
        }

        let Some(memory) = self.ir.memory_operand(operation) else {
            return Err(IlError::missing_component(MCodeIr::FORM, "memory domain").into());
        };
        if self.ir.values()[memory.index()].width() != 0 {
            return Err(IlError::width_mismatch(MCodeIr::FORM).into());
        }

        if matches!(
            operation.opcode(),
            MCodeOpcode::Store
                | MCodeOpcode::SetVarAliased
                | MCodeOpcode::SetVarAliasedField
                | MCodeOpcode::Call
                | MCodeOpcode::CallIndirect
        ) {
            if operation.results().is_empty() {
                return Err(VerifyError::invalid_result_count(operation_id, 1, 0));
            }

            let result = self.ir.values()[operation.results().start()];

            if result.width() != 0 {
                return Err(IlError::width_mismatch(MCodeIr::FORM).into());
            }
        }

        Ok(())
    }

    fn verify_variables(
        &self,
        variable_widths: &FxHashMap<MCodeVarId, u32>,
    ) -> Result<(), VerifyError> {
        let uses = self.ir.analyse::<MCodeUses>();
        let mut previous = None;
        for id in self.ir.aliased_variables() {
            let variable = self
                .ir
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

        for (operation_index, operation) in self.ir.ops().iter().enumerate() {
            let operation_id = IlOpId::try_from_index(operation_index)?;
            let opcode = operation.opcode();

            match operation.variable() {
                Some(variable) => {
                    if !opcode.requires_variable() {
                        return Err(VerifyError::unexpected_variable(operation_id));
                    }
                    if self.ir.variable(variable).is_none() {
                        return Err(VerifyError::unknown_variable(variable));
                    }
                    if opcode.expects_aliased_variable() != self.ir.is_aliased(variable) {
                        return Err(VerifyError::aliased_variable_mismatch(operation_id));
                    }
                }
                None => {
                    if opcode.requires_variable() {
                        return Err(VerifyError::missing_variable(operation_id));
                    }
                }
            }

            self.verify_op_bindings(operation)?;
            self.verify_variable_widths(operation, variable_widths)?;

            match opcode {
                MCodeOpcode::VarSplit => self.verify_split(operation_id, operation)?,
                MCodeOpcode::AddressOfField
                | MCodeOpcode::SetVarField
                | MCodeOpcode::SetVarAliasedField
                | MCodeOpcode::VarAliasedField => {
                    self.verify_field(operation_id, operation, variable_widths)?;
                }
                MCodeOpcode::Call | MCodeOpcode::CallIndirect => {
                    self.verify_call_outputs(operation_id, operation, &uses)?;
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn verify_variable_widths(
        &self,
        operation: &MCodeOp,
        variable_widths: &FxHashMap<MCodeVarId, u32>,
    ) -> Result<(), VerifyError> {
        let Some(variable) = operation.variable() else {
            return Ok(());
        };
        let width = variable_widths.get(&variable).copied().unwrap_or(0);
        let operands = self.ir.op_operands_for(operation);
        let matches = match operation.opcode() {
            MCodeOpcode::SetVar | MCodeOpcode::SetVarAliased => {
                operation.width() == width && self.ir.values()[operands[0].index()].width() == width
            }
            MCodeOpcode::VarAliased => operation.width() == width,
            _ => true,
        };
        if !matches {
            return Err(IlError::width_mismatch(MCodeIr::FORM).into());
        }

        Ok(())
    }

    fn verify_op_bindings(&self, operation: &MCodeOp) -> Result<(), VerifyError> {
        for result_index in operation.results().start()..operation.results().end() {
            let result = self.ir.values()[result_index];
            let offset = result_index - operation.results().start();
            let expected = match operation.opcode() {
                MCodeOpcode::Constant | MCodeOpcode::Undefined => result.variable(),
                MCodeOpcode::SetVar | MCodeOpcode::SetVarField => operation.variable(),
                MCodeOpcode::SetVarAliased | MCodeOpcode::SetVarAliasedField if offset == 1 => {
                    operation.variable()
                }
                MCodeOpcode::Call | MCodeOpcode::CallIndirect if offset > 0 => result.variable(),
                _ => None,
            };
            let binding_required = offset > 0
                && !matches!(
                    operation.opcode(),
                    MCodeOpcode::Call | MCodeOpcode::CallIndirect
                );
            if result.variable() != expected || (binding_required && expected.is_none()) {
                let value_id = IlValueId::try_from_index(result_index)?;
                return Err(VerifyError::inconsistent_binding(value_id));
            }
        }

        Ok(())
    }

    fn verify_split(&self, operation_id: IlOpId, operation: &MCodeOp) -> Result<(), VerifyError> {
        let operands = self.ir.op_operands_for(operation);
        if operands.len() != 2 || operation.results().len() != 1 {
            return Err(VerifyError::invalid_split(operation_id));
        }

        let combined = self.ir.values()[operation.results().start()].width();
        let high = self.ir.values()[operands[0].index()].width();
        let low = self.ir.values()[operands[1].index()].width();
        if high.checked_add(low) != Some(combined) {
            return Err(VerifyError::invalid_split(operation_id));
        }

        Ok(())
    }

    fn verify_field(
        &self,
        operation_id: IlOpId,
        operation: &MCodeOp,
        variable_widths: &FxHashMap<MCodeVarId, u32>,
    ) -> Result<(), VerifyError> {
        let variable = operation
            .variable()
            .expect("field operation has been checked for a variable");
        if operation.opcode() == MCodeOpcode::SetVarField {
            let previous_id = self.ir.op_operands_for(operation)[0];
            let previous = self.ir.values()[previous_id.index()];
            let result_id = IlValueId::try_from_index(operation.results().start())?;
            let result = self.ir.values()[result_id.index()];

            if previous.variable() != Some(variable)
                || previous.version().checked_next() != Some(result.version())
            {
                return Err(VerifyError::inconsistent_binding(result_id));
            }
        }

        let width = variable_widths.get(&variable).copied().unwrap_or(0);
        let operands = self.ir.op_operands_for(operation);
        let widths_match = match operation.opcode() {
            MCodeOpcode::SetVarField => {
                self.ir.values()[operands[0].index()].width() == width
                    && self.ir.values()[operands[1].index()].width() == operation.width()
                    && self.ir.values()[operation.results().start()].width() == width
            }
            MCodeOpcode::SetVarAliasedField => {
                self.ir.values()[operands[0].index()].width() == operation.width()
                    && self.ir.values()[operation.results().start() + 1].width() == width
            }
            _ => true,
        };
        if !widths_match {
            return Err(IlError::width_mismatch(MCodeIr::FORM).into());
        }

        let in_bounds = if operation.opcode() == MCodeOpcode::AddressOfField {
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
        operation: &MCodeOp,
        uses: &MCodeUses,
    ) -> Result<(), VerifyError> {
        for result_index in (operation.results().start() + 1)..operation.results().end() {
            let result = self.ir.values()[result_index];
            if result.variable().is_some() {
                continue;
            }
            let value = IlValueId::try_from_index(result_index)?;
            let materialised = !uses.uses_for(value).is_empty()
                && uses.uses_for(value).iter().all(|usage| {
                    let user = &self.ir.ops()[usage.user().index()];
                    match user.opcode() {
                        MCodeOpcode::SetVarAliased | MCodeOpcode::SetVarAliasedField => {
                            usage.operand_index() == 0
                        }
                        MCodeOpcode::SetVarField => usage.operand_index() == 1,
                        MCodeOpcode::Insert if usage.operand_index() == 1 => {
                            let operands = self.ir.op_operands_for(user);
                            self.ir.values()[operands[0].index()].width() == user.width()
                                && self.ir.values()[user.results().start()].width() == user.width()
                                && user
                                    .immediate()
                                    .checked_add(u64::from(result.width()))
                                    .is_some_and(|end| end <= u64::from(user.width()))
                        }
                        _ => false,
                    }
                });
            if !materialised {
                return Err(VerifyError::invalid_call(operation_id));
            }
        }

        Ok(())
    }

    fn verify_terminators(&self) -> Result<(), VerifyError> {
        if self.ir.graph().blocks().is_empty() {
            for (operation_index, operation) in self.ir.ops().iter().enumerate() {
                if operation.opcode().is_terminator() && operation_index + 1 != self.ir.ops().len()
                {
                    let operation_id = IlOpId::try_from_index(operation_index)?;
                    return Err(VerifyError::invalid_op_placement(operation_id));
                }
            }
            return Ok(());
        }

        for (block_index, block) in self.ir.graph().blocks().iter().enumerate() {
            let block_id = IlBlockId::try_from_index(block_index)?;
            for operation_index in block.ops().start()..block.ops().end() {
                let operation = self.ir.ops()[operation_index];
                if operation.opcode().is_terminator() && operation_index + 1 != block.ops().end() {
                    let operation_id = IlOpId::try_from_index(operation_index)?;
                    return Err(VerifyError::invalid_op_placement(operation_id));
                }
            }
            self.verify_edge_kinds(block, block_id)?;
        }

        Ok(())
    }

    fn verify_edge_kinds(&self, block: &IlBlock, block_id: IlBlockId) -> Result<(), VerifyError> {
        let terminator = (!block.ops().is_empty())
            .then(|| block.ops().end() - 1)
            .and_then(|index| self.ir.ops().get(index))
            .map(MCodeOp::opcode);
        let permitted = match terminator {
            Some(MCodeOpcode::Branch) => IlEdgeKinds::UNCONDITIONAL,
            Some(MCodeOpcode::BranchIndirect | MCodeOpcode::Switch) => IlEdgeKinds::COMPUTED,
            Some(MCodeOpcode::ConditionalBranch) => IlEdgeKinds::FALL_THROUGH | IlEdgeKinds::TAKEN,
            Some(
                MCodeOpcode::Return
                | MCodeOpcode::TailCall
                | MCodeOpcode::TailCallIndirect
                | MCodeOpcode::Trap,
            ) => IlEdgeKinds::empty(),
            _ => IlEdgeKinds::FALL_THROUGH | IlEdgeKinds::UNCONDITIONAL,
        };

        let kinds = block.successors().slice(self.ir.graph().successor_kinds());
        let start = block.successors().start();
        let mut covered = IlEdgeKinds::empty();
        for (edge, kinds) in kinds.iter().enumerate() {
            let repeated = covered.intersects(*kinds & IlEdgeKinds::SINGULAR);
            if !kinds.is_empty() && permitted.contains(*kinds) && !repeated {
                covered |= *kinds;
                continue;
            }
            return Err(VerifyError::Structure(StructureError::EdgeKindMismatch {
                block: block_id.value(),
                edge: start.saturating_add(edge),
                kinds: *kinds,
            }));
        }

        Ok(())
    }
}
