use std::collections::hash_map::Entry;
use std::{iter, mem};

use super::{MCodeCallOutputSite, MCodeSsaConstruction, MCodeSsaRenameState};
use crate::il::common::{IlArtefact, IlError, IlIndexRange, IlOpId, IlValueId, RegisterId};
use crate::il::ecode::ssa::{ECodeSsaDomain, ECodeSsaIr, ECodeSsaOp, ECodeSsaOpcode};
use crate::il::mcode::recovery::{MCodeCallArgument, MCodeStorageLocation};
use crate::il::mcode::ssa::{MCodeSsaIr, MCodeSsaOp, MCodeSsaOpcode};
use crate::il::mcode::{MCodeVar, MCodeVarId};
use crate::ir::Address;
use crate::storage::segments::space::AddressSpaceId;

impl MCodeSsaConstruction<'_, '_> {
    pub(super) fn build_operation_at(
        &mut self,
        index: usize,
        current: &mut MCodeSsaRenameState,
    ) -> Result<(), IlError> {
        let start = self.builder.operation_count();
        let site = IlOpId::try_from_index(index)?;
        let operation = self.source.operations()[index];

        match operation.opcode() {
            ECodeSsaOpcode::Call | ECodeSsaOpcode::CallIndirect => {
                self.build_call(site, operation, current)?;
            }
            ECodeSsaOpcode::Branch | ECodeSsaOpcode::BranchIndirect
                if self
                    .recovery
                    .abi()
                    .call(site)
                    .is_some_and(|call| call.is_tail_call()) =>
            {
                self.build_tail_call(site, operation, current)?;
            }
            ECodeSsaOpcode::Load if self.recovery.stack().access_for(site).is_some() => {
                self.build_stack_load(site, operation, current)?;
            }
            ECodeSsaOpcode::Store if self.recovery.stack().access_for(site).is_some() => {
                self.build_stack_store(site, operation, current)?;
            }
            ECodeSsaOpcode::Return => {
                self.build_carried(site, operation, current)?;
            }
            ECodeSsaOpcode::Undefined => self.build_undefined(site, operation, current)?,
            ECodeSsaOpcode::WriteFlag | ECodeSsaOpcode::WriteRegister => {
                self.build_variable_write(operation, current)?;
            }
            _ => self.build_carried(site, operation, current)?,
        }

        for &source in self.recovery.abi().exit_values(site) {
            self.scratch
                .required_values
                .push(self.source_value(source)?);
        }

        let end = self.builder.operation_count();
        self.operation_ranges[index] = IlIndexRange::new(start, end)?;

        Ok(())
    }

    pub(super) fn push_variable_undefined(
        &mut self,
        variable: MCodeVarId,
        width: u32,
    ) -> Result<IlValueId, IlError> {
        let results = self.emit(
            MCodeSsaOperationSpec::new(MCodeSsaOpcode::Undefined, width),
            [],
            [width],
        )?;
        let value = IlValueId::try_from_index(results.start())?;
        self.insert_binding(value, variable)?;

        Ok(value)
    }

    fn push_memory_undefined(&mut self, space: AddressSpaceId) -> Result<IlValueId, IlError> {
        self.builder.ensure_memory_domain(space);
        let immediate = u64::try_from(space.index())
            .map_err(|_| IlError::integer_overflow("address-space identifier"))?;
        let results = self.emit(
            MCodeSsaOperationSpec::new(MCodeSsaOpcode::Undefined, 0).with_immediate(immediate),
            [],
            [0],
        )?;

        IlValueId::try_from_index(results.start())
    }

    fn build_undefined(
        &mut self,
        site: IlOpId,
        operation: ECodeSsaOp,
        current: &mut MCodeSsaRenameState,
    ) -> Result<(), IlError> {
        let source = self.single_source_result(operation)?;
        let domain = self.source_domain(source);
        match domain {
            Some(ECodeSsaDomain::Memory(space)) if current.pending_memory.remove(&space) => {
                let value = current.memory.get(&space).copied().ok_or_else(|| {
                    IlError::missing_component(MCodeSsaIr::FORM, "post-call memory")
                })?;
                self.values[source.index()] = Some(value);
            }
            Some(ECodeSsaDomain::Register(root)) if current.pending_outputs.contains_key(&root) => {
                let value = current
                    .pending_outputs
                    .remove(&root)
                    .expect("the pending output was checked before removal");
                let variable = self.recovered_variable(source)?;
                self.insert_binding(value, variable)?;
                self.values[source.index()] = Some(value);
            }
            domain => {
                self.build_carried(site, operation, current)?;
                let value = self.source_value(source)?;
                match domain {
                    Some(ECodeSsaDomain::Memory(space)) => {
                        current.memory.insert(space, value);
                        current.pending_memory.remove(&space);
                    }
                    Some(domain) if domain.is_register_or_flag() => {
                        let variable = self.recovered_variable(source)?;
                        self.insert_binding(value, variable)?;
                        Self::clear_pending_output(current, Some(domain));
                    }
                    Some(_) | None => {}
                }
            }
        }
        Ok(())
    }

    fn build_variable_write(
        &mut self,
        operation: ECodeSsaOp,
        current: &mut MCodeSsaRenameState,
    ) -> Result<(), IlError> {
        let result = self.single_source_result(operation)?;
        let variable = self.recovered_variable(result)?;
        let source_operand = self
            .source
            .operation_operands_for(&operation)
            .first()
            .copied()
            .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "variable value"))?;

        let results = match self
            .source
            .defining_operation(source_operand)
            .filter(|insert| insert.opcode() == ECodeSsaOpcode::Insert)
        {
            Some(insert) => {
                let insert_operands = self.source.operation_operands_for(insert);
                let previous_source = insert_operands.first().copied().ok_or_else(|| {
                    IlError::missing_component(MCodeSsaIr::FORM, "partial variable")
                })?;
                let inserted_source = insert_operands.get(1).copied().ok_or_else(|| {
                    IlError::missing_component(MCodeSsaIr::FORM, "partial variable value")
                })?;
                let previous = self.source_value(previous_source)?;
                if self.bindings.variable_for(previous) != Some(variable)
                    || self.bindings.latest(variable) != Some(previous)
                {
                    let value = self.source_value(source_operand)?;
                    self.emit(
                        MCodeSsaOperationSpec::new(MCodeSsaOpcode::SetVar, operation.width())
                            .with_variable(variable),
                        [value],
                        [operation.width()],
                    )?
                } else {
                    let inserted = self.source_value(inserted_source)?;
                    let width = self.source.value_width(inserted_source).ok_or_else(|| {
                        IlError::missing_component(MCodeSsaIr::FORM, "partial variable width")
                    })?;
                    self.emit(
                        MCodeSsaOperationSpec::new(MCodeSsaOpcode::SetVarField, width)
                            .with_variable(variable)
                            .with_immediate(insert.immediate()),
                        [previous, inserted],
                        [operation.width()],
                    )?
                }
            }
            None => {
                let value = self.source_value(source_operand)?;
                self.emit(
                    MCodeSsaOperationSpec::new(MCodeSsaOpcode::SetVar, operation.width())
                        .with_variable(variable),
                    [value],
                    [operation.width()],
                )?
            }
        };
        let value = IlValueId::try_from_index(results.start())?;
        self.insert_binding(value, variable)?;
        self.values[result.index()] = Some(value);
        let domain = self.source_domain(result);
        Self::clear_pending_output(current, domain);

        Ok(())
    }

    fn build_stack_load(
        &mut self,
        site: IlOpId,
        operation: ECodeSsaOp,
        current: &mut MCodeSsaRenameState,
    ) -> Result<(), IlError> {
        let access = self
            .recovery
            .stack()
            .access_for(site)
            .expect("fixed stack access was checked before translation");
        let recovered = self
            .recovery
            .variables()
            .stack_variable(access.object())
            .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "stack variable"))?;
        let variable = self.variable(recovered);
        let result = self.single_source_result(operation)?;
        let full_width = self.variable_width(variable)?;

        if self.recovery.aliases().contains(recovered) {
            if let Entry::Vacant(entry) = current.stack.entry(variable) {
                let value = self.push_variable_undefined(variable, full_width)?;
                entry.insert(value);
            }
            let memory = self.mapped_memory_operand(operation)?;
            let field = access.field_offset() != 0 || operation.width() != full_width;
            let opcode = if field {
                MCodeSsaOpcode::VarAliasedField
            } else {
                MCodeSsaOpcode::VarAliased
            };
            let space = operation
                .address_space()
                .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "address space"))?;
            let spec = MCodeSsaOperationSpec::new(opcode, operation.width())
                .with_variable(variable)
                .with_immediate(access.field_offset())
                .with_address_space(space);
            let results = self.emit(spec, [memory], [operation.width()])?;
            self.values[result.index()] = Some(IlValueId::try_from_index(results.start())?);
            return Ok(());
        }

        let previous = match current.stack.get(&variable).copied() {
            Some(value) => value,
            None => {
                let value = self.push_variable_undefined(variable, full_width)?;
                current.stack.insert(variable, value);
                value
            }
        };
        if access.field_offset() == 0 && operation.width() == full_width {
            self.values[result.index()] = Some(previous);
            return Ok(());
        }

        let results = self.emit(
            MCodeSsaOperationSpec::new(MCodeSsaOpcode::Extract, operation.width())
                .with_immediate(access.field_offset()),
            [previous],
            [operation.width()],
        )?;
        self.values[result.index()] = Some(IlValueId::try_from_index(results.start())?);

        Ok(())
    }

    fn build_stack_store(
        &mut self,
        site: IlOpId,
        operation: ECodeSsaOp,
        current: &mut MCodeSsaRenameState,
    ) -> Result<(), IlError> {
        let access = self
            .recovery
            .stack()
            .access_for(site)
            .expect("fixed stack access was checked before translation");
        let recovered = self
            .recovery
            .variables()
            .stack_variable(access.object())
            .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "stack variable"))?;
        let variable = self.variable(recovered);
        let full_width = self.variable_width(variable)?;
        let source_operands = self.source.operation_operands_for(&operation);
        let source_value = source_operands
            .get(1)
            .copied()
            .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "stored stack value"))?;
        let value = self.source_value(source_value)?;
        let width = self
            .source
            .value_width(source_value)
            .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "stored stack width"))?;
        let memory = self.mapped_memory_operand(operation)?;
        let source_result = self.single_source_result(operation)?;
        let space = operation
            .address_space()
            .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "address space"))?;
        let field = access.field_offset() != 0 || width != full_width;

        if self.recovery.aliases().contains(recovered) {
            let opcode = if field {
                MCodeSsaOpcode::SetVarAliasedField
            } else {
                MCodeSsaOpcode::SetVarAliased
            };
            let spec = MCodeSsaOperationSpec::new(opcode, width)
                .with_variable(variable)
                .with_immediate(access.field_offset())
                .with_address_space(space);
            let results = self.emit(spec, [value, memory], [0, full_width])?;
            let memory_result = IlValueId::try_from_index(results.start())?;
            let variable_result = IlValueId::try_from_index(results.start() + 1)?;
            self.values[source_result.index()] = Some(memory_result);
            self.insert_binding(variable_result, variable)?;
            current.memory.insert(space, memory_result);
            current.pending_memory.remove(&space);
            current.stack.insert(variable, variable_result);
            return Ok(());
        }

        let results = if field {
            let previous = match current.stack.get(&variable).copied() {
                Some(value) => value,
                None => {
                    let value = self.push_variable_undefined(variable, full_width)?;
                    current.stack.insert(variable, value);
                    value
                }
            };
            if self.bindings.latest(variable) == Some(previous) {
                self.emit(
                    MCodeSsaOperationSpec::new(MCodeSsaOpcode::SetVarField, width)
                        .with_variable(variable)
                        .with_immediate(access.field_offset()),
                    [previous, value],
                    [full_width],
                )?
            } else {
                let results = self.emit(
                    MCodeSsaOperationSpec::new(MCodeSsaOpcode::Insert, full_width)
                        .with_immediate(access.field_offset()),
                    [previous, value],
                    [full_width],
                )?;
                let inserted = IlValueId::try_from_index(results.start())?;
                self.emit(
                    MCodeSsaOperationSpec::new(MCodeSsaOpcode::SetVar, full_width)
                        .with_variable(variable),
                    [inserted],
                    [full_width],
                )?
            }
        } else {
            self.emit(
                MCodeSsaOperationSpec::new(MCodeSsaOpcode::SetVar, full_width)
                    .with_variable(variable),
                [value],
                [full_width],
            )?
        };
        let variable_result = IlValueId::try_from_index(results.start())?;
        self.insert_binding(variable_result, variable)?;
        self.values[source_result.index()] = Some(memory);
        current.memory.insert(space, memory);
        current.pending_memory.remove(&space);
        current.stack.insert(variable, variable_result);

        Ok(())
    }

    fn build_call(
        &mut self,
        site: IlOpId,
        operation: ECodeSsaOp,
        current: &mut MCodeSsaRenameState,
    ) -> Result<(), IlError> {
        let space = match operation.opcode() {
            ECodeSsaOpcode::Call => operation
                .address()
                .map(|address| address.space())
                .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "call target"))?,
            ECodeSsaOpcode::CallIndirect => operation
                .address_space()
                .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "address space"))?,
            _ => unreachable!(),
        };
        self.builder.ensure_memory_domain(space);
        let memory = match current.memory.get(&space).copied() {
            Some(value) => value,
            None => {
                let value = self.push_memory_undefined(space)?;
                current.memory.insert(space, value);
                value
            }
        };
        let call = self.recovery.abi().call(site).cloned();
        let mut operands = Vec::new();
        if operation.opcode() == ECodeSsaOpcode::CallIndirect {
            let destination = self
                .source
                .operation_operands_for(&operation)
                .first()
                .copied()
                .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "call target"))?;
            operands.push(self.source_value(destination)?);
        }
        if let Some(call) = &call {
            for argument in call.arguments() {
                operands.push(match argument {
                    MCodeCallArgument::Value(value) => self.source_value(*value)?,
                    MCodeCallArgument::Pair { high, low } => self.push_split(*high, *low)?,
                    MCodeCallArgument::Stack { offset, width } => {
                        self.stack_argument_value(*offset, *width, space, memory, current)?
                    }
                });
            }
        }
        operands.push(memory);

        let outputs = call.as_ref().map_or(&[][..], |call| call.outputs());
        let widths = iter::once(0).chain(outputs.iter().flat_map(|output| {
            output
                .components()
                .iter()
                .map(|component| component.width())
        }));
        let opcode = match operation.opcode() {
            ECodeSsaOpcode::Call => MCodeSsaOpcode::Call,
            ECodeSsaOpcode::CallIndirect => MCodeSsaOpcode::CallIndirect,
            _ => unreachable!(),
        };
        let mut spec = MCodeSsaOperationSpec::new(opcode, 0).with_address_space(space);
        if let Some(address) = operation.address() {
            spec = spec.with_address(address);
        }
        let results = self.emit(spec, operands, widths)?;
        let memory_result = IlValueId::try_from_index(results.start())?;
        current.memory.clear();
        current.pending_memory.clear();
        current.memory.insert(space, memory_result);
        current.pending_memory.insert(space);
        current.pending_outputs.clear();

        let mut result_index = results.start() + 1;
        for output in outputs {
            for component in output.components() {
                let value = IlValueId::try_from_index(result_index)?;
                let variable = if let Some(root) = component.register_id() {
                    let variable =
                        self.intern_call_output_variable(site, output.location(), root)?;
                    current.pending_outputs.insert(root, value);
                    variable
                } else {
                    let offset = component
                        .stack_offset()
                        .expect("a non-register call output is stack storage");
                    let access = self
                        .recovery
                        .stack()
                        .storage_access(offset, component.width())
                        .ok_or_else(|| {
                            IlError::missing_component(MCodeSsaIr::FORM, "stack call output")
                        })?;
                    let recovered = self
                        .recovery
                        .variables()
                        .stack_variable(access.object())
                        .ok_or_else(|| {
                            IlError::missing_component(MCodeSsaIr::FORM, "stack variable")
                        })?;
                    let variable = self.variable(recovered);
                    current.stack.insert(variable, value);
                    variable
                };
                self.insert_binding(value, variable)?;
                result_index += 1;
            }
        }

        Ok(())
    }

    fn build_tail_call(
        &mut self,
        site: IlOpId,
        operation: ECodeSsaOp,
        current: &mut MCodeSsaRenameState,
    ) -> Result<(), IlError> {
        let space = match operation.opcode() {
            ECodeSsaOpcode::Branch => operation
                .address()
                .map(|address| address.space())
                .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "tail-call target"))?,
            ECodeSsaOpcode::BranchIndirect => operation
                .address_space()
                .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "address space"))?,
            _ => unreachable!(),
        };
        self.builder.ensure_memory_domain(space);
        let memory = match current.memory.get(&space).copied() {
            Some(value) => value,
            None => {
                let value = self.push_memory_undefined(space)?;
                current.memory.insert(space, value);
                value
            }
        };
        let mut operands = Vec::new();
        if operation.opcode() == ECodeSsaOpcode::BranchIndirect {
            let destination = self
                .source
                .operation_operands_for(&operation)
                .first()
                .copied()
                .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "tail-call target"))?;
            operands.push(self.source_value(destination)?);
        }
        if let Some(call) = self.recovery.abi().call(site).cloned() {
            for argument in call.arguments() {
                operands.push(match argument {
                    MCodeCallArgument::Value(value) => self.source_value(*value)?,
                    MCodeCallArgument::Pair { high, low } => self.push_split(*high, *low)?,
                    MCodeCallArgument::Stack { offset, width } => {
                        self.stack_argument_value(*offset, *width, space, memory, current)?
                    }
                });
            }
        }
        operands.push(memory);

        let opcode = match operation.opcode() {
            ECodeSsaOpcode::Branch => MCodeSsaOpcode::TailCall,
            ECodeSsaOpcode::BranchIndirect => MCodeSsaOpcode::TailCallIndirect,
            _ => unreachable!(),
        };
        let mut spec = MCodeSsaOperationSpec::new(opcode, 0).with_address_space(space);
        if let Some(address) = operation.address() {
            spec = spec.with_address(address);
        }
        self.emit(spec, operands, [])?;

        Ok(())
    }

    fn push_split(&mut self, high: IlValueId, low: IlValueId) -> Result<IlValueId, IlError> {
        let high_value = self.source_value(high)?;
        let low_value = self.source_value(low)?;
        let width = self
            .source
            .value_width(high)
            .and_then(|high| {
                self.source
                    .value_width(low)
                    .and_then(|low| high.checked_add(low))
            })
            .ok_or_else(|| IlError::integer_overflow("split variable width"))?;
        let results = self.emit(
            MCodeSsaOperationSpec::new(MCodeSsaOpcode::VarSplit, width),
            [high_value, low_value],
            [width],
        )?;

        IlValueId::try_from_index(results.start())
    }

    fn stack_argument_value(
        &mut self,
        offset: i64,
        width: u32,
        space: AddressSpaceId,
        memory: IlValueId,
        current: &mut MCodeSsaRenameState,
    ) -> Result<IlValueId, IlError> {
        let access = self
            .recovery
            .stack()
            .storage_access(offset, width)
            .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "stack call input"))?;
        let recovered = self
            .recovery
            .variables()
            .stack_variable(access.object())
            .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "stack variable"))?;
        let variable = self.variable(recovered);
        let full_width = self.variable_width(variable)?;

        if self.recovery.aliases().contains(recovered) {
            if let Entry::Vacant(entry) = current.stack.entry(variable) {
                let value = self.push_variable_undefined(variable, full_width)?;
                entry.insert(value);
            }
            let opcode = if access.field_offset() != 0 || width != full_width {
                MCodeSsaOpcode::VarAliasedField
            } else {
                MCodeSsaOpcode::VarAliased
            };
            let results = self.emit(
                MCodeSsaOperationSpec::new(opcode, width)
                    .with_variable(variable)
                    .with_immediate(access.field_offset())
                    .with_address_space(space),
                [memory],
                [width],
            )?;
            return IlValueId::try_from_index(results.start());
        }

        let value = match current.stack.get(&variable).copied() {
            Some(value) => value,
            None => {
                let value = self.push_variable_undefined(variable, full_width)?;
                current.stack.insert(variable, value);
                value
            }
        };
        if access.field_offset() == 0 && width == full_width {
            return Ok(value);
        }
        let results = self.emit(
            MCodeSsaOperationSpec::new(MCodeSsaOpcode::Extract, width)
                .with_immediate(access.field_offset()),
            [value],
            [width],
        )?;
        IlValueId::try_from_index(results.start())
    }

    fn intern_call_output_variable(
        &mut self,
        site: IlOpId,
        location: MCodeStorageLocation,
        root: RegisterId,
    ) -> Result<MCodeVarId, IlError> {
        if let Some(variable) = self
            .call_output_variables
            .get(MCodeCallOutputSite::new(site, location, root))
        {
            return Ok(variable);
        }

        let next = self
            .recovery
            .variables()
            .variables()
            .iter()
            .filter(|variable| variable.register_id() == Some(root))
            .map(MCodeVar::index)
            .max()
            .map_or(0, |index| index.saturating_add(1));
        self.builder.intern_variable(MCodeVar::register(root, next))
    }

    fn build_carried(
        &mut self,
        site: IlOpId,
        operation: ECodeSsaOp,
        current: &mut MCodeSsaRenameState,
    ) -> Result<(), IlError> {
        if operation.results().len() == 1 {
            let source = self.single_source_result(operation)?;
            if self.source_domain(source).is_none()
                && let Some(access) = self.recovery.stack().address_for(source)
            {
                self.recovery.stack().offset_of(source).ok_or_else(|| {
                    IlError::missing_component(MCodeSsaIr::FORM, "stack-derived address")
                })?;
                let recovered = self
                    .recovery
                    .variables()
                    .stack_variable(access.object())
                    .ok_or_else(|| {
                        IlError::missing_component(MCodeSsaIr::FORM, "stack variable")
                    })?;
                if self.recovery.aliases().contains(recovered) {
                    let variable = self.variable(recovered);
                    if let Entry::Vacant(entry) = current.stack.entry(variable) {
                        let value =
                            self.push_variable_undefined(variable, self.variable_width(variable)?)?;
                        entry.insert(value);
                    }
                    let field = access.field_offset() != 0;
                    let opcode = if field {
                        MCodeSsaOpcode::AddressOfField
                    } else {
                        MCodeSsaOpcode::AddressOf
                    };
                    let spec = MCodeSsaOperationSpec::new(opcode, operation.width())
                        .with_variable(variable)
                        .with_immediate(access.field_offset());
                    let results = self.emit(spec, [], [operation.width()])?;
                    self.values[source.index()] = Some(IlValueId::try_from_index(results.start())?);
                    return Ok(());
                }
            }
        }

        self.scratch.operands.clear();
        for operand in self.source.operation_operands_for(&operation) {
            self.scratch.operands.push(self.source_value(*operand)?);
        }
        let opcode = self.lift_opcode(site, operation.opcode())?;
        let immediate = if operation.opcode() == ECodeSsaOpcode::Constant && operation.width() > 64
        {
            let value = operation
                .constant(self.source.constant_storage())
                .ok_or_else(|| IlError::missing_component(ECodeSsaIr::FORM, "constant"))?;
            self.builder.intern_constant(&value)
        } else {
            operation.immediate()
        };
        let mut spec =
            MCodeSsaOperationSpec::new(opcode, operation.width()).with_immediate(immediate);
        if let Some(address) = operation.address() {
            spec = spec.with_address(address);
        }
        if let Some(space) = operation.address_space() {
            spec = spec.with_address_space(space);
            if opcode.requires_memory_domain() {
                self.builder.ensure_memory_domain(space);
            }
        }
        let mut operands = mem::take(&mut self.scratch.operands);
        let result_widths = operation
            .results()
            .slice(self.source.values())
            .iter()
            .map(|value| value.width());
        let results = self.emit(spec, operands.iter().copied(), result_widths);
        operands.clear();
        self.scratch.operands = operands;
        let results = results?;
        for (offset, source_index) in
            (operation.results().start()..operation.results().end()).enumerate()
        {
            let source = IlValueId::try_from_index(source_index)?;
            let value = IlValueId::try_from_index(results.start() + offset)?;
            self.values[source.index()] = Some(value);
            if let Some(ECodeSsaDomain::Memory(space)) = self.source_domain(source) {
                current.memory.insert(space, value);
                current.pending_memory.remove(&space);
            }
        }

        Ok(())
    }

    fn lift_opcode(&self, site: IlOpId, opcode: ECodeSsaOpcode) -> Result<MCodeSsaOpcode, IlError> {
        let opcode = match opcode {
            ECodeSsaOpcode::Constant => MCodeSsaOpcode::Constant,
            ECodeSsaOpcode::Address => MCodeSsaOpcode::Address,
            ECodeSsaOpcode::Undefined => MCodeSsaOpcode::Undefined,
            ECodeSsaOpcode::Load => MCodeSsaOpcode::Load,
            ECodeSsaOpcode::Copy => MCodeSsaOpcode::Copy,
            ECodeSsaOpcode::Add => MCodeSsaOpcode::Add,
            ECodeSsaOpcode::Sub => MCodeSsaOpcode::Sub,
            ECodeSsaOpcode::Mul => MCodeSsaOpcode::Mul,
            ECodeSsaOpcode::UnsignedDiv => MCodeSsaOpcode::UnsignedDiv,
            ECodeSsaOpcode::SignedDiv => MCodeSsaOpcode::SignedDiv,
            ECodeSsaOpcode::UnsignedRem => MCodeSsaOpcode::UnsignedRem,
            ECodeSsaOpcode::SignedRem => MCodeSsaOpcode::SignedRem,
            ECodeSsaOpcode::Negate => MCodeSsaOpcode::Negate,
            ECodeSsaOpcode::LeftShift => MCodeSsaOpcode::LeftShift,
            ECodeSsaOpcode::LogicalRightShift => MCodeSsaOpcode::LogicalRightShift,
            ECodeSsaOpcode::ArithmeticRightShift => MCodeSsaOpcode::ArithmeticRightShift,
            ECodeSsaOpcode::And => MCodeSsaOpcode::And,
            ECodeSsaOpcode::Or => MCodeSsaOpcode::Or,
            ECodeSsaOpcode::Xor => MCodeSsaOpcode::Xor,
            ECodeSsaOpcode::Not => MCodeSsaOpcode::Not,
            ECodeSsaOpcode::BoolAnd => MCodeSsaOpcode::BoolAnd,
            ECodeSsaOpcode::BoolOr => MCodeSsaOpcode::BoolOr,
            ECodeSsaOpcode::BoolXor => MCodeSsaOpcode::BoolXor,
            ECodeSsaOpcode::BoolNot => MCodeSsaOpcode::BoolNot,
            ECodeSsaOpcode::IntEqual => MCodeSsaOpcode::IntEqual,
            ECodeSsaOpcode::IntNotEqual => MCodeSsaOpcode::IntNotEqual,
            ECodeSsaOpcode::IntLess => MCodeSsaOpcode::IntLess,
            ECodeSsaOpcode::IntSignedLess => MCodeSsaOpcode::IntSignedLess,
            ECodeSsaOpcode::IntLessEqual => MCodeSsaOpcode::IntLessEqual,
            ECodeSsaOpcode::IntSignedLessEqual => MCodeSsaOpcode::IntSignedLessEqual,
            ECodeSsaOpcode::Carry => MCodeSsaOpcode::Carry,
            ECodeSsaOpcode::SignedCarry => MCodeSsaOpcode::SignedCarry,
            ECodeSsaOpcode::SignedBorrow => MCodeSsaOpcode::SignedBorrow,
            ECodeSsaOpcode::CountOnes => MCodeSsaOpcode::CountOnes,
            ECodeSsaOpcode::CountLeadingZeros => MCodeSsaOpcode::CountLeadingZeros,
            ECodeSsaOpcode::ZeroExtend => MCodeSsaOpcode::ZeroExtend,
            ECodeSsaOpcode::SignExtend => MCodeSsaOpcode::SignExtend,
            ECodeSsaOpcode::Truncate => MCodeSsaOpcode::Truncate,
            ECodeSsaOpcode::Extract => MCodeSsaOpcode::Extract,
            ECodeSsaOpcode::Insert => MCodeSsaOpcode::Insert,
            ECodeSsaOpcode::FloatAdd => MCodeSsaOpcode::FloatAdd,
            ECodeSsaOpcode::FloatSub => MCodeSsaOpcode::FloatSub,
            ECodeSsaOpcode::FloatMul => MCodeSsaOpcode::FloatMul,
            ECodeSsaOpcode::FloatDiv => MCodeSsaOpcode::FloatDiv,
            ECodeSsaOpcode::FloatNegate => MCodeSsaOpcode::FloatNegate,
            ECodeSsaOpcode::FloatAbs => MCodeSsaOpcode::FloatAbs,
            ECodeSsaOpcode::FloatSqrt => MCodeSsaOpcode::FloatSqrt,
            ECodeSsaOpcode::FloatCeiling => MCodeSsaOpcode::FloatCeiling,
            ECodeSsaOpcode::FloatFloor => MCodeSsaOpcode::FloatFloor,
            ECodeSsaOpcode::FloatRound => MCodeSsaOpcode::FloatRound,
            ECodeSsaOpcode::FloatIsNan => MCodeSsaOpcode::FloatIsNan,
            ECodeSsaOpcode::FloatEqual => MCodeSsaOpcode::FloatEqual,
            ECodeSsaOpcode::FloatNotEqual => MCodeSsaOpcode::FloatNotEqual,
            ECodeSsaOpcode::FloatLess => MCodeSsaOpcode::FloatLess,
            ECodeSsaOpcode::FloatLessEqual => MCodeSsaOpcode::FloatLessEqual,
            ECodeSsaOpcode::FloatToInt => MCodeSsaOpcode::FloatToInt,
            ECodeSsaOpcode::FloatToFloat => MCodeSsaOpcode::FloatToFloat,
            ECodeSsaOpcode::IntToFloat => MCodeSsaOpcode::IntToFloat,
            ECodeSsaOpcode::IntrinsicResult => MCodeSsaOpcode::IntrinsicResult,
            ECodeSsaOpcode::Intrinsic => MCodeSsaOpcode::Intrinsic,
            ECodeSsaOpcode::Store => MCodeSsaOpcode::Store,
            ECodeSsaOpcode::Branch => MCodeSsaOpcode::Branch,
            ECodeSsaOpcode::ConditionalBranch => MCodeSsaOpcode::ConditionalBranch,
            ECodeSsaOpcode::BranchIndirect if self.is_switch(site) => MCodeSsaOpcode::Switch,
            ECodeSsaOpcode::BranchIndirect => MCodeSsaOpcode::BranchIndirect,
            ECodeSsaOpcode::Return => MCodeSsaOpcode::Return,
            ECodeSsaOpcode::Trap => MCodeSsaOpcode::Trap,
            ECodeSsaOpcode::Call
            | ECodeSsaOpcode::CallIndirect
            | ECodeSsaOpcode::WriteRegister
            | ECodeSsaOpcode::WriteFlag => {
                return Err(IlError::unsupported_opcode(MCodeSsaIr::FORM));
            }
        };
        Ok(opcode)
    }

    fn is_switch(&self, site: IlOpId) -> bool {
        self.operation_blocks
            .get(site.index())
            .copied()
            .flatten()
            .and_then(|block| self.source.graph().blocks().get(block.index()))
            .is_some_and(|block| {
                block
                    .successors()
                    .slice(self.source.graph().successor_kinds())
                    .iter()
                    .any(|kinds| kinds.is_computed())
            })
    }

    fn mapped_memory_operand(&self, operation: ECodeSsaOp) -> Result<IlValueId, IlError> {
        self.source
            .memory_operand(&operation)
            .ok_or_else(|| IlError::missing_component(MCodeSsaIr::FORM, "memory operand"))
            .and_then(|value| self.source_value(value))
    }

    fn single_source_result(&self, operation: ECodeSsaOp) -> Result<IlValueId, IlError> {
        if operation.results().len() != 1 {
            return Err(IlError::missing_component(
                MCodeSsaIr::FORM,
                "single operation result",
            ));
        }
        IlValueId::try_from_index(operation.results().start())
    }

    fn emit(
        &mut self,
        spec: MCodeSsaOperationSpec,
        operands: impl IntoIterator<Item = IlValueId>,
        widths: impl IntoIterator<Item = u32>,
    ) -> Result<IlIndexRange, IlError> {
        let operands = self.builder.push_value_operands(operands)?;
        let results = self.builder.push_result_values(widths)?;
        let mut operation = MCodeSsaOp::new(spec.opcode, results, operands, spec.width)
            .with_immediate(spec.immediate);
        if let Some(variable) = spec.variable {
            operation = operation.with_variable(variable);
        }
        if let Some(address) = spec.address {
            operation = operation.with_address(address);
        }
        if let Some(space) = spec.address_space {
            operation = operation.with_address_space(space);
        }
        self.builder.push_operation(operation)?;

        Ok(results)
    }
}

#[derive(Debug, Copy, Clone)]
struct MCodeSsaOperationSpec {
    opcode: MCodeSsaOpcode,
    width: u32,
    variable: Option<MCodeVarId>,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<AddressSpaceId>,
}

impl MCodeSsaOperationSpec {
    const fn new(opcode: MCodeSsaOpcode, width: u32) -> Self {
        Self {
            opcode,
            width,
            variable: None,
            immediate: 0,
            address: None,
            address_space: None,
        }
    }

    const fn set_variable(&mut self, variable: MCodeVarId) {
        self.variable = Some(variable);
    }

    const fn with_variable(mut self, variable: MCodeVarId) -> Self {
        self.set_variable(variable);
        self
    }

    const fn set_immediate(&mut self, immediate: u64) {
        self.immediate = immediate;
    }

    const fn with_immediate(mut self, immediate: u64) -> Self {
        self.set_immediate(immediate);
        self
    }

    const fn set_address(&mut self, address: Address) {
        self.address = Some(address);
    }

    const fn with_address(mut self, address: Address) -> Self {
        self.set_address(address);
        self
    }

    const fn set_address_space(&mut self, address_space: AddressSpaceId) {
        self.address_space = Some(address_space);
    }

    const fn with_address_space(mut self, address_space: AddressSpaceId) -> Self {
        self.set_address_space(address_space);
        self
    }
}
