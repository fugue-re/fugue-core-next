use std::collections::BTreeMap;

use super::{ECodeSsaConstruction, ECodeSsaExpressionStep};
use crate::il::common::{
    FlagId, IlArtefact, IlError, IlExprId, IlIndexRange, IlValueId, RegisterId,
};
use crate::il::ecode::ssa::{ECodeSsaDomain, ECodeSsaIr, ECodeSsaOp, ECodeSsaOpcode};
use crate::il::ecode::{ECodeExprOpcode, ECodeIr, ECodeStmt, ECodeStmtOpcode};
use crate::storage::segments::space::AddressSpaceId;

impl ECodeSsaConstruction<'_, '_> {
    pub(crate) fn build_statement_at(
        &mut self,
        index: usize,
        current: &mut BTreeMap<ECodeSsaDomain, IlValueId>,
    ) -> Result<(), IlError> {
        let spans = self.source.source_spans();
        let span = spans.partition_point(|span| span.destination().start() < index);
        if spans
            .get(span)
            .is_some_and(|span| span.destination().start() == index)
        {
            self.reset_expression_cache();
        }
        let start = self.builder.operation_count();
        let statement = &self.source.statements()[index];

        self.build_statement(statement, current)?;

        let end = self.builder.operation_count();
        self.statement_ranges[index] = IlIndexRange::new(start, end)?;

        Ok(())
    }

    pub(crate) fn reset_expression_cache(&mut self) {
        for expression in self.built_expressions.drain(..) {
            self.values[expression.index()] = None;
        }
    }

    fn build_statement(
        &mut self,
        statement: &ECodeStmt,
        current: &mut BTreeMap<ECodeSsaDomain, IlValueId>,
    ) -> Result<(), IlError> {
        match statement.opcode() {
            ECodeStmtOpcode::WriteRegister | ECodeStmtOpcode::WriteFlag => {
                let source_expression = statement
                    .value()
                    .ok_or_else(|| IlError::missing_component(ECodeIr::FORM, "value"))?;
                let width = self.source.expressions()[source_expression.index()].width();
                let source = self.build_expression(source_expression, current)?;
                let (opcode, domain) = match statement.opcode() {
                    ECodeStmtOpcode::WriteRegister => (
                        ECodeSsaOpcode::WriteRegister,
                        ECodeSsaDomain::Register(RegisterId::new(statement.immediate())),
                    ),
                    ECodeStmtOpcode::WriteFlag => (
                        ECodeSsaOpcode::WriteFlag,
                        ECodeSsaDomain::Flag(FlagId::new(statement.immediate())),
                    ),
                    _ => unreachable!(),
                };
                let operands = self.builder.push_value_operands([source])?;
                let value = self.push_value_operation(
                    opcode,
                    width,
                    operands,
                    statement.immediate(),
                    None,
                )?;
                self.builder.set_value_domain(value, domain);
                current.insert(domain, value);
            }
            ECodeStmtOpcode::Store => {
                let address_space = statement
                    .address_space()
                    .ok_or_else(|| IlError::missing_component(ECodeIr::FORM, "address space"))?;
                self.build_statement_operands(statement, current)?;
                let memory =
                    self.current_value(ECodeSsaDomain::Memory(address_space), 0, current)?;

                self.statement_operands.push(memory);

                let operands = self
                    .builder
                    .push_value_operands(self.statement_operands.iter().copied())?;
                let (memory, results) = self.builder.push_result_value(0)?;
                let domain = ECodeSsaDomain::Memory(address_space);
                self.builder.set_value_domain(memory, domain);
                self.builder.ensure_memory_domain(address_space);
                let operation = ECodeSsaOp::new(ECodeSsaOpcode::Store, results, operands, 0)
                    .with_address_space(address_space)
                    .with_immediate(statement.immediate());

                self.builder.push_operation(operation)?;
                current.insert(domain, memory);
            }
            opcode => {
                self.build_statement_operands(statement, current)?;
                let operands = self
                    .builder
                    .push_value_operands(self.statement_operands.iter().copied())?;
                let opcode = ECodeSsaOpcode::from_statement(opcode)
                    .ok_or_else(|| IlError::unsupported_opcode(ECodeSsaIr::FORM))?;
                let mut operation = ECodeSsaOp::new(opcode, IlIndexRange::EMPTY, operands, 0)
                    .with_immediate(statement.immediate());

                if let Some(address) = statement.address() {
                    operation = operation.with_address(address);
                }

                if let Some(address_space) = statement.address_space() {
                    if opcode.requires_memory_domain() {
                        self.builder.ensure_memory_domain(address_space);
                    }

                    operation = operation.with_address_space(address_space);
                }

                self.builder.push_operation(operation)?;
                if matches!(opcode, ECodeSsaOpcode::Call | ECodeSsaOpcode::CallIndirect) {
                    let preserved = self.source.call_preserved_registers();
                    current.retain(|domain, _| match domain {
                        ECodeSsaDomain::Register(register) => {
                            preserved.binary_search(register).is_ok()
                        }
                        ECodeSsaDomain::Flag(_) | ECodeSsaDomain::Memory(_) => false,
                    });
                }
            }
        }

        Ok(())
    }

    fn build_statement_operands(
        &mut self,
        statement: &ECodeStmt,
        current: &mut BTreeMap<ECodeSsaDomain, IlValueId>,
    ) -> Result<(), IlError> {
        self.statement_operands.clear();

        if let Some(value) = statement.value() {
            let value = self.build_expression(value, current)?;
            self.statement_operands.push(value);
        }

        for operand in self.source.statement_operands_for(statement) {
            let operand = self.build_expression(*operand, current)?;
            self.statement_operands.push(operand);
        }

        Ok(())
    }

    fn build_expression(
        &mut self,
        id: IlExprId,
        current: &mut BTreeMap<ECodeSsaDomain, IlValueId>,
    ) -> Result<IlValueId, IlError> {
        self.expression_steps.clear();
        self.expression_steps
            .push(ECodeSsaExpressionStep::Visit(id));

        while let Some(step) = self.expression_steps.pop() {
            let expression_id = match step {
                ECodeSsaExpressionStep::Visit(expression_id) => {
                    if self.values[expression_id.index()].is_some() {
                        continue;
                    }

                    let expression = self.source.expressions()[expression_id.index()];
                    match expression.opcode() {
                        ECodeExprOpcode::ReadRegister => {
                            let value = self.current_value(
                                ECodeSsaDomain::Register(RegisterId::new(expression.immediate())),
                                expression.width(),
                                current,
                            )?;
                            self.values[expression_id.index()] = Some(value);
                            self.built_expressions.push(expression_id);
                            continue;
                        }
                        ECodeExprOpcode::ReadFlag => {
                            let value = self.current_value(
                                ECodeSsaDomain::Flag(FlagId::new(expression.immediate())),
                                expression.width(),
                                current,
                            )?;
                            self.values[expression_id.index()] = Some(value);
                            self.built_expressions.push(expression_id);
                            continue;
                        }
                        _ => {}
                    }

                    self.expression_steps
                        .push(ECodeSsaExpressionStep::Build(expression_id));
                    for operand in self
                        .source
                        .expression_operands_for(&expression)
                        .iter()
                        .rev()
                    {
                        self.expression_steps
                            .push(ECodeSsaExpressionStep::Visit(*operand));
                    }
                    continue;
                }
                ECodeSsaExpressionStep::Build(expression_id) => expression_id,
            };

            if self.values[expression_id.index()].is_some() {
                continue;
            }

            let expression = self.source.expressions()[expression_id.index()];
            self.expression_operands.clear();
            for operand in self.source.expression_operands_for(&expression) {
                let operand = self.values[operand.index()]
                    .ok_or_else(|| IlError::missing_component(ECodeSsaIr::FORM, "operand"))?;
                self.expression_operands.push(operand);
            }
            if expression.opcode() == ECodeExprOpcode::Load {
                let address_space = expression
                    .address_space()
                    .ok_or_else(|| IlError::missing_component(ECodeIr::FORM, "address space"))?;
                let memory =
                    self.current_value(ECodeSsaDomain::Memory(address_space), 0, current)?;
                self.expression_operands.push(memory);
            }

            let operands = self
                .builder
                .push_value_operands(self.expression_operands.iter().copied())?;
            let opcode = ECodeSsaOpcode::from_expression(expression.opcode())
                .ok_or_else(|| IlError::unsupported_opcode(ECodeSsaIr::FORM))?;
            let value = self.push_value_operation(
                opcode,
                expression.width(),
                operands,
                expression.immediate(),
                expression.address_space(),
            )?;
            self.values[expression_id.index()] = Some(value);
            self.built_expressions.push(expression_id);
        }

        self.values[id.index()]
            .ok_or_else(|| IlError::missing_component(ECodeSsaIr::FORM, "expression value"))
    }

    fn current_value(
        &mut self,
        domain: ECodeSsaDomain,
        width: u32,
        current: &mut BTreeMap<ECodeSsaDomain, IlValueId>,
    ) -> Result<IlValueId, IlError> {
        if let Some(value) = current.get(&domain).copied() {
            return Ok(value);
        }

        let value = self.push_undefined(domain, width)?;

        current.insert(domain, value);

        Ok(value)
    }

    pub(crate) fn push_undefined(
        &mut self,
        domain: ECodeSsaDomain,
        width: u32,
    ) -> Result<IlValueId, IlError> {
        let immediate = match domain {
            ECodeSsaDomain::Flag(flag) => flag.value(),
            ECodeSsaDomain::Memory(space) => {
                u64::try_from(space.index()).expect("address-space identifier is representable")
            }
            ECodeSsaDomain::Register(register) => register.value(),
        };
        let value = self.push_value_operation(
            ECodeSsaOpcode::Undefined,
            width,
            IlIndexRange::EMPTY,
            immediate,
            None,
        )?;
        self.builder.set_value_domain(value, domain);

        Ok(value)
    }

    fn push_value_operation(
        &mut self,
        opcode: ECodeSsaOpcode,
        width: u32,
        operands: IlIndexRange,
        immediate: u64,
        address_space: Option<AddressSpaceId>,
    ) -> Result<IlValueId, IlError> {
        let (value, results) = self.builder.push_result_value(width)?;
        let mut operation =
            ECodeSsaOp::new(opcode, results, operands, width).with_immediate(immediate);

        if let Some(address_space) = address_space {
            if opcode.requires_memory_domain() {
                self.builder.ensure_memory_domain(address_space);
            }

            operation = operation.with_address_space(address_space);
        }

        self.builder.push_operation(operation)?;

        Ok(value)
    }
}
