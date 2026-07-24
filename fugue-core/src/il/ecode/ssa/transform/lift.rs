use std::collections::BTreeMap;

use super::{ExpressionStep, SsaConstruction, SsaDomain};
use crate::il::common::{IlError, IlExprId, IlIndexRange, IlLevel, IlValueId};
use crate::il::ecode::ssa::{ECodeSsaOp, ECodeSsaOpcode};
use crate::il::ecode::{ECodeExprOpcode, ECodeStmt, ECodeStmtOpcode};
use crate::il::pcode::{FlagId, RegisterId};
use crate::storage::segments::space::AddressSpaceId;

impl SsaConstruction<'_, '_> {
    pub(crate) fn build_statement_at(
        &mut self,
        index: usize,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<(), IlError> {
        for expression in self.built_expressions.drain(..) {
            self.values[expression.index()] = None;
        }
        let start = self.builder.operation_count();
        let statement = &self.source.statements()[index];

        self.build_statement(statement, current)?;

        let end = self.builder.operation_count();
        self.statement_ranges[index] = IlIndexRange::new(start, end)?;

        Ok(())
    }

    fn build_statement(
        &mut self,
        statement: &ECodeStmt,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<(), IlError> {
        match statement.opcode() {
            ECodeStmtOpcode::WriteRegister => {
                let value = self.build_statement_value(statement, current)?;
                current.insert(
                    SsaDomain::Register(RegisterId::new(statement.immediate())),
                    value,
                );
            }
            ECodeStmtOpcode::WriteFlag => {
                let value = self.build_statement_value(statement, current)?;
                current.insert(SsaDomain::Flag(FlagId::new(statement.immediate())), value);
            }
            ECodeStmtOpcode::Store => {
                let address_space = statement
                    .address_space()
                    .ok_or(IlError::missing_component(IlLevel::ECode, "address space"))?;
                self.build_statement_operands(statement, current)?;
                let memory = self.current_value(SsaDomain::Memory(address_space), 0, current)?;

                self.statement_operands.push(memory);

                let operands = self
                    .builder
                    .push_value_operands(self.statement_operands.iter().copied())?;
                let (memory, results) = self.builder.push_result_value(0)?;
                self.builder.ensure_memory_domain(address_space);
                let operation = ECodeSsaOp::new(ECodeSsaOpcode::Store, results, operands, 0)
                    .with_address_space(address_space)
                    .with_immediate(statement.immediate());

                self.builder.push_operation(operation)?;
                current.insert(SsaDomain::Memory(address_space), memory);
            }
            opcode => {
                let invalidates_state = matches!(
                    statement.opcode(),
                    ECodeStmtOpcode::Call | ECodeStmtOpcode::CallIndirect
                );
                self.build_statement_operands(statement, current)?;
                let operands = self
                    .builder
                    .push_value_operands(self.statement_operands.iter().copied())?;
                let opcode = ECodeSsaOpcode::from_statement(opcode)
                    .ok_or(IlError::unsupported_opcode(IlLevel::ECodeSsa))?;
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
                if invalidates_state {
                    current.clear();
                }
            }
        }

        Ok(())
    }

    fn build_statement_value(
        &mut self,
        statement: &ECodeStmt,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<IlValueId, IlError> {
        let value = statement
            .value()
            .ok_or(IlError::missing_component(IlLevel::ECode, "value"))?;

        self.build_expression(value, current)
    }

    fn build_statement_operands(
        &mut self,
        statement: &ECodeStmt,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
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
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<IlValueId, IlError> {
        self.expression_steps.clear();
        self.expression_steps.push(ExpressionStep::Visit(id));

        while let Some(step) = self.expression_steps.pop() {
            let expression_id = match step {
                ExpressionStep::Visit(expression_id) => {
                    if self.values[expression_id.index()].is_some() {
                        continue;
                    }

                    let expression = self.source.expressions()[expression_id.index()];
                    match expression.opcode() {
                        ECodeExprOpcode::ReadRegister => {
                            let value = self.current_value(
                                SsaDomain::Register(RegisterId::new(expression.immediate())),
                                expression.width(),
                                current,
                            )?;
                            self.values[expression_id.index()] = Some(value);
                            self.built_expressions.push(expression_id);
                            continue;
                        }
                        ECodeExprOpcode::ReadFlag => {
                            let value = self.current_value(
                                SsaDomain::Flag(FlagId::new(expression.immediate())),
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
                        .push(ExpressionStep::Build(expression_id));
                    for operand in self
                        .source
                        .expression_operands_for(&expression)
                        .iter()
                        .rev()
                    {
                        self.expression_steps.push(ExpressionStep::Visit(*operand));
                    }
                    continue;
                }
                ExpressionStep::Build(expression_id) => expression_id,
            };

            if self.values[expression_id.index()].is_some() {
                continue;
            }

            let expression = self.source.expressions()[expression_id.index()];
            self.expression_operands.clear();
            for operand in self.source.expression_operands_for(&expression) {
                let operand = self.values[operand.index()]
                    .ok_or(IlError::missing_component(IlLevel::ECodeSsa, "operand"))?;
                self.expression_operands.push(operand);
            }
            if expression.opcode() == ECodeExprOpcode::Load {
                let address_space = expression
                    .address_space()
                    .ok_or(IlError::missing_component(IlLevel::ECode, "address space"))?;
                let memory = self.current_value(SsaDomain::Memory(address_space), 0, current)?;
                self.expression_operands.push(memory);
            }

            let operands = self
                .builder
                .push_value_operands(self.expression_operands.iter().copied())?;
            let opcode = ECodeSsaOpcode::from_expression(expression.opcode())
                .ok_or(IlError::unsupported_opcode(IlLevel::ECodeSsa))?;
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

        self.values[id.index()].ok_or(IlError::missing_component(
            IlLevel::ECodeSsa,
            "expression value",
        ))
    }

    fn current_value(
        &mut self,
        domain: SsaDomain,
        width: u32,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
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
        domain: SsaDomain,
        width: u32,
    ) -> Result<IlValueId, IlError> {
        self.push_value_operation(
            ECodeSsaOpcode::Undefined,
            width,
            IlIndexRange::EMPTY,
            domain.undefined_immediate(),
            None,
        )
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
