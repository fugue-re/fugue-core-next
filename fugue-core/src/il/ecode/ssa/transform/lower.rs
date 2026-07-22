use std::collections::BTreeMap;

use super::{SsaConstruction, SsaDomain};
use crate::il::common::{IlError, IlExprId, IlIndexRange, IlLevel, IlValueId};
use crate::il::ecode::ssa::{ECodeSsaOp, ECodeSsaOpcode};
use crate::il::ecode::{ECodeExpr, ECodeExprOpcode, ECodeStmt, ECodeStmtOpcode};
use crate::storage::segments::space::AddressSpaceId;

impl SsaConstruction<'_, '_> {
    pub(crate) fn construct_statement_at(
        &mut self,
        index: usize,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<(), IlError> {
        self.values.fill(None);
        let start = self.builder.operation_count();
        let statement = &self.source.statements()[index];

        self.construct_statement(statement, current)?;

        let end = self.builder.operation_count();
        self.statement_ranges[index] = IlIndexRange::new(start, end)?;

        Ok(())
    }

    fn construct_statement(
        &mut self,
        statement: &ECodeStmt,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<(), IlError> {
        match statement.opcode() {
            ECodeStmtOpcode::WriteRegister => {
                let value = self.construct_statement_value(statement, current)?;
                current.insert(SsaDomain::Register(statement.immediate()), value);
            }
            ECodeStmtOpcode::WriteFlag => {
                let value = self.construct_statement_value(statement, current)?;
                current.insert(SsaDomain::Flag(statement.immediate()), value);
            }
            ECodeStmtOpcode::Store => {
                let address_space = statement
                    .address_space()
                    .ok_or(IlError::missing_component(IlLevel::ECode, "address space"))?;
                let mut operands = self.construct_statement_operands(statement, current)?;
                let memory = self.current_memory(address_space, current)?;

                operands.push(memory);

                let operands = self.builder.push_value_operands(operands)?;
                let (memory, results) = self.builder.push_result_value(0)?;
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
                let operands = self.construct_statement_operands(statement, current)?;
                let operands = self.builder.push_value_operands(operands)?;
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

    fn construct_statement_value(
        &mut self,
        statement: &ECodeStmt,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<IlValueId, IlError> {
        let value = statement
            .value()
            .ok_or(IlError::missing_component(IlLevel::ECode, "value"))?;

        self.construct_expression(value, current)
    }

    fn construct_statement_operands(
        &mut self,
        statement: &ECodeStmt,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<Vec<IlValueId>, IlError> {
        let mut operands = Vec::new();

        if let Some(value) = statement.value() {
            operands.push(self.construct_expression(value, current)?);
        }

        for operand in self.source.statement_operands_for(statement) {
            operands.push(self.construct_expression(*operand, current)?);
        }

        Ok(operands)
    }

    fn construct_expression(
        &mut self,
        id: IlExprId,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<IlValueId, IlError> {
        if let Some(value) = self.values.get(id.index()).and_then(|value| *value) {
            return Ok(value);
        }

        let expression = self.source.expressions()[id.index()];

        let value = match expression.opcode() {
            ECodeExprOpcode::ReadRegister => self.construct_read_register(&expression, current)?,
            ECodeExprOpcode::ReadFlag => self.construct_read_flag(&expression, current)?,
            opcode => self.construct_value_expression(&expression, opcode, current)?,
        };

        if let Some(slot) = self.values.get_mut(id.index()) {
            *slot = Some(value);
        }

        Ok(value)
    }

    fn construct_read_register(
        &mut self,
        expression: &ECodeExpr,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<IlValueId, IlError> {
        let domain = SsaDomain::Register(expression.immediate());

        if let Some(value) = current.get(&domain).copied() {
            return Ok(value);
        }

        let value = self.push_undefined(domain, expression.width())?;

        current.insert(domain, value);

        Ok(value)
    }

    fn construct_read_flag(
        &mut self,
        expression: &ECodeExpr,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<IlValueId, IlError> {
        let domain = SsaDomain::Flag(expression.immediate());

        if let Some(value) = current.get(&domain).copied() {
            return Ok(value);
        }

        let value = self.push_undefined(domain, expression.width())?;

        current.insert(domain, value);

        Ok(value)
    }

    fn construct_value_expression(
        &mut self,
        expression: &ECodeExpr,
        opcode: ECodeExprOpcode,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<IlValueId, IlError> {
        let mut operands = self.construct_expression_operands(expression, current)?;
        if opcode == ECodeExprOpcode::Load {
            let address_space = expression
                .address_space()
                .ok_or(IlError::missing_component(IlLevel::ECode, "address space"))?;
            let memory = self.current_memory(address_space, current)?;

            operands.push(memory);
        }

        let operands = self.builder.push_value_operands(operands)?;
        let opcode = ECodeSsaOpcode::from_expression(opcode)
            .ok_or(IlError::unsupported_opcode(IlLevel::ECodeSsa))?;

        self.push_value_operation(
            opcode,
            expression.width(),
            operands,
            expression.immediate(),
            expression.address_space(),
        )
    }

    fn construct_expression_operands(
        &mut self,
        expression: &ECodeExpr,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<Vec<IlValueId>, IlError> {
        let mut operands = Vec::new();

        for operand in self.source.expression_operands_for(expression) {
            operands.push(self.construct_expression(*operand, current)?);
        }

        Ok(operands)
    }

    fn current_memory(
        &mut self,
        address_space: AddressSpaceId,
        current: &mut BTreeMap<SsaDomain, IlValueId>,
    ) -> Result<IlValueId, IlError> {
        let domain = SsaDomain::Memory(address_space);

        if let Some(value) = current.get(&domain).copied() {
            return Ok(value);
        }

        let value = self.push_undefined(domain, 0)?;

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
