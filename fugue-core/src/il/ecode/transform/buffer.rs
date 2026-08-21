use crate::il::common::{FlagId, IlError, IlExprId, IlIndexRange, IlOpId, IlPool, RegisterId};
use crate::il::ecode::ECodeOpcode;
use crate::ir::Address;
use crate::storage::segments::space::AddressSpaceId;

mod expression;
mod operation;

pub(crate) use expression::{PCodeToECodeExpr, PCodeToECodeExprKind};
pub(crate) use operation::PCodeToECodeEffect;

#[derive(Debug)]
pub(crate) struct PCodeToECodeBuffer {
    call_preserved_registers: Vec<RegisterId>,
    expressions: Vec<PCodeToECodeExpr>,
    expression_operands: IlPool<IlExprId>,
    operations: Vec<PCodeToECodeEffect>,
    operation_operands: IlPool<IlExprId>,
}

impl Default for PCodeToECodeBuffer {
    fn default() -> Self {
        Self {
            call_preserved_registers: Vec::new(),
            expressions: Vec::new(),
            expression_operands: IlPool::new(),
            operations: Vec::new(),
            operation_operands: IlPool::new(),
        }
    }
}

impl PCodeToECodeBuffer {
    pub(crate) fn expressions(&self) -> &[PCodeToECodeExpr] {
        &self.expressions
    }

    pub(crate) fn ops(&self) -> &[PCodeToECodeEffect] {
        &self.operations
    }

    pub(crate) fn call_preserved_registers(&self) -> &[RegisterId] {
        &self.call_preserved_registers
    }

    pub(crate) fn expression_operands_for(&self, expression: &PCodeToECodeExpr) -> &[IlExprId] {
        expression
            .operands()
            .slice(self.expression_operands.values())
    }

    pub(crate) fn op_operands_for(&self, operation: &PCodeToECodeEffect) -> &[IlExprId] {
        operation.operands().slice(self.operation_operands.values())
    }

    pub(crate) fn set_call_preserved_registers(&mut self, registers: Vec<RegisterId>) {
        self.call_preserved_registers = registers;
        self.call_preserved_registers.sort_unstable();
        self.call_preserved_registers.dedup();
    }

    pub(crate) fn push_expression(
        &mut self,
        expression: PCodeToECodeExpr,
    ) -> Result<IlExprId, IlError> {
        let id = IlExprId::try_from_index(self.expressions.len())?;
        self.expressions.push(expression);
        Ok(id)
    }

    pub(crate) fn push_expression_operands(
        &mut self,
        operands: impl IntoIterator<Item = IlExprId>,
    ) -> Result<IlIndexRange, IlError> {
        self.expression_operands.append(operands)
    }

    pub(crate) fn push_op(&mut self, operation: PCodeToECodeEffect) -> Result<IlOpId, IlError> {
        let id = IlOpId::try_from_index(self.operations.len())?;
        self.operations.push(operation);
        Ok(id)
    }

    pub(crate) fn push_op_operands(
        &mut self,
        operands: impl IntoIterator<Item = IlExprId>,
    ) -> Result<IlIndexRange, IlError> {
        self.operation_operands.append(operands)
    }

    fn push_nullary(
        &mut self,
        kind: PCodeToECodeExprKind,
        width: u32,
        immediate: u64,
    ) -> Result<IlExprId, IlError> {
        self.push_expression(PCodeToECodeExpr::new(
            kind,
            width,
            IlIndexRange::EMPTY,
            immediate,
            None,
        ))
    }

    pub(crate) fn constant(&mut self, width: u32, value: u64) -> Result<IlExprId, IlError> {
        self.push_nullary(
            PCodeToECodeExprKind::Op(ECodeOpcode::Constant),
            width,
            value,
        )
    }

    pub(crate) fn address(&mut self, width: u32, offset: u64) -> Result<IlExprId, IlError> {
        self.push_nullary(
            PCodeToECodeExprKind::Op(ECodeOpcode::Address),
            width,
            offset,
        )
    }

    pub(crate) fn undefined(&mut self, width: u32, discriminant: u64) -> Result<IlExprId, IlError> {
        self.push_nullary(
            PCodeToECodeExprKind::Op(ECodeOpcode::Undefined),
            width,
            discriminant,
        )
    }

    pub(crate) fn read_register(
        &mut self,
        register: RegisterId,
        width: u32,
    ) -> Result<IlExprId, IlError> {
        self.push_nullary(PCodeToECodeExprKind::ReadRegister, width, register.value())
    }

    pub(crate) fn read_flag(&mut self, flag: FlagId, width: u32) -> Result<IlExprId, IlError> {
        self.push_nullary(PCodeToECodeExprKind::ReadFlag, width, flag.value())
    }

    pub(crate) fn apply(
        &mut self,
        opcode: ECodeOpcode,
        width: u32,
        operands: &[IlExprId],
        immediate: u64,
        address_space: Option<AddressSpaceId>,
    ) -> Result<IlExprId, IlError> {
        let operands = self.push_expression_operands(operands.iter().copied())?;
        self.push_expression(PCodeToECodeExpr::new(
            PCodeToECodeExprKind::Op(opcode),
            width,
            operands,
            immediate,
            address_space,
        ))
    }

    pub(crate) fn write_register(
        &mut self,
        register: RegisterId,
        value: IlExprId,
    ) -> Result<(), IlError> {
        self.push_op(
            PCodeToECodeEffect::new(
                ECodeOpcode::WriteRegister,
                IlIndexRange::EMPTY,
                Some(value),
                None,
                None,
            )
            .with_immediate(register.value()),
        )?;
        Ok(())
    }

    pub(crate) fn write_flag(&mut self, flag: FlagId, value: IlExprId) -> Result<(), IlError> {
        self.push_op(
            PCodeToECodeEffect::new(
                ECodeOpcode::WriteFlag,
                IlIndexRange::EMPTY,
                Some(value),
                None,
                None,
            )
            .with_immediate(flag.value()),
        )?;
        Ok(())
    }

    pub(crate) fn store(
        &mut self,
        operands: &[IlExprId],
        address_space: Option<AddressSpaceId>,
    ) -> Result<(), IlError> {
        let operands = self.push_op_operands(operands.iter().copied())?;
        self.push_op(PCodeToECodeEffect::new(
            ECodeOpcode::Store,
            operands,
            None,
            None,
            address_space,
        ))?;
        Ok(())
    }

    pub(crate) fn direct_flow(
        &mut self,
        opcode: ECodeOpcode,
        target: Address,
        operands: &[IlExprId],
    ) -> Result<(), IlError> {
        let operands = self.push_op_operands(operands.iter().copied())?;
        self.push_op(PCodeToECodeEffect::new(
            opcode,
            operands,
            None,
            Some(target),
            None,
        ))?;
        Ok(())
    }

    pub(crate) fn indirect_flow(
        &mut self,
        opcode: ECodeOpcode,
        operands: &[IlExprId],
        address_space: Option<AddressSpaceId>,
    ) -> Result<(), IlError> {
        let operands = self.push_op_operands(operands.iter().copied())?;
        self.push_op(PCodeToECodeEffect::new(
            opcode,
            operands,
            None,
            None,
            address_space,
        ))?;
        Ok(())
    }

    pub(crate) fn intrinsic(
        &mut self,
        intrinsic: u64,
        operands: &[IlExprId],
        address_space: Option<AddressSpaceId>,
    ) -> Result<(), IlError> {
        let operands = self.push_op_operands(operands.iter().copied())?;
        self.push_op(
            PCodeToECodeEffect::new(ECodeOpcode::Intrinsic, operands, None, None, address_space)
                .with_immediate(intrinsic),
        )?;
        Ok(())
    }

    pub(crate) fn trap(
        &mut self,
        intrinsic: u64,
        address_space: Option<AddressSpaceId>,
    ) -> Result<(), IlError> {
        self.push_op(
            PCodeToECodeEffect::new(
                ECodeOpcode::Trap,
                IlIndexRange::EMPTY,
                None,
                None,
                address_space,
            )
            .with_immediate(intrinsic),
        )?;
        Ok(())
    }
}
