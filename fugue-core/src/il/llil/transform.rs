use rustc_hash::FxHashMap;

use crate::il::common::{
    ArtefactHeader, ExpressionId, Finish, IlError, IrLevel, PackedRange, Transform,
    TransformContext,
};
use crate::il::llil::{
    Expression, ExpressionOpcode, LLIL_SCHEMA_VERSION, LlilBody, LlilBuilder, Statement,
    StatementOpcode,
};
use crate::il::pcode::{Location, LocationId, Opcode, Operation, PCodeBody};

#[derive(Debug, Default)]
pub struct PCodeToLlil;

impl Transform<PCodeBody, LlilBody> for PCodeToLlil {
    fn transform(
        &mut self,
        source: &PCodeBody,
        context: &mut TransformContext<'_>,
    ) -> Result<LlilBody, IlError> {
        context.check_cancelled()?;

        let mut header = ArtefactHeader::new(
            source.header().function(),
            IrLevel::Llil,
            LLIL_SCHEMA_VERSION,
            source.header().input_revision(),
        );
        header.set_parent_digest(source.header().content_digest());
        let mut builder = LlilBuilder::new(header, source.common().clone());
        let mut lowering = LlilLowering::new(source, &mut builder);

        let body = match lowering.lower(context) {
            Ok(()) => {
                drop(lowering);
                builder.finish(context.cancellation())
            }
            Err(error) => Err(error),
        };

        context.finish(body)
    }
}

struct LlilLowering<'a, 'b> {
    source: &'a PCodeBody,
    builder: &'b mut LlilBuilder,
    values: FxHashMap<LocationId, ExpressionId>,
}

impl<'a, 'b> LlilLowering<'a, 'b> {
    fn new(source: &'a PCodeBody, builder: &'b mut LlilBuilder) -> Self {
        Self {
            source,
            builder,
            values: FxHashMap::default(),
        }
    }

    fn lower(&mut self, context: &mut TransformContext<'_>) -> Result<(), IlError> {
        for operation in self.source.operations() {
            context.check_cancelled()?;
            self.lower_operation(operation)?;
        }

        Ok(())
    }

    fn lower_operation(&mut self, operation: &Operation) -> Result<(), IlError> {
        match operation.opcode() {
            Opcode::Store => self.lower_store(operation),
            Opcode::Branch => self.lower_direct_flow(operation, StatementOpcode::Branch),
            Opcode::CBranch => {
                self.lower_direct_flow(operation, StatementOpcode::ConditionalBranch)
            }
            Opcode::IBranch => self.lower_indirect_flow(operation, StatementOpcode::BranchIndirect),
            Opcode::Call => self.lower_direct_flow(operation, StatementOpcode::Call),
            Opcode::ICall => self.lower_indirect_flow(operation, StatementOpcode::CallIndirect),
            Opcode::Return => self.lower_indirect_flow(operation, StatementOpcode::Return),
            opcode => self.lower_expression_operation(operation, opcode),
        }
    }

    fn lower_expression_operation(
        &mut self,
        operation: &Operation,
        opcode: Opcode,
    ) -> Result<(), IlError> {
        let Some(output) = operation.output() else {
            return Err(IlError::pcode_missing_output());
        };
        let output_width = self.location(output)?.width() as u32 * 8;
        let operands = self.lower_expression_operands(operation)?;
        let expression_opcode = self.expression_opcode(opcode)?;
        let expression = Expression::new(
            expression_opcode,
            output_width,
            operands,
            operation.immediate() as u64,
            operation.effect_space(),
        );
        let expression = self.builder.push_expression(expression)?;

        self.values.insert(output, expression);

        if self.location(output)?.is_register() {
            self.builder.push_statement(
                Statement::new(
                    StatementOpcode::WriteRegister,
                    PackedRange::EMPTY,
                    Some(expression),
                    None,
                    None,
                )
                .with_immediate(output.value() as u64),
            )?;
        }

        Ok(())
    }

    fn lower_store(&mut self, operation: &Operation) -> Result<(), IlError> {
        let operands = self.lower_statement_operands(operation)?;

        self.builder.push_statement(Statement::new(
            StatementOpcode::Store,
            operands,
            None,
            None,
            operation.effect_space(),
        ))?;

        Ok(())
    }

    fn lower_direct_flow(
        &mut self,
        operation: &Operation,
        opcode: StatementOpcode,
    ) -> Result<(), IlError> {
        let operands = self.lower_statement_operands(operation)?;
        let target =
            self.source
                .target(operation.immediate())
                .ok_or(IlError::range_out_of_bounds(
                    operation.immediate(),
                    self.source.targets().len(),
                ))?;

        self.builder
            .push_statement(Statement::new(opcode, operands, None, Some(target), None))?;

        Ok(())
    }

    fn lower_indirect_flow(
        &mut self,
        operation: &Operation,
        opcode: StatementOpcode,
    ) -> Result<(), IlError> {
        let operands = self.lower_statement_operands(operation)?;

        self.builder.push_statement(Statement::new(
            opcode,
            operands,
            None,
            None,
            operation.effect_space(),
        ))?;

        Ok(())
    }

    fn lower_expression_operands(&mut self, operation: &Operation) -> Result<PackedRange, IlError> {
        let operands = self.lower_operand_values(operation)?;

        self.builder.push_expression_operands(operands)
    }

    fn lower_statement_operands(&mut self, operation: &Operation) -> Result<PackedRange, IlError> {
        let operands = self.lower_operand_values(operation)?;

        self.builder.push_statement_operands(operands)
    }

    fn lower_operand_values(
        &mut self,
        operation: &Operation,
    ) -> Result<Vec<ExpressionId>, IlError> {
        let operands = self
            .source
            .operation_operands(operation)?
            .iter()
            .map(|operand| self.lower_location(*operand))
            .collect::<Result<Vec<_>, IlError>>()?;

        Ok(operands)
    }

    fn lower_location(&mut self, id: LocationId) -> Result<ExpressionId, IlError> {
        if let Some(expression) = self.values.get(&id).copied() {
            return Ok(expression);
        }

        let location = *self.location(id)?;
        let expression = if location.is_constant() {
            Expression::new(
                ExpressionOpcode::Constant,
                location.width() as u32 * 8,
                PackedRange::EMPTY,
                location.offset(),
                None,
            )
        } else {
            Expression::new(
                ExpressionOpcode::ReadRegister,
                location.width() as u32 * 8,
                PackedRange::EMPTY,
                id.value() as u64,
                None,
            )
        };
        let expression = self.builder.push_expression(expression)?;

        self.values.insert(id, expression);

        Ok(expression)
    }

    fn location(&self, id: LocationId) -> Result<&Location, IlError> {
        self.source.location(id).ok_or(IlError::range_out_of_bounds(
            id.value(),
            self.source.locations().len(),
        ))
    }

    fn expression_opcode(&self, opcode: Opcode) -> Result<ExpressionOpcode, IlError> {
        match opcode {
            Opcode::Copy => Ok(ExpressionOpcode::Copy),
            Opcode::Load => Ok(ExpressionOpcode::Load),
            Opcode::IntAdd => Ok(ExpressionOpcode::Add),
            Opcode::IntSub => Ok(ExpressionOpcode::Sub),
            Opcode::IntMul => Ok(ExpressionOpcode::Mul),
            Opcode::IntDiv => Ok(ExpressionOpcode::UnsignedDiv),
            Opcode::IntSignedDiv => Ok(ExpressionOpcode::SignedDiv),
            Opcode::IntRem => Ok(ExpressionOpcode::UnsignedRem),
            Opcode::IntSignedRem => Ok(ExpressionOpcode::SignedRem),
            Opcode::IntLeftShift => Ok(ExpressionOpcode::LeftShift),
            Opcode::IntRightShift => Ok(ExpressionOpcode::LogicalRightShift),
            Opcode::IntSignedRightShift => Ok(ExpressionOpcode::ArithmeticRightShift),
            Opcode::IntEq
            | Opcode::IntNotEq
            | Opcode::IntLess
            | Opcode::IntSignedLess
            | Opcode::IntLessEq
            | Opcode::IntSignedLessEq
            | Opcode::FloatEq
            | Opcode::FloatNotEq
            | Opcode::FloatLess
            | Opcode::FloatLessEq => Ok(ExpressionOpcode::Compare),
            Opcode::IntCarry | Opcode::IntSignedCarry => Ok(ExpressionOpcode::Carry),
            Opcode::IntSignedBorrow => Ok(ExpressionOpcode::Borrow),
            Opcode::IntXor | Opcode::IntOr | Opcode::IntAnd => Ok(ExpressionOpcode::Bool),
            Opcode::IntNot => Ok(ExpressionOpcode::Not),
            Opcode::IntNeg => Ok(ExpressionOpcode::Negate),
            Opcode::CountOnes => Ok(ExpressionOpcode::CountOnes),
            Opcode::CountLeadingZeros => Ok(ExpressionOpcode::CountLeadingZeros),
            Opcode::ZeroExt => Ok(ExpressionOpcode::ZeroExtend),
            Opcode::SignExt => Ok(ExpressionOpcode::SignExtend),
            Opcode::BoolAnd | Opcode::BoolOr | Opcode::BoolXor => Ok(ExpressionOpcode::Bool),
            Opcode::BoolNot => Ok(ExpressionOpcode::Not),
            Opcode::Subpiece => Ok(ExpressionOpcode::Extract),
            Opcode::FloatAdd => Ok(ExpressionOpcode::Add),
            Opcode::FloatSub => Ok(ExpressionOpcode::Sub),
            Opcode::FloatMul => Ok(ExpressionOpcode::Mul),
            Opcode::FloatDiv => Ok(ExpressionOpcode::UnsignedDiv),
            Opcode::FloatNeg => Ok(ExpressionOpcode::Negate),
            Opcode::FloatAbs
            | Opcode::FloatSqrt
            | Opcode::FloatCeiling
            | Opcode::FloatFloor
            | Opcode::FloatRound
            | Opcode::FloatIsNan
            | Opcode::FloatToInt
            | Opcode::FloatToFloat
            | Opcode::IntToFloat
            | Opcode::UserOp => Ok(ExpressionOpcode::IntrinsicResult),
            Opcode::Store
            | Opcode::Branch
            | Opcode::CBranch
            | Opcode::IBranch
            | Opcode::Call
            | Opcode::ICall
            | Opcode::Return => Err(IlError::pcode_effect_opcode_as_llil_expression()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::common::{BuildStatus, CommonBody, Scratch};
    use crate::il::pcode::{
        LifterSpaceHandle, Location, Opcode, Operation, PCODE_SCHEMA_VERSION, PCodeBuilder,
    };
    use crate::ir::{Address, FunctionId};
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn empty_pcode_lowers_to_empty_llil() {
        let source_header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            11,
        );
        let source = PCodeBuilder::new(source_header, CommonBody::default())
            .finish(&BuildStatus::new())
            .unwrap();
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(1024);
        let mut context = TransformContext::new(&status, &mut scratch);
        let mut transform = PCodeToLlil;

        let lowered = transform.transform(&source, &mut context).unwrap();

        assert_eq!(lowered.header().level(), IrLevel::Llil);
        assert!(lowered.statements().is_empty());
    }

    #[test]
    fn copy_pcode_lowers_to_llil_write() {
        let source = copy_source();
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(1024);
        let mut context = TransformContext::new(&status, &mut scratch);
        let mut transform = PCodeToLlil;

        let lowered = transform.transform(&source, &mut context).unwrap();

        assert_eq!(lowered.expressions().len(), 2);
        assert_eq!(lowered.expressions()[1].opcode(), ExpressionOpcode::Copy);
        assert_eq!(lowered.statements().len(), 1);
        assert_eq!(
            lowered.statements()[0].opcode(),
            StatementOpcode::WriteRegister
        );
        assert_eq!(lowered.statements()[0].immediate(), 2);
    }

    #[test]
    fn unique_output_pcode_does_not_lower_to_register_write() {
        let source = unique_copy_source();
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(1024);
        let mut context = TransformContext::new(&status, &mut scratch);
        let mut transform = PCodeToLlil;

        let lowered = transform.transform(&source, &mut context).unwrap();

        assert_eq!(lowered.expressions().len(), 2);
        assert!(lowered.statements().is_empty());
    }

    #[test]
    fn store_pcode_lowers_to_llil_store_with_fugue_space() {
        let source = store_source();
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(1024);
        let mut context = TransformContext::new(&status, &mut scratch);
        let mut transform = PCodeToLlil;

        let lowered = transform.transform(&source, &mut context).unwrap();

        assert_eq!(lowered.statements().len(), 1);
        assert_eq!(lowered.statements()[0].opcode(), StatementOpcode::Store);
        assert_eq!(
            lowered.statements()[0].address_space(),
            Some(AddressSpaceId::new(7))
        );
    }

    #[test]
    fn branch_pcode_lowers_to_llil_branch_with_target() {
        let target = Address::new(AddressSpaceId::new(3), 0x2000u64);
        let source = branch_source(target);
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(1024);
        let mut context = TransformContext::new(&status, &mut scratch);
        let mut transform = PCodeToLlil;

        let lowered = transform.transform(&source, &mut context).unwrap();

        assert_eq!(lowered.statements().len(), 1);
        assert_eq!(lowered.statements()[0].opcode(), StatementOpcode::Branch);
        assert_eq!(lowered.statements()[0].address(), Some(target));
    }

    #[test]
    fn return_pcode_lowers_to_llil_return_with_fugue_space() {
        let source = return_source(AddressSpaceId::new(9));
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(1024);
        let mut context = TransformContext::new(&status, &mut scratch);
        let mut transform = PCodeToLlil;

        let lowered = transform.transform(&source, &mut context).unwrap();

        assert_eq!(lowered.statements().len(), 1);
        assert_eq!(lowered.statements()[0].opcode(), StatementOpcode::Return);
        assert_eq!(
            lowered.statements()[0].address_space(),
            Some(AddressSpaceId::new(9))
        );
    }

    fn pcode_header() -> ArtefactHeader {
        ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            11,
        )
    }

    fn copy_source() -> PCodeBody {
        let mut builder = PCodeBuilder::new(pcode_header(), CommonBody::default());
        let input = builder
            .push_location(Location::new(
                LifterSpaceHandle::new(0),
                1,
                8,
                Location::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .push_location(Location::new(
                LifterSpaceHandle::new(1),
                8,
                8,
                Location::REGISTER,
            ))
            .unwrap();
        let operands = builder.push_operands([input]).unwrap();

        builder.push_operation(Operation::new(
            Opcode::Copy,
            Some(output),
            operands,
            0,
            None,
        ));

        builder.finish(&BuildStatus::new()).unwrap()
    }

    fn unique_copy_source() -> PCodeBody {
        let mut builder = PCodeBuilder::new(pcode_header(), CommonBody::default());
        let input = builder
            .push_location(Location::new(
                LifterSpaceHandle::new(0),
                1,
                8,
                Location::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .push_location(Location::new(
                LifterSpaceHandle::new(2),
                8,
                8,
                Location::UNIQUE,
            ))
            .unwrap();
        let operands = builder.push_operands([input]).unwrap();

        builder.push_operation(Operation::new(
            Opcode::Copy,
            Some(output),
            operands,
            0,
            None,
        ));

        builder.finish(&BuildStatus::new()).unwrap()
    }

    fn store_source() -> PCodeBody {
        let mut builder = PCodeBuilder::new(pcode_header(), CommonBody::default());
        let offset = builder
            .push_location(Location::new(
                LifterSpaceHandle::new(0),
                0x1000,
                8,
                Location::CONSTANT,
            ))
            .unwrap();
        let value = builder
            .push_location(Location::new(
                LifterSpaceHandle::new(0),
                0xff,
                1,
                Location::CONSTANT,
            ))
            .unwrap();
        let operands = builder.push_operands([offset, value]).unwrap();

        builder.push_operation(Operation::new(
            Opcode::Store,
            None,
            operands,
            0,
            Some(AddressSpaceId::new(7)),
        ));

        builder.finish(&BuildStatus::new()).unwrap()
    }

    fn branch_source(target: Address) -> PCodeBody {
        let mut builder = PCodeBuilder::new(pcode_header(), CommonBody::default());
        let target_location = builder
            .push_location(Location::new(
                LifterSpaceHandle::new(0),
                target.offset(),
                8,
                Location::CONSTANT,
            ))
            .unwrap();
        let operands = builder.push_operands([target_location]).unwrap();
        let target = builder.push_target(target).unwrap();

        builder.push_operation(Operation::new(Opcode::Branch, None, operands, target, None));

        builder.finish(&BuildStatus::new()).unwrap()
    }

    fn return_source(space: AddressSpaceId) -> PCodeBody {
        let mut builder = PCodeBuilder::new(pcode_header(), CommonBody::default());
        let target = builder
            .push_location(Location::new(
                LifterSpaceHandle::new(0),
                0x1000,
                8,
                Location::CONSTANT,
            ))
            .unwrap();
        let operands = builder.push_operands([target]).unwrap();

        builder.push_operation(Operation::new(
            Opcode::Return,
            None,
            operands,
            0,
            Some(space),
        ));

        builder.finish(&BuildStatus::new()).unwrap()
    }
}
