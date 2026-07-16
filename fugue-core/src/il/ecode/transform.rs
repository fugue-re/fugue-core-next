use rustc_hash::FxHashMap;

use crate::analysis::control::CancellationToken;
use crate::il::common::{IlError, IlExprId, IlHeader, IlIndexRange, IlLevel};
use crate::il::ecode::{
    ECODE_SCHEMA_VERSION, ECodeBuilder, ECodeExpr, ECodeExprOpcode, ECodeIr, ECodeStmt,
    ECodeStmtOpcode,
};
use crate::il::pcode::{PCodeIr, PCodeLocation, PCodeLocationId, PCodeOp, PCodeOpcode};

#[derive(Debug, Default)]
pub struct PCodeToECode;

impl PCodeToECode {
    pub fn transform(
        &mut self,
        source: &PCodeIr,
        cancellation: &CancellationToken,
    ) -> Result<ECodeIr, IlError> {
        cancellation.check()?;

        let header = IlHeader::new(
            source.header().function(),
            ECODE_SCHEMA_VERSION,
            source.header().input_revision(),
        );
        let mut builder = ECodeBuilder::new(header, source.graph().clone());
        builder.replace_source_spans(source.source_spans().to_vec());
        let mut lifting = ECodeLifting::new(source, &mut builder);

        lifting.lift(cancellation)?;
        drop(lifting);

        builder.build(cancellation)
    }
}

struct ECodeLifting<'a, 'b> {
    source: &'a PCodeIr,
    builder: &'b mut ECodeBuilder,
    values: FxHashMap<PCodeLocationId, IlExprId>,
}

impl<'a, 'b> ECodeLifting<'a, 'b> {
    fn new(source: &'a PCodeIr, builder: &'b mut ECodeBuilder) -> Self {
        Self {
            source,
            builder,
            values: FxHashMap::default(),
        }
    }

    fn lift(&mut self, cancellation: &CancellationToken) -> Result<(), IlError> {
        for operation in self.source.operations() {
            cancellation.check()?;
            self.lift_operation(operation)?;
        }

        Ok(())
    }

    fn lift_operation(&mut self, operation: &PCodeOp) -> Result<(), IlError> {
        match operation.opcode() {
            PCodeOpcode::Store => self.lift_store(operation),
            PCodeOpcode::Branch => self.lift_direct_flow(operation, ECodeStmtOpcode::Branch),
            PCodeOpcode::CBranch => {
                self.lift_direct_flow(operation, ECodeStmtOpcode::ConditionalBranch)
            }
            PCodeOpcode::IBranch => {
                self.lift_indirect_flow(operation, ECodeStmtOpcode::BranchIndirect)
            }
            PCodeOpcode::Call => self.lift_direct_flow(operation, ECodeStmtOpcode::Call),
            PCodeOpcode::ICall => self.lift_indirect_flow(operation, ECodeStmtOpcode::CallIndirect),
            PCodeOpcode::Return => self.lift_indirect_flow(operation, ECodeStmtOpcode::Return),
            opcode => self.lift_expression_operation(operation, opcode),
        }
    }

    fn lift_expression_operation(
        &mut self,
        operation: &PCodeOp,
        opcode: PCodeOpcode,
    ) -> Result<(), IlError> {
        let Some(output) = operation.output() else {
            return Err(IlError::missing_component(IlLevel::PCode, "output"));
        };
        let output_width = self.location(output).width() as u32 * 8;
        let operands = self.lift_expression_operands(operation)?;
        let expression_opcode = self.expression_opcode(opcode)?;
        let expression = ECodeExpr::new(
            expression_opcode,
            output_width,
            operands,
            operation.immediate() as u64,
            operation.effect_space(),
        );
        let expression = self.builder.push_expression(expression)?;

        self.values.insert(output, expression);

        if self.location(output).is_register() {
            self.builder.push_statement(
                ECodeStmt::new(
                    ECodeStmtOpcode::WriteRegister,
                    IlIndexRange::EMPTY,
                    Some(expression),
                    None,
                    None,
                )
                .with_immediate(output.value() as u64),
            )?;
        }

        Ok(())
    }

    fn lift_store(&mut self, operation: &PCodeOp) -> Result<(), IlError> {
        let operands = self.lift_statement_operands(operation)?;

        self.builder.push_statement(ECodeStmt::new(
            ECodeStmtOpcode::Store,
            operands,
            None,
            None,
            operation.effect_space(),
        ))?;

        Ok(())
    }

    fn lift_direct_flow(
        &mut self,
        operation: &PCodeOp,
        opcode: ECodeStmtOpcode,
    ) -> Result<(), IlError> {
        let operands = self.lift_statement_operands(operation)?;
        let target = self
            .source
            .target(operation.immediate())
            .expect("direct flow target is within the target pool");

        self.builder
            .push_statement(ECodeStmt::new(opcode, operands, None, Some(target), None))?;

        Ok(())
    }

    fn lift_indirect_flow(
        &mut self,
        operation: &PCodeOp,
        opcode: ECodeStmtOpcode,
    ) -> Result<(), IlError> {
        let operands = self.lift_statement_operands(operation)?;

        self.builder.push_statement(ECodeStmt::new(
            opcode,
            operands,
            None,
            None,
            operation.effect_space(),
        ))?;

        Ok(())
    }

    fn lift_expression_operands(&mut self, operation: &PCodeOp) -> Result<IlIndexRange, IlError> {
        let operands = self.lift_operand_values(operation)?;

        self.builder.push_expression_operands(operands)
    }

    fn lift_statement_operands(&mut self, operation: &PCodeOp) -> Result<IlIndexRange, IlError> {
        let operands = self.lift_operand_values(operation)?;

        self.builder.push_statement_operands(operands)
    }

    fn lift_operand_values(&mut self, operation: &PCodeOp) -> Result<Vec<IlExprId>, IlError> {
        let operands = self
            .source
            .operation_operands(operation)
            .iter()
            .map(|operand| self.lift_location(*operand))
            .collect::<Result<Vec<_>, IlError>>()?;

        Ok(operands)
    }

    fn lift_location(&mut self, id: PCodeLocationId) -> Result<IlExprId, IlError> {
        if let Some(expression) = self.values.get(&id).copied() {
            return Ok(expression);
        }

        let location = *self.location(id);
        let expression = if location.is_constant() {
            ECodeExpr::new(
                ECodeExprOpcode::Constant,
                location.width() as u32 * 8,
                IlIndexRange::EMPTY,
                location.offset(),
                None,
            )
        } else {
            ECodeExpr::new(
                ECodeExprOpcode::ReadRegister,
                location.width() as u32 * 8,
                IlIndexRange::EMPTY,
                id.value() as u64,
                None,
            )
        };
        let expression = self.builder.push_expression(expression)?;

        self.values.insert(id, expression);

        Ok(expression)
    }

    fn location(&self, id: PCodeLocationId) -> &PCodeLocation {
        self.source
            .location(id)
            .expect("location id is within the location pool")
    }

    fn expression_opcode(&self, opcode: PCodeOpcode) -> Result<ECodeExprOpcode, IlError> {
        match opcode {
            PCodeOpcode::Copy => Ok(ECodeExprOpcode::Copy),
            PCodeOpcode::Load => Ok(ECodeExprOpcode::Load),
            PCodeOpcode::IntAdd => Ok(ECodeExprOpcode::Add),
            PCodeOpcode::IntSub => Ok(ECodeExprOpcode::Sub),
            PCodeOpcode::IntMul => Ok(ECodeExprOpcode::Mul),
            PCodeOpcode::IntDiv => Ok(ECodeExprOpcode::UnsignedDiv),
            PCodeOpcode::IntSignedDiv => Ok(ECodeExprOpcode::SignedDiv),
            PCodeOpcode::IntRem => Ok(ECodeExprOpcode::UnsignedRem),
            PCodeOpcode::IntSignedRem => Ok(ECodeExprOpcode::SignedRem),
            PCodeOpcode::IntLeftShift => Ok(ECodeExprOpcode::LeftShift),
            PCodeOpcode::IntRightShift => Ok(ECodeExprOpcode::LogicalRightShift),
            PCodeOpcode::IntSignedRightShift => Ok(ECodeExprOpcode::ArithmeticRightShift),
            PCodeOpcode::IntEq
            | PCodeOpcode::IntNotEq
            | PCodeOpcode::IntLess
            | PCodeOpcode::IntSignedLess
            | PCodeOpcode::IntLessEq
            | PCodeOpcode::IntSignedLessEq
            | PCodeOpcode::FloatEq
            | PCodeOpcode::FloatNotEq
            | PCodeOpcode::FloatLess
            | PCodeOpcode::FloatLessEq => Ok(ECodeExprOpcode::Compare),
            PCodeOpcode::IntCarry | PCodeOpcode::IntSignedCarry => Ok(ECodeExprOpcode::Carry),
            PCodeOpcode::IntSignedBorrow => Ok(ECodeExprOpcode::Borrow),
            PCodeOpcode::IntXor | PCodeOpcode::IntOr | PCodeOpcode::IntAnd => {
                Ok(ECodeExprOpcode::Bool)
            }
            PCodeOpcode::IntNot => Ok(ECodeExprOpcode::Not),
            PCodeOpcode::IntNeg => Ok(ECodeExprOpcode::Negate),
            PCodeOpcode::CountOnes => Ok(ECodeExprOpcode::CountOnes),
            PCodeOpcode::CountLeadingZeros => Ok(ECodeExprOpcode::CountLeadingZeros),
            PCodeOpcode::ZeroExt => Ok(ECodeExprOpcode::ZeroExtend),
            PCodeOpcode::SignExt => Ok(ECodeExprOpcode::SignExtend),
            PCodeOpcode::BoolAnd | PCodeOpcode::BoolOr | PCodeOpcode::BoolXor => {
                Ok(ECodeExprOpcode::Bool)
            }
            PCodeOpcode::BoolNot => Ok(ECodeExprOpcode::Not),
            PCodeOpcode::Subpiece => Ok(ECodeExprOpcode::Extract),
            PCodeOpcode::FloatAdd => Ok(ECodeExprOpcode::Add),
            PCodeOpcode::FloatSub => Ok(ECodeExprOpcode::Sub),
            PCodeOpcode::FloatMul => Ok(ECodeExprOpcode::Mul),
            PCodeOpcode::FloatDiv => Ok(ECodeExprOpcode::UnsignedDiv),
            PCodeOpcode::FloatNeg => Ok(ECodeExprOpcode::Negate),
            PCodeOpcode::FloatAbs
            | PCodeOpcode::FloatSqrt
            | PCodeOpcode::FloatCeiling
            | PCodeOpcode::FloatFloor
            | PCodeOpcode::FloatRound
            | PCodeOpcode::FloatIsNan
            | PCodeOpcode::FloatToInt
            | PCodeOpcode::FloatToFloat
            | PCodeOpcode::IntToFloat
            | PCodeOpcode::UserOp => Ok(ECodeExprOpcode::IntrinsicResult),
            PCodeOpcode::Store
            | PCodeOpcode::Branch
            | PCodeOpcode::CBranch
            | PCodeOpcode::IBranch
            | PCodeOpcode::Call
            | PCodeOpcode::ICall
            | PCodeOpcode::Return => Err(IlError::unsupported_opcode(IlLevel::ECode)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::IlGraph;
    use crate::il::pcode::{
        LifterSpaceHandle, PCODE_SCHEMA_VERSION, PCodeBuilder, PCodeLocation,
        PCodeLocationProperties, PCodeOp, PCodeOpcode,
    };
    use crate::ir::{Address, FunctionId};
    use crate::lifter::{Language, resolve_language};
    use crate::storage::segments::space::AddressSpaceId;

    fn language() -> &'static Language {
        resolve_language("x86:LE:64").expect("test language should resolve")
    }

    #[test]
    fn empty_pcode_lifts_to_empty_ecode() {
        let source_header = IlHeader::new(FunctionId::default(), PCODE_SCHEMA_VERSION, 11);
        let source = PCodeBuilder::new(language(), source_header, IlGraph::default())
            .build(&CancellationToken::default())
            .unwrap();
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode;

        let lifted = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(lifted.header().input_revision(), 11);
        assert!(lifted.statements().is_empty());
    }

    #[test]
    fn copy_pcode_lifts_to_ecode_write() {
        let source = copy_source();
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode;

        let lifted = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        assert_eq!(lifted.expressions()[1].opcode(), ECodeExprOpcode::Copy);
        assert_eq!(lifted.statements().len(), 1);
        assert_eq!(
            lifted.statements()[0].opcode(),
            ECodeStmtOpcode::WriteRegister
        );
        assert_eq!(lifted.statements()[0].immediate(), 2);
    }

    #[test]
    fn unique_output_pcode_does_not_lift_to_register_write() {
        let source = unique_copy_source();
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode;

        let lifted = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        assert!(lifted.statements().is_empty());
    }

    #[test]
    fn store_pcode_lifts_to_ecode_store_with_fugue_space() {
        let source = store_source();
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode;

        let lifted = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(lifted.statements().len(), 1);
        assert_eq!(lifted.statements()[0].opcode(), ECodeStmtOpcode::Store);
        assert_eq!(
            lifted.statements()[0].address_space(),
            Some(AddressSpaceId::new(7))
        );
    }

    #[test]
    fn branch_pcode_lifts_to_ecode_branch_with_target() {
        let target = Address::new(AddressSpaceId::new(3), 0x2000u64);
        let source = branch_source(target);
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode;

        let lifted = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(lifted.statements().len(), 1);
        assert_eq!(lifted.statements()[0].opcode(), ECodeStmtOpcode::Branch);
        assert_eq!(lifted.statements()[0].address(), Some(target));
    }

    #[test]
    fn return_pcode_lifts_to_ecode_return_with_fugue_space() {
        let source = return_source(AddressSpaceId::new(9));
        let cancellation = CancellationToken::default();
        let mut transform = PCodeToECode;

        let lifted = transform.transform(&source, &cancellation).unwrap();

        assert_eq!(lifted.statements().len(), 1);
        assert_eq!(lifted.statements()[0].opcode(), ECodeStmtOpcode::Return);
        assert_eq!(
            lifted.statements()[0].address_space(),
            Some(AddressSpaceId::new(9))
        );
    }

    fn pcode_header() -> IlHeader {
        IlHeader::new(FunctionId::default(), PCODE_SCHEMA_VERSION, 11)
    }

    fn copy_source() -> PCodeIr {
        let mut builder = PCodeBuilder::new(language(), pcode_header(), IlGraph::default());
        let input = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(1),
                8,
                8,
                PCodeLocationProperties::REGISTER,
            ))
            .unwrap();
        let operands = builder.push_operands([input]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(output),
            operands,
            0,
            None,
        ));

        builder.build(&CancellationToken::default()).unwrap()
    }

    fn unique_copy_source() -> PCodeIr {
        let mut builder = PCodeBuilder::new(language(), pcode_header(), IlGraph::default());
        let input = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(2),
                8,
                8,
                PCodeLocationProperties::UNIQUE,
            ))
            .unwrap();
        let operands = builder.push_operands([input]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(output),
            operands,
            0,
            None,
        ));

        builder.build(&CancellationToken::default()).unwrap()
    }

    fn store_source() -> PCodeIr {
        let mut builder = PCodeBuilder::new(language(), pcode_header(), IlGraph::default());
        let offset = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                0x1000,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let value = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                0xff,
                1,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let operands = builder.push_operands([offset, value]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Store,
            None,
            operands,
            0,
            Some(AddressSpaceId::new(7)),
        ));

        builder.build(&CancellationToken::default()).unwrap()
    }

    fn branch_source(target: Address) -> PCodeIr {
        let mut builder = PCodeBuilder::new(language(), pcode_header(), IlGraph::default());
        let target_location = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                target.offset(),
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let operands = builder.push_operands([target_location]).unwrap();
        let target = builder.push_target(target).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Branch,
            None,
            operands,
            target,
            None,
        ));

        builder.build(&CancellationToken::default()).unwrap()
    }

    fn return_source(space: AddressSpaceId) -> PCodeIr {
        let mut builder = PCodeBuilder::new(language(), pcode_header(), IlGraph::default());
        let target = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                0x1000,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let operands = builder.push_operands([target]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Return,
            None,
            operands,
            0,
            Some(space),
        ));

        builder.build(&CancellationToken::default()).unwrap()
    }
}
