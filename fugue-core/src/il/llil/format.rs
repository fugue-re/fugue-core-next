use std::fmt;

use crate::il::common::ExpressionId;
use crate::il::llil::{Expression, ExpressionOpcode, LlilBody, Statement, StatementOpcode};

#[derive(Debug, Copy, Clone)]
pub struct ExpressionOpcodeDisplay(pub ExpressionOpcode);

impl fmt::Display for ExpressionOpcodeDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnemonic = self.0.mnemonic();
        write!(f, "llil.{mnemonic}")
    }
}

#[derive(Debug, Copy, Clone)]
pub struct StatementOpcodeDisplay(pub StatementOpcode);

impl fmt::Display for StatementOpcodeDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnemonic = self.0.mnemonic();
        write!(f, "llil.{mnemonic}")
    }
}

#[derive(Debug, Copy, Clone)]
pub struct LlilBodyDisplay<'a> {
    body: &'a LlilBody,
}

impl<'a> LlilBodyDisplay<'a> {
    pub const fn new(body: &'a LlilBody) -> Self {
        Self { body }
    }
}

impl fmt::Display for LlilBodyDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, expression) in self.body.expressions().iter().enumerate() {
            let display = ExpressionDisplay::new(self.body, index, expression);
            writeln!(f, "{display}")?;
        }

        for (index, statement) in self.body.statements().iter().enumerate() {
            let display = StatementDisplay::new(self.body, index, statement);
            write!(f, "{display}")?;

            if index + 1 < self.body.statements().len() {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ExpressionDisplay<'a> {
    body: &'a LlilBody,
    index: usize,
    expression: &'a Expression,
}

impl<'a> ExpressionDisplay<'a> {
    pub const fn new(body: &'a LlilBody, index: usize, expression: &'a Expression) -> Self {
        Self {
            body,
            index,
            expression,
        }
    }

    fn write_operand(&self, f: &mut fmt::Formatter<'_>, operand: ExpressionId) -> fmt::Result {
        let index = operand.index();
        write!(f, "%e{index}")
    }

    fn write_operands(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operands = self
            .body
            .expression_operands_for(self.expression)
            .map_err(|_| fmt::Error)?;

        for (index, operand) in operands.iter().enumerate() {
            if index == 0 {
                write!(f, " ")?;
            } else {
                write!(f, ", ")?;
            }

            self.write_operand(f, *operand)?;
        }

        Ok(())
    }

    fn write_metadata(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(space) = self.expression.address_space() {
            let space = space.index();
            write!(f, " @fugue_space<{space}>")?;
        }

        match self.expression.opcode() {
            ExpressionOpcode::Constant | ExpressionOpcode::Address => {
                let immediate = self.expression.immediate();
                write!(f, " 0x{immediate:x}")?;
            }
            ExpressionOpcode::ReadRegister => {
                let register = self.expression.immediate();
                write!(f, " register<{register}>")?;
            }
            ExpressionOpcode::ReadFlag => {
                let flag = self.expression.immediate();
                write!(f, " flag<{flag}>")?;
            }
            ExpressionOpcode::IntrinsicResult => {
                let intrinsic = self.expression.immediate();
                write!(f, " intrinsic<{intrinsic}>")?;
            }
            ExpressionOpcode::Undefined => {
                let origin = self.expression.immediate();
                write!(f, " origin<{origin}>")?;
            }
            _ if self.expression.immediate() != 0 => {
                let immediate = self.expression.immediate();
                write!(f, " imm<{immediate}>")?;
            }
            _ => {}
        }

        Ok(())
    }
}

impl fmt::Display for ExpressionDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;
        let width = self.expression.width();
        let opcode = ExpressionOpcodeDisplay(self.expression.opcode());

        write!(f, "%e{index}:bits<{width}> = {opcode}")?;
        self.write_metadata(f)?;
        self.write_operands(f)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct StatementDisplay<'a> {
    body: &'a LlilBody,
    index: usize,
    statement: &'a Statement,
}

impl<'a> StatementDisplay<'a> {
    pub const fn new(body: &'a LlilBody, index: usize, statement: &'a Statement) -> Self {
        Self {
            body,
            index,
            statement,
        }
    }

    fn write_operand(&self, f: &mut fmt::Formatter<'_>, operand: ExpressionId) -> fmt::Result {
        let index = operand.index();
        write!(f, "%e{index}")
    }

    fn write_operands(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operands = self
            .body
            .statement_operands_for(self.statement)
            .map_err(|_| fmt::Error)?;

        for (index, operand) in operands.iter().enumerate() {
            if index == 0 && self.statement.value().is_none() {
                write!(f, " ")?;
            } else {
                write!(f, ", ")?;
            }

            self.write_operand(f, *operand)?;
        }

        Ok(())
    }

    fn write_metadata(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.statement.opcode() {
            StatementOpcode::WriteRegister => {
                let register = self.statement.immediate();
                write!(f, " register<{register}>")?;
            }
            StatementOpcode::WriteFlag => {
                let flag = self.statement.immediate();
                write!(f, " flag<{flag}>")?;
            }
            _ if self.statement.immediate() != 0 => {
                let immediate = self.statement.immediate();
                write!(f, " imm<{immediate}>")?;
            }
            _ => {}
        }

        if let Some(space) = self.statement.address_space() {
            let space = space.index();
            write!(f, " @fugue_space<{space}>")?;
        }

        if let Some(address) = self.statement.address() {
            write!(f, " -> {address}")?;
        }

        Ok(())
    }
}

impl fmt::Display for StatementDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;
        let opcode = StatementOpcodeDisplay(self.statement.opcode());

        write!(f, "@s{index} {opcode}")?;
        self.write_metadata(f)?;

        if let Some(value) = self.statement.value() {
            write!(f, " value=")?;
            self.write_operand(f, value)?;
        }

        self.write_operands(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::common::{
        ArtefactHeader, BuildStatus, CommonBody, Finish, IrLevel, PackedRange,
    };
    use crate::il::llil::{LLIL_SCHEMA_VERSION, LlilBuilder};
    use crate::ir::{Address, FunctionId};
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn llil_body_display_is_deterministic() {
        let header =
            ArtefactHeader::new(FunctionId::default(), IrLevel::Llil, LLIL_SCHEMA_VERSION, 0);
        let mut builder = LlilBuilder::new(header, CommonBody::default());
        let value = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                64,
                PackedRange::EMPTY,
                0x2a,
                None,
            ))
            .unwrap();
        let address = builder
            .push_expression(Expression::new(
                ExpressionOpcode::Constant,
                64,
                PackedRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let operands = builder.push_statement_operands([address, value]).unwrap();

        builder
            .push_statement(Statement::new(
                StatementOpcode::Store,
                operands,
                None,
                None,
                Some(AddressSpaceId::new(3)),
            ))
            .unwrap();

        let branch_operands = builder.push_statement_operands([value]).unwrap();
        builder
            .push_statement(Statement::new(
                StatementOpcode::Branch,
                branch_operands,
                None,
                Some(Address::new(AddressSpaceId::new(2), 0x2000u64)),
                None,
            ))
            .unwrap();

        let body = builder.finish(&BuildStatus::new()).unwrap();

        assert_eq!(
            body.display().to_string(),
            "%e0:bits<64> = llil.const 0x2a\n\
             %e1:bits<64> = llil.const 0x1000\n\
             @s0 llil.store @fugue_space<3> %e1, %e0\n\
             @s1 llil.branch -> 0x2:0x2000 %e0"
        );
    }
}
