use std::fmt;

use crate::il::common::IlExprId;
use crate::il::ecode::{ECodeExpr, ECodeExprOpcode, ECodeIr, ECodeStmt, ECodeStmtOpcode};

fn write_operand(f: &mut fmt::Formatter<'_>, operand: IlExprId) -> fmt::Result {
    let index = operand.index();
    write!(f, "%e{index}")
}

#[derive(Debug, Copy, Clone)]
struct ECodeExprOpcodeDisplay(ECodeExprOpcode);

impl fmt::Display for ECodeExprOpcodeDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnemonic = self.0.mnemonic();
        write!(f, "ecode.{mnemonic}")
    }
}

#[derive(Debug, Copy, Clone)]
struct ECodeStmtOpcodeDisplay(ECodeStmtOpcode);

impl fmt::Display for ECodeStmtOpcodeDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnemonic = self.0.mnemonic();
        write!(f, "ecode.{mnemonic}")
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ECodeIrDisplay<'a> {
    body: &'a ECodeIr,
}

impl<'a> ECodeIrDisplay<'a> {
    pub(crate) const fn new(body: &'a ECodeIr) -> Self {
        Self { body }
    }
}

impl fmt::Display for ECodeIrDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, expression) in self.body.expressions().iter().enumerate() {
            let display = ECodeExprDisplay::new(self.body, index, expression);
            writeln!(f, "{display}")?;
        }

        for (index, statement) in self.body.statements().iter().enumerate() {
            let display = ECodeStmtDisplay::new(self.body, index, statement);
            write!(f, "{display}")?;

            if index + 1 < self.body.statements().len() {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
struct ECodeExprDisplay<'a> {
    body: &'a ECodeIr,
    index: usize,
    expression: &'a ECodeExpr,
}

impl<'a> ECodeExprDisplay<'a> {
    pub(crate) const fn new(body: &'a ECodeIr, index: usize, expression: &'a ECodeExpr) -> Self {
        Self {
            body,
            index,
            expression,
        }
    }

    fn write_operands(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operands = self.body.expression_operands_for(self.expression);

        for (index, operand) in operands.iter().enumerate() {
            if index == 0 {
                write!(f, " ")?;
            } else {
                write!(f, ", ")?;
            }

            write_operand(f, *operand)?;
        }

        Ok(())
    }

    fn write_metadata(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(space) = self.expression.address_space() {
            let space = space.index();
            write!(f, " @fugue_space<{space}>")?;
        }

        match self.expression.opcode() {
            ECodeExprOpcode::Constant | ECodeExprOpcode::Address => {
                let immediate = self.expression.immediate();
                write!(f, " 0x{immediate:x}")?;
            }
            ECodeExprOpcode::ReadRegister => {
                let register = self.expression.immediate();
                write!(f, " register<{register}>")?;
            }
            ECodeExprOpcode::ReadFlag => {
                let flag = self.expression.immediate();
                write!(f, " flag<{flag}>")?;
            }
            ECodeExprOpcode::IntrinsicResult => {
                let intrinsic = self.expression.immediate();
                write!(f, " intrinsic<{intrinsic}>")?;
            }
            ECodeExprOpcode::Undefined => {
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

impl fmt::Display for ECodeExprDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;
        let width = self.expression.width();
        let opcode = ECodeExprOpcodeDisplay(self.expression.opcode());

        write!(f, "%e{index}:bits<{width}> = {opcode}")?;
        self.write_metadata(f)?;
        self.write_operands(f)
    }
}

#[derive(Debug, Copy, Clone)]
struct ECodeStmtDisplay<'a> {
    body: &'a ECodeIr,
    index: usize,
    statement: &'a ECodeStmt,
}

impl<'a> ECodeStmtDisplay<'a> {
    pub(crate) const fn new(body: &'a ECodeIr, index: usize, statement: &'a ECodeStmt) -> Self {
        Self {
            body,
            index,
            statement,
        }
    }

    fn write_operands(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operands = self.body.statement_operands_for(self.statement);

        for (index, operand) in operands.iter().enumerate() {
            if index == 0 && self.statement.value().is_none() {
                write!(f, " ")?;
            } else {
                write!(f, ", ")?;
            }

            write_operand(f, *operand)?;
        }

        Ok(())
    }

    fn write_metadata(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.statement.opcode() {
            ECodeStmtOpcode::WriteRegister => {
                let register = self.statement.immediate();
                write!(f, " register<{register}>")?;
            }
            ECodeStmtOpcode::WriteFlag => {
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

impl fmt::Display for ECodeStmtDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;
        let opcode = ECodeStmtOpcodeDisplay(self.statement.opcode());

        write!(f, "@s{index} {opcode}")?;
        self.write_metadata(f)?;

        if let Some(value) = self.statement.value() {
            write!(f, " value=")?;
            write_operand(f, value)?;
        }

        self.write_operands(f)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::analysis::control::CancellationToken;
    use crate::il::common::{IlGraph, IlIndexRange, IlMetadata};
    use crate::il::ecode::{ECODE_SCHEMA_VERSION, ECodeBuilder};
    use crate::ir::{Address, FunctionId};
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn ecode_body_display_is_deterministic() {
        let metadata = IlMetadata::new(FunctionId::default(), ECODE_SCHEMA_VERSION, 0);
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
        let value = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                64,
                IlIndexRange::EMPTY,
                0x2a,
                None,
            ))
            .unwrap();
        let address = builder
            .push_expression(ECodeExpr::new(
                ECodeExprOpcode::Constant,
                64,
                IlIndexRange::EMPTY,
                0x1000,
                None,
            ))
            .unwrap();
        let operands = builder.push_statement_operands([address, value]).unwrap();

        builder
            .push_statement(ECodeStmt::new(
                ECodeStmtOpcode::Store,
                operands,
                None,
                None,
                Some(AddressSpaceId::new(3)),
            ))
            .unwrap();

        let branch_operands = builder.push_statement_operands([value]).unwrap();
        builder
            .push_statement(ECodeStmt::new(
                ECodeStmtOpcode::Branch,
                branch_operands,
                None,
                Some(Address::new(AddressSpaceId::new(2), 0x2000u64)),
                None,
            ))
            .unwrap();

        let body = builder.build(&CancellationToken::default()).unwrap();

        assert_eq!(
            body.display().to_string(),
            "%e0:bits<64> = ecode.const 0x2a\n\
             %e1:bits<64> = ecode.const 0x1000\n\
             @s0 ecode.store @fugue_space<3> %e1, %e0\n\
             @s1 ecode.br -> 0x2:0x2000 %e0"
        );
    }
}
