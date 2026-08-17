use std::fmt;

use crate::il::common::{IlSsaDef, IlValueId};
use crate::il::ecode::{
    ECodeBlockArg, ECodeIr, ECodeMemoryDomain, ECodeOp, ECodeOpcode, ECodeValue,
};
use crate::ir::Address;

#[derive(Debug, Copy, Clone)]
struct ECodeOpcodeDisplay(ECodeOpcode);

impl fmt::Display for ECodeOpcodeDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnemonic = self.0.mnemonic();
        write!(f, "ecode.{mnemonic}")
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ECodeIrDisplay<'a> {
    ir: &'a ECodeIr,
}

impl<'a> ECodeIrDisplay<'a> {
    pub(crate) const fn new(ir: &'a ECodeIr) -> Self {
        Self { ir }
    }
}

impl fmt::Display for ECodeIrDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, value) in self.ir.values().iter().enumerate() {
            let id = IlValueId::try_from_index(index).map_err(|_| fmt::Error)?;
            let display = ECodeValueDisplay::new(id, value);
            writeln!(f, "{display}")?;
        }

        for (index, arg) in self.ir.block_args().iter().enumerate() {
            let display = ECodeBlockArgDisplay::new(index, arg);
            writeln!(f, "{display}")?;
        }

        for (index, domain) in self.ir.memory_domains().iter().enumerate() {
            let display = ECodeMemoryDomainDisplay::new(index, domain);
            writeln!(f, "{display}")?;
        }

        for (index, operation) in self.ir.operations().iter().enumerate() {
            let display = ECodeOpDisplay::new(self.ir, index, operation);
            write!(f, "{display}")?;

            if index + 1 < self.ir.operations().len() {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ECodeSourceDisplay<'a> {
    ir: &'a ECodeIr,
    address: Address,
}

impl<'a> ECodeSourceDisplay<'a> {
    pub(crate) const fn new(ir: &'a ECodeIr, address: Address) -> Self {
        Self { ir, address }
    }
}

impl fmt::Display for ECodeSourceDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut operations = self.ir.operations_for_source(self.address).peekable();

        while let Some((id, operation)) = operations.next() {
            let display = ECodeOpDisplay::new(self.ir, id.index(), operation);
            write!(f, "{display}")?;

            if operations.peek().is_some() {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
struct ECodeValueDisplay<'a> {
    id: IlValueId,
    value: &'a ECodeValue,
}

impl<'a> ECodeValueDisplay<'a> {
    const fn new(id: IlValueId, value: &'a ECodeValue) -> Self {
        Self { id, value }
    }
}

impl fmt::Display for ECodeValueDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.id.index();
        let width = self.value.width();
        let (definition, definition_index) = match self.value.definition() {
            IlSsaDef::BlockArg(arg) => ("block_arg", arg.index()),
            IlSsaDef::Op(operation) => ("operation", operation.index()),
        };

        write!(
            f,
            "%v{index}:bits<{width}> = {definition}<{definition_index}>"
        )
    }
}

#[derive(Debug, Copy, Clone)]
struct ECodeBlockArgDisplay<'a> {
    index: usize,
    arg: &'a ECodeBlockArg,
}

impl<'a> ECodeBlockArgDisplay<'a> {
    const fn new(index: usize, arg: &'a ECodeBlockArg) -> Self {
        Self { index, arg }
    }
}

impl fmt::Display for ECodeBlockArgDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;
        let block = self.arg.block().index();
        let value = self.arg.value().index();
        let width = self.arg.width();

        write!(f, "^b{block}.arg{index} %v{value}:bits<{width}>")
    }
}

#[derive(Debug, Copy, Clone)]
struct ECodeMemoryDomainDisplay<'a> {
    index: usize,
    domain: &'a ECodeMemoryDomain,
}

impl<'a> ECodeMemoryDomainDisplay<'a> {
    const fn new(index: usize, domain: &'a ECodeMemoryDomain) -> Self {
        Self { index, domain }
    }
}

impl fmt::Display for ECodeMemoryDomainDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;
        let space = self.domain.space().index();

        write!(f, "@mem{index} @space<{space}>")
    }
}

#[derive(Debug, Copy, Clone)]
struct ECodeOpDisplay<'a> {
    ir: &'a ECodeIr,
    index: usize,
    operation: &'a ECodeOp,
}

impl<'a> ECodeOpDisplay<'a> {
    const fn new(ir: &'a ECodeIr, index: usize, operation: &'a ECodeOp) -> Self {
        Self {
            ir,
            index,
            operation,
        }
    }

    fn write_result(&self, f: &mut fmt::Formatter<'_>, id: IlValueId) -> fmt::Result {
        let value = self.ir.values().get(id.index()).ok_or(fmt::Error)?;
        let index = id.index();
        let width = value.width();

        write!(f, "%v{index}:bits<{width}>")
    }

    fn write_value(&self, f: &mut fmt::Formatter<'_>, id: IlValueId) -> fmt::Result {
        self.ir.values().get(id.index()).ok_or(fmt::Error)?;
        let index = id.index();

        write!(f, "%v{index}")
    }

    fn write_results(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for index in self.operation.results().start()..self.operation.results().end() {
            let id = IlValueId::try_from_index(index).map_err(|_| fmt::Error)?;

            if index == self.operation.results().start() {
                self.write_result(f, id)?;
            } else {
                write!(f, ", ")?;
                self.write_result(f, id)?;
            }
        }

        if !self.operation.results().is_empty() {
            write!(f, " = ")?;
        }

        Ok(())
    }

    fn write_operands(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operands = self.ir.operation_operands_for(self.operation);

        for (index, operand) in operands.iter().enumerate() {
            if index == 0 {
                write!(f, " ")?;
            } else {
                write!(f, ", ")?;
            }

            self.write_value(f, *operand)?;
        }

        Ok(())
    }

    fn write_metadata(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.operation.opcode() {
            ECodeOpcode::Constant if self.operation.width() > 64 => {
                let constant = self
                    .operation
                    .constant(self.ir.constant_storage())
                    .ok_or(fmt::Error)?;
                write!(f, " 0x{constant:x}")?;
            }
            ECodeOpcode::Constant | ECodeOpcode::Address => {
                let immediate = self.operation.immediate();
                write!(f, " 0x{immediate:x}")?;
            }
            ECodeOpcode::Undefined => {
                let origin = self.operation.immediate();
                write!(f, " origin<{origin}>")?;
            }
            ECodeOpcode::Intrinsic | ECodeOpcode::IntrinsicResult
                if self.operation.immediate() != 0 =>
            {
                let intrinsic = self.operation.immediate();
                write!(f, " intrinsic<{intrinsic}>")?;
            }
            ECodeOpcode::WriteFlag => {
                let storage = self.operation.immediate();
                write!(f, " flag<{storage}>")?;
            }
            ECodeOpcode::WriteRegister => {
                let storage = self.operation.immediate();
                write!(f, " register<{storage}>")?;
            }
            _ if self.operation.immediate() != 0 => {
                let immediate = self.operation.immediate();
                write!(f, " imm<{immediate}>")?;
            }
            _ => {}
        }

        if let Some(space) = self.operation.address_space() {
            let space = space.index();
            write!(f, " @space<{space}>")?;
        }

        if let Some(address) = self.operation.address() {
            write!(f, " -> {address}")?;
        }

        Ok(())
    }
}

impl fmt::Display for ECodeOpDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;
        let opcode = ECodeOpcodeDisplay(self.operation.opcode());

        write!(f, "@o{index} ")?;
        self.write_results(f)?;
        write!(f, "{opcode}")?;
        self.write_metadata(f)?;
        self.write_operands(f)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::analysis::control::CancellationToken;
    use crate::il::common::{IlGraph, IlMetadata};
    use crate::il::ecode::{ECodeBuilder, ECodeOpSpec};
    use crate::ir::FunctionId;

    #[test]
    fn ecode_display_is_deterministic() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
        let value = crate::il::ecode::test::emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(0x2a),
            [],
        )
        .unwrap();
        builder
            .emitter()
            .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [value], 0)
            .unwrap();

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert_eq!(
            ir.display().to_string(),
            "%v0:bits<64> = operation<0>\n\
             @o0 %v0:bits<64> = ecode.const 0x2a\n\
             @o1 ecode.ret %v0"
        );
    }
}
