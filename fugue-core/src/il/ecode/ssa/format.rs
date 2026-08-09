use std::fmt;

use crate::il::common::IlValueId;
use crate::il::ecode::ssa::{
    ECodeSsaBlockArg, ECodeSsaIr, ECodeSsaMemoryDomain, ECodeSsaOp, ECodeSsaOpcode, ECodeSsaValue,
    ECodeSsaValueKind,
};
use crate::ir::Address;

#[derive(Debug, Copy, Clone)]
struct ECodeSsaOpcodeDisplay(ECodeSsaOpcode);

impl fmt::Display for ECodeSsaOpcodeDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnemonic = self.0.mnemonic();
        write!(f, "ecode.ssa.{mnemonic}")
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ECodeSsaIrDisplay<'a> {
    ir: &'a ECodeSsaIr,
}

impl<'a> ECodeSsaIrDisplay<'a> {
    pub(crate) const fn new(ir: &'a ECodeSsaIr) -> Self {
        Self { ir }
    }
}

impl ECodeSsaIr {
    pub const fn display(&self) -> ECodeSsaIrDisplay<'_> {
        ECodeSsaIrDisplay::new(self)
    }

    pub const fn display_source(&self, address: Address) -> ECodeSsaSourceDisplay<'_> {
        ECodeSsaSourceDisplay::new(self, address)
    }
}

impl fmt::Display for ECodeSsaIrDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, value) in self.ir.values().iter().enumerate() {
            let id = IlValueId::try_from_index(index).map_err(|_| fmt::Error)?;
            let display = ECodeSsaValueDisplay::new(id, value);
            writeln!(f, "{display}")?;
        }

        for (index, argument) in self.ir.block_arguments().iter().enumerate() {
            let display = ECodeSsaBlockArgDisplay::new(index, argument);
            writeln!(f, "{display}")?;
        }

        for (index, domain) in self.ir.memory_domains().iter().enumerate() {
            let display = ECodeSsaMemoryDomainDisplay::new(index, domain);
            writeln!(f, "{display}")?;
        }

        for (index, operation) in self.ir.operations().iter().enumerate() {
            let display = ECodeSsaOpDisplay::new(self.ir, index, operation);
            write!(f, "{display}")?;

            if index + 1 < self.ir.operations().len() {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ECodeSsaSourceDisplay<'a> {
    ir: &'a ECodeSsaIr,
    address: Address,
}

impl<'a> ECodeSsaSourceDisplay<'a> {
    const fn new(ir: &'a ECodeSsaIr, address: Address) -> Self {
        Self { ir, address }
    }
}

impl fmt::Display for ECodeSsaSourceDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut operations = self.ir.operations_for_source(self.address).peekable();

        while let Some((id, operation)) = operations.next() {
            let display = ECodeSsaOpDisplay::new(self.ir, id.index(), operation);
            write!(f, "{display}")?;

            if operations.peek().is_some() {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
struct ECodeSsaValueDisplay<'a> {
    id: IlValueId,
    value: &'a ECodeSsaValue,
}

impl<'a> ECodeSsaValueDisplay<'a> {
    pub(crate) const fn new(id: IlValueId, value: &'a ECodeSsaValue) -> Self {
        Self { id, value }
    }
}

impl fmt::Display for ECodeSsaValueDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.id.index();
        let width = self.value.width();
        let definition = match self.value.definition_kind() {
            ECodeSsaValueKind::Operation => "operation",
            ECodeSsaValueKind::BlockArgument => "block_argument",
        };
        let definition_index = self.value.definition_index();

        write!(
            f,
            "%v{index}:bits<{width}> = {definition}<{definition_index}>"
        )
    }
}

#[derive(Debug, Copy, Clone)]
struct ECodeSsaBlockArgDisplay<'a> {
    index: usize,
    argument: &'a ECodeSsaBlockArg,
}

impl<'a> ECodeSsaBlockArgDisplay<'a> {
    pub(crate) const fn new(index: usize, argument: &'a ECodeSsaBlockArg) -> Self {
        Self { index, argument }
    }
}

impl fmt::Display for ECodeSsaBlockArgDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;
        let block = self.argument.block().index();
        let value = self.argument.value().index();
        let width = self.argument.width();

        write!(f, "^b{block}.arg{index} %v{value}:bits<{width}>")
    }
}

#[derive(Debug, Copy, Clone)]
struct ECodeSsaMemoryDomainDisplay<'a> {
    index: usize,
    domain: &'a ECodeSsaMemoryDomain,
}

impl<'a> ECodeSsaMemoryDomainDisplay<'a> {
    pub(crate) const fn new(index: usize, domain: &'a ECodeSsaMemoryDomain) -> Self {
        Self { index, domain }
    }
}

impl fmt::Display for ECodeSsaMemoryDomainDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;
        let space = self.domain.space().index();

        write!(f, "@mem{index} @space<{space}>")
    }
}

#[derive(Debug, Copy, Clone)]
struct ECodeSsaOpDisplay<'a> {
    ir: &'a ECodeSsaIr,
    index: usize,
    operation: &'a ECodeSsaOp,
}

impl<'a> ECodeSsaOpDisplay<'a> {
    pub(crate) const fn new(ir: &'a ECodeSsaIr, index: usize, operation: &'a ECodeSsaOp) -> Self {
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
            ECodeSsaOpcode::Constant if self.operation.width() > 64 => {
                let constant = self
                    .operation
                    .constant(self.ir.constant_storage())
                    .ok_or(fmt::Error)?;
                write!(f, " 0x{constant:x}")?;
            }
            ECodeSsaOpcode::Constant | ECodeSsaOpcode::Address => {
                let immediate = self.operation.immediate();
                write!(f, " 0x{immediate:x}")?;
            }
            ECodeSsaOpcode::Undefined => {
                let origin = self.operation.immediate();
                write!(f, " origin<{origin}>")?;
            }
            ECodeSsaOpcode::Intrinsic | ECodeSsaOpcode::IntrinsicResult
                if self.operation.immediate() != 0 =>
            {
                let intrinsic = self.operation.immediate();
                write!(f, " intrinsic<{intrinsic}>")?;
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

impl fmt::Display for ECodeSsaOpDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;
        let opcode = ECodeSsaOpcodeDisplay(self.operation.opcode());

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
    use crate::il::common::{IlGraph, IlIndexRange, IlMetadata};
    use crate::il::ecode::ssa::ECodeSsaBuilder;
    use crate::ir::FunctionId;

    #[test]
    fn ssa_body_display_is_deterministic() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());
        let (value, results) = builder.push_result_value(64).unwrap();

        builder
            .push_operation(
                ECodeSsaOp::new(ECodeSsaOpcode::Constant, results, IlIndexRange::EMPTY, 64)
                    .with_immediate(0x2a),
            )
            .unwrap();

        let operands = builder.push_value_operands([value]).unwrap();
        builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::Return,
                IlIndexRange::EMPTY,
                operands,
                0,
            ))
            .unwrap();

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert_eq!(
            ir.display().to_string(),
            "%v0:bits<64> = operation<0>\n\
             @o0 %v0:bits<64> = ecode.ssa.const 0x2a\n\
             @o1 ecode.ssa.ret %v0"
        );
    }
}
