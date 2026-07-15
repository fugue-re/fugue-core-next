use std::fmt;

use crate::il::common::ValueId;
use crate::il::llil::ssa::{
    BlockArgument, MemoryDomain, SsaBody, SsaOpcode, SsaOperation, Value, ValueDefinitionKind,
};

#[derive(Debug, Copy, Clone)]
pub struct SsaOpcodeDisplay(pub SsaOpcode);

impl fmt::Display for SsaOpcodeDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnemonic = self.0.mnemonic();
        write!(f, "llil.ssa.{mnemonic}")
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SsaBodyDisplay<'a> {
    body: &'a SsaBody,
}

impl<'a> SsaBodyDisplay<'a> {
    pub const fn new(body: &'a SsaBody) -> Self {
        Self { body }
    }
}

impl fmt::Display for SsaBodyDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, value) in self.body.values().iter().enumerate() {
            let id = ValueId::try_from_index(index).map_err(|_| fmt::Error)?;
            let display = ValueDisplay::new(id, value);
            writeln!(f, "{display}")?;
        }

        for (index, argument) in self.body.block_arguments().iter().enumerate() {
            let display = BlockArgumentDisplay::new(index, argument);
            writeln!(f, "{display}")?;
        }

        for (index, domain) in self.body.memory_domains().iter().enumerate() {
            let display = MemoryDomainDisplay::new(index, domain);
            writeln!(f, "{display}")?;
        }

        for (index, operation) in self.body.operations().iter().enumerate() {
            let display = SsaOperationDisplay::new(self.body, index, operation);
            write!(f, "{display}")?;

            if index + 1 < self.body.operations().len() {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ValueDisplay<'a> {
    id: ValueId,
    value: &'a Value,
}

impl<'a> ValueDisplay<'a> {
    pub const fn new(id: ValueId, value: &'a Value) -> Self {
        Self { id, value }
    }
}

impl fmt::Display for ValueDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.id.index();
        let width = self.value.width();
        let definition = match self.value.definition_kind() {
            ValueDefinitionKind::Operation => "operation",
            ValueDefinitionKind::BlockArgument => "block_argument",
        };
        let definition_index = self.value.definition_index();

        write!(
            f,
            "%v{index}:bits<{width}> = {definition}<{definition_index}>"
        )
    }
}

#[derive(Debug, Copy, Clone)]
pub struct BlockArgumentDisplay<'a> {
    index: usize,
    argument: &'a BlockArgument,
}

impl<'a> BlockArgumentDisplay<'a> {
    pub const fn new(index: usize, argument: &'a BlockArgument) -> Self {
        Self { index, argument }
    }
}

impl fmt::Display for BlockArgumentDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;
        let block = self.argument.block().index();
        let value = self.argument.value().index();
        let width = self.argument.width();

        write!(f, "^b{block}.arg{index} %v{value}:bits<{width}>")
    }
}

#[derive(Debug, Copy, Clone)]
pub struct MemoryDomainDisplay<'a> {
    index: usize,
    domain: &'a MemoryDomain,
}

impl<'a> MemoryDomainDisplay<'a> {
    pub const fn new(index: usize, domain: &'a MemoryDomain) -> Self {
        Self { index, domain }
    }
}

impl fmt::Display for MemoryDomainDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;
        let space = self.domain.space().index();

        write!(f, "@mem{index} @fugue_space<{space}>")
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SsaOperationDisplay<'a> {
    body: &'a SsaBody,
    index: usize,
    operation: &'a SsaOperation,
}

impl<'a> SsaOperationDisplay<'a> {
    pub const fn new(body: &'a SsaBody, index: usize, operation: &'a SsaOperation) -> Self {
        Self {
            body,
            index,
            operation,
        }
    }

    fn write_result(&self, f: &mut fmt::Formatter<'_>, id: ValueId) -> fmt::Result {
        let value = self.body.values().get(id.index()).ok_or(fmt::Error)?;
        let index = id.index();
        let width = value.width();

        write!(f, "%v{index}:bits<{width}>")
    }

    fn write_value(&self, f: &mut fmt::Formatter<'_>, id: ValueId) -> fmt::Result {
        self.body.values().get(id.index()).ok_or(fmt::Error)?;
        let index = id.index();

        write!(f, "%v{index}")
    }

    fn write_results(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.operation
            .results()
            .verify_bounds(self.body.values().len())
            .map_err(|_| fmt::Error)?;

        for index in self.operation.results().start()..self.operation.results().end() {
            let id = ValueId::try_from_index(index).map_err(|_| fmt::Error)?;

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
        let operands = self
            .body
            .operation_operands(self.operation)
            .map_err(|_| fmt::Error)?;

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
            SsaOpcode::Constant | SsaOpcode::Address => {
                let immediate = self.operation.immediate();
                write!(f, " 0x{immediate:x}")?;
            }
            SsaOpcode::Undefined => {
                let origin = self.operation.immediate();
                write!(f, " origin<{origin}>")?;
            }
            SsaOpcode::Intrinsic | SsaOpcode::IntrinsicResult
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
            write!(f, " @fugue_space<{space}>")?;
        }

        if let Some(address) = self.operation.address() {
            write!(f, " -> {address}")?;
        }

        Ok(())
    }
}

impl fmt::Display for SsaOperationDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;
        let opcode = SsaOpcodeDisplay(self.operation.opcode());

        write!(f, "@o{index} ")?;
        self.write_results(f)?;
        write!(f, "{opcode}")?;
        self.write_metadata(f)?;
        self.write_operands(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::common::{
        ArtefactHeader, BuildStatus, CommonBody, Finish, IrLevel, PackedRange,
    };
    use crate::il::llil::ssa::{LLIL_SSA_SCHEMA_VERSION, SsaBuilder};
    use crate::ir::FunctionId;

    #[test]
    fn ssa_body_display_is_deterministic() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let mut builder = SsaBuilder::new(header, CommonBody::default());
        let (value, results) = builder.push_result_value(64).unwrap();

        builder
            .push_operation(
                SsaOperation::new(SsaOpcode::Constant, results, PackedRange::EMPTY, 64)
                    .with_immediate(0x2a),
            )
            .unwrap();

        let operands = builder.push_value_operands([value]).unwrap();
        builder
            .push_operation(SsaOperation::new(
                SsaOpcode::Return,
                PackedRange::EMPTY,
                operands,
                0,
            ))
            .unwrap();

        let body = builder.finish(&BuildStatus::new()).unwrap();

        assert_eq!(
            body.display().to_string(),
            "%v0:bits<64> = operation<0>\n\
             @o0 %v0:bits<64> = llil.ssa.constant 0x2a\n\
             @o1 llil.ssa.return %v0"
        );
    }
}
