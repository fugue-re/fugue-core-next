use std::fmt;

use crate::il::common::{IlSsaDef, IlValueId};
use crate::il::mcode::{
    MCodeIr, MCodeMemoryDomain, MCodeOp, MCodeOpcode, MCodeVarId, MCodeVarKind,
};
use crate::ir::Address;

#[derive(Debug, Copy, Clone)]
struct MCodeVariableDisplay<'a> {
    ir: &'a MCodeIr,
    variable: MCodeVarId,
}

impl<'a> MCodeVariableDisplay<'a> {
    const fn new(ir: &'a MCodeIr, variable: MCodeVarId) -> Self {
        Self { ir, variable }
    }
}

impl fmt::Display for MCodeVariableDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variable = self.ir.variable(self.variable).ok_or(fmt::Error)?;
        match variable.kind() {
            MCodeVarKind::Flag => {
                write!(f, "flag[{}]", variable.flag_id().ok_or(fmt::Error)?.value())?
            }
            MCodeVarKind::Register => write!(
                f,
                "reg[{}]",
                variable.register_id().ok_or(fmt::Error)?.value()
            )?,
            MCodeVarKind::Stack => {
                write!(f, "stack[{}]", variable.stack_offset().ok_or(fmt::Error)?)?
            }
        }
        if variable.index() != 0 {
            write!(f, "_{}", variable.index())?;
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
struct MCodeValueDisplay<'a> {
    ir: &'a MCodeIr,
    id: IlValueId,
}

impl<'a> MCodeValueDisplay<'a> {
    const fn new(ir: &'a MCodeIr, id: IlValueId) -> Self {
        Self { ir, id }
    }
}

impl fmt::Display for MCodeValueDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(binding) = self.ir.binding(self.id) else {
            return write!(f, "%v{}", self.id.index());
        };
        write!(
            f,
            "{}#{}",
            MCodeVariableDisplay::new(self.ir, binding.variable()),
            binding.version().value()
        )
    }
}

#[derive(Debug, Copy, Clone)]
pub struct MCodeIrDisplay<'a> {
    ir: &'a MCodeIr,
}

impl<'a> MCodeIrDisplay<'a> {
    pub(crate) const fn new(ir: &'a MCodeIr) -> Self {
        Self { ir }
    }
}

impl fmt::Display for MCodeIrDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, value) in self.ir.values().iter().enumerate() {
            let id = IlValueId::try_from_index(index).map_err(|_| fmt::Error)?;
            let reference = MCodeValueDisplay::new(self.ir, id);
            let width = value.width();
            let (definition, definition_index) = match value.definition() {
                IlSsaDef::BlockArg(arg) => ("block_arg", arg.index()),
                IlSsaDef::Op(operation) => ("operation", operation.index()),
            };
            writeln!(
                f,
                "{reference}:bits<{width}> = {definition}<{definition_index}>"
            )?;
        }

        for (index, arg) in self.ir.block_args().iter().enumerate() {
            let block = arg.block().index();
            let reference = MCodeValueDisplay::new(self.ir, arg.value());
            let width = arg.width();
            writeln!(f, "^b{block}.arg{index} {reference}:bits<{width}>")?;
        }

        for (index, domain) in self.ir.memory_domains().iter().enumerate() {
            let display = MCodeMemoryDomainDisplay::new(index, domain);
            writeln!(f, "{display}")?;
        }

        for (index, operation) in self.ir.ops().iter().enumerate() {
            let display = MCodeOpDisplay::new(self.ir, index, operation);
            write!(f, "{display}")?;

            if index + 1 < self.ir.ops().len() {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct MCodeSourceDisplay<'a> {
    ir: &'a MCodeIr,
    address: Address,
}

impl<'a> MCodeSourceDisplay<'a> {
    pub(crate) const fn new(ir: &'a MCodeIr, address: Address) -> Self {
        Self { ir, address }
    }
}

impl fmt::Display for MCodeSourceDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut operations = self.ir.ops_for_source(self.address).peekable();

        while let Some((id, operation)) = operations.next() {
            let display = MCodeOpDisplay::new(self.ir, id.index(), operation);
            write!(f, "{display}")?;

            if operations.peek().is_some() {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
struct MCodeMemoryDomainDisplay<'a> {
    index: usize,
    domain: &'a MCodeMemoryDomain,
}

impl<'a> MCodeMemoryDomainDisplay<'a> {
    const fn new(index: usize, domain: &'a MCodeMemoryDomain) -> Self {
        Self { index, domain }
    }
}

impl fmt::Display for MCodeMemoryDomainDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;
        let space = self.domain.space().index();

        write!(f, "@mem{index} @space<{space}>")
    }
}

#[derive(Debug, Copy, Clone)]
struct MCodeOpcodeDisplay(MCodeOpcode);

impl fmt::Display for MCodeOpcodeDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnemonic = self.0.mnemonic();
        write!(f, "mcode.{mnemonic}")
    }
}

#[derive(Debug, Copy, Clone)]
struct MCodeOpDisplay<'a> {
    ir: &'a MCodeIr,
    index: usize,
    operation: &'a MCodeOp,
}

impl<'a> MCodeOpDisplay<'a> {
    const fn new(ir: &'a MCodeIr, index: usize, operation: &'a MCodeOp) -> Self {
        Self {
            ir,
            index,
            operation,
        }
    }

    fn write_results(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for index in self.operation.results().start()..self.operation.results().end() {
            let id = IlValueId::try_from_index(index).map_err(|_| fmt::Error)?;
            let value = self.ir.values().get(index).ok_or(fmt::Error)?;
            let reference = MCodeValueDisplay::new(self.ir, id);
            let width = value.width();

            if index != self.operation.results().start() {
                write!(f, ", ")?;
            }
            write!(f, "{reference}:bits<{width}>")?;
        }

        if !self.operation.results().is_empty() {
            write!(f, " = ")?;
        }

        Ok(())
    }

    fn write_operands(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operands = self.ir.op_operands_for(self.operation);

        for (index, operand) in operands.iter().enumerate() {
            if index == 0 {
                write!(f, " ")?;
            } else {
                write!(f, ", ")?;
            }

            let reference = MCodeValueDisplay::new(self.ir, *operand);
            write!(f, "{reference}")?;
        }

        Ok(())
    }

    fn write_metadata(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.operation.opcode() {
            MCodeOpcode::Constant if self.operation.width() > 64 => {
                let constant = self
                    .operation
                    .constant(self.ir.constant_storage())
                    .ok_or(fmt::Error)?;
                write!(f, " 0x{constant:x}")?;
            }
            MCodeOpcode::Constant | MCodeOpcode::Address => {
                let immediate = self.operation.immediate();
                write!(f, " 0x{immediate:x}")?;
            }
            MCodeOpcode::Undefined => {
                let origin = self.operation.immediate();
                write!(f, " origin<{origin}>")?;
            }
            MCodeOpcode::Intrinsic | MCodeOpcode::IntrinsicResult
                if self.operation.immediate() != 0 =>
            {
                let intrinsic = self.operation.immediate();
                write!(f, " intrinsic<{intrinsic}>")?;
            }
            MCodeOpcode::SetVarField
            | MCodeOpcode::VarAliasedField
            | MCodeOpcode::SetVarAliasedField
            | MCodeOpcode::AddressOfField => {
                let offset = self.operation.immediate();
                write!(f, " @{offset}")?;
            }
            _ if self.operation.immediate() != 0 => {
                let immediate = self.operation.immediate();
                write!(f, " imm<{immediate}>")?;
            }
            _ => {}
        }

        if matches!(
            self.operation.opcode(),
            MCodeOpcode::VarAliased
                | MCodeOpcode::VarAliasedField
                | MCodeOpcode::AddressOf
                | MCodeOpcode::AddressOfField
        ) && let Some(variable) = self.operation.variable()
        {
            write!(f, " {}", MCodeVariableDisplay::new(self.ir, variable))?;
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

impl fmt::Display for MCodeOpDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;
        let opcode = MCodeOpcodeDisplay(self.operation.opcode());

        write!(f, "@o{index} ")?;
        self.write_results(f)?;
        write!(f, "{opcode}")?;
        self.write_metadata(f)?;
        self.write_operands(f)
    }
}
