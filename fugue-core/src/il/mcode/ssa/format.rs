use std::fmt;

use crate::il::common::{IlSsaDef, IlValueId};
use crate::il::mcode::ssa::{MCodeSsaIr, MCodeSsaMemoryDomain, MCodeSsaOp, MCodeSsaOpcode};
use crate::il::mcode::{MCodeVarId, MCodeVarKind};
use crate::ir::Address;

#[derive(Debug, Copy, Clone)]
struct MCodeSsaVariableRef<'a> {
    ir: &'a MCodeSsaIr,
    id: MCodeVarId,
}

impl<'a> MCodeSsaVariableRef<'a> {
    const fn new(ir: &'a MCodeSsaIr, id: MCodeVarId) -> Self {
        Self { ir, id }
    }
}

impl fmt::Display for MCodeSsaVariableRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variable = self.ir.variable(self.id).ok_or(fmt::Error)?;
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
struct MCodeSsaValueRef<'a> {
    ir: &'a MCodeSsaIr,
    id: IlValueId,
}

impl<'a> MCodeSsaValueRef<'a> {
    const fn new(ir: &'a MCodeSsaIr, id: IlValueId) -> Self {
        Self { ir, id }
    }
}

impl fmt::Display for MCodeSsaValueRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(binding) = self.ir.binding(self.id) else {
            return write!(f, "%v{}", self.id.index());
        };
        write!(
            f,
            "{}#{}",
            MCodeSsaVariableRef::new(self.ir, binding.variable()),
            binding.version().value()
        )
    }
}

#[derive(Debug, Copy, Clone)]
pub struct MCodeSsaIrDisplay<'a> {
    ir: &'a MCodeSsaIr,
}

impl<'a> MCodeSsaIrDisplay<'a> {
    pub(crate) const fn new(ir: &'a MCodeSsaIr) -> Self {
        Self { ir }
    }
}

impl MCodeSsaIr {
    pub const fn display(&self) -> MCodeSsaIrDisplay<'_> {
        MCodeSsaIrDisplay::new(self)
    }

    pub const fn display_source(&self, address: Address) -> MCodeSsaSourceDisplay<'_> {
        MCodeSsaSourceDisplay::new(self, address)
    }
}

impl fmt::Display for MCodeSsaIrDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, value) in self.ir.values().iter().enumerate() {
            let id = IlValueId::try_from_index(index).map_err(|_| fmt::Error)?;
            let reference = MCodeSsaValueRef::new(self.ir, id);
            let width = value.width();
            let (definition, definition_index) = match value.definition() {
                IlSsaDef::BlockArgument(argument) => ("block_argument", argument.index()),
                IlSsaDef::Operation(operation) => ("operation", operation.index()),
            };
            writeln!(
                f,
                "{reference}:bits<{width}> = {definition}<{definition_index}>"
            )?;
        }

        for (index, argument) in self.ir.block_arguments().iter().enumerate() {
            let block = argument.block().index();
            let reference = MCodeSsaValueRef::new(self.ir, argument.value());
            let width = argument.width();
            writeln!(f, "^b{block}.arg{index} {reference}:bits<{width}>")?;
        }

        for (index, domain) in self.ir.memory_domains().iter().enumerate() {
            let display = MCodeSsaMemoryDomainDisplay::new(index, domain);
            writeln!(f, "{display}")?;
        }

        for (index, operation) in self.ir.operations().iter().enumerate() {
            let display = MCodeSsaOpDisplay::new(self.ir, index, operation);
            write!(f, "{display}")?;

            if index + 1 < self.ir.operations().len() {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct MCodeSsaSourceDisplay<'a> {
    ir: &'a MCodeSsaIr,
    address: Address,
}

impl<'a> MCodeSsaSourceDisplay<'a> {
    const fn new(ir: &'a MCodeSsaIr, address: Address) -> Self {
        Self { ir, address }
    }
}

impl fmt::Display for MCodeSsaSourceDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut operations = self.ir.operations_for_source(self.address).peekable();

        while let Some((id, operation)) = operations.next() {
            let display = MCodeSsaOpDisplay::new(self.ir, id.index(), operation);
            write!(f, "{display}")?;

            if operations.peek().is_some() {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
struct MCodeSsaMemoryDomainDisplay<'a> {
    index: usize,
    domain: &'a MCodeSsaMemoryDomain,
}

impl<'a> MCodeSsaMemoryDomainDisplay<'a> {
    const fn new(index: usize, domain: &'a MCodeSsaMemoryDomain) -> Self {
        Self { index, domain }
    }
}

impl fmt::Display for MCodeSsaMemoryDomainDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;
        let space = self.domain.space().index();

        write!(f, "@mem{index} @space<{space}>")
    }
}

#[derive(Debug, Copy, Clone)]
struct MCodeSsaOpcodeDisplay(MCodeSsaOpcode);

impl fmt::Display for MCodeSsaOpcodeDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnemonic = self.0.mnemonic();
        write!(f, "mcode.ssa.{mnemonic}")
    }
}

#[derive(Debug, Copy, Clone)]
struct MCodeSsaOpDisplay<'a> {
    ir: &'a MCodeSsaIr,
    index: usize,
    operation: &'a MCodeSsaOp,
}

impl<'a> MCodeSsaOpDisplay<'a> {
    const fn new(ir: &'a MCodeSsaIr, index: usize, operation: &'a MCodeSsaOp) -> Self {
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
            let reference = MCodeSsaValueRef::new(self.ir, id);
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
        let operands = self.ir.operation_operands_for(self.operation);

        for (index, operand) in operands.iter().enumerate() {
            if index == 0 {
                write!(f, " ")?;
            } else {
                write!(f, ", ")?;
            }

            let reference = MCodeSsaValueRef::new(self.ir, *operand);
            write!(f, "{reference}")?;
        }

        Ok(())
    }

    fn write_metadata(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.operation.opcode() {
            MCodeSsaOpcode::Constant if self.operation.width() > 64 => {
                let constant = self
                    .operation
                    .constant(self.ir.constant_storage())
                    .ok_or(fmt::Error)?;
                write!(f, " 0x{constant:x}")?;
            }
            MCodeSsaOpcode::Constant | MCodeSsaOpcode::Address => {
                let immediate = self.operation.immediate();
                write!(f, " 0x{immediate:x}")?;
            }
            MCodeSsaOpcode::Undefined => {
                let origin = self.operation.immediate();
                write!(f, " origin<{origin}>")?;
            }
            MCodeSsaOpcode::Intrinsic | MCodeSsaOpcode::IntrinsicResult
                if self.operation.immediate() != 0 =>
            {
                let intrinsic = self.operation.immediate();
                write!(f, " intrinsic<{intrinsic}>")?;
            }
            MCodeSsaOpcode::SetVarField
            | MCodeSsaOpcode::VarAliasedField
            | MCodeSsaOpcode::SetVarAliasedField
            | MCodeSsaOpcode::AddressOfField => {
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
            MCodeSsaOpcode::VarAliased
                | MCodeSsaOpcode::VarAliasedField
                | MCodeSsaOpcode::AddressOf
                | MCodeSsaOpcode::AddressOfField
        ) && let Some(variable) = self.operation.variable()
        {
            write!(f, " {}", MCodeSsaVariableRef::new(self.ir, variable))?;
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

impl fmt::Display for MCodeSsaOpDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;
        let opcode = MCodeSsaOpcodeDisplay(self.operation.opcode());

        write!(f, "@o{index} ")?;
        self.write_results(f)?;
        write!(f, "{opcode}")?;
        self.write_metadata(f)?;
        self.write_operands(f)
    }
}
