use std::fmt;

use crate::il::pcode::{PCodeIr, PCodeLocation, PCodeLocationId, PCodeOp, PCodeOpcode};
use crate::ir::Address;

#[derive(Debug, Copy, Clone)]
pub struct PCodeOpcodeDisplay(pub PCodeOpcode);

impl fmt::Display for PCodeOpcodeDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnemonic = self.0.mnemonic();
        write!(f, "pcode.{mnemonic}")
    }
}

#[derive(Debug, Copy, Clone)]
pub struct PCodeIrDisplay<'a> {
    body: &'a PCodeIr,
}

impl<'a> PCodeIrDisplay<'a> {
    pub(crate) const fn new(body: &'a PCodeIr) -> Self {
        Self { body }
    }
}

impl fmt::Display for PCodeIrDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, operation) in self.body.operations().iter().enumerate() {
            let display = PCodeOpDisplay::new(self.body, index, operation);
            write!(f, "{display}")?;

            if index + 1 < self.body.operations().len() {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct PCodeSourceDisplay<'a> {
    body: &'a PCodeIr,
    address: Address,
}

impl<'a> PCodeSourceDisplay<'a> {
    pub(crate) const fn new(body: &'a PCodeIr, address: Address) -> Self {
        Self { body, address }
    }
}

impl fmt::Display for PCodeSourceDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;

        for (index, operation) in self.body.operations_for_source(self.address) {
            if !first {
                writeln!(f)?;
            }

            first = false;
            let display = PCodeOpDisplay::new(self.body, index, operation);
            write!(f, "{display}")?;
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct PCodeLocationDisplay<'a> {
    id: PCodeLocationId,
    location: &'a PCodeLocation,
}

impl<'a> PCodeLocationDisplay<'a> {
    pub(crate) const fn new(id: PCodeLocationId, location: &'a PCodeLocation) -> Self {
        Self { id, location }
    }
}

impl fmt::Display for PCodeLocationDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.id.index();
        let width = self.location.width();
        let lifter_space = self.location.lifter_space().value();
        let offset = self.location.offset();
        let kind = if self.location.is_constant() {
            "constant"
        } else if self.location.is_register() {
            "register"
        } else if self.location.is_unique() {
            "unique"
        } else {
            "varnode"
        };

        write!(
            f,
            "%l{index}:bytes<{width}>@lifter_space<{lifter_space}>[0x{offset:x}]{{{kind}}}"
        )
    }
}

#[derive(Debug, Copy, Clone)]
pub struct PCodeOpDisplay<'a> {
    body: &'a PCodeIr,
    index: usize,
    operation: &'a PCodeOp,
}

impl<'a> PCodeOpDisplay<'a> {
    pub(crate) const fn new(body: &'a PCodeIr, index: usize, operation: &'a PCodeOp) -> Self {
        Self {
            body,
            index,
            operation,
        }
    }

    fn write_location(&self, f: &mut fmt::Formatter<'_>, id: PCodeLocationId) -> fmt::Result {
        let location = self.body.location(id).ok_or(fmt::Error)?;
        let display = PCodeLocationDisplay::new(id, location);
        write!(f, "{display}")
    }

    fn write_operands(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operands = self.body.operation_operands(self.operation);

        for (index, operand) in operands.iter().enumerate() {
            if index == 0 {
                write!(f, " ")?;
            } else {
                write!(f, ", ")?;
            }

            self.write_location(f, *operand)?;
        }

        Ok(())
    }

    fn write_effects(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(space) = self.operation.effect_space() {
            let space = space.index();
            write!(f, " @fugue_space<{space}>")?;
        }

        if matches!(
            self.operation.opcode(),
            PCodeOpcode::Load | PCodeOpcode::Store
        ) {
            let lifter_space = self.operation.immediate();
            write!(f, " @lifter_space<{lifter_space}>")?;
        }

        if matches!(self.operation.opcode(), PCodeOpcode::UserOp) {
            let user_op = self.operation.immediate();
            write!(f, " @user_op<{user_op}>")?;
        }

        Ok(())
    }

    fn write_target(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if matches!(
            self.operation.opcode(),
            PCodeOpcode::Branch | PCodeOpcode::CBranch | PCodeOpcode::Call
        ) {
            let target = self
                .body
                .target(self.operation.immediate())
                .ok_or(fmt::Error)?;

            write!(f, " -> {target}")?;
        }

        Ok(())
    }
}

impl fmt::Display for PCodeOpDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;

        write!(f, "@{index} ")?;

        if let Some(output) = self.operation.output() {
            self.write_location(f, output)?;
            write!(f, " = ")?;
        }

        let opcode = PCodeOpcodeDisplay(self.operation.opcode());
        write!(f, "{opcode}")?;
        self.write_effects(f)?;
        self.write_operands(f)?;
        self.write_target(f)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::analysis::control::CancellationToken;
    use crate::il::common::{IlGraph, IlHeader, IlIndexRange, IlSourceSpan};
    use crate::il::pcode::{
        LifterSpaceHandle, PCODE_SCHEMA_VERSION, PCodeBuilder, PCodeLocationProperties,
    };
    use crate::ir::FunctionId;
    use crate::lifter::{Language, resolve_language};
    use crate::storage::segments::space::AddressSpaceId;

    fn language() -> &'static Language {
        resolve_language("x86:LE:64").expect("test language should resolve")
    }

    #[test]
    fn pcode_ir_display_is_deterministic() {
        let header = IlHeader::new(FunctionId::default(), PCODE_SCHEMA_VERSION, 0);
        let mut builder = PCodeBuilder::new(language(), header, IlGraph::default());
        let input = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                0x11,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(1),
                0x20,
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

        let target = Address::new(AddressSpaceId::new(2), 0x2000u64);
        let branch_target = builder.push_target(target).unwrap();
        let branch_operands = builder.push_operands([input]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Branch,
            None,
            branch_operands,
            branch_target,
            None,
        ));

        let ir = builder.build(&CancellationToken::default()).unwrap();

        assert_eq!(
            ir.display().to_string(),
            "@0 %l1:bytes<8>@lifter_space<1>[0x20]{register} = pcode.copy %l0:bytes<8>@lifter_space<0>[0x11]{constant}\n\
             @1 pcode.branch %l0:bytes<8>@lifter_space<0>[0x11]{constant} -> 0x2:0x2000"
        );
    }

    #[test]
    fn pcode_source_display_selects_source_instruction_operations() {
        let first = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let second = Address::new(AddressSpaceId::new(1), 0x1004u64);
        let header = IlHeader::new(FunctionId::default(), PCODE_SCHEMA_VERSION, 0);
        let mut builder = PCodeBuilder::new(language(), header, IlGraph::default());

        builder.replace_source_spans(vec![
            IlSourceSpan::new(IlIndexRange::new(0, 1).unwrap(), first, 0, 1),
            IlSourceSpan::new(IlIndexRange::new(1, 2).unwrap(), second, 0, 1),
        ]);

        let input = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(0),
                0x11,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .push_location(PCodeLocation::new(
                LifterSpaceHandle::new(1),
                0x20,
                8,
                PCodeLocationProperties::REGISTER,
            ))
            .unwrap();
        let first_operands = builder.push_operands([input]).unwrap();
        let second_operands = builder.push_operands([output]).unwrap();

        builder.push_operation(PCodeOp::new(
            PCodeOpcode::Copy,
            Some(output),
            first_operands,
            0,
            None,
        ));
        builder.push_operation(PCodeOp::new(
            PCodeOpcode::IntNeg,
            Some(output),
            second_operands,
            0,
            None,
        ));

        let ir = builder.build(&CancellationToken::default()).unwrap();
        let operations = ir.operations_for_source(second).collect::<Vec<_>>();

        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].0, 1);
        assert_eq!(operations[0].1.opcode(), PCodeOpcode::IntNeg);
        assert_eq!(
            ir.display_source(second).to_string(),
            "@1 %l1:bytes<8>@lifter_space<1>[0x20]{register} = pcode.int_neg %l1:bytes<8>@lifter_space<1>[0x20]{register}"
        );
        assert_eq!(
            ir.display_source(Address::new(AddressSpaceId::new(1), 0x2000u64))
                .to_string(),
            ""
        );
    }
}
