use std::fmt;

use crate::il::pcode::{Location, LocationId, Opcode, Operation, PCodeBody};
use crate::ir::Address;

#[derive(Debug, Copy, Clone)]
pub struct OpcodeDisplay(pub Opcode);

impl fmt::Display for OpcodeDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnemonic = self.0.mnemonic();
        write!(f, "pcode.{mnemonic}")
    }
}

#[derive(Debug, Copy, Clone)]
pub struct PCodeBodyDisplay<'a> {
    body: &'a PCodeBody,
}

impl<'a> PCodeBodyDisplay<'a> {
    pub const fn new(body: &'a PCodeBody) -> Self {
        Self { body }
    }
}

impl fmt::Display for PCodeBodyDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, operation) in self.body.operations().iter().enumerate() {
            let display = OperationDisplay::new(self.body, index, operation);
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
    body: &'a PCodeBody,
    machine_address: Address,
}

impl<'a> PCodeSourceDisplay<'a> {
    pub const fn new(body: &'a PCodeBody, machine_address: Address) -> Self {
        Self {
            body,
            machine_address,
        }
    }
}

impl fmt::Display for PCodeSourceDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;

        for (index, operation) in self.body.operations_for_source(self.machine_address) {
            if !first {
                writeln!(f)?;
            }

            first = false;
            let display = OperationDisplay::new(self.body, index, operation);
            write!(f, "{display}")?;
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct LocationDisplay<'a> {
    id: LocationId,
    location: &'a Location,
}

impl<'a> LocationDisplay<'a> {
    pub const fn new(id: LocationId, location: &'a Location) -> Self {
        Self { id, location }
    }
}

impl fmt::Display for LocationDisplay<'_> {
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
pub struct OperationDisplay<'a> {
    body: &'a PCodeBody,
    index: usize,
    operation: &'a Operation,
}

impl<'a> OperationDisplay<'a> {
    pub const fn new(body: &'a PCodeBody, index: usize, operation: &'a Operation) -> Self {
        Self {
            body,
            index,
            operation,
        }
    }

    fn write_location(&self, f: &mut fmt::Formatter<'_>, id: LocationId) -> fmt::Result {
        let location = self.body.location(id).ok_or(fmt::Error)?;
        let display = LocationDisplay::new(id, location);
        write!(f, "{display}")
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

            self.write_location(f, *operand)?;
        }

        Ok(())
    }

    fn write_effects(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(space) = self.operation.effect_space() {
            let space = space.index();
            write!(f, " @fugue_space<{space}>")?;
        }

        if matches!(self.operation.opcode(), Opcode::Load | Opcode::Store) {
            let lifter_space = self.operation.immediate();
            write!(f, " @lifter_space<{lifter_space}>")?;
        }

        if matches!(self.operation.opcode(), Opcode::UserOp) {
            let user_op = self.operation.immediate();
            write!(f, " @user_op<{user_op}>")?;
        }

        Ok(())
    }

    fn write_target(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if matches!(
            self.operation.opcode(),
            Opcode::Branch | Opcode::CBranch | Opcode::Call
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

impl fmt::Display for OperationDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index = self.index;

        write!(f, "@{index} ")?;

        if let Some(output) = self.operation.output() {
            self.write_location(f, output)?;
            write!(f, " = ")?;
        }

        let opcode = OpcodeDisplay(self.operation.opcode());
        write!(f, "{opcode}")?;
        self.write_effects(f)?;
        self.write_operands(f)?;
        self.write_target(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::common::{
        ArtefactHeader, BuildStatus, CommonBody, Finish, IrLevel, PackedRange, SourceRun,
    };
    use crate::il::pcode::{LifterSpaceHandle, PCODE_SCHEMA_VERSION, PCodeBuilder};
    use crate::ir::{Address, FunctionId};
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn pcode_body_display_is_deterministic() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            0,
        );
        let mut builder = PCodeBuilder::new(header, CommonBody::default());
        let input = builder
            .push_location(Location::new(
                LifterSpaceHandle::new(0),
                0x11,
                8,
                Location::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .push_location(Location::new(
                LifterSpaceHandle::new(1),
                0x20,
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

        let target = Address::new(AddressSpaceId::new(2), 0x2000u64);
        let branch_target = builder.push_target(target).unwrap();
        let branch_operands = builder.push_operands([input]).unwrap();
        builder.push_operation(Operation::new(
            Opcode::Branch,
            None,
            branch_operands,
            branch_target,
            None,
        ));

        let body = builder.finish(&BuildStatus::new()).unwrap();

        assert_eq!(
            body.display().to_string(),
            "@0 %l1:bytes<8>@lifter_space<1>[0x20]{register} = pcode.copy %l0:bytes<8>@lifter_space<0>[0x11]{constant}\n\
             @1 pcode.branch %l0:bytes<8>@lifter_space<0>[0x11]{constant} -> 0x2:0x2000"
        );
    }

    #[test]
    fn pcode_source_display_selects_source_instruction_operations() {
        let first = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let second = Address::new(AddressSpaceId::new(1), 0x1004u64);
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            0,
        );
        let common = CommonBody::new(
            Vec::new(),
            Vec::new(),
            vec![
                SourceRun::new(PackedRange::new(0, 1).unwrap(), first, 0, 1),
                SourceRun::new(PackedRange::new(1, 2).unwrap(), second, 0, 1),
            ],
            Vec::new(),
        );
        let mut builder = PCodeBuilder::new(header, common);
        let input = builder
            .push_location(Location::new(
                LifterSpaceHandle::new(0),
                0x11,
                8,
                Location::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .push_location(Location::new(
                LifterSpaceHandle::new(1),
                0x20,
                8,
                Location::REGISTER,
            ))
            .unwrap();
        let first_operands = builder.push_operands([input]).unwrap();
        let second_operands = builder.push_operands([output]).unwrap();

        builder.push_operation(Operation::new(
            Opcode::Copy,
            Some(output),
            first_operands,
            0,
            None,
        ));
        builder.push_operation(Operation::new(
            Opcode::IntNeg,
            Some(output),
            second_operands,
            0,
            None,
        ));

        let body = builder.finish(&BuildStatus::new()).unwrap();
        let operations = body.operations_for_source(second).collect::<Vec<_>>();

        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].0, 1);
        assert_eq!(operations[0].1.opcode(), Opcode::IntNeg);
        assert_eq!(
            body.display_source(second).to_string(),
            "@1 %l1:bytes<8>@lifter_space<1>[0x20]{register} = pcode.int_neg %l1:bytes<8>@lifter_space<1>[0x20]{register}"
        );
        assert_eq!(
            body.display_source(Address::new(AddressSpaceId::new(1), 0x2000u64))
                .to_string(),
            ""
        );
    }
}
