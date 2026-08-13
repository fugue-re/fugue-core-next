use smallvec::SmallVec;

use crate::il::common::{FlagId, IlError, RegisterId};
use crate::il::ecode::{ECodeExprOpcode, ECodeStmtOpcode};
use crate::ir::Address;
use crate::storage::segments::space::AddressSpaceId;

pub(crate) trait ECodeSink {
    type Value: Copy;

    fn begin_instruction(&mut self, _address: Address) -> Result<(), IlError> {
        Ok(())
    }

    fn constant(&mut self, width: u32, value: u64) -> Result<Self::Value, IlError>;

    fn address(&mut self, width: u32, offset: u64) -> Result<Self::Value, IlError>;

    fn undefined(&mut self, width: u32, discriminant: u64) -> Result<Self::Value, IlError>;

    fn read_register(&mut self, register: RegisterId, width: u32) -> Result<Self::Value, IlError>;

    fn read_flag(&mut self, flag: FlagId, width: u32) -> Result<Self::Value, IlError>;

    fn apply(
        &mut self,
        opcode: ECodeExprOpcode,
        width: u32,
        operands: &[Self::Value],
        immediate: u64,
        address_space: Option<AddressSpaceId>,
    ) -> Result<Self::Value, IlError>;

    fn write_register(&mut self, register: RegisterId, value: Self::Value) -> Result<(), IlError>;

    fn write_flag(&mut self, flag: FlagId, value: Self::Value) -> Result<(), IlError>;

    fn store(
        &mut self,
        operands: &[Self::Value],
        address_space: Option<AddressSpaceId>,
    ) -> Result<(), IlError>;

    fn direct_flow(
        &mut self,
        opcode: ECodeStmtOpcode,
        target: Address,
        operands: &[Self::Value],
    ) -> Result<(), IlError>;

    fn indirect_flow(
        &mut self,
        opcode: ECodeStmtOpcode,
        operands: &[Self::Value],
        address_space: Option<AddressSpaceId>,
    ) -> Result<(), IlError>;

    fn intrinsic(
        &mut self,
        intrinsic: u64,
        operands: &[Self::Value],
        address_space: Option<AddressSpaceId>,
    ) -> Result<(), IlError>;

    fn trap(
        &mut self,
        intrinsic: u64,
        address_space: Option<AddressSpaceId>,
    ) -> Result<(), IlError>;
}

fn unzip<A, B>(operands: &[(A, B)]) -> (SmallVec<[A; 4]>, SmallVec<[B; 4]>)
where
    A: Copy,
    B: Copy,
{
    (
        operands.iter().map(|operand| operand.0).collect(),
        operands.iter().map(|operand| operand.1).collect(),
    )
}

impl<A, B> ECodeSink for (A, B)
where
    A: ECodeSink,
    B: ECodeSink,
{
    type Value = (A::Value, B::Value);

    fn begin_instruction(&mut self, address: Address) -> Result<(), IlError> {
        self.0.begin_instruction(address)?;
        self.1.begin_instruction(address)
    }

    fn constant(&mut self, width: u32, value: u64) -> Result<Self::Value, IlError> {
        Ok((
            self.0.constant(width, value)?,
            self.1.constant(width, value)?,
        ))
    }

    fn address(&mut self, width: u32, offset: u64) -> Result<Self::Value, IlError> {
        Ok((
            self.0.address(width, offset)?,
            self.1.address(width, offset)?,
        ))
    }

    fn undefined(&mut self, width: u32, discriminant: u64) -> Result<Self::Value, IlError> {
        Ok((
            self.0.undefined(width, discriminant)?,
            self.1.undefined(width, discriminant)?,
        ))
    }

    fn read_register(&mut self, register: RegisterId, width: u32) -> Result<Self::Value, IlError> {
        Ok((
            self.0.read_register(register, width)?,
            self.1.read_register(register, width)?,
        ))
    }

    fn read_flag(&mut self, flag: FlagId, width: u32) -> Result<Self::Value, IlError> {
        Ok((
            self.0.read_flag(flag, width)?,
            self.1.read_flag(flag, width)?,
        ))
    }

    fn apply(
        &mut self,
        opcode: ECodeExprOpcode,
        width: u32,
        operands: &[Self::Value],
        immediate: u64,
        address_space: Option<AddressSpaceId>,
    ) -> Result<Self::Value, IlError> {
        let (left, right) = unzip(operands);
        Ok((
            self.0
                .apply(opcode, width, &left, immediate, address_space)?,
            self.1
                .apply(opcode, width, &right, immediate, address_space)?,
        ))
    }

    fn write_register(&mut self, register: RegisterId, value: Self::Value) -> Result<(), IlError> {
        self.0.write_register(register, value.0)?;
        self.1.write_register(register, value.1)
    }

    fn write_flag(&mut self, flag: FlagId, value: Self::Value) -> Result<(), IlError> {
        self.0.write_flag(flag, value.0)?;
        self.1.write_flag(flag, value.1)
    }

    fn store(
        &mut self,
        operands: &[Self::Value],
        address_space: Option<AddressSpaceId>,
    ) -> Result<(), IlError> {
        let (left, right) = unzip(operands);
        self.0.store(&left, address_space)?;
        self.1.store(&right, address_space)
    }

    fn direct_flow(
        &mut self,
        opcode: ECodeStmtOpcode,
        target: Address,
        operands: &[Self::Value],
    ) -> Result<(), IlError> {
        let (left, right) = unzip(operands);
        self.0.direct_flow(opcode, target, &left)?;
        self.1.direct_flow(opcode, target, &right)
    }

    fn indirect_flow(
        &mut self,
        opcode: ECodeStmtOpcode,
        operands: &[Self::Value],
        address_space: Option<AddressSpaceId>,
    ) -> Result<(), IlError> {
        let (left, right) = unzip(operands);
        self.0.indirect_flow(opcode, &left, address_space)?;
        self.1.indirect_flow(opcode, &right, address_space)
    }

    fn intrinsic(
        &mut self,
        intrinsic: u64,
        operands: &[Self::Value],
        address_space: Option<AddressSpaceId>,
    ) -> Result<(), IlError> {
        let (left, right) = unzip(operands);
        self.0.intrinsic(intrinsic, &left, address_space)?;
        self.1.intrinsic(intrinsic, &right, address_space)
    }

    fn trap(
        &mut self,
        intrinsic: u64,
        address_space: Option<AddressSpaceId>,
    ) -> Result<(), IlError> {
        self.0.trap(intrinsic, address_space)?;
        self.1.trap(intrinsic, address_space)
    }
}
