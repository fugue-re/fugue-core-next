use std::mem::size_of;

use fugue_bv::BitVec;

use crate::il::common::IlIndexRange;
use crate::il::mcode::{MCodeOpcode, MCodeVarId};
use crate::ir::Address;
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MCodeOpSpec {
    opcode: MCodeOpcode,
    width: u32,
    variable: Option<MCodeVarId>,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<AddressSpaceId>,
}

impl MCodeOpSpec {
    pub const fn new(opcode: MCodeOpcode, width: u32) -> Self {
        Self {
            opcode,
            width,
            variable: None,
            immediate: 0,
            address: None,
            address_space: None,
        }
    }

    pub const fn set_variable(&mut self, variable: MCodeVarId) {
        self.variable = Some(variable);
    }

    pub const fn with_variable(mut self, variable: MCodeVarId) -> Self {
        self.set_variable(variable);
        self
    }

    pub const fn set_immediate(&mut self, immediate: u64) {
        self.immediate = immediate;
    }

    pub const fn with_immediate(mut self, immediate: u64) -> Self {
        self.set_immediate(immediate);
        self
    }

    pub const fn set_address(&mut self, address: Address) {
        self.address = Some(address);
    }

    pub const fn with_address(mut self, address: Address) -> Self {
        self.set_address(address);
        self
    }

    pub const fn set_address_space(&mut self, address_space: AddressSpaceId) {
        self.address_space = Some(address_space);
    }

    pub const fn with_address_space(mut self, address_space: AddressSpaceId) -> Self {
        self.set_address_space(address_space);
        self
    }

    pub const fn opcode(&self) -> MCodeOpcode {
        self.opcode
    }

    pub const fn width(&self) -> u32 {
        self.width
    }

    pub const fn variable(&self) -> Option<MCodeVarId> {
        self.variable
    }

    pub const fn immediate(&self) -> u64 {
        self.immediate
    }

    pub const fn address(&self) -> Option<Address> {
        self.address
    }

    pub const fn address_space(&self) -> Option<AddressSpaceId> {
        self.address_space
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct MCodeOp {
    opcode: MCodeOpcode,
    results: IlIndexRange,
    operands: IlIndexRange,
    width: u32,
    variable: Option<MCodeVarId>,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<AddressSpaceId>,
}

const _: () = assert!(size_of::<MCodeOp>() <= 64);

impl MCodeOp {
    pub(crate) const fn new(
        opcode: MCodeOpcode,
        results: IlIndexRange,
        operands: IlIndexRange,
        width: u32,
    ) -> Self {
        Self {
            opcode,
            results,
            operands,
            width,
            variable: None,
            immediate: 0,
            address: None,
            address_space: None,
        }
    }

    pub const fn set_variable(&mut self, variable: MCodeVarId) {
        self.variable = Some(variable);
    }

    pub const fn with_variable(mut self, variable: MCodeVarId) -> Self {
        self.set_variable(variable);
        self
    }

    pub const fn set_immediate(&mut self, immediate: u64) {
        self.immediate = immediate;
    }

    pub const fn with_immediate(mut self, immediate: u64) -> Self {
        self.set_immediate(immediate);
        self
    }

    pub const fn set_address(&mut self, address: Address) {
        self.address = Some(address);
    }

    pub const fn with_address(mut self, address: Address) -> Self {
        self.set_address(address);
        self
    }

    pub const fn set_address_space(&mut self, address_space: AddressSpaceId) {
        self.address_space = Some(address_space);
    }

    pub const fn with_address_space(mut self, address_space: AddressSpaceId) -> Self {
        self.set_address_space(address_space);
        self
    }

    pub const fn opcode(&self) -> MCodeOpcode {
        self.opcode
    }

    pub const fn results(&self) -> IlIndexRange {
        self.results
    }

    pub const fn operands(&self) -> IlIndexRange {
        self.operands
    }

    pub const fn width(&self) -> u32 {
        self.width
    }

    pub const fn variable(&self) -> Option<MCodeVarId> {
        self.variable
    }

    pub const fn immediate(&self) -> u64 {
        self.immediate
    }

    pub const fn address(&self) -> Option<Address> {
        self.address
    }

    pub const fn address_space(&self) -> Option<AddressSpaceId> {
        self.address_space
    }

    pub(crate) fn set_results(&mut self, results: IlIndexRange) {
        self.results = results;
    }

    pub(crate) fn set_operands(&mut self, operands: IlIndexRange) {
        self.operands = operands;
    }

    pub(crate) fn constant(&self, constants: &[u8]) -> Option<BitVec> {
        if !matches!(self.opcode, MCodeOpcode::Constant) {
            return None;
        }
        if self.width <= 64 {
            return Some(BitVec::from_u64(self.immediate, self.width));
        }
        let slice = self.constant_bytes(constants)?;
        Some(BitVec::from_le_bytes(slice).cast(self.width))
    }

    pub(crate) fn constant_bytes<'a>(&self, constants: &'a [u8]) -> Option<&'a [u8]> {
        if !matches!(self.opcode, MCodeOpcode::Constant) || self.width <= 64 {
            return None;
        }
        let bytes = usize::try_from(self.width.div_ceil(8)).ok()?;
        let start = usize::try_from(self.immediate).ok()?;
        let end = start.checked_add(bytes)?;
        constants.get(start..end)
    }

    pub(crate) fn replace_with_constant(&mut self, immediate: u64) {
        self.opcode = MCodeOpcode::Constant;
        self.operands = IlIndexRange::EMPTY;
        self.variable = None;
        self.immediate = immediate;
        self.address = None;
        self.address_space = None;
    }

}
