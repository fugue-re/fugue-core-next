use std::mem::size_of;

use fugue_bv::BitVec;

use crate::il::common::{IlIndexRange, IlValueId};
use crate::il::ecode::ECodeOpcode;
use crate::ir::Address;
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ECodeOpSpec {
    opcode: ECodeOpcode,
    width: u32,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<AddressSpaceId>,
}

impl ECodeOpSpec {
    pub const fn new(opcode: ECodeOpcode, width: u32) -> Self {
        Self {
            opcode,
            width,
            immediate: 0,
            address: None,
            address_space: None,
        }
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

    pub const fn opcode(&self) -> ECodeOpcode {
        self.opcode
    }

    pub const fn width(&self) -> u32 {
        self.width
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
pub struct ECodeOp {
    opcode: ECodeOpcode,
    results: IlIndexRange,
    operands: IlIndexRange,
    width: u32,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<AddressSpaceId>,
}

const _: () = assert!(size_of::<ECodeOp>() <= 64);

impl ECodeOp {
    pub(crate) const fn new(
        opcode: ECodeOpcode,
        results: IlIndexRange,
        operands: IlIndexRange,
        width: u32,
    ) -> Self {
        Self {
            opcode,
            results,
            operands,
            width,
            immediate: 0,
            address: None,
            address_space: None,
        }
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

    pub const fn opcode(&self) -> ECodeOpcode {
        self.opcode
    }

    pub const fn results(&self) -> IlIndexRange {
        self.results
    }

    pub fn single_result(&self) -> Option<IlValueId> {
        (self.results.len() == 1)
            .then(|| self.results.start())
            .and_then(|index| IlValueId::try_from_index(index).ok())
    }

    pub const fn operands(&self) -> IlIndexRange {
        self.operands
    }

    pub const fn width(&self) -> u32 {
        self.width
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
        if !matches!(self.opcode, ECodeOpcode::Constant) {
            return None;
        }
        if self.width <= 64 {
            return Some(BitVec::from_u64(self.immediate, self.width));
        }
        let slice = self.constant_bytes(constants)?;
        Some(BitVec::from_le_bytes(slice).cast(self.width))
    }

    pub(crate) fn constant_bytes<'a>(&self, constants: &'a [u8]) -> Option<&'a [u8]> {
        if !matches!(self.opcode, ECodeOpcode::Constant) || self.width <= 64 {
            return None;
        }
        let bytes = usize::try_from(self.width.div_ceil(8)).ok()?;
        let start = usize::try_from(self.immediate).ok()?;
        constants.get(start..start.checked_add(bytes)?)
    }

    pub(crate) fn replace_with_constant(&mut self, immediate: u64) {
        self.opcode = ECodeOpcode::Constant;
        self.operands = IlIndexRange::EMPTY;
        self.immediate = immediate;
        self.address = None;
        self.address_space = None;
    }
}

