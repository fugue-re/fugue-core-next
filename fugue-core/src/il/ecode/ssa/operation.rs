use fugue_bv::BitVec;

use crate::il::common::IlIndexRange;
use crate::il::ecode::ssa::ECodeSsaOpcode;
use crate::ir::Address;
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ECodeSsaOp {
    opcode: ECodeSsaOpcode,
    results: IlIndexRange,
    operands: IlIndexRange,
    width: u32,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<AddressSpaceId>,
}

impl ECodeSsaOp {
    pub(crate) const fn new(
        opcode: ECodeSsaOpcode,
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

    pub const fn with_immediate(mut self, immediate: u64) -> Self {
        self.immediate = immediate;
        self
    }

    pub const fn with_address(mut self, address: Address) -> Self {
        self.address = Some(address);
        self
    }

    pub const fn with_address_space(mut self, address_space: AddressSpaceId) -> Self {
        self.address_space = Some(address_space);
        self
    }

    pub const fn opcode(&self) -> ECodeSsaOpcode {
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

    pub const fn immediate(&self) -> u64 {
        self.immediate
    }

    pub const fn address(&self) -> Option<Address> {
        self.address
    }

    pub const fn address_space(&self) -> Option<AddressSpaceId> {
        self.address_space
    }

    pub(crate) fn constant(&self, constants: &[u8]) -> Option<BitVec> {
        if !matches!(self.opcode, ECodeSsaOpcode::Constant) {
            return None;
        }
        if self.width <= 64 {
            return Some(BitVec::from_u64(self.immediate, self.width));
        }
        let bytes = self.width.div_ceil(8) as usize;
        let start = self.immediate as usize;
        let slice = constants.get(start..start + bytes)?;
        Some(BitVec::from_le_bytes(slice).cast(self.width))
    }

    pub(crate) fn replace_with_constant(&mut self, immediate: u64) {
        self.opcode = ECodeSsaOpcode::Constant;
        self.operands = IlIndexRange::EMPTY;
        self.immediate = immediate;
        self.address = None;
        self.address_space = None;
    }

    pub(crate) fn make_undefined(&mut self) {
        self.opcode = ECodeSsaOpcode::Undefined;
        self.operands = IlIndexRange::EMPTY;
        self.immediate = 0;
        self.address = None;
        self.address_space = None;
    }

    pub(crate) fn set_results(&mut self, results: IlIndexRange) {
        self.results = results;
    }

    pub(crate) fn set_operands(&mut self, operands: IlIndexRange) {
        self.operands = operands;
    }
}
