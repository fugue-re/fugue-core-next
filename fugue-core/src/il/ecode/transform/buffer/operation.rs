use std::mem::size_of;

use crate::il::common::{IlExprId, IlIndexRange};
use crate::il::ecode::ECodeOpcode;
use crate::ir::Address;
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct PCodeToECodeEffect {
    opcode: ECodeOpcode,
    operands: IlIndexRange,
    value: Option<IlExprId>,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<AddressSpaceId>,
}

impl PCodeToECodeEffect {
    pub(crate) const fn new(
        opcode: ECodeOpcode,
        operands: IlIndexRange,
        value: Option<IlExprId>,
        address: Option<Address>,
        address_space: Option<AddressSpaceId>,
    ) -> Self {
        Self {
            opcode,
            operands,
            value,
            immediate: 0,
            address,
            address_space,
        }
    }

    pub(crate) const fn set_immediate(&mut self, immediate: u64) {
        self.immediate = immediate;
    }

    pub(crate) const fn with_immediate(mut self, immediate: u64) -> Self {
        self.set_immediate(immediate);
        self
    }

    pub(crate) const fn opcode(&self) -> ECodeOpcode {
        self.opcode
    }

    pub(crate) const fn operands(&self) -> IlIndexRange {
        self.operands
    }

    pub(crate) const fn value(&self) -> Option<IlExprId> {
        self.value
    }

    pub(crate) const fn immediate(&self) -> u64 {
        self.immediate
    }

    pub(crate) const fn address(&self) -> Option<Address> {
        self.address
    }

    pub(crate) const fn address_space(&self) -> Option<AddressSpaceId> {
        self.address_space
    }
}

const _: () = assert!(size_of::<PCodeToECodeEffect>() <= 64);
