use bincode::{Decode, Encode};
use ustr::Ustr;

use crate::entities::BasicBlockId;
use crate::storage::entities::common::ENTITY_FUNCTION_ID;
use crate::storage::entities::{Entity, EntityId, MutableEntity};
use crate::types::Address;

pub mod frame;
pub use frame::{FunctionFrame, StackChangePoint};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    name: Option<Ustr>,
    entry: Address,
    blocks: Vec<(Address, BasicBlockId)>,
    frame: FunctionFrame,
    properties: FunctionProperties,
}

impl Entity for Function {
    const ID: EntityId = ENTITY_FUNCTION_ID;
}

impl MutableEntity<Address> for Function {
    fn entity_key(&self) -> Address {
        self.entry
    }
}

impl Encode for Function {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        use bincode::serde::Compat;

        Compat(&self.name).encode(encoder)?;
        self.entry.encode(encoder)?;
        self.blocks.encode(encoder)?;
        self.frame.encode(encoder)?;
        self.properties.encode(encoder)?;

        Ok(())
    }
}

impl<C> Decode<C> for Function {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        use bincode::serde::Compat;

        let Compat(name) = Compat::<Option<Ustr>>::decode(decoder)?;
        let entry = Address::decode(decoder)?;
        let blocks = Vec::<(Address, BasicBlockId)>::decode(decoder)?;
        let frame = FunctionFrame::decode(decoder)?;
        let properties = FunctionProperties::decode(decoder)?;

        Ok(Function {
            name,
            entry,
            blocks,
            frame,
            properties,
        })
    }
}

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct FunctionProperties: u32 {
        const NONE          = 0x0000_0000;
        /// Function does not return.
        const NON_RETURNING = 0x0000_0001;
        /// Thunk (jump) function, e.g., .plt entry.
        const THUNK         = 0x0000_0002;
        /// External (virtual function) not in the current module.
        const EXTERNAL      = 0x0000_0004;
    }
}

impl Encode for FunctionProperties {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.bits().encode(encoder)
    }
}

impl<C> Decode<C> for FunctionProperties {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let bits = u32::decode(decoder)?;
        Ok(FunctionProperties::from_bits_truncate(bits))
    }
}

impl Function {
    pub fn new(entry: Address) -> Self {
        Self::new_with(None, entry)
    }

    pub fn new_with(name: impl Into<Option<Ustr>>, entry: Address) -> Self {
        Function {
            name: name.into(),
            entry,
            blocks: Vec::new(),
            frame: FunctionFrame::default(),
            properties: FunctionProperties::NONE,
        }
    }

    pub fn set_frame(&mut self, frame: FunctionFrame) {
        self.frame = frame;
    }

    pub fn with_frame(mut self, frame: FunctionFrame) -> Self {
        self.set_frame(frame);
        self
    }

    pub fn frame(&self) -> &FunctionFrame {
        &self.frame
    }

    pub fn update_name(&mut self, name: impl Into<Ustr>) {
        self.name = Some(name.into());
    }

    pub fn clear_name(&mut self) {
        self.name = None;
    }

    pub fn name(&self) -> Option<Ustr> {
        self.name
    }

    pub fn entry(&self) -> Address {
        self.entry
    }

    pub fn entry_block(&self) -> BasicBlockId {
        self.block_at(self.entry)
            .expect("entry block should always exist")
    }

    pub(crate) fn add_block(&mut self, address: Address, block: BasicBlockId) {
        self.blocks.insert(
            self.blocks
                .binary_search_by_key(&address, |(addr, _)| *addr)
                .unwrap_or_else(|idx| idx),
            (address, block),
        );
    }

    pub(crate) fn add_blocks(&mut self, blocks: impl IntoIterator<Item = (Address, BasicBlockId)>) {
        self.blocks.extend(blocks);
        self.blocks.sort_by_key(|(addr, _)| *addr);
    }

    pub fn blocks(&self) -> impl ExactSizeIterator<Item = (Address, BasicBlockId)> + '_ {
        self.blocks.iter().map(|(addr, blk)| (*addr, *blk))
    }

    pub fn block_at(&self, address: Address) -> Option<BasicBlockId> {
        self.blocks
            .binary_search_by_key(&address, |(addr, _)| *addr)
            .ok()
            .map(|idx| self.blocks[idx].1)
    }

    pub fn is_non_returning(&self) -> bool {
        self.properties.contains(FunctionProperties::NON_RETURNING)
    }

    pub fn mark_non_returning(&mut self) {
        self.properties.insert(FunctionProperties::NON_RETURNING);
    }

    pub fn is_thunk(&self) -> bool {
        self.properties.contains(FunctionProperties::THUNK)
    }

    pub fn mark_thunk(&mut self) {
        self.properties.insert(FunctionProperties::THUNK);
    }

    pub fn is_external(&self) -> bool {
        self.properties.contains(FunctionProperties::EXTERNAL)
    }

    pub fn mark_external(&mut self) {
        self.properties.insert(FunctionProperties::EXTERNAL);
    }

    pub fn properties(&self) -> FunctionProperties {
        self.properties
    }

    pub fn set_properties(&mut self, properties: FunctionProperties) {
        self.properties = properties;
    }

    pub fn with_properties(mut self, properties: FunctionProperties) -> Self {
        self.set_properties(properties);
        self
    }
}
