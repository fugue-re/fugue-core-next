use bincode::{Decode, Encode};

use crate::ir::{Address, Id, IdSet, InsnList};
use crate::lifter::ContextSet;
use crate::storage::entities::common::ENTITY_BASIC_BLOCK_ID;
use crate::storage::entities::{Entity, EntityId, MutableEntity};

pub type BasicBlockId = Id<BasicBlock>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    id: Id<Self>,
    start: Address,
    len: u16,
    instructions: InsnList,
    successors: IdSet<BasicBlock>,
    predecessors: IdSet<BasicBlock>,
    properties: BasicBlockProperties,
    context: ContextSet,
}

impl Entity for BasicBlock {
    const ID: EntityId = ENTITY_BASIC_BLOCK_ID;
}

impl MutableEntity<BasicBlockId> for BasicBlock {
    fn entity_key(&self) -> BasicBlockId {
        self.id
    }
}

impl Encode for BasicBlock {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.id.encode(encoder)?;
        self.start.encode(encoder)?;
        self.len.encode(encoder)?;
        self.instructions.encode(encoder)?;

        self.successors.encode(encoder)?;
        self.predecessors.encode(encoder)?;

        self.properties.encode(encoder)?;
        self.context.encode(encoder)?;

        Ok(())
    }
}

impl<C> Decode<C> for BasicBlock {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let id = Id::<Self>::decode(decoder)?;
        let start = Address::decode(decoder)?;
        let len = u16::decode(decoder)?;
        let instructions = InsnList::decode(decoder)?;

        let successors_len = usize::decode(decoder)?;
        let mut successors = IdSet::new();
        for _ in 0..successors_len {
            let succ = Id::decode(decoder)?;
            successors.insert(succ);
        }

        let predecessors_len = usize::decode(decoder)?;
        let mut predecessors = IdSet::new();
        for _ in 0..predecessors_len {
            let pred = Id::decode(decoder)?;
            predecessors.insert(pred);
        }

        let properties = BasicBlockProperties::decode(decoder)?;
        let context = ContextSet::decode(decoder)?;

        Ok(BasicBlock {
            id,
            start,
            len,
            instructions,
            successors,
            predecessors,
            properties,
            context,
        })
    }
}

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct BasicBlockProperties: u32 {
        const NONE          = 0x0000_0000;
        /// The block is a function entry point.
        const ENTRY         = 0x0000_0001;
        /// The block is a function exit point.
        const EXIT          = 0x0000_0002;
        /// The block causes the function to not return.
        const NON_RETURNING = 0x0000_0004;
        /// The block ends in a call to another function.
        const CALL          = 0x0000_0008;
        /// The block ends in a tail call to another function.
        const TAIL_CALL     = 0x0000_0010;
        /// The block has unresolved control flow.
        const UNRESOLVED    = 0x0000_0020;
    }
}

impl Encode for BasicBlockProperties {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.bits().encode(encoder)
    }
}

impl<C> Decode<C> for BasicBlockProperties {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let bits = u32::decode(decoder)?;
        Ok(BasicBlockProperties::from_bits(bits).unwrap_or(BasicBlockProperties::NONE))
    }
}

impl BasicBlock {
    pub fn new(id: Id<Self>, start: Address, len: usize, instructions: InsnList) -> Self {
        Self::new_with(id, start, len, instructions, ContextSet::default())
    }

    pub fn new_with(
        id: Id<Self>,
        start: Address,
        len: usize,
        instructions: InsnList,
        context: ContextSet,
    ) -> Self {
        Self {
            id,
            start,
            len: len
                .try_into()
                .expect("basic block length must not exceed 65535"),
            instructions,
            properties: BasicBlockProperties::NONE,
            successors: IdSet::new(),
            predecessors: IdSet::new(),
            context,
        }
    }

    pub fn start(&self) -> Address {
        self.start
    }

    pub fn len(&self) -> usize {
        self.len as _
    }

    pub fn instructions(&self) -> &InsnList {
        &self.instructions
    }

    pub fn mark_entry(&mut self) {
        self.properties.insert(BasicBlockProperties::ENTRY);
    }

    pub fn mark_exit(&mut self) {
        self.properties.insert(BasicBlockProperties::EXIT);
    }

    pub fn mark_non_returning(&mut self) {
        self.properties.insert(BasicBlockProperties::NON_RETURNING);
    }

    pub fn mark_call(&mut self) {
        self.properties.insert(BasicBlockProperties::CALL);
    }

    pub fn mark_tail_call(&mut self) {
        self.properties
            .insert(BasicBlockProperties::TAIL_CALL | BasicBlockProperties::CALL);
    }

    pub fn mark_unresolved(&mut self) {
        self.properties.insert(BasicBlockProperties::UNRESOLVED);
    }

    pub fn is_entry(&self) -> bool {
        self.properties.contains(BasicBlockProperties::ENTRY)
    }

    pub fn is_exit(&self) -> bool {
        self.properties.contains(BasicBlockProperties::EXIT)
    }

    pub fn is_non_returning(&self) -> bool {
        self.properties
            .contains(BasicBlockProperties::NON_RETURNING)
    }

    pub fn is_call(&self) -> bool {
        self.properties.contains(BasicBlockProperties::CALL)
    }

    pub fn is_tail_call(&self) -> bool {
        self.properties.contains(BasicBlockProperties::TAIL_CALL)
    }

    pub fn has_unresolved(&self) -> bool {
        self.properties.contains(BasicBlockProperties::UNRESOLVED)
    }

    pub fn context(&self) -> &ContextSet {
        &self.context
    }

    pub fn add_successor(&mut self, target: BasicBlockId) {
        self.successors.insert(target);
    }

    pub fn add_predecessor(&mut self, source: BasicBlockId) {
        self.predecessors.insert(source);
    }

    pub fn successors(&self) -> &IdSet<BasicBlock> {
        &self.successors
    }

    pub fn predecessors(&self) -> &IdSet<BasicBlock> {
        &self.predecessors
    }
}
