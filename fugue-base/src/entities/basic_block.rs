use bincode::{Decode, Encode};
use tinyset::SetUsize;

use crate::entities::instruction::InsnList;
use crate::lifter::ContextSet;
use crate::types::Address;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    start: Address,
    len: usize,
    instructions: InsnList,
    successors: SetUsize,
    predecessors: SetUsize,
    properties: BasicBlockProperties,
    context: ContextSet,
}

impl Encode for BasicBlock {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.start.encode(encoder)?;
        self.len.encode(encoder)?;
        self.instructions.encode(encoder)?;

        // TODO: figure out a more optimal encoding, since this expands the whole
        // set--defeating the purpose of using SetUsize (at least for storage).

        self.successors.len().encode(encoder)?;
        for succ in self.successors.iter() {
            succ.encode(encoder)?;
        }

        self.predecessors.len().encode(encoder)?;
        for pred in self.predecessors.iter() {
            pred.encode(encoder)?;
        }

        self.properties.encode(encoder)?;
        self.context.encode(encoder)?;
        Ok(())
    }
}

impl<C> Decode<C> for BasicBlock {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let start = Address::decode(decoder)?;
        let len = usize::decode(decoder)?;
        let instructions = InsnList::decode(decoder)?;

        let successors_len = usize::decode(decoder)?;
        let mut successors = SetUsize::new();
        for _ in 0..successors_len {
            let succ = usize::decode(decoder)?;
            successors.insert(succ);
        }

        let predecessors_len = usize::decode(decoder)?;
        let mut predecessors = SetUsize::new();
        for _ in 0..predecessors_len {
            let pred = usize::decode(decoder)?;
            predecessors.insert(pred);
        }

        let properties = BasicBlockProperties::decode(decoder)?;
        let context = ContextSet::decode(decoder)?;

        Ok(BasicBlock {
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
    pub fn new(start: Address, len: usize, instructions: InsnList) -> Self {
        Self::new_with(start, len, instructions, ContextSet::default())
    }

    pub fn new_with(
        start: Address,
        len: usize,
        instructions: InsnList,
        context: ContextSet,
    ) -> Self {
        BasicBlock {
            start,
            len,
            instructions,
            properties: BasicBlockProperties::NONE,
            successors: SetUsize::new(),
            predecessors: SetUsize::new(),
            context,
        }
    }

    pub fn start(&self) -> Address {
        self.start
    }

    pub fn len(&self) -> usize {
        self.len
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

    pub fn add_successor(&mut self, target: usize) {
        self.successors.insert(target);
    }

    pub fn add_predecessor(&mut self, source: usize) {
        self.predecessors.insert(source);
    }

    pub fn successors(&self) -> &SetUsize {
        &self.successors
    }

    pub fn predecessors(&self) -> &SetUsize {
        &self.predecessors
    }
}
