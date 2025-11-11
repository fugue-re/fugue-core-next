use std::num::NonZeroUsize;
use std::ops::Range;

use bincode::{BorrowDecode, Decode, Encode};

use crate::ir::{Address, Id, IdSet, InsnList};
use crate::lifter::ContextSet;
use crate::storage::entities::schema::ENTITY_CODE_BLOCK_ID;
use crate::storage::entities::{Entity, EntityId, MutableEntity};

pub mod table;
pub use table::{CodeBlockTable, IndexedCodeBlockTable};

pub type CodeBlockId = Id<CodeBlock>;

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
pub struct CodeBlock {
    id: Id<Self>,
    start: Address,
    len: u16,
    instructions: InsnList,
    successors: IdSet<CodeBlock>,
    predecessors: IdSet<CodeBlock>,
    properties: CodeBlockProperties,
    context: ContextSet,
}

impl Entity for CodeBlock {
    const ID: EntityId = ENTITY_CODE_BLOCK_ID;
}

impl MutableEntity<CodeBlockId> for CodeBlock {
    fn entity_key(&self) -> CodeBlockId {
        self.id
    }
}

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CodeBlockProperties: u32 {
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

impl Encode for CodeBlockProperties {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.bits().encode(encoder)
    }
}

impl<C> Decode<C> for CodeBlockProperties {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let bits = u32::decode(decoder)?;
        Ok(CodeBlockProperties::from_bits(bits).unwrap_or(CodeBlockProperties::NONE))
    }
}

impl<'de, C> BorrowDecode<'de, C> for CodeBlockProperties {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let bits = u32::borrow_decode(decoder)?;
        Ok(CodeBlockProperties::from_bits(bits).unwrap_or(CodeBlockProperties::NONE))
    }
}

impl CodeBlock {
    pub fn new(id: Id<Self>, start: Address, len: NonZeroUsize, instructions: InsnList) -> Self {
        Self::new_with(id, start, len, instructions, ContextSet::default())
    }

    pub fn new_with(
        id: Id<Self>,
        start: Address,
        len: NonZeroUsize,
        instructions: InsnList,
        context: ContextSet,
    ) -> Self {
        Self {
            id,
            start,
            len: len
                .get()
                .try_into()
                .expect("basic block length must not exceed 65535 bytes"),
            instructions,
            properties: CodeBlockProperties::NONE,
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

    pub fn range(&self) -> Range<Address> {
        self.start..(self.start + self.len())
    }

    pub fn instructions(&self) -> &InsnList {
        &self.instructions
    }

    pub fn mark_entry(&mut self) {
        self.properties.insert(CodeBlockProperties::ENTRY);
    }

    pub fn mark_exit(&mut self) {
        self.properties.insert(CodeBlockProperties::EXIT);
    }

    pub fn mark_non_returning(&mut self) {
        self.properties.insert(CodeBlockProperties::NON_RETURNING);
    }

    pub fn mark_call(&mut self) {
        self.properties.insert(CodeBlockProperties::CALL);
    }

    pub fn mark_tail_call(&mut self) {
        self.properties
            .insert(CodeBlockProperties::TAIL_CALL | CodeBlockProperties::CALL);
    }

    pub fn mark_unresolved(&mut self) {
        self.properties.insert(CodeBlockProperties::UNRESOLVED);
    }

    pub fn is_entry(&self) -> bool {
        self.properties.contains(CodeBlockProperties::ENTRY)
    }

    pub fn is_exit(&self) -> bool {
        self.properties.contains(CodeBlockProperties::EXIT)
    }

    pub fn is_non_returning(&self) -> bool {
        self.properties.contains(CodeBlockProperties::NON_RETURNING)
    }

    pub fn is_call(&self) -> bool {
        self.properties.contains(CodeBlockProperties::CALL)
    }

    pub fn is_tail_call(&self) -> bool {
        self.properties.contains(CodeBlockProperties::TAIL_CALL)
    }

    pub fn has_unresolved(&self) -> bool {
        self.properties.contains(CodeBlockProperties::UNRESOLVED)
    }

    pub fn context(&self) -> &ContextSet {
        &self.context
    }

    pub fn add_successor(&mut self, target: CodeBlockId) {
        self.successors.insert(target);
    }

    pub fn add_predecessor(&mut self, source: CodeBlockId) {
        self.predecessors.insert(source);
    }

    pub fn successors(&self) -> &IdSet<CodeBlock> {
        &self.successors
    }

    pub fn predecessors(&self) -> &IdSet<CodeBlock> {
        &self.predecessors
    }
}
