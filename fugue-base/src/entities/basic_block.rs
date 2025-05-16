use crate::lifter::ContextSet;
use crate::types::Address;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BasicBlock {
    start: Address,
    len: usize,
    instructions: Vec<usize>,
    properties: BasicBlockProperties,
    context: ContextSet,
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

impl BasicBlock {
    pub fn new(start: Address, len: usize, instructions: Vec<usize>) -> Self {
        Self::new_with(start, len, instructions, ContextSet::default())
    }

    pub fn new_with(
        start: Address,
        len: usize,
        instructions: Vec<usize>,
        context: ContextSet,
    ) -> Self {
        BasicBlock {
            start,
            len,
            instructions,
            properties: BasicBlockProperties::NONE,
            context,
        }
    }

    pub fn start(&self) -> Address {
        self.start
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn instructions(&self) -> &[usize] {
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
}
