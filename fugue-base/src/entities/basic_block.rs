use crate::lifter::ContextSet;
use crate::types::Address;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BasicBlock {
    start: Address,
    len: usize,
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
        /// The block ends in a tail call.
        const TAIL_CALL     = 0x0000_0010;
        /// The block has unresolved control flow.
        const UNRESOLVED    = 0x0000_0020;
    }
}

impl BasicBlock {
    pub fn new(start: Address, len: usize) -> Self {
        Self::new_with(start, len, ContextSet::default())
    }

    pub fn new_with(start: Address, len: usize, context: ContextSet) -> Self {
        BasicBlock {
            start,
            len,
            context,
        }
    }

    pub fn start(&self) -> Address {
        self.start
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn context(&self) -> &ContextSet {
        &self.context
    }
}
