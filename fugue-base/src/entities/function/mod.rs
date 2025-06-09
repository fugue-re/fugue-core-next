use ustr::Ustr;

use crate::entities::{BasicBlock, Insn};
use crate::types::Address;

pub mod frame;
pub use frame::{FunctionFrame, StackChangePoint};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    name: Option<Ustr>,
    entry: Address,
    blocks: Vec<BasicBlock>,
    instructions: Vec<Insn>,
    frame: FunctionFrame,
    properties: FunctionProperties,
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

impl Function {
    pub fn new(entry: Address) -> Self {
        Self::new_with(None, entry)
    }

    pub fn new_with(name: impl Into<Option<Ustr>>, entry: Address) -> Self {
        Function {
            name: name.into(),
            entry,
            blocks: Vec::new(),
            instructions: Vec::new(),
            frame: FunctionFrame::default(),
            properties: FunctionProperties::NONE,
        }
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

    pub fn entry_block(&self) -> &BasicBlock {
        self.block_at(self.entry).expect("entry block should always exist")
    }

    pub fn add_block(&mut self, block: BasicBlock) {
        self.blocks.push(block);
        self.blocks.sort_by_key(|blk| blk.start());
    }

    pub fn blocks(&self) -> &[BasicBlock] {
        &self.blocks
    }

    pub fn block_at(&self, address: Address) -> Option<&BasicBlock> {
        self.blocks.binary_search_by_key(&address, |blk| blk.start())
            .ok()
            .map(|idx| &self.blocks[idx])
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
}
