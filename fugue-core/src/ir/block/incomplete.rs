use crate::ir::{Address, Id, IdSet, InsnId};
use crate::lifter::ContextSet;

pub type IncompleteCodeBlockId = Id<IncompleteCodeBlock>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IncompleteCodeBlock {
    start: Address,
    size: u16,
    context: ContextSet,
    successors: IdSet<IncompleteCodeBlock>,
    predecessors: IdSet<IncompleteCodeBlock>,
    insns: Vec<InsnId>,
}

impl IncompleteCodeBlock {
    pub fn new(start: Address, size: u16, insns: Vec<InsnId>, context: ContextSet) -> Self {
        Self {
            start,
            size,
            insns,
            predecessors: IdSet::new(),
            successors: IdSet::new(),
            context,
        }
    }

    pub fn try_new(
        start: Address,
        size: usize,
        insns: Vec<InsnId>,
        context: ContextSet,
    ) -> Option<Self> {
        Some(Self::new(start, size.try_into().ok()?, insns, context))
    }

    pub fn address(&self) -> Address {
        self.start
    }

    pub fn size(&self) -> usize {
        self.size as usize
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn insns(&self) -> &[InsnId] {
        &self.insns
    }

    pub fn push_insn(&mut self, insn_id: InsnId) {
        self.insns.push(insn_id);
    }

    pub fn context(&self) -> &ContextSet {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut ContextSet {
        &mut self.context
    }

    pub fn predecessors(&self) -> &IdSet<IncompleteCodeBlock> {
        &self.predecessors
    }

    pub(crate) fn add_predecessor(&mut self, block_id: IncompleteCodeBlockId) {
        self.predecessors.insert(block_id);
    }

    pub(crate) fn remove_predecessor(&mut self, block_id: IncompleteCodeBlockId) {
        self.predecessors.remove(block_id);
    }

    pub fn successors(&self) -> &IdSet<IncompleteCodeBlock> {
        &self.successors
    }

    pub(crate) fn add_successor(&mut self, block_id: IncompleteCodeBlockId) {
        self.successors.insert(block_id);
    }

    pub(crate) fn remove_successor(&mut self, block_id: IncompleteCodeBlockId) {
        self.successors.remove(block_id);
    }
}
