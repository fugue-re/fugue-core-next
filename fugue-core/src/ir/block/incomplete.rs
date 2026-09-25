use std::num::NonZeroU16;

use smallvec::SmallVec;

use crate::ir::block::CodeBlockFlowTarget;
use crate::ir::{
    Address, AddressRange, CodeBlock, CodeBlockId, CodeBlockProperties, FlowTarget, Id, IdSet,
    Insn, InsnId,
};
use crate::lifter::ContextSet;

pub type IncompleteCodeBlockId = Id<IncompleteCodeBlock>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IncompleteCodeBlock {
    start: Address,
    size: u16,
    context: ContextSet,
    successors: IdSet<IncompleteCodeBlock>,
    predecessors: IdSet<IncompleteCodeBlock>,
    insn_ids: Vec<InsnId>,
}

pub(crate) struct CodeBlockRecord {
    address: Address,
    context: ContextSet,
    targets: SmallVec<[CodeBlockFlowTarget; 2]>,
    properties: CodeBlockProperties,
    size: NonZeroU16,
}

impl IncompleteCodeBlock {
    pub fn new(start: Address, size: u16, insn_ids: Vec<InsnId>, context: ContextSet) -> Self {
        Self {
            start,
            size,
            insn_ids,
            predecessors: IdSet::new(),
            successors: IdSet::new(),
            context,
        }
    }

    pub fn try_new(
        start: Address,
        size: usize,
        insn_ids: Vec<InsnId>,
        context: ContextSet,
    ) -> Option<Self> {
        Some(Self::new(start, size.try_into().ok()?, insn_ids, context))
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

    pub fn insn_ids(&self) -> &[InsnId] {
        &self.insn_ids
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

    pub fn successors(&self) -> &IdSet<IncompleteCodeBlock> {
        &self.successors
    }

    pub fn push_insn(&mut self, id: InsnId) {
        self.insn_ids.push(id);
    }

    pub(crate) fn add_predecessor(&mut self, block_id: IncompleteCodeBlockId) {
        self.predecessors.insert(block_id);
    }

    pub(crate) fn remove_predecessor(&mut self, block_id: IncompleteCodeBlockId) {
        self.predecessors.remove(block_id);
    }

    pub(crate) fn add_successor(&mut self, block_id: IncompleteCodeBlockId) {
        self.successors.insert(block_id);
    }

    pub(crate) fn remove_successor(&mut self, block_id: IncompleteCodeBlockId) {
        self.successors.remove(block_id);
    }
}

impl CodeBlockRecord {
    pub(crate) fn new<'a>(
        address: Address,
        size: NonZeroU16,
        insns: impl IntoIterator<Item = &'a Insn>,
        context: ContextSet,
    ) -> Self {
        let mut targets = SmallVec::new();
        let mut properties = CodeBlockProperties::NONE;
        let mut terminator = None;
        for insn in insns {
            targets.extend(
                insn.flow_targets()
                    .filter(|target| {
                        !target.kind().is_fall_through()
                            || target.to() == address + usize::from(size.get())
                    })
                    .map(|target| {
                        CodeBlockFlowTarget::from_flow(address, usize::from(size.get()), target)
                    }),
            );
            terminator = Some(insn);
        }
        if let Some(terminator) = terminator {
            if terminator.is_call() {
                properties |= CodeBlockProperties::CALL;
            }
            if terminator.is_return() {
                properties |= CodeBlockProperties::RETURN;
            }
            if terminator.is_branch()
                && terminator.is_indirect()
                && !terminator.is_call()
                && !terminator.is_return()
                && terminator.iter_targets().next().is_none()
            {
                properties |= CodeBlockProperties::UNRESOLVED;
            }
        }
        Self {
            address,
            context,
            targets,
            properties,
            size,
        }
    }

    pub(crate) fn address(&self) -> Address {
        self.address
    }

    pub(crate) fn context(&self) -> &ContextSet {
        &self.context
    }

    pub(crate) fn address_range(&self) -> AddressRange {
        AddressRange::from_size(self.address, u64::from(self.size.get()))
            .expect("code block range must fit within its address space")
    }

    pub(crate) fn flow_targets(&self) -> impl Iterator<Item = FlowTarget> + '_ {
        self.targets
            .iter()
            .map(|target| target.to_flow(self.address))
    }

    pub(crate) fn matches(&self, block: &CodeBlock) -> bool {
        block.start == self.address
            && block.size() == usize::from(self.size.get())
            && block.context == self.context
            && block.targets == self.targets
            && block.properties == self.properties
    }

    pub(crate) fn materialise(self, id: CodeBlockId) -> CodeBlock {
        CodeBlock {
            id,
            start: self.address,
            size: self.size.get(),
            targets: self.targets,
            properties: self.properties,
            context: self.context,
        }
    }
}
