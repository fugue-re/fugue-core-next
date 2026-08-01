use std::collections::BTreeMap;

use ustr::Ustr;

use crate::ir::block::CodeBlockFlowCursor;
use crate::ir::{
    Address, CodeBlockId, CodeBlockRef, CodeBlockTable, FlowKind, FlowTarget, Id, Reference,
    ReferenceKey, ReferenceOrigin, ReferenceProperties,
};
use crate::storage::entities::schema::ENTITY_FUNCTION_ID;
use crate::storage::entities::{Entity, EntityId, MutableEntity};
use crate::types::common::archived_bitflags;
use crate::types::{Confidence, Revision};

pub(crate) mod frame;
pub use frame::{FunctionFrame, StackChangePoint};

pub(crate) mod incomplete;
pub(crate) use incomplete::{CodeBlockMaterialisation, FunctionInsnIndex, FunctionMaterialisation};
pub use incomplete::{IncompleteFunction, IncompleteFunctionError, InsnEntry};

mod table;
pub use table::{FunctionMut, FunctionRef, FunctionTable, FunctionTableError};
pub(crate) use table::FunctionTableStage;

pub type FunctionId = Id<Function>;

#[derive(
    Debug, Clone, Default, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct Function {
    id: Id<Self>,
    name: Option<Ustr>,
    entry: Address,
    entry_block: CodeBlockId,
    blocks: Vec<(Address, CodeBlockId)>,
    edges: Vec<(CodeBlockId, CodeBlockId)>,
    frame: FunctionFrame,
    properties: FunctionProperties,
    origin: ReferenceOrigin,
    confidence: Confidence,
    input_revision: Revision,
    tail_call_sites: Vec<Address>,
}

impl AsRef<Function> for Function {
    fn as_ref(&self) -> &Function {
        self
    }
}

impl AsMut<Function> for Function {
    fn as_mut(&mut self) -> &mut Function {
        self
    }
}

impl Entity for Function {
    const ID: EntityId = ENTITY_FUNCTION_ID;
}

impl MutableEntity for Function {
    type Key = FunctionId;

    fn entity_key(&self) -> FunctionId {
        self.id
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

archived_bitflags!(FunctionProperties, ArchivedFunctionProperties, u32);

impl Function {
    pub fn new(id: FunctionId, entry: impl Into<Address>) -> Self {
        Self::new_with(id, entry, None)
    }

    pub fn new_with(
        id: FunctionId,
        entry: impl Into<Address>,
        name: impl Into<Option<Ustr>>,
    ) -> Self {
        Function {
            id,
            name: name.into(),
            entry: entry.into(),
            entry_block: CodeBlockId::INVALID,
            blocks: Vec::new(),
            edges: Vec::new(),
            frame: FunctionFrame::default(),
            properties: FunctionProperties::NONE,
            origin: ReferenceOrigin::Derived,
            confidence: Confidence::certain(),
            input_revision: Revision::default(),
            tail_call_sites: Vec::new(),
        }
    }

    pub fn id(&self) -> FunctionId {
        self.id
    }

    pub fn set_id(&mut self, id: FunctionId) {
        self.id = id;
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

    pub fn address(&self) -> Address {
        self.entry
    }

    pub fn entry_block(&self) -> Option<CodeBlockId> {
        self.entry_block.is_valid().then_some(self.entry_block)
    }

    pub fn is_entry_block(&self, block: CodeBlockId) -> bool {
        self.entry_block == block
    }

    pub fn is_exit_block(&self, block: CodeBlockId) -> bool {
        self.blocks.iter().any(|(_, candidate)| *candidate == block) && !self.has_successors(block)
    }

    pub fn add_block(&mut self, address: Address, block: CodeBlockId) {
        let index = self
            .blocks
            .partition_point(|(candidate, _)| *candidate <= address);
        self.blocks.insert(index, (address, block));
        if self.entry_block.is_invalid() && address == self.entry {
            self.entry_block = block;
        }
    }

    pub fn add_blocks(&mut self, blocks: impl IntoIterator<Item = (Address, CodeBlockId)>) {
        for (address, block) in blocks {
            self.add_block(address, block);
        }
    }

    pub fn with_blocks(mut self, blocks: impl IntoIterator<Item = (Address, CodeBlockId)>) -> Self {
        self.add_blocks(blocks);
        self
    }

    fn with_body(
        mut self,
        blocks: Vec<(Address, CodeBlockId)>,
        edges: Vec<(CodeBlockId, CodeBlockId)>,
        entry_block: Option<CodeBlockId>,
    ) -> Self {
        debug_assert!(blocks.is_sorted_by_key(|(address, _)| *address));
        debug_assert!(edges.is_sorted());
        self.blocks = blocks;
        self.edges = edges;
        self.entry_block = entry_block.unwrap_or(CodeBlockId::INVALID);
        self
    }

    pub fn blocks(
        &self,
    ) -> impl DoubleEndedIterator<Item = (Address, CodeBlockId)> + ExactSizeIterator + '_ {
        self.blocks.iter().map(|(addr, blk)| (*addr, *blk))
    }

    pub fn blocks_at(&self, address: Address) -> impl ExactSizeIterator<Item = CodeBlockId> + '_ {
        let start = self
            .blocks
            .partition_point(|(candidate, _)| *candidate < address);
        let end = self
            .blocks
            .partition_point(|(candidate, _)| *candidate <= address);
        self.blocks[start..end].iter().map(|(_, block)| *block)
    }

    pub fn successors(
        &self,
        block: CodeBlockId,
    ) -> impl ExactSizeIterator<Item = CodeBlockId> + '_ {
        let start = self.edges.partition_point(|(source, _)| *source < block);
        let end = self.edges.partition_point(|(source, _)| *source <= block);
        self.edges[start..end]
            .iter()
            .map(|(_, successor)| *successor)
    }

    pub fn has_successors(&self, block: CodeBlockId) -> bool {
        self.edges
            .binary_search_by_key(&block, |(source, _)| *source)
            .is_ok()
    }

    pub(crate) fn edges(&self) -> impl ExactSizeIterator<Item = (CodeBlockId, CodeBlockId)> + '_ {
        self.edges.iter().copied()
    }

    pub(crate) fn set_tail_call_sites(&mut self, sites: impl IntoIterator<Item = Address>) {
        self.tail_call_sites.clear();
        self.tail_call_sites.extend(sites);
        self.tail_call_sites.sort_unstable();
        self.tail_call_sites.dedup();
    }

    pub(crate) fn tail_call_sites(&self) -> impl ExactSizeIterator<Item = Address> + '_ {
        self.tail_call_sites.iter().copied()
    }

    pub(crate) fn classify_flow_target(&self, mut target: FlowTarget) -> FlowTarget {
        if target.kind() == FlowKind::Branch
            && self.tail_call_sites.binary_search(&target.from()).is_ok()
        {
            target = FlowTarget::new(target.from(), target.to(), FlowKind::TailCallBranch);
        }
        target
    }

    pub fn flow_targets<'a>(
        &'a self,
        blocks: &'a CodeBlockTable,
    ) -> impl Iterator<Item = FlowTarget> + 'a {
        let mut ids = self.blocks();
        let mut block = None::<CodeBlockRef<'a>>;
        let mut cursor = CodeBlockFlowCursor::default();

        std::iter::from_fn(move || {
            loop {
                if let Some(current) = block.as_ref()
                    && let Some(target) = current.next_flow_target(&mut cursor)
                {
                    return Some(self.classify_flow_target(target));
                }

                block = ids.find_map(|(_, id)| blocks.get_by_id(id));
                cursor = CodeBlockFlowCursor::default();
                block.as_ref()?;
            }
        })
    }

    pub(crate) fn flow_references(&self, blocks: &CodeBlockTable) -> Vec<Reference> {
        let mut coalesced = BTreeMap::<ReferenceKey, ReferenceProperties>::new();

        for target in self
            .flow_targets(blocks)
            .filter(|target| target.kind().is_global())
        {
            let reference = Reference::from_flow(target.from(), target.to(), target.kind());
            let key = ReferenceKey::new(reference.from(), reference.target());
            coalesced
                .entry(key)
                .and_modify(|properties| *properties |= reference.properties())
                .or_insert_with(|| reference.properties());
        }

        coalesced
            .into_iter()
            .map(|(key, properties)| {
                Reference::flow(key.from(), key.target(), properties)
                    .with_origin(ReferenceOrigin::Derived)
            })
            .collect()
    }

    pub fn clear_blocks(&mut self) {
        self.blocks.clear();
        self.edges.clear();
        self.entry_block = CodeBlockId::INVALID;
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

    pub fn origin(&self) -> ReferenceOrigin {
        self.origin
    }

    pub fn set_origin(&mut self, origin: ReferenceOrigin) {
        self.origin = origin;
    }

    pub fn with_origin(mut self, origin: ReferenceOrigin) -> Self {
        self.origin = origin;
        self
    }

    pub fn is_asserted(&self) -> bool {
        self.origin.is_asserted()
    }

    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    pub fn set_confidence(&mut self, confidence: Confidence) {
        self.confidence = confidence;
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn input_revision(&self) -> Revision {
        self.input_revision
    }

    pub fn set_input_revision(&mut self, input_revision: Revision) {
        self.input_revision = input_revision;
    }

    pub fn with_input_revision(mut self, input_revision: Revision) -> Self {
        self.set_input_revision(input_revision);
        self
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
