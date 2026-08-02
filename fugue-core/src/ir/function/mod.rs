use std::collections::BTreeMap;

use rustc_hash::FxHashSet;
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
pub(crate) use incomplete::{FunctionInsnIndex, FunctionMaterialisation};
pub use incomplete::{IncompleteFunction, IncompleteFunctionError, InsnEntry};

mod table;
pub(crate) use table::{
    ATTRIBUTE_FUNCTION_CACHE_SIZE, DEFAULT_FUNCTION_CACHE_BYTES, FunctionTableStage,
    PreparedFunctionMutation,
};
pub use table::{FunctionMut, FunctionRef, FunctionTable, FunctionTableError};

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

    pub(crate) fn set_id(&mut self, id: FunctionId) {
        self.id = id;
    }

    pub fn with_id(mut self, id: FunctionId) -> Self {
        self.set_id(id);
        self
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

    pub fn set_name(&mut self, name: impl Into<Ustr>) {
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

    fn reachable_blocks(
        &self,
        entry: CodeBlockId,
        boundary: CodeBlockId,
    ) -> FxHashSet<CodeBlockId> {
        let mut reachable = FxHashSet::default();
        let mut pending = vec![entry];
        while let Some(block) = pending.pop() {
            if block == boundary || !reachable.insert(block) {
                continue;
            }
            pending.extend(self.successors(block));
        }
        reachable
    }

    fn tail_call_sites_in(
        &self,
        blocks: &CodeBlockTable,
        members: &FxHashSet<CodeBlockId>,
    ) -> Vec<Address> {
        let mut sites = Vec::new();
        for (_, id) in self.blocks().filter(|(_, id)| members.contains(id)) {
            let block = blocks
                .get_by_id(id)
                .expect("function block must exist in the code block table");
            sites.extend(block.flow_targets().filter_map(|target| {
                self.tail_call_sites
                    .binary_search(&target.from())
                    .is_ok()
                    .then_some(target.from())
            }));
        }
        sites.sort_unstable();
        sites.dedup();
        sites
    }

    fn unconditional_branch_sites_to(
        &self,
        blocks: &CodeBlockTable,
        sources: &FxHashSet<CodeBlockId>,
        target: Address,
    ) -> Option<Vec<Address>> {
        let mut sites = Vec::new();
        for &source in sources {
            let block = blocks
                .get_by_id(source)
                .expect("function block must exist in the code block table");
            let before = sites.len();
            sites.extend(block.flow_targets().filter_map(|flow| {
                (flow.kind() == FlowKind::Branch && flow.to() == target).then_some(flow.from())
            }));
            if sites.len() == before {
                return None;
            }
        }
        sites.sort_unstable();
        sites.dedup();
        Some(sites)
    }

    fn tail_call_sources_to(
        &self,
        blocks: &CodeBlockTable,
        members: &FxHashSet<CodeBlockId>,
        target: Address,
    ) -> Vec<(CodeBlockId, Address)> {
        let mut sources = Vec::new();
        for (_, id) in self.blocks().filter(|(_, id)| members.contains(id)) {
            let block = blocks
                .get_by_id(id)
                .expect("function block must exist in the code block table");
            sources.extend(block.flow_targets().filter_map(|flow| {
                (flow.kind() == FlowKind::Branch
                    && flow.to() == target
                    && self.tail_call_sites.binary_search(&flow.from()).is_ok())
                .then_some((id, flow.from()))
            }));
        }
        sources.sort_unstable();
        sources.dedup();
        sources
    }

    fn clear_body_analysis(&mut self) {
        self.frame = FunctionFrame::default();
        self.properties = FunctionProperties::NONE;
    }

    pub(crate) fn split_at_block(
        &self,
        new_entry: CodeBlockId,
        blocks: &CodeBlockTable,
    ) -> Option<(Self, Self)> {
        let current_entry = self.entry_block()?;
        if new_entry == current_entry || !self.blocks.iter().any(|(_, block)| *block == new_entry) {
            return None;
        }
        let split_entry = blocks.get_by_id(new_entry)?.address();
        let child_members = self.reachable_blocks(new_entry, current_entry);
        let parent_reachable = self.reachable_blocks(current_entry, new_entry);
        let exclusive_child = child_members
            .difference(&parent_reachable)
            .copied()
            .collect::<FxHashSet<_>>();
        let parent_members = self
            .blocks()
            .filter_map(|(_, block)| (!exclusive_child.contains(&block)).then_some(block))
            .collect::<FxHashSet<_>>();

        let parent_blocks = self
            .blocks()
            .filter(|(_, block)| parent_members.contains(block))
            .collect::<Vec<_>>();
        let child_blocks = self
            .blocks()
            .filter(|(_, block)| child_members.contains(block))
            .collect::<Vec<_>>();
        if parent_blocks.is_empty() || child_blocks.is_empty() {
            return None;
        }

        let parent_edges = self
            .edges()
            .filter(|(source, target)| {
                parent_members.contains(source) && parent_members.contains(target)
            })
            .collect::<Vec<_>>();
        let child_edges = self
            .edges()
            .filter(|(source, target)| {
                child_members.contains(source) && child_members.contains(target)
            })
            .collect::<Vec<_>>();
        let parent_boundary_sources = self
            .edges()
            .filter_map(|(source, target)| {
                (target == new_entry && parent_members.contains(&source)).then_some(source)
            })
            .collect::<FxHashSet<_>>();
        let child_boundary_sources = self
            .edges()
            .filter_map(|(source, target)| {
                (target == current_entry && child_members.contains(&source)).then_some(source)
            })
            .collect::<FxHashSet<_>>();
        let parent_boundary =
            self.unconditional_branch_sites_to(blocks, &parent_boundary_sources, split_entry)?;
        let child_boundary =
            self.unconditional_branch_sites_to(blocks, &child_boundary_sources, self.entry)?;

        let mut parent_tail_calls = self.tail_call_sites_in(blocks, &parent_members);
        parent_tail_calls.extend(parent_boundary);
        let mut child_tail_calls = self.tail_call_sites_in(blocks, &child_members);
        child_tail_calls.extend(child_boundary);

        let mut parent = self
            .clone()
            .with_body(parent_blocks, parent_edges, Some(current_entry));
        parent.clear_body_analysis();
        parent.set_tail_call_sites(parent_tail_calls);
        let mut child = Self::new(FunctionId::INVALID, split_entry)
            .with_origin(self.origin)
            .with_confidence(self.confidence)
            .with_body(child_blocks, child_edges, Some(new_entry));
        child.set_tail_call_sites(child_tail_calls);
        Some((parent, child))
    }

    pub(crate) fn merge_with(&self, source: &Self, blocks: &CodeBlockTable) -> Option<Self> {
        let target_entry = self.entry_block()?;
        let source_entry = source.entry_block()?;
        let mut members = self.blocks().chain(source.blocks()).collect::<Vec<_>>();
        members.sort_unstable();
        members.dedup();
        let member_ids = members
            .iter()
            .map(|(_, block)| *block)
            .collect::<FxHashSet<_>>();
        let target_boundary = self.tail_call_sources_to(blocks, &member_ids, source.entry);
        let source_boundary = source.tail_call_sources_to(blocks, &member_ids, self.entry);

        let mut edges = self.edges().chain(source.edges()).collect::<Vec<_>>();
        edges.extend(
            target_boundary
                .iter()
                .map(|(block, _)| (*block, source_entry)),
        );
        edges.extend(
            source_boundary
                .iter()
                .map(|(block, _)| (*block, target_entry)),
        );
        edges.sort_unstable();
        edges.dedup();

        let internalised = target_boundary
            .iter()
            .chain(&source_boundary)
            .map(|(_, site)| *site)
            .collect::<FxHashSet<_>>();
        let mut tail_call_sites = self.tail_call_sites_in(blocks, &member_ids);
        tail_call_sites.extend(source.tail_call_sites_in(blocks, &member_ids));
        tail_call_sites.retain(|site| !internalised.contains(site));

        let mut merged = self.clone().with_body(members, edges, Some(target_entry));
        merged.clear_body_analysis();
        merged.set_tail_call_sites(tail_call_sites);
        Some(merged)
    }

    pub(crate) fn set_tail_call_sites(&mut self, sites: impl IntoIterator<Item = Address>) {
        self.tail_call_sites.clear();
        self.tail_call_sites.extend(sites);
        self.tail_call_sites.sort_unstable();
        self.tail_call_sites.dedup();
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
        Self::flow_references_from(self.flow_targets(blocks))
    }

    fn flow_references_from(targets: impl IntoIterator<Item = FlowTarget>) -> Vec<Reference> {
        let mut coalesced = BTreeMap::<ReferenceKey, ReferenceProperties>::new();

        for target in targets
            .into_iter()
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
