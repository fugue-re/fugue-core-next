use std::collections::BTreeMap;

use ustr::Ustr;

use crate::ir::block::CodeBlockFlowCursor;
use crate::ir::{
    Address, CodeBlockId, CodeBlockRef, CodeBlockTable, FlowTarget, Id, Reference, ReferenceKey,
    ReferenceOrigin, ReferenceProperties,
};
use crate::storage::entities::schema::ENTITY_FUNCTION_ID;
use crate::storage::entities::{Entity, EntityId, MutableEntity};
use crate::types::common::archived_bitflags;

pub mod frame;
pub use frame::{FunctionFrame, StackChangePoint};

pub mod incomplete;
pub use incomplete::{IncompleteFunction, IncompleteFunctionError, InsnEntry};

mod table;
pub(crate) use table::FunctionTableRevert;
pub use table::{FunctionMut, FunctionRef, FunctionTable, FunctionTableError};

pub type FunctionId = Id<Function>;

#[derive(
    Debug, Clone, Default, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct Function {
    id: Id<Self>,
    name: Option<Ustr>,
    entry: Address,
    blocks: Vec<(Address, CodeBlockId)>,
    frame: FunctionFrame,
    properties: FunctionProperties,
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
            blocks: Vec::new(),
            frame: FunctionFrame::default(),
            properties: FunctionProperties::NONE,
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

    pub fn entry_block(&self) -> CodeBlockId {
        self.block_at(self.entry)
            .expect("entry block should always exist")
    }

    pub fn add_block(&mut self, address: Address, block: CodeBlockId) {
        self.blocks.insert(
            self.blocks
                .binary_search_by_key(&address, |(addr, _)| *addr)
                .unwrap_or_else(|idx| idx),
            (address, block),
        );
    }

    pub fn add_blocks(&mut self, blocks: impl IntoIterator<Item = (Address, CodeBlockId)>) {
        self.blocks.extend(blocks);
        self.blocks.sort_by_key(|(addr, _)| *addr);
    }

    pub fn with_blocks(mut self, blocks: impl IntoIterator<Item = (Address, CodeBlockId)>) -> Self {
        self.add_blocks(blocks);
        self
    }

    pub fn blocks(&self) -> impl ExactSizeIterator<Item = (Address, CodeBlockId)> + '_ {
        self.blocks.iter().map(|(addr, blk)| (*addr, *blk))
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
                    return Some(target);
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

    pub fn block_at(&self, address: Address) -> Option<CodeBlockId> {
        self.blocks
            .binary_search_by_key(&address, |(addr, _)| *addr)
            .ok()
            .map(|idx| self.blocks[idx].1)
    }

    pub fn clear_blocks(&mut self) {
        self.blocks.clear();
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
