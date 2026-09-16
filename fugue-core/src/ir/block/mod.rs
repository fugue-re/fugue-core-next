use std::ops::RangeInclusive;

use smallvec::SmallVec;

use crate::ir::{Address, AddressRange, AddressRangeSet, FlowKind, FlowTarget, Id};
use crate::lifter::ContextSet;
use crate::storage::entities::schema::{ENTITY_CODE_BLOCK_ID, ENTITY_KEY_CODE_BLOCK_ID};
use crate::storage::entities::{Entity, EntityId, EntityKey, EntityKeyId, MutableEntity};
use crate::storage::schema::bitflags::archived_bitflags;
use crate::storage::segments::space::AddressSpaceId;

pub(crate) mod incomplete;
pub(crate) use incomplete::CodeBlockRecord;
pub use incomplete::{IncompleteCodeBlock, IncompleteCodeBlockId};

mod table;
pub(crate) use table::{
    ATTRIBUTE_CODE_BLOCK_CACHE_SIZE, CodeBlockIdsByAddress, DEFAULT_CODE_BLOCK_CACHE_BYTES,
    PreparedCodeBlockRecord,
};
pub use table::{CodeBlockRef, CodeBlockTable};

pub type CodeBlockId = Id<CodeBlock>;

impl EntityKey for CodeBlockId {
    const ID: EntityKeyId = ENTITY_KEY_CODE_BLOCK_ID;
}

#[derive(
    Debug, Clone, Default, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct CodeBlock {
    id: Id<Self>,
    start: Address,
    size: u16,
    targets: SmallVec<[CodeBlockFlowTarget; 2]>,
    properties: CodeBlockProperties,
    context: ContextSet,
}

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct CodeBlockFlowTarget {
    target: Address,
    source_offset: u16,
    kind: FlowKind,
}

impl CodeBlockFlowTarget {
    fn from_flow(block: Address, size: usize, flow: FlowTarget) -> Self {
        assert_eq!(block.space(), flow.from().space());
        let source_offset = flow
            .from()
            .checked_offset_from(block)
            .and_then(|offset| offset.try_into().ok())
            .expect("flow source must fall within its code block");
        assert!(
            usize::from(source_offset) < size,
            "flow source must fall within its code block"
        );
        Self {
            target: flow.to(),
            source_offset,
            kind: flow.kind(),
        }
    }

    fn to_flow(&self, block: Address) -> FlowTarget {
        FlowTarget::new(
            block + usize::from(self.source_offset),
            self.target,
            self.kind,
        )
    }
}

impl AsRef<CodeBlock> for CodeBlock {
    fn as_ref(&self) -> &CodeBlock {
        self
    }
}

impl AsMut<CodeBlock> for CodeBlock {
    fn as_mut(&mut self) -> &mut CodeBlock {
        self
    }
}

impl Entity for CodeBlock {
    const ID: EntityId = ENTITY_CODE_BLOCK_ID;
}

impl MutableEntity for CodeBlock {
    type Key = CodeBlockId;

    fn entity_key(&self) -> CodeBlockId {
        self.id
    }
}

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CodeBlockProperties: u32 {
        const NONE       = 0x0000_0000;
        /// The block ends in a call to another function.
        const CALL       = 0x0000_0001;
        /// The block has unresolved control flow.
        const UNRESOLVED = 0x0000_0002;
        /// The block ends in a return.
        const RETURN     = 0x0000_0004;
    }
}

archived_bitflags!(CodeBlockProperties, ArchivedCodeBlockProperties, u32);

impl CodeBlock {
    pub fn id(&self) -> CodeBlockId {
        self.id
    }

    pub fn address(&self) -> Address {
        self.start
    }

    pub fn space(&self) -> AddressSpaceId {
        self.start.space()
    }

    pub fn size(&self) -> usize {
        self.size as _
    }

    pub fn is_call(&self) -> bool {
        self.properties.contains(CodeBlockProperties::CALL)
    }

    pub fn is_return(&self) -> bool {
        self.properties.contains(CodeBlockProperties::RETURN)
    }

    pub fn is_branch(&self) -> bool {
        self.targets.iter().any(|target| target.kind.is_branch())
    }

    pub fn call_target(&self) -> Option<Address> {
        self.targets
            .iter()
            .find_map(|target| target.kind.is_call().then_some(target.target))
    }

    pub fn has_unresolved(&self) -> bool {
        self.properties.contains(CodeBlockProperties::UNRESOLVED)
    }

    pub fn context(&self) -> &ContextSet {
        &self.context
    }

    pub fn last_address(&self) -> Address {
        self.start + self.size() - 1usize
    }

    pub fn next_address(&self) -> Address {
        self.start + self.size()
    }

    pub fn range(&self) -> RangeInclusive<Address> {
        self.address()..=self.last_address()
    }

    pub fn address_range(&self) -> AddressRange {
        AddressRange::from_size(self.address(), u64::from(self.size))
            .expect("code block range must fit within its address space")
    }

    pub fn coverage(&self) -> AddressRangeSet {
        let mut covered = AddressRangeSet::new();
        self.coverage_into(&mut covered);
        covered
    }

    pub fn coverage_into(&self, covered: &mut AddressRangeSet) {
        covered.insert_range(self.address_range());
    }

    pub fn flow_targets(&self) -> impl Iterator<Item = FlowTarget> + '_ {
        self.targets.iter().map(|target| target.to_flow(self.start))
    }
}
