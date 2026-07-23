use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use crate::ir::{Address, AddressRange, AddressRangeSet, Id, IdSet, InsnList};
use crate::lifter::ContextSet;
use crate::storage::entities::schema::ENTITY_CODE_BLOCK_ID;
use crate::storage::entities::{Entity, EntityId, MutableEntity};
use crate::storage::segments::space::AddressSpaceId;

pub mod incomplete;
pub use incomplete::{IncompleteCodeBlock, IncompleteCodeBlockId};

pub mod table;
pub use table::CodeBlockTable;

pub type CodeBlockId = Id<CodeBlock>;

#[derive(
    Debug, Clone, Default, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
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

#[repr(transparent)]
pub struct ArchivedCodeBlockProperties(rkyv::Archived<u32>);

unsafe impl rkyv::Portable for ArchivedCodeBlockProperties {}
unsafe impl rkyv::traits::NoUndef for ArchivedCodeBlockProperties {}

unsafe impl<C: rkyv::rancor::Fallible + ?Sized> rkyv::bytecheck::CheckBytes<C>
    for ArchivedCodeBlockProperties
where
    rkyv::primitive::ArchivedU32: rkyv::bytecheck::CheckBytes<C>,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe { rkyv::primitive::ArchivedU32::check_bytes(value.cast(), context) }
    }
}

impl rkyv::Archive for CodeBlockProperties {
    type Archived = ArchivedCodeBlockProperties;
    type Resolver = ();

    fn resolve(&self, _: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        out.write(ArchivedCodeBlockProperties(
            rkyv::primitive::ArchivedU32::from_native(self.bits()),
        ));
    }
}

impl<S: rkyv::rancor::Fallible + ?Sized> rkyv::Serialize<S> for CodeBlockProperties {
    fn serialize(&self, _: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

impl<D: rkyv::rancor::Fallible + ?Sized> rkyv::Deserialize<CodeBlockProperties, D>
    for ArchivedCodeBlockProperties
{
    fn deserialize(&self, _: &mut D) -> Result<CodeBlockProperties, D::Error> {
        Ok(CodeBlockProperties::from_bits(self.0.to_native()).unwrap_or(CodeBlockProperties::NONE))
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

    pub fn try_new(
        id: Id<Self>,
        start: Address,
        len: usize,
        instructions: InsnList,
    ) -> Option<Self> {
        Self::try_new_with(id, start, len, instructions, ContextSet::default())
    }

    pub fn try_new_with(
        id: Id<Self>,
        start: Address,
        len: usize,
        instructions: InsnList,
        context: ContextSet,
    ) -> Option<Self> {
        Some(Self::new_with(
            id,
            start,
            NonZeroUsize::new(len)?,
            instructions,
            context,
        ))
    }

    pub fn id(&self) -> CodeBlockId {
        self.id
    }

    pub fn start(&self) -> Address {
        self.start
    }

    pub fn address(&self) -> Address {
        self.start
    }

    pub fn last_address(&self) -> Address {
        self.start + self.len() - 1usize
    }

    pub fn next_address(&self) -> Address {
        self.start + self.len()
    }

    pub fn space(&self) -> AddressSpaceId {
        self.start.space()
    }

    pub fn len(&self) -> usize {
        self.len as _
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn range(&self) -> RangeInclusive<Address> {
        self.address()..=self.last_address()
    }

    pub fn address_range(&self) -> AddressRange {
        AddressRange::new(
            self.space(),
            self.address().raw_address(),
            self.last_address().raw_address(),
        )
    }

    pub fn coverage(&self) -> AddressRangeSet {
        let mut covered = AddressRangeSet::new();
        self.coverage_into(&mut covered);
        covered
    }

    pub fn coverage_into(&self, covered: &mut AddressRangeSet) {
        if !self.is_empty() {
            covered.insert_range(self.address_range());
        }
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
