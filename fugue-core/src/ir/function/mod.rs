use rkyv::rancor::Fallible;
use rkyv::{Archive, Place, Serialize};
use ustr::Ustr;

use crate::ir::{Address, CodeBlockId, Id};
use crate::storage::entities::schema::ENTITY_FUNCTION_ID;
use crate::storage::entities::{Entity, EntityId, MutableEntity};

pub mod frame;
pub use frame::{FunctionFrame, StackChangePoint};

pub mod table;
pub use table::FunctionTable;

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

impl MutableEntity<FunctionId> for Function {
    fn entity_key(&self) -> FunctionId {
        self.id
    }
}

impl MutableEntity<Address> for Function {
    fn entity_key(&self) -> Address {
        self.entry
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

#[repr(transparent)]
pub struct ArchivedFunctionProperties(rkyv::Archived<u32>);

unsafe impl rkyv::Portable for ArchivedFunctionProperties {}
unsafe impl rkyv::traits::NoUndef for ArchivedFunctionProperties {}

unsafe impl<C: rkyv::rancor::Fallible + ?Sized> rkyv::bytecheck::CheckBytes<C>
    for ArchivedFunctionProperties
where
    rkyv::primitive::ArchivedU32: rkyv::bytecheck::CheckBytes<C>,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe { rkyv::primitive::ArchivedU32::check_bytes(value.cast(), context) }
    }
}

impl Archive for FunctionProperties {
    type Archived = ArchivedFunctionProperties;
    type Resolver = ();

    fn resolve(&self, _: Self::Resolver, out: Place<Self::Archived>) {
        out.write(ArchivedFunctionProperties(
            rkyv::primitive::ArchivedU32::from_native(self.bits()),
        ));
    }
}

impl<S: Fallible + ?Sized> Serialize<S> for FunctionProperties {
    fn serialize(&self, _: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

impl<D: Fallible + ?Sized> rkyv::Deserialize<FunctionProperties, D> for ArchivedFunctionProperties {
    fn deserialize(&self, _: &mut D) -> Result<FunctionProperties, D::Error> {
        Ok(FunctionProperties::from_bits_truncate(self.0.to_native()))
    }
}

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
