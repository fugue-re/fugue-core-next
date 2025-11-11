use std::ops::Range;

use bincode::{BorrowDecode, Decode, Encode};
use iset::IntervalMap;

use crate::ir::traits::{
    CodeBlockIter, CodeBlockIterMut, CodeBlockMut, CodeBlockRef, CodeBlockTable as CodeBlockTableT,
};
use crate::ir::{Address, CodeBlock, Id, IdSet};
use crate::lifter::ContextSet;
use crate::storage::entities::schema::ENTITY_KEY_CODE_BLOCK_ENTITY_ID;
use crate::storage::entities::{Entity, EntityKeyId, ProjectEntity};
use crate::storage::project::{PersistableProjectEntity, ProjectEntityFromStorage};
use crate::storage::{EntityStorage, EntityStorageError};

#[derive(Clone)]
pub struct IndexedCodeBlockTable {
    blocks: Vec<CodeBlock>,
    bounds: IntervalMap<Address, IdSet<CodeBlock>>,
}

impl Encode for IndexedCodeBlockTable {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.blocks.encode(encoder)?;
        self.bounds.len().encode(encoder)?;
        for (iv, val) in self.bounds.unsorted_iter() {
            iv.encode(encoder)?;
            val.encode(encoder)?;
        }
        Ok(())
    }
}

impl<C> Decode<C> for IndexedCodeBlockTable {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let blocks = Vec::<CodeBlock>::decode(decoder)?;
        let nbounds = usize::decode(decoder)?;
        let mut bounds = IntervalMap::with_capacity(nbounds);
        for _ in 0..nbounds {
            let iv = Range::<Address>::decode(decoder)?;
            let val = IdSet::<CodeBlock>::decode(decoder)?;
            bounds.force_insert(iv, val);
        }
        Ok(Self { blocks, bounds })
    }
}

impl<'de, C> BorrowDecode<'de, C> for IndexedCodeBlockTable {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let blocks = Vec::<CodeBlock>::borrow_decode(decoder)?;
        let nbounds = usize::borrow_decode(decoder)?;
        let mut bounds = IntervalMap::with_capacity(nbounds);
        for _ in 0..nbounds {
            let iv = Range::<Address>::borrow_decode(decoder)?;
            let val = IdSet::<CodeBlock>::borrow_decode(decoder)?;
            bounds.force_insert(iv, val);
        }
        Ok(Self { blocks, bounds })
    }
}

impl IndexedCodeBlockTable {
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
            bounds: IntervalMap::new(),
        }
    }
}

impl CodeBlockTableT for IndexedCodeBlockTable {
    fn insert(&mut self, block: CodeBlock) {
        let id = Id::new(self.blocks.len() as u32);
        let bounds = block.range();
        self.bounds
            .entry(bounds)
            .or_insert_with(IdSet::new)
            .insert(id);
        self.blocks.push(block);
    }

    fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    fn len(&self) -> usize {
        self.blocks.len()
    }

    fn get_by_id(&self, id: Id<CodeBlock>) -> Option<CodeBlockRef> {
        self.blocks.get(id.index())
    }

    fn get_by_id_mut(&mut self, id: Id<CodeBlock>) -> Option<CodeBlockMut> {
        self.blocks.get_mut(id.index())
    }

    fn get_by_address(&self, addr: Address) -> CodeBlockIter {
        CodeBlockIter::new(self.bounds.values(addr..=addr).flat_map(move |id_set| {
            id_set.iter().filter_map(move |id| {
                let block = &self.blocks[id.index()];
                (block.start() == addr).then_some(block)
            })
        }))
    }

    fn get_by_address_and_context<'a>(
        &'a self,
        addr: Address,
        context: &'a ContextSet,
    ) -> CodeBlockIter<'a> {
        CodeBlockIter::new(self.bounds.values(addr..=addr).flat_map(move |id_set| {
            id_set.iter().filter_map(move |id| {
                let block = &self.blocks[id.index()];
                (block.start() == addr && block.context() == context).then_some(block)
            })
        }))
    }

    fn get_by_address_mut(&mut self, addr: Address) -> CodeBlockIterMut {
        let blocks_ptr = self.blocks.as_mut_ptr();
        CodeBlockIterMut::new(self.bounds.values(addr..=addr).flat_map(move |id_set| {
            id_set.iter().filter_map(move |id| {
                // SAFETY:
                //
                // We are guaranteed not to have multiple instances of an
                // Id<CodeBlock> within the sets iterated over.
                //
                // The indices are guaranteed to be valid as they were obtained
                // from the IdSet<CodeBlock> which only contains valid indices.
                //
                let block = unsafe { &mut *blocks_ptr.add(id.index()) };
                (block.start() == addr).then_some(block)
            })
        }))
    }

    fn get_by_address_and_context_mut<'a>(
        &'a mut self,
        addr: Address,
        context: &'a ContextSet,
    ) -> CodeBlockIterMut<'a> {
        let blocks_ptr = self.blocks.as_mut_ptr();
        CodeBlockIterMut::new(self.bounds.values(addr..=addr).flat_map(move |id_set| {
            id_set.iter().filter_map(move |id| {
                // SAFETY: see `get_by_address_mut` for justification.
                let block = unsafe { &mut *blocks_ptr.add(id.index()) };
                (block.start() == addr && block.context() == context).then_some(block)
            })
        }))
    }

    fn contains(&self, addr: Address) -> bool {
        self.bounds.has_overlap(addr..=addr)
    }

    fn overlaps<'a>(&'a self, addr: Address) -> CodeBlockIter<'a> {
        CodeBlockIter::new(
            self.bounds
                .values(addr..=addr)
                .flat_map(|id_set| id_set.iter().map(|id| &self.blocks[id.index()])),
        )
    }

    fn overlaps_mut<'a>(&'a mut self, addr: Address) -> CodeBlockIterMut<'a> {
        let blocks_ptr = self.blocks.as_mut_ptr();
        CodeBlockIterMut::new(self.bounds.values(addr..=addr).flat_map(move |id_set| {
            id_set.iter().map(move |id| {
                // SAFETY: see `get_by_address_mut` for justification.
                unsafe { &mut *blocks_ptr.add(id.index()) }
            })
        }))
    }

    fn iter(&self) -> CodeBlockIter {
        CodeBlockIter::new(self.blocks.iter())
    }

    fn iter_mut(&mut self) -> CodeBlockIterMut {
        CodeBlockIterMut::new(self.blocks.iter_mut())
    }
}

impl Entity for IndexedCodeBlockTable {
    const ID: EntityKeyId = ENTITY_KEY_CODE_BLOCK_ENTITY_ID;
}

impl ProjectEntityFromStorage for IndexedCodeBlockTable {
    fn from_entity_storage(storage: &EntityStorage) -> Result<Option<Self>, EntityStorageError> {
        storage.get(&ProjectEntity::CodeBlockTable)
    }

    fn default_from_entity_storage(_storage: &EntityStorage) -> Result<Self, EntityStorageError> {
        Ok(Self::new())
    }
}

impl PersistableProjectEntity for IndexedCodeBlockTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        storage.insert(&ProjectEntity::CodeBlockTable, self)
    }
}

pub struct CodeBlockTable {
    inner: Box<dyn CodeBlockTableT>,
}

impl CodeBlockTable {
    pub fn new(inner: impl CodeBlockTableT + 'static) -> Self {
        Self {
            inner: Box::new(inner),
        }
    }

    pub fn insert(&mut self, block: CodeBlock) {
        self.inner.insert(block);
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn get_by_id(&self, id: Id<CodeBlock>) -> Option<CodeBlockRef> {
        self.inner.get_by_id(id)
    }

    pub fn get_by_id_mut(&mut self, id: Id<CodeBlock>) -> Option<CodeBlockMut> {
        self.inner.get_by_id_mut(id)
    }

    pub fn get_by_address(&self, addr: impl Into<Address>) -> CodeBlockIter {
        self.inner.get_by_address(addr.into())
    }

    pub fn get_by_address_and_context<'a>(
        &'a self,
        addr: impl Into<Address>,
        context: &'a ContextSet,
    ) -> CodeBlockIter<'a> {
        self.inner.get_by_address_and_context(addr.into(), context)
    }

    pub fn get_by_address_mut(&mut self, addr: impl Into<Address>) -> CodeBlockIterMut {
        self.inner.get_by_address_mut(addr.into())
    }

    pub fn get_by_address_and_context_mut<'a>(
        &'a mut self,
        addr: impl Into<Address>,
        context: &'a ContextSet,
    ) -> CodeBlockIterMut<'a> {
        self.inner
            .get_by_address_and_context_mut(addr.into(), context)
    }

    pub fn contains(&self, addr: impl Into<Address>) -> bool {
        self.inner.contains(addr.into())
    }

    pub fn overlaps<'a>(&'a self, addr: impl Into<Address>) -> CodeBlockIter<'a> {
        self.inner.overlaps(addr.into())
    }

    pub fn overlaps_mut<'a>(&'a mut self, addr: impl Into<Address>) -> CodeBlockIterMut<'a> {
        self.inner.overlaps_mut(addr.into())
    }

    pub fn iter(&self) -> CodeBlockIter {
        self.inner.iter()
    }

    pub fn iter_mut(&mut self) -> CodeBlockIterMut {
        self.inner.iter_mut()
    }
}
