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
    type CodeBlockRef<'a> = CodeBlockRef<'a>;
    type CodeBlockMut<'a> = CodeBlockMut<'a>;

    type CodeBlockIter<'a> = CodeBlockIter<'a>;
    type CodeBlockIterMut<'a> = CodeBlockIterMut<'a>;

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
