use bincode::{BorrowDecode, Decode, Encode};
use iset::IntervalMap;

use crate::ir::traits::{
    CodeBlockIter, CodeBlockIterMut, CodeBlockMut, CodeBlockRef, CodeBlockTable as CodeBlockTableT,
};
use crate::ir::{Address, CodeBlock, Id, IdSet};
use crate::storage::entities::schema::ENTITY_KEY_CODE_BLOCK_ENTITY_ID;
use crate::storage::entities::{
    DefaultFromEntityStorage, Entity, EntityKeyId, PersistableEntity, ProjectEntity,
};
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
        todo!()
    }
}

impl<C> Decode<C> for IndexedCodeBlockTable {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        todo!()
    }
}

impl<'de, C> BorrowDecode<'de, C> for IndexedCodeBlockTable {
    fn borrow_decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        todo!()
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

    fn get_by_address_mut(&mut self, addr: Address) -> CodeBlockIterMut {
        todo!()
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
        todo!()
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

impl DefaultFromEntityStorage for IndexedCodeBlockTable {
    fn default_from_entity_storage(
        _storage: &EntityStorage,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::new())
    }
}

impl PersistableEntity for IndexedCodeBlockTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        storage.insert(&ProjectEntity::CodeBlockTable, self)
    }
}
