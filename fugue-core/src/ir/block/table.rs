use std::collections::BTreeMap;
use std::mem;
use std::ops::Range;

use bincode::{BorrowDecode, Decode, Encode};
use iset::{Entry, IntervalMap};
use smallvec::SmallVec;
use thiserror::Error;

use crate::ir::traits::{
    CodeBlockIter, CodeBlockIterMut, CodeBlockMut, CodeBlockRef, CodeBlockTable as CodeBlockTableT,
};
use crate::ir::{Address, CodeBlock, Id, IdSet, MetaAddress};
use crate::lifter::ContextSet;
use crate::storage::entities::schema::ENTITY_KEY_CODE_BLOCK_ENTITY_ID;
use crate::storage::entities::{Entity, EntityKeyId, ProjectEntity};
use crate::storage::project::{PersistableProjectEntity, ProjectEntityFromStorage};
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::{EntityStorage, EntityStorageError};

#[derive(Debug, Clone, Default)]
pub struct IndexedCodeBlockTable {
    bounds: BTreeMap<AddressSpaceId, IntervalMap<Address, IdSet<CodeBlock>>>,
    blocks: Vec<CodeBlock>,
    free_ids: Vec<Id<CodeBlock>>,
}

impl Encode for IndexedCodeBlockTable {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.bounds.len().encode(encoder)?;

        for (space_id, iv_map) in self.bounds.iter() {
            space_id.encode(encoder)?;
            iv_map.len().encode(encoder)?;

            for (iv, val) in iv_map.unsorted_iter() {
                iv.encode(encoder)?;
                val.encode(encoder)?;
            }
        }

        self.blocks.encode(encoder)?;
        self.free_ids.encode(encoder)?;
        Ok(())
    }
}

impl<C> Decode<C> for IndexedCodeBlockTable {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let nbounds = usize::decode(decoder)?;
        let mut bounds = BTreeMap::new();

        for _ in 0..nbounds {
            let space_id = AddressSpaceId::decode(decoder)?;
            let nintervals = usize::decode(decoder)?;

            let mut sbounds = IntervalMap::with_capacity(nintervals);

            for _ in 0..nintervals {
                let iv = Range::<Address>::decode(decoder)?;
                let val = IdSet::<CodeBlock>::decode(decoder)?;
                sbounds.force_insert(iv, val);
            }

            bounds.insert(space_id, sbounds);
        }

        let blocks = Vec::<CodeBlock>::decode(decoder)?;
        let free_ids = Vec::<Id<CodeBlock>>::decode(decoder)?;

        Ok(Self {
            bounds,
            blocks,
            free_ids,
        })
    }
}

impl<'de, C> BorrowDecode<'de, C> for IndexedCodeBlockTable {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let nbounds = usize::borrow_decode(decoder)?;
        let mut bounds = BTreeMap::new();

        for _ in 0..nbounds {
            let space_id = AddressSpaceId::borrow_decode(decoder)?;
            let nintervals = usize::borrow_decode(decoder)?;

            let mut sbounds = IntervalMap::with_capacity(nintervals);

            for _ in 0..nintervals {
                let iv = Range::<Address>::borrow_decode(decoder)?;
                let val = IdSet::<CodeBlock>::borrow_decode(decoder)?;
                sbounds.force_insert(iv, val);
            }

            bounds.insert(space_id, sbounds);
        }

        let blocks = Vec::<CodeBlock>::borrow_decode(decoder)?;
        let free_ids = Vec::<Id<CodeBlock>>::borrow_decode(decoder)?;

        Ok(Self {
            bounds,
            blocks,
            free_ids,
        })
    }
}

impl IndexedCodeBlockTable {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Error)]
pub enum IndexedCodeBlockTableError {
    #[error("code block to insert has a different address than that used for insertion")]
    AddressMismatch,
    #[error(transparent)]
    Other(anyhow::Error),
    #[error(transparent)]
    Storage(#[from] EntityStorageError),
}

impl IndexedCodeBlockTableError {
    pub fn other<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Other(anyhow::Error::new(error))
    }

    pub fn other_with<M>(msg: M) -> Self
    where
        M: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    {
        Self::Other(anyhow::Error::msg(msg))
    }
}

impl CodeBlockTableT for IndexedCodeBlockTable {
    type Error = IndexedCodeBlockTableError;

    type CodeBlockRef<'a> = CodeBlockRef<'a>;
    type CodeBlockMut<'a> = CodeBlockMut<'a>;

    type CodeBlockIter<'a> = CodeBlockIter<'a>;
    type CodeBlockIterMut<'a> = CodeBlockIterMut<'a>;

    fn insert<F>(&mut self, addr: MetaAddress, f: F) -> Result<Id<CodeBlock>, Self::Error>
    where
        F: Fn(Id<CodeBlock>, MetaAddress) -> Result<CodeBlock, Self::Error>,
    {
        let (reuse, id) = if let Some(free_id) = self.free_ids.last().copied() {
            (true, free_id)
        } else {
            (false, Id::new(self.blocks.len() as u32))
        };

        let nblk = f(id, addr)?;

        if nblk.start() != addr {
            return Err(IndexedCodeBlockTableError::AddressMismatch);
        }

        let range = nblk.start().address()..nblk.next_address().address();

        self.bounds
            .entry(addr.space())
            .or_default()
            .entry(range)
            .or_default()
            .insert(id);

        if reuse {
            self.free_ids.pop();
            self.blocks[id.index()] = nblk;
        } else {
            self.blocks.push(nblk);
        }

        Ok(id)
    }

    fn remove_by_id(&mut self, id: Id<CodeBlock>) -> bool {
        let Some(blk) = self
            .blocks
            .get_mut(id.index())
            .filter(|blk| blk.id().is_valid())
        else {
            return false;
        };

        let range = blk.start().address()..blk.next_address().address();

        let Some(Entry::Occupied(mut entry)) =
            self.bounds.get_mut(&blk.space()).map(|m| m.entry(range))
        else {
            // this should never happen
            return false;
        };

        let id_set = entry.get_mut();
        id_set.remove(id);

        if id_set.is_empty() {
            entry.remove();
        }

        self.free_ids.push(id);

        mem::take(blk); // remove the block; replace with default

        true
    }

    fn remove_by_address(&mut self, addr: MetaAddress) -> usize {
        let mut removed = 0;

        let space = addr.space();
        let addr = addr.address();

        let Some(bounds) = self.bounds.get_mut(&space) else {
            return removed;
        };

        let ranges_to_remove = bounds
            .intervals_overlap(addr)
            .filter(|iv| iv.start == addr)
            .collect::<SmallVec<[_; 2]>>();

        for range in ranges_to_remove.into_iter() {
            let Some(id_set) = bounds.remove(range) else {
                // this should never happen
                continue;
            };

            for id in id_set.iter().filter(|id| id.is_valid()) {
                let blk = &mut self.blocks[id.index()];

                self.free_ids.push(id);
                mem::take(blk); // remove the block; replace with default
                removed += 1;
            }
        }

        removed
    }

    fn remove_by_address_and_context(&mut self, addr: MetaAddress, context: &ContextSet) -> usize {
        let mut removed = 0;

        let space = addr.space();
        let addr = addr.address();

        let Some(bounds) = self.bounds.get_mut(&space) else {
            return removed;
        };

        let ranges_to_remove = bounds
            .intervals_overlap(addr)
            .filter(|iv| iv.start == addr)
            .collect::<SmallVec<[_; 2]>>();

        for range in ranges_to_remove.into_iter() {
            let Entry::Occupied(id_set) = bounds.entry(range) else {
                // this should never happen
                continue;
            };

            for id in id_set.get().iter().filter(|id| id.is_valid()) {
                let blk = &mut self.blocks[id.index()];

                if blk.context() != context {
                    continue;
                }

                self.free_ids.push(id);
                mem::take(blk); // remove the block; replace with default
                removed += 1;
            }

            if id_set.get().is_empty() {
                id_set.remove();
            }
        }

        removed
    }

    fn get_by_id(&self, id: Id<CodeBlock>) -> Option<CodeBlockRef> {
        self.blocks
            .get(id.index())
            .filter(|blk| blk.id().is_valid())
    }

    fn get_by_id_mut(&mut self, id: Id<CodeBlock>) -> Option<CodeBlockMut> {
        self.blocks
            .get_mut(id.index())
            .filter(|blk| blk.id().is_valid())
    }

    fn get_by_address(&self, maddr: MetaAddress) -> CodeBlockIter {
        let space = maddr.space();
        let addr = maddr.address();

        let bounds = match self.bounds.get(&space) {
            Some(bounds) => bounds,
            None => return CodeBlockIter::new(std::iter::empty()),
        };

        CodeBlockIter::new(bounds.values(addr..=addr).flat_map(move |id_set| {
            id_set.iter().filter_map(move |id| {
                let block = &self.blocks[id.index()];
                (block.start() == maddr).then_some(block)
            })
        }))
    }

    fn get_by_address_and_context<'a>(
        &'a self,
        maddr: MetaAddress,
        context: &'a ContextSet,
    ) -> CodeBlockIter<'a> {
        let space = maddr.space();
        let addr = maddr.address();

        let bounds = match self.bounds.get(&space) {
            Some(bounds) => bounds,
            None => return CodeBlockIter::new(std::iter::empty()),
        };

        CodeBlockIter::new(bounds.values(addr..=addr).flat_map(move |id_set| {
            id_set.iter().filter_map(move |id| {
                let block = &self.blocks[id.index()];
                (block.start() == maddr && block.context() == context).then_some(block)
            })
        }))
    }

    fn get_by_address_mut(&mut self, maddr: MetaAddress) -> CodeBlockIterMut {
        let space = maddr.space();
        let addr = maddr.address();

        let bounds = match self.bounds.get(&space) {
            Some(bounds) => bounds,
            None => return CodeBlockIterMut::new(std::iter::empty()),
        };

        let blocks_ptr = self.blocks.as_mut_ptr();
        CodeBlockIterMut::new(bounds.values(addr..=addr).flat_map(move |id_set| {
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
                (block.start() == maddr).then_some(block)
            })
        }))
    }

    fn get_by_address_and_context_mut<'a>(
        &'a mut self,
        maddr: MetaAddress,
        context: &'a ContextSet,
    ) -> CodeBlockIterMut<'a> {
        let space = maddr.space();
        let addr = maddr.address();

        let bounds = match self.bounds.get(&space) {
            Some(bounds) => bounds,
            None => return CodeBlockIterMut::new(std::iter::empty()),
        };

        let blocks_ptr = self.blocks.as_mut_ptr();
        CodeBlockIterMut::new(bounds.values(addr..=addr).flat_map(move |id_set| {
            id_set.iter().filter_map(move |id| {
                // SAFETY: see `get_by_address_mut` for justification.
                let block = unsafe { &mut *blocks_ptr.add(id.index()) };
                (block.start() == maddr && block.context() == context).then_some(block)
            })
        }))
    }

    fn contains(&self, addr: MetaAddress) -> bool {
        let space = addr.space();
        let addr = addr.address();

        self.bounds
            .get(&space)
            .map_or(false, |bounds| bounds.has_overlap(addr..=addr))
    }

    fn overlaps<'a>(&'a self, addr: MetaAddress) -> CodeBlockIter<'a> {
        let space = addr.space();
        let addr = addr.address();

        let bounds = match self.bounds.get(&space) {
            Some(bounds) => bounds,
            None => return CodeBlockIter::new(std::iter::empty()),
        };

        CodeBlockIter::new(
            bounds
                .values(addr..=addr)
                .flat_map(|id_set| id_set.iter().map(|id| &self.blocks[id.index()])),
        )
    }

    fn overlaps_mut<'a>(&'a mut self, addr: MetaAddress) -> CodeBlockIterMut<'a> {
        let space = addr.space();
        let addr = addr.address();

        let bounds = match self.bounds.get(&space) {
            Some(bounds) => bounds,
            None => return CodeBlockIterMut::new(std::iter::empty()),
        };

        let blocks_ptr = self.blocks.as_mut_ptr();
        CodeBlockIterMut::new(bounds.values(addr..=addr).flat_map(move |id_set| {
            id_set.iter().map(move |id| {
                // SAFETY: see `get_by_address_mut` for justification.
                unsafe { &mut *blocks_ptr.add(id.index()) }
            })
        }))
    }

    fn iter(&self) -> CodeBlockIter {
        CodeBlockIter::new(self.blocks.iter().filter(|blk| blk.id().is_valid()))
    }

    fn iter_mut(&mut self) -> CodeBlockIterMut {
        CodeBlockIterMut::new(self.blocks.iter_mut().filter(|blk| blk.id().is_valid()))
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn len(&self) -> usize {
        self.blocks.len() - self.free_ids.len()
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

#[cfg(test)]
mod test {
    use crate::ir::InsnList;

    use super::*;

    #[test]
    fn test_basic_operations() {
        let mut table = IndexedCodeBlockTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        let addr = MetaAddress::from(0x1000);
        let blk_id = table
            .insert(addr, |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
            })
            .unwrap();
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);

        let blk = table.get_by_id(blk_id).unwrap();
        assert_eq!(blk.start(), addr);
        assert_eq!(blk.len(), 0x10);

        let removed = table.remove_by_id(blk_id);
        assert!(removed);
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_overlapped() {
        let mut table = IndexedCodeBlockTable::new();

        let addr1 = MetaAddress::from(0x1000);
        let addr2 = MetaAddress::from(0x1000); // overlaps with addr1
        let addr3 = MetaAddress::from(0x1005);

        let blk_id1 = table
            .insert(addr1, |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x10, InsnList::new()).unwrap())
            })
            .unwrap();
        let blk_id2 = table
            .insert(addr2, |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x8, InsnList::new()).unwrap())
            })
            .unwrap();
        let blk_id3 = table
            .insert(addr3, |id, start| {
                Ok(CodeBlock::try_new(id, start, 0x6, InsnList::new()).unwrap())
            })
            .unwrap();

        let overlaps = table
            .overlaps(MetaAddress::from(0x1007))
            .collect::<Vec<_>>();
        assert_eq!(overlaps.len(), 3); // all three blocks overlap at 0x1007
        assert!(overlaps.iter().any(|blk| blk.id() == blk_id1));
        assert!(overlaps.iter().any(|blk| blk.id() == blk_id2));
        assert!(overlaps.iter().any(|blk| blk.id() == blk_id3));

        let removed_count = table.remove_by_address(MetaAddress::from(0x1000));
        assert_eq!(removed_count, 2);

        let remaining_blk = table.get_by_id(blk_id3).unwrap();
        assert_eq!(remaining_blk.start(), addr3);
    }
}
