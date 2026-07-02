use std::collections::BTreeMap;
use std::mem;

use iset::{Entry, IntervalMap};
use smallvec::SmallVec;
use thiserror::Error;

use crate::ir::{Address, CodeBlock, Id, IdSet, RawAddress};
use crate::lifter::ContextSet;
use crate::storage::entities::schema::ENTITY_CODE_BLOCK_TABLE_ID;
use crate::storage::entities::{Entity, EntityId, ProjectEntity};
use crate::storage::project::{PersistableProjectEntity, ProjectEntityFromStorage};
use crate::storage::segments::space::AddressSpaceId;
use crate::storage::{EntityStorage, EntityStorageError};

#[derive(Debug, Clone, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct CodeBlockTable {
    bounds: BTreeMap<AddressSpaceId, IntervalMap<RawAddress, IdSet<CodeBlock>>>,
    blocks: Vec<CodeBlock>,
    free_ids: Vec<Id<CodeBlock>>,
}

impl CodeBlockTable {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Error)]
pub enum CodeBlockTableError {
    #[error("code block to insert has a different address than that used for insertion")]
    AddressMismatch,
    #[error(transparent)]
    Other(anyhow::Error),
    #[error(transparent)]
    Storage(#[from] EntityStorageError),
}

impl CodeBlockTableError {
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

pub type CodeBlockRef<'a> = &'a CodeBlock;
pub type CodeBlockMut<'a> = &'a mut CodeBlock;

pub struct CodeBlockIter<'a> {
    inner: Box<dyn Iterator<Item = CodeBlockRef<'a>> + 'a>,
}

impl<'a> CodeBlockIter<'a> {
    pub fn new(iter: impl Iterator<Item = CodeBlockRef<'a>> + 'a) -> Self {
        Self {
            inner: Box::new(iter),
        }
    }
}

impl<'a> Iterator for CodeBlockIter<'a> {
    type Item = CodeBlockRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

pub struct CodeBlockIterMut<'a> {
    inner: Box<dyn Iterator<Item = CodeBlockMut<'a>> + 'a>,
}

impl<'a> CodeBlockIterMut<'a> {
    pub fn new(iter: impl Iterator<Item = CodeBlockMut<'a>> + 'a) -> Self {
        Self {
            inner: Box::new(iter),
        }
    }
}

impl<'a> Iterator for CodeBlockIterMut<'a> {
    type Item = CodeBlockMut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl CodeBlockTable {
    pub fn insert<F>(&mut self, addr: Address, f: F) -> Result<Id<CodeBlock>, CodeBlockTableError>
    where
        F: Fn(Id<CodeBlock>, Address) -> Result<CodeBlock, CodeBlockTableError>,
    {
        let (reuse, id) = if let Some(free_id) = self.free_ids.last().copied() {
            (true, free_id)
        } else {
            (false, Id::new(self.blocks.len() as u32))
        };

        let nblk = f(id, addr)?;

        if nblk.start() != addr {
            return Err(CodeBlockTableError::AddressMismatch);
        }

        let range = nblk.start().raw_address()..nblk.next_address().raw_address();

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

    pub fn remove_by_id(&mut self, id: Id<CodeBlock>) -> bool {
        let Some(blk) = self
            .blocks
            .get_mut(id.index())
            .filter(|blk| blk.id().is_valid())
        else {
            return false;
        };

        let range = blk.start().raw_address()..blk.next_address().raw_address();

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

    pub fn remove_by_address(&mut self, addr: Address) -> usize {
        let mut removed = 0;

        let space = addr.space();
        let addr = addr.raw_address();

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

    pub fn remove_by_address_and_context(&mut self, addr: Address, context: &ContextSet) -> usize {
        let mut removed = 0;

        let space = addr.space();
        let addr = addr.raw_address();

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

    pub fn get_by_id(&self, id: Id<CodeBlock>) -> Option<CodeBlockRef> {
        self.blocks
            .get(id.index())
            .filter(|blk| blk.id().is_valid())
    }

    pub fn get_by_id_mut(&mut self, id: Id<CodeBlock>) -> Option<CodeBlockMut> {
        self.blocks
            .get_mut(id.index())
            .filter(|blk| blk.id().is_valid())
    }

    pub fn get_by_address(&self, maddr: Address) -> CodeBlockIter<'_> {
        let space = maddr.space();
        let addr = maddr.raw_address();

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

    pub fn get_by_address_and_context<'a>(
        &'a self,
        maddr: Address,
        context: &'a ContextSet,
    ) -> CodeBlockIter<'a> {
        let space = maddr.space();
        let addr = maddr.raw_address();

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

    pub fn get_by_address_mut(&mut self, maddr: Address) -> CodeBlockIterMut<'_> {
        let space = maddr.space();
        let addr = maddr.raw_address();

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

    pub fn get_by_address_and_context_mut<'a>(
        &'a mut self,
        maddr: Address,
        context: &'a ContextSet,
    ) -> CodeBlockIterMut<'a> {
        let space = maddr.space();
        let addr = maddr.raw_address();

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

    pub fn contains(&self, addr: Address) -> bool {
        let space = addr.space();
        let addr = addr.raw_address();

        self.bounds
            .get(&space)
            .map_or(false, |bounds| bounds.has_overlap(addr..=addr))
    }

    pub fn overlaps(&self, addr: Address) -> CodeBlockIter<'_> {
        let space = addr.space();
        let addr = addr.raw_address();

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

    pub fn overlaps_mut(&mut self, addr: Address) -> CodeBlockIterMut<'_> {
        let space = addr.space();
        let addr = addr.raw_address();

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

    pub fn iter(&self) -> CodeBlockIter<'_> {
        CodeBlockIter::new(self.blocks.iter().filter(|blk| blk.id().is_valid()))
    }

    pub fn iter_mut(&mut self) -> CodeBlockIterMut<'_> {
        CodeBlockIterMut::new(self.blocks.iter_mut().filter(|blk| blk.id().is_valid()))
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.blocks.len() - self.free_ids.len()
    }
}

impl Entity for CodeBlockTable {
    const ID: EntityId = ENTITY_CODE_BLOCK_TABLE_ID;
}

impl ProjectEntityFromStorage for CodeBlockTable {
    fn from_entity_storage(storage: &EntityStorage) -> Result<Option<Self>, EntityStorageError> {
        storage.get(&ProjectEntity::CodeBlockTable)
    }

    fn default_from_entity_storage(_storage: &EntityStorage) -> Result<Self, EntityStorageError> {
        Ok(Self::new())
    }
}

impl PersistableProjectEntity for CodeBlockTable {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        storage.insert(&ProjectEntity::CodeBlockTable, self)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ir::InsnList;

    #[test]
    fn test_basic_operations() {
        let mut table = CodeBlockTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        let addr = Address::from(0x1000);
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
        let mut table = CodeBlockTable::new();

        let addr1 = Address::from(0x1000);
        let addr2 = Address::from(0x1000); // overlaps with addr1
        let addr3 = Address::from(0x1005);

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

        let overlaps = table.overlaps(Address::from(0x1007)).collect::<Vec<_>>();
        assert_eq!(overlaps.len(), 3); // all three blocks overlap at 0x1007
        assert!(overlaps.iter().any(|blk| blk.id() == blk_id1));
        assert!(overlaps.iter().any(|blk| blk.id() == blk_id2));
        assert!(overlaps.iter().any(|blk| blk.id() == blk_id3));

        let removed_count = table.remove_by_address(Address::from(0x1000));
        assert_eq!(removed_count, 2);

        let remaining_blk = table.get_by_id(blk_id3).unwrap();
        assert_eq!(remaining_blk.start(), addr3);
    }
}
