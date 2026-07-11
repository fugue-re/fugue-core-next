use std::collections::BTreeMap;

use iset::Entry;
use smallvec::SmallVec;

use super::{CodeBlockIndex, CodeBlockTableError};
use crate::ir::{Address, CodeBlock, Id};
use crate::lifter::ContextSet;
use crate::storage::EntityStorageError;

pub struct CodeBlockTable {
    index: CodeBlockIndex,
    entries: Vec<Option<CodeBlock>>,
}

impl Default for CodeBlockTable {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeBlockTable {
    pub fn new() -> Self {
        Self {
            index: CodeBlockIndex {
                bounds: BTreeMap::new(),
                free_ids: Vec::new(),
                live_entries: 0,
                next_index: 0,
            },
            entries: Vec::new(),
        }
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        Ok(())
    }

    fn get_raw(&self, id: Id<CodeBlock>) -> Option<&CodeBlock> {
        self.entries
            .get(id.index())?
            .as_ref()
            .filter(|block| block.id() == id)
    }

    pub fn insert<F>(&mut self, addr: Address, f: F) -> Result<Id<CodeBlock>, CodeBlockTableError>
    where
        F: FnOnce(Id<CodeBlock>, Address) -> Result<CodeBlock, CodeBlockTableError>,
    {
        let reuse_id = self.index.free_ids.last().copied();
        let id = reuse_id.unwrap_or_else(|| Id::from_index(self.index.next_index));

        let block = f(id, addr)?;

        if block.start() != addr {
            return Err(CodeBlockTableError::AddressMismatch);
        }

        let range = block.start().raw_address()..=block.last_address().raw_address();
        self.index
            .bounds
            .entry(addr.space())
            .or_default()
            .entry(range)
            .or_default()
            .insert(id);

        if reuse_id.is_some() {
            self.index.free_ids.pop();
        } else {
            self.index.next_index += 1;
        }

        let index = id.index();
        if index >= self.entries.len() {
            self.entries.resize_with(index + 1, || None);
        }
        self.entries[index] = Some(block);
        self.index.live_entries += 1;

        Ok(id)
    }

    pub fn get_by_id(&self, id: Id<CodeBlock>) -> Option<&CodeBlock> {
        self.get_raw(id)
    }

    pub fn modify_by_id<R>(
        &mut self,
        id: Id<CodeBlock>,
        f: impl FnOnce(&mut CodeBlock) -> R,
    ) -> Option<R> {
        self.get_by_id_mut(id).map(f)
    }

    pub fn get_by_id_mut(&mut self, id: Id<CodeBlock>) -> Option<&mut CodeBlock> {
        self.entries
            .get_mut(id.index())?
            .as_mut()
            .filter(|block| block.id() == id)
    }

    pub fn remove_by_id(&mut self, id: Id<CodeBlock>) -> bool {
        let Some(block) = self.get_raw(id) else {
            return false;
        };

        let space = block.space();
        let range = block.start().raw_address()..=block.last_address().raw_address();

        if let Some(Entry::Occupied(mut entry)) =
            self.index.bounds.get_mut(&space).map(|m| m.entry(range))
        {
            let id_set = entry.get_mut();
            id_set.remove(id);

            if id_set.is_empty() {
                entry.remove();
            }
        }

        self.entries[id.index()] = None;
        self.index.free_ids.push(id.next_generation());
        self.index.live_entries -= 1;

        true
    }

    pub fn remove_by_address(&mut self, addr: Address) -> usize {
        let space = addr.space();
        let raw = addr.raw_address();

        let Some(bounds) = self.index.bounds.get_mut(&space) else {
            return 0;
        };

        let ranges = bounds
            .intervals_overlap(raw)
            .filter(|iv| *iv.start() == raw)
            .collect::<SmallVec<[_; 2]>>();

        let mut removed = 0;

        for range in ranges {
            let Some(id_set) = bounds.remove(range) else {
                continue;
            };

            for id in id_set.iter() {
                self.entries[id.index()] = None;
                self.index.free_ids.push(id.next_generation());
                self.index.live_entries -= 1;
                removed += 1;
            }
        }

        removed
    }

    pub fn remove_by_address_and_context(&mut self, addr: Address, context: &ContextSet) -> usize {
        let space = addr.space();
        let raw = addr.raw_address();

        let Some(bounds) = self.index.bounds.get_mut(&space) else {
            return 0;
        };

        let ranges = bounds
            .intervals_overlap(raw)
            .filter(|iv| *iv.start() == raw)
            .collect::<SmallVec<[_; 2]>>();

        let mut matching = SmallVec::<[Id<CodeBlock>; 2]>::new();

        for range in ranges {
            let Entry::Occupied(mut entry) = bounds.entry(range) else {
                continue;
            };

            let mut local = SmallVec::<[Id<CodeBlock>; 2]>::new();
            for id in entry.get().iter() {
                let Some(block) = self.entries.get(id.index()).and_then(Option::as_ref) else {
                    continue;
                };
                if block.context() == context {
                    local.push(id);
                }
            }

            for &id in &local {
                entry.get_mut().remove(id);
            }

            if entry.get().is_empty() {
                entry.remove();
            }

            matching.extend(local);
        }

        let removed = matching.len();

        for id in matching {
            self.entries[id.index()] = None;
            self.index.free_ids.push(id.next_generation());
            self.index.live_entries -= 1;
        }

        removed
    }

    pub fn get_by_address(&self, maddr: Address) -> impl Iterator<Item = &CodeBlock> + '_ {
        let space = maddr.space();
        let raw = maddr.raw_address();

        self.index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(raw..=raw))
            .flat_map(move |id_set| {
                id_set.iter().filter_map(move |id| {
                    let block = self.get_raw(id)?;
                    (block.start() == maddr).then_some(block)
                })
            })
    }

    pub fn get_by_address_and_context<'a>(
        &'a self,
        maddr: Address,
        context: &'a ContextSet,
    ) -> impl Iterator<Item = &'a CodeBlock> + 'a {
        let space = maddr.space();
        let raw = maddr.raw_address();

        self.index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(raw..=raw))
            .flat_map(move |id_set| {
                id_set.iter().filter_map(move |id| {
                    let block = self.get_raw(id)?;
                    (block.start() == maddr && block.context() == context).then_some(block)
                })
            })
    }

    pub fn contains(&self, addr: Address) -> bool {
        let space = addr.space();
        let raw = addr.raw_address();

        self.index
            .bounds
            .get(&space)
            .is_some_and(|bounds| bounds.has_overlap(raw..=raw))
    }

    pub fn overlaps(&self, addr: Address) -> impl Iterator<Item = &CodeBlock> + '_ {
        let space = addr.space();
        let raw = addr.raw_address();

        self.index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(raw..=raw))
            .flat_map(move |id_set| id_set.iter().filter_map(move |id| self.get_raw(id)))
    }

    pub fn get_by_address_mut(
        &mut self,
        maddr: Address,
    ) -> impl Iterator<Item = &mut CodeBlock> + '_ {
        let space = maddr.space();
        let raw = maddr.raw_address();

        let blocks_ptr = self.entries.as_mut_ptr();
        self.index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(raw..=raw))
            .flat_map(move |id_set| {
                id_set.iter().filter_map(move |id| {
                    // SAFETY:
                    //
                    // We are guaranteed not to have multiple instances of an
                    // Id<CodeBlock> within the sets iterated over, so the
                    // produced references never alias.
                    //
                    // The indices are guaranteed to be valid as they were
                    // obtained from the IdSet<CodeBlock> which only contains
                    // valid indices.
                    //
                    let block = unsafe { &mut *blocks_ptr.add(id.index()) }.as_mut()?;
                    (block.start() == maddr).then_some(block)
                })
            })
    }

    pub fn get_by_address_and_context_mut<'a>(
        &'a mut self,
        maddr: Address,
        context: &'a ContextSet,
    ) -> impl Iterator<Item = &'a mut CodeBlock> + 'a {
        let space = maddr.space();
        let raw = maddr.raw_address();

        let blocks_ptr = self.entries.as_mut_ptr();
        self.index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(raw..=raw))
            .flat_map(move |id_set| {
                id_set.iter().filter_map(move |id| {
                    // SAFETY: see `get_by_address_mut` for justification.
                    let block = unsafe { &mut *blocks_ptr.add(id.index()) }.as_mut()?;
                    (block.start() == maddr && block.context() == context).then_some(block)
                })
            })
    }

    pub fn overlaps_mut(&mut self, addr: Address) -> impl Iterator<Item = &mut CodeBlock> + '_ {
        let space = addr.space();
        let raw = addr.raw_address();

        let blocks_ptr = self.entries.as_mut_ptr();
        self.index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(raw..=raw))
            .flat_map(move |id_set| {
                id_set.iter().filter_map(move |id| {
                    // SAFETY: see `get_by_address_mut` for justification.
                    unsafe { &mut *blocks_ptr.add(id.index()) }.as_mut()
                })
            })
    }

    pub fn iter(&self) -> impl Iterator<Item = &CodeBlock> + '_ {
        self.entries.iter().filter_map(Option::as_ref)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut CodeBlock> + '_ {
        self.entries.iter_mut().filter_map(Option::as_mut)
    }

    pub fn is_empty(&self) -> bool {
        self.index.live_entries == 0
    }

    pub fn len(&self) -> usize {
        self.index.live_entries
    }
}
