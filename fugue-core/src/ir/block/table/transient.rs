use std::collections::BTreeMap;

use iset::{Entry, IntervalMap};
use smallvec::SmallVec;

use super::{CodeBlockIds, CodeBlockIdsByStart, CodeBlockIndex, CodeBlockTableError};
use crate::ir::{Address, AddressRange, CodeBlock, Id, IdAllocator, IdSet};
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
                allocator: IdAllocator::new(),
                bounds: BTreeMap::new(),
                live: 0,
            },
            entries: Vec::new(),
        }
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        Ok(())
    }

    pub(super) fn preview_id(&self, offset: usize) -> Id<CodeBlock> {
        self.index.allocator.preview_id(offset)
    }

    pub(super) fn publish_reservations(&mut self, reservations: &[Id<CodeBlock>]) {
        let mut required = self.entries.len();
        for &id in reservations {
            let allocated = self.index.allocator.allocate();
            debug_assert_eq!(allocated, id);
            required = required.max(id.index() + 1);
        }
        if required > self.entries.len() {
            self.entries.resize_with(required, || None);
        }
    }

    pub(super) fn publish_release(&mut self, id: Id<CodeBlock>) {
        self.index.allocator.release(id);
    }

    pub(super) fn publish_upsert(&mut self, block: CodeBlock) {
        let id = block.id();
        let index = id.index();
        if index >= self.entries.len() {
            self.entries.resize_with(index + 1, || None);
        }
        let range = block.start().raw_address()..=block.last_address().raw_address();
        self.index
            .bounds
            .entry(block.space())
            .or_default()
            .entry(range)
            .or_default()
            .insert(id);
        self.entries[index] = Some(block);
        self.index.live += 1;
    }

    pub(super) fn publish_batch(&mut self, blocks: impl IntoIterator<Item = CodeBlock>) {
        let mut blocks = blocks.into_iter().peekable();

        while let Some(space) = blocks.peek().map(|block| block.space()) {
            let mut incoming = Vec::new();
            while blocks.peek().is_some_and(|block| block.space() == space) {
                let block = blocks.next().expect("peeked block must exist");
                let start = block.start().raw_address();
                let end = block.last_address().raw_address();
                let mut ids = IdSet::new();
                self.publish_batch_entry(block, &mut ids);

                while blocks.peek().is_some_and(|block| {
                    block.space() == space
                        && block.start().raw_address() == start
                        && block.last_address().raw_address() == end
                }) {
                    let block = blocks.next().expect("peeked block must exist");
                    self.publish_batch_entry(block, &mut ids);
                }

                incoming.push((start..=end, ids));
            }
            let bounds = self.index.bounds.entry(space).or_default();
            if bounds.is_empty() {
                *bounds = IntervalMap::from_sorted(incoming);
                continue;
            }

            let mut pending = SmallVec::<[(usize, usize); 32]>::new();
            pending.push((0, incoming.len()));

            while let Some((start, end)) = pending.pop() {
                if start == end {
                    continue;
                }

                let middle = start + (end - start) / 2;
                let (range, added) = &incoming[middle];
                let ids = bounds.entry(range.clone()).or_default();
                for id in added.iter() {
                    ids.insert(id);
                }

                pending.push((middle + 1, end));
                pending.push((start, middle));
            }
        }
    }

    fn publish_batch_entry(&mut self, block: CodeBlock, ids: &mut IdSet<CodeBlock>) {
        let id = block.id();
        let index = id.index();
        if index >= self.entries.len() {
            self.entries.resize_with(index + 1, || None);
        }
        debug_assert!(self.entries[index].is_none());
        ids.insert(id);
        self.entries[index] = Some(block);
        self.index.live += 1;
    }

    pub(super) fn publish_remove(&mut self, id: Id<CodeBlock>, previous: AddressRange) {
        let range = previous.start()..=previous.end();
        if let Some(Entry::Occupied(mut entry)) = self
            .index
            .bounds
            .get_mut(&previous.space())
            .map(|bounds| bounds.entry(range))
        {
            entry.get_mut().remove(id);
            if entry.get().is_empty() {
                entry.remove();
            }
        }
        self.entries[id.index()] = None;
        self.index.allocator.release(id);
        self.index.live -= 1;
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
        let (id, block) = self.index.allocator.try_allocate(|id| {
            let block = f(id, addr)?;
            if block.start() != addr {
                return Err(CodeBlockTableError::AddressMismatch);
            }
            Ok(block)
        })?;

        let range = block.start().raw_address()..=block.last_address().raw_address();
        self.index
            .bounds
            .entry(addr.space())
            .or_default()
            .entry(range)
            .or_default()
            .insert(id);

        let index = id.index();
        if index >= self.entries.len() {
            self.entries.resize_with(index + 1, || None);
        }
        self.entries[index] = Some(block);
        self.index.live += 1;

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
        self.index.allocator.release(id);
        self.index.live -= 1;

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
                self.index.allocator.release(id);
                self.index.live -= 1;
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
            self.index.allocator.release(id);
            self.index.live -= 1;
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

    pub(super) fn find_by_range_and_context(
        &self,
        range: AddressRange,
        context: &ContextSet,
        mut predicate: impl FnMut(&CodeBlock) -> bool,
    ) -> Option<&CodeBlock> {
        let ids = self
            .index
            .bounds
            .get(&range.space())?
            .get(range.start()..=range.end())?;
        ids.iter().find_map(|id| {
            let block = self.get_raw(id)?;
            (block.context() == context && predicate(block)).then_some(block)
        })
    }

    pub(super) fn ids_at_starts(&self, starts: &[Address]) -> CodeBlockIdsByStart {
        starts
            .iter()
            .map(|&address| {
                (
                    address,
                    self.get_by_address(address)
                        .map(CodeBlock::id)
                        .collect::<CodeBlockIds>(),
                )
            })
            .collect()
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

    pub fn overlaps_range(&self, range: &AddressRange) -> impl Iterator<Item = &CodeBlock> + '_ {
        let space = range.space();
        let start = range.start();
        let end = range.end();
        self.index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(start..=end))
            .flat_map(move |ids| ids.iter().filter_map(move |id| self.get_raw(id)))
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
        self.index.live == 0
    }

    pub fn len(&self) -> usize {
        self.index.live
    }
}
