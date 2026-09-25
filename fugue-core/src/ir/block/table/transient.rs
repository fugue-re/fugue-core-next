use std::collections::BTreeMap;

use iset::{Entry, IntervalMap};
use smallvec::SmallVec;

use super::{CodeBlockIds, CodeBlockIdsByAddress, CodeBlockIndex};
use crate::ir::{Address, AddressRange, CodeBlock, Id, IdAllocator, IdSet};
use crate::lifter::ContextSet;

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

    pub(crate) fn pending_id(&self, offset: usize) -> Id<CodeBlock> {
        self.index.allocator.pending_id(offset)
    }

    fn get_raw(&self, id: Id<CodeBlock>) -> Option<&CodeBlock> {
        self.entries
            .get(id.index())?
            .as_ref()
            .filter(|block| block.id() == id)
    }

    pub fn contains(&self, addr: Address) -> bool {
        let space = addr.space();
        let raw = addr.raw_address();

        self.index
            .bounds
            .get(&space)
            .is_some_and(|bounds| bounds.has_overlap(raw..=raw))
    }

    pub fn iter(&self) -> impl Iterator<Item = &CodeBlock> + '_ {
        self.entries.iter().filter_map(Option::as_ref)
    }

    pub fn is_empty(&self) -> bool {
        self.index.live == 0
    }

    pub fn len(&self) -> usize {
        self.index.live
    }

    pub fn get_by_id(&self, id: Id<CodeBlock>) -> Option<&CodeBlock> {
        self.get_raw(id)
    }

    pub fn get_by_address(&self, address: Address) -> impl Iterator<Item = &CodeBlock> + '_ {
        let space = address.space();
        let raw = address.raw_address();

        self.index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(raw..=raw))
            .flat_map(move |id_set| {
                id_set.iter().filter_map(move |id| {
                    let block = self.get_raw(id)?;
                    (block.address() == address).then_some(block)
                })
            })
    }

    pub fn get_by_address_and_context<'a>(
        &'a self,
        address: Address,
        context: &'a ContextSet,
    ) -> impl Iterator<Item = &'a CodeBlock> + 'a {
        let space = address.space();
        let raw = address.raw_address();

        self.index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(raw..=raw))
            .flat_map(move |id_set| {
                id_set.iter().filter_map(move |id| {
                    let block = self.get_raw(id)?;
                    (block.address() == address && block.context() == context).then_some(block)
                })
            })
    }

    pub(crate) fn get_ids_by_address(&self, addresses: &[Address]) -> CodeBlockIdsByAddress {
        let mut ids_by_address = CodeBlockIdsByAddress::with_capacity(addresses.len());
        for &address in addresses {
            ids_by_address.push(
                address,
                self.get_by_address(address)
                    .map(CodeBlock::id)
                    .collect::<CodeBlockIds>(),
            );
        }
        ids_by_address
    }

    pub fn overlaps_address(&self, addr: Address) -> impl Iterator<Item = &CodeBlock> + '_ {
        let space = addr.space();
        let raw = addr.raw_address();

        self.index
            .bounds
            .get(&space)
            .into_iter()
            .flat_map(move |bounds| bounds.values(raw..=raw))
            .flat_map(move |id_set| id_set.iter().filter_map(move |id| self.get_raw(id)))
    }

    pub fn overlaps(&self, range: &AddressRange) -> impl Iterator<Item = &CodeBlock> + '_ {
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

    pub(crate) fn find_by_range_and_context(
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

    pub(crate) fn publish_reservations(&mut self, reservations: &[Id<CodeBlock>]) {
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

    pub(crate) fn publish_release(&mut self, id: Id<CodeBlock>) {
        self.index.allocator.release(id);
    }

    pub(crate) fn publish_upsert(&mut self, block: CodeBlock) {
        let id = block.id();
        let index = id.index();
        if index >= self.entries.len() {
            self.entries.resize_with(index + 1, || None);
        }
        let range = block.address().raw_address()..=block.last_address().raw_address();
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

    pub(crate) fn publish_batch(&mut self, blocks: impl IntoIterator<Item = CodeBlock>) {
        let mut blocks = blocks.into_iter().peekable();

        while let Some(space) = blocks.peek().map(|block| block.space()) {
            let mut incoming = Vec::new();
            while blocks.peek().is_some_and(|block| block.space() == space) {
                let block = blocks.next().expect("peeked block must exist");
                let start = block.address().raw_address();
                let end = block.last_address().raw_address();
                let mut ids = IdSet::new();
                self.publish_batch_entry(block, &mut ids);

                while blocks.peek().is_some_and(|block| {
                    block.space() == space
                        && block.address().raw_address() == start
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

    pub(crate) fn publish_remove(&mut self, id: Id<CodeBlock>, previous: AddressRange) {
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
}
