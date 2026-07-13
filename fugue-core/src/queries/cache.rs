use std::sync::Arc;

use indexmap::IndexMap;

use crate::ir::Address;
use crate::ir::cfg::FlowGraph;

pub(crate) const QUERY_MEMO_CAPACITY: usize = 1024;

pub(crate) struct QueryCache {
    memo: IndexMap<Address, Option<Arc<FlowGraph>>>,
}

impl QueryCache {
    pub(crate) fn new() -> Self {
        Self {
            memo: IndexMap::with_capacity(QUERY_MEMO_CAPACITY),
        }
    }

    pub(crate) fn get(&mut self, entry: Address) -> Option<Option<Arc<FlowGraph>>> {
        let index = self.memo.get_index_of(&entry)?;
        let last = self.memo.len() - 1;
        self.memo.move_index(index, last);
        self.memo.get(&entry).cloned()
    }

    pub(crate) fn insert(&mut self, entry: Address, graph: Option<Arc<FlowGraph>>) {
        if let Some(index) = self.memo.get_index_of(&entry) {
            if let Some((_, slot)) = self.memo.get_index_mut(index) {
                *slot = graph;
            }
            let last = self.memo.len() - 1;
            self.memo.move_index(index, last);
            return;
        }

        if self.memo.len() >= QUERY_MEMO_CAPACITY {
            self.memo.shift_remove_index(0);
        }
        self.memo.insert(entry, graph);
    }

    pub(crate) fn evict(&mut self, entry: Address) {
        self.memo.shift_remove(&entry);
    }

    pub(crate) fn clear(&mut self) {
        self.memo.clear();
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.memo.len()
    }
}
