use std::sync::Arc;

use quick_cache::sync::Cache;

use crate::ir::Address;
use crate::ir::cfg::FlowGraph;

pub(crate) const QUERY_MEMO_CAPACITY: usize = 1024;

pub(crate) struct QueryCache {
    memo: Cache<Address, Option<Arc<FlowGraph>>>,
}

impl QueryCache {
    pub(crate) fn new() -> Self {
        Self {
            memo: Cache::new(QUERY_MEMO_CAPACITY),
        }
    }

    pub(crate) fn get(&self, entry: Address) -> Option<Option<Arc<FlowGraph>>> {
        self.memo.get(&entry)
    }

    pub(crate) fn insert(&self, entry: Address, graph: Option<Arc<FlowGraph>>) {
        self.memo.insert(entry, graph);
    }

    pub(crate) fn evict(&self, entry: Address) {
        self.memo.remove(&entry);
    }

    pub(crate) fn clear(&self) {
        self.memo.clear();
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.memo.len()
    }
}
