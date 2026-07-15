use std::sync::Arc;

use quick_cache::sync::Cache;

use crate::il::common::{IrArtefactKey, IrLevel, RawIrArtefact};
use crate::ir::cfg::FlowGraph;
use crate::ir::{Address, FunctionId};

pub(crate) const QUERY_MEMO_CAPACITY: usize = 1024;
pub(crate) const IR_MEMO_CAPACITY: usize = 256;

pub(crate) struct QueryCache {
    memo: Cache<Address, Option<Arc<FlowGraph>>>,
    ir: Cache<IrArtefactKey, Option<Arc<RawIrArtefact>>>,
}

impl QueryCache {
    pub(crate) fn new() -> Self {
        Self {
            memo: Cache::new(QUERY_MEMO_CAPACITY),
            ir: Cache::new(IR_MEMO_CAPACITY),
        }
    }

    pub(crate) fn get(&self, entry: Address) -> Option<Option<Arc<FlowGraph>>> {
        self.memo.get(&entry)
    }

    pub(crate) fn insert(&self, entry: Address, graph: Option<Arc<FlowGraph>>) {
        self.memo.insert(entry, graph);
    }

    pub(crate) fn get_ir(&self, key: IrArtefactKey) -> Option<Option<Arc<RawIrArtefact>>> {
        self.ir.get(&key)
    }

    pub(crate) fn insert_ir(&self, key: IrArtefactKey, artefact: Option<Arc<RawIrArtefact>>) {
        self.ir.insert(key, artefact);
    }

    pub(crate) fn evict(&self, entry: Address) {
        self.memo.remove(&entry);
    }

    pub(crate) fn evict_ir(&self, function: FunctionId, level: IrLevel) {
        self.ir.remove(&IrArtefactKey::new(function, level));
    }

    pub(crate) fn clear_ir(&self) {
        self.ir.clear();
    }

    pub(crate) fn clear(&self) {
        self.memo.clear();
        self.ir.clear();
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.memo.len()
    }

    #[cfg(test)]
    pub(crate) fn ir_len(&self) -> usize {
        self.ir.len()
    }
}
