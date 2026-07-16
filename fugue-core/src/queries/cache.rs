use std::sync::Arc;

use quick_cache::sync::Cache;

use crate::il::common::IlLevel;
use crate::il::ecode::ECodeIr;
use crate::il::ecode::ssa::ECodeSsaIr;
use crate::il::pcode::PCodeIr;
use crate::ir::cfg::FlowGraph;
use crate::ir::{Address, FunctionId};

pub(crate) const CFG_CACHE_CAPACITY: usize = 1024;
pub(crate) const LIFTED_CACHE_CAPACITY: usize = 256;

pub(crate) struct QueryCache {
    memo: Cache<Address, Option<Arc<FlowGraph>>>,
    pcode: Cache<FunctionId, Option<Arc<PCodeIr>>>,
    ecode: Cache<FunctionId, Option<Arc<ECodeIr>>>,
    ecode_ssa: Cache<FunctionId, Option<Arc<ECodeSsaIr>>>,
}

impl QueryCache {
    pub(crate) fn new() -> Self {
        Self {
            memo: Cache::new(CFG_CACHE_CAPACITY),
            pcode: Cache::new(LIFTED_CACHE_CAPACITY),
            ecode: Cache::new(LIFTED_CACHE_CAPACITY),
            ecode_ssa: Cache::new(LIFTED_CACHE_CAPACITY),
        }
    }

    pub(crate) fn get(&self, entry: Address) -> Option<Option<Arc<FlowGraph>>> {
        self.memo.get(&entry)
    }

    pub(crate) fn insert(&self, entry: Address, graph: Option<Arc<FlowGraph>>) {
        self.memo.insert(entry, graph);
    }

    pub(crate) fn pcode(&self, function: FunctionId) -> Option<Option<Arc<PCodeIr>>> {
        self.pcode.get(&function)
    }

    pub(crate) fn insert_pcode(&self, function: FunctionId, ir: Option<Arc<PCodeIr>>) {
        self.pcode.insert(function, ir);
    }

    pub(crate) fn ecode(&self, function: FunctionId) -> Option<Option<Arc<ECodeIr>>> {
        self.ecode.get(&function)
    }

    pub(crate) fn insert_ecode(&self, function: FunctionId, ir: Option<Arc<ECodeIr>>) {
        self.ecode.insert(function, ir);
    }

    pub(crate) fn ecode_ssa(&self, function: FunctionId) -> Option<Option<Arc<ECodeSsaIr>>> {
        self.ecode_ssa.get(&function)
    }

    pub(crate) fn insert_ecode_ssa(&self, function: FunctionId, ir: Option<Arc<ECodeSsaIr>>) {
        self.ecode_ssa.insert(function, ir);
    }

    pub(crate) fn evict(&self, entry: Address) {
        self.memo.remove(&entry);
    }

    pub(crate) fn evict_lifted(&self, function: FunctionId, level: IlLevel) {
        match level {
            IlLevel::PCode => {
                self.pcode.remove(&function);
            }
            IlLevel::ECode => {
                self.ecode.remove(&function);
            }
            IlLevel::ECodeSsa => {
                self.ecode_ssa.remove(&function);
            }
        }
    }

    pub(crate) fn clear_lifted(&self) {
        self.pcode.clear();
        self.ecode.clear();
        self.ecode_ssa.clear();
    }

    pub(crate) fn clear(&self) {
        self.memo.clear();
        self.clear_lifted();
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.memo.len()
    }

    #[cfg(test)]
    pub(crate) fn lifted_len(&self) -> usize {
        self.pcode.len() + self.ecode.len() + self.ecode_ssa.len()
    }
}
