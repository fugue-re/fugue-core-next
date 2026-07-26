use std::sync::Arc;

use quick_cache::sync::Cache;

use crate::il::common::{IlArtefact, IlLevel};
use crate::il::ecode::ECodeIr;
use crate::il::ecode::ssa::ECodeSsaIr;
use crate::il::pcode::PCodeIr;
use crate::ir::cfg::FlowTargets;
use crate::ir::{Address, FunctionId};

pub(crate) const CFG_CACHE_CAPACITY: usize = 1024;
pub(crate) const LIFTED_CACHE_CAPACITY: usize = 256;

pub(crate) struct QueryCache {
    flow_targets: Cache<Address, Option<Arc<FlowTargets>>>,
    pcode: Cache<FunctionId, Option<Arc<PCodeIr>>>,
    ecode: Cache<FunctionId, Option<Arc<ECodeIr>>>,
    ecode_ssa: Cache<FunctionId, Option<Arc<ECodeSsaIr>>>,
}

pub(crate) trait QueryCachedIl: IlArtefact {
    fn cached(cache: &QueryCache, function: FunctionId) -> Option<Option<Arc<Self>>>;
    fn insert_cached(cache: &QueryCache, function: FunctionId, ir: Option<Arc<Self>>);
}

impl QueryCachedIl for PCodeIr {
    fn cached(cache: &QueryCache, function: FunctionId) -> Option<Option<Arc<Self>>> {
        cache.pcode.get(&function)
    }

    fn insert_cached(cache: &QueryCache, function: FunctionId, ir: Option<Arc<Self>>) {
        cache.pcode.insert(function, ir);
    }
}

impl QueryCachedIl for ECodeIr {
    fn cached(cache: &QueryCache, function: FunctionId) -> Option<Option<Arc<Self>>> {
        cache.ecode.get(&function)
    }

    fn insert_cached(cache: &QueryCache, function: FunctionId, ir: Option<Arc<Self>>) {
        cache.ecode.insert(function, ir);
    }
}

impl QueryCachedIl for ECodeSsaIr {
    fn cached(cache: &QueryCache, function: FunctionId) -> Option<Option<Arc<Self>>> {
        cache.ecode_ssa.get(&function)
    }

    fn insert_cached(cache: &QueryCache, function: FunctionId, ir: Option<Arc<Self>>) {
        cache.ecode_ssa.insert(function, ir);
    }
}

impl QueryCache {
    pub(crate) fn new() -> Self {
        Self {
            flow_targets: Cache::new(CFG_CACHE_CAPACITY),
            pcode: Cache::new(LIFTED_CACHE_CAPACITY),
            ecode: Cache::new(LIFTED_CACHE_CAPACITY),
            ecode_ssa: Cache::new(LIFTED_CACHE_CAPACITY),
        }
    }

    pub(crate) fn flow_targets(&self, entry: Address) -> Option<Option<Arc<FlowTargets>>> {
        self.flow_targets.get(&entry)
    }

    pub(crate) fn insert_flow_targets(&self, entry: Address, targets: Option<Arc<FlowTargets>>) {
        self.flow_targets.insert(entry, targets);
    }

    pub(crate) fn evict_flow_targets(&self, entry: Address) {
        self.flow_targets.remove(&entry);
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
        self.flow_targets.clear();
        self.clear_lifted();
    }
}
