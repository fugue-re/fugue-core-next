use std::mem::size_of;
use std::sync::Arc;

use quick_cache::Weighter;
use quick_cache::sync::Cache;

use crate::il::common::{IlArtefact, IlLevel};
use crate::il::ecode::ECodeIr;
use crate::il::ecode::ssa::ECodeSsaIr;
use crate::il::pcode::PCodeIr;
use crate::ir::cfg::FlowTargets;
use crate::ir::{Address, CodeBlockId, FunctionId, InsnList};
use crate::types::EstimateSize;

const CFG_CACHE_CAPACITY: usize = 1024;
const ESTIMATED_LIFTED_CACHE_ENTRIES: usize = 256;
const ESTIMATED_INSN_CACHE_ENTRIES: usize = 4096;

#[derive(Clone, Copy)]
struct InsnWeigher;

impl Weighter<CodeBlockId, Option<Arc<InsnList>>> for InsnWeigher {
    fn weight(&self, _block: &CodeBlockId, insns: &Option<Arc<InsnList>>) -> u64 {
        let size = insns.as_ref().map_or(0, |insns| insns.estimate_size());
        (size_of::<CodeBlockId>() + size_of::<Arc<InsnList>>() + size) as u64
    }
}

#[derive(Clone, Copy)]
struct LiftedWeigher;

impl<T> Weighter<FunctionId, Option<Arc<T>>> for LiftedWeigher
where
    T: EstimateSize,
{
    fn weight(&self, _function: &FunctionId, ir: &Option<Arc<T>>) -> u64 {
        let size = ir.as_ref().map_or(0, |ir| ir.estimate_size());
        (size_of::<FunctionId>() + size_of::<Arc<T>>() + size) as u64
    }
}

pub(crate) struct QueryCache {
    flow_targets: Cache<Address, Option<Arc<FlowTargets>>>,
    insns: Cache<CodeBlockId, Option<Arc<InsnList>>, InsnWeigher>,
    insn_cache_bytes: usize,
    pcode: Cache<FunctionId, Option<Arc<PCodeIr>>, LiftedWeigher>,
    ecode: Cache<FunctionId, Option<Arc<ECodeIr>>, LiftedWeigher>,
    ecode_ssa: Cache<FunctionId, Option<Arc<ECodeSsaIr>>, LiftedWeigher>,
    lifted_entry_cache_bytes: usize,
}

pub(crate) enum CacheLookup<T> {
    Absent,
    Hit(Arc<T>),
    Miss,
}

impl<T> CacheLookup<T> {
    fn from_cached(cached: Option<Option<Arc<T>>>) -> Self {
        match cached {
            None => Self::Miss,
            Some(None) => Self::Absent,
            Some(Some(value)) => Self::Hit(value),
        }
    }
}

pub(crate) trait QueryCachedIl: EstimateSize + IlArtefact {
    fn cached(cache: &QueryCache, function: FunctionId) -> CacheLookup<Self>;
    fn insert_cached(cache: &QueryCache, function: FunctionId, ir: Option<Arc<Self>>);
}

impl QueryCachedIl for PCodeIr {
    fn cached(cache: &QueryCache, function: FunctionId) -> CacheLookup<Self> {
        CacheLookup::from_cached(cache.pcode.get(&function))
    }

    fn insert_cached(cache: &QueryCache, function: FunctionId, ir: Option<Arc<Self>>) {
        cache.insert_lifted(&cache.pcode, function, ir);
    }
}

impl QueryCachedIl for ECodeIr {
    fn cached(cache: &QueryCache, function: FunctionId) -> CacheLookup<Self> {
        CacheLookup::from_cached(cache.ecode.get(&function))
    }

    fn insert_cached(cache: &QueryCache, function: FunctionId, ir: Option<Arc<Self>>) {
        cache.insert_lifted(&cache.ecode, function, ir);
    }
}

impl QueryCachedIl for ECodeSsaIr {
    fn cached(cache: &QueryCache, function: FunctionId) -> CacheLookup<Self> {
        CacheLookup::from_cached(cache.ecode_ssa.get(&function))
    }

    fn insert_cached(cache: &QueryCache, function: FunctionId, ir: Option<Arc<Self>>) {
        cache.insert_lifted(&cache.ecode_ssa, function, ir);
    }
}

impl QueryCache {
    pub(crate) fn new(insn_cache_bytes: usize, lifted_cache_bytes: usize) -> Self {
        let lifted_entry_cache_bytes = lifted_cache_bytes / 3;
        Self {
            flow_targets: Cache::new(CFG_CACHE_CAPACITY),
            insns: Cache::with_weighter(
                ESTIMATED_INSN_CACHE_ENTRIES,
                insn_cache_bytes as u64,
                InsnWeigher,
            ),
            insn_cache_bytes,
            pcode: Cache::with_weighter(
                ESTIMATED_LIFTED_CACHE_ENTRIES,
                lifted_entry_cache_bytes as u64,
                LiftedWeigher,
            ),
            ecode: Cache::with_weighter(
                ESTIMATED_LIFTED_CACHE_ENTRIES,
                lifted_entry_cache_bytes as u64,
                LiftedWeigher,
            ),
            ecode_ssa: Cache::with_weighter(
                ESTIMATED_LIFTED_CACHE_ENTRIES,
                lifted_entry_cache_bytes as u64,
                LiftedWeigher,
            ),
            lifted_entry_cache_bytes,
        }
    }

    pub(crate) fn insns(&self, block: CodeBlockId) -> CacheLookup<InsnList> {
        CacheLookup::from_cached(self.insns.get(&block))
    }

    pub(crate) fn insert_insns(&self, block: CodeBlockId, insns: Arc<InsnList>) {
        let retained = InsnWeigher.weight(&block, &Some(insns.clone())) as usize;
        if retained <= self.insn_cache_bytes {
            self.insns.insert(block, Some(insns));
        }
    }

    pub(crate) fn insert_missing_insns(&self, block: CodeBlockId) {
        let retained = InsnWeigher.weight(&block, &None) as usize;
        if retained <= self.insn_cache_bytes {
            self.insns.insert(block, None);
        }
    }

    pub(crate) fn clear_insns(&self) {
        self.insns.clear();
    }

    fn insert_lifted<T>(
        &self,
        cache: &Cache<FunctionId, Option<Arc<T>>, LiftedWeigher>,
        function: FunctionId,
        ir: Option<Arc<T>>,
    ) where
        T: EstimateSize,
    {
        let retained = LiftedWeigher.weight(&function, &ir) as usize;
        if retained <= self.lifted_entry_cache_bytes {
            cache.insert(function, ir);
        }
    }

    pub(crate) fn flow_targets(&self, entry: Address) -> CacheLookup<FlowTargets> {
        CacheLookup::from_cached(self.flow_targets.get(&entry))
    }

    pub(crate) fn insert_flow_targets(&self, entry: Address, targets: Option<Arc<FlowTargets>>) {
        self.flow_targets.insert(entry, targets);
    }

    pub(crate) fn remove_flow_targets(&self, entry: Address) {
        self.flow_targets.remove(&entry);
    }

    pub(crate) fn remove_lifted(&self, function: FunctionId, level: IlLevel) {
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
        self.clear_insns();
        self.clear_lifted();
    }
}
