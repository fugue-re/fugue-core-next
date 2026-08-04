use std::any::Any;
use std::mem::size_of;
use std::sync::Arc;

use quick_cache::sync::{Cache, DefaultLifecycle};
use quick_cache::{DefaultHashBuilder, OptionsBuilder, Weighter};

use crate::il::common::{IlArtefact, IlError, IlFormId};
use crate::il::ecode::ECodeIr;
use crate::il::ecode::ssa::ECodeSsaIr;
use crate::il::pcode::PCodeIr;
use crate::ir::cfg::FlowTargets;
use crate::ir::{Address, CodeBlockId, FunctionId, InsnList};
use crate::project::{Project, ProjectError};
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

#[derive(Clone)]
pub(crate) struct CachedIl {
    value: Arc<dyn Any + Send + Sync>,
    size: usize,
}

impl CachedIl {
    fn new<T: IlArtefact>(value: Arc<T>) -> Self {
        let size = value.estimate_size();
        Self { value, size }
    }

    fn downcast<T: IlArtefact>(&self) -> Result<Arc<T>, IlError> {
        self.value
            .clone()
            .downcast::<T>()
            .map_err(|_| IlError::mismatched_artefact(T::FORM))
    }
}

#[derive(Clone, Copy)]
struct LiftedWeigher;

impl Weighter<IlCacheKey, Option<CachedIl>> for LiftedWeigher {
    fn weight(&self, key: &IlCacheKey, ir: &Option<CachedIl>) -> u64 {
        let size = ir.as_ref().map_or(0, |ir| ir.size);
        (size_of::<IlCacheKey>() + key.1.as_str().len() + size_of::<CachedIl>() + size) as u64
    }
}

type IlCacheKey = (FunctionId, IlFormId);

pub(crate) struct QueryCache {
    flow_targets: Cache<Address, Option<Arc<FlowTargets>>>,
    insns: Cache<CodeBlockId, Option<Arc<InsnList>>, InsnWeigher>,
    insn_cache_bytes: usize,
    lifted: Cache<IlCacheKey, Option<CachedIl>, LiftedWeigher>,
    lifted_cache_bytes: usize,
}

pub(crate) enum CacheLookup<T: ?Sized> {
    Absent,
    Hit(Arc<T>),
    Miss,
}

impl<T: ?Sized> CacheLookup<T> {
    fn from_cached(cached: Option<Option<Arc<T>>>) -> Self {
        match cached {
            None => Self::Miss,
            Some(None) => Self::Absent,
            Some(Some(value)) => Self::Hit(value),
        }
    }
}

pub trait QueryableIl: IlArtefact {
    fn load_persisted(
        _project: &Project,
        _function: FunctionId,
    ) -> Result<Option<Self>, ProjectError> {
        Ok(None)
    }
}

impl QueryableIl for PCodeIr {
    fn load_persisted(
        project: &Project,
        function: FunctionId,
    ) -> Result<Option<Self>, ProjectError> {
        project.lifted::<Self>(function)
    }
}

impl QueryableIl for ECodeIr {
    fn load_persisted(
        project: &Project,
        function: FunctionId,
    ) -> Result<Option<Self>, ProjectError> {
        project.lifted::<Self>(function)
    }
}

impl QueryableIl for ECodeSsaIr {
    fn load_persisted(
        project: &Project,
        function: FunctionId,
    ) -> Result<Option<Self>, ProjectError> {
        project.lifted::<Self>(function)
    }
}

impl QueryCache {
    pub(crate) fn new(insn_cache_bytes: usize, lifted_cache_bytes: usize) -> Self {
        let lifted_options = OptionsBuilder::new()
            .shards(1)
            .estimated_items_capacity(ESTIMATED_LIFTED_CACHE_ENTRIES)
            .weight_capacity(lifted_cache_bytes as u64)
            .hot_allocation(1.0)
            .build()
            .expect("valid lifted cache configuration");

        Self {
            flow_targets: Cache::new(CFG_CACHE_CAPACITY),
            insns: Cache::with_weighter(
                ESTIMATED_INSN_CACHE_ENTRIES,
                insn_cache_bytes as u64,
                InsnWeigher,
            ),
            insn_cache_bytes,
            lifted: Cache::with_options(
                lifted_options,
                LiftedWeigher,
                DefaultHashBuilder::default(),
                DefaultLifecycle::default(),
            ),
            lifted_cache_bytes,
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

    pub(crate) fn lifted<T: IlArtefact>(
        &self,
        function: FunctionId,
    ) -> Result<CacheLookup<T>, IlError> {
        Ok(match self.lifted.get(&(function, T::FORM)) {
            None => CacheLookup::Miss,
            Some(None) => CacheLookup::Absent,
            Some(Some(cached)) => CacheLookup::Hit(cached.downcast::<T>()?),
        })
    }

    pub(crate) fn lifted_erased(
        &self,
        function: FunctionId,
        form: &IlFormId,
    ) -> CacheLookup<dyn Any + Send + Sync> {
        match self.lifted.get(&(function, form.clone())) {
            None => CacheLookup::Miss,
            Some(None) => CacheLookup::Absent,
            Some(Some(cached)) => CacheLookup::Hit(cached.value),
        }
    }

    pub(crate) fn insert_lifted_erased(
        &self,
        function: FunctionId,
        form: &IlFormId,
        ir: Option<Arc<dyn Any + Send + Sync>>,
        size: usize,
    ) {
        let key = (function, form.clone());
        let entry = ir.map(|value| CachedIl { value, size });
        let retained = LiftedWeigher.weight(&key, &entry) as usize;
        if retained <= self.lifted_cache_bytes {
            self.lifted.insert(key, entry);
        }
    }

    pub(crate) fn insert_lifted<T: IlArtefact>(&self, function: FunctionId, ir: Option<Arc<T>>) {
        let key = (function, T::FORM);
        let entry = ir.map(CachedIl::new);
        let retained = LiftedWeigher.weight(&key, &entry) as usize;
        if retained <= self.lifted_cache_bytes {
            self.lifted.insert(key, entry);
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

    pub(crate) fn remove_lifted(&self, function: FunctionId, form: &IlFormId) {
        self.lifted.remove(&(function, form.clone()));
    }

    pub(crate) fn clear_lifted(&self) {
        self.lifted.clear();
    }

    pub(crate) fn clear(&self) {
        self.flow_targets.clear();
        self.clear_insns();
        self.clear_lifted();
    }
}

#[cfg(test)]
mod test;
